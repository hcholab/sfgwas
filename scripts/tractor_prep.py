"""Prepares Tractor test runs from extract_tracts.py output and SF-GWAS-style inputs.

Subcommands (run each with -h for details):

  table    Builds an ID-keyed phenotype/covariate table from SF-GWAS inputs
           (.psam [+ sample_keep.txt] + pheno.txt + cov.txt, whose rows follow the .psam
           order filtered by sample_keep, as plink2 --keep --indiv-sort none emits them).
           Also writes <out>.cols.sh with PHENOS=... and COVS=... (constant covariate
           columns left out) for the later steps.
  split    Picks samples present in both the genotypes (a VCF sample list or hapdose
           files) and the table (complete rows) and splits them at random into parties:
           party<p>.ids and all.ids (genotype order, for bcftools view -S). With --msp it
           also checks that the MSP's haplotype columns follow the VCF sample order and
           writes the MSP restricted to the chosen samples, in all.ids order, so that
           extract_tracts.py can run on the subset (its run time grows faster than linearly
           with the number of samples).
  sfgwas   Writes a ready-to-run sfgwas Tractor run directory for those parties: per-party
           int8 block files (tractor_a/amr/eur = anc0 hapcount / anc0 dosage / anc1
           dosage, geno = total dosage), pheno.txt, cov.txt, snp_pos.txt, block sizes,
           config/tractor/*.toml, fresh random MPC keys and the scripts symlink.
  compare  Compares the run's output with tractor_plaintext.py's output for the same
           samples (same tolerances as the oracle test).

tractor_plaintext.py must sit in the same directory (its file readers are reused).
"""
import argparse
import os
import socket
import sys

import numpy as np
import pandas as pd

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tractor_plaintext import VARIANT_COLS, find_file, read_header, reader  # noqa: E402

KEY_NAMES = ["shared_key_global.bin", "shared_key_0_1.bin", "shared_key_0_2.bin", "shared_key_1_2.bin"]


def split_line(line):
    line = line.rstrip("\n")
    return line.split("\t") if "\t" in line else line.split()


def read_rows(path):
    return [split_line(l) for l in open(path) if l.strip()]


def read_psam(path):
    header, rows = None, []
    for l in open(path):
        if not l.strip():
            continue
        if l.startswith("#"):
            header = [h.upper() for h in split_line(l.lstrip("#"))]
            continue
        rows.append(split_line(l))
    if header is None or "IID" not in header:
        sys.exit(f"{path}: no '#... IID ...' header line")
    iid = header.index("IID")
    fid = header.index("FID") if "FID" in header else None
    return [(r[fid] if fid is not None else r[iid], r[iid]) for r in rows]


def keep_filter(ids, keep_path):
    rows = read_rows(keep_path)
    if rows and rows[0][0].startswith("#"):
        rows = rows[1:]
    ncols = {len(r) for r in rows}
    if len(ncols) != 1:
        sys.exit(f"{keep_path}: inconsistent column counts {ncols}")
    if ncols.pop() >= 2:
        keep = {(r[0], r[1]) for r in rows}
        return [p for p in ids if p in keep]
    keep = {r[0] for r in rows}
    return [p for p in ids if p[1] in keep]


def cmd_table(a):
    n_groups = len(a.pheno)
    if len(a.cov) != n_groups:
        sys.exit("give one --cov per --pheno")
    if len(a.psam) not in (1, n_groups) or (a.keep and len(a.keep) not in (1, n_groups)):
        sys.exit("give one --psam (and --keep) in total, or one per --pheno")
    ids_all, P, C = [], [], []
    for g in range(n_groups):
        psam = a.psam[g if len(a.psam) > 1 else 0]
        ids = read_psam(psam)
        n_psam = len(ids)
        if a.keep:
            ids = keep_filter(ids, a.keep[g if len(a.keep) > 1 else 0])
        p, c = read_rows(a.pheno[g]), read_rows(a.cov[g])
        if not (len(p) == len(c) == len(ids)):
            sys.exit(f"group {g + 1}: {a.pheno[g]} has {len(p)} rows, {a.cov[g]} {len(c)}, but {psam} has {n_psam} "
                     f"samples{f' and {len(ids)} after --keep' if a.keep else ''}. pheno/cov rows must follow the "
                     ".psam order filtered by sample_keep.txt (pass --keep if they were filtered).")
        for name, rows in (("pheno", p), ("cov", c)):
            if len({len(r) for r in rows}) != 1:
                sys.exit(f"{name} file of group {g + 1} has rows with different column counts")
        ids_all += [i for _, i in ids]
        P += p
        C += c
    if len(set(ids_all)) != len(ids_all):
        sys.exit("duplicate sample IDs across the inputs")
    npheno, ncov = len(P[0]), len(C[0])
    if len({len(r) for r in P}) != 1 or len({len(r) for r in C}) != 1:
        sys.exit("the groups' pheno (or cov) files have different column counts")
    pnames = a.pheno_names.split(",") if a.pheno_names else [f"pheno{k + 1}" for k in range(npheno)]
    cnames = a.cov_names.split(",") if a.cov_names else [f"cov{k + 1}" for k in range(ncov)]
    if len(pnames) != npheno or len(cnames) != ncov:
        sys.exit(f"--pheno-names/--cov-names must have {npheno} / {ncov} names")
    df = pd.DataFrame(np.hstack([np.array(P, dtype=object), np.array(C, dtype=object)]), columns=pnames + cnames)
    df.insert(0, "IID", ids_all)
    df.to_csv(a.out, sep="\t", index=False)
    num = df[pnames + cnames].apply(pd.to_numeric, errors="coerce")
    const = [c for c in cnames if num[c].nunique(dropna=True) <= 1]
    covs = [c for c in cnames if c not in const]
    with open(f"{a.out}.cols.sh", "w") as f:
        f.write(f"PHENOS={','.join(pnames)}\nCOVS={','.join(covs)}\n")
    print(f"{a.out}: {len(df)} samples, phenotypes {pnames}, covariates {cnames}")
    if const:
        print(f"  constant covariate column(s) left out of COVS (an intercept is added): {const}")
    nbad = int(num.isna().any(axis=1).sum())
    if nbad:
        print(f"  {nbad} sample(s) have a missing/non-numeric value; they are skipped later")
    print(f"  wrote {a.out}.cols.sh: PHENOS={','.join(pnames)} COVS={','.join(covs)}")


def load_table(path, idcol, phenos, covs):
    t = pd.read_csv(path, sep=r"\s+", dtype={idcol: str})
    for c in [idcol] + phenos + covs:
        if c not in t.columns:
            sys.exit(f"{path}: no column {c!r}")
    t = t.set_index(idcol)[phenos + covs].apply(pd.to_numeric, errors="coerce")
    return t.dropna()


def subset_msp(msp_in, msp_out, vcf_samples, chosen):
    """Writes msp_in restricted to the chosen samples' haplotype columns, in the order of chosen."""
    col = {s: i for i, s in enumerate(vcf_samples)}
    keep = list(range(6)) + [6 + 2 * col[s] + h for s in chosen for h in (0, 1)]
    with open(msp_in) as fi, open(msp_out, "w") as fo:
        for ln, line in enumerate(fi):
            f = line.rstrip("\n").split("\t")
            if ln == 0 and line.startswith("#Subpopulation"):
                fo.write(line)
                continue
            if line.startswith("#"):
                haps = [h.rsplit(".", 1)[0] for h in f[6::2]]
                if haps != vcf_samples or any(not h.endswith(".1") for h in f[7::2]):
                    sys.exit(f"{msp_in}: haplotype columns do not follow the VCF sample order (ID.0 ID.1 per sample)")
            elif len(f) != 6 + 2 * len(vcf_samples):
                sys.exit(f"{msp_in} line {ln + 1}: {len(f)} columns, expected {6 + 2 * len(vcf_samples)}")
            fo.write("\t".join(f[i] for i in keep) + "\n")


def cmd_split(a):
    phenos, covs = a.phenocol.split(","), [c for c in a.covarcollist.split(",") if c]
    if bool(a.hapdose) == bool(a.vcf_samples):
        sys.exit("give exactly one of --hapdose and --vcf-samples")
    if a.msp and not (a.vcf_samples and a.msp_out):
        sys.exit("--msp needs --vcf-samples and --msp-out")
    if a.hapdose:
        hdr = read_header(find_file(a.hapdose, 0, "hapcount"))
    else:
        hdr = [l.strip() for l in open(a.vcf_samples) if l.strip()]
    table = load_table(a.table, a.sampleidcol, phenos, covs)
    in_table = set(table.index)
    cands = [s for s in hdr if s in in_table]
    print(f"genotyped samples: {len(hdr)}; complete table rows: {len(table)}; in both: {len(cands)}")
    if not cands:
        sys.exit("no overlap between the genotyped samples and the table IDs: is the table from the same cohort, "
                 "and are the IDs the same kind (VCF sample names vs .psam IIDs)?")
    n = a.n if a.n > 0 else len(cands)
    if n > len(cands):
        sys.exit(f"--n {n} > {len(cands)} available samples")
    rng = np.random.default_rng(a.seed)
    chosen = rng.permutation(rng.choice(len(cands), n, replace=False))
    os.makedirs(a.out_dir, exist_ok=True)
    for p, part in enumerate(np.array_split(chosen, a.parties), start=1):
        ids = [cands[i] for i in sorted(part)]  # genotype-file order within a party
        with open(os.path.join(a.out_dir, f"party{p}.ids"), "w") as f:
            f.write("\n".join(ids) + "\n")
        print(f"  party{p}.ids: {len(ids)} samples")
    allids = [cands[i] for i in sorted(chosen)]  # genotype-file order, for bcftools view -S
    with open(os.path.join(a.out_dir, "all.ids"), "w") as f:
        f.write("\n".join(allids) + "\n")
    print(f"  all.ids: {len(allids)} samples (seed {a.seed})")
    if a.msp:
        subset_msp(a.msp, a.msp_out, hdr, allids)
        print(f"  {a.msp_out}: MSP restricted to these samples, in the order of all.ids")


def port_of(base, nparty, p, q):
    """Port on which party p listens for party q (q > p); each MPC thread t uses port + t."""
    return base + 20 * (p * (nparty + 1) + q)


def check_ports(base, nparty, threads):
    busy = []
    for p in range(nparty + 1):
        for q in range(p + 1, nparty + 1):
            for t in range(threads):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind(("0.0.0.0", port_of(base, nparty, p, q) + t))
                except OSError:
                    busy.append(port_of(base, nparty, p, q) + t)
                finally:
                    s.close()
    if busy:
        sys.exit(f"port(s) {busy} are in use on this machine: pick another --base-port")


def toml_global(nparty, num_inds, m, ncov, nblocks, thr, tol, base, threads):
    servers = []
    for p in range(nparty + 1):
        ports = ", ".join(f'party{q} = "{port_of(base, nparty, p, q)}"' for q in range(p + 1, nparty + 1))
        servers.append(f'[servers.party{p}]\nipaddr = "127.0.0.1"\nports = {{{" " + ports + " " if ports else ""}}}\n')
    return f"""num_main_parties = {nparty}
hub_party_id = 1
debug = false
ckks_params = "PN14QP438"
phase = ""
mpc_num_threads = {threads}
mpc_field_size = 256
mpc_data_bits = 60
mpc_frac_bits = 30
div_sqrt_max_len = 1000000
mpc_boolean_shares = true
num_inds = [0, {", ".join(str(x) for x in num_inds)}]
num_snps = {m}
num_covs = {ncov}
cov_all_ones = false
geno_file_format = "blocks"
use_precomputed_geno_count = false
geno_num_blocks = {nblocks}
use_cached_qc = false
skip_qc = true
imiss_ub = 1.0
het_lb = 0.0
het_ub = 1.0
gmiss = 1.0
maf_lb = 0.0
hwe_ub = 1e9
snp_dist_thres = 1
use_cached_pca = false
skip_pca = true
iter_per_eigenval = 2
num_pcs_to_remove = 0
num_oversampling = 5
num_power_iters = 3
use_cached_combined_q = false
blocks_for_assoc_test = []
pgen_batch_nsnp = 8192
use_plain_mult_phase_3 = true
use_eigen_cov_ortho = false
use_high_prec_cov_ortho = false
use_tractor_phase_3 = true
tractor_count_threshold = {thr:g}
tractor_det_tol = {tol:g}
binding_ipaddr = "0.0.0.0"

""" + "\n".join(servers)


def cmd_sfgwas(a):
    phenos, covs = a.phenocol.split(","), [c for c in a.covarcollist.split(",") if c]
    run = os.path.abspath(a.run_dir)
    if os.path.exists(os.path.join(run, "config")):
        sys.exit(f"{run} already holds a run; remove it or pick another --run-dir")
    repo = os.path.abspath(a.sfgwas_repo)
    check_ports(a.base_port, len(a.party_ids), a.threads)
    table = load_table(a.table, a.sampleidcol, phenos, covs)
    parties = [[l.split()[0] for l in open(f) if l.strip()] for f in a.party_ids]
    allids = [s for ids in parties for s in ids]
    if len(set(allids)) != len(allids):
        sys.exit("a sample appears in more than one party (or twice in one)")
    f_hap0, f_dos0, f_dos1 = (find_file(a.hapdose, 0, "hapcount"), find_file(a.hapdose, 0, "dosage"),
                              find_file(a.hapdose, 1, "dosage"))
    if find_file(a.hapdose, 2, "dosage", required=False):
        sys.exit(f"{a.hapdose}.anc2.* exists: collapse the MSP to two ancestries first")
    hdr = read_header(f_hap0)
    for f in (f_dos0, f_dos1):
        if read_header(f) != hdr:
            sys.exit(f"{f}: sample columns differ from {f_hap0}")
    pos_of = {s: i for i, s in enumerate(hdr)}
    missing = [s for s in allids if s not in pos_of or s not in table.index]
    if missing:
        sys.exit(f"{len(missing)} sample(s) lack genotypes or a complete table row, e.g. {missing[:3]}")
    Zall = table.loc[allids, covs].to_numpy(float).reshape(len(allids), len(covs))
    Zreg = np.column_stack([np.ones(len(allids)), Zall])
    if np.linalg.matrix_rank(Zreg) < Zreg.shape[1]:
        sys.exit("[1 | covariates] is rank deficient over the pooled samples: drop constant/collinear covariates")

    sample_pos = sorted(pos_of[s] for s in allids)       # union, in hapdose column order
    col_of = {hdr[p]: j for j, p in enumerate(sample_pos)}
    pidx = [np.array([col_of[s] for s in ids]) for ids in parties]
    os.makedirs(run, exist_ok=True)
    pdirs = []
    for p, ids in enumerate(parties, start=1):
        d = os.path.join(run, f"party{p}")
        os.makedirs(d, exist_ok=True)
        pdirs.append(d)
        with open(os.path.join(d, "ids.txt"), "w") as f:
            f.write("\n".join(ids) + "\n")
        np.savetxt(os.path.join(d, "pheno.txt"), table.loc[ids, phenos].to_numpy(float), fmt="%.17g", delimiter="\t")
        np.savetxt(os.path.join(d, "cov.txt"), table.loc[ids, covs].to_numpy(float).reshape(len(ids), len(covs)),
                   fmt="%.17g", delimiter="\t")

    sizes, snp_rows, pos_rows = [], [], []
    bufs, have = None, 0

    def flush(blk, k):
        A, M, E = (b[:k] for b in bufs)  # SNPs x union samples
        for p, d in enumerate(pdirs):
            cols = pidx[p]
            for name, X in (("tractor_a", A), ("tractor_amr", M), ("tractor_eur", E), ("geno", M + E)):
                np.ascontiguousarray(X[:, cols].T).astype(np.int8).tofile(os.path.join(d, f"{name}.{blk}.bin"))
        sizes.append(k)

    gens = [reader(f, sample_pos, min(a.block_size, 1000)) for f in (f_hap0, f_dos0, f_dos1)]
    for ci, ((info, A), (info_m, M), (info_e, E)) in enumerate(zip(*gens)):
        if not (info.equals(info_m) and info.equals(info_e)):
            sys.exit(f"variant rows differ between the hapdose files in chunk {ci}")
        if A.min() < 0 or A.max() > 2 or (M > A).any() or (E > 2 - A).any() or M.min() < 0 or E.min() < 0:
            sys.exit(f"chunk {ci}: haplotype counts / dosages are inconsistent")
        for _, r in info.iterrows():
            chrom = r.CHROM[3:] if r.CHROM.lower().startswith("chr") else r.CHROM
            if not chrom.isdigit():
                sys.exit(f"chromosome {r.CHROM!r}: sfgwas snp_pos.txt needs numeric chromosomes")
            pos_rows.append(f"{chrom}\t{r.POS}")
            snp_rows.append("\t".join(str(x) for x in r))
        start = 0
        while start < len(info):
            if bufs is None:
                bufs = [np.empty((a.block_size, len(sample_pos)), dtype=np.int8) for _ in range(3)]
                have = 0
            take = min(a.block_size - have, len(info) - start)
            for b, X in zip(bufs, (A, M, E)):
                b[have:have + take] = X[start:start + take]
            have += take
            start += take
            if have == a.block_size:
                flush(len(sizes), have)
                bufs = None
        print(f"  {len(snp_rows)} SNPs converted", flush=True)
    if bufs is not None and have:
        flush(len(sizes), have)
    m = sum(sizes)
    if m < 5:
        sys.exit("sfgwas needs at least 5 SNPs")
    for d in pdirs:
        open(os.path.join(d, "geno_block_sizes.txt"), "w").write("\n".join(str(s) for s in sizes) + "\n")
        open(os.path.join(d, "snp_pos.txt"), "w").write("\n".join(pos_rows) + "\n")
    with open(os.path.join(run, "snps.tsv"), "w") as f:
        f.write("\t".join(VARIANT_COLS) + "\n" + "\n".join(snp_rows) + "\n")

    keys = os.path.abspath(a.keys or os.path.join(run, "keys"))
    if not os.path.isdir(keys):
        os.makedirs(keys, mode=0o700)
        for k in KEY_NAMES:
            fd = os.open(os.path.join(keys, k), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, os.urandom(32))
            os.close(fd)
        print(f"  generated fresh MPC keys in {keys}")
    elif not all(os.path.exists(os.path.join(keys, k)) for k in KEY_NAMES):
        sys.exit(f"{keys} lacks some of {KEY_NAMES}")

    cfg = os.path.join(run, "config", "tractor")
    os.makedirs(cfg)
    nparty = len(parties)
    with open(os.path.join(cfg, "configGlobal.toml"), "w") as f:
        f.write(toml_global(nparty, [len(x) for x in parties], m, len(covs), len(sizes), a.count_threshold,
                            a.det_tol, a.base_port, a.threads))
    for p in range(nparty + 1):
        lines = [f'shared_keys_path = "{keys}"']
        if p > 0:
            d = pdirs[p - 1]
            lines += [f'geno_binary_file_prefix = "{d}/geno"', f'geno_block_size_file = "{d}/geno_block_sizes.txt"',
                      f'pheno_file = "{d}/pheno.txt"', f'covar_file = "{d}/cov.txt"',
                      f'snp_position_file = "{d}/snp_pos.txt"', f'tractor_geno_prefix_a = "{d}/tractor_a"',
                      f'tractor_geno_prefix_amr = "{d}/tractor_amr"', f'tractor_geno_prefix_eur = "{d}/tractor_eur"',
                      "assoc_num_blocks_parallel = 1"]
        lines += [f'output_dir = "out/party{p}"', f'cache_dir = "cache/party{p}"', f"local_num_threads = {a.threads}",
                  f"memory_limit = {a.memory_limit}"]
        open(os.path.join(cfg, f"configLocal.Party{p}.toml"), "w").write("\n".join(lines) + "\n")
    link = os.path.join(run, "scripts")
    if not os.path.lexists(link):
        os.symlink(os.path.join(repo, "scripts"), link)
    print(f"{run}: {nparty} parties ({', '.join(str(len(x)) for x in parties)} samples), {m} SNPs in "
          f"{len(sizes)} block(s), {len(phenos)} phenotype(s), {len(covs)} covariate(s) + intercept; "
          f"ports {a.base_port + 20}-{port_of(a.base_port, nparty, nparty - 1, nparty) + a.threads - 1}")


def cmd_compare(a):
    phenos = a.phenocol.split(",")
    run = os.path.abspath(a.run_dir)
    out = os.path.join(run, "out", "party1")
    snps = pd.read_csv(os.path.join(run, "snps.tsv"), sep="\t", dtype=str)
    used = {s.strip() for s in open(f"{a.plain}.samples.txt") if s.strip()}
    parts = set()
    p = 1
    while os.path.isdir(os.path.join(run, f"party{p}")):
        parts |= {s.strip() for s in open(os.path.join(run, f"party{p}", "ids.txt")) if s.strip()}
        p += 1
    if used != parts:
        sys.exit(f"plaintext used {len(used)} samples, the run's parties hold {len(parts)}, "
                 f"{len(used & parts)} in common: run tractor_plaintext.py with --samples all.ids")
    idx = [int(l) for l in open(os.path.join(out, "tractor_snp_index.txt")) if l.strip()]
    ok = True
    for k, ph in enumerate(phenos):
        plain = pd.read_csv(f"{a.plain}.{ph}.tsv", sep="\t", dtype={c: str for c in VARIANT_COLS})
        if not plain[VARIANT_COLS].equals(snps):
            sys.exit(f"{a.plain}.{ph}.tsv and {run}/snps.tsv list different SNPs")
        plain = plain.iloc[idx].reset_index(drop=True)
        rows = [l.rstrip("\n").split("\t") for l in open(os.path.join(out, f"tractor_{k}.txt"))]
        if len(rows) != len(plain):
            print(f"  {ph}: {len(rows)} output rows, expected {len(plain)}")
            ok = False
            continue
        got = np.array([[float(x) for x in r[:9]] for r in rows])
        gvalid = np.array([r[9] == "true" for r in rows])
        pvalid = plain["valid"].astype(str).str.lower().eq("true").to_numpy()
        mism = int((gvalid != pvalid).sum())
        both = gvalid & pvalid
        worst = {"beta": 0.0, "se": 0.0, "log10p": 0.0}
        viol = 0
        for ge, c in (("A", 0), ("anc0", 3), ("anc1", 6)):
            rb, rs, rp = (plain[f"{s}_{ge}"].to_numpy(float)[both] for s in ("beta", "se", "p"))
            gb, gs, gp = got[both, c], got[both, c + 1], got[both, c + 2]
            d = {"beta": np.abs(gb - rb) / rs, "se": np.abs(gs - rs) / rs,
                 "log10p": np.abs(np.log10(np.maximum(gp, 5e-324)) - np.log10(np.maximum(rp, 5e-324)))}
            tol = {"beta": 1e-2, "se": 1e-3, "log10p": 1e-2}
            for key in d:
                if d[key].size:
                    worst[key] = float("nan") if np.isnan(d[key]).any() or np.isnan(worst[key]) else max(worst[key], float(d[key].max()))
                    viol += int((~(d[key] <= tol[key])).sum())
        print(f"  {ph}: compared {int(both.sum())}/{len(plain)} SNPs, validity mismatches {mism}, "
              f"max |dbeta|/SE={worst['beta']:.3g} |dSE|/SE={worst['se']:.3g} |dlog10p|={worst['log10p']:.3g}, "
              f"tolerance violations {viol}")
        ok = ok and mism == 0 and viol == 0
    print("  Secure Tractor vs plaintext:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("table", help="ID-keyed pheno/cov table from SF-GWAS inputs")
    t.add_argument("--psam", nargs="+", required=True, help=".psam file(s) whose sample order pheno/cov follow")
    t.add_argument("--keep", nargs="*", default=[], help="sample_keep.txt file(s) used to filter the .psam, if any")
    t.add_argument("--pheno", nargs="+", required=True, help="pheno.txt file(s), no header, no ID column")
    t.add_argument("--cov", nargs="+", required=True, help="cov.txt file(s), no header, no ID column")
    t.add_argument("--pheno-names", help="comma-separated names for the pheno.txt columns (default pheno1,...)")
    t.add_argument("--cov-names", help="comma-separated names for the cov.txt columns (default cov1,...)")
    t.add_argument("--out", required=True)

    def common(p):
        p.add_argument("--table", required=True)
        p.add_argument("--sampleidcol", default="IID")
        p.add_argument("--phenocol", required=True)
        p.add_argument("--covarcollist", default="")

    s = sub.add_parser("split", help="random party split of the usable samples")
    s.add_argument("--hapdose", help="take the genotyped samples from these hapdose files ...")
    s.add_argument("--vcf-samples", help="... or from this list (bcftools query -l), in VCF order")
    s.add_argument("--msp", help="also restrict this (two-way) MSP to the chosen samples (needs --vcf-samples)")
    s.add_argument("--msp-out")
    common(s)
    s.add_argument("--n", type=int, default=10000, help="total samples to use (0 = all usable)")
    s.add_argument("--parties", type=int, default=2)
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--out-dir", required=True)

    f = sub.add_parser("sfgwas", help="write an sfgwas Tractor run directory")
    f.add_argument("--hapdose", required=True)
    common(f)
    f.add_argument("--party-ids", nargs="+", required=True)
    f.add_argument("--run-dir", required=True)
    f.add_argument("--block-size", type=int, default=8192, help="SNPs per block (default 8192, one ciphertext)")
    f.add_argument("--count-threshold", type=float, default=20)
    f.add_argument("--det-tol", type=float, default=1e-6)
    f.add_argument("--base-port", type=int, default=51000)
    f.add_argument("--threads", type=int, default=4)
    f.add_argument("--memory-limit", type=int, default=8000000000)
    f.add_argument("--keys", help="directory with the four shared_key_*.bin files (default: <run-dir>/keys, "
                                  "created with fresh random keys)")
    f.add_argument("--sfgwas-repo", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

    c = sub.add_parser("compare", help="compare a finished run with tractor_plaintext.py output")
    c.add_argument("--run-dir", required=True)
    c.add_argument("--plain", required=True, help="the --output prefix given to tractor_plaintext.py")
    c.add_argument("--phenocol", required=True)

    a = ap.parse_args()
    {"table": cmd_table, "split": cmd_split, "sfgwas": cmd_sfgwas, "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    main()
