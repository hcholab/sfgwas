"""Plaintext two-way Tractor on extract_tracts.py output, using tractor.ipynb's own functions.

usage:
  python -I scripts/tractor_plaintext.py --hapdose PREFIX --phenofile TABLE \
      --phenocol y1[,y2,...] --covarcollist c1,c2,... --output OUT \
      [--sampleidcol IID] [--samples IDS_FILE] [--notebook tractor.ipynb] \
      [--count-threshold 20] [--det-tol 1e-6] [--chunksize 1000]

Inputs
  PREFIX.anc0.hapcount.txt[.gz], PREFIX.anc0.dosage.txt[.gz], PREFIX.anc1.dosage.txt[.gz]
      Output of Tractor's extract_tracts.py with --num-ancs 2 (one row per variant:
      CHROM POS ID REF ALT, then one column per VCF sample). PREFIX.anc1.hapcount is read
      only for the first chunk, to check that every haplotype was assigned to exactly one
      of the two ancestries.
  TABLE
      Whitespace-separated table with a header: a sample ID column (--sampleidcol), the
      phenotype columns (--phenocol) and the covariate columns (--covarcollist). Samples
      with a missing value in any of these columns are dropped. An intercept is added, so
      the covariates must not include a constant column.
  IDS_FILE (optional)
      Sample IDs to analyse (first column, one per line), e.g. the union of the party
      split. The script stops if any of them is absent from the hapdose files or lacks a
      complete row in TABLE, so that the sample set is exactly the one requested.

The model is y ~ 1 + covariates + A + X_anc0 + X_anc1, with A the anc0 haplotype count
(Tractor's two-way model; run_tractor.R fits the same one). SNPs are processed in chunks
of --chunksize; each chunk is passed to the notebook's precompute_tractor_stats and
tractor_from_precomputed exactly as the notebook calls them, so the results equal a single
call on all SNPs. --count-threshold / --det-tol have the notebook's meaning and the
values the sfgwas config uses for tractor_count_threshold / tractor_det_tol
(count threshold <= 0 disables the count filter).

Outputs
  OUT.<phenotype>.tsv   one row per variant: CHROM POS ID REF ALT N, the dosage counts
                        used by the count filter, det, valid, then beta/se/p for A, anc0
                        and anc1 (NaN where valid is false).
  OUT.samples.txt       the sample IDs used, in the order of the hapdose files.
"""
import argparse
import gzip
import json
import os
import sys
import time

import numpy as np
import pandas as pd

VARIANT_COLS = ["CHROM", "POS", "ID", "REF", "ALT"]


def load_notebook_functions(path):
    nb = json.load(open(path))
    ns = {}
    for cell in nb["cells"]:
        src = "".join(cell["source"])
        if cell["cell_type"] == "code" and ("def precompute_tractor_stats" in src or "def tractor_from_precomputed" in src):
            exec(compile(src, f"{path}:cell", "exec"), ns)
    for fn in ("precompute_tractor_stats", "tractor_from_precomputed"):
        if fn not in ns:
            sys.exit(f"{path}: no cell defines {fn}")
    return ns["precompute_tractor_stats"], ns["tractor_from_precomputed"]


def find_file(prefix, anc, kind, required=True):
    for ext in (".txt.gz", ".txt"):
        p = f"{prefix}.anc{anc}.{kind}{ext}"
        if os.path.exists(p):
            return p
    if required:
        sys.exit(f"missing {prefix}.anc{anc}.{kind}.txt[.gz]")
    return None


def read_header(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as f:
        cols = f.readline().rstrip("\n").split("\t")
    if cols[:5] != VARIANT_COLS:
        sys.exit(f"{path}: header does not start with {' '.join(VARIANT_COLS)}")
    return cols[5:]


def reader(path, sample_pos, chunksize):
    """Yields (variant info DataFrame, int8 array chunk x n) for the selected sample columns."""
    usecols = list(range(5)) + [5 + i for i in sample_pos]
    dtype = {i: str for i in range(5)}
    dtype.update({5 + i: np.int8 for i in sample_pos})
    for chunk in pd.read_csv(path, sep="\t", header=None, skiprows=1, usecols=usecols, dtype=dtype,
                             chunksize=chunksize, engine="c"):
        info = chunk.iloc[:, :5].copy()
        info.columns = VARIANT_COLS
        # usecols ignores the order given, so select the sample columns in the requested order
        vals = chunk[[5 + i for i in sample_pos]].to_numpy(dtype=np.int8)
        yield info.reset_index(drop=True), vals


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--hapdose", required=True, help="prefix of the extract_tracts.py output files")
    ap.add_argument("--phenofile", required=True)
    ap.add_argument("--phenocol", required=True, help="comma-separated phenotype column names")
    ap.add_argument("--covarcollist", default="", help="comma-separated covariate column names")
    ap.add_argument("--sampleidcol", default="IID")
    ap.add_argument("--samples", help="file of sample IDs to analyse (first column)")
    ap.add_argument("--output", required=True, help="output prefix")
    ap.add_argument("--notebook", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tractor.ipynb"))
    ap.add_argument("--count-threshold", type=float, default=20)
    ap.add_argument("--det-tol", type=float, default=1e-6)
    ap.add_argument("--chunksize", type=int, default=1000,
                    help="SNPs per chunk; peak memory is roughly 100 bytes x samples x chunksize")
    args = ap.parse_args()

    precompute, from_precomputed = load_notebook_functions(args.notebook)

    if find_file(args.hapdose, 2, "dosage", required=False) or find_file(args.hapdose, 2, "hapcount", required=False):
        sys.exit(f"{args.hapdose}.anc2.* exists: this is a two-way analysis; collapse the MSP to two "
                 "ancestries and re-run extract_tracts.py with --num-ancs 2")
    f_hap0 = find_file(args.hapdose, 0, "hapcount")
    f_dos0 = find_file(args.hapdose, 0, "dosage")
    f_dos1 = find_file(args.hapdose, 1, "dosage")
    f_hap1 = find_file(args.hapdose, 1, "hapcount", required=False)

    hdr = read_header(f_hap0)
    for f in (f_dos0, f_dos1) + ((f_hap1,) if f_hap1 else ()):
        if read_header(f) != hdr:
            sys.exit(f"{f}: sample columns differ from {f_hap0}")
    if len(set(hdr)) != len(hdr):
        sys.exit(f"{f_hap0}: duplicate sample IDs in the header")

    phenos = [c for c in args.phenocol.split(",") if c]
    covs = [c for c in args.covarcollist.split(",") if c]
    table = pd.read_csv(args.phenofile, sep=r"\s+", dtype={args.sampleidcol: str})
    for c in [args.sampleidcol] + phenos + covs:
        if c not in table.columns:
            sys.exit(f"{args.phenofile}: no column {c!r}")
    if table[args.sampleidcol].duplicated().any():
        sys.exit(f"{args.phenofile}: duplicate sample IDs")
    table = table.set_index(args.sampleidcol)[phenos + covs].apply(pd.to_numeric, errors="coerce")
    complete = table.dropna()
    print(f"phenotype table: {len(table)} samples, {len(complete)} with complete {len(phenos)} phenotype(s) "
          f"and {len(covs)} covariate(s)")

    in_hap = set(hdr)
    if args.samples:
        want = [l.split()[0] for l in open(args.samples) if l.strip()]
        if len(set(want)) != len(want):
            sys.exit(f"{args.samples}: duplicate sample IDs")
        no_geno = [s for s in want if s not in in_hap]
        no_pheno = [s for s in want if s not in complete.index]
        if no_geno or no_pheno:
            sys.exit(f"{args.samples}: {len(no_geno)} ID(s) not in the hapdose files (e.g. {no_geno[:3]}), "
                     f"{len(no_pheno)} without a complete phenotype/covariate row (e.g. {no_pheno[:3]})")
        keep = set(want)
    else:
        keep = in_hap & set(complete.index)
    sample_pos = [i for i, s in enumerate(hdr) if s in keep]
    ids = [hdr[i] for i in sample_pos]
    n = len(ids)
    if n == 0:
        sys.exit("no samples left")

    Y = complete.loc[ids, phenos].to_numpy(float)
    Z = complete.loc[ids, covs].to_numpy(float).reshape(n, len(covs))
    const = [c for j, c in enumerate(covs) if np.ptp(Z[:, j]) == 0]
    if const:
        sys.exit(f"constant covariate(s) {const}: drop them (an intercept is added)")
    Z_reg = np.column_stack([np.ones(n), Z])
    rank = np.linalg.matrix_rank(Z_reg)
    if rank < Z_reg.shape[1]:
        sys.exit(f"[1 | covariates] has rank {rank} < {Z_reg.shape[1]} columns: drop collinear covariates")
    print(f"samples: {n} (of {len(hdr)} in the hapdose files); covariates incl. intercept: {Z_reg.shape[1]}")

    with open(f"{args.output}.samples.txt", "w") as f:
        f.write("\n".join(ids) + "\n")

    thr = args.count_threshold if args.count_threshold > 0 else None
    outs = {k: open(f"{args.output}.{k}.tsv", "w") for k in phenos}
    stat_cols = ["beta_A", "se_A", "p_A", "beta_anc0", "se_anc0", "p_anc0", "beta_anc1", "se_anc1", "p_anc1"]
    head = VARIANT_COLS + ["N", "haps_anc0", "alt_anc0", "haps_anc1", "alt_anc1", "det", "valid"] + stat_cols
    for f in outs.values():
        f.write("\t".join(head) + "\n")

    t0 = time.time()
    m = 0
    nvalid = {k: 0 for k in phenos}
    minp = {k: (np.inf, None) for k in phenos}
    gens = [reader(f, sample_pos, args.chunksize) for f in (f_hap0, f_dos0, f_dos1)]
    for ci, ((info, A), (info_m, M), (info_e, E)) in enumerate(zip(*gens)):
        if not (info.equals(info_m) and info.equals(info_e)):
            sys.exit(f"variant rows differ between the hapdose files in chunk {ci}")
        if ci == 0 and f_hap1:
            _, A1 = next(reader(f_hap1, sample_pos, args.chunksize))
            if A1.shape != A.shape or not np.all(A.astype(int) + A1 == 2):
                sys.exit("anc0 + anc1 haplotype counts are not 2 everywhere in the first chunk: some haplotypes "
                         "were assigned to neither ancestry (was the MSP collapsed to two ancestries?)")
        if A.min() < 0 or M.min() < 0 or E.min() < 0 or A.max() > 2 or (M > A).any() or (E > 2 - A).any():
            sys.exit(f"chunk {ci}: haplotype counts / dosages are inconsistent")
        stats = precompute(y=Y, Z=Z_reg, A=A.T.astype(float), X_AMR=M.T.astype(float), X_EUR=E.T.astype(float))
        r = from_precomputed(stats, count_threshold=thr, det_tol=args.det_tol)
        valid = np.asarray(r["valid"])
        for k_i, k in enumerate(phenos):
            cols = [r[f"{s}_{e}"][:, k_i] for e in ("A", "AMR", "EUR") for s in ("beta", "se", "p")]
            df = info.copy()
            df["N"] = n
            df["haps_anc0"] = r["n_AMR_haps"].astype(int)
            df["alt_anc0"] = r["alt_AMR"].astype(int)
            df["haps_anc1"] = r["n_EUR_haps"].astype(int)
            df["alt_anc1"] = r["alt_EUR"].astype(int)
            df["det"] = r["det"]
            df["valid"] = valid
            for name, v in zip(stat_cols, cols):
                df[name] = v
            df.to_csv(outs[k], sep="\t", header=False, index=False, float_format="%.10g", na_rep="NaN")
            nvalid[k] += int(valid.sum())
            pv = np.where(valid, np.fmin(r["p_AMR"][:, k_i], r["p_EUR"][:, k_i]), np.inf)
            if valid.any() and pv.min() < minp[k][0]:
                j = int(np.argmin(pv))
                minp[k] = (float(pv[j]), f"{info.CHROM[j]}:{info.POS[j]}")
        m += len(info)
        print(f"  {m} SNPs done ({time.time() - t0:.0f}s)", flush=True)

    for f in outs.values():
        f.close()
    for k in phenos:
        best = f", smallest ancestry-specific p = {minp[k][0]:.3g} at {minp[k][1]}" if minp[k][1] else ""
        print(f"{k}: {nvalid[k]}/{m} SNPs valid{best} -> {args.output}.{k}.tsv")


if __name__ == "__main__":
    main()
