#!/usr/bin/env python3
"""Independent accuracy check for a completed sfgwas run: recomputes the association
statistics with plink2's own --glm linear regression (covariates + PCs included) and
compares against out/party1/assoc_<i>.txt.

Why this exists: sfgwas's own oracle test (tests/e2e_tests/assoc_oracle_test.go) is an
independent *implementation* (Go, Gram-Schmidt) but not an independent *tool* -- it's
still code from this repo. This script cross-checks against plink2, a widely-used,
separately-developed GWAS tool, for a genuinely external reference point.

What it does, per chromosome:
  1. Exports each party's pgen to VCF (plink2 --export vcf)
  2. bcftools merges the two parties' VCFs (union of samples, same variants)
  3. Re-imports the merged VCF as pgen
Then concatenates all chromosomes' merged pgen filesets into one, builds a combined
pheno/covar file (covariates + cached PCs, jittered by <1e-6 so plink2 treats them as
quantitative rather than auto-detecting case/control), runs --glm, and converts each
SNP's T_STAT to a partial correlation r via r = t / sqrt(t^2 + df) -- the same quantity
sfgwas reports -- for direct comparison.

Requires: plink2, bcftools on PATH. Only tested against the pgen input path.

Usage:
  python3 scripts/validate_against_plink2.py \\
      --party1-prefix example_data/party1/geno/chr%d --party1-nchr 22 \\
      --party1-sample-keep example_data/party1/sample_keep.txt \\
      --party1-pheno example_data/party1/pheno.txt --party1-cov example_data/party1/cov.txt \\
      --party1-qpc cache/party1/Qpc.txt \\
      --party2-prefix example_data/party2/geno/chr%d \\
      --party2-sample-keep example_data/party2/sample_keep.txt \\
      --party2-pheno example_data/party2/pheno.txt --party2-cov example_data/party2/cov.txt \\
      --party2-qpc cache/party2/Qpc.txt \\
      --gkeep cache/party1/gkeep.txt --num-pcs 5 \\
      --assoc-dir out/party1 --out-dir /tmp/plink_validation
"""
import argparse
import csv
import math
import os
import subprocess
import sys


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        sys.exit(f"command failed: {' '.join(cmd)}\n{r.stdout}\n{r.stderr}")
    return r


def load_party(prefix_template, nchr, sample_keep, pheno_file, cov_file, qpc_file):
    ids = [line.split()[1] for line in open(sample_keep)]
    pheno = [line.split() for line in open(pheno_file)]
    cov = [line.split() for line in open(cov_file)]
    with open(qpc_file) as f:
        pcs = list(csv.reader(f))
    if not (len(ids) == len(pheno) == len(cov) == len(pcs[0])):
        sys.exit(f"row count mismatch: ids={len(ids)} pheno={len(pheno)} cov={len(cov)} qpc_cols={len(pcs[0])}")
    return {"ids": ids, "pheno": pheno, "cov": cov, "pcs": pcs, "id_to_row": {iid: i for i, iid in enumerate(ids)}}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for p in ("1", "2"):
        ap.add_argument(f"--party{p}-prefix", required=True, help="pgen prefix with %%d for chromosome number")
        ap.add_argument(f"--party{p}-nchr", type=int, default=22)
        ap.add_argument(f"--party{p}-sample-keep", required=True)
        ap.add_argument(f"--party{p}-pheno", required=True)
        ap.add_argument(f"--party{p}-cov", required=True)
        ap.add_argument(f"--party{p}-qpc", required=True)
    ap.add_argument("--gkeep", required=True, help="path to cache/party1/gkeep.txt (QC mask, all chromosomes concatenated)")
    ap.add_argument("--num-pcs", type=int, required=True)
    ap.add_argument("--assoc-dir", required=True, help="e.g. out/party1 -- where assoc_<i>.txt live")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--jitter", type=float, default=1e-6, help="phenotype jitter so plink2 treats it as quantitative")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    nchr = getattr(args, "party1_nchr")
    if getattr(args, "party2_nchr") != nchr:
        sys.exit("party1/party2 chromosome counts differ")

    p1 = load_party(args.party1_prefix, nchr, args.party1_sample_keep, args.party1_pheno, args.party1_cov, args.party1_qpc)
    p2 = load_party(args.party2_prefix, nchr, args.party2_sample_keep, args.party2_pheno, args.party2_cov, args.party2_qpc)
    parties = {1: p1, 2: p2}

    merged_prefixes = []
    for c in range(1, nchr + 1):
        for pid, prefix in ((1, args.party1_prefix), (2, args.party2_prefix)):
            pf = prefix % c
            run(["plink2", "--pfile", pf, "--export", "vcf", "bgz", "--out", f"{args.out_dir}/chr{c}_p{pid}"])
        for pid in (1, 2):
            run(["bcftools", "index", "-f", f"{args.out_dir}/chr{c}_p{pid}.vcf.gz"])
        run(["bcftools", "merge", f"{args.out_dir}/chr{c}_p1.vcf.gz", f"{args.out_dir}/chr{c}_p2.vcf.gz",
             "-Oz", "-o", f"{args.out_dir}/chr{c}_merged.vcf.gz"])
        run(["plink2", "--vcf", f"{args.out_dir}/chr{c}_merged.vcf.gz", "--make-pgen", "--out", f"{args.out_dir}/chr{c}_merged"])
        merged_prefixes.append(f"{args.out_dir}/chr{c}_merged")
        print(f"chr{c} merged", flush=True)

    with open(f"{args.out_dir}/merge_list.txt", "w") as f:
        f.write("\n".join(merged_prefixes) + "\n")
    run(["plink2", "--pmerge-list", f"{args.out_dir}/merge_list.txt", "--make-pgen", "--out", f"{args.out_dir}/allchr_merged"])

    merged_ids = []
    with open(f"{args.out_dir}/allchr_merged.psam") as f:
        next(f)
        for line in f:
            fid_iid = line.split()[0]
            merged_ids.append((fid_iid, fid_iid.split("_")[0]))

    import random
    random.seed(0)
    npc = args.num_pcs
    ncov = None
    pheno_rows, covar_rows = [], []
    for fid_iid, iid in merged_ids:
        owner = 1 if iid in p1["id_to_row"] else (2 if iid in p2["id_to_row"] else None)
        if owner is None:
            sys.exit(f"sample {iid} not found in either party -- sample_keep files may not match the genotype data")
        row = parties[owner]["id_to_row"][iid]
        pheno_vals = [float(v) + random.uniform(-args.jitter, args.jitter) for v in parties[owner]["pheno"][row]]
        cov_vals = parties[owner]["cov"][row]
        ncov = len(cov_vals)
        pc_vals = [parties[owner]["pcs"][k][row] for k in range(npc)]
        pheno_rows.append([fid_iid] + [str(v) for v in pheno_vals])
        covar_rows.append([fid_iid] + cov_vals + pc_vals)

    npheno = len(pheno_rows[0]) - 1
    with open(f"{args.out_dir}/pheno.txt", "w") as f:
        f.write("#IID\t" + "\t".join(f"PHENO{i+1}" for i in range(npheno)) + "\n")
        for r in pheno_rows:
            f.write("\t".join(r) + "\n")
    with open(f"{args.out_dir}/covar.txt", "w") as f:
        f.write("#IID\t" + "\t".join(f"COV{i+1}" for i in range(ncov)) + "\t" + "\t".join(f"PC{i+1}" for i in range(npc)) + "\n")
        for r in covar_rows:
            f.write("\t".join(r) + "\n")

    run(["plink2", "--pfile", f"{args.out_dir}/allchr_merged", "--pheno", f"{args.out_dir}/pheno.txt",
         "--covar", f"{args.out_dir}/covar.txt", "--glm", "hide-covar", "--covar-variance-standardize",
         "--out", f"{args.out_dir}/glm_result"])

    n = len(merged_ids)
    df_resid = n - ncov - npc - 1 - 1  # N - covariates - PCs - snp - intercept
    print(f"n={n}, df={df_resid}")

    gkeep = [int(l) for l in open(args.gkeep)]

    for i in range(npheno):
        glm_path = f"{args.out_dir}/glm_result.PHENO{i+1}.glm.linear"
        rows = [l.rstrip("\n").split("\t") for l in open(glm_path)][1:]
        if len(rows) != len(gkeep):
            sys.exit(f"variant count mismatch: glm has {len(rows)}, gkeep has {len(gkeep)} -- "
                     f"is --gkeep the mask for the SAME chromosome set/order used here?")
        plink_r = []
        for keep, row in zip(gkeep, rows):
            if not keep:
                continue
            t = row[13]
            plink_r.append(None if t == "NA" else t)

        assoc_path = os.path.join(args.assoc_dir, f"assoc_{i}.txt")
        sfgwas_r = [l.strip() for l in open(assoc_path)]
        if len(sfgwas_r) != len(plink_r):
            sys.exit(f"phenotype {i}: sfgwas has {len(sfgwas_r)} SNPs, plink2 (post-QC-filter) has {len(plink_r)}")

        max_diff, max_at, n_cmp = 0.0, -1, 0
        for j, (a, t) in enumerate(zip(sfgwas_r, plink_r)):
            if t is None:
                continue
            tt = float(t)
            r = tt / math.sqrt(tt * tt + df_resid)
            d = abs(float(a) - r)
            n_cmp += 1
            if d > max_diff:
                max_diff, max_at = d, j
        print(f"phenotype {i}: compared {n_cmp} SNPs, max|diff vs plink2|={max_diff:.4e} at row {max_at}")


if __name__ == "__main__":
    main()
