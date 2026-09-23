#!/usr/bin/env python3
"""Convert plink2 --glm linear regression output to the equivalent partial Pearson
correlation r, for direct comparison against sfgwas's association statistic.

plink2's T_STAT is a Wald t-statistic with df = OBS_CT - k, where k is the number of
fitted regressors: 1 (intercept -- plink2 always fits one, even if you never named it
in --covar-name) + number of named covariates + 1 (the SNP's own ADD term). Given t and
df, the partial correlation between the SNP and phenotype (after projecting out the same
covariates) is:

    r = t / sqrt(t^2 + df)

which is the same quantity sfgwas's plain/MPC pipeline reports (see gwas/assoc.go and
scripts/validate_against_plink2.py).

Usage:
  python3 scripts/glm_to_pearson.py \\
      --glm intermediate_results/amr_qc_gwas.LDL.glm.linear \\
      --ncovar 14 \\
      --out intermediate_results/amr_qc_gwas.LDL.r.tsv

  --ncovar is the count of names passed to --covar-name (do NOT include the intercept --
  it's added automatically). For the command in this conversation that's
  age_at_profile, sex_at_birth_name, sex_other, age_sq, pc1..pc10 = 14.

  Glob multiple phenotypes at once:
  python3 scripts/glm_to_pearson.py \\
      --glm 'intermediate_results/amr_qc_gwas.*.glm.linear' --ncovar 14 \\
      --out intermediate_results/amr_qc_gwas.all_r.tsv
"""
import argparse
import glob
import math
import re
import sys

import pandas as pd


def glm_to_r(path: str, ncovar: int) -> pd.DataFrame:
    df = pd.read_csv(path, sep="\t")
    df = df.rename(columns={"#CHROM": "CHROM"})
    df = df[df["TEST"] == "ADD"].copy()

    k = ncovar + 2  # + intercept + this SNP's own term
    df_resid = df["OBS_CT"] - k

    t = pd.to_numeric(df["T_STAT"], errors="coerce")
    df["r"] = t / (t.pow(2) + df_resid).pow(0.5)
    df["df_resid"] = df_resid

    m = re.search(r"\.([^.]+)\.glm\.linear$", path)
    df["PHENO"] = m.group(1) if m else ""

    return df[["CHROM", "POS", "ID", "PHENO", "OBS_CT", "df_resid", "T_STAT", "P", "r"]]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--glm", required=True, help="path to a .glm.linear file, or a glob matching several")
    ap.add_argument("--ncovar", type=int, required=True,
                     help="number of names passed to --covar-name (exclude the intercept)")
    ap.add_argument("--out", required=True, help="output TSV path")
    args = ap.parse_args()

    paths = sorted(glob.glob(args.glm)) if any(c in args.glm for c in "*?[") else [args.glm]
    if not paths:
        sys.exit(f"no files matched: {args.glm}")

    out = pd.concat([glm_to_r(p, args.ncovar) for p in paths], ignore_index=True)
    n_dropped = out["r"].isna().sum()
    if n_dropped:
        print(f"warning: {n_dropped} rows had no T_STAT (NA/singular) and got r=NaN", file=sys.stderr)

    out.to_csv(args.out, sep="\t", index=False)
    print(f"wrote {len(out)} rows ({out['PHENO'].nunique()} phenotype(s)) to {args.out}")


if __name__ == "__main__":
    main()
