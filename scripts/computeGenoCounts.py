#!/usr/bin/env python3

import numpy as np
import sys
import os

pgen_filename_template = sys.argv[1]  # e.g., "gwas_data_chr%d_wgs"
# Note the formatting string "%d",
# which will be replaced with "1", "2", ..., "22"

# Samples to keep, in a format expected by PLINK2 with the "--keep" flag
sample_keep_file = sys.argv[2]

# Output directory, will be created if it does not exist
out_dir = sys.argv[3]

# The six statistics, in the exact order gwas.ReadGenoStatsFromFile expects to find
# them as rows of the output binary. Selected BY NAME from each .gcount header rather
# than by a fixed column offset: plink2's --geno-counts column set is version- and
# cols=-dependent (e.g. POS is not always emitted), and a fixed slice silently yields
# a shifted -- or short -- table that only surfaces much later as an EOF partway
# through QC, or, worse, as a valid-looking run built on the wrong columns.
REQUIRED_COLS = [
    "HOM_REF_CT",
    "HET_REF_ALT_CTS",
    "TWO_ALT_GENO_CTS",
    "HAP_REF_CT",
    "HAP_ALT_CTS",
    "MISSING_CT",
]

# Set FORCE_PLINK2=1 to recompute counts even when a .gcount is already on disk.
# Off by default so that fixing up the aggregation step does not mean paying for
# 22 more plink2 passes over whole-genome data.
force_plink2 = os.environ.get("FORCE_PLINK2", "") == "1"

os.system(f"mkdir -p {out_dir}")

all_fname = os.path.join(out_dir, "all.gcount")
all_file = open(all_fname, "w")

per_chr = []

for chr in range(1, 23):
    pgen_prefix = pgen_filename_template % chr
    out_prefix = os.path.join(out_dir, f"chr{chr}")

    out_file = f"{out_prefix}.gcount"

    if force_plink2 or not os.path.exists(out_file):
        os.system(
            f"plink2 --threads 1 --pfile {pgen_prefix} --keep {sample_keep_file} --geno-counts --out {out_prefix}"
        )
        print(f"Geno counts computed for chromosome {chr}")
    else:
        print(f"Geno counts reused for chromosome {chr}: {out_file}")

    with open(out_file, "r") as fp:
        header = fp.readline()
        if not header:
            sys.exit(f"{out_file} is empty")

        names = header.lstrip("#").rstrip("\n").split("\t")
        missing = [c for c in REQUIRED_COLS if c not in names]
        if missing:
            sys.exit(
                f"{out_file}: header is missing required column(s) {missing}.\n"
                f"  header  : {names}\n"
                f"  required: {REQUIRED_COLS}\n"
                "Re-run plink2 with an explicit column set, e.g.\n"
                "  --geno-counts cols=chrom,pos,ref,alt,homref,refalt,altxy,hapref,hapalt,missing"
            )
        idx = [names.index(c) for c in REQUIRED_COLS]

        rows = []
        for line in fp:
            tok = line.rstrip("\n").split("\t")
            sel = [tok[i] for i in idx]
            all_file.write("\t".join(sel) + "\n")
            rows.append(sel)

    per_chr.append(np.array(rows, dtype=np.uint32))

    print(f"Geno counts for chromosome {chr} ({len(rows)} variants) added to: {all_fname}")

all_file.close()

x = np.concatenate(per_chr) if per_chr else np.empty((0, len(REQUIRED_COLS)), np.uint32)
del per_chr

print("Dimensions:", x.shape, x.dtype)

# The Go reader takes the row count on faith from config's num_snps and reads exactly
# 6 * 4 * num_snps bytes, so a wrong column count here is undetectable there until it
# runs off the end of the file. Fail now, where the cause is visible, instead.
if x.ndim != 2 or x.shape[1] != len(REQUIRED_COLS):
    sys.exit(f"expected {len(REQUIRED_COLS)} columns, got shape {x.shape}")

x = x.transpose()

print("After transpose:", x.shape, x.dtype)

all_bin_fname = f"{all_fname}.transpose.bin"
x.tofile(all_bin_fname)

print("Saved output binary file to:", all_bin_fname)
print(f"Set num_snps = {x.shape[1]} in configGlobal.toml "
      f"(binary is {x.shape[0] * 4 * x.shape[1]} bytes = 6 * 4 * num_snps)")
