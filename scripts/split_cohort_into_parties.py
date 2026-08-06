#!/usr/bin/env python3
"""
Split a single whole-cohort dataset (amr/) into two disjoint per-party subsets for the
sfgwas 2-party MPC simulation, WITHOUT touching the genotype files themselves.

Why this is safe: scripts/filterMatrixPgen.sh calls `plink2 --keep <sample_keep_file>
--indiv-sort none`, which filters a SHARED .pgen down to a party's individuals while
preserving the .pgen's own internal sample order. So both parties can point
geno_binary_file_prefix / snp_ids_file / snp_position_file / geno_block_size_file at the
SAME amr/geno files -- only sample_keep.txt needs to differ per party, and pheno.txt /
cov.txt need to be row-subsetted to match.

What this script does:
  1. Reads the canonical individual order from a .psam file (any one chromosome's --
     they must all share the same sample list, which pgen requires anyway).
  2. Splits that ordered individual list into two disjoint groups (default: first half /
     second half, in native order -- pass --shuffle-seed N for a randomized split instead).
  3. Writes party{1,2}/sample_keep.txt in plink2 --keep format (FID IID).
  4. Row-subsets pheno.txt and cov.txt to each party, in the SAME order plink2 will
     produce (native .psam order, restricted to that party's IDs) -- this is the part
     that's easy to get silently wrong by hand.
  5. If --pca is given, column-subsets it the same way: Qpc.txt is npc rows x n
     individuals columns (this pipeline's own cache format -- see gwas/gwas.go's
     pcaCacheFile / LoadMatrixFromFileFloat), so individuals are COLUMNS here, not rows,
     but the same per-party index set and native-.psam-order rule applies.

ASSUMPTION THIS SCRIPT DEPENDS ON: pheno.txt / cov.txt have exactly one row per
individual, IN THE ORDER plink2 would emit them, with NO id column -- this is what
LoadMatrixFromFile in gwas/utilities.go assumes. That order is either:
  - the raw .psam's own native order, if pheno/cov cover every individual in .psam, or
  - .psam's native order FILTERED DOWN to --whole-cohort-keep (plink2 --keep semantics:
    order preserved, non-members dropped), if pheno/cov were already produced from a
    LARGER raw genotype file than the cohort you're analyzing (e.g. .psam has more
    samples than pheno.txt because it spans populations beyond this cohort, and
    pheno/cov only cover the ones kept by an existing whole-cohort sample_keep.txt).
Pass --whole-cohort-keep in the second case. Either way the script asserts the resulting
count matches pheno/cov's row count and refuses to proceed if it doesn't -- that
mismatch is the one thing it CAN catch; it cannot detect a silent reordering, so
sanity-check a few rows by hand once (e.g. a covariate you can independently verify)
before trusting a full run.

Usage (amr/ as a sibling of the sfgwas repo, chromosome files named ch%d, and pheno/cov
already filtered from a larger raw .psam via an existing amr/sample_keep.txt):
  python3 scripts/split_cohort_into_parties.py \
    --psam ../amr/geno/ch1.psam \
    --whole-cohort-keep ../amr/sample_keep.txt \
    --pheno ../amr/pheno.txt --cov ../amr/cov.txt \
    --pca ../amr/Qpc.txt \
    --out-dir ../amr_split \
    [--split-ratio 0.5] [--shuffle-seed 12345]

Then point configLocal.Party1.toml / Party2.toml (paths relative to the sfgwas repo root,
since that's where you run go run sfgwas.go from) at:
  geno_binary_file_prefix = "../amr/geno/ch%d"        (SAME for both parties)
  snp_ids_file            = "../amr/snp_ids.txt"       (SAME for both parties)
  snp_position_file       = "../amr/snp_pos.txt"       (SAME for both parties)
  geno_block_size_file    = "../amr/chrom_sizes.txt"   (SAME for both parties)
  sample_keep_file        = "../amr_split/party1/sample_keep.txt"  (party1 only)
  pheno_file              = "../amr_split/party1/pheno.txt"        (party1 only)
  covar_file              = "../amr_split/party1/cov.txt"          (party1 only)
  # ... and ../amr_split/party2/... for party 2
And copy amr_split/party{1,2}/Qpc.txt into each party's cache_dir (alongside gkeep.txt)
so use_cached_pca=true picks it up.
"""
import argparse
import os
import random
import sys


def read_psam_ids(psam_path):
    with open(psam_path) as f:
        header = None
        rows = []
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                header = line.lstrip("#").split("\t")
                if len(header) == 1:
                    header = line.lstrip("#").split()
                continue
            rows.append(line.split("\t") if "\t" in line else line.split())

    if header is None:
        sys.exit(f"no header line (starting with #) found in {psam_path}")

    header_lc = [h.upper() for h in header]
    try:
        iid_idx = header_lc.index("IID")
    except ValueError:
        sys.exit(f"no IID column found in {psam_path} header: {header}")
    fid_idx = header_lc.index("FID") if "FID" in header_lc else None

    ids = []
    for r in rows:
        iid = r[iid_idx]
        fid = r[fid_idx] if fid_idx is not None else iid
        ids.append((fid, iid))

    if not ids:
        sys.exit(f"no individuals parsed from {psam_path} -- check the file format")

    # has_fid matters downstream: a .psam with no real FID column (header is just #IID,
    # like an FID-less dataset) means plink2's internal sample-ID space for this file is
    # IID-only. Writing a synthesized 2-column FID=IID --keep file then does NOT match
    # plink2's internal IDs and silently keeps zero samples -- the keep file's column
    # count needs to mirror the .psam's, not just look superficially valid.
    has_fid = fid_idx is not None
    return ids, has_fid


def read_keep_list(path):
    """Parse a plink2 --keep-style file: 'IID' per line, or 'FID IID' per line.
    Returns (is_two_col, entries) -- entries are IID strings if one column, else (FID,IID)
    tuples. Matching by (FID,IID) when only IID was given would silently match nothing
    (or the wrong rows) whenever a psam's FID != IID, so callers must branch on this."""
    rows = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            rows.append(line.split("\t") if "\t" in line else line.split())

    ncols = {len(r) for r in rows}
    if len(ncols) > 1:
        sys.exit(f"FATAL: {path} has inconsistent column counts per line ({ncols}) -- fix the file")

    is_two_col = ncols == {2} or ncols == {3}  # tolerate a trailing 3rd column, ignored
    entries = [(r[0], r[1]) for r in rows] if is_two_col else [r[0] for r in rows]
    return is_two_col, entries


def read_matrix(path):
    with open(path) as f:
        sniffer_line = f.readline()
        delim = "\t" if "\t" in sniffer_line else None  # None -> split() on any whitespace
        f.seek(0)
        rows = []
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            rows.append(line.split(delim) if delim else line.split())
    return rows


def write_matrix(path, rows, delim="\t"):
    with open(path, "w") as f:
        for r in rows:
            f.write(delim.join(r) + "\n")


def read_csv_matrix(path):
    with open(path) as f:
        rows = [line.rstrip("\n").split(",") for line in f if line.strip()]
    ncols = len(rows[0])
    for i, r in enumerate(rows):
        if len(r) != ncols:
            sys.exit(f"FATAL: {path} row {i} has {len(r)} columns, expected {ncols} (ragged CSV)")
    return rows


def write_csv_matrix(path, rows):
    with open(path, "w") as f:
        for r in rows:
            f.write(",".join(r) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--psam", required=True, help="any one chromosome's .psam from the shared geno dataset")
    ap.add_argument("--whole-cohort-keep", default=None,
                     help="existing whole-cohort sample_keep.txt (e.g. amr/sample_keep.txt), if pheno/cov were "
                          "already filtered down from a LARGER raw .psam via plink2 --keep --indiv-sort none. "
                          "Omit if pheno/cov cover every individual in --psam directly.")
    ap.add_argument("--pheno", required=True, help="whole-cohort pheno.txt, one row per individual in .psam order")
    ap.add_argument("--cov", required=True, help="whole-cohort cov.txt, one row per individual in .psam order")
    ap.add_argument("--pca", default=None,
                     help="whole-cohort Qpc.txt (npc rows x n individuals columns, comma-delimited, "
                          "this pipeline's own cache format), individual order/columns matching .psam")
    ap.add_argument("--out-dir", required=True, help="output root; writes <out-dir>/party1/ and <out-dir>/party2/")
    ap.add_argument("--split-ratio", type=float, default=0.5, help="fraction of individuals assigned to party1 (default 0.5)")
    ap.add_argument("--shuffle-seed", type=int, default=None,
                     help="if set, shuffle individuals with this seed before splitting; default keeps native .psam order (first k -> party1)")
    args = ap.parse_args()

    ids, has_fid = read_psam_ids(args.psam)
    print(f"{len(ids)} individuals found in {args.psam} (native order); "
          f"{'FID+IID' if has_fid else 'IID-only (no FID column in .psam header)'}")

    if args.whole_cohort_keep:
        is_two_col, keep_entries = read_keep_list(args.whole_cohort_keep)
        keep = set(keep_entries)
        if is_two_col:
            print(f"{args.whole_cohort_keep} looks like FID+IID format; matching on both")
            filtered = [pair for pair in ids if pair in keep]
            found = set(filtered)
        else:
            print(f"{args.whole_cohort_keep} looks like IID-only format; matching on IID, ignoring FID")
            filtered = [pair for pair in ids if pair[1] in keep]
            found = {pair[1] for pair in filtered}
        missing = keep - found
        if missing:
            sample = sorted(missing)[:3]
            print(f"WARNING: {len(missing)} of {len(keep)} IDs in {args.whole_cohort_keep} were not found "
                  f"in {args.psam} (e.g. {sample}) -- plink2 --keep would silently drop these too, but this "
                  f"usually means the wrong .psam or keep file was passed. Double-check before proceeding.")
        ids = filtered
        print(f"{len(ids)} individuals remain after filtering by {args.whole_cohort_keep} "
              f"(native .psam order preserved, matching plink2 --keep --indiv-sort none)")

    n = len(ids)
    pheno_rows = read_matrix(args.pheno)
    cov_rows = read_matrix(args.cov)
    if len(pheno_rows) != n:
        sys.exit(f"FATAL: {args.pheno} has {len(pheno_rows)} rows, expected {n} "
                  f"(one per {'whole-cohort-keep-filtered' if args.whole_cohort_keep else '.psam'} individual). "
                  f"Do not proceed -- row alignment with genotypes cannot be assumed if this doesn't match.")
    if len(cov_rows) != n:
        sys.exit(f"FATAL: {args.cov} has {len(cov_rows)} rows, expected {n}. Do not proceed.")

    pca_rows = None
    if args.pca:
        pca_rows = read_csv_matrix(args.pca)
        npc, npc_cols = len(pca_rows), len(pca_rows[0])
        if npc_cols != n:
            sys.exit(f"FATAL: {args.pca} has {npc_cols} columns, expected {n} (one per .psam individual). "
                      f"If this looks like a plink2/flashpca eigenvec file instead (individuals as ROWS, "
                      f"with an ID column), it needs reshaping first -- do not proceed as-is.")
        print(f"{args.pca}: {npc} PCs x {npc_cols} individuals")

    order = list(range(n))
    if args.shuffle_seed is not None:
        random.Random(args.shuffle_seed).shuffle(order)
        print(f"shuffled with seed {args.shuffle_seed}")
    else:
        print("using native .psam order (no shuffle) -- first k individuals go to party1")

    k = round(n * args.split_ratio)
    party_indices = {1: sorted(order[:k]), 2: sorted(order[k:])}
    # sorted() above keeps each party's OWN individuals in ascending native-.psam-order --
    # matching exactly what `plink2 --keep ... --indiv-sort none` will output.

    for party, idxs in party_indices.items():
        pdir = os.path.join(args.out_dir, f"party{party}")
        os.makedirs(pdir, exist_ok=True)

        keep_path = os.path.join(pdir, "sample_keep.txt")
        with open(keep_path, "w") as f:
            # Column count must mirror the source .psam's: a 2-column FID+IID file
            # against an FID-less .psam (header is just #IID) matches zero samples,
            # because plink2's internal per-sample ID for that file has no FID part to
            # match against. Header line matches .psam's own #-prefixed convention.
            if has_fid:
                f.write("#FID\tIID\n")
                for i in idxs:
                    fid, iid = ids[i]
                    f.write(f"{fid}\t{iid}\n")
            else:
                f.write("#IID\n")
                for i in idxs:
                    _, iid = ids[i]
                    f.write(f"{iid}\n")

        write_matrix(os.path.join(pdir, "pheno.txt"), [pheno_rows[i] for i in idxs])
        write_matrix(os.path.join(pdir, "cov.txt"), [cov_rows[i] for i in idxs])

        wrote = "sample_keep.txt,pheno.txt,cov.txt"
        if pca_rows is not None:
            # pca_rows is npc x n -- subset COLUMNS i in idxs, one output row per PC.
            write_csv_matrix(os.path.join(pdir, "Qpc.txt"), [[row[i] for i in idxs] for row in pca_rows])
            wrote += ",Qpc.txt"

        print(f"party{party}: {len(idxs)} individuals -> {pdir}/{{{wrote}}}")

    print()
    print("Sanity check before trusting this: run plink2 on one chromosome for one party (pass the .pfile")
    print("PREFIX with no extension -- plink2 appends .pgen/.pvar/.psam itself) and confirm its output .psam")
    print("individual list matches sample_keep.txt's individuals in the same order, e.g.:")
    print(f"  plink2 --pfile {args.psam[:-len('.psam')] if args.psam.endswith('.psam') else '<geno_prefix>'} "
          f"--keep {args.out_dir}/party1/sample_keep.txt --indiv-sort none --make-just-psam --out /tmp/check_party1")
    # Column index of IID is the same on both sides: --make-just-psam preserves the
    # input .psam's FID-or-not column layout, same as sample_keep.txt mirrors it above.
    iid_col = "1" if not has_fid else "2"
    print(f"  diff <(tail -n +2 {args.out_dir}/party1/sample_keep.txt | cut -f{iid_col}) "
          f"<(tail -n +2 /tmp/check_party1.psam | cut -f{iid_col})")


if __name__ == "__main__":
    main()
