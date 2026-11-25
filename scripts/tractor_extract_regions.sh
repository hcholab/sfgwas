#!/usr/bin/env bash
# Runs the variant/sample filter (bcftools) and Tractor's extract_tracts.py on consecutive
# windows of one chromosome, several windows at a time. Both steps are single-threaded, and
# extract_tracts.py's time per variant grows faster than linearly with the number of
# samples, so this is what makes whole-chromosome runs practical.
#
# usage: scripts/tractor_extract_regions.sh -v VCF -m MSP -s SAMPLES -t TRACTOR_DIR -o OUTDIR
#            [-b START] [-e END] [-w WINDOW] [-j JOBS] [-q MAF]
#
#   -v  phased VCF, bgzipped and indexed (all samples; -s picks the ones to keep)
#   -m  two-way MSP whose haplotype columns follow SAMPLES' order
#       (tractor_prep.py split --msp-out)
#   -s  sample IDs to keep, in the MSP's order (split/all.ids); bcftools view -S puts the
#       samples in this order, so the VCF and MSP columns line up
#   -t  Tractor checkout (uses scripts/extract_tracts.py)
#   -o  output directory (must not exist yet); gets r<NNN>.anc*.txt.gz per non-empty window,
#       vcf/, logs/, windows.txt (window, region, SNPs after filtering) and prefixes.txt
#   -b/-e  range to cover (default: the MSP's first window start to its last window end).
#       Always clipped to the MSP's range: extract_tracts.py skips sites before the first
#       window but gives sites after the last one that window's ancestry calls.
#   -w  window length in bp (default 1000000)
#   -j  windows processed at once (default 12)
#   -q  minor allele frequency cutoff, computed on the kept samples (default 0.05)
#
# The chromosome name is taken from the MSP and must match the VCF's. Variants kept:
# biallelic SNPs with MAF >= -q. prefixes.txt lists the non-empty windows' output prefixes in
# genomic order, for tractor_plaintext.py / tractor_prep.py --hapdose $(cat OUTDIR/prefixes.txt).
# Set PYTHON to choose the Python that runs extract_tracts.py (default python3).
set -euo pipefail

VCF="" MSP="" SAMPLES="" TRACTOR="" OUT="" START="" END="" WINDOW=1000000 JOBS=12 MAF=0.05
while getopts "v:m:s:t:o:b:e:w:j:q:h" opt; do
  case $opt in
    v) VCF=$OPTARG ;; m) MSP=$OPTARG ;; s) SAMPLES=$OPTARG ;; t) TRACTOR=$OPTARG ;; o) OUT=$OPTARG ;;
    b) START=$OPTARG ;; e) END=$OPTARG ;; w) WINDOW=$OPTARG ;; j) JOBS=$OPTARG ;; q) MAF=$OPTARG ;;
    *) sed -n '2,29p' "$0"; exit 2 ;;
  esac
done
for v in VCF MSP SAMPLES TRACTOR OUT; do
  [ -n "${!v}" ] || { echo "missing -${v:0:1} (see -h)"; exit 2; }
done
[ -e "$OUT" ] && { echo "$OUT already exists: pick another -o"; exit 2; }
for f in "$VCF" "$MSP" "$SAMPLES" "$TRACTOR/scripts/extract_tracts.py"; do
  [ -f "$f" ] || { echo "missing $f"; exit 2; }
done
PY=${PYTHON:-python3}

# the MSP's chromosome and covered range [first window start, last window end)
read -r CHROM MSP_START _ < <(awk -F'\t' '!/^#/ {print $1, $2, $3; exit}' "$MSP")
MSP_END=$(tail -n 1 "$MSP" | cut -f3)
[ -n "$CHROM" ] && [ -n "$MSP_END" ] || { echo "$MSP: no data rows"; exit 2; }
if ! bcftools index -s "$VCF" | cut -f1 | grep -qx "$CHROM"; then
  echo "chromosome $CHROM (from the MSP) is not in $VCF's index; names must match (e.g. chr22 vs 22)"; exit 2
fi
LO=${START:-$MSP_START}; HI=${END:-$((MSP_END - 1))}
[ "$LO" -lt "$MSP_START" ] && LO=$MSP_START
[ "$HI" -gt $((MSP_END - 1)) ] && HI=$((MSP_END - 1))
[ "$LO" -le "$HI" ] || { echo "empty range $LO-$HI after clipping to the MSP's $MSP_START-$((MSP_END - 1))"; exit 2; }

mkdir -p "$OUT/vcf" "$OUT/logs"
OUT=$(cd "$OUT" && pwd)
echo "$CHROM:$LO-$HI in windows of $WINDOW bp, $JOBS at a time, MAF >= $MAF, $(wc -l < "$SAMPLES") samples"

one() { # id start end
  local tag v n
  tag=$(printf 'r%03d' "$1"); v="$OUT/vcf/$tag.vcf.gz"
  bcftools view -S "$SAMPLES" -r "$CHROM:$2-$3" -m2 -M2 -v snps "$VCF" -Ou 2> "$OUT/logs/$tag.bcftools.log" \
    | bcftools view -q "$MAF:minor" -Oz -o "$v" 2>> "$OUT/logs/$tag.bcftools.log"
  n=$(bcftools view -H "$v" | wc -l)
  if [ "$n" -gt 0 ]; then
    "$PY" "$TRACTOR/scripts/extract_tracts.py" --vcf "$v" --msp "$MSP" --num-ancs 2 \
      --output-dir "$OUT" --compress-output > "$OUT/logs/$tag.extract.log" 2>&1 \
      || { echo "$tag FAILED in extract_tracts.py (see $OUT/logs/$tag.extract.log)" >&2; return 1; }
  fi
  echo "$tag $CHROM:$2-$3 $n"
}
export -f one
export VCF MSP SAMPLES OUT CHROM MAF PY TRACTOR

id=0
for ((a = LO; a <= HI; a += WINDOW)); do
  b=$((a + WINDOW - 1)); [ "$b" -gt "$HI" ] && b=$HI
  id=$((id + 1)); echo "$id $a $b"
done > "$OUT/windows.todo"
status=0
xargs -P "$JOBS" -L 1 bash -c 'set -eo pipefail; one "$@"' _ < "$OUT/windows.todo" > "$OUT/windows.unsorted" || status=1
sort "$OUT/windows.unsorted" > "$OUT/windows.txt" && rm "$OUT/windows.unsorted" "$OUT/windows.todo"
awk -v d="$OUT" '$3 > 0 {print d "/" $1}' "$OUT/windows.txt" > "$OUT/prefixes.txt"

nwin=$(wc -l < "$OUT/windows.txt"); nsnp=$(awk '{s += $3} END {print s + 0}' "$OUT/windows.txt")
echo "$nwin/$id windows done, $(wc -l < "$OUT/prefixes.txt") with SNPs; $nsnp SNPs after filtering"
echo "(extract_tracts.py drops sites between MSP windows, so the Tractor files can hold a few fewer)"
[ $status -eq 0 ] || { echo "some windows FAILED: see the messages above and $OUT/logs"; exit 1; }
echo "prefixes: $OUT/prefixes.txt"
