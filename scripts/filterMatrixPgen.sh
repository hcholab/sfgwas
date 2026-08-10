#!/bin/sh
# Abort on the first failing command instead of silently continuing: without this, a
# failed plink2 (e.g. "not found") or python3 call still lets the script fall through to
# the next line, which then processes whatever .bed file happens to already be sitting at
# OUT_FILE from a PREVIOUS invocation -- producing a confusing downstream size-mismatch
# error instead of the real, actionable one.
set -e

PGEN_PREFIX=$1
NR=$2
NC=$3
ROW_FILT_FILE=$4
COL_FILT_FILE=$5
COL_NAMES_FILE=$6
COL_START_POS=$7
OUT_FILE=$8
N_THREADS=${9:-1}

python3 scripts/filterLines.py ${COL_NAMES_FILE} ${COL_FILT_FILE} ${COL_START_POS} ${OUT_FILE}.snps.txt
if [ ${#ROW_FILT_FILE} = 0 ]
then
    plink2 --threads ${N_THREADS} --pfile ${PGEN_PREFIX} --extract ${OUT_FILE}.snps.txt --indiv-sort none --make-bed --out ${OUT_FILE}
else
    plink2 --threads ${N_THREADS} --pfile ${PGEN_PREFIX} --keep ${ROW_FILT_FILE} --extract ${OUT_FILE}.snps.txt --indiv-sort none --make-bed --out ${OUT_FILE}
fi
python3 scripts/plinkBedToBinary.py ${OUT_FILE}.bed ${NR} ${NC} ${OUT_FILE}