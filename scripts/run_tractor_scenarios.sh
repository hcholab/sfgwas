#!/usr/bin/env bash
# Runs the 3-party Tractor protocol on synthetic scenarios and checks each one against
# the plaintext oracle (TestTractorOracle) and the reference notebook
# (scripts/compare_tractor_notebook.py).
#
# usage: scripts/run_tractor_scenarios.sh [-o OUTROOT] [-b BINARY] [-p PYTHON] [-j JOBS] [SCENARIO...]
#
#   -o  where scenario directories go (default: ./tractor_scenarios under the repo)
#   -b  sfgwas binary to run (default: build one into OUTROOT)
#   -p  Python with numpy+scipy for the notebook check (default: .venv/bin/python;
#       the check is skipped if it is missing)
#   -j  scenarios run concurrently (default 3; each uses 3 processes x local_num_threads)
#
# Scenarios (default: all):
#   a  n=40, 1 block                       (the historical tractor_fixture), thresholds 5 / 1e-9
#   b  n=40, 2 blocks                      5 / 1e-9
#   c  n=1,000                             5 / 1e-9
#   d  n=10,000, ~standardized phenotype   20 / 1e-6 (the notebook's values)
#   e  n=10,000, phenotype mean ~170, sd ~10 (height-like)   20 / 1e-6
#   f  n=1,000, 1% missing calls           5 / 1e-9
#   g  n=1,000, 2 blocks, QC on (SNP missingness/MAF and sample missingness filters,
#      exercised by extra missing calls and low-frequency SNPs)   5 / 1e-9
#   h  n=1,000 with low-frequency SNPs, 20 / 1e-6 (counts near the threshold)
#   i  as g, plus PCA (2 PCs as covariates)
#   j  as g, but SNP QC from precomputed genotype counts (use_precomputed_geno_count, the
#      path pgen inputs use; it has no sample filter)
#
# Each scenario directory holds fixture/, config/tractor/, a scripts symlink (QC/PCA
# shell out to scripts/ relative to the working directory), party logs, oracle.log and
# notebook.log. The script exits non-zero if any run or check fails.
set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTROOT="$REPO/tractor_scenarios"
BIN=""
PY="$REPO/.venv/bin/python"
JOBS=3
while getopts "o:b:p:j:h" opt; do
  case $opt in
    o) OUTROOT=$OPTARG ;;
    b) BIN=$OPTARG ;;
    p) PY=$OPTARG ;;
    j) JOBS=$OPTARG ;;
    *) sed -n '2,30p' "$0"; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -eq 0 ] && SCENARIOS=(a b c d e f g h i j)

mkdir -p "$OUTROOT"
OUTROOT=$(cd "$OUTROOT" && pwd)
if [ -z "$BIN" ]; then
  BIN="$OUTROOT/sfgwas"
  (cd "$REPO" && go build -o "$BIN" .) || { echo "build failed"; exit 1; }
fi
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

# name -> "generator flags|count_threshold|det_tol|qc|npcs"
spec() {
  case $1 in
    a) echo "-n1 20 -n2 20 -m 30|5|1e-9|off|0" ;;
    b) echo "-n1 20 -n2 20 -m 30 -nblocks 2|5|1e-9|off|0" ;;
    c) echo "-n1 500 -n2 500 -m 30|5|1e-9|off|0" ;;
    d) echo "-n1 5000 -n2 5000 -m 30 -ymean -0.9 -yscale 0.55|20|1e-6|off|0" ;;
    e) echo "-n1 5000 -n2 5000 -m 30 -ymean 170 -yscale 10|20|1e-6|off|0" ;;
    f) echo "-n1 500 -n2 500 -m 30 -missing 0.01|5|1e-9|off|0" ;;
    g) echo "-n1 500 -n2 500 -m 40 -nblocks 2 -missing 0.005 -bad-inds 0.05 -bad-snps 0.1 -rare 0.15|5|1e-9|blocks|0" ;;
    h) echo "-n1 500 -n2 500 -m 40 -rare 0.35 -seed 7|20|1e-6|off|0" ;;
    i) echo "-n1 500 -n2 500 -m 40 -nblocks 2 -missing 0.005 -bad-inds 0.05 -bad-snps 0.1 -rare 0.15|5|1e-9|blocks|2" ;;
    j) echo "-n1 500 -n2 500 -m 40 -nblocks 2 -missing 0.005 -bad-snps 0.1 -rare 0.15|5|1e-9|counts|0" ;;
    *) return 1 ;;
  esac
}

write_configs() { # dir index flags thr tol qc npcs
  local dir=$1 idx=$2 thr=$4 tol=$5 qc=$6 npcs=$7
  local fix="$dir/fixture" base=$((63000 + 100 * idx))
  local n1 n2 m nb
  n1=$(wc -l < "$fix/party1/pheno.txt"); n2=$(wc -l < "$fix/party2/pheno.txt")
  m=$(paste -sd+ "$fix/party1/geno_block_sizes.txt" | bc); nb=$(wc -l < "$fix/party1/geno_block_sizes.txt")
  local skip_qc=true gmiss=1.0 maf=0.0 imiss=1.0 precomp=false
  if [ "$qc" = blocks ]; then skip_qc=false; gmiss=0.1; maf=0.05; imiss=0.1; fi
  if [ "$qc" = counts ]; then skip_qc=false; gmiss=0.1; maf=0.05; precomp=true; fi
  local skip_pca=true
  [ "$npcs" -gt 0 ] && skip_pca=false
  mkdir -p "$dir/config/tractor"
  cat > "$dir/config/tractor/configGlobal.toml" <<EOF
num_main_parties = 2
hub_party_id = 1
debug = false
ckks_params = "PN14QP438"
phase = ""
mpc_num_threads = 4
mpc_field_size = 256
mpc_data_bits = 60
mpc_frac_bits = 30
div_sqrt_max_len = 1000000
mpc_boolean_shares = true
num_inds = [0, $n1, $n2]
num_snps = $m
num_covs = 2
cov_all_ones = false
geno_file_format = "blocks"
use_precomputed_geno_count = $precomp
geno_num_blocks = $nb
use_cached_qc = false
skip_qc = $skip_qc
imiss_ub = $imiss
het_lb = 0.0
het_ub = 1.0
gmiss = $gmiss
maf_lb = $maf
hwe_ub = 1e9
snp_dist_thres = 1
use_cached_pca = false
skip_pca = $skip_pca
iter_per_eigenval = 2
num_pcs_to_remove = $npcs
num_oversampling = 5
num_power_iters = 3
use_cached_combined_q = false
blocks_for_assoc_test = []
pgen_batch_nsnp = 8192
use_plain_mult_phase_3 = true
use_eigen_cov_ortho = false
use_high_prec_cov_ortho = false
use_tractor_phase_3 = true
tractor_count_threshold = $thr
tractor_det_tol = $tol
binding_ipaddr = "0.0.0.0"

[servers.party0]
ipaddr = "127.0.0.1"
ports = { party1 = "$((base + 20))", party2 = "$((base + 40))" }

[servers.party1]
ipaddr = "127.0.0.1"
ports = { party2 = "$((base + 60))" }

[servers.party2]
ipaddr = "127.0.0.1"
ports = {}
EOF
  for p in 0 1 2; do
    {
      echo "shared_keys_path = \"$REPO/example_data/keys\""
      if [ $p -gt 0 ]; then
        local d="$fix/party$p"
        cat <<EOF
geno_binary_file_prefix = "$d/geno"
geno_block_size_file = "$d/geno_block_sizes.txt"
pheno_file = "$d/pheno.txt"
covar_file = "$d/cov.txt"
snp_position_file = "$d/snp_pos.txt"
tractor_geno_prefix_a = "$d/tractor_a"
tractor_geno_prefix_amr = "$d/tractor_amr"
tractor_geno_prefix_eur = "$d/tractor_eur"
geno_count_file = "$d/all.gcount.transpose.bin"
assoc_num_blocks_parallel = 1
EOF
      fi
      echo "output_dir = \"out/party$p\""
      echo "cache_dir = \"cache/party$p\""
      echo "local_num_threads = 4"
      echo "memory_limit = 4000000000"
    } > "$dir/config/tractor/configLocal.Party$p.toml"
  done
}

run_one() { # name index
  local name=$1 idx=$2 s flags thr tol qc npcs
  s=$(spec "$name") || { echo "$name: unknown scenario"; return 1; }
  IFS='|' read -r flags thr tol qc npcs <<< "$s"
  local dir="$OUTROOT/$name"
  rm -rf "$dir"; mkdir -p "$dir"
  # shellcheck disable=SC2086
  (cd "$REPO" && go run ./scripts/gen_tractor_fixture -out "$dir/fixture" $flags) > "$dir/fixture.log" 2>&1 || { echo "$name: fixture generation failed"; return 1; }
  write_configs "$dir" "$idx" "$flags" "$thr" "$tol" "$qc" "$npcs"
  ln -sfn "$REPO/scripts" "$dir/scripts"

  local start rc=0 pids=()
  start=$(date +%s)
  for p in 0 1 2; do
    (cd "$dir" && PID=$p PROTOCOL=tractor RUN_STAGE=all timeout 30m "$BIN" > "party$p.log" 2>&1) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || rc=$?; done
  local elapsed=$(( $(date +%s) - start ))
  if [ $rc -ne 0 ]; then echo "$name: protocol run FAILED (exit $rc, ${elapsed}s); see $dir/party*.log"; return 1; fi

  local orc=0
  (cd "$REPO" && SFGWAS_TRACTOR_RUN_DIR="$dir" go test ./tests/e2e_tests/ -run 'TestTractorOracle$' -count=1 -v) > "$dir/oracle.log" 2>&1 || orc=1
  if grep -q -- "--- SKIP" "$dir/oracle.log"; then orc=1; echo "$name: oracle SKIPPED (no output?)"; fi
  local nrc=0 nb="skipped"
  if [ -x "$PY" ]; then
    "$PY" -I "$REPO/scripts/compare_tractor_notebook.py" "$dir" --notebook "$REPO/tractor.ipynb" > "$dir/notebook.log" 2>&1 || nrc=1
    nb=$([ $nrc -eq 0 ] && echo PASS || echo FAIL)
  fi
  echo "$name: run ${elapsed}s, oracle $([ $orc -eq 0 ] && echo PASS || echo FAIL), notebook $nb"
  grep -h "phenotype .*compared" "$dir/oracle.log" | sed 's/^ *tractor_oracle_test.go:[0-9]*: /    oracle: /'
  [ -f "$dir/notebook.log" ] && grep -h "pheno " "$dir/notebook.log" | sed 's/^/    notebook:/'
  [ $orc -eq 0 ] && [ $nrc -eq 0 ]
}

status=0
running=0
i=0
for name in "${SCENARIOS[@]}"; do
  run_one "$name" "$i" > "$OUTROOT/$name.summary" 2>&1 &
  i=$((i + 1)); running=$((running + 1))
  if [ $running -ge "$JOBS" ]; then wait -n || status=1; running=$((running - 1)); fi
done
while [ $running -gt 0 ]; do wait -n || status=1; running=$((running - 1)); done
for name in "${SCENARIOS[@]}"; do cat "$OUTROOT/$name.summary"; done
exit $status
