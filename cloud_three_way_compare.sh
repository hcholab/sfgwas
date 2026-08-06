#!/bin/bash
#
# Assoc-test comparison (plain+Cholesky vs. plain+Eigen) for a large dataset that already
# has QC + PCA cached, run as 3 local processes on one cloud VM. Adapted from
# compare_assoc_paths.sh + the local three-way run, with three changes:
#
#   1. QC and PCA are NEVER (re)computed -- this script assumes cache/party*/gkeep.txt
#      and cache/party*/Qpc.txt are already sitting on disk, produced elsewhere, and
#      fails fast with a clear message if they're missing or look inconsistent.
#   2. The legacy (fully-encrypted joint-QR) path is skipped entirely -- at this dataset's
#      scale it takes ~17h for phase 3 alone, and it isn't needed to compare Cholesky vs.
#      Eigen against each other or against the oracle. Both compared variants already use
#      plain-mult; run_variant still has a "legacy" case if you ever want it standalone.
#   3. Everything is sized for "this may take a long time" -- explicit timeouts you
#      control, an optional smoke-test pass on a handful of blocks first, and an
#      optional fast repeat-eigen mode that reuses the (expensive) genotype-matmul
#      cache to just re-run the small, randomized covariate-orthogonalization step --
#      useful since we found EigenDecomp's error is *run-dependent*, not fixed.
#
# Run this FROM THE REPO ROOT on the cloud VM, after editing the CONFIG variable below
# (and configGlobal.toml / configLocal.Party*.toml) to point at your real dataset.
#
# Usage:
#   ./cloud_three_way_compare.sh preflight                 # sanity-check cache only, no compute
#   ./cloud_three_way_compare.sh smoke   [tol]              # cholesky+eigen on SMOKE_BLOCKS only
#   ./cloud_three_way_compare.sh full    [tol] [oracle_timeout]   # the real comparison run
#   ./cloud_three_way_compare.sh eigen-repeat N [reuse_geno_cache=1]  # re-run eigen N times, cheaply
#
set -uo pipefail

CONFIG="config/gwas/configGlobal.toml"          # <-- point this at your cloud config if different
NUM_MAIN_PARTY=2
RESULTS="compare_results/cloud_$(date +%Y%m%d_%H%M%S)"
SMOKE_BLOCKS="[0,1]"                            # first two blocks only (0-indexed), for the smoke pass

MODE="${1:-}"
TOL="${2:-1e-3}"
# $3 means different things per mode (smoke/full: oracle_timeout: eigen-repeat: reuse_geno_cache)
# -- only smoke/full read it as a timeout, so don't set this from $3 unconditionally here.
ORACLE_TIMEOUT="60m"
[ "$MODE" = smoke ] || [ "$MODE" = full ] && ORACLE_TIMEOUT="${3:-60m}"

[ -f "$CONFIG" ] || { echo "run this from the repo root ($CONFIG not found)" >&2; exit 1; }

set_flag() {
  local key="$1" value="$2"
  if grep -qE "^${key}[[:space:]]*=" "$CONFIG"; then
    sed -i.tmp -E "s|^${key}[[:space:]]*=.*|${key} = ${value}|" "$CONFIG" && rm -f "${CONFIG}.tmp"
  else
    printf '\n%s = %s\n' "$key" "$value" >> "$CONFIG"
  fi
}
get_flag() { grep -E "^${1}[[:space:]]*=" "$CONFIG" | sed -E "s|^${1}[[:space:]]*=[[:space:]]*||"; }
get_local_flag() { grep -E "^${1}[[:space:]]*=" "config/gwas/configLocal.Party${2}.toml" | sed -E "s/^${1}[[:space:]]*=[[:space:]]*\"(.*)\"/\1/"; }

# ---------------------------------------------------------------- preflight
preflight() {
  echo "=== preflight: cache sanity check (no computation) ==="
  local num_snps num_pcs ok=1
  num_snps=$(get_flag num_snps)
  num_pcs=$(get_flag num_pcs_to_remove)
  echo "configGlobal: num_snps=$num_snps  num_pcs_to_remove=$num_pcs"

  # Parties must NOT share cache_dir/output_dir -- a copy-paste mistake when hand-editing
  # near-identical configLocal.PartyN.toml files (easy to make, and per-party dimension
  # checks below can't catch it if party sample counts happen to match, e.g. an even
  # split). Two processes racing os.Create on the same file produces exactly the kind of
  # intermittent "wrong number of fields" corruption this preflight exists to prevent.
  local seen_cache="" seen_out=""
  for p in $(seq 1 $NUM_MAIN_PARTY); do
    local this_cache this_out
    this_cache=$(get_local_flag cache_dir "$p")
    this_out=$(get_local_flag output_dir "$p")
    if [ -n "$seen_cache" ] && grep -qxF "$this_cache" <<<"$seen_cache"; then
      echo "FAIL     party$p: cache_dir ($this_cache) is shared with an earlier party -- must be unique per party" >&2
      ok=0
    fi
    if [ -n "$seen_out" ] && grep -qxF "$this_out" <<<"$seen_out"; then
      echo "FAIL     party$p: output_dir ($this_out) is shared with an earlier party -- must be unique per party" >&2
      ok=0
    fi
    seen_cache="${seen_cache}${this_cache}"$'\n'
    seen_out="${seen_out}${this_out}"$'\n'
  done

  local ref_lines=""
  for p in $(seq 1 $NUM_MAIN_PARTY); do
    local cache_dir
    cache_dir=$(get_local_flag cache_dir "$p")
    local gkeep="${cache_dir}/gkeep.txt" qpc="${cache_dir}/Qpc.txt"

    if [ ! -f "$gkeep" ]; then echo "MISSING  party$p: $gkeep" >&2; ok=0; continue; fi
    if [ ! -f "$qpc" ]; then echo "MISSING  party$p: $qpc" >&2; ok=0; continue; fi

    local n_lines n_qpc_rows n_qpc_cols
    n_lines=$(wc -l < "$gkeep")
    n_qpc_rows=$(wc -l < "$qpc")
    n_qpc_cols=$(head -1 "$qpc" | awk -F, '{print NF}')

    echo "party$p: gkeep.txt has $n_lines lines (want $num_snps) | Qpc.txt is ${n_qpc_rows} x ${n_qpc_cols} (want ${num_pcs} x <party${p}_individuals>)"

    [ "$n_lines" -eq "$num_snps" ] || { echo "FAIL     party$p: gkeep.txt line count != num_snps" >&2; ok=0; }
    [ "$n_qpc_rows" -eq "$num_pcs" ] || { echo "FAIL     party$p: Qpc.txt row count != num_pcs_to_remove" >&2; ok=0; }

    if [ -z "$ref_lines" ]; then
      ref_lines="$gkeep"
    elif ! cmp -s "$ref_lines" "$gkeep"; then
      echo "FAIL     party$p: gkeep.txt differs from party1's -- QC filter must be IDENTICAL across parties" >&2
      ok=0
    fi
  done

  command -v plink2 >/dev/null || { echo "WARN     plink2 not on PATH -- the pipeline and the oracle test both need it" >&2; }

  if [ "$ok" -eq 1 ]; then
    echo "OK: cache looks consistent. Set use_cached_qc/use_cached_pca=true and proceed."
  else
    echo "FAIL: fix the above before running anything -- these mismatches fail silently otherwise." >&2
    exit 1
  fi
}

# ---------------------------------------------------------------- run machinery
run_all_parties() {
  local stage="$1" label="$2"
  local pids=() i
  echo ">>> [$label] RUN_STAGE=$stage  $(date)"
  for i in $(seq 0 $NUM_MAIN_PARTY); do
    PID=$i PROTOCOL=gwas RUN_STAGE="$stage" go run sfgwas.go > "${RESULTS}/${label}_party${i}.log" 2>&1 &
    pids+=($!)
  done
  local rc=0
  for p in "${pids[@]}"; do wait "$p" || rc=$?; done
  return $rc
}

run_variant() {
  local variant="$1" clear_geno_cache="$2"
  case "$variant" in
    legacy)   set_flag use_plain_mult_phase_3 false; set_flag use_eigen_cov_ortho false ;;
    cholesky) set_flag use_plain_mult_phase_3 true;  set_flag use_eigen_cov_ortho false ;;
    eigen)    set_flag use_plain_mult_phase_3 true;  set_flag use_eigen_cov_ortho true  ;;
  esac

  if [ "$clear_geno_cache" -eq 1 ]; then
    for p in $(seq 1 $NUM_MAIN_PARTY); do
      rm -f "$(get_local_flag cache_dir "$p")"/assoc_cache_*
    done
  fi

  local start elapsed
  start=$(date +%s)
  if ! run_all_parties "all" "$variant"; then
    echo "!!! [$variant] a party exited non-zero; see ${RESULTS}/${variant}_party*.log" | tee -a "${RESULTS}/summary.log"
    return 1
  fi
  elapsed=$(( $(date +%s) - start ))
  echo "    [$variant] wall time: ${elapsed}s" | tee -a "${RESULTS}/summary.log"

  for p in $(seq 1 $NUM_MAIN_PARTY); do
    local out_dir
    out_dir=$(get_local_flag output_dir "$p")
    for f in "${out_dir}"/assoc_*.txt; do
      [ -e "$f" ] || { echo "!!! [$variant] no assoc output in ${out_dir}" | tee -a "${RESULTS}/summary.log"; return 1; }
      cp "$f" "${RESULTS}/${variant}.party${p}.$(basename "$f")"
    done
  done
  return 0
}

run_oracle() {
  local variant="$1"
  echo ">>> [$variant] oracle  $(date)" | tee -a "${RESULTS}/summary.log"
  go test ./tests/e2e_tests/ -run TestAssocPlaintextOracle -v -timeout "$ORACLE_TIMEOUT" \
    > "${RESULTS}/oracle_${variant}.log" 2>&1
  local rc=$?
  grep -E "phenotype [0-9]+:|--- (PASS|FAIL)|^(PASS|FAIL)|panic|SKIP" "${RESULTS}/oracle_${variant}.log" | tee -a "${RESULTS}/summary.log"
  # A skip exits 0 (go test doesn't treat it as a failure), which is exactly how a
  # hardcoded-path bug in the oracle test itself went unnoticed all day: every run
  # "passed" without ever actually comparing anything. Don't let that happen silently
  # again -- treat "no comparison happened" the same as "comparison failed" here.
  if grep -q "^--- SKIP" "${RESULTS}/oracle_${variant}.log"; then
    echo "!!! [oracle:$variant] SKIPPED, not validated -- treating as failure. See ${RESULTS}/oracle_${variant}.log" | tee -a "${RESULTS}/summary.log"
    rc=1
  fi
  echo "    [oracle:$variant] exit=${rc}" | tee -a "${RESULTS}/summary.log"
  return $rc
}

compare_pair() {
  local a="$1" b="$2"
  for fa in "${RESULTS}"/${a}.party*.assoc_*.txt; do
    [ -e "$fa" ] || continue
    local fb label
    fb="${fa/${a}./${b}.}"; label="$(basename "$fa" | sed "s/^${a}\.//")"
    [ -f "$fb" ] || { echo "MISSING  $a vs $b $label" | tee -a "${RESULTS}/summary.log"; continue; }
    paste "$fa" "$fb" | awk -v tol="$TOL" -v label="$label" -v a="$a" -v b="$b" '
      { n++; d=$1-$2; if(d<0)d=-d; if(d>maxd){maxd=d;maxline=NR}; sum+=d; if(d>tol)bad++
        sx+=$1;sy+=$2;sxx+=$1*$1;syy+=$2*$2;sxy+=$1*$2 }
      END { cov=sxy/n-(sx/n)*(sy/n); vx=sxx/n-(sx/n)^2; vy=syy/n-(sy/n)^2
        r=(vx>0&&vy>0)?cov/sqrt(vx*vy):0
        printf "%-8s %s vs %-8s %-16s n=%d max|diff|=%.3e(line %d) mean|diff|=%.3e corr=%.9f over-tol=%d\n", \
          (bad?"FAIL":"OK"),a,b,label,n,maxd,maxline,sum/n,r,bad+0 }' | tee -a "${RESULTS}/summary.log"
  done
}

# ---------------------------------------------------------------- modes
case "$MODE" in
  preflight)
    preflight
    ;;

  smoke|full)
    # Run preflight's cache/dir sanity checks unconditionally first, not just when someone
    # remembers to run `preflight` manually: the shared-cache_dir/output_dir mistake this
    # catches has now happened twice this session, each time costing 10+ minutes of compute
    # before surfacing as a confusing downstream symptom instead of failing immediately here.
    preflight

    mkdir -p "$RESULTS"
    set_flag use_cached_qc true
    set_flag use_cached_pca true
    [ "$MODE" = smoke ] && set_flag blocks_for_assoc_test "$SMOKE_BLOCKS" || set_flag blocks_for_assoc_test "[]"
    echo "=== $MODE run: $(date) ===" | tee "${RESULTS}/summary.log"

    # Stop here on failure rather than silently continuing to eigen: eigen reuses the
    # same threadId-keyed temp filenames (pgen_gfs.<id>.tmp etc.), so proceeding would
    # overwrite whatever cholesky's failed attempt left behind within minutes -- exactly
    # the trap that once made a stale-looking file look "fine" when it was actually
    # evidence from a later, unrelated run, not the one that failed.
    if ! run_variant cholesky 1; then
      echo "!!! cholesky failed -- stopping before eigen can overwrite its temp files. See ${RESULTS}/cholesky_party*.log" | tee -a "${RESULTS}/summary.log"
      exit 1
    fi
    run_oracle cholesky

    run_variant eigen 0 && run_oracle eigen   # reuses cholesky's geno-matmul cache (same inputs)

    echo | tee -a "${RESULTS}/summary.log"
    echo "=== pairwise (tolerance ${TOL}) ===" | tee -a "${RESULTS}/summary.log"
    compare_pair cholesky eigen
    echo "Results in $RESULTS"
    ;;

  eigen-repeat)
    N="${2:?usage: eigen-repeat N [reuse_geno_cache=1]}"
    REUSE="${3:-1}"
    mkdir -p "$RESULTS"
    set_flag use_cached_qc true
    set_flag use_cached_pca true
    set_flag use_plain_mult_phase_3 true
    set_flag use_eigen_cov_ortho true
    # Deliberately does NOT touch blocks_for_assoc_test -- respects whatever scope is
    # already in the config (e.g. a smoke subset left there for a fast reuse-cache check),
    # instead of forcing a full run every time.
    echo "=== eigen x${N} run-dependent-variance probe: $(date) ===" | tee "${RESULTS}/summary.log"
    for i in $(seq 1 "$N"); do
      [ "$REUSE" -eq 1 ] || rm -f cache/party*/assoc_cache_*
      run_variant "eigen_run${i}" 0
      run_oracle "eigen_run${i}"
    done
    echo "Results in $RESULTS -- diff oracle_eigen_run*.log to see whether accuracy is consistent or run-dependent."
    ;;

  *)
    echo "usage: $0 {preflight|smoke [tol]|full [tol] [oracle_timeout]|eigen-repeat N [reuse_geno_cache]}" >&2
    exit 1
    ;;
esac
