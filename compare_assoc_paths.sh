#!/bin/bash
#
# End-to-end comparison of the two association-test implementations on example_data.
#
#   legacy — joint QR over the encrypted genotype matrix   (use_plain_mult_phase_3 = false)
#   plain  — lazy covariate projection via (Z'Z)^-1        (use_plain_mult_phase_3 = true)
#
# The two are mathematically equivalent, so the test is that they agree on assoc_*.txt
# within CKKS/fixed-point noise, and that the plain path is faster.
#
# QC and PCA are run ONCE up front and cached. This matters: PCA uses randomized power
# iteration, so without pinning it the two runs would be projecting out different PCs and
# any comparison would be meaningless.
#
# Usage:  ./compare_assoc_paths.sh [tolerance]      (default tolerance 1e-3)
#
set -euo pipefail

TOL="${1:-1e-3}"
NUM_MAIN_PARTY=2
CONFIG="config/gwas/configGlobal.toml"
RESULTS="compare_results"

command -v go >/dev/null || { echo "go not found on PATH" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "run this from the repository root" >&2; exit 1; }

BACKUP="$(mktemp)"
cp "$CONFIG" "$BACKUP"
restore() { cp "$BACKUP" "$CONFIG"; rm -f "$BACKUP"; }
trap restore EXIT

# set_flag <key> <value> — rewrite a top-level boolean in the global config.
set_flag() {
  local key="$1" value="$2"
  if grep -qE "^${key}[[:space:]]*=" "$CONFIG"; then
    sed -i.tmp -E "s|^${key}[[:space:]]*=.*|${key} = ${value}|" "$CONFIG" && rm -f "${CONFIG}.tmp"
  else
    printf '\n%s = %s\n' "$key" "$value" >> "$CONFIG"
  fi
}

# run_all_parties <stage> <label> — spawn one process per party, wait for all of them.
run_all_parties() {
  local stage="$1" label="$2"
  local pids=()
  echo ">>> [$label] RUN_STAGE=$stage"
  for i in $(seq 0 $NUM_MAIN_PARTY); do
    PID=$i PROTOCOL=gwas RUN_STAGE="$stage" go run sfgwas.go > "${RESULTS}/${label}_party${i}.log" 2>&1 &
    pids+=($!)
  done
  local rc=0
  for p in "${pids[@]}"; do
    wait "$p" || rc=$?
  done
  if [ "$rc" -ne 0 ]; then
    echo "!!! [$label] a party exited non-zero; see ${RESULTS}/${label}_party*.log" >&2
    exit "$rc"
  fi
}

mkdir -p "$RESULTS"
rm -rf cache out
mkdir -p cache out

# ---------------------------------------------------------------- QC + PCA (once)
set_flag use_cached_qc false
set_flag use_cached_pca false
run_all_parties "qc+pca" "setup"

# Both assoc runs now reuse the identical QC filter and identical PCs.
set_flag use_cached_qc true
set_flag use_cached_pca true

# ---------------------------------------------------------------- the two assoc paths
for variant in legacy plain; do
  case "$variant" in
    legacy) set_flag use_plain_mult_phase_3 false ;;
    plain)  set_flag use_plain_mult_phase_3 true  ;;
  esac

  # Force a real computation rather than a cache hit, so the timing is meaningful.
  rm -f cache/party*/assoc_cache_*

  start=$(date +%s)
  run_all_parties "all" "$variant"
  echo "    [$variant] wall time: $(( $(date +%s) - start ))s"

  for p in $(seq 1 $NUM_MAIN_PARTY); do
    for f in out/party${p}/assoc_*.txt; do
      [ -e "$f" ] || { echo "!!! [$variant] no assoc output in out/party${p}" >&2; exit 1; }
      cp "$f" "${RESULTS}/${variant}.party${p}.$(basename "$f")"
    done
  done
done

# ---------------------------------------------------------------- compare
echo
echo "=== legacy vs plain (tolerance ${TOL}) ==="
status=0
for legacy_file in "${RESULTS}"/legacy.party*.assoc_*.txt; do
  plain_file="${legacy_file/legacy./plain.}"
  label="$(basename "$legacy_file" | sed 's/^legacy\.//')"
  if [ ! -f "$plain_file" ]; then
    echo "MISSING  $label: no plain-path counterpart" >&2
    status=1
    continue
  fi
  paste "$legacy_file" "$plain_file" | awk -v tol="$TOL" -v label="$label" '
    {
      n++
      d = $1 - $2; if (d < 0) d = -d
      if (d > maxd) { maxd = d; maxline = NR }
      sum += d
      if (d > tol) bad++
      # running stats for a correlation between the two vectors
      sx += $1; sy += $2; sxx += $1*$1; syy += $2*$2; sxy += $1*$2
    }
    END {
      if (n == 0) { printf "EMPTY    %s\n", label; exit 1 }
      cov = sxy/n - (sx/n)*(sy/n)
      vx  = sxx/n - (sx/n)^2
      vy  = syy/n - (sy/n)^2
      r   = (vx > 0 && vy > 0) ? cov/sqrt(vx*vy) : 0
      printf "%-8s %s  n=%d  max|diff|=%.3e (line %d)  mean|diff|=%.3e  corr=%.9f  over-tol=%d\n", \
             (bad ? "FAIL" : "OK"), label, n, maxd, maxline, sum/n, r, bad+0
      exit (bad ? 1 : 0)
    }' || status=1
done

# Party 1 and party 2 decrypt the same global statistics; they must match exactly.
for p in $(seq 2 $NUM_MAIN_PARTY); do
  for f in "${RESULTS}"/plain.party1.assoc_*.txt; do
    other="${f/party1./party${p}.}"
    [ -f "$other" ] || continue
    if ! cmp -s "$f" "$other"; then
      echo "FAIL     $(basename "$f"): party1 and party${p} disagree" >&2
      status=1
    fi
  done
done

echo
[ "$status" -eq 0 ] && echo "PASS: the two paths agree within ${TOL}" || echo "FAIL: see above"
exit "$status"
