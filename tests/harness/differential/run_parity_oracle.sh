#!/usr/bin/env bash
# Sapling Groth16 differential parity oracle — build + replay.
#
#   run_parity_oracle.sh check    (default) rebuild verifier + assert every
#                                  verdict matches the frozen golden AND every
#                                  pairing Fp12 matches the frozen values.
#                                  rc!=0 on ANY mismatch (= a consensus-
#                                  affecting change).
#   run_parity_oracle.sh record    re-freeze the golden + the pairing values
#                                  from the CURRENT verifier (only after an
#                                  INTENTIONAL, replay-approved consensus
#                                  change — never to paper over a diff).
#   run_parity_oracle.sh list      print the vector manifest.
#   run_parity_oracle.sh bench [n] time naive vs fixed-base public-input paths
#                                  over n iterations (default 30).
#   run_parity_oracle.sh pairing [n]
#                                  differential the PAIRING itself: baseline vs
#                                  bls12_381_pairing_candidate, asserting Fp12
#                                  BIT equality (not verdict equality) on every
#                                  vector. This is the gate the pairing
#                                  restructure must clear.
#   run_parity_oracle.sh profile [n]
#                                  where the time goes: exact Fp-multiply
#                                  counts per phase (Miller loop / final
#                                  exponentiation / public-input MSM / the
#                                  to-affine inversions) plus per-phase wall
#                                  time. Builds TWICE — once linker-interposed
#                                  for exact counts, once clean for honest
#                                  absolute times.
#
# Builds the CURRENT in-tree consensus verifier (core/modules/sapling/src/bls12_381.c)
# straight from source, so any edit to that file is exercised on the next run.
set -euo pipefail
MODE="${1:-check}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BIN="${TMPDIR:-/tmp}/g16_parity_oracle.$$"
BINC="${TMPDIR:-/tmp}/g16_parity_oracle_counted.$$"

case "$MODE" in
    bench|pairing|profile) MAIN="$HERE/groth16_comb_bench.c" ;;
    *)                     MAIN="$HERE/groth16_parity_oracle.c" ;;
esac

SRCS=(
    "$MAIN"
    "$ROOT/core/modules/sapling/src/bls12_381.c"
    "$ROOT/core/modules/sapling/src/fr_avx512.c"
    "$ROOT/core/modules/crypto/src/blake2b.c"
    "$ROOT/platform/modules/base/src/safe_alloc.c"
    "$ROOT/platform/modules/base/src/log_level.c"
)
CFLAGS=(
    -std=c23 -O2 -march=x86-64-v3 -DZCL_TESTING
    -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
    -I"$HERE"
    -I"$ROOT/core/modules/sapling/include" -I"$ROOT/core/modules/crypto/include"
    -I"$ROOT/platform/modules/util/include" -I"$ROOT/platform/modules/base/include"
)

cc "${CFLAGS[@]}" "${SRCS[@]}" -o "$BIN"
trap 'rm -f "$BIN" "$BINC"' EXIT

# Both binaries silence the verifier's own reject-path logging themselves, so
# stderr here carries only mismatch / divergence diagnostics — never swallow it.
case "$MODE" in
    bench)
        "$BIN" comb "${2:-30}"
        ;;
    pairing)
        "$BIN" pairing "${2:-30}"
        ;;
    profile)
        # Pass 1: clean build — honest absolute wall times.
        echo "=== profile pass 1/2: uninstrumented (absolute times) ==="
        "$BIN" profile "${2:-30}"
        # Pass 2: linker-interposed fp_mont_mul_accel — exact multiply counts.
        # bls12_381.c reaches every Fp multiply through that one cross-TU
        # symbol, so --wrap counts it exactly with no edit to the frozen
        # consensus source.
        echo
        echo "=== profile pass 2/2: instrumented (exact Fp-multiply counts) ==="
        cc "${CFLAGS[@]}" -DZCL_FPMUL_COUNT \
           -Wl,--wrap=fp_mont_mul_accel "${SRCS[@]}" -o "$BINC"
        "$BINC" profile "${2:-30}"
        ;;
    *)
        "$BIN" "$MODE" "$HERE"
        ;;
esac
