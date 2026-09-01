#!/usr/bin/env bash
# check-simd-os-support: a SIMD dispatch predicate may not ship without an
# OS-state check.
#
# THE BUG THIS EXISTS TO PREVENT
# -----------------------------
# CPUID reports what the SILICON can decode. It does not report whether the
# OS agreed to save the corresponding register state across a context switch.
# If it did not, the first wide instruction is #UD — the process takes a
# SIGILL even though CPUID said the feature was present. `noxsave`,
# `clearcpuid=avx512f`, and hypervisors that mask XCR0 all produce exactly
# that machine.
#
# core/modules/crypto/src/blake2b_avx2.c shipped with this bug: detect_features() read
# CPUID.7.0:EBX bit 5 and dispatched straight into the 4-way AVX2 compress with
# no XGETBV check at all. That code path is Equihash verification, so the fault
# would have landed on the consensus path on a host whose boot flags we do not
# control. Its AVX-512 arm, and the ones in keccak_x4.c and fr_avx512.c, DID
# read XCR0 — but executed XGETBV without first checking CPUID.1:ECX[27]
# OSXSAVE, and XGETBV is itself #UD when the OS has not enabled XSAVE. Checking
# the state word with an instruction that faults for the same reason the state
# word would have told you about is not a check.
#
# THE RULE
# --------
# Any source file that carries __attribute__((target("avx..."))) — i.e. that
# compiles wide instructions into the baseline binary and reaches them
# through runtime dispatch — must reach an OS-support check. Three forms
# count:
#   1. it includes "crypto/simd_dispatch.h" (the audited predicate: OSXSAVE
#      first, then CPUID, then the XCR0 state bits); or
#   2. it reads XCR0 itself AND names OSXSAVE, i.e. it made the whole check
#      locally — an `xgetbv` with no OSXSAVE guard does not count, because that
#      is the exact shape all three sites in this tree shipped with; or
#   3. it gates its dispatch on one of the DELEGATES below — a named
#      predicate defined in another file, which this gate then holds to
#      rule 1 or 2 in turn, so delegation cannot launder the requirement.
# Form 1 is strongly preferred: the pure policy functions there are unit
# tested against synthetic register words in tests/harness/src/test_simd_os_support.c,
# which is how the AVX-512-disabled machine gets covered without owning one.
#
# NOT in scope: target("sha,..."), target("sse..."), target("bmi2,adx").
# Those are XMM- or general-purpose-register instructions with no XSAVE state
# component beyond what 64-bit mode always enables, so CPUID alone settles
# them. The pattern below deliberately matches only `target("avx`.
#
# Mode: WARN | FAIL (controlled by ZCL_LINT_MODE; default FAIL).
set -euo pipefail

MODE="${ZCL_LINT_MODE:-FAIL}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

# Every tracked C source that compiles an AVX/AVX-512 target function.
mapfile -t avx_files < <(
    git grep -l -E '__attribute__\(\(target\("avx' -- '*.c' | sort -u
)

scanned=${#avx_files[@]}
gate_require_scanned "$scanned" 1 "check_simd_os_support" \
    "expected at least core/modules/crypto/src/blake2b_avx2.c to carry target(\"avx...\")"

# Delegated predicates: "<function name> <file that defines it>". The
# defining file is itself graded by checks_locally() below, so a delegate
# whose own OS check is removed re-arms this gate for every caller.
DELEGATES=(
    "keccak_x4_available core/modules/crypto/src/keccak_x4.c"
)

checks_locally() {
    local f="$1"
    grep -q 'crypto/simd_dispatch\.h' "$f" && return 0
    # A local check must be the WHOLE check: reading XCR0 is only legal once
    # OSXSAVE is confirmed, so a file that names xgetbv but never OSXSAVE has
    # written the faulting half and skipped the guarding half.
    if grep -qi 'xgetbv' "$f" && grep -qi 'osxsave' "$f"; then return 0; fi
    return 1
}

violations=0

# First: every delegate's defining file must itself hold the line.
for entry in "${DELEGATES[@]}"; do
    dfile="${entry##* }"
    dname="${entry%% *}"
    if [[ ! -f "$dfile" ]]; then
        echo "$dfile: delegate '$dname' names a file that no longer exists" >&2
        violations=$((violations + 1))
        continue
    fi
    if ! checks_locally "$dfile"; then
        echo "$dfile: defines delegate '$dname' but performs no OS-state check" >&2
        echo "    -> every caller that relies on it is now unguarded" >&2
        violations=$((violations + 1))
    fi
done

for f in "${avx_files[@]}"; do
    checks_locally "$f" && continue

    delegated=0
    for entry in "${DELEGATES[@]}"; do
        dname="${entry%% *}"
        if grep -q "$dname" "$f"; then delegated=1; break; fi
    done
    (( delegated )) && continue

    echo "$f: dispatches into target(\"avx...\") code with no OS-state check" >&2
    echo "    -> #include \"crypto/simd_dispatch.h\" and gate the dispatch on" >&2
    echo "       simd_host_has_avx2() / simd_host_has_avx512f()" >&2
    violations=$((violations + 1))
done

echo "[check_simd_os_support] scanned $scanned AVX dispatch file(s), $violations violation(s) (mode: $MODE)"
echo "[check_simd_os_support] CPUID says what the CPU decodes; XCR0 says what"
echo "[check_simd_os_support] the OS will save. Dispatching on the first alone"
echo "[check_simd_os_support] is a SIGILL on a host booted with the state off."

if (( violations > 0 )) && [[ "$MODE" == "FAIL" ]]; then
    exit 1
fi
exit 0
