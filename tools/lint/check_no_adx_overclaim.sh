#!/usr/bin/env bash
# check-no-adx-overclaim: a file may not advertise ADCX/ADOX carry chains that
# its own object code does not contain.
#
# WHAT WENT WRONG
# ---------------
# core/modules/sapling/src/bn254_accel.c and the BLS12-381 Fr/Fp tier in
# core/modules/sapling/src/fr_avx512.c both carried __attribute__((target("bmi2,adx")))
# and both described themselves as "BMI2+ADX (MULX+ADCX+ADOX)" —
# bn254_accel_implementation() returned that string into `zclassic23`'s boot
# banner. The target attribute only makes the compiler WILLING to emit
# ADCX/ADOX. Emitting them requires threading each _addcarryx_u64's returned
# carry into the next so that two INDEPENDENT carry chains (one on CF, one on
# OF) interleave through a multiply column. The code in both files passed a
# literal 0 carry-in to (nearly) every _addcarryx_u64 and folded carries with
# scalar adds instead.
#
# The measurement, not the argument: bn_fq_mont_mul_bmi2 compiled at
# -O2 -march=x86-64-v3 disassembled to 8 mulx, 4 adc, 24 add, 13 setb —
# and zero adcx, zero adox.
#
# An overclaim in a crypto tier banner is not cosmetic. It is the line an
# operator reads to decide whether a host is on the fast path, and the line a
# future optimiser reads to decide the work is already done.
#
# Both files have since been repaired (core/modules/sapling/src/mont_adx.h, inline asm
# with the two flag chains pinned to the two flags explicitly). This gate keeps
# them repaired and grades anything that joins them.
#
# THE RULE
# --------
# This gate does not grade prose against prose. For every lib/ source that
# either carries target(...adx...) or pulls in the shared ADX Montgomery
# header, it COMPILES the file and disassembles the object. If the source names
# ADCX/ADOX outside a negation but the emitted code contains neither
# instruction, that is a violation. Build the chains and the gate goes quiet on
# its own; write the claim without the instructions and it fires.
#
# The union of the two population rules matters: inline asm needs no target
# attribute, so a file could consume the shared header, inherit its banner
# string, and be graded by nothing at all if the population were the attribute
# alone.
#
# Fail-closed: if the compile or the disassembly cannot run, the gate exits 2
# (FATAL) rather than reporting a clean scan it never performed.
#
# Mode: WARN | FAIL (controlled by ZCL_LINT_MODE; default FAIL).
set -euo pipefail

MODE="${ZCL_LINT_MODE:-FAIL}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

extract_canonical_includes() {
    local output="$1" dest_name="$2"
    local -n dest="$dest_name"
    local line token candidate_count=0
    local -a fields=() candidate=()
    local all_include_flags

    dest=()
    while IFS= read -r line; do
        read -r -a fields <<< "$line"
        ((${#fields[@]} > 0)) || continue
        all_include_flags=1
        for token in "${fields[@]}"; do
            if [[ "$token" != -I?* ]]; then
                all_include_flags=0
                break
            fi
        done
        ((all_include_flags == 1)) || continue
        candidate=("${fields[@]}")
        candidate_count=$((candidate_count + 1))
    done <<< "$output"

    ((candidate_count == 1)) || return 2
    dest=("${candidate[@]}")
}

run_selftest() {
    local fixture
    local -a got=()

    fixture=$'gen_templates: 49 inputs -> generated.h (unchanged)\n-Icore/a/include -Iengine/b/include -Iplatform/c/include'
    extract_canonical_includes "$fixture" got
    [[ "${got[*]}" == "-Icore/a/include -Iengine/b/include -Iplatform/c/include" ]]

    fixture=$'make[1]: Entering directory /checkout\n-Ione -Itwo\ngen_templates: done'
    extract_canonical_includes "$fixture" got
    [[ "${#got[@]}" -eq 2 && "${got[0]}" == "-Ione" && "${got[1]}" == "-Itwo" ]]

    fixture=$'-Ione -Itwo\n-Ithree -Ifour'
    if extract_canonical_includes "$fixture" got; then
        echo "check_no_adx_overclaim: selftest FAILED — ambiguous include records were accepted" >&2
        return 1
    fi
    if extract_canonical_includes 'gen_templates: no canonical record' got; then
        echo "check_no_adx_overclaim: selftest FAILED — hollow include output was accepted" >&2
        return 1
    fi

    echo "check_no_adx_overclaim: selftest PASS — generator chatter ignored; ambiguous and hollow include records refused"
}

if [[ "${1:-}" == "--selftest" ]]; then
    run_selftest
    exit 0
fi
if (($# != 0)); then
    echo "usage: $0 [--selftest]" >&2
    exit 2
fi

CC="${CC:-cc}"
command -v "$CC" >/dev/null 2>&1 || {
    echo "check_no_adx_overclaim: FATAL — no C compiler ('$CC') to measure with." >&2
    exit 2
}
command -v objdump >/dev/null 2>&1 || {
    echo "check_no_adx_overclaim: FATAL — objdump not found; cannot read emitted code." >&2
    exit 2
}

# The population this gate grades: sources that use the ADX target attribute,
# plus sources that include the shared inline-asm Montgomery header (which
# carries the ADCX/ADOX chains without needing the attribute). Non-empty by
# construction today (bn254_accel.c, fr_avx512.c).
mapfile -t adx_files < <(
    {
        git grep -l -E '__attribute__\(\(target\("[^"]*adx' -- core engine contexts cognition platform || true
        git grep -l -E '#[[:space:]]*include[[:space:]]+"mont_adx\.h"' -- core engine contexts cognition platform || true
    } | sort -u
)

scanned=${#adx_files[@]}
gate_require_scanned "$scanned" 2 "check_no_adx_overclaim" \
    "expected at least core/modules/sapling/src/bn254_accel.c and core/modules/sapling/src/fr_avx512.c"

# Include path: every authority-owned module/include plus the shared roots, so
# a standalone -c of one file resolves its headers without the full Makefile.
# Make may first rebuild generated headers, whose progress records share
# stdout with print-includes. Select the one record made entirely of -I flags;
# accepting the first line silently graded five words of generator chatter.
include_output="$(make --no-print-directory -s print-includes)"
declare -a incs=()
if ! extract_canonical_includes "$include_output" incs; then
    echo "check_no_adx_overclaim: FATAL — print-includes did not emit exactly one canonical -I record." >&2
    exit 2
fi
gate_require_scanned "${#incs[@]}" 20 "check_no_adx_overclaim" \
    "canonical build include set came back hollow"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

violations=0
for f in "${adx_files[@]}"; do
    # Claim lines: name ADCX or ADOX. Drop the ones explicitly denying the
    # claim — an honest "does NOT build ADCX/ADOX chains" banner is a valid
    # steady state and must pass.
    claims=$(grep -n -E 'ADCX|ADOX|adcx|adox' "$f" \
             | grep -v -i -E 'not |never|no ADCX|no adcx|without |zero carry-in|literal 0|overclaim' \
             || true)
    [[ -z "$claims" ]] && continue

    # Measure the object the way the node ships it: same -std, same -O, and —
    # on x86 where the claim can even be true — the same -march as CFLAGS in
    # the Makefile. Grading a different build would grade code the operator
    # never runs. Off-x86 the ADX instructions do not exist in the ISA, so
    # the shipped build cannot contain them by construction; compile portable
    # and let the objdump scan below confirm zero adcx/adox.
    march_flags=(-march=x86-64-v3)
    if [[ "$(uname -m)" != x86_64 ]]; then
        march_flags=()
    fi
    obj="$tmpdir/$(basename "$f" .c).o"
    if ! "$CC" -std=c23 -O3 "${march_flags[@]}" "${incs[@]}" \
              -c -o "$obj" "$f" >"$tmpdir/cc.log" 2>&1; then
        echo "check_no_adx_overclaim: FATAL — could not compile $f to measure it." >&2
        sed 's/^/    /' "$tmpdir/cc.log" >&2
        exit 2
    fi

    emitted=$(objdump -d --no-show-raw-insn "$obj" \
              | grep -c -E '^[[:space:]]+[0-9a-f]+:[[:space:]]+(adcx|adox)[[:space:]]' \
              || true)

    if (( emitted > 0 )); then
        continue
    fi

    # Off x86 the ISA has no ADCX/ADOX, so a zero count is the tautology the
    # portability promise wants — the overclaim class this gate hunts can
    # only exist where the instruction exists.
    if [[ "${#march_flags[@]}" -eq 0 ]]; then
        continue
    fi

    echo "$f: names ADCX/ADOX but the compiled object contains none" >&2
    while IFS= read -r line; do
        [[ -n "$line" ]] && echo "    $line" >&2
    done <<< "$claims"
    echo "    -> pin the two carry chains in inline asm (core/modules/sapling/src/mont_adx.h)," >&2
    echo "       or report the tier honestly as \"BMI2 MULX\"" >&2
    violations=$((violations + 1))
done

echo "[check_no_adx_overclaim] scanned $scanned ADX-claiming file(s), $violations violation(s) (mode: $MODE)"
echo "[check_no_adx_overclaim] target(\"bmi2,adx\") buys MULX; ADCX/ADOX only"
echo "[check_no_adx_overclaim] materialise when a carry is threaded forward,"
echo "[check_no_adx_overclaim] and this gate reads the object file to check."

if (( violations > 0 )) && [[ "$MODE" == "FAIL" ]]; then
    exit 1
fi
exit 0
