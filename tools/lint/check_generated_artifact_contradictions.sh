#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
#
# Fail closed when generated evidence artifacts disagree. The capability
# inventory declares its consumed artifact in its own first record; the arm
# baseline declares the assertion and regeneration command in comment headers.
# No central artifact registry is consulted.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

GATE=check-generated-artifact-contradictions
CAP="${ZCL_ARTIFACT_CAPABILITY_INVENTORY:-}"
if [ -z "$CAP" ]; then
    mapfile -t cap_candidates < <(
        git grep -l '"artifact_id":"zcl.code_capability_inventory.v1"' -- \
            2>/dev/null | while IFS= read -r candidate; do
            first="$(sed -n '1p' "$candidate")"
            printf '%s\n' "$first" | grep -Fq \
                '"generated_artifact_schema":"zcl.generated_artifact.v1"' ||
                continue
            printf '%s\n' "$first" | grep -Fq \
                '"artifact_id":"zcl.code_capability_inventory.v1"' ||
                continue
            printf '%s\n' "$candidate"
        done
    )
    [ "${#cap_candidates[@]}" -eq 1 ] || {
        echo "[$GATE] UNPROVEN — capability artifact discovery found ${#cap_candidates[@]} candidates" >&2
        exit 1
    }
    CAP="${cap_candidates[0]}"
fi
ARM="${ZCL_ARTIFACT_ARM_BASELINE:-}"
if [ -z "$ARM" ] && [ -f "$CAP" ]; then
    ARM="$(sed -n '1s/.*"consumes":\[{"path":"\([^"]*\)".*/\1/p' "$CAP")"
fi
[ -n "$ARM" ] || {
    echo "[$GATE] UNPROVEN — $CAP declares no consumable arm artifact path" >&2
    exit 1
}
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-artifact-contradiction.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

unproven()
{
    echo "[$GATE] UNPROVEN — $*" >&2
    exit 1
}

contradiction()
{
    echo "[$GATE] CONTRADICTION — $*" >&2
    exit 1
}

require_exact_line()
{
    local file="$1" line="$2"
    [ -f "$file" ] || unproven "generated artifact absent: $file"
    grep -Fqx "$line" "$file" ||
        unproven "$file lacks self-describing header: $line"
}

check_artifacts()
{
    [ -f "$ARM" ] || unproven "generated arm artifact absent: $ARM"
    [ -f "$CAP" ] || unproven "generated capability artifact absent: $CAP"
    require_exact_line "$ARM" \
        '# z23-generated-artifact: zcl.generated_artifact.v1'
    require_exact_line "$ARM" \
        '# artifact-id: zcl.arm_symbol_single_baseline.v1'
    require_exact_line "$ARM" \
        '# asserts: multi_arm_definition(path,symbol)'
    require_exact_line "$ARM" \
        '# generated-by: tools/lint/check_arm_symbol_single.sh'
    require_exact_line "$ARM" \
        '# regenerate: ZCL_LINT_MODE=UPDATE tools/lint/check_arm_symbol_single.sh'

    local meta
    meta="$(sed -n '1p' "$CAP")"
    for claim in \
        '"generated_artifact_schema":"zcl.generated_artifact.v1"' \
        '"artifact_id":"zcl.code_capability_inventory.v1"' \
        '"generated_by":"tools/gen_capability_inventory.c"' \
        '"regenerate":"make docs-capability-inventory"' \
        '"path":"tools/lint/arm_symbol_single_baseline.txt"' \
        '"artifact_id":"zcl.arm_symbol_single_baseline.v1"' \
        '"asserts":"multi_arm_definition(path,symbol)"'; do
        printf '%s\n' "$meta" | grep -Fq "$claim" ||
            unproven "$CAP lacks declared generated-artifact edge: $claim"
    done

    if [ "${ZCL_ARTIFACT_SKIP_FRESHNESS:-0}" != "1" ]; then
        if ! ZCL_ARM_SYMBOL_BASELINE="$ARM" ZCL_LINT_MODE=FAIL \
                tools/lint/check_arm_symbol_single.sh >"$WORK/arm.log" 2>&1; then
            sed -n '1,80p' "$WORK/arm.log" >&2
            unproven "$ARM is stale or its generator could not prove freshness"
        fi
        if ! tools/lint/check_capability_inventory_generated.sh \
                >"$WORK/cap.log" 2>&1; then
            sed -n '1,80p' "$WORK/cap.log" >&2
            unproven "$CAP is stale or its generator could not prove freshness"
        fi
    fi

    awk -F '\t' 'NF == 2 && $0 !~ /^#/ { print $1 "\t" $2 }' "$ARM" |
        LC_ALL=C sort -u >"$WORK/baseline.tsv"
    [ -s "$WORK/baseline.tsv" ] ||
        unproven "$ARM asserts no rows; absence is not agreement"

    sed -n 's/^{"record":"multi_arm_symbol","header":"\([^"]*\)","symbol":"\([^"]*\)","source_path":"\([^"]*\)","definition_arm_count":\([0-9][0-9]*\),"aggregate_definition":"\([^"]*\)","aggregate_constant_return":"\([^"]*\)".*/\1\t\3\t\2\t\4\t\5\t\6/p' \
        "$CAP" >"$WORK/multi.tsv"
    sed -n 's/^{"record":"definition_arm","header":"\([^"]*\)","symbol":"\([^"]*\)".*"path":"\([^"]*\)".*"constant_return_evidence":"\([^"]*\)".*"definition_scope":"\([^"]*\)","verdict":"\([^"]*\)".*/\1\t\3\t\2\t\4\t\5\t\6/p' \
        "$CAP" >"$WORK/arms.tsv"

    local header path symbol claimed aggregate_def aggregate_constant actual
    while IFS=$'\t' read -r header path symbol claimed aggregate_def aggregate_constant; do
        [ -n "$path" ] && [ -n "$symbol" ] ||
            unproven "$CAP emitted a multi-arm claim without an exact path/symbol"
        grep -Fqx "$path"$'\t'"$symbol" "$WORK/baseline.tsv" ||
            contradiction "$CAP says $path:$symbol is multi-arm but $ARM does not"
        actual="$(awk -F '\t' -v h="$header" -v p="$path" -v s="$symbol" \
            '$1 == h && $2 == p && $3 == s { n++ } END { print n + 0 }' "$WORK/arms.tsv")"
        [ "$actual" -ge 2 ] ||
            unproven "$path:$symbol has $actual inventory arm(s), but the consumed artifact asserts multiple definitions"
        [ "$claimed" -eq "$actual" ] ||
            contradiction "$path:$symbol claims $claimed arms but emits $actual"
        [ "$aggregate_def" = "UNPROVEN" ] &&
            [ "$aggregate_constant" = "UNPROVEN" ] ||
            contradiction "$path:$symbol collapses a multi-arm definition into an aggregate claim"
        if ! awk -F '\t' -v h="$header" -v p="$path" -v s="$symbol" '
            $1 == h && $2 == p && $3 == s &&
            ($4 == "parsed_definition_body" || $4 == "body_binding_UNPROVEN") &&
            $5 == "preprocessor_arm_UNPROVEN" && $6 == "UNPROVEN" { ok++ }
            END { exit !(ok >= 2) }
        ' "$WORK/arms.tsv"; then
            contradiction "$path:$symbol has an arm lacking an explicit UNPROVEN scope/evidence ceiling"
        fi
    done <"$WORK/multi.tsv"

    while IFS=$'\t' read -r header path symbol; do
        awk -F '\t' -v h="$header" -v p="$path" -v s="$symbol" \
            '$1 == h && $2 == p && $3 == s { found = 1 } END { exit !found }' \
            "$WORK/multi.tsv" ||
            contradiction "$CAP emits definition arms for $path:$symbol without a multi-arm aggregate row"
    done < <(awk -F '\t' '{ print $1 "\t" $2 "\t" $3 }' "$WORK/arms.tsv" |
             LC_ALL=C sort -u)

    local line
    while IFS= read -r line; do
        path="$(printf '%s\n' "$line" |
            sed -n 's/.*"definition":{"path":"\([^"]*\)".*/\1/p')"
        symbol="$(printf '%s\n' "$line" |
            sed -n 's/.*"symbol":"\([^"]*\)".*/\1/p')"
        grep -Fqx "$path"$'\t'"$symbol" "$WORK/baseline.tsv" || continue
        printf '%s\n' "$line" |
            grep -Fq '"multi_arm_definition":true,"definition_scope":"preprocessor_arm_UNPROVEN"' ||
            contradiction "$path:$symbol is reported as a constant stub without per-arm scope"
        printf '%s\n' "$line" | grep -Fq '"verdict":"UNPROVEN"' ||
            contradiction "$path:$symbol constant arm lacks an UNPROVEN verdict"
    done < <(grep '^{"record":"untested_invariant".*"constant_return_body":true' \
                   "$CAP" || true)

    echo "[$GATE] PASS ($(wc -l <"$WORK/multi.tsv" | tr -d ' ') exposed multi-arm symbols; artifacts fresh and compatible)"
}

selftest()
{
    local fixture="$WORK/self"
    mkdir -p "$fixture"
    printf '%s\n' \
        '# z23-generated-artifact: zcl.generated_artifact.v1' \
        '# artifact-id: zcl.arm_symbol_single_baseline.v1' \
        '# asserts: multi_arm_definition(path,symbol)' \
        '# generated-by: tools/lint/check_arm_symbol_single.sh' \
        '# regenerate: ZCL_LINT_MODE=UPDATE tools/lint/check_arm_symbol_single.sh' \
        $'a.c\tf' >"$fixture/arm.txt"
    printf '%s\n' \
        '{"record":"inventory","generated_artifact_schema":"zcl.generated_artifact.v1","artifact_id":"zcl.code_capability_inventory.v1","generated_by":"tools/gen_capability_inventory.c","regenerate":"make docs-capability-inventory","consumes":[{"path":"tools/lint/arm_symbol_single_baseline.txt","artifact_id":"zcl.arm_symbol_single_baseline.v1","asserts":"multi_arm_definition(path,symbol)"}]}' \
        '{"record":"multi_arm_symbol","header":"a.h","symbol":"f","source_path":"a.c","definition_arm_count":2,"aggregate_definition":"UNPROVEN","aggregate_constant_return":"UNPROVEN","verdict":"UNPROVEN"}' \
        '{"record":"definition_arm","header":"a.h","symbol":"f","definition":{"path":"a.c","line":1},"constant_return_evidence":"parsed_definition_body","constant_return_body":true,"constant_return_value":"false","definition_scope":"preprocessor_arm_UNPROVEN","verdict":"UNPROVEN"}' \
        '{"record":"definition_arm","header":"a.h","symbol":"f","definition":{"path":"a.c","line":9},"constant_return_evidence":"parsed_definition_body","constant_return_body":false,"constant_return_value":null,"definition_scope":"preprocessor_arm_UNPROVEN","verdict":"UNPROVEN"}' \
        '{"record":"untested_invariant","symbol":"f","definition":{"path":"a.c","line":1},"multi_arm_definition":true,"definition_scope":"preprocessor_arm_UNPROVEN","constant_return_body":true,"verdict":"UNPROVEN"}' \
        >"$fixture/cap.jsonl"
    ZCL_ARTIFACT_SKIP_FRESHNESS=1 \
    ZCL_ARTIFACT_ARM_BASELINE="$fixture/arm.txt" \
    ZCL_ARTIFACT_CAPABILITY_INVENTORY="$fixture/cap.jsonl" \
        "$0" >"$fixture/pass.log" 2>&1 || {
            sed -n '1,100p' "$fixture/pass.log" >&2
            echo "[$GATE] SELFTEST FAIL — compatible artifacts did not pass" >&2
            exit 1
        }
    mv "$fixture/arm.txt" "$fixture/arm.absent"
    if ZCL_ARTIFACT_SKIP_FRESHNESS=1 \
       ZCL_ARTIFACT_ARM_BASELINE="$fixture/arm.txt" \
       ZCL_ARTIFACT_CAPABILITY_INVENTORY="$fixture/cap.jsonl" \
            "$0" >"$fixture/absent.log" 2>&1; then
        echo "[$GATE] SELFTEST FAIL — absent artifact passed" >&2
        exit 1
    fi
    grep -Fq 'UNPROVEN' "$fixture/absent.log" || {
        echo "[$GATE] SELFTEST FAIL — absence was not named UNPROVEN" >&2
        exit 1
    }
    mv "$fixture/arm.absent" "$fixture/arm.txt"
    sed 's/"aggregate_constant_return":"UNPROVEN"/"aggregate_constant_return":"constant_false"/' \
        "$fixture/cap.jsonl" >"$fixture/conflict.jsonl"
    if ZCL_ARTIFACT_SKIP_FRESHNESS=1 \
       ZCL_ARTIFACT_ARM_BASELINE="$fixture/arm.txt" \
       ZCL_ARTIFACT_CAPABILITY_INVENTORY="$fixture/conflict.jsonl" \
            "$0" >"$fixture/conflict.log" 2>&1; then
        echo "[$GATE] SELFTEST FAIL — contradiction passed" >&2
        exit 1
    fi
    grep -Fq 'CONTRADICTION' "$fixture/conflict.log" || {
        echo "[$GATE] SELFTEST FAIL — conflict was not named CONTRADICTION" >&2
        exit 1
    }
    echo "[$GATE] SELFTEST PASS (compatible passes; absent is UNPROVEN; conflict is red)"
}

if [ "${1:-}" = "--selftest" ]; then
    selftest
else
    check_artifacts
fi
