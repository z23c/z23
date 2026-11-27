# shellcheck shell=bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# dev_lib.sh — shared primitives that were byte-identical copies across the
# tools/dev/ dev-loop scripts. One canonical definition per function.
# Sourcing contract: no cwd/global side effects beyond defining the
# functions below. is_true() calls fail() on an unrecognized value — the
# sourcing script must already define fail() (all current callers do).
#
# The retrieval receipt validators below (uint_field, validate_metric,
# validate_eval_arm, validate_eval_arm_scope, validate_batch_scope,
# decode_base64) were byte-identical copies in the four
# tools/dev/retrieval-gold-*-receipt-check.sh scripts. They resolve fail(),
# field(), field_type(), keys_exact() and the metric_keys / eval_arm_keys
# values from the sourcing script at call time, so the sourcing script must
# define those helpers before first use (all current callers do). The two
# eval-arm variants differ in arity: validate_eval_arm takes four arguments
# (receipt-check, current-receipt-check), validate_eval_arm_scope takes the
# additional wrong-scope basis-points argument (scope-receipt-check,
# identifier-graph-receipt-check). validate_batch_scope keeps its historical
# "retrieval-gold-scope-receipt-check: scope bits:" refusal prefix verbatim —
# both former copies printed it.

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

is_uint() {
    [[ "${1:-}" =~ ^[0-9]+$ ]]
}

is_true()
{
    case "${1:-}" in
        1|true|yes|on) return 0 ;;
        0|false|no|off|"") return 1 ;;
        *) fail "expected boolean value, got: $1" ;;
    esac
}

# The BAKED source identity of a binary — its first `source_id_sha256`.
#
# `agentbuild` emits that key FOUR times on one line: once at the top level
# (what this binary was compiled from) and again inside nested runtime blocks
# that describe the dev lane as it exists right now. Because the payload is a
# single line, a `sed 's/.*"key":"\(...\)".*/\1/'` is greedy and returns the
# LAST occurrence — a runtime value — while `head -1` does nothing to help.
# That is not hypothetical: json_string_field reported the live daemon and the
# dev build as having identical identities on 2026-07-28, which is exactly the
# false "everything matches" a drift check must never produce. Anchor on the
# first occurrence and require 64 hex chars.
#
# Canonical home is here because two independent callers need the identical
# rule: tools/dev/agent-doctor.sh (human-run) and
# tools/scripts/build_drift_probe.sh (scheduled). A second copy of this
# function is a second chance to get the greedy-match bug back.
baked_source_id() {
    local bin="$1"
    [ -x "$bin" ] || return 0
    timeout 20 "$bin" agentbuild 2>/dev/null |
        grep -oE '"source_id_sha256"[[:space:]]*:[[:space:]]*"[0-9a-f]{64}"' |
        head -1 |
        grep -oE '[0-9a-f]{64}' || true
}

uint_field() {
    local value
    [[ $(field_type "$1" "$2") = number ]] || fail "not a number: $2"
    value=$(field "$1" "$2")
    [[ $value =~ ^(0|[1-9][0-9]*)$ ]] || fail "not a canonical integer: $2"
    ((${#value} < ${#3} || (${#value} == ${#3} && 10#$value <= 10#$3))) ||
        fail "integer exceeds bound: $2"
    printf '%s' "$value"
}

validate_metric() {
    local available
    keys_exact "$1" "$2" "$metric_keys"
    available=$(bool_field "$1" "$2.available")
    if [[ $available = true ]]; then
        uint_field "$1" "$2.basis_points" 10000 >/dev/null
    else
        [[ $(field_type "$1" "$2.basis_points") = null ]] ||
            fail "unavailable metric carries a value: $2"
    fi
}

validate_eval_arm() {
    local document=$1 arm=$2 expected_files=$3 expected_context=$4
    local actual_files actual_context actual_tokens
    keys_exact "$document" "$arm" "$eval_arm_keys"
    validate_metric "$document" "$arm.recall_at_5"
    validate_metric "$document" "$arm.recall_at_20"
    validate_metric "$document" "$arm.mrr"
    validate_metric "$document" "$arm.wrong_scope_at_5"
    [[ $(bool_field "$document" "$arm.wrong_scope_at_5.available") = false &&
       $(field_type "$document" "$arm.wrong_scope_at_5.basis_points") = null ]] ||
        fail "$arm wrong-scope overclaims unavailable evidence"
    actual_files=$(uint_field "$document" "$arm.task_unique_file_selections_at_5" 3840)
    actual_context=$(uint_field "$document" "$arm.projected_context_bytes_at_5" 9223372036854775807)
    actual_tokens=$(uint_field "$document" "$arm.approximate_tokens_at_5" 9223372036854775807)
    [[ $actual_files -eq $expected_files && $actual_context -eq $expected_context &&
       $actual_tokens -eq $(((expected_context + 3) / 4)) ]] ||
        fail "$arm aggregate cost formula differs"
}

validate_eval_arm_scope() {
    local document=$1 arm=$2 expected_files=$3 expected_context=$4 expected_wrong_bp=$5
    local actual_files actual_context actual_tokens
    keys_exact "$document" "$arm" "$eval_arm_keys"
    validate_metric "$document" "$arm.recall_at_5"
    validate_metric "$document" "$arm.recall_at_20"
    validate_metric "$document" "$arm.mrr"
    validate_metric "$document" "$arm.wrong_scope_at_5"
    [[ $(bool_field "$document" "$arm.wrong_scope_at_5.available") = true &&
       $(uint_field "$document" "$arm.wrong_scope_at_5.basis_points" 10000) -eq $expected_wrong_bp ]] ||
        fail "$arm wrong-directory-group metric differs"
    actual_files=$(uint_field "$document" "$arm.task_unique_file_selections_at_5" 3840)
    actual_context=$(uint_field "$document" "$arm.projected_context_bytes_at_5" 9223372036854775807)
    actual_tokens=$(uint_field "$document" "$arm.approximate_tokens_at_5" 9223372036854775807)
    [[ $actual_files -eq $expected_files && $actual_context -eq $expected_context &&
       $actual_tokens -eq $(((expected_context + 3) / 4)) ]] ||
        fail "$arm aggregate cost formula differs"
}

validate_batch_scope() {
    local candidate=$1 counts=$2
    awk '
        function refuse(message) {
            print "retrieval-gold-scope-receipt-check: scope bits: " message > "/dev/stderr"
            bad = 1
            exit 1
        }
        ($1 == "literal" || $1 == "bm25") && $2 == "observed" {
            arm = $1
            rank = 0
            next
        }
        $1 == "rank" {
            if (arm == "" || NF != 5) refuse("rank outside an observed arm")
            rank++
            if (rank <= 5) {
                if ($3 != 1 || ($4 != 0 && $4 != 1))
                    refuse("top-five rank lacks an exact scope classification")
                selected[arm]++
                if ($4 == 0) wrong[arm]++
            } else if ($3 != 0 || $4 != 0) {
                refuse("post-five rank carries undeclared scope evidence")
            }
            next
        }
        END {
            if (!bad) {
                print "literal\t" selected["literal"] + 0 "\t" wrong["literal"] + 0
                print "bm25\t" selected["bm25"] + 0 "\t" wrong["bm25"] + 0
            }
        }
    ' "$candidate" >"$counts" || fail "sealed batch scope classification is invalid"
}

decode_base64() {
    local help
    help=$(base64 --help 2>&1 || true)
    if grep -q -- '--decode' <<<"$help"; then
        base64 --decode
    else
        base64 -D
    fi
}

field() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" get "$2") ||
        fail "missing or malformed field: $2"
    printf '%s' "$value"
}

raw_field() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" raw "$2") ||
        fail "missing or malformed value: $2"
    printf '%s' "$value"
}

field_type() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" type "$2") ||
        fail "missing type: $2"
    printf '%s' "$value"
}

array_count() {
    local value
    value=$(printf '%s\n' "$1" | "$jsonq" count "$2") ||
        fail "missing array: $2"
    [[ $value =~ ^(0|[1-9][0-9]*)$ ]] || fail "invalid array count: $2"
    printf '%s' "$value"
}

keys_exact() {
    local observed
    observed=$(printf '%s\n' "$1" | "$jsonq" keys "$2" | paste -sd, -) ||
        fail "cannot enumerate keys: $2"
    [[ $observed = "$3" ]] || fail "unexpected object shape: $2"
}

bool_field() {
    local value
    [[ $(field_type "$1" "$2") = bool ]] || fail "not a boolean: $2"
    value=$(field "$1" "$2")
    [[ $value = true || $value = false ]] || fail "invalid boolean: $2"
    printf '%s' "$value"
}

expect_semantic_refusal() {
    local name=$1 candidate=$2
    if "$0" --semantic-fixture "$candidate" >/dev/null 2>&1; then
        fail "mutation was accepted: $name"
    fi
}
