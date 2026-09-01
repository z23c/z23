#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# test-group-list.sh — print the REGISTERED test-group names without building.
#
# ── WHY THIS EXISTS ────────────────────────────────────────────────────────
# The documented way to enumerate test groups was an incantation in the
# project's front-page CLAUDE.md:
#
#     git grep -hoE 'X\([a-z_0-9]+\)' tests/harness/src/test_parallel.c | tr -d 'X()'
#
# It has two defects and both were being hit. Dropping -h glues the filename
# onto every name (CLAUDE.md warns about it, which means everyone trips it).
# And it drops the registry's PREFIXES: g_groups[] is built from the canonical
# catalog, stamping "test_" onto ZCL_TEST_GROUP rows and "spec_" onto
# ZCL_SPEC_GROUP rows. The incantation prints 28 SPEC
# names as if they were "test_<name>", which is not what the runner prints,
# not what --only matches against, and not what a report can diff against a
# run artifact. Verified on this tree: naive output vs the runner's own
# .cache/test-timing/last-run.json disagreed on 32 names, of which 28 were
# pure prefix error.
#
# Output order is catalog order, which is g_groups[] order — the order the
# runner reports in. The C planner and the test binary include the same file;
# this script only renders that source for compatibility with Make and shell.
#
# Modes (all read-only, no build, no network):
#   (none)             every registered group name, one per line
#   --count            the number of registered groups
#   --match SUBSTR     the groups a `--only=SUBSTR` run would select, using the
#                      runner's own rule (plain substring of the FULL name,
#                      tests/harness/src/test_parallel.c strstr()). Exit 1, no
#                      output, when nothing matches.
#   --resolve-exact ID... resolve proof-plan IDs to canonical FULL names.
#                      Accepts either the full name or the legacy prefixless
#                      name, never a substring. Exit 1 when absent/ambiguous.
#   --resolve-proof ID... validate every plan ID has one canonical exact
#                      group. Canonical test_*/spec_* IDs select only that
#                      group; legacy prefixless IDs preserve their former
#                      substring union as canonical full IDs. No substring
#                      reaches the runner.
#   --resolve-exact-set CSV
#                      canonicalize/validate a comma-separated exact set.
#   --check-impact-rules [FILE]
#                      fail when any declared proof-plan ID is not exact.
#   --suggest SUBSTR   nearest candidates for a SUBSTR that matched nothing
#   --params-gated     the groups group_is_params_heavy() excludes from a
#                      default full run
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO"
# shellcheck source=tools/scripts/sh_str.sh
. "$REPO/tools/scripts/sh_str.sh"  # str_contains / str_lacks — see F-note

REGISTRY="${ZCL_TEST_REGISTRY_SRC:-tools/dev/test_group_catalog.def}"
RUNNER="${ZCL_TEST_RUNNER_SRC:-tests/harness/src/test_parallel.c}"
FAMILIES="${ZCL_TEST_PROOF_FAMILIES_SRC:-tools/dev/test_proof_families.def}"

for required in "$REGISTRY" "$RUNNER" "$FAMILIES"; do
    [ -f "$required" ] || {
        echo "test-group-list: FATAL — missing proof source $required" >&2
        exit 2
    }
done

# ── the registry parse ─────────────────────────────────────────────────────
# One row per group; names are emitted with the same prefix the C expansion
# stamps into the runner and native catalog.
registered() {
    awk '
    /^[[:space:]]*ZCL_TEST_GROUP\([A-Za-z_0-9]+\)[[:space:]]*$/ {
        line = $0
        sub(/^[^(]*\(/, "", line); sub(/\).*/, "", line)
        print "test_" line
        next
    }
    /^[[:space:]]*ZCL_SPEC_GROUP\([A-Za-z_0-9]+\)[[:space:]]*$/ {
        line = $0
        sub(/^[^(]*\(/, "", line); sub(/\).*/, "", line)
        print "spec_" line
    }
    ' "$REGISTRY"
}

# ── the params-heavy gate, read from the function that enforces it ─────────
# group_is_params_heavy() in the runner names its groups with strcmp against a
# prefix-stripped name. Deriving the list from that function (rather than
# retyping it here) means a change to the policy shows up in the report
# instead of silently drifting away from it. Refuses loudly if the function's
# shape changes, because an empty list would read as "nothing is gated".
params_gated() {
    awk '
        /^static bool group_is_params_heavy/ { inside = 1; next }
        inside && /^}/ { inside = 0 }
        inside {
            rest = $0
            while (match(rest, /strcmp\(name,[[:space:]]*"[A-Za-z_0-9]+"\)/)) {
                seg = substr(rest, RSTART, RLENGTH)
                match(seg, /"[A-Za-z_0-9]+"/)
                print "test_" substr(seg, RSTART + 1, RLENGTH - 2)
                rest = substr(rest, RSTART + RLENGTH)
            }
        }
    ' "$RUNNER"
}

REGISTERED_CACHE=""
FAMILY_CACHE=""

load_registered_cache() {
    [ -n "$REGISTERED_CACHE" ] || REGISTERED_CACHE="$(registered)"
}

load_family_cache() {
    [ -n "$FAMILY_CACHE" ] || FAMILY_CACHE="$(awk -F'"' \
        '/^[[:space:]]*ZCL_TEST_PROOF_FAMILY\(/ {print $2 "\t" $4}' \
        "$FAMILIES")"
}

resolve_exact() {
    local needle="$1" candidate hit="" count=0 haystack
    case "$needle" in
        ''|*[!A-Za-z_0-9]*) return 1 ;;
    esac
    load_registered_cache
    haystack="
${REGISTERED_CACHE}
"
    for candidate in "$needle" "test_$needle" "spec_$needle"; do
        case "$haystack" in
            *$'\n'"$candidate"$'\n'*)
                hit="$candidate"
                count=$((count + 1))
                ;;
        esac
    done
    [ "$count" = 1 ] || return 1
    printf '%s\n' "$hit"
}

# Explicit semantic families that were not expressible by the historical
# substring selector. Keep this tiny and named: callers still need an exact
# primary ID, while a registry full name may additionally belong to one of
# these declared aggregates.
proof_plan_token_selects_full() {
    local token="$1" full="$2" family glob haystack
    load_registered_cache
    haystack="
${REGISTERED_CACHE}
"
    case "$haystack" in
        *$'\n'"$token"$'\n'*) [ "$token" = "$full" ]; return ;;
    esac
    case "$full" in
        *"$token"*) return 0 ;;
    esac
    load_family_cache
    while IFS=$'\t' read -r family glob; do
        [ -n "$family" ] && [ -n "$glob" ] || continue
        if [ "$token" = "$family" ] && [[ "$full" == $glob ]]; then
            return 0
        fi
    done <<<"$FAMILY_CACHE"
    return 1
}

check_impact_rules() {
    local rules="$1" rule_line patterns plan group test_file pattern source_group selected
    local bad=0 registered_tests tracked_haystack
    declare -A matched_plans=()
    [ -f "$rules" ] || {
        echo "test-group-list: impact rules missing: $rules" >&2
        return 2
    }
    load_registered_cache
    registered_tests="$(git ls-files --cached --others --exclude-standard -- \
        'tests/harness/src/test_*.c')"
    tracked_haystack="
${registered_tests}
"
    while IFS=$'\034' read -r rule_line patterns plan; do
        case "$patterns" in
            *[![:space:]]*) ;;
            *)
                echo "test-group-list: empty impact pattern at $rules:$rule_line" >&2
                bad=1
                continue
                ;;
        esac
        case "$plan" in
            *[![:space:]]*) ;;
            *)
                echo "test-group-list: empty impact proof plan at $rules:$rule_line" >&2
                bad=1
                continue
                ;;
        esac
        for group in $plan; do
            if ! resolve_exact "$group" >/dev/null; then
                echo "test-group-list: non-exact impact proof id: $group" >&2
                bad=1
            fi
        done
        IFS='|' read -r -a rule_patterns <<<"$patterns"
        for pattern in "${rule_patterns[@]}"; do
            case "$pattern" in
                tests/harness/src/test_*.c) ;;
                *) continue ;;
            esac
            while IFS= read -r test_file; do
                [ -n "$test_file" ] || continue
                case "$tracked_haystack" in
                    *$'\n'"$test_file"$'\n'*) ;;
                    *) continue ;;
                esac
                matched_plans["$test_file"]="${matched_plans[$test_file]:-}$plan "
            done < <(compgen -G "$pattern" || true)
        done
    done < <(awk -F'"' \
        '/^[[:space:]]*AGENT_IMPACT_RULE\(/ {print NR "\034" $2 "\034" $4}' \
        "$rules")

    # Rules compose by union, so verify each registered test source against
    # every plan row that matches it. A token selects the source group iff the
    # old runner's strstr selector would have selected it; resolve_proof then
    # transports that same union as full IDs to the exact runner.
    while IFS= read -r test_file; do
        [ -n "$test_file" ] || continue
        plan="${matched_plans[$test_file]:-}"
        [ -n "$plan" ] || continue
        source_group="$(basename "$test_file" .c)"
        case "
${REGISTERED_CACHE}
" in
            *$'\n'"$source_group"$'\n'*) ;;
            *) continue ;;
        esac
        selected=0
        for group in $plan; do
            if proof_plan_token_selects_full "$group" "$source_group"; then
                selected=1
                break
            fi
        done
        if [ "$selected" = 0 ]; then
            echo "test-group-list: impact rules match $test_file but their union omits its registered group $source_group (plans: $plan)" >&2
            bad=1
        fi
    done <<<"$registered_tests"
    [ "$bad" = 0 ]
}

resolve_proof() {
    local needle candidate resolved="" exact family_count
    load_registered_cache
    for needle in "$@"; do
        # The exact primary is the fail-closed admission check. A canonical
        # full ID is an explicit exact request. A legacy prefixless ID keeps
        # the old runner's substring family as an explicit set of full IDs.
        exact="$(resolve_exact "$needle")" || return 1
        family_count=0
        while IFS= read -r candidate; do
            [ -n "$candidate" ] || continue
            if proof_plan_token_selects_full "$needle" "$candidate"; then
                    family_count=$((family_count + 1))
                    case "
${resolved}
" in
                        *$'\n'"$candidate"$'\n'*) ;;
                        *) resolved="${resolved}${candidate}
" ;;
                    esac
            fi
        done <<<"$REGISTERED_CACHE"
        [ "$family_count" -gt 0 ] || return 1
    done
    [ -n "$resolved" ] || return 1
    printf '%s' "$resolved"
}

resolve_exact_set() {
    local csv="$1" token canonical out="" old_ifs="$IFS"
    case "$csv" in
        ,*|*,|*,,*) return 1 ;;
    esac
    IFS=','
    read -r -a tokens <<<"$csv"
    IFS="$old_ifs"
    [ "${#tokens[@]}" -gt 0 ] || return 1
    for token in "${tokens[@]}"; do
        [ -n "$token" ] || return 1
        canonical="$(resolve_exact "$token")" || return 1
        case ",$out," in
            *,"$canonical",*) ;;
            *) out="${out:+$out,}$canonical" ;;
        esac
    done
    [ -n "$out" ] || return 1
    printf '%s\n' "$out"
}

mode="${1:-list}"
case "$mode" in
    list)
        registered
        ;;
    --count)
        registered | wc -l | tr -d ' '
        ;;
    --match)
        needle="${2:-}"
        [ -n "$needle" ] || {
            echo "test-group-list: --match needs a substring" >&2
            exit 2
        }
        # Substring semantics MUST equal the runner's strstr() over the full
        # name. Pipeline-free per-name test (see tools/scripts/sh_str.sh): a
        # `grep -q` here carries a decision and can invert under pipefail.
        found=0
        while IFS= read -r g; do
            if str_contains "$g" "$needle"; then
                printf '%s\n' "$g"
                found=1
            fi
        done < <(registered)
        [ "$found" = 1 ] || exit 1
        ;;
    --resolve-exact)
        shift
        [ "$#" -gt 0 ] || {
            echo "test-group-list: --resolve-exact needs one or more group ids" >&2
            exit 2
        }
        for needle in "$@"; do
            resolve_exact "$needle" || exit 1
        done
        ;;
    --resolve-proof)
        shift
        [ "$#" -gt 0 ] || {
            echo "test-group-list: --resolve-proof needs one or more plan ids" >&2
            exit 2
        }
        resolve_proof "$@"
        ;;
    --resolve-exact-set)
        needle="${2:-}"
        [ -n "$needle" ] || {
            echo "test-group-list: --resolve-exact-set needs CSV ids" >&2
            exit 2
        }
        resolve_exact_set "$needle"
        ;;
    --check-impact-rules)
        check_impact_rules "${2:-cognition/controllers/include/controllers/agent_impact_rules.def}"
        ;;
    --suggest)
        needle="${2:-}"
        [ -n "$needle" ] || exit 0
        # Cheap, dependency-free nearest-candidate. No edit-distance library
        # and no new dependency; two passes that between them cover the two
        # ways an ONLY= is actually wrong here:
        #
        #   1. WRONG SEPARATOR / STRAY PUNCTUATION (`test-bloom`, `<substring>`).
        #      Split on every character a group name cannot contain and try the
        #      resulting tokens LONGEST FIRST. `test-bloom` yields {test, bloom};
        #      trying `bloom` before `test` is what turns a useless "here are
        #      the first 8 of 866" into `test_bloom`.
        #   2. TRAILING TYPO (`boot_phasez`). Shrink the longest token from the
        #      right until it matches.
        #
        # The shrink stops at 3 characters. Below that a probe matches dozens of
        # unrelated groups, and a suggestion list that is mostly noise trains
        # the reader to ignore it.
        GROUPS_CACHE="$(registered)"
        # Caps at 8 hits WITHOUT `| head -8`: an early-exiting downstream
        # SIGPIPEs printf, and under `set -o pipefail` that 141 becomes the
        # status of a function whose status is a decision. Counting in the
        # loop keeps the whole thing pipeline-free (tools/scripts/sh_str.sh).
        suggest_probe() {
            local p="$1" hits="" n=0
            while IFS= read -r g; do
                if str_contains "$g" "$p"; then
                    hits="${hits}${g}
"
                    n=$(( n + 1 ))
                    [ "$n" -ge 8 ] && break
                fi
            done <<<"$GROUPS_CACHE"
            [ -n "$hits" ] || return 1
            printf '%s' "$hits"
            return 0
        }

        tokens="$(printf '%s' "$needle" | tr -c 'A-Za-z_0-9' '\n' |
                  awk 'length($0) >= 3 { print length($0) "\t" $0 }' |
                  sort -rn | cut -f2-)"
        while IFS= read -r tok; do
            [ -n "$tok" ] || continue
            suggest_probe "$tok" && exit 0
        done <<<"$tokens"

        probe="${tokens%%$'\n'*}"
        while [ "${#probe}" -ge 3 ]; do
            suggest_probe "$probe" && exit 0
            probe="${probe%?}"
        done
        exit 0
        ;;
    --params-gated)
        out="$(params_gated)"
        [ -n "$out" ] || {
            echo "test-group-list: FATAL — group_is_params_heavy() in $REGISTRY" \
                 "yielded no names; its shape changed and this parse is stale" >&2
            exit 2
        }
        printf '%s\n' "$out"
        ;;
    *)
        echo "usage: $0 [--count | --match SUBSTR | --resolve-exact ID... | --resolve-proof ID... | --resolve-exact-set CSV | --check-impact-rules [FILE] | --suggest SUBSTR | --params-gated]" >&2
        exit 2
        ;;
esac
