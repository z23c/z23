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
#                      reaches the runner. A selected umbrella is omitted
#                      only when the complete registered shard set is selected.
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

# Membership is answered from associative sets built once per process. The
# proof resolver asks one lookup per registered group per plan token, and the
# impact-rule check asks several per rule row, so a lookup that rescans the
# whole ~28 KB registry text turns one --check-impact-rules pass into ~13 s of
# string scanning. The sets hold exactly the names registered() prints.
REGISTERED_CACHE=""
REGISTERED_LOADED=0
declare -A REGISTERED_SET=()
FAMILY_LOADED=0
FAMILY_TOKENS=()
FAMILY_GLOBS=()

load_registered_cache() {
    local name
    [ "$REGISTERED_LOADED" = 1 ] && return 0
    REGISTERED_CACHE="$(registered)"
    while IFS= read -r name; do
        [ -n "$name" ] && REGISTERED_SET["$name"]=1
    done <<<"$REGISTERED_CACHE"
    REGISTERED_LOADED=1
}

# True when $1 is one registered FULL name (never a substring of one).
is_registered() {
    [ -n "$1" ] && [ -n "${REGISTERED_SET["$1"]+x}" ]
}

load_family_cache() {
    local family glob
    [ "$FAMILY_LOADED" = 1 ] && return 0
    while IFS=$'\t' read -r family glob; do
        [ -n "$family" ] && [ -n "$glob" ] || continue
        FAMILY_TOKENS+=("$family")
        FAMILY_GLOBS+=("$glob")
    done < <(awk -F'"' \
        '/^[[:space:]]*ZCL_TEST_PROOF_FAMILY\(/ {print $2 "\t" $4}' \
        "$FAMILIES")
    FAMILY_LOADED=1
}

resolve_exact() {
    local needle="$1" candidate hit="" count=0
    case "$needle" in
        ''|*[!A-Za-z_0-9]*) return 1 ;;
    esac
    load_registered_cache
    for candidate in "$needle" "test_$needle" "spec_$needle"; do
        if is_registered "$candidate"; then
            hit="$candidate"
            count=$((count + 1))
        fi
    done
    [ "$count" = 1 ] || return 1
    printf '%s\n' "$hit"
}

# Explicit semantic families that were not expressible by the historical
# substring selector. Keep this tiny and named: callers still need an exact
# primary ID, while a registry full name may additionally belong to one of
# these declared aggregates.
proof_plan_token_selects_full() {
    local token="$1" full="$2" i
    load_registered_cache
    if is_registered "$token"; then
        [ "$token" = "$full" ]
        return
    fi
    case "$full" in
        *"$token"*) return 0 ;;
    esac
    load_family_cache
    for i in "${!FAMILY_TOKENS[@]}"; do
        if [ "$token" = "${FAMILY_TOKENS[$i]}" ] &&
           [[ "$full" == ${FAMILY_GLOBS[$i]} ]]; then
            return 0
        fi
    done
    return 1
}

check_impact_rules() {
    local rules="$1" rule_line patterns plan group test_file pattern source_group selected
    local bad=0 registered_tests
    declare -A matched_plans=() tracked_tests=()
    [ -f "$rules" ] || {
        echo "test-group-list: impact rules missing: $rules" >&2
        return 2
    }
    load_registered_cache
    registered_tests="$(git ls-files --cached --others --exclude-standard -- \
        'tests/harness/src/test_*.c')"
    while IFS= read -r test_file; do
        [ -n "$test_file" ] && tracked_tests["$test_file"]=1
    done <<<"$registered_tests"
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
                [ -n "${tracked_tests["$test_file"]+x}" ] || continue
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
        source_group="${test_file##*/}"
        source_group="${source_group%.c}"
        is_registered "$source_group" || continue
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

# Render only the canonical declaration form, including multiline rows.
# This is compatibility glue for the native catalog, never another registry.
# C-string escapes and POSIX locale classes are deliberately refused: decoding
# either here could disagree with platform_glob_match's byte-wise grammar.
fold_proof_umbrellas() {
    proof_umbrella_source="${ZCL_TEST_UMBRELLAS_SRC:-tools/dev/test_group_umbrellas.def}"
    [ -f "$proof_umbrella_source" ] || {
        echo "test-group-list: missing umbrella source $proof_umbrella_source" >&2
        return 1
    }
    proof_umbrella_rows="$(LC_ALL=C awk '
        function bad() {
            failed = 1
            print "test-group-list: malformed or unsupported umbrella declaration at line " NR > "/dev/stderr"
            exit 1
        }
        function uncomment(line,    i, c, pair, out, quoted) {
            out = ""; quoted = 0
            for (i = 1; i <= length(line); i++) {
                c = substr(line, i, 1); pair = substr(line, i, 2)
                if (comment) {
                    if (pair == "*/") { comment = 0; i++ }
                } else if (!quoted && pair == "/*") {
                    comment = 1; i++; out = out " "
                } else if (!quoted && pair == "//") {
                    break
                } else {
                    out = out c
                    if (c == "\"") quoted = !quoted
                }
            }
            return out
        }
        {
            line = uncomment($0)
            if (line ~ /^[[:space:]]*$/) next
            row = row " " line
            if (length(row) > 8192) bad()
            if (index(row, ")") == 0) next
            if (split(row, fields, "\"") != 5 ||
                fields[1] !~ /^[[:space:]]*ZCL_TEST_GROUP_UMBRELLA[[:space:]]*\([[:space:]]*$/ ||
                fields[2] !~ /^[A-Za-z_0-9]+$/ ||
                fields[3] !~ /^[[:space:]]*,[[:space:]]*$/ ||
                fields[5] !~ /^[[:space:]]*\)[[:space:]]*$/ ||
                fields[4] == "" || seen[fields[2]]++) bad()
            pattern = fields[4]
            # platform/glob_match.h: PLATFORM_GLOB_INPUT_MAX is 4096;
            # longer shell patterns must never subsume a native umbrella.
            if (length(pattern) > 4096) bad()
            for (i = 1; i <= length(pattern); i++) {
                c = substr(pattern, i, 1)
                if (c !~ /^[A-Za-z_0-9]$/ && index("*?[]!^-", c) == 0) bad()
            }
            if (index(pattern, "[:") || index(pattern, "[.") ||
                index(pattern, "[=")) bad()
            print fields[2] "\t" pattern
            row = ""
        }
        END { if (!failed && (comment || row !~ /^[[:space:]]*$/)) bad() }
    ' "$proof_umbrella_source")" || return 1

    proof_umbrella_drop=""
    while IFS="$(printf '\t')" read -r proof_umbrella_id proof_umbrella_glob; do
        [ -n "$proof_umbrella_id" ] || continue
        is_registered "$proof_umbrella_id" || continue
        case "
$1" in
            *"
$proof_umbrella_id
"*) ;;
            *) continue ;;
        esac
        proof_umbrella_count=0
        proof_umbrella_missing=0
        # Registered IDs contain only identifier bytes: splitting this cache
        # cannot expand paths or split an ID. The case pattern is data.
        for proof_umbrella_member in $REGISTERED_CACHE; do
            [ "$proof_umbrella_member" != "$proof_umbrella_id" ] || continue
            case "$proof_umbrella_member" in
                $proof_umbrella_glob)
                    proof_umbrella_count=$((proof_umbrella_count + 1))
                    case "
$1" in
                        *"
$proof_umbrella_member
"*) ;;
                        *) proof_umbrella_missing=1 ;;
                    esac ;;
            esac
        done
        if [ "$proof_umbrella_count" -gt 0 ] &&
           [ "$proof_umbrella_missing" = 0 ]; then
            proof_umbrella_drop="$proof_umbrella_drop$proof_umbrella_id
"
        fi
    done <<EOF
$proof_umbrella_rows
EOF
    # All input and declaration validation finished before any selection is
    # printed. Filtering preserves the resolver's first-selection order.
    for proof_umbrella_member in $1; do
        case "
$proof_umbrella_drop" in
            *"
$proof_umbrella_member
"*) ;;
            *) printf '%s\n' "$proof_umbrella_member" ;;
        esac
    done
}

resolve_proof() {
    local needle candidate resolved="" exact family_count
    declare -A resolved_set=()
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
                if [ -z "${resolved_set["$candidate"]+x}" ]; then
                    resolved_set["$candidate"]=1
                    resolved="${resolved}${candidate}
"
                fi
            fi
        done <<<"$REGISTERED_CACHE"
        [ "$family_count" -gt 0 ] || return 1
    done
    [ -n "$resolved" ] || return 1
    # Full exact IDs still select themselves. A complete UNION of explicitly
    # requested shards subsumes its umbrella, just like a legacy family does.
    LC_ALL=C fold_proof_umbrellas "$resolved"
}

exact_set_help() {
    echo 'test-group-list: use comma-separated exact groups (not spaces), e.g. ONLY=dev_land,impact_composition; full test_/spec_ names are also accepted.' >&2
}

exact_set_unknown() {
    local token="$1" name kind=unknown
    for name in "$token" "test_$token" "spec_$token"; do
        if is_registered "$name"; then kind=ambiguous; fi
    done
    printf "test-group-list: %s exact group '%s'\n" "$kind" "$token" >&2
    echo 'closest registered names:' >&2
    # Rank whole names and accepted prefixless aliases by edit distance.
    # Keep stdout exclusively for a completely valid canonical selection.
    printf '%s\n' "$REGISTERED_CACHE" | LC_ALL=C awk -v needle="$token" '
        function distance(a,b, i,j,old,diag,cost,x,y) {
            for (j=0; j<=length(b); j++) row[j]=j
            for (i=1; i<=length(a); i++) {
                diag=row[0]; row[0]=i
                for (j=1; j<=length(b); j++) {
                    old=row[j]; cost=(substr(a,i,1)!=substr(b,j,1))
                    x=row[j]+1; y=row[j-1]+1; if (y<x) x=y
                    y=diag+cost; if (y<x) x=y
                    row[j]=x; diag=old
                }
            }
            return row[length(b)]
        }
        { full=$0; alias=full; sub(/^(test_|spec_)/,"",alias)
          d=distance(needle,full); e=distance(needle,alias)
          if(e<d) d=e; printf "%d %s\n",d,full }
    ' | LC_ALL=C sort -k1,1n -k2,2 | awk 'NR<=3 {print "  " $2}' >&2
}

resolve_exact_set() {
    local csv="$1" token canonical out="" old_ifs="$IFS" invalid=0
    case "$csv" in
        ,*|*,|*,,*) echo 'test-group-list: empty exact group token' >&2
                    invalid=1 ;;
    esac
    IFS=','
    read -r -a tokens <<<"$csv"
    IFS="$old_ifs"
    if [ "${#tokens[@]}" -eq 0 ]; then
        echo 'test-group-list: empty exact group selection' >&2
        exact_set_help
        return 1
    fi
    load_registered_cache
    for token in "${tokens[@]}"; do
        [ -n "$token" ] || continue
        if ! canonical="$(resolve_exact "$token")"; then
            exact_set_unknown "$token"
            invalid=1
            continue
        fi
        case ",$out," in
            *,"$canonical",*) ;;
            *) out="${out:+$out,}$canonical" ;;
        esac
    done
    if [ "$invalid" = 1 ]; then exact_set_help; return 1; fi
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
            echo "test-group-list: empty exact group selection" >&2
            exact_set_help
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
