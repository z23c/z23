#!/usr/bin/env bash
# Lint gate #49 — blocker escape-action totality.
#
# escape_action is dual-purpose, and a literal is valid in any of three
# forms:
#
#   1. A DISPATCH KEY: blocker_supervisor_sweep() (platform/modules/util/src/blocker.c
#      ~:492) looks the string up in the blocker_register_escape() registry
#      via exact strcmp and calls the matching function. Valid iff a
#      blocker_register_escape("<same string>") call exists anywhere in the
#      tree.
#   2. A human-readable REMEDY DESCRIPTION for the operator (e.g. "re-run
#      script_validate for selected block hash") — never dispatched, purely
#      informational. A dispatch key or a condition name is always a single
#      identifier, never a phrase, so any literal containing whitespace is
#      recognized as this form and is exempt unconditionally.
#   3. The name of a CONDITION-ENGINE healer that drives the fix out of
#      band (e.g. "reducer_frontier_reconcile_light") — not a registered
#      escape function, but still not dead: the condition runs on its own
#      cadence and the literal is documentation of which one owns the fix.
#      Valid iff the identifier matches a registered condition name, i.e. a
#      ZCL_CONDITION(<name>) entry in
#      engine/conditions/include/conditions/condition_registry.def and/or a
#      `#define <X>_COND_NAME "<name>"` literal anywhere in the tree.
#
# A literal that is none of the three — an identifier matching no
# registered escape function AND no registered condition name — silently
# dead-ends blocker_supervisor_sweep's lookup AND is invisible to
# engine/conditions/src/blocker_stall_meta_detector.c's empty-escape backstop
# (which only catches truly empty strings), so nothing catches it. That is
# what this gate exists to catch.
#
# Empty escape_action strings are exempt (the meta-detector backstop already
# covers the "no escape configured" case; this gate is about strings that
# LOOK configured but silently dead-end).
#
# Scope: app/ config/ lib/ src/, excluding lib/test (production code only —
# test fixtures intentionally exercise unregistered names).
set -euo pipefail

cd "$(dirname "$0")/../.."

ROOTS=(core engine contexts cognition platform)

# The primitive's own file is excluded: it DEFINES blocker_register_escape
# (a function definition, not a call) and internally re-copies escape_action
# via a "%s" runtime format (already filtered below), not a literal. Mirrors
# the exclusion in check_typed_blocker.sh.
collect_registry_files() {
    for root in "${ROOTS[@]}"; do
        [ -d "$root" ] || continue
        find "$root" -type f \( -name '*.c' -o -name '*.h' -o -name '*.def' \) \
            ! -path 'tests/harness/include/test/*' \
            ! -path 'platform/modules/util/src/blocker.c' \
            ! -path 'platform/modules/util/include/util/blocker.h' \
            2>/dev/null
    done
}

# ZCL_BLOCKER_ESCAPE_SCAN_FILES overrides only the assignment-side file set,
# newline-separated — used by the gate's own negative self-test to feed an
# isolated fixture file instead of walking the real tree. The registry side
# always scans the real tree (that's what auto-escape can actually dispatch
# to at runtime).
if [ -n "${ZCL_BLOCKER_ESCAPE_SCAN_FILES:-}" ]; then
    mapfile -t assign_files <<< "${ZCL_BLOCKER_ESCAPE_SCAN_FILES}"
else
    mapfile -t assign_files < <(collect_registry_files)
fi
mapfile -t registry_files < <(collect_registry_files)

if [ "${#assign_files[@]}" -eq 0 ]; then
    echo "check_blocker_escape_registered: no files to scan" >&2
    exit 1
fi

# file<TAB>line<TAB>literal for every `snprintf(<expr>.escape_action, ...,
# "literal")` call site, joining wrapped statements onto one buffer. Skips
# any literal containing '%' — that is a runtime copy (e.g. blocker.c's
# internal `snprintf(s->escape_action, ..., "%s", r->escape_action)`
# propagation), not an action-name literal.
extract_escape_action_literals() {
    awk '
        {
            if (match($0, /snprintf\([^,]*escape_action/)) {
                startline = FNR
                buf = $0
                while (buf !~ /;/) {
                    if ((getline nextline) <= 0) break
                    buf = buf "\n" nextline
                }
                if (match(buf, /"([^"\\]|\\.)*"/)) {
                    s = substr(buf, RSTART + 1, RLENGTH - 2)
                    if (s !~ /%/ && s != "") {
                        printf "%s\t%d\t%s\n", FILENAME, startline, s
                    }
                }
            }
        }
    ' "$@"
}

# One registered name per line for every blocker_register_escape("name", fn).
extract_registered_names() {
    awk '
        {
            if (match($0, /blocker_register_escape\(/)) {
                buf = $0
                while (buf !~ /;/) {
                    if ((getline nextline) <= 0) break
                    buf = buf "\n" nextline
                }
                if (match(buf, /"([^"\\]|\\.)*"/)) {
                    s = substr(buf, RSTART + 1, RLENGTH - 2)
                    print s
                }
            }
        }
    ' "$@"
}

# One condition name per line: every ZCL_CONDITION(<name>) entry (the data
# table in condition_registry.def, where <name> IS the condition's string
# name — see tests/harness/src/test_condition_engine.c's `#define
# ZCL_CONDITION(name) #name,` stringization) plus every literal on a
# `#define <X>_COND_NAME "<name>"` line, wherever it appears in the tree.
extract_condition_names() {
    awk '
        {
            if (match($0, /ZCL_CONDITION\([A-Za-z0-9_]+\)/)) {
                s = substr($0, RSTART, RLENGTH)
                sub(/^ZCL_CONDITION\(/, "", s)
                sub(/\)$/, "", s)
                print s
            }
            if (match($0, /#define[ \t]+[A-Za-z0-9_]+_COND_NAME[ \t]+"([^"\\]|\\.)*"/)) {
                line = substr($0, RSTART, RLENGTH)
                if (match(line, /"([^"\\]|\\.)*"/)) {
                    print substr(line, RSTART + 1, RLENGTH - 2)
                }
            }
        }
    ' "$@"
}

declare -A registered
while IFS= read -r name; do
    [ -n "$name" ] && registered["$name"]=1
done < <(extract_registered_names "${registry_files[@]}")

declare -A conditions
while IFS= read -r name; do
    [ -n "$name" ] && conditions["$name"]=1
done < <(extract_condition_names "${registry_files[@]}")

fail=0
violations=()
while IFS=$'\t' read -r file line lit; do
    [ -z "$file" ] && continue
    # Form 1: a registered dispatch key.
    [ -n "${registered[$lit]+x}" ] && continue
    # Form 2: a human-readable remedy phrase — a dispatch key or condition
    # name is always a single identifier, never a phrase, so whitespace
    # alone marks this form. Exempt unconditionally.
    case "$lit" in
        *[[:space:]]*) continue ;;
    esac
    # Form 3: an identifier naming a registered condition-engine healer.
    [ -n "${conditions[$lit]+x}" ] && continue
    violations+=("$file:$line: \"$lit\"")
    fail=1
done < <(extract_escape_action_literals "${assign_files[@]}")

if [ "$fail" = "0" ]; then
    echo "check_blocker_escape_registered: clean — ${#registered[@]} registered escape(s), ${#conditions[@]} condition name(s), all escape_action literals resolve"
    exit 0
fi

echo ""
echo "check_blocker_escape_registered: ${#violations[@]} escape_action literal(s) matching no registered escape function and no registered condition name"
echo ""
for v in "${violations[@]}"; do
    echo "  $v"
done
echo ""
echo "Fix options:"
echo "  1. Register the escape: blocker_register_escape(\"<same string>\", <fn>)"
echo "     at the owning subsystem's init (see"
echo "     engine/services/src/chain_activation_service.c for the pattern)."
echo "  2. If the string names the condition-engine healer that actually"
echo "     drives the fix (e.g. \"reducer_frontier_reconcile_light\"), add a"
echo "     ZCL_CONDITION(<name>) entry to"
echo "     engine/conditions/include/conditions/condition_registry.def (or a"
echo "     matching <X>_COND_NAME #define) so the gate recognizes it."
echo "  3. If it's operator guidance rather than a dispatch key, phrase it as"
echo "     a sentence (e.g. \"re-run script_validate for selected block"
echo "     hash\") — any literal containing whitespace is exempt as a"
echo "     human-readable remedy description."
echo "  4. If the blocker never sets escape_deadline_secs (no auto-escape is"
echo "     intended — it is dispatched some other way, e.g. its own"
echo "     condition cadence, and there's no useful remedy text to add),"
echo "     empty the string instead: it then falls under the"
echo "     blocker_stall_meta_detector.c empty-escape backstop rather than"
echo "     silently dead-ending an unregistered name."
exit 1
