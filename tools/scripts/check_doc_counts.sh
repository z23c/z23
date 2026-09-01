#!/usr/bin/env bash
# Doc-count lint gate — machine-checks the numeric claims docs make about code.
#
# Doc count rot is silent: code grows a new test group / port / adapter and the
# docs still cite the old number (or, worse, the prose drifts to a number that
# was never true, e.g. "15 ports + 10 sqlite impls"). This gate has two prongs:
#
#   (A) CANONICAL BLOCK (HARD): a machine-readable declaration in
#       docs/CODEBASE_MAP.md delimited by
#         <!-- DOC-COUNTS-BEGIN --> ... <!-- DOC-COUNTS-END -->
#       containing `key: value` lines for test_groups / port_interfaces /
#       persistence_adapters / condition_registrations. This gate measures the
#       real counts from the code and FAILS if the declared counts disagree. To
#       fix a real drift: update the canonical block (and any prose) to match the
#       code — never the other way around; the code is authoritative for what
#       exists.
#
#   (B) PROSE NUMBER SCAN (regression guard) over every TRACKED *.md in the
#       repo. Two matchers:
#         B1 DERIVED — a compound "<N> <unit>" phrase whose unit maps to a
#            count this script measures from the code (e.g. "<N> parallel
#            groups" -> test_groups) FAILS when N disagrees with the measured
#            count. "<N>+ <unit>" is an at-least claim: it fails only when N
#            exceeds the measured count.
#         B2 DENYLIST — a fixed set of historically-wrong phrases that no
#            derived rule covers (e.g. "1500+ tests", "10 sqlite impls").
#       Compound phrases only (number+unit together) => no false positives on
#       bare numbers. Per-line escape hatch: put `doc-count-ok` in an HTML
#       comment on the same line when a small local number is genuinely not a
#       whole-repo count.
#
#       The scan set is `git ls-files '*.md'` — TRACKED files only. It used to
#       be `CLAUDE.md` + `find docs -name '*.md'`, which silently excluded the
#       root README.md; README.md then claimed "631 parallel groups" (real
#       count 739, correctly declared in docs/CODEBASE_MAP.md all along) and
#       this gate — the gate whose entire job is catching that — passed every
#       run. A `find` set also lets untracked scratch .md files into the scan.
#
#   (C) SELF-CHECK (runs BEFORE the tree scan, always): the B matchers are run
#       over a hermetic temp fixture with known-good and known-bad prose, and
#       the script aborts if the matchers do not produce exactly the expected
#       violations. A gate that reports clean because it can no longer fail is
#       the failure mode this whole file exists to prevent, so "clean" is only
#       printed after the matcher has demonstrated it still fires.
#
# Standalone-runnable; wired into `make lint` as `check-doc-counts`. Fast:
# filesystem + grep only, no build, no test run.
#
# Source of truth: the CODE.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/repo_shape.sh
. tools/lint/repo_shape.sh

fail=0
fail_lines=()

add_fail() { fail_lines+=("$1"); fail=1; }

# --------------------------------------------------------------------------
# Measure the real counts from the code. These mirror the commands in the task
# definition; keep them in sync with how the counts are defined.
# --------------------------------------------------------------------------
test_groups_file=tools/dev/test_group_catalog.def
ports_glob='platform/ports/include/ports/*.h'
adapters_glob='platform/adapters/outbound/persistence/src/*.c'
shopt -s nullglob
condition_files=(engine/conditions/src/*.c engine/reducer/conditions/src/*.c \
                 contexts/*/conditions/src/*.c cognition/conditions/src/*.c)
# Both the flat bundles and the nested ones. A bare engine/composition/commands/*.def
# stopped being the whole catalog when the telemetry bundles moved into
# engine/composition/commands/telemetry/, and this measurement went on reporting the flat
# count as if it were the total.
commands_glob='engine/composition/commands/*.def engine/composition/commands/*/*.def'
# The DIAG_* rows live in per-domain files under a pure aggregator; resolving
# the set has exactly one owner. See tools/lint/dumper_defs.sh.
# shellcheck source=tools/lint/dumper_defs.sh
. tools/lint/dumper_defs.sh

if [ ! -f "$test_groups_file" ]; then
    echo "FAIL: $test_groups_file not found (run from repo root)" >&2
    exit 1
fi
if ! dumper_def_files dumper_defs; then
    echo "FAIL: could not resolve the dumpstate descriptor set (run from repo root)" >&2
    exit 1
fi

# Count parallel test groups: one row per canonical test/spec registration.
code_test_groups=$(grep -Ec \
    '^[[:space:]]*ZCL_(TEST|SPEC)_GROUP\([a-z_0-9]+\)[[:space:]]*$' \
    "$test_groups_file")
code_ports=$(ls $ports_glob 2>/dev/null | wc -l)
code_adapters=$(ls $adapters_glob 2>/dev/null | wc -l)
code_conditions=$(grep -RhoE 'condition_register[[:space:]]*\(' \
    "${condition_files[@]}" 2>/dev/null | wc -l)

# Native command surface. `command_bundles` is one .def per catalog bundle;
# `command_roots` is the branches declared with an EMPTY parent, i.e. the
# top-level names `discover help` lists (plus the bare `status` leaf, which is
# not a branch and is deliberately not counted here). Both drifted silently
# when the vault and zcode bundles landed: every doc still said "seven roots"
# and "eight .def bundles".
code_command_bundles=$(ls $commands_glob 2>/dev/null | wc -l)
code_command_roots=$(grep -h 'ZCL_COMMAND_BRANCH(' $commands_glob 2>/dev/null \
    | sed 's/.*ZCL_COMMAND_BRANCH(//' \
    | awk -F'"' '$4 == "" { n++ } END { print n + 0 }')

# `dumpstate` subsystems: one DIAG_* row per subsystem across the .def set the
# diagnostics registry #includes to build g_dumpers[]. There are nine row
# macros, not the three the docs used to name. Counted over the whole resolved
# set — the aggregator itself holds no rows, so counting it alone reports 0.
code_dumpstate=$(grep -chE '^[[:space:]]*DIAG_[A-Z]+\(' "${dumper_defs[@]}" \
    | awk '{ n += $1 } END { print n + 0 }')

# Distinct product shapes; each may recur beneath multiple feature rooms.
code_app_shapes=${#ZCL_APP_SHAPES[@]}

echo "code-measured: test_groups=$code_test_groups port_interfaces=$code_ports persistence_adapters=$code_adapters condition_registrations=$code_conditions command_bundles=$code_command_bundles command_roots=$code_command_roots dumpstate_subsystems=$code_dumpstate app_shape_folders=$code_app_shapes"

# --------------------------------------------------------------------------
# (A) Canonical block in docs/CODEBASE_MAP.md must agree with the code.
# --------------------------------------------------------------------------
DOC=docs/CODEBASE_MAP.md
[ -f "$DOC" ] || { echo "FAIL: $DOC not found" >&2; exit 1; }

# --fix: the code is authoritative, so a mismatch is ALWAYS resolved by
# rewriting the declared values from the code-measured ones. No human (or
# agent) should ever hand-edit these numbers or resolve a merge conflict on
# them — run this, commit, done.
if [ "${1:-}" = "--fix" ]; then
    sed -i \
        -e "s/^\(test_groups[[:space:]]*:\).*/\1 $code_test_groups/" \
        -e "s/^\(port_interfaces[[:space:]]*:\).*/\1 $code_ports/" \
        -e "s/^\(persistence_adapters[[:space:]]*:\).*/\1 $code_adapters/" \
        -e "s/^\(condition_registrations[[:space:]]*:\).*/\1 $code_conditions/" \
        -e "s/^\(command_bundles[[:space:]]*:\).*/\1 $code_command_bundles/" \
        -e "s/^\(command_roots[[:space:]]*:\).*/\1 $code_command_roots/" \
        -e "s/^\(dumpstate_subsystems[[:space:]]*:\).*/\1 $code_dumpstate/" \
        -e "s/^\(app_shape_folders[[:space:]]*:\).*/\1 $code_app_shapes/" \
        "$DOC"
    echo "fixed: DOC-COUNTS block in $DOC rewritten from code-measured values"
fi

block=$(awk '/<!-- DOC-COUNTS-BEGIN -->/{f=1;next} /<!-- DOC-COUNTS-END -->/{f=0} f' "$DOC")
if [ -z "${block//[[:space:]]/}" ]; then
    echo "FAIL: missing or empty <!-- DOC-COUNTS-BEGIN/END --> block in $DOC"
    echo "      Add test_groups / port_interfaces / persistence_adapters /"
    echo "      condition_registrations declarations"
    echo "      (see the block format in $DOC) so the counts can be machine-checked."
    exit 1
fi

get_declared() { # $1=key
    local line
    line=$(echo "$block" | grep -E "^[[:space:]]*${1}[[:space:]]*:" | head -1) || true
    echo "${line##*:}" | tr -d '[:space:]'
}

# check_one <key> <code-measured value>
check_one() {
    local key="$1" measured="$2" declared
    declared=$(get_declared "$key")
    if [ -z "$declared" ]; then
        add_fail "$key not declared in $DOC DOC-COUNTS block"
        return
    fi
    [ "$declared" = "$measured" ] || \
        add_fail "$key MISMATCH — code=$measured doc-says=$declared (update the DOC-COUNTS block in $DOC)"
}

check_one test_groups             "$code_test_groups"
check_one port_interfaces         "$code_ports"
check_one persistence_adapters    "$code_adapters"
check_one condition_registrations "$code_conditions"
check_one command_bundles         "$code_command_bundles"
check_one command_roots           "$code_command_roots"
check_one dumpstate_subsystems    "$code_dumpstate"
check_one app_shape_folders       "$code_app_shapes"

# --------------------------------------------------------------------------
# (B) Prose number scan. Two matchers, both compound (number+unit) so a bare
# number in unrelated prose can never trip them.
#
# B1 DERIVED rules: "<unit-regex>#<expected>#<label>". Any "<N> <unit>" whose N
# disagrees with the code-measured count fails. "<N>+ <unit>" is an at-least
# claim and fails only when N exceeds the measured count. The unit regexes are
# deliberately qualified ("parallel groups", "port interfaces") so ordinary
# prose ("8 groups of peers", "3 ports") is not matched.
#
# B2 DENYLIST: historically-wrong fixed phrases that no derived rule covers.
# --------------------------------------------------------------------------
# Fields are '#'-separated: the unit regexes contain '|' alternations, so '|'
# cannot be the field separator.
derived_rules=(
    "((registered|parallel|test)[ -])+groups#$code_test_groups#test_groups"
    "port interfaces#$code_ports#port_interfaces"
    "(persistence adapters|sqlite impls)#$code_adapters#persistence_adapters"
    "(registered conditions|conditions registered)#$code_conditions#condition_registrations"
    "command bundles#$code_command_bundles#command_bundles"
    "command roots#$code_command_roots#command_roots"
    "dumpstate subsystems#$code_dumpstate#dumpstate_subsystems"
    "(app shape folders|shape folders)#$code_app_shapes#app_shape_folders"
)

denylist=(
    # total-test-count claims (no derived rule: the suite counts groups, not tests)
    '1500+ tests' '1500 tests'
    # historical ports drift, phrased without the "interfaces" qualifier
    '15 ports'
    # historical condition-count drift, phrased without the "registered" qualifier
    '28 conditions live'
)

# A line carrying `doc-count-ok` (put it in an HTML comment) is exempt — for the
# rare case where a small local number legitimately shares a unit phrase with a
# whole-repo count.
SUPPRESS_MARKER='doc-count-ok'

# scan_prose <file>... — prints one violation per line; prints nothing when clean.
scan_prose() {
    [ "$#" -gt 0 ] || return 0
    local phrase rule unit rest expected label hit hrest f ln text m num_tok plus num

    for phrase in "${denylist[@]}"; do
        # -F fixed-string (phrases contain regex metachars like '+'), -I skip
        # binary, -H always print the filename (a single-file scan otherwise
        # emits bare line numbers), -n line numbers.
        while IFS= read -r hit; do
            [ -n "$hit" ] || continue
            case "$hit" in *"$SUPPRESS_MARKER"*) continue ;; esac
            echo "stale phrase \"$phrase\" → $hit  (remove or correct the prose)"
        done < <(grep -HnIF -- "$phrase" "$@" 2>/dev/null || true)
    done

    for rule in "${derived_rules[@]}"; do
        unit=${rule%%#*}
        rest=${rule#*#}
        expected=${rest%%#*}
        label=${rest##*#}
        while IFS= read -r hit; do
            [ -n "$hit" ] || continue
            case "$hit" in *"$SUPPRESS_MARKER"*) continue ;; esac
            f=${hit%%:*}
            hrest=${hit#*:}
            ln=${hrest%%:*}
            text=${hrest#*:}
            # One line can carry several claims; check each match on it.
            while IFS= read -r m; do
                [ -n "$m" ] || continue
                num_tok=$(printf '%s' "$m" | grep -oE '^[0-9][0-9,]*\+?')
                plus=0
                case "$num_tok" in *+) plus=1; num_tok=${num_tok%+} ;; esac
                num=$((10#${num_tok//,/}))
                if [ "$plus" = 1 ]; then
                    [ "$num" -le "$expected" ] && continue
                    echo "count claim \"$m\" at $f:$ln claims MORE than the code has — code-measured $label=$expected"
                else
                    [ "$num" -eq "$expected" ] && continue
                    echo "count claim \"$m\" at $f:$ln disagrees with the code — code-measured $label=$expected"
                fi
            done < <(printf '%s\n' "$text" | grep -oE "[0-9][0-9,]*\+?[*_\` ]+$unit" || true)
        done < <(grep -HnIE -- "[0-9][0-9,]*\+?[*_\` ]+$unit" "$@" 2>/dev/null || true)
    done
}

# --------------------------------------------------------------------------
# (C) Self-check — prove the matchers still fire BEFORE trusting a clean tree
# scan. Hermetic: a temp dir, no repo files read or written.
# --------------------------------------------------------------------------
selftest_dir=$(mktemp -d)
trap 'rm -rf "$selftest_dir"' EXIT

at_least=$(( code_test_groups > 1 ? code_test_groups - 1 : 1 ))
{
    echo "The suite has $code_test_groups parallel groups."
    echo "There are $code_ports port interfaces and $code_adapters persistence adapters."
    echo "More than ${at_least}+ parallel groups run per CI pass."
    echo "Unrelated prose: 8 groups of peers, 3 ports, 12 conditions were met."
    echo "The catalog is $code_command_bundles command bundles under $code_command_roots command roots."
    echo "It exposes $code_dumpstate dumpstate subsystems across $code_app_shapes shape folders."
    echo "Unrelated prose: 4 bundles arrived, 3 roots were pruned, 9 subsystems rebooted."
} > "$selftest_dir/good.md"
{
    echo "$((code_test_groups + 1)) parallel groups"
    echo "$((code_ports + 1)) port interfaces"
    echo "$((code_test_groups + 5))+ registered test groups"
    echo "1500+ tests"
    echo "$((code_command_bundles + 1)) command bundles"
    echo "$((code_command_roots - 1)) command roots"
    echo "$((code_dumpstate - 5)) dumpstate subsystems"
    echo "$((code_app_shapes + 1)) shape folders"
} > "$selftest_dir/bad.md"
{
    echo "$((code_test_groups + 1)) parallel groups <!-- doc-count-ok: fixture -->"
    echo "1500+ tests <!-- doc-count-ok: fixture -->"
} > "$selftest_dir/suppressed.md"

selftest_out=$(scan_prose "$selftest_dir/good.md" "$selftest_dir/bad.md" \
                          "$selftest_dir/suppressed.md")
selftest_n=$(printf '%s' "$selftest_out" | grep -c . || true)
selftest_bad=$(printf '%s' "$selftest_out" | grep -c 'bad\.md' || true)

if [ "$selftest_n" != "8" ] || [ "$selftest_bad" != "8" ]; then
    echo "FAIL: check_doc_counts self-check broken — the prose matcher no longer" >&2
    echo "      behaves as specified, so a clean tree scan would prove nothing." >&2
    echo "      expected 8 violations (one per derived rule, plus the denylist" >&2
    echo "      phrase), all in bad.md; got $selftest_n total," >&2
    echo "      $selftest_bad in bad.md:" >&2
    printf '        %s\n' "$selftest_out" >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Tree scan: every TRACKED *.md. `git ls-files` (not `find`) so untracked
# scratch files never enter the scan and no tracked file escapes it.
# --------------------------------------------------------------------------
# Symlinks are skipped so a doc that is an alias of another (AGENTS.md ->
# CLAUDE.md) is not reported twice; the target is tracked and scanned in its
# own right.
scan_files=()
while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] && [ ! -L "$f" ] && scan_files+=("$f")
done < <(git ls-files -- '*.md' 2>/dev/null || true)

if [ "${#scan_files[@]}" -lt 2 ]; then
    # No git index available (source tarball / detached export): fall back to
    # the historical set rather than skipping the scan entirely.
    scan_files=()
    [ -f CLAUDE.md ] && scan_files+=(CLAUDE.md)
    [ -f README.md ] && scan_files+=(README.md)
    while IFS= read -r f; do scan_files+=("$f"); done \
        < <(find docs -type f -name '*.md' 2>/dev/null)
fi

while IFS= read -r violation; do
    [ -n "$violation" ] || continue
    add_fail "$violation"
done < <(scan_prose "${scan_files[@]}")

# --------------------------------------------------------------------------
# Report.
# --------------------------------------------------------------------------
if [ "$fail" != "0" ]; then
    echo ""
    echo "FAIL: doc-count drift detected."
    printf '    %s\n' "${fail_lines[@]}"
    echo ""
    echo "Fix: the CODE is authoritative."
    echo "  - For a MISMATCH: update the <!-- DOC-COUNTS --> block in $DOC"
    echo "    AND any prose (FRAMEWORK.md, CLAUDE.md, docs/BUILD.md, docs/HANDOFF.md) to match."
    echo "  - For a stale phrase: delete or correct the prose (the number is wrong)."
    exit 1
fi

echo "check_doc_counts: clean — test_groups=$code_test_groups port_interfaces=$code_ports persistence_adapters=$code_adapters condition_registrations=$code_conditions command_bundles=$code_command_bundles command_roots=$code_command_roots dumpstate_subsystems=$code_dumpstate app_shape_folders=$code_app_shapes; self-check fired as expected; ${#scan_files[@]} tracked *.md scanned, no stale count claims"
exit 0
