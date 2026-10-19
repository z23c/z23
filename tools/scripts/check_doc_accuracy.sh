#!/usr/bin/env bash
# Lint gate E11 — the documented lint-gate set matches the Makefile (HARD).
#
# Doc rot is silent: the Makefile LINT_GATES target gains/loses a check-* gate
# and DEFENSIVE_CODING.md still claims the old count and names. This gate
# cross-checks the two sources of truth so the doc can never drift from
# the build.
#
# Source of truth A: the LINT_GATES variable in Makefile (the umbrella gate
#   list; historically the literal check-* prerequisites of the `lint:`
#   target, which remains the fallback when LINT_GATES is absent).
# Source of truth B: a machine-readable canonical block in
#   DEFENSIVE_CODING.md delimited by the markers
#     <!-- LINT-GATES-BEGIN --> ... <!-- LINT-GATES-END -->
#   containing one `check-*` token per documented gate (any surrounding
#   markdown is ignored; we extract the check-* tokens).
#
# The gate fails if the COUNT differs or the NAME SET differs. To fix a
# real drift: update the doc block (markers) to match the Makefile — never
# the other way around (the Makefile is authoritative for what runs).
#
# Prong C (repo-wide, added after a measured escape): checking one filename
# only protects one filename. On 2026-07-25 the Makefile carried 98 gates and
# DEFENSIVE_CODING.md correctly said 98, so prongs A/B were green — while
# docs/dev/BUILD.md said "40 defensive-coding gates" and docs/TENACITY.md said
# "36 lint gates". Both had been wrong for months with lint green, because
# neither file was named in this script. Prong C therefore does NOT name
# files: it derives the count from the Makefile (source A) and then scans
# EVERY in-tree *.md (tracked, plus not-yet-added files git does not ignore)
# for a count-shaped claim about the umbrella gate set.
# Writing the stale claim into a brand-new file is caught the same way, and
# the gate stays correct when the gate count changes because nothing here is
# hardcoded to a number.
#
# What prong C considers a claim about the umbrella set (deliberately narrow
# so it can be strict rather than advisory): a number immediately followed by
# a FAMILY NAME for the whole set — "lint gates", "defensive-coding gates",
# "defensive-coding lint gates". Anything between the number and "gates" that
# is not a family word makes it a SUBSET claim and is ignored, which is what
# keeps true statements like "11 architecture gates", "7 fail-silent lint
# gates" and "~15 high-signal lint gates" from being false positives. The
# number must also start on a non-alphanumeric boundary, so identifier runs
# like "the P1/P2/P3 lint gates" and "I1/I2 lint gates" do not read as "3
# lint gates" / "2 lint gates".
#
# A matched claim must equal the derived count EXACTLY — including the "98+"
# form. The intended fix for a failure is not to re-pin a fresh number (that
# buys one week); it is to delete the number and point at the derived source.
set -euo pipefail

cd "$(dirname "$0")/../.."

MAKEFILE=Makefile
DOC=docs/DEFENSIVE_CODING.md

[ -f "$MAKEFILE" ] || { echo "FAIL: $MAKEFILE not found"; exit 1; }
[ -f "$DOC" ]      || { echo "FAIL: $DOC not found"; exit 1; }

# A) Extract the umbrella gate list. Since the loop-speed lane, the single
#    source of truth is the LINT_GATES variable (a backslash-continued list):
#    the serial fallback runs it as lint: prerequisites, the default path
#    passes it to tools/lint/run_lint.sh. Fall back to the historical
#    literal `lint: dep dep ...` line if LINT_GATES is absent.
lint_gates_block=$(awk '
    /^LINT_GATES[[:space:]]*:=/ { inb=1 }
    inb { print; if ($0 !~ /\\[[:space:]]*$/) exit }
' "$MAKEFILE")
if [ -n "$lint_gates_block" ]; then
    make_gates=$(printf '%s\n' "$lint_gates_block" | grep -oE 'check-[a-z0-9-]+' | sort -u)
else
    lint_line=$(grep -E '^lint:[[:space:]]' "$MAKEFILE" | head -1)
    if [ -z "$lint_line" ]; then
        echo "FAIL: could not find LINT_GATES or a literal 'lint:' target line in $MAKEFILE"
        exit 1
    fi
    make_gates=$(echo "$lint_line" | grep -oE 'check-[a-z0-9-]+' | sort -u)
fi

# B) Extract the check-* tokens from the canonical doc block.
doc_block=$(awk '/<!-- LINT-GATES-BEGIN -->/{f=1;next} /<!-- LINT-GATES-END -->/{f=0} f' "$DOC")
if [ -z "${doc_block//[[:space:]]/}" ]; then
    echo "FAIL: missing or empty <!-- LINT-GATES-BEGIN/END --> block in $DOC"
    echo "      Add the canonical gate list so E11 can verify doc/Makefile parity."
    exit 1
fi
doc_gates=$(echo "$doc_block" | grep -oE 'check-[a-z0-9-]+' | sort -u)

make_count=$(echo "$make_gates" | grep -c . || true)
doc_count=$(echo "$doc_gates" | grep -c . || true)

fail=0

if [ "$make_count" != "$doc_count" ]; then
    echo "FAIL: gate COUNT mismatch — Makefile LINT_GATES has $make_count check-* gates, $DOC documents $doc_count"
    fail=1
fi

only_make=$(comm -23 <(echo "$make_gates") <(echo "$doc_gates") || true)
only_doc=$(comm -13 <(echo "$make_gates") <(echo "$doc_gates") || true)

if [ -n "${only_make//[[:space:]]/}" ]; then
    echo "FAIL: gates in Makefile LINT_GATES but NOT documented in $DOC:"
    echo "$only_make" | sed 's/^/    /'
    fail=1
fi
if [ -n "${only_doc//[[:space:]]/}" ]; then
    echo "FAIL: gates documented in $DOC but NOT in Makefile LINT_GATES:"
    echo "$only_doc" | sed 's/^/    /'
    fail=1
fi

if [ "$fail" != "0" ]; then
    echo ""
    echo "Fix: update the <!-- LINT-GATES-BEGIN/END --> block in $DOC to"
    echo "     match the LINT_GATES list in Makefile. The Makefile is"
    echo "     authoritative for what actually runs."
    exit 1
fi

# ---------------------------------------------------------------------------
# C) Repo-wide: no in-tree .md may state a gate count other than the derived
#    one. No filename is hardcoded here on purpose — see the header comment.
# ---------------------------------------------------------------------------

# A number on a word boundary, then a family name for the WHOLE gate set,
# then "gate"/"gates". Subset qualifiers between the number and "gates"
# (architecture, fail-silent, high-signal, ...) make it not a whole-set claim.
CLAIM_RE='(^|[^[:alnum:]/_-])[0-9]+\+?[[:space:]]+(defensive[- ]coding([[:space:]]+lint)?|lint)[[:space:]]+gates?([^a-zA-Z]|$)'

# git is the right lister only when THIS directory is the root of the repo git
# would answer for. `--is-inside-work-tree` was not that test: the lint-gate
# self-test runs these scripts inside a hardlink COPY of the tree (a sibling of
# the worktree root, with no .git of its own), and when that copy lands under
# some OTHER repo's ignored path — an agent worktree under .claude/worktrees/,
# say — the probe answered yes for the ENCLOSING repo and both ls-files calls
# returned nothing, because an ignored prefix has no tracked files and
# --exclude-standard drops the rest. Prong C then scanned zero files and
# reported clean. Compare the toplevel against the cwd and fall back to find
# whenever they differ.
list_docs() {
    # Two lanes found this independently and wrote the same test; the sandbox
    # is a private clone at <root>.lint_sb_<pid>, so the gate was hollow
    # exactly where its own plant/trip/recover proof runs.
    local top=""
    top=$(git rev-parse --show-toplevel 2>/dev/null || true)
    if [ -n "$top" ] && [ "$top" -ef . ] 2>/dev/null; then
        # Tracked AND not-yet-added-but-not-ignored: a stale claim must be
        # caught the moment the file exists, not only after `git add`. The
        # `--exclude-standard` filter keeps build output and gitignored
        # scratch out of the scan.
        git ls-files -z -- '*.md'
        git ls-files -z --others --exclude-standard -- '*.md'
    else
        # Tarball / vendored checkout / private sandbox: same scan without git.
        find . \( -name .git -o -name vendor -o -name build -o -name node_modules \) \
             -prune -o -name '*.md' -type f -print0
    fi
}

# FAIL-LOUD floor on the SCAN SET, not on the hit count. The repo currently
# carries zero prose gate-count claims (they were all de-pinned), so
# "0 claims verified" is a legitimate clean result and cannot be the floor.
# What must never be zero is the number of .md files actually looked at — that
# is the signal that list_docs came back empty and the gate is inspecting
# nothing. Hundreds of .md files are tracked; anything under 50 means the
# enumeration broke.
docs_scanned=$(list_docs | tr -cd '\0' | wc -c)
if [ "$docs_scanned" -lt 50 ]; then
    echo "check_doc_accuracy: FATAL — scan set is $docs_scanned .md file(s) (expected >=50)." >&2
    echo "  list_docs came back (near-)empty, so this gate would report clean" >&2
    echo "  without inspecting anything. Refusing to pass off a dead scan." >&2
    exit 2
fi

claim_hits=$(list_docs | xargs -0 -r grep -HnoEi "$CLAIM_RE" 2>/dev/null || true)

claims_checked=0
while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    hit_file=${hit%%:*}
    hit_rest=${hit#*:}
    hit_line=${hit_rest%%:*}
    hit_text=${hit_rest#*:}
    claimed=$(printf '%s' "$hit_text" | grep -oE '[0-9]+' | head -1)
    [ -n "$claimed" ] || continue
    claims_checked=$((claims_checked + 1))
    if [ "$claimed" != "$make_count" ]; then
        echo "FAIL: $hit_file:$hit_line claims $claimed gates; Makefile LINT_GATES has $make_count"
        echo "      claim text: $(printf '%s' "$hit_text" | sed 's/^[[:space:]]*//')"
        fail=1
    fi
done <<EOF
$claim_hits
EOF

if [ "$fail" != "0" ]; then
    echo ""
    echo "Fix: do NOT re-pin the number — a corrected constant goes stale again"
    echo "     the next time a gate lands. Delete the count from the prose and"
    echo "     point at the derived source instead: \`make lint\` prints what it"
    echo "     ran, and the canonical gate list lives in the"
    echo "     <!-- LINT-GATES-BEGIN/END --> block of $DOC."
    exit 1
fi

echo "check_doc_accuracy: clean — $make_count gates; doc block agrees; $claims_checked prose gate-count claim(s) across in-tree .md verified"
exit 0
