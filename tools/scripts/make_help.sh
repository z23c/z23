#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# make_help.sh — `make help`. A curated entry point, not a target dump.
#
# The Makefile defines hundreds of targets and, until this existed, `make help`
# answered "No rule to make target 'help'" — the first thing a stranger and the
# first thing an agent both try.
#
# Two standing rules for this file:
#
#   1. NO DURATIONS. Not "~2 minutes", not "fast", not "slow". Wall time is
#      per host and per commit, and a number typed into a help text is stale
#      the day after it is typed. Every line that wants to say how long
#      something takes points at `make timings`, which reads only artifacts
#      measured on the host it is running on.
#   2. EVERY TARGET NAMED HERE MUST EXIST. `--self-test` re-derives that from
#      the Makefile, so a renamed or deleted target breaks the check instead
#      of silently sending the next reader to a "No rule to make target"
#      error. That is the same failure this file was written to remove.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MAKEFILE="$ROOT/Makefile"

# group <TAB> target <TAB> one-line description
read -r -d '' ENTRIES <<'TABLE' || true
first	doctor-env	C23 compiler, git, vendor/tor, stack: what this machine is missing
first	doctor	what this host is still missing, with the exact install line
first	setup	arm the git hooks and generate compile_commands.json (idempotent)
first	z23	build the public node (bare make does the same; vendor setup is automatic)
loop	all	build the node plus the monolithic test harness and auxiliary tools
loop	new-app	scaffold a GUI app from zhello: make new-app NAME=myapp, then make myapp
loop	game	link the Sky Combat binary at build/bin/z23-skycombat (opt-in; needs X11/GL)
loop	game-check	compile apps/skycombat and vendor/raylib to objects only, no window needed
loop	build-only	compile every translation unit, no link — genuinely parallel under -j
loop	syntax-check	whole-tree no-link syntax pass in one compiler invocation
loop	dev-bin	non-LTO local node binary at build/bin/zclassic23-dev
loop	t-fast	one test group: make t-fast ONLY=<group>
loop	lint-fast	the highest-signal subset of the lint gates
gate	lint	the full lint umbrella — every gate, run in parallel
gate	test-parallel	every test group, each in its own process
gate	pr-check	lint plus a whole-tree syntax pass; needs nothing built first
gate	ci	the umbrella a push must survive: lint, then the isolated test runner
gate	fuzz-ci	build the fuzz harnesses and smoke-run each one
agent	timings	where wall time actually went ON THIS HOST (reads measured artifacts)
agent	first-build-timing	time a fresh clone through the full suite and record it for make timings
agent	build-bench	measure the build and test loop scenario by scenario (ARGS=--quick for the subset)
agent	compdb	regenerate compile_commands.json for clangd / LSP
agent	doctor-build	which build accelerators (ccache, mold, clang) this host has
TABLE

group_title() {
    case "$1" in
        first) echo "First run, in this order" ;;
        loop)  echo "Inner loop — while you are editing" ;;
        gate)  echo "Gates — what a change must survive" ;;
        agent) echo "Agent and operator surface" ;;
    esac
}

# A target "exists" if it heads a rule line, alone or among several targets.
target_exists() {
    awk -v t="$1" '
        /^[ \t]/ { next }
        /^[A-Za-z0-9_.\/-]+([ \t]+[A-Za-z0-9_.\/$()-]+)*[ \t]*:([^=]|$)/ {
            split($0, parts, ":")
            n = split(parts[1], names, /[ \t]+/)
            for (i = 1; i <= n; i++) if (names[i] == t) { found = 1; exit }
        }
        END { exit(found ? 0 : 1) }
    ' "$MAKEFILE"
}

if [ "${1:-}" = "--self-test" ]; then
    missing=()
    while IFS=$'\t' read -r group target desc; do
        [ -n "${target:-}" ] || continue
        target_exists "$target" || missing+=("$target")
    done <<<"$ENTRIES"

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "make_help selftest: FAIL — help names targets the Makefile does not define:" >&2
        printf '    %s\n' "${missing[@]}" >&2
        exit 1
    fi

    # The detector must be able to fail, or it proves nothing.
    if target_exists zcl-target-that-cannot-exist; then
        echo "make_help selftest: FAIL — detector accepts a nonexistent target" >&2
        exit 1
    fi

    # Rule 1 is mechanical: no duration may be written into the table.
    if grep -qiE '[0-9]+[[:space:]]*(ms|s|sec|second|min|minute|hour)s?\b' <<<"$ENTRIES"; then
        echo "make_help selftest: FAIL — a duration leaked into the help text; point at 'make timings'" >&2
        exit 1
    fi

    echo "make_help selftest: PASS — $(grep -c . <<<"$ENTRIES") documented targets all exist"
    exit 0
fi

total="$(awk '
    /^[ \t]/ { next }
    /^[A-Za-z0-9_.\/-]+([ \t]+[A-Za-z0-9_.\/$()-]+)*[ \t]*:([^=]|$)/ { n++ }
    END { print n+0 }
' "$MAKEFILE")"

echo "zclassic23 — one C23 binary: full node, wallet, explorer, onion service."
echo
for g in first loop gate agent; do
    printf '%s\n' "$(group_title "$g")"
    while IFS=$'\t' read -r group target desc; do
        [ "$group" = "$g" ] || continue
        printf '  make %-16s %s\n' "$target" "$desc"
    done <<<"$ENTRIES"
    echo
done

cat <<EOF
How long does any of this take? Ask the host, not this page:
  make timings          reads the measured artifacts, and says NOT MEASURED
                        rather than quoting a number from another machine.

This page is a curated subset. The Makefile defines ${total} rule targets;
list them all with:
  grep -E '^[A-Za-z0-9_.-]+:' Makefile

Deeper reading:
  AGENTS.md                          model-neutral mission and authority rules
  CLAUDE.md                          thin Claude compatibility adapter
  docs/HOW_THE_NODE_WORKS.md         the node as a state machine, in one page
  docs/DEFENSIVE_CODING.md           the coding laws and every lint gate
  .claude/skills/z23-dev/     the developer operating manual
EOF
