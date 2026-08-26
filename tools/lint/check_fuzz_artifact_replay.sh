#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_fuzz_artifact_replay.sh — a saved fuzz finding that still reproduces
# fails the build. It is not allowed to just be a file.
#
# THE INCIDENT. On 2026-07-14 a fuzzer found that a five-byte script from any
# peer hangs the node forever. The bytes were committed as
# lib/test/fuzz_seeds/script/timeout-689f73ac89dc1264744711de8383742b90c892b0.bin
# and read by nobody for two weeks. It surfaced only because a human went
# looking. The galling part: THREE mechanisms had already replayed it and
# already gone red.
#
#   make fuzz-ci                     passes the seed dir to libFuzzer, so it
#                                    executes the whole corpus before mutating.
#                                    Exit 70, red since 2026-07-14 — but it is
#                                    reachable only from `make ci`, which no
#                                    hook, timer or workflow runs.
#   background_quality_lane.sh       hourly timer; it CAUGHT this, wrote the
#                                    stack trace to a log, and put its verdict
#                                    in a JSON file nothing gates on.
#   promote_fuzz_artifacts.sh        saw the same bytes a second time and
#                                    logged "SKIP duplicate", exit 0 by design.
#
# So the replay capability was never missing. The VERDICT ROUTING was. Nothing
# that could fail a build ever read the answer. This gate is that route.
#
# WHAT IT CHECKS. Every artifact-prefixed seed under lib/test/fuzz_seeds/
# (crash- / timeout- / oom- / leak- / slow-unit- / minimized-from-, the six
# prefixes libFuzzer writes — see ARTIFACT_RE below for where each comes from)
# must carry exactly one verdict line in lib/test/fuzz_seeds/ARTIFACT_VERDICTS.txt,
# and that verdict must still be TRUE of what the artifact does today:
#
#   ledger says      replays clean            replays as hang/crash
#   ---------------  -----------------------  -------------------------------
#   regression-seed  pass                     FAIL — the bug came back
#   open             FAIL — reclassify it     FAIL — live bug, named + repro'd
#   accepted         FAIL — reclassify it     pass, reprinted loudly every run
#   (no line)        FAIL — untriaged         FAIL — untriaged
#
# Note what `open` does NOT do: it does not suppress anything. An unfixed bug
# stays red. The verdict only gives the redness a name, a date and an owner, so
# the next person reads a sentence instead of a hash. And an entry that has
# stopped being true fails in BOTH directions, so the ledger cannot rot into
# decoration the way a plain allowlist does.
#
# THE ONLY WAY TO PASS WHILE REPRODUCING is `accepted`: per-file, dated,
# reason >= 30 chars, and re-printed by name on every single run. There is no
# directory-wide exemption.
#
# WHAT A GREEN RUN ACTUALLY GUARANTEES. An earlier version of this comment
# claimed "no skip path anywhere". That was a wish, not a property, and on
# 2026-07-29 an adversarial review collected the exit-0 receipts: one artifact
# whose filename contained a single quote aborted `xargs` mid-stream, 14 live
# hangs went unreplayed, and the run printed "0 clean, 0 reproducing / 0
# violations". Nothing was checking that the number of results equalled the
# number of artifacts. The honest statement of what is enforced now, each
# clause backed by a specific line below:
#
#   * Every artifact selected for replay produces exactly one of three
#     verdicts — clean, reproduces, nobin — and that is ASSERTED by count
#     after the replay stage, not assumed from it. A selected artifact with no
#     result is exit 2, named. This is the invariant that matters: an artifact
#     that did not produce a verdict is a FAILURE, never a nothing.
#   * The replay stage's own exit status is captured and checked, so a broken
#     stage (bad -P value, a name xargs chokes on, an OOM-killed child) is
#     exit 2 rather than an empty result set that reads as clean.
#   * The selection is never allowed to be empty, and --corpus= only accepts
#     names that have a fuzz target, so a typo cannot replay nothing quietly.
#   * A file that LOOKS like a saved finding but misses the canonical spelling
#     (CRASH-, crash_, hang-, ...) is refused by name instead of being filed
#     away as an ordinary hand-written seed.
#   * A missing fuzz binary, a corpus with no binary behind it, a binary with
#     no corpus, and an artifact that git tracks but that is absent from disk
#     are each their own failure.
#
# What it still does NOT guarantee: that the corpus contains every finding the
# fuzzer has ever produced (only `promote_fuzz_artifacts.sh` feeds it), and
# that an `accepted` verdict is true — that one is a human judgement, which is
# why it is reprinted by name on every run.
#
# TWO MODES, because the build dominates the cost by 4-20x:
#
#   --ledger-only   Text and git only, milliseconds. Every artifact has a live
#                   binary rule and a recorded verdict; no orphan lines; the
#                   corpus <-> binary mapping is 1:1. This is what `make lint`
#                   runs (gate: check-fuzz-artifact-ledger) — it keeps the
#                   inner loop honest without paying for a fuzz build.
#   (default)       Actually re-runs all of them. This is what `make fuzz-replay`
#                   runs, and it is wired into `make ci` and into its own CI job.
#                   Measured on the dev reference host with binaries prebuilt:
#                   22 artifacts in 18.3 s at -P6 (85.4 s serial). Building the
#                   nine sanitizer-instrumented binaries first is 34 s cold at
#                   -j6 (21 s after a header edit), which is still why this is
#                   not folded into `make lint`.
#
#   --selftest      Plant / trip / recover proof that the gate still fires.
#
# REPLAY INVOCATION — three flags are load-bearing, each for a measured reason:
#   -timeout=5              libFuzzer's default is 1200 s. Without this a hang
#                           spins ~20 minutes instead of failing. 5 s is a ~70x
#                           margin over the slowest clean seed (73 ms).
#   ASAN_OPTIONS=symbolize=0
#                           With symbolization ON the process prints its verdict
#                           at t=5 s and then STALLS ~85 s inside llvm-symbolizer
#                           on a binary that large. That turns a 6 s gate into a
#                           91 s one, or into an outer wall-kill.
#   -artifact_prefix=$work/ libFuzzer writes a repro unit to CWD otherwise —
#                           which is how `make fuzz-ci` drops files into the
#                           repository root and trips check-no-stray-root-files.
#
# ANTI-FLAKE, DELIBERATELY. A unit that trips -timeout=5 and would thereby be a
# NEW accusation (the ledger says regression-seed, or there is no ledger line at
# all) is re-run once, serially, at ZCL_FUZZ_REPLAY_CONFIRM_TIMEOUT (default
# 15 s) before it is called reproducing. This exists because 8 of the 22
# artifacts in this corpus are NOT bugs: they are spurious -timeout=2 trips from
# a contended box, filed automatically with no reproduction check. A gate that
# cries wolf teaches people to ignore it, which is the same failure as silence.
# An artifact the ledger ALREADY records as reproducing is not re-confirmed —
# the result agrees with the record, and confirming all of them anyway cost
# 4 minutes instead of 18 seconds for no additional information.
#
# Mode: WARN | FAIL (ZCL_LINT_MODE; default FAIL).
set -euo pipefail

MODE="${ZCL_LINT_MODE:-FAIL}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"
# Pipeline-free substring predicates. FATAL if missing: the --selftest verdict
# below depends on one, and a gate that silently loses its detector is exactly
# the hollow PASS this file exists to prevent. See tools/scripts/sh_str.sh.
# shellcheck source=tools/scripts/sh_str.sh
. "$ROOT/tools/scripts/sh_str.sh" || { echo "$0: cannot source tools/scripts/sh_str.sh" >&2; exit 2; }
# Shared with tools/scripts/promote_fuzz_artifacts.sh: what phrase in a
# ledger reason counts as "names a fix" or "records a pattern-init replay".
# shellcheck source=tools/scripts/fuzz_verdict_lib.sh
. "$ROOT/tools/scripts/fuzz_verdict_lib.sh" || { echo "$0: cannot source tools/scripts/fuzz_verdict_lib.sh" >&2; exit 2; }

SEED_ROOT="lib/test/fuzz_seeds"
LEDGER="$SEED_ROOT/ARTIFACT_VERDICTS.txt"
GATE="check_fuzz_artifact_replay"

# libFuzzer's artifact filename prefixes — the COMPLETE set, read off
# compiler-rt/lib/fuzzer rather than remembered. An artifact is a finding the
# fuzzer SAVED because a run went wrong; a plain seed is hand-authored input.
# Only the former carries a verdict.
#
#   crash-           FuzzerLoop.cpp CrashCallback / DeathCallback /
#                    ExitCallback / HandleMalloc — any deadly signal, any
#                    sanitizer report, -error_exitcode.
#   timeout-         FuzzerLoop.cpp AlarmCallback — the -timeout= wall.
#   oom-             FuzzerLoop.cpp RssLimitCallback and the malloc-limit
#                    path — -rss_limit_mb / -malloc_limit_mb.
#   leak-            FuzzerLoop.cpp TryDetectingAMemoryLeak — LSan.
#   slow-unit-       FuzzerLoop.cpp ExecuteCallback — a unit slower than
#                    -report_slow_units.
#   minimized-from-  FuzzerDriver.cpp MinimizeCrashInput — what
#                    `-minimize_crash=1` writes. This one was MISSING until
#                    2026-07-29, which meant the natural next step after a
#                    crash- lands (minimize it, commit the small one) produced
#                    a finding this gate could not see.
#
# Those six are all of them: they are every literal that reaches
# WriteUnitToFileWithPrefix(), plus the one ArtifactPrefix concatenation in
# the crash minimizer. Deliberately not in the list: `-cleanse_crash` writes
# no prefixed name (it REQUIRES -exact_artifact_path and refuses to run
# without it), and -merge / the output-corpus writer emit a bare content hash,
# which is a seed, not a finding.
ARTIFACT_RE='^(crash|timeout|oom|leak|slow-unit|minimized-from)-'

# Names that are TRYING to be an artifact but are not one of the six: wrong
# case, an underscore where libFuzzer writes a hyphen, or a hand-invented word
# like "hang-". Each is a file somebody saved because something went wrong,
# and each would otherwise be enumerated as an ordinary hand-authored seed and
# never replayed — the original bug in miniature. Matched against the
# lowercased basename, so CRASH- and Crash- land here too, and reported as a
# violation that says what to rename it to. If a legitimate hand-written seed
# ever needs one of these words, rename the seed: the cost of a false positive
# is one rename, the cost of a false negative is an unread finding.
NEARMISS_RE='^(crash|crashes|timeout|timeouts|oom|ooms|leak|leaks|slow-unit|slow_unit|slowunit|minimized-from|minimized_from|minimized|hang|hangs|repro|abort|assert)[-_]'

REPLAY_TIMEOUT="${ZCL_FUZZ_REPLAY_TIMEOUT:-5}"
CONFIRM_TIMEOUT="${ZCL_FUZZ_REPLAY_CONFIRM_TIMEOUT:-15}"
JOBS="${ZCL_FUZZ_REPLAY_JOBS:-6}"
BIN_DIR="${ZCL_LINT_BIN_DIR:-build/bin}"
# Where promote_fuzz_artifacts.sh builds the pattern-init variant (see its
# ensure_binary()/the Makefile's ZCL_FUZZ_EXTRA_CFLAGS hook). Only consulted
# below for the one case where getting it wrong would push a real "open"
# finding back to a false "regression-seed": a crash-/leak- artifact whose
# STOCK replay just came back clean. Never required to exist — a missing
# pattern-init binary here means "cannot confirm", not "clean".
PI_BIN_DIR="${ZCL_LINT_PATTERNINIT_BIN_DIR:-build/fuzz-patterninit/bin}"

# Env equivalents of the two flags, so the C selftest registry in
# lib/test/src/test_make_lint_gates.c can drive this gate through
# run_gate_script(), which passes a mode env var and no argv. Same shape as
# ZCL_CONDITION_COOLDOWN_SELFTEST / ZCL_MARKDOWN_LINKS_SELFTEST.
LEDGER_ONLY="${ZCL_FUZZ_REPLAY_LEDGER_ONLY:-0}"
SELFTEST="${ZCL_FUZZ_REPLAY_SELFTEST:-0}"
ONLY_CORPORA=""
for arg in "$@"; do
    case "$arg" in
        --ledger-only) LEDGER_ONLY=1 ;;
        --selftest)    SELFTEST=1 ;;
        --corpus=*)    ONLY_CORPORA="${arg#--corpus=}" ;;
        -h|--help)
            echo "usage: check_fuzz_artifact_replay.sh [--ledger-only] [--selftest] [--corpus=a,b]"
            exit 0 ;;
        *) echo "$GATE: unknown arg '$arg'" >&2; exit 2 ;;
    esac
done

# One finding = one violation, however many lines it takes to explain itself.
# `report` opens a finding and counts it; `note` adds context to the finding
# already open. (Counting lines instead of findings reported "42 violations"
# for 14 broken artifacts, which is the kind of number that makes a red build
# look worse than it is and teaches people to discount it.)
violations=0
report() { violations=$((violations + 1)); echo "    $*" >&2; }
note()   { echo "      $*" >&2; }

# ── --selftest: prove the gate still FIRES ───────────────────────────────
# A gate that reports clean because it can no longer fail is the failure mode
# this whole file exists to prevent, so "clean" is only trustworthy after the
# detector has been shown to still trip. Plant an untriaged artifact into a
# real corpus dir, assert the ledger half rejects it AND names it, remove it,
# assert recovery. Uses a distinctive fixture name so a crashed run leaves
# something obvious rather than something that looks like a real finding.
if (( SELFTEST )); then
    # The child invocations below are plain --ledger-only runs. Clear the env
    # triggers first or a ZCL_FUZZ_REPLAY_SELFTEST=1 invocation re-enters the
    # selftest in every child, forever.
    unset ZCL_FUZZ_REPLAY_SELFTEST ZCL_FUZZ_REPLAY_LEDGER_ONLY
    fixture="$SEED_ROOT/block/crash-selftest-planted-not-a-real-finding.bin"
    rm -f "$fixture"
    if ! out="$("$0" --ledger-only 2>&1)"; then
        echo "$GATE --selftest: FAIL — the clean tree does not pass" >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    printf '\x4e\xfb\xff\xff\xff' > "$fixture"
    trip_rc=0
    trip_out="$("$0" --ledger-only 2>&1)" || trip_rc=$?
    rm -f "$fixture"
    if [[ "$trip_rc" -eq 0 ]]; then
        echo "$GATE --selftest: FAIL — a planted untriaged artifact did NOT trip the gate" >&2
        exit 1
    fi
    # str_lacks, not `printf | grep -qF`: under pipefail a MATCH could come
    # back as printf's SIGPIPE 141, i.e. "the gate never named the file" when
    # it had. MEASURED 2026-07-30: `$trip_out` is 423 bytes, so the inversion
    # is NOT reachable at that size — a shape fix, not a live-bug fix, kept
    # because the transcript grows with findings. Fixed string in, fixed string
    # out: str_contains quotes the needle, so this is identical to grep -qF.
    if str_lacks "$trip_out" "$fixture"; then
        echo "$GATE --selftest: FAIL — the gate tripped but never named $fixture" >&2
        echo "  Naming the exact file is the point: a red build must not send" >&2
        echo "  anyone hunting for which artifact broke." >&2
        printf '%s\n' "$trip_out" >&2
        exit 1
    fi
    if ! "$0" --ledger-only >/dev/null 2>&1; then
        echo "$GATE --selftest: FAIL — the gate stayed red after the fixture was removed" >&2
        exit 1
    fi
    echo "[$GATE] selftest: clean passes, planted artifact trips and is NAMED, removal recovers"
    exit 0
fi

# ── The corpus <-> binary map, DERIVED from the Makefile ─────────────────
# Never hand-written: a new fuzz target is covered the day its rule lands, and
# a corpus whose binary rule was renamed away becomes a failure instead of a
# quiet skip. The mapping the Makefile itself uses (fuzz-ci, Makefile:3932) is
# kind = basename minus "fuzz_", corpus dir = lib/test/fuzz_seeds/<kind>.
declare -A BIN_KIND=()
kind_count=0
while IFS= read -r k; do
    [[ -z "$k" ]] && continue
    BIN_KIND["$k"]=1
    kind_count=$((kind_count + 1))
done < <(gate_grep -oE '^\$\(BIN_DIR\)/fuzz_[a-z_0-9]+:' Makefile \
         | sed 's|^\$(BIN_DIR)/fuzz_||; s|:$||' | sort -u || true)

gate_require_scanned "$kind_count" 5 "$GATE" \
    "no \$(BIN_DIR)/fuzz_<kind> rules found in the Makefile — did the rule spelling change?"

# ── Load the ledger ──────────────────────────────────────────────────────
declare -A LEDGER_VERDICT=() LEDGER_DATE=() LEDGER_REASON=() LEDGER_SEEN=()
ledger_lines=0
if [[ ! -f "$LEDGER" ]]; then
    echo "$GATE: FATAL — $LEDGER is missing." >&2
    echo "  Every saved fuzz artifact needs a written verdict. Without the" >&2
    echo "  ledger this gate cannot tell a triaged finding from an unread one," >&2
    echo "  and reporting 'clean' off that is the exact hole it exists to close." >&2
    exit 2
fi
while IFS= read -r raw; do
    line="${raw%%#*}"
    reason="${raw#*#}"
    [[ "$raw" != *"#"* ]] && reason=""
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    read -r f v d _rest <<< "$line"
    reason="${reason#"${reason%%[![:space:]]*}"}"
    if [[ -n "${LEDGER_VERDICT[$f]:-}" ]]; then
        report "$LEDGER: duplicate entry for '$f' — one line per artifact"
    fi
    LEDGER_VERDICT["$f"]="$v"
    LEDGER_DATE["$f"]="$d"
    LEDGER_REASON["$f"]="$reason"
    ledger_lines=$((ledger_lines + 1))
done < "$LEDGER"

# ── Enumerate the artifacts ──────────────────────────────────────────────
# Tracked AND untracked-but-present, because both are findings. A repro that a
# local fuzz run dropped into the corpus and nobody committed is the same hole
# in a smaller form — the bytes exist, they reproduce, and no build reads them.
# So an untracked artifact is enumerated, replayed, AND reported as its own
# violation: commit it with a verdict, or delete it.
artifacts=()
nearmiss=()
declare -A UNTRACKED=() ENUMERATED=() KIND_OF=()
scanned=0

# Classify one repo-relative path found under $SEED_ROOT. Shared by all three
# enumerators below so the artifact / near-miss / plain-seed decision is made
# in exactly one place and cannot drift between them.
#   $1 = path (repo-relative)   $2 = "tracked" | "untracked"
consider_path() {
    local p="$1" origin="$2" base rel lc
    [[ -z "$p" ]] && return 0
    base="${p##*/}"
    rel="${p#"$SEED_ROOT"/}"
    [[ "$rel" == */* ]] || return 0          # corpus-dir-relative only
    # `git ls-files` repeats a path that has unmerged index stages, and the
    # tracked and untracked passes could in principle both name one. Counting
    # it twice would inflate `scanned` and replay it twice; first sighting wins.
    [[ -n "${ENUMERATED[$rel]:-}" ]] && return 0
    ENUMERATED["$rel"]=1
    if [[ "$base" =~ $ARTIFACT_RE ]]; then
        artifacts+=("$rel")
        KIND_OF["$rel"]="${BASH_REMATCH[1]}"
        if [[ "$origin" == untracked ]]; then UNTRACKED["$rel"]=1; fi
        scanned=$((scanned + 1))
        return 0
    fi
    lc="${base,,}"
    if [[ "$lc" =~ $NEARMISS_RE ]]; then
        nearmiss+=("$rel")
    fi
    return 0
}

# git is the preferred enumerator because it can tell a committed finding from
# an uncommitted one. It is not always safe to trust: the lint-gate selftest
# runs every sandbox-lane gate inside an inode-independent private clone that
# deliberately omits .git (so a tarball checkout would look the same), but
# that copy typically lives under a runtime directory (e.g.
# .claude/worktrees/<name>.lint_sb_<pid>/w<n>) that is itself nested inside a
# REAL git worktree/repo one or more levels up. `git rev-parse --git-dir`
# walks UP the directory tree looking for a .git, so from inside the
# git-less sandbox it does not fail — it keeps climbing past the sandbox and
# finds the outer repo's real .git, and happily reports success. That is a
# genuine repo, just not the one this script's $SEED_ROOT is meant to be
# read from: $ROOT (this script's own directory two levels up) is the
# sandbox copy, but git's resolved top-level is the ancestor repo, so
# `git ls-files "$SEED_ROOT"` is asking for a path relative to the WRONG
# tree. Measured 2026-07-30: inside the sandbox, `git rev-parse
# --show-toplevel` printed the outer repo's root while $ROOT was the
# sandbox path underneath it — and since .claude/worktrees/ is itself
# gitignored there, both the tracked and the --others --exclude-standard
# passes came back with nothing, silently reporting 0 artifacts scanned
# instead of erroring or falling back. So "git is available" is not the
# right test; "git resolves to THIS tree" is. Compare --show-toplevel
# against $ROOT and only trust git when they match. Fall back to `find` and
# SAY SO whenever they don't (deliberately git-less sandbox, tarball
# checkout, or — this case — git present but pointed at an ancestor repo) —
# the artifacts still all get replayed, only the tracked/untracked split
# goes unchecked. A silent degrade here would be the same class of problem
# as the hole this gate closes, so it is announced, not assumed.
# All three enumerators are NUL-delimited (`git ls-files -z`, `find -print0`).
# Line-delimited git output is not safe here: with the default core.quotePath
# git RENAMES a path containing a quote or a non-ASCII byte into a C-quoted
# string, and a path containing a newline becomes two lines. Either turns one
# artifact into a name that does not exist on disk, which is a skip.
GIT_TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -n "$GIT_TOPLEVEL" && "$GIT_TOPLEVEL" == "$ROOT" ]]; then
    while IFS= read -r -d '' p; do
        consider_path "$p" tracked
    done < <( git ls-files -z "$SEED_ROOT" 2>/dev/null || true )

    while IFS= read -r -d '' p; do
        consider_path "$p" untracked
    done < <( git ls-files -z --others --exclude-standard "$SEED_ROOT" 2>/dev/null || true )
else
    if [[ -z "$GIT_TOPLEVEL" ]]; then
        echo "[$GATE] no git here — enumerating with find; every artifact is still"
    else
        echo "[$GATE] git resolved to '$GIT_TOPLEVEL', not this tree ('$ROOT') —" \
             "enumerating with find instead; every artifact is still"
    fi
    echo "[$GATE] replayed and still needs a verdict, but the tracked vs"
    echo "[$GATE] uncommitted distinction is NOT being checked on this run."
    while IFS= read -r -d '' p; do
        consider_path "$p" tracked
    done < <(find "$SEED_ROOT" -mindepth 2 -maxdepth 2 -type f -print0 2>/dev/null)
fi

gate_require_scanned "$scanned" 20 "$GATE" \
    "git ls-files found almost no saved artifacts under $SEED_ROOT — wrong cwd, or the corpus moved?"

echo "[$GATE] $scanned saved artifact(s); $ledger_lines ledger line(s); ${kind_count} fuzz target(s)"

# ── (1) Structural checks — the cheap half, always run ───────────────────
VALID_VERDICTS=" regression-seed open accepted "

# A file that is trying to be a finding but is not spelled like one. It would
# otherwise be filed as an ordinary hand-written seed: never replayed against a
# verdict, never demanded of the ledger, invisible. `minimized-from-` was
# exactly this until 2026-07-29 — a real libFuzzer prefix the regex missed —
# so the near-miss list is deliberately wider than the six canonical prefixes.
for rel in "${nearmiss[@]}"; do
    report "$SEED_ROOT/$rel [NOT A LIBFUZZER ARTIFACT NAME — nothing will ever replay it]"
    note "This reads as a saved finding but does not match any prefix"
    note "libFuzzer writes, so the gate would file it as a hand-authored seed"
    note "and never demand a verdict for it."
    note "Rename it to one of: crash- timeout- oom- leak- slow-unit- minimized-from-"
    note "(hyphen, lowercase, then the hash), then add its verdict line to"
    note "$LEDGER. If it really is a hand-written"
    note "seed, give it a name that does not start with a finding word."
done

for rel in "${artifacts[@]}"; do
    corpus="${rel%%/*}"
    LEDGER_SEEN["$rel"]=1

    if [[ -n "${UNTRACKED[$rel]:-}" ]]; then
        report "$SEED_ROOT/$rel [UNCOMMITTED — a saved repro sitting in the corpus, untracked]"
        note "A finding nobody committed is a finding nobody reads. Either"
        note "'git add' it and record a verdict in $LEDGER,"
        note "or delete it if it was local debris."
    fi

    # Tracked by git but gone from the working tree. The replay half would
    # hand libFuzzer a path that does not exist, get a non-zero exit, and
    # report the artifact as "reproduces" — a true-looking red for a false
    # reason, and in --ledger-only it was not visible at all.
    if [[ ! -f "$SEED_ROOT/$rel" ]]; then
        report "$SEED_ROOT/$rel [MISSING FROM DISK — git tracks it, the file is not there]"
        note "A deleted artifact is not a triaged one. Restore it"
        note "('git checkout -- $SEED_ROOT/$rel'), or 'git rm' it AND delete"
        note "its line from $LEDGER so the record"
        note "says the finding left the corpus on purpose."
        continue
    fi

    if [[ -z "${BIN_KIND[$corpus]:-}" ]]; then
        report "$SEED_ROOT/$rel [no fuzz binary: the Makefile has no \$(BIN_DIR)/fuzz_$corpus rule]"
        note "An artifact nothing can replay is an artifact nobody will read."
        continue
    fi

    v="${LEDGER_VERDICT[$rel]:-}"
    if [[ -z "$v" ]]; then
        report "$SEED_ROOT/$rel [UNTRIAGED — no verdict recorded]"
        note "Reproduce it:  ASAN_OPTIONS=detect_leaks=0:symbolize=0 \\"
        note "  timeout -k 5 $((REPLAY_TIMEOUT + 10)) $BIN_DIR/fuzz_$corpus -timeout=$REPLAY_TIMEOUT \\"
        note "  -runs=1 -artifact_prefix=/tmp/ $SEED_ROOT/$rel"
        note "Then add one line to $LEDGER:"
        note "  $rel  <regression-seed|open|accepted>  $(date -u +%Y-%m-%d)  # why"
        continue
    fi
    case "$VALID_VERDICTS" in
        *" $v "*) ;;
        *)
            if [[ "$v" == "unaudited" ]]; then
                # Written by the OLD promote_fuzz_artifacts.sh when it filed a
                # new artifact straight from its filename. Deliberately not a
                # verdict: it is a placeholder that keeps the build red until
                # a human has actually replayed the thing and decided
                # something. Rejecting it here IS the feature. The current
                # promoter no longer writes this — it replays before it files
                # — but old trees or a hand-edit can still produce one.
                report "$SEED_ROOT/$rel [UNAUDITED — auto-filed on ${LEDGER_DATE[$rel]:-?}, nobody has triaged it]"
                note "Replay it:  ASAN_OPTIONS=detect_leaks=0:symbolize=0 \\"
                note "  timeout -k 5 $((REPLAY_TIMEOUT + 10)) $BIN_DIR/fuzz_$corpus -timeout=$REPLAY_TIMEOUT \\"
                note "  -runs=1 -artifact_prefix=/tmp/ $SEED_ROOT/$rel"
                note "Then replace its line in $LEDGER with a real"
                note "verdict: regression-seed (it is clean), open (it is a bug you"
                note "have not fixed), or accepted (it is genuinely not a bug, +why)."
            elif [[ "$v" == "unreplayable" ]]; then
                # Written by promote_fuzz_artifacts.sh when it could not get
                # the evidence this artifact's bug class requires (missing or
                # unbuildable stock or pattern-init binary). Fail-closed by
                # design: an artifact nobody could replay is never allowed to
                # read as clean just because nothing contradicted it.
                report "$SEED_ROOT/$rel [UNREPLAYABLE — filed ${LEDGER_DATE[$rel]:-?}, promoter could not get a verdict]"
                note "${LEDGER_REASON[$rel]:-}"
                note "Build the missing binary (stock: 'make fuzz_$corpus'; pattern-init:"
                note "  'make BUILD_DIR=build/fuzz-patterninit ZCL_FUZZ_EXTRA_CFLAGS=-ftrivial-auto-var-init=pattern fuzz_$corpus')"
                note "then re-run promote_fuzz_artifacts.sh or replay it by hand and write a real verdict."
            else
                report "$LEDGER: '$rel' has unknown verdict '$v' (want regression-seed | open | accepted)"
            fi ;;
    esac
    d="${LEDGER_DATE[$rel]:-}"
    [[ "$d" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || \
        report "$LEDGER: '$rel' has no valid YYYY-MM-DD date (got '$d')"
    r="${LEDGER_REASON[$rel]:-}"
    if [[ -z "$r" ]]; then
        report "$LEDGER: '$rel' has no reason — say what you decided and why"
    elif [[ "$v" == "accepted" && ${#r} -lt 30 ]]; then
        report "$LEDGER: '$rel' is 'accepted' with a ${#r}-char reason (need >= 30)"
        note "'accepted' is the ONLY verdict that lets a reproducing artifact"
        note "pass a build. It costs a real sentence. A bug you have not"
        note "fixed is 'open', not 'accepted'."
    fi

    # "It did not reproduce" is not, by itself, enough to close a crash-/leak-
    # kind artifact. A stale-stack bug can be probabilistic on a clean
    # process (a freshly-mapped stack reads back as zero), so ONE clean
    # replay proves nothing about it — see fuzz_verdict_lib.sh's header for
    # the incident this closes: a real remote memory-safety bug was once
    # filed 'regression-seed' with a reason that said, in so many words,
    # "not explained, only unreproducible". Closing it requires either a
    # named fix ("fixed by ..." / "root cause: ...") or an explicit
    # pattern-init replay that ALSO came back clean. timeout-/oom-/slow-unit-
    # kinds are a different, algorithmic bug class and are not held to this.
    if [[ "$v" == "regression-seed" && -n "$r" ]]; then
        kind="${KIND_OF[$rel]:-}"
        if ! regression_seed_reason_is_sufficient "$kind" "$r"; then
            report "$LEDGER: '$rel' ($kind) closed 'regression-seed' on non-reproduction alone"
            note "reason: $r"
            note "A $kind finding needs a named fix ('fixed by <commit>') or an"
            note "explicit pattern-init replay recorded in the reason ('pattern-init:"
            note "clean (Nx)') before it can close. 'it replayed clean' by itself is"
            note "not exoneration — a freshly-mapped stack reads as zero, so one"
            note "clean run proves nothing about a stale-stack bug. Rebuild under"
            note "  make BUILD_DIR=build/fuzz-patterninit \\"
            note "    ZCL_FUZZ_EXTRA_CFLAGS=-ftrivial-auto-var-init=pattern fuzz_$corpus"
            note "and replay against that binary too, then record what it did."
        fi
    fi
done

# Orphan ledger lines: an entry whose file is gone is a verdict about nothing,
# and it hides the fact that the finding left the corpus.
for f in "${!LEDGER_VERDICT[@]}"; do
    [[ -n "${LEDGER_SEEN[$f]:-}" ]] && continue
    report "$LEDGER: line for '$f' but no such tracked artifact — delete the line or restore the file"
done

# Every fuzz binary must own a corpus dir, and vice versa. This is the 9<->9
# invariant; a target with no corpus is a target whose findings have nowhere
# to land.
for k in "${!BIN_KIND[@]}"; do
    [[ -d "$SEED_ROOT/$k" ]] || \
        report "$SEED_ROOT/$k/ missing — \$(BIN_DIR)/fuzz_$k exists but has no corpus dir"
done
while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    k="${d##*/}"
    [[ -n "${BIN_KIND[$k]:-}" ]] || \
        report "$SEED_ROOT/$k/ has no fuzz binary — add a \$(BIN_DIR)/fuzz_$k rule or remove the corpus"
done < <(find "$SEED_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)

if (( LEDGER_ONLY )); then
    echo "[$GATE] ledger-only: structure checked, no artifact replayed"
    echo "[$GATE] the replay itself is 'make fuzz-replay' (in make ci) — this half"
    echo "[$GATE] only proves every finding has a live binary and a written verdict."
    echo "[$GATE] $violations violation(s) found (mode: $MODE)"
    if (( violations > 0 )) && [[ "$MODE" == "FAIL" ]]; then exit 1; fi
    exit 0
fi

# ── (2) Replay — the half that catches a returning bug ───────────────────
work="$(mktemp -d "${TMPDIR:-/tmp}/zcl-fuzz-replay.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# One artifact -> one NUL-terminated "<state>\t<rel>" record on stdout. state
# is clean | reproduces | nobin. Runs with CWD inside $work so nothing
# libFuzzer writes can reach the repo.
#
# State FIRST and tab-separated, NUL-terminated: the old "<rel> <state>" form
# was parsed with `read -r rel st`, which mangles any artifact name containing
# a space and cannot represent one containing a newline. The state token is a
# fixed word with no separators in it, so putting it first makes the record
# unambiguous whatever the filename is.
replay_one() {
    local rel="$1" tmo="$2"
    local corpus="${rel%%/*}"
    local bin="$ROOT/$BIN_DIR/fuzz_$corpus"
    if [[ ! -x "$bin" ]]; then printf '%s\t%s\0' nobin "$rel"; return 0; fi
    local rc=0
    ( cd "$work" && \
      ASAN_OPTIONS=detect_leaks=0:symbolize=0 \
      UBSAN_OPTIONS=print_stacktrace=0 \
      timeout -k 5 "$((tmo + 10))" "$bin" \
        -timeout="$tmo" -rss_limit_mb=2048 -runs=1 \
        -timeout_exitcode=70 -error_exitcode=77 \
        -artifact_prefix="$work/" \
        "$ROOT/$SEED_ROOT/$rel" >/dev/null 2>&1 ) || rc=$?
    if [[ "$rc" -eq 0 ]]; then printf '%s\t%s\0' clean "$rel"
    else printf '%s\t%s\0' reproduces "$rel"; fi
}
export -f replay_one
export ROOT work BIN_DIR SEED_ROOT

# ── Selection. A filter that selects nothing is not a clean run ──────────
# `--corpus=blockk` used to replay 0 artifacts and exit 0: a one-character typo
# turned the gate into a no-op that still printed a pass. Both halves of that
# are now refused — an unknown corpus name, and an empty selection however it
# arose.
if [[ -n "$ONLY_CORPORA" ]]; then
    IFS=',' read -r -a want_corpora <<< "$ONLY_CORPORA"
    for c in "${want_corpora[@]}"; do
        [[ -z "$c" ]] && continue
        if [[ -z "${BIN_KIND[$c]:-}" ]]; then
            echo "$GATE: FATAL — --corpus='$c' names no fuzz target." >&2
            echo "  The Makefile has no \$(BIN_DIR)/fuzz_$c rule, so this run" >&2
            echo "  would replay nothing and report clean. A typo in a filter" >&2
            echo "  is not allowed to look like an audited corpus." >&2
            echo "  Known corpora: $(printf '%s ' "${!BIN_KIND[@]}" | tr ' ' '\n' | sort | tr '\n' ' ')" >&2
            exit 2
        fi
    done
fi

selected=()
for rel in "${artifacts[@]}"; do
    if [[ -n "$ONLY_CORPORA" ]]; then
        case ",$ONLY_CORPORA," in *",${rel%%/*},"*) ;; *) continue ;; esac
    fi
    selected+=("$rel")
done

if (( ${#selected[@]} == 0 )); then
    echo "$GATE: FATAL — nothing was selected for replay." >&2
    echo "  $scanned artifact(s) were enumerated${ONLY_CORPORA:+, then --corpus=$ONLY_CORPORA filtered them all out}." >&2
    echo "  A replay run that replays nothing has proved nothing, so it does" >&2
    echo "  not get to exit 0. Widen or drop the --corpus filter." >&2
    exit 2
fi

echo "[$GATE] replaying ${#selected[@]} artifact(s) at -timeout=${REPLAY_TIMEOUT}s, ${JOBS} at a time"

# ── The replay stage, which is not allowed to fail quietly ───────────────
# Two things used to make it do exactly that, and both were demonstrated:
#
#   * `xargs` without -0 does quote processing, so ONE artifact named with a
#     single quote aborted xargs mid-stream. Everything after it never ran.
#     Planting lib/test/fuzz_seeds/script/crash-'x.bin took a run from
#     "RC=1, 14 live hangs named" to "RC=0, 0 clean, 0 reproducing".
#   * the whole pipeline sat inside `done < <( ... )`, whose exit status bash
#     discards. ZCL_FUZZ_REPLAY_JOBS=notanumber -> "xargs: invalid number" ->
#     zero results -> exit 0. The quote was one instance of the class; ANY
#     failure of this stage produced the same clean green.
#
# So: NUL-delimited both directions, the stage's status captured through a
# real pipeline (pipefail is on) instead of a process substitution, and the
# per-artifact accounting asserted below rather than assumed.
replay_out="$work/replay.records"
replay_rc=0
printf '%s\0' "${selected[@]}" \
    | xargs -0 -P "$JOBS" -I{} bash -c 'replay_one "$@"' _ {} "$REPLAY_TIMEOUT" \
    > "$replay_out" || replay_rc=$?
if (( replay_rc != 0 )); then
    echo "$GATE: FATAL — the replay stage exited $replay_rc." >&2
    echo "  Not one artifact's result can be trusted, so this run reports" >&2
    echo "  nothing rather than reporting clean. Check ZCL_FUZZ_REPLAY_JOBS" >&2
    echo "  (currently '$JOBS'), and check the stderr above this line." >&2
    exit 2
fi

declare -A STATE=()
while IFS=$'\t' read -r -d '' st rel; do
    [[ -z "$rel" ]] && continue
    STATE["$rel"]="$st"
done < "$replay_out"

# ── THE ACCOUNTING ASSERTION ─────────────────────────────────────────────
# An artifact that did not produce a verdict is a FAILURE, never a nothing.
# This is the assertion whose absence let a single quote hide 14 live remote
# denial-of-service hangs behind a green build. It is independent of the -0
# fix above on purpose: -0 closes the one hole that was found, this closes
# every hole of that shape, including the next one nobody has thought of.
unaccounted=()
for rel in "${selected[@]}"; do
    [[ -n "${STATE[$rel]:-}" ]] || unaccounted+=("$rel")
done
if (( ${#unaccounted[@]} > 0 )); then
    echo "$GATE: FATAL — ${#unaccounted[@]} of ${#selected[@]} selected artifact(s) came back with no result." >&2
    echo "  The replay stage exited 0 but did not account for every artifact" >&2
    echo "  it was given. A missing result is not a pass: these were never" >&2
    echo "  run, so nothing is known about them." >&2
    for rel in "${unaccounted[@]}"; do
        printf '    %s\n' "$SEED_ROOT/$rel" >&2
    done
    exit 2
fi

# Anti-flake confirmation: re-run ONCE, serially, on a longer clock — but ONLY
# where a hit would be a NEW accusation. Under -P6 on a busy box a genuinely
# fast unit can lose enough CPU to trip a 5 s wall, and that is exactly how the
# 8 noise artifacts in this corpus got filed in the first place; serial + 15 s
# removes that class before we call anything a regression.
#
# An artifact the ledger already records as reproducing (open / accepted) needs
# no second opinion: the result agrees with the record, and confirming it costs
# CONFIRM_TIMEOUT seconds each. Confirming all of them turned a ~20 s gate into
# a 4-minute one for no information.
for rel in "${selected[@]}"; do
    [[ "${STATE[$rel]:-}" == "reproduces" ]] || continue
    case "${LEDGER_VERDICT[$rel]:-}" in
        open|accepted) continue ;;   # expected to reproduce; nothing to confirm
    esac
    st=""
    IFS=$'\t' read -r -d '' st _ < <(replay_one "$rel" "$CONFIRM_TIMEOUT") || true
    if [[ -z "$st" ]]; then
        echo "$GATE: FATAL — the confirmation re-run of $rel produced no result." >&2
        echo "  Same rule as the first pass: an artifact with no verdict is a" >&2
        echo "  failure, not a nothing. Refusing to guess which it was." >&2
        exit 2
    fi
    STATE["$rel"]="$st"
    if [[ "$st" == "clean" ]]; then
        echo "[$GATE] $rel tripped ${REPLAY_TIMEOUT}s under load but is clean at" \
             "${CONFIRM_TIMEOUT}s serial — treated as load noise, not a finding"
    fi
done

n_clean=0; n_repro=0; n_nobin=0; accepted_live=()
for rel in "${selected[@]}"; do
    st="${STATE[$rel]:-}"
    v="${LEDGER_VERDICT[$rel]:-}"
    corpus="${rel%%/*}"
    repro_cmd="ASAN_OPTIONS=detect_leaks=0:symbolize=0 timeout -k 5 $((CONFIRM_TIMEOUT + 10)) $BIN_DIR/fuzz_$corpus -timeout=$CONFIRM_TIMEOUT -runs=1 -artifact_prefix=/tmp/ $SEED_ROOT/$rel"

    case "$st" in
    nobin)
        n_nobin=$((n_nobin + 1))
        report "$SEED_ROOT/$rel [$BIN_DIR/fuzz_$corpus MISSING — cannot replay]"
        note "Build it:  make fuzz_$corpus"
        note "This is a FAILURE, not a skip: an artifact nobody replays is"
        note "an artifact nobody reads, which is the whole incident."
        ;;
    clean)
        n_clean=$((n_clean + 1))
        case "$v" in
        regression-seed) ;;   # the good case
        open)
            kind="${KIND_OF[$rel]:-}"
            pi_bin="$ROOT/$PI_BIN_DIR/fuzz_$corpus"
            pi_status=""
            if verdict_kind_needs_pattern_init_evidence "$kind"; then
                if [[ -x "$pi_bin" ]]; then
                    pi_rc=0
                    ( cd "$work" && ASAN_OPTIONS=detect_leaks=0:symbolize=0 \
                      UBSAN_OPTIONS=print_stacktrace=0 \
                      timeout -k 5 "$((CONFIRM_TIMEOUT + 10))" "$pi_bin" \
                        -timeout="$CONFIRM_TIMEOUT" -rss_limit_mb=2048 -runs=1 \
                        -timeout_exitcode=70 -error_exitcode=77 \
                        -artifact_prefix="$work/" \
                        "$ROOT/$SEED_ROOT/$rel" >/dev/null 2>&1 ) || pi_rc=$?
                    [[ "$pi_rc" -ne 0 ]] && pi_status="reproduces" || pi_status="clean"
                fi
            fi
            case "$pi_status" in
            reproduces)
                echo "[$GATE] $rel: stock replay is clean but pattern-init still" \
                     "reproduces — 'open' stands, this is NOT a stale verdict" ;;
            clean|"")
                # kind does not need pattern-init evidence (timeout/oom/slow-unit),
                # OR it does and pattern-init ALSO came back clean, OR there is no
                # pattern-init binary to ask (ambiguous — reported as its own,
                # distinct violation below rather than silently assumed clean).
                if [[ "$pi_status" == "" ]] && verdict_kind_needs_pattern_init_evidence "$kind"; then
                    report "$SEED_ROOT/$rel [ledger says 'open', stock replay is clean, and there is no pattern-init binary to confirm it — cannot tell]"
                    note "Build it:  make BUILD_DIR=$PI_BIN_DIR/.. ZCL_FUZZ_EXTRA_CFLAGS=-ftrivial-auto-var-init=pattern fuzz_$corpus"
                    note "then re-run. Neither reclassifying nor leaving this stale is"
                    note "safe without that answer for a $kind finding."
                else
                    report "$SEED_ROOT/$rel [ledger says 'open' but it no longer reproduces]"
                    note "Fixed? Then say so — reclassify to 'regression-seed' in"
                    note "$LEDGER with today's date and the commit that fixed it."
                    note "A stale 'open' is how a ledger rots into decoration."
                fi ;;
            esac ;;
        accepted)
            report "$SEED_ROOT/$rel [ledger says 'accepted' but it no longer reproduces]"
            note "Reclassify to 'regression-seed' — an 'accepted' entry that"
            note "does nothing is an exemption nobody is checking." ;;
        esac ;;
    reproduces)
        n_repro=$((n_repro + 1))
        case "$v" in
        accepted)
            accepted_live+=("$rel") ;;
        regression-seed)
            report "$SEED_ROOT/$rel [REGRESSION — recorded clean on ${LEDGER_DATE[$rel]:-?}, hangs/crashes NOW]"
            note "This artifact was audited and passed. It does not any more."
            note "Reproduce it:  $repro_cmd" ;;
        open)
            report "$SEED_ROOT/$rel [LIVE — still reproduces; filed ${LEDGER_DATE[$rel]:-?}]"
            note "${LEDGER_REASON[$rel]:-}"
            note "Reproduce it:  $repro_cmd" ;;
        esac ;;
    *)
        # Unreachable while the accounting assertion above holds — which is
        # exactly why it is here. This `case` used to have no default arm, so
        # an artifact with no state fell through it silently and was counted
        # as neither clean nor reproducing. Belt and braces: if a state token
        # ever appears that replay_one does not emit, it is a violation with a
        # name on it, not a gap in the summary.
        report "$SEED_ROOT/$rel [UNACCOUNTED — replay state '${st:-<empty>}' is not a verdict]"
        note "Every replayed artifact must come back clean, reproduces or"
        note "nobin. Anything else means this file's result was lost, and a"
        note "lost result is an unread finding — the whole incident."
        ;;
    esac
done

# Accepted-and-reproducing is the one pass-while-red path, so it is printed by
# name every single run. An exemption that stops being visible stops being a
# decision and becomes a habit.
if (( ${#accepted_live[@]} > 0 )); then
    echo "[$GATE] ${#accepted_live[@]} artifact(s) reproduce and are explicitly ACCEPTED:"
    for rel in "${accepted_live[@]}"; do
        echo "[$GATE]   $rel — ${LEDGER_REASON[$rel]:-}"
    done
fi

echo "[$GATE] replayed ${#selected[@]}: $n_clean clean, $n_repro reproducing," \
     "$n_nobin unreplayable"
echo "[$GATE] $violations violation(s) found (mode: $MODE)"
# Name the cause that actually fired. This trailer used to say "a saved fuzz
# finding that still reproduces" on EVERY violation, including the case where
# nothing was replayed at all because the binaries were not built — which is
# what a fresh worktree looks like. Two reviewers read it, saw a claim that
# did not match their tree, and concluded the whole red suite was
# environmental noise. A gate that names the wrong cause teaches people to
# ignore it, and this one guards real crashes. Same violations, same exit
# code; only the advice is now true.
if (( n_nobin > 0 )); then
    echo "[$GATE] $n_nobin artifact(s) had NO BINARY to replay against. That is a"
    echo "[$GATE] failure, not a skip — an artifact nobody replays is an artifact"
    echo "[$GATE] nobody reads. Build them:  make fuzz"
    echo "[$GATE] (a fresh worktree has none until you do; that is this case)"
fi
if (( violations > n_nobin )); then
    echo "[$GATE] A saved fuzz finding that still reproduces is a bug the node has"
    echo "[$GATE] TODAY, on a path a peer can reach. Fix it, or — if it is genuinely"
    echo "[$GATE] a non-bug — add a per-file 'accepted' line to $LEDGER"
    echo "[$GATE] saying why. There is no directory-wide exemption on purpose."
fi

if (( violations > 0 )) && [[ "$MODE" == "FAIL" ]]; then
    exit 1
fi
exit 0
