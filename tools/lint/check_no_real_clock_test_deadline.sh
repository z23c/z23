#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_real_clock_test_deadline.sh — refuse, in tests/harness/src/*.c, an
# assertion or a hand-timed retry loop whose PASS/FAIL depends on a reading of
# a real clock, unless the line carries a reviewed `/* real-clock: <reason>
# */` marker.
#
# ── WHY A SEPARATE GATE FROM check_no_wallclock_assertion.sh ──────────────
# check_no_wallclock_assertion.sh already refuses an ASSERT/CHECK graded on a
# measured clock INTERVAL, tree-wide, with a shrink-only baseline file and
# (deliberately) no per-line escape hatch. It also documents its own biggest
# blind spot in its header: "IT DOES NOT SEE A FIXED-ITERATION RETRY LOOP...
# test_onion_bootstrap.c polled `for (i = 0; i < 90; i++) { if (ready) break;
# sleep(1); }` ... FAILED inside a full gate run and PASSED standalone". That
# is exactly the shape that cost this project two thrown-away proofs on
# 2026-09-04: a group whose own poll-for-done loop used a fixed iteration
# count as a real-clock deadline surrogate, and failed only under a
# contended, 8-worker pool.
#
# So this gate closes that specific blind spot — a sleep/usleep/nanosleep
# call inside a loop bounded by a fixed iteration count, i.e. "poll N times,
# sleeping between each" used as a real-clock deadline — over the harness's
# own registered-group sources (tests/harness/src/*.c), and it uses a
# PER-LINE marker rather than a baseline file: unlike the tree-wide
# assertion-interval case, the fix here is usually "raise the poll budget
# with a documented reason" (see 3469d44f6), which is a one-line, reviewed,
# self-documenting change — a baseline row a reviewer never re-reads is the
# worse fit for it.
#
# It also independently (and more narrowly) polices the direct clock-in-
# assertion shape named in the same spirit — an ASSERT/CHECK/EXPECT/REQUIRE
# macro whose argument reads a real clock (clock_gettime, gettimeofday,
# time(NULL)/time(0), or this tree's platform_time_* / clock_now_* readers) —
# over the same tests/harness/src/*.c scope, so the harness's own sources
# have ONE marker-driven gate for "this line's verdict rides on a real clock"
# rather than two different remediation stories depending on shape.
#
# ── WHAT COUNTS ────────────────────────────────────────────────────────────
#   (A) ASSERT*/EXPECT*/REQUIRE*/*CHECK(...) whose balanced-paren argument
#       text calls a real-clock reader: clock_gettime, gettimeofday, time(
#       NULL|0), platform_time_monotonic_timespec, platform_time_wall_time_t,
#       platform_time_monotonic_ms, platform_now_* (any name with that
#       prefix), clock_now_monotonic_ns, clock_now_wall_ms, difftime.
#   (B) sleep(/usleep(/nanosleep(/platform_sleep_ms( appearing inside a
#       for/while loop whose own header compares its counter against a fixed
#       numeric bound on the same line as the loop's opening brace (this
#       tree's house style) — the "poll N times" idiom.
#
# Both are refused UNLESS the exact source line carries the marker
# `/* real-clock: <reason> */` (a non-empty reason is required — a bare
# marker documents nothing and is refused just like a missing one).
#
# ── WHAT THIS GATE CANNOT DO (stated plainly) ─────────────────────────────
#   * (A) is a single balanced-paren join per assertion, not the full
#     cross-function taint fixpoint check_no_wallclock_assertion.sh runs —
#     an interval built from a LOCAL VARIABLE that was itself assigned from a
#     reader on an earlier line is invisible here (that shape is exactly what
#     the tree-wide gate exists for; this gate is the narrower, marker-driven
#     complement for tests/harness/src/*.c, not a replacement).
#   * (B) requires the loop header and its opening `{` on ONE physical line
#     (this tree's house style everywhere it was checked) and the sleep call
#     literally inside that same brace-delimited body; a multi-line header or
#     a sleep call reached only through a helper function is invisible.
#   * Comments and string literals are stripped before matching, so a marker
#     can only ever appear as what it actually is: a real, visible comment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

GATE=check_no_real_clock_test_deadline
MODE="${ZCL_LINT_MODE:-FAIL}"

# Emits one row per violation: path<TAB>line<TAB>kind<TAB>text
scan_violations() {
    awk '
        function reset_file() {
            delete loopstack; loopdepth = 0; depth = 0
            nlines = 0; inblk = 0
        }
        # Strip //-comments, block comments and string/char literals for
        # PATTERN matching. The marker check below is done against the RAW
        # line on purpose — a marker is a comment, so it must survive.
        function strip(s,   out, i, n, c, two, q, d) {
            out = ""; n = length(s); i = 1
            while (i <= n) {
                two = substr(s, i, 2)
                if (inblk) {
                    if (two == "*/") { inblk = 0; i += 2 } else { i++ }
                    continue
                }
                if (two == "/*") { inblk = 1; i += 2; continue }
                if (two == "//") break
                c = substr(s, i, 1)
                if (c == "\"" || c == "\047") {
                    q = c; i++
                    while (i <= n) {
                        d = substr(s, i, 1)
                        if (d == "\\") { i += 2; continue }
                        i++
                        if (d == q) break
                    }
                    out = out " "
                    continue
                }
                out = out c; i++
            }
            return out
        }
        function has_marker(raw) {
            return raw ~ /\/\*[ \t]*real-clock:[ \t]*[^*]+\*\//
        }
        function is_reader_call(s) {
            return s ~ /(^|[^A-Za-z0-9_])(clock_gettime|gettimeofday|platform_time_monotonic_timespec|platform_time_wall_time_t|platform_time_monotonic_ms|platform_now_[A-Za-z0-9_]*|clock_now_monotonic_ns|clock_now_wall_ms|difftime)[ \t]*\(/ \
                || s ~ /(^|[^A-Za-z0-9_])time[ \t]*\([ \t]*(NULL|0)[ \t]*\)/
        }
        function is_sleep_call(s) {
            return s ~ /(^|[^A-Za-z0-9_])(usleep|nanosleep|platform_sleep_ms|sleep)[ \t]*\(/
        }
        # A for/while header, opening brace on the SAME line, with a fixed
        # numeric bound in a relational comparison — the "poll N times" idiom.
        function is_bounded_loop_open(s) {
            return s ~ /(^|[^A-Za-z0-9_])(for|while)[ \t]*\(.*(<|<=)[ \t]*[0-9]+.*\)[ \t]*\{[ \t]*$/
        }
        FNR == 1 {
            if (NR > 1) {}
            path = FILENAME
            reset_file()
        }
        {
            raw = $0
            s = strip(raw)
            marker = has_marker(raw)

            # ── (B) sleep-for-deadline: maintain a brace-depth loop stack ──
            opens = gsub(/\{/, "{", s)
            closes = gsub(/\}/, "}", s)
            if (is_bounded_loop_open(s)) {
                loopstack[loopdepth] = depth + opens
                loopdepth++
            }
            if (is_sleep_call(s) && loopdepth > 0 && !marker) {
                printf "%s\t%d\tB\t%s\n", path, FNR, s
            }
            depth += opens - closes
            while (loopdepth > 0 && loopstack[loopdepth - 1] > depth)
                loopdepth--

            # ── (A) single-line assertion-reads-a-clock (joined across at
            # most a handful of following lines by paren balance) ──────────
            pos = 1
            while (match(substr(s, pos), /(^|[^A-Za-z0-9_])(ASSERT[A-Za-z0-9_]*|EXPECT[A-Za-z0-9_]*|REQUIRE[A-Za-z0-9_]*|[A-Za-z0-9_]*CHECK)[ \t]*\(/)) {
                k = pos + RSTART - 1
                pos = k + RLENGTH
                buf = substr(s, pos - 1)
                bufmarker = marker
                d2 = 0
                for (c = 1; c <= length(buf); c++) {
                    ch = substr(buf, c, 1)
                    if (ch == "(") d2++
                    else if (ch == ")") { d2--; if (d2 == 0) break }
                }
                joined = substr(buf, 1, c)
                # An ELAPSED measurement, not a bare reading: the correct,
                # common idiom in this tree hands a single clock reading to
                # the subject as a base/argument (`ASSERT(gate_verify(tok,
                # platform_time_wall_time_t(), 0))`) or checks it against an
                # injected stub fixed return value — neither is load-sensitive.
                # What load can flip is a DIFFERENCE, so require an
                # arithmetic `-` alongside the reader call (or difftime(),
                # which computes the difference itself).
                if (is_reader_call(joined) && index(joined, "-") > 0 &&
                    !bufmarker) {
                    printf "%s\t%d\tA\t%s\n", path, FNR, joined
                }
                if (index(joined, "difftime") > 0 && !bufmarker) {
                    printf "%s\t%d\tA\t%s\n", path, FNR, joined
                }
                if (pos > length(s)) break
            }
        }
    ' "$@"
}

# ── --selftest ─────────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/src"

    plant() { printf '%s\n' "$1" > "$tmp/src/sandbox_probe.c"; }
    self="$PWD/tools/lint/$GATE.sh"

    run_sandbox() {
        ZCL_REAL_CLOCK_GATE_SCAN_GLOB="$tmp/src/*.c" \
        ZCL_REAL_CLOCK_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1
    }
    expect() {
        local want="$1" msg="$2" body="$3" rc=0
        plant "$body"
        run_sandbox || rc=$?
        if [ "$want" = fail ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
        if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg (rc=$rc)" >&2; exit 2
        fi
    }

    expect fail "a real clock read inside an ASSERT was reported clean" \
'int t_probe(void) {
    int64_t started = clock_gettime_stub();
    ASSERT(clock_gettime(CLOCK_MONOTONIC, &ts) == 0 && ts.tv_sec - started < 1);
    return 0;
}'

    expect fail "a fixed-iteration poll loop sleeping toward a deadline was reported clean" \
'static bool probe(void) {
    bool done = false;
    for (unsigned i = 0; i < 250; i++) {
        if (check_done()) { done = true; break; }
        platform_sleep_ms(1);
    }
    return done;
}'

    expect pass "a marked real-clock assertion was still reported as a violation" \
'int t_probe(void) {
    ASSERT(clock_gettime(CLOCK_MONOTONIC, &ts) == 0); /* real-clock: selftest fixture */
    return 0;
}'

    expect pass "a marked fixed-iteration poll loop was still reported as a violation" \
'static bool probe(void) {
    bool done = false;
    for (unsigned i = 0; i < 250; i++) {
        if (check_done()) { done = true; break; }
        platform_sleep_ms(1); /* real-clock: selftest fixture */
    }
    return done;
}'

    expect pass "virtual time (an injected now, no real clock read) was reported as a violation" \
'int t_probe(void) {
    int64_t now = 1000;
    ASSERT(check_timeouts(&dm, now + 3600) == 1);
    for (unsigned i = 0; i < 250; i++) { do_work(i); }
    return 0;
}'

    hollow_rc=0
    ZCL_REAL_CLOCK_GATE_SCAN_GLOB="$tmp/src/nothing-matches-this-*.c" \
        ZCL_REAL_CLOCK_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1 || hollow_rc=$?
    if [ "$hollow_rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — an EMPTY scan set exited $hollow_rc, not 2" >&2
        exit 2
    fi

    echo "[$GATE] SELFTEST PASSED (bare assertion, bare poll loop, marked assertion, marked poll loop, virtual-time clean file, hollow scan)"
    exit 0
fi

# ── the scan set ─────────────────────────────────────────────────────────
if [ -n "${ZCL_REAL_CLOCK_GATE_SCAN_GLOB:-}" ]; then
    # shellcheck disable=SC2086
    mapfile -t scan_files < <(ls -1 ${ZCL_REAL_CLOCK_GATE_SCAN_GLOB} 2>/dev/null || true)
    FILE_FLOOR="${ZCL_REAL_CLOCK_GATE_FILE_FLOOR:-1}"
else
    mapfile -t scan_files < <(git ls-files 'tests/harness/src/*.c')
    # Floor, not a guess: tests/harness/src/*.c carried this many files when
    # the gate was written. A count under that means the glob broke, and a
    # "clean" verdict off a collapsed scan set is exactly the hollow pass
    # gate_lib.sh exists to refuse.
    FILE_FLOOR="${ZCL_REAL_CLOCK_GATE_FILE_FLOOR:-500}"
fi

gate_require_scanned "${#scan_files[@]}" "$FILE_FLOOR" "$GATE" \
    "Expected the harness's registered-group sources (tests/harness/src/*.c)."

set +e
scan_out="$(scan_violations "${scan_files[@]}")"
scan_rc=$?
set -e
if [ "$scan_rc" -ne 0 ]; then
    echo "$GATE: FATAL — the detector exited $scan_rc. Refusing to report" >&2
    echo "  'clean' off a scan that did not run." >&2
    exit 2
fi

violations=()
markers_seeded=0
if [ -n "$scan_out" ]; then
    while IFS=$'\t' read -r path line kind text; do
        [ -n "$path" ] || continue
        if [ "$kind" = A ]; then
            violations+=("$path:$line — ASSERT/CHECK reads a real clock: $text")
        else
            violations+=("$path:$line — sleep toward a fixed-iteration deadline: $text")
        fi
    done <<< "$scan_out"
fi

# Count seeded markers across the scanned tree, for the report line — this is
# an OBSERVABILITY count, not a ratchet: the marker is per-line and reviewed
# at the point of use, so there is no baseline file to keep honest.
for f in "${scan_files[@]}"; do
    [ -f "$f" ] || continue
    n=$(grep -c '/\*[ \t]*real-clock:[ \t]*[^*]\+\*/' "$f" 2>/dev/null || true)
    markers_seeded=$((markers_seeded + ${n:-0}))
done

if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} unmarked real-clock test deadline(s) in tests/harness/src/*.c:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  A verdict a busy box can flip is measuring the box, not the code — see"
    echo "  tools/lint/check_no_wallclock_assertion.sh's header for the full case."
    echo "  If this really is the one case in this file with no injected clock (a"
    echo "  real kernel/OS deadline), add a *reviewed* reason on the SAME line:"
    echo "    /* real-clock: <why this one line genuinely has no fake-clock seam> */"
    echo "  Otherwise: inject the fake clock this file's other cases already use, or"
    echo "  assert the OUTCOME and let a progress watchdog catch a true wedge (see"
    echo "  group_watchdog_expired() in tests/harness/src/test_parallel.c)."
    if [ "$MODE" = "FAIL" ]; then
        exit 1
    fi
fi

echo "[$GATE] PASS (${#scan_files[@]} harness source file(s) scanned, $markers_seeded real-clock marker(s) seeded)"
