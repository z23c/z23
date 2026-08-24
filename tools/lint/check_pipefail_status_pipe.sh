#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_pipefail_status_pipe.sh — refuse NEW status-carrying `printf | grep -q`
# / `echo | grep -q` pipelines in a script that sets pipefail. Mode: shrink-only
# ratchet (ZCL_LINT_MODE: FAIL default | WARN | UPDATE — same shape as
# check_status_reason_single.sh).
#
# ── WHY THIS EXISTS ────────────────────────────────────────────────────────
# Under `set -o pipefail`,
#
#     printf '%s' "$out" | grep -q 'needle'
#
# reports 141, not 0, when the needle IS present: grep -q exits at the first
# match, printf then takes SIGPIPE, and pipefail surfaces printf's status. A
# successful match becomes indistinguishable from a miss, so any decision
# written that way can silently invert. Full mechanism, measurement and the
# deliberate exceptions: tools/scripts/sh_str.sh.
#
# For a LINT GATE the inverted direction is the dangerous one — a gate greping
# for a violation reads "found it" as "clean" and reports a hollow PASS that
# something downstream trusts. Measured on this tree 2026-07-30:
# check_release_no_dev_symbols.sh asked `printf '%s\n' "$syms" | gate_grep -qx
# "$sym"` over the release binary's 555 KB .dynsym name list, and with a
# forbidden dev-only symbol planted on line 6 it reported the binary CLEAN in
# 20 of 20 runs. Hosted CI found the class; the dev host had passed it for
# months.
#
# ── WHAT IS COUNTED, AND WHY IT CANNOT BE DODGED BY REINDENTING ────────────
# `grep -q` writes NOTHING to stdout. Its only product is its exit status.
# So every `printf|…|grep -q…` pipeline is status-carrying BY CONSTRUCTION,
# and this gate does not have to recognise `if`, `!`, `&&`, `while` or any
# other syntactic context to know the status is a decision. That matters,
# because every one of those recognisers is a whitespace/line-shape
# assumption, and a shape-matching gate in this tree was recently defeated by
# a plain reindent (see check_status_reason_single.sh's header). Nothing here
# anchors to a line start, a column, an indent level, a brace position, or
# one-statement-per-line: the scanner tokenises with a quote-aware state
# machine and splits only on characters and keywords that are statement or
# pipeline separators in the shell grammar (`;` `&&` `||` `|` `(` `)` `{` `}`
# `then` `do` `else`, and a newline that is not a continuation). Reindent a
# violation, move the pipe onto its own line, collapse the `if` onto one
# line — all of it still counts. --selftest proves exactly that with a
# reindented copy of a planted violation.
#
# Also by construction:
#   * COMMENTS are stripped quote-aware, so prose describing the bug (this
#     header, and the explanatory comments left at every converted site) is
#     not a violation.
#   * A VALUE pipeline is not counted: `printf … | head -n1`, `… | sed …`,
#     `… | grep -o …` all deliver their value regardless of EPIPE, and only a
#     status-carrying pipeline can invert. Only a `-q` grep counts.
#   * A `grep -q` NOT fed by printf/echo is not counted here. A `cmd | grep -q`
#     can SIGPIPE too, but `cmd` is usually a short single-line producer and
#     rewriting arbitrary producers is a different, larger job; this gate
#     ratchets the measured shape rather than pretending to cover the class.
#   * A script with no pipefail is not counted: without pipefail the pipeline
#     reports grep's status and the inversion cannot happen.
#
# NO ALLOW-COMMENT ESCAPE HATCH EXISTS, on purpose. A per-line `# pipefail-ok`
# marker would turn this gate into a suggestion: it is unbounded, it is never
# reviewed, and the one thing it would be used for is the exact case that
# needs a human to look. The baseline file is the only route, it is
# shrink-only, and every change to it is a visible diff in review.
#
# RATCHET_CEILING below is the total measured across the baseline: 156 sites in
# 49 files (see tools/lint/pipefail_status_pipe_baseline.txt for exactly
# which). It may only go DOWN. Fixing a site means converting it
# (str_contains/str_lacks from tools/scripts/sh_str.sh, or extract the match
# into a variable and test the STRING) and then lowering the number — never
# raising it. Note the tokeniser counts MORE than a naive
# `git grep 'printf.*| grep -q'`: it joins continuation lines, so the
# trailing-pipe form
#     printf '%s\n' "$json" |
#         grep -qE '"schema"…'
# (nine of them in tools/agent_fast_ci.sh alone) is counted, and a hand grep
# misses every one. Do not reconcile this number against a hand grep.
#
# --selftest plants a violation in a sandboxed shell tree, proves the gate
# FAILS; reindents the identical violation and proves it STILL fails; removes
# it and proves PASS; and asserts each fixture really carries the shape it
# claims, so a fixture that silently stopped containing the violation cannot
# make this self-test hollow.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh
# Pipeline-free substring predicates — this gate must not contain the bug it
# detects. FATAL if missing: the self-test's fixture guards depend on them.
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh || { echo "check_pipefail_status_pipe: cannot source tools/scripts/sh_str.sh" >&2; exit 2; }

GATE=check_pipefail_status_pipe
RATCHET_CEILING=156

# ── the detector ─────────────────────────────────────────────────────────
# Emits: path<TAB>count<TAB>first-line-number. See the header for why this is
# a shell-grammar tokeniser and not a line-shape matcher.
scan_counts() {
    awk -v SEP_PIPE=$'\001' -v QCH=$'\047"' '
        function flush_stmt(   nst, si, stage, head, w, k, isgrep, hasq) {
            if (stmt == "") { stmt_line = 0; return }
            nst = split(stmt, stage, SEP_PIPE)
            if (nst < 2) { stmt = ""; stmt_line = 0; return }
            # Head of the pipeline: first word, after discarding the shell
            # keywords and the negation that may precede a command. These are
            # WORDS, not positions, so indentation is irrelevant.
            head = stage[1]
            gsub(/^[ \t]+|[ \t]+$/, "", head)
            while (match(head, /^(if|elif|while|until|!|then|do|else|local|declare|export|time)[ \t]+/)) {
                head = substr(head, RLENGTH + 1)
                gsub(/^[ \t]+/, "", head)
            }
            if (head !~ /^(printf|echo)([ \t]|$)/) { stmt = ""; stmt_line = 0; return }
            # Any later stage that is a grep carrying -q in its flag words.
            for (si = 2; si <= nst; si++) {
                s = stage[si]
                gsub(/^[ \t]+|[ \t]+$/, "", s)
                isgrep = (s ~ /^(grep|egrep|fgrep|gate_grep)([ \t]|$)/)
                if (!isgrep) continue
                hasq = 0
                nw = split(s, w, /[ \t]+/)
                for (k = 2; k <= nw; k++) {
                    # A single-dash flag cluster containing q: -q, -qF, -qE,
                    # -qx, -qxF, -Fq, and the split form -F -q all land here.
                    if (w[k] ~ /^-[A-Za-z]*q[A-Za-z]*$/) { hasq = 1; break }
                }
                if (hasq) {
                    count++
                    if (first_line == 0) first_line = stmt_line
                    break
                }
            }
            stmt = ""; stmt_line = 0
        }
        # Append a separator, closing the current statement.
        function sep() { flush_stmt() }
        function emit(   c) {
            if (path != "" && count > 0) printf "%s\t%d\t%d\n", path, count, first_line
        }
        FNR == 1 {
            if (NR > 1) { flush_stmt(); emit() }
            path = FILENAME; count = 0; first_line = 0
            stmt = ""; stmt_line = 0; pipefail = 0
            insq = 0; indq = 0; hd_delim = ""; hd_tabs = 0
            # Two passes are not available here, so the pipefail question is
            # answered by a cheap pre-read of the same file.
            pipefail = 0
            while ((getline probe < FILENAME) > 0)
                if (probe ~ /pipefail/) { pipefail = 1 }
            close(FILENAME)
        }
        {
            if (!pipefail) next
            # A HEREDOC BODY is data, not executed shell — a planted fixture in
            # a gate self-test is the common case in this tree. The delimiter
            # rule is the one in the shell grammar (a line containing only the
            # delimiter, leading tabs allowed for <<-), not a formatting rule.
            if (hd_delim != "") {
                probe2 = $0
                if (hd_tabs) sub(/^\t+/, "", probe2)
                if (probe2 == hd_delim) hd_delim = ""
                next
            }
            line = $0
            n = length(line)
            out = ""
            prevc = ""
            for (i = 1; i <= n; i++) {
                c = substr(line, i, 1)
                if (insq) { out = out c; if (c == "\047") insq = 0; prevc = c; continue }
                if (indq) {
                    if (c == "\\") { out = out c substr(line, i + 1, 1); i++; prevc = "x"; continue }
                    out = out c; if (c == "\"") indq = 0; prevc = c; continue
                }
                if (c == "\\") { out = out c substr(line, i + 1, 1); i++; prevc = "x"; continue }
                if (c == "\047") { insq = 1; out = out c; prevc = c; continue }
                if (c == "\"")   { indq = 1; out = out c; prevc = c; continue }
                # `#` opens a comment only at the start of a word — POSIX. This
                # is a word-boundary test, not a column test.
                if (c == "#" && (prevc == "" || prevc ~ /[ \t;&|()\{\}]/)) break
                out = out c
                prevc = c
            }
            # Now walk the comment-stripped, quote-aware text and split it into
            # statements/stages on shell separators.
            m = length(out)
            i = 1
            while (i <= m) {
                c = substr(out, i, 1)
                if (c == "\047" || c == "\"") {
                    q = c; j = i + 1
                    buf = c
                    while (j <= m) {
                        d = substr(out, j, 1)
                        if (q == "\"" && d == "\\") { buf = buf d substr(out, j + 1, 1); j += 2; continue }
                        buf = buf d; j++
                        if (d == q) break
                    }
                    if (stmt_line == 0) stmt_line = FNR
                    stmt = stmt buf
                    i = j
                    continue
                }
                two = substr(out, i, 2)
                if (two == "&&" || two == "||") { sep(); i += 2; continue }
                if (c == ";" || c == "&" || c == "(" || c == ")" || c == "{" || c == "}") { sep(); i++; continue }
                if (c == "|") {
                    if (stmt_line == 0) stmt_line = FNR
                    stmt = stmt SEP_PIPE
                    i++
                    continue
                }
                # `then` / `do` / `else` as WORDS end the preceding statement.
                if (substr(out, i) ~ /^(then|do|else)([ \t;&|()]|$)/) {
                    sep()
                    while (i <= m && substr(out, i, 1) ~ /[A-Za-z]/) i++
                    continue
                }
                # Record the line on the first NON-BLANK char of the statement.
                # Testing `stmt == ""` instead was wrong: leading indentation is
                # appended to stmt, so an indented statement never got a line
                # number and every violation was reported at line 0.
                if (stmt_line == 0 && c !~ /[ \t]/) stmt_line = FNR
                stmt = stmt c
                i++
            }
            # A newline ends the statement UNLESS the line ended on a
            # continuation: a trailing pipe, `&&`/`||` (already consumed as a
            # separator), or a backslash. A trailing pipe leaves SEP_PIPE as
            # the last thing in stmt, which is exactly the join we want.
            tail = out
            gsub(/[ \t]+$/, "", tail)
            # Opening a heredoc: everything up to the delimiter line is data.
            # `<<<` (herestring) and `$((1 << 3))` are excluded — the former by
            # the third `<`, the latter because a delimiter must be a word.
            if (match($0, "<<-?[ \t]*[" QCH "]?[A-Za-z_][A-Za-z0-9_]*")) {
                hd = substr($0, RSTART, RLENGTH)
                if (hd !~ /^<<</) {
                    hd_tabs = (hd ~ /^<<-/)
                    sub("^<<-?[ \t]*[" QCH "]?", "", hd)
                    hd_delim = hd
                }
            }
            if (tail ~ /\\$/) next
            if (stmt ~ (SEP_PIPE "$")) next
            flush_stmt()
        }
        END { flush_stmt(); emit() }
    ' "$@"
}

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/sh"

    # The plain violation, written the way every real site in this tree is.
    plain="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
out="$(some_producer)"
if printf '%s\n' "$out" | grep -q 'needle'; then
    echo "found"
fi
FIXTURE
)"
    # The SAME violation, only the whitespace differs: the pipe moved onto its
    # own continuation line, the body reindented, and the `then` pulled down.
    # If the gate anchors on line starts, statement-per-line, or brace/keyword
    # position, this one escapes — which is the demonstrated dodge in this tree.
    reindented="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
out="$(some_producer)"
      if      printf '%s\n' "$out"    |
                    grep     -q    'needle'
      then
                    echo "found"
      fi
FIXTURE
)"
    # A THIRD spelling: everything crammed onto one line inside a function
    # body, no `if` at all, status consumed by `&&`.
    oneline="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
probe() { out="$(some_producer)"; printf '%s' "$out" | grep -qE 'need|le' && return 0; return 1; }
FIXTURE
)"
    # Clean: the value-extraction form, the converted form, a commented-out
    # violation, and a grep -q with no printf/echo head. NONE may count, or
    # the gate is noise that will be turned off.
    clean="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
. tools/scripts/sh_str.sh
out="$(some_producer)"
first="$(printf '%s\n' "$out" | head -n1)"
name="$(printf '%s\n' "$out" | sed -n 's/^name=//p')"
hit="$(printf '%s\n' "$out" | grep '^FATAL' || true)"
if [ -n "$hit" ]; then echo "found"; fi
if str_contains "$out" 'needle'; then echo "found"; fi
# if printf '%s\n' "$out" | grep -q 'needle'; then echo "commented out"; fi
echo "a # b" | wc -c   # a '#' inside quotes is not a comment
if some_producer | grep -q 'needle'; then echo "not the shape this gate counts"; fi
FIXTURE
)"
    # The identical plain violation in a script WITHOUT pipefail. Must not
    # count: without pipefail the pipeline reports grep's status.
    no_pipefail="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -eu
out="$(some_producer)"
if printf '%s\n' "$out" | grep -q 'needle'; then
    echo "found"
fi
FIXTURE
)"

    # ── HOLLOWNESS GUARDS on the fixtures themselves ─────────────────────
    # A fixture that silently stopped carrying the shape it claims turns every
    # assertion below into a tautology. Check the claims, not just the files.
    if [ "$reindented" = "$plain" ]; then
        echo "$GATE: SELFTEST FAILED — the reindented fixture is byte-identical to the plain one; the reindent-dodge assertion is hollow" >&2
        exit 2
    fi
    for pair in "plain:$plain" "reindented:$reindented" "oneline:$oneline" "no_pipefail:$no_pipefail"; do
        nm="${pair%%:*}"; body="${pair#*:}"
        if str_lacks "$body" 'grep'; then
            echo "$GATE: SELFTEST FAILED — the $nm fixture no longer contains a grep at all; it cannot prove anything" >&2
            exit 2
        fi
        case "$body" in
            *-q*) : ;;
            *)  echo "$GATE: SELFTEST FAILED — the $nm fixture no longer contains a -q grep flag; the violation it claims to carry is gone" >&2
                exit 2 ;;
        esac
    done
    # The reindent fixture must really have the pipe as the last thing on its
    # line — that is the specific shape a line-anchored matcher misses.
    if str_lacks "$reindented" '"$out"    |'; then
        echo "$GATE: SELFTEST FAILED — the reindented fixture no longer ends a line on the pipe; it is not testing the reindent dodge" >&2
        exit 2
    fi
    # The commented-out violation in the clean fixture must really be there,
    # or the "comments are not violations" assertion proves nothing.
    if str_lacks "$clean" "# if printf '%s\\n' \"\$out\" | grep -q 'needle'"; then
        echo "$GATE: SELFTEST FAILED — the clean fixture no longer carries a commented-out violation; the comment-stripping assertion is hollow" >&2
        exit 2
    fi
    if str_lacks "$no_pipefail" 'set -eu'; then
        echo "$GATE: SELFTEST FAILED — the no_pipefail fixture's set line changed; it may now set pipefail and the assertion would invert" >&2
        exit 2
    fi
    case "$no_pipefail" in
        *pipefail*)
            echo "$GATE: SELFTEST FAILED — the no_pipefail fixture mentions pipefail; it cannot test the no-pipefail exemption" >&2
            exit 2 ;;
    esac

    plant() { printf '%s\n' "$1" > "$tmp/sh/sandbox_probe.sh"; }
    self="$PWD/tools/lint/$GATE.sh"
    : > "$tmp/empty_baseline.txt"

    run_sandbox() {
        ZCL_PIPEFAIL_GATE_SCAN_GLOB="$tmp/sh/*.sh" \
        ZCL_PIPEFAIL_GATE_BASELINE="$tmp/empty_baseline.txt" \
        ZCL_PIPEFAIL_GATE_CEILING=0 \
        ZCL_PIPEFAIL_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1
    }

    expect() { # $1 = pass|fail, $2 = message, $3 = fixture body
        local want="$1" msg="$2" body="$3" rc=0
        plant "$body"
        run_sandbox || rc=$?
        if [ "$want" = fail ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
        if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
    }

    expect pass "a clean file with no status-carrying grep -q was reported as a violation" \
        "$clean"
    printf '%s 1\n' "$tmp/sh/sandbox_probe.sh" > "$tmp/stale_baseline.txt"
    plant "$clean"
    stale_rc=0
    ZCL_PIPEFAIL_GATE_SCAN_GLOB="$tmp/sh/*.sh" \
        ZCL_PIPEFAIL_GATE_BASELINE="$tmp/stale_baseline.txt" \
        ZCL_PIPEFAIL_GATE_CEILING=1 \
        ZCL_PIPEFAIL_GATE_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1 || stale_rc=$?
    if [ "$stale_rc" -eq 0 ]; then
        echo "$GATE: SELFTEST FAILED — a stale baseline row for a clean file was accepted" >&2
        exit 2
    fi
    expect fail "a plain 'printf | grep -q' status pipeline did not fail the gate" \
        "$plain"
    expect pass "removing the planted violation did not clear it" \
        "$clean"
    expect fail "the SAME violation reindented (pipe at end of line, body reindented, 'then' on its own line) did not fail the gate; the reindent dodge is not closed" \
        "$reindented"
    expect pass "removing the reindented violation did not clear it" \
        "$clean"
    expect fail "the same violation crammed onto one line inside a function body did not fail the gate" \
        "$oneline"
    expect pass "removing the one-line violation did not clear it" \
        "$clean"
    expect pass "the identical violation in a script that never sets pipefail was counted; without pipefail the inversion cannot happen" \
        "$no_pipefail"

    # This gate must not contain the bug it detects.
    if [ -n "$(scan_counts "$self")" ]; then
        echo "$GATE: SELFTEST FAILED — this gate itself carries a status-carrying printf|grep -q pipeline" >&2
        exit 2
    fi
    # Nor may tools/scripts/sh_str.sh, the fix everyone is pointed at.
    if [ -n "$(scan_counts tools/scripts/sh_str.sh)" ]; then
        echo "$GATE: SELFTEST FAILED — tools/scripts/sh_str.sh carries the shape it exists to replace" >&2
        exit 2
    fi

    echo "[$GATE] SELFTEST PASS (clean passes; stale baseline rows and plain, REINDENTED and one-line violations all fail; a value pipeline, a converted site, a commented-out violation and a non-printf grep -q do not count; a no-pipefail script is exempt; this gate and sh_str.sh are clean)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_PIPEFAIL_GATE_BASELINE:-tools/lint/pipefail_status_pipe_baseline.txt}"
CEILING="${ZCL_PIPEFAIL_GATE_CEILING:-$RATCHET_CEILING}"

if [ -n "${ZCL_PIPEFAIL_GATE_SCAN_GLOB:-}" ]; then
    # Sandbox path (--selftest): a literal glob over a temp tree.
    # shellcheck disable=SC2206
    mapfile -t scan_files < <(ls -1 ${ZCL_PIPEFAIL_GATE_SCAN_GLOB} 2>/dev/null || true)
    FILE_FLOOR="${ZCL_PIPEFAIL_GATE_FILE_FLOOR:-1}"
else
    mapfile -t scan_files < <(git ls-files '*.sh')
    FILE_FLOOR="${ZCL_PIPEFAIL_GATE_FILE_FLOOR:-200}"
fi

gate_require_scanned "${#scan_files[@]}" "$FILE_FLOOR" "$GATE" \
    "no *.sh files found — the scan set (git ls-files '*.sh') moved or emptied"

mapfile -t COUNT_ROWS < <(scan_counts "${scan_files[@]}")

declare -A BASELINED=()
gate_load_kv_file "$BASELINE" BASELINED
baseline_count="${#BASELINED[@]}"
baseline_sum=0
for path in "${!BASELINED[@]}"; do
    # Reject a non-numeric baseline value with `case` rather than a regex test
    # on a line: a stray value must not arithmetically expand.
    case "${BASELINED[$path]}" in
        ''|*[!0-9]*)
            echo "[$GATE] FATAL — baseline row '$path' has a non-numeric count '${BASELINED[$path]}' in $BASELINE" >&2
            exit 2 ;;
    esac
    baseline_sum=$(( baseline_sum + ${BASELINED[$path]} ))
done

declare -A HIT=()
violations=()
tolerated=()
total_sites=0

for row in "${COUNT_ROWS[@]}"; do
    IFS=$'\t' read -r path debt line <<< "$row"
    total_sites=$(( total_sites + debt ))
    allowed="${BASELINED[$path]:-}"
    if [ -n "$allowed" ]; then
        HIT["$path"]=1
        if [ "$debt" -le "$allowed" ]; then
            tolerated+=("$path ($debt/$allowed)")
            continue
        fi
        violations+=("$path:$line — $debt status-carrying grep -q pipeline(s), baseline allows $allowed")
    else
        violations+=("$path:$line — $debt status-carrying grep -q pipeline(s), not in the baseline (a new file may carry ZERO)")
    fi
done

# A baseline row whose file is now clean (or gone) must be deleted, or the
# ratchet rusts shut at a stale number.
stale=()
for path in "${!BASELINED[@]}"; do
    [ -z "${HIT[$path]+x}" ] && stale+=("$path (baseline says ${BASELINED[$path]}, actual 0)")
done

# The baseline FILE's own recorded SUM may never exceed the ceiling this gate
# was introduced with. The only way to raise the ceiling is a change to the
# constant in this script — a visible source diff, not a quiet data-file edit.
if [ "$baseline_sum" -gt "$CEILING" ]; then
    echo ""
    echo "[$GATE] baseline sum ($baseline_sum) exceeds the ratchet ceiling ($CEILING)"
    echo "        in $BASELINE — the baseline was edited upward. Lower it back, or"
    echo "        lower RATCHET_CEILING in this script if the tolerated set has"
    echo "        genuinely shrunk (a change that belongs in code review, not a"
    echo "        quiet data-file edit)."
    violations+=("$BASELINE — baseline sum $baseline_sum exceeds ceiling $CEILING")
fi

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# $GATE baseline — scripts still deciding something on the exit"
        echo "# status of a \`printf | grep -q\` / \`echo | grep -q\` pipeline while"
        echo "# pipefail is set. Under pipefail a MATCH can report printf's SIGPIPE"
        echo "# 141 instead of grep's 0, so the decision can silently invert."
        echo "#"
        echo "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK."
        echo "#"
        echo "# Fix a row: use str_contains/str_lacks from tools/scripts/sh_str.sh, or"
        echo "# extract the match into a variable (drop -q, so grep drains stdin) and"
        echo "# test the STRING. Then lower or delete the number here. Adding a row"
        echo "# for a NEW file is not a fix — a file with no row may carry ZERO."
        echo "#"
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        for row in "${COUNT_ROWS[@]}"; do
            IFS=$'\t' read -r path debt line <<< "$row"
            echo "$path $debt"
        done | sort
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED: $BASELINE"
    exit 0
fi

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} violation(s) — a new or grown status-carrying"
    echo "        \`printf | grep -q\` / \`echo | grep -q\` pipeline under pipefail:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  grep -q writes nothing to stdout, so its exit status IS the decision —"
    echo "  and under pipefail a MATCH can surface printf's SIGPIPE 141 instead of"
    echo "  grep's 0. Rewrite it one of two ways:"
    echo "    . tools/scripts/sh_str.sh   # then str_contains / str_lacks"
    echo "    hit=\$(printf '%s\\n' \"\$out\" | grep 'RE' || true); [ -n \"\$hit\" ]"
    echo "  The second keeps your exact regex and is the right choice for an"
    echo "  anchored or otherwise non-fixed-string match — never rewrite a"
    echo "  digest/signature validator into a different regex engine to fix a bug"
    echo "  a short single-value haystack cannot have."
    echo "  Raising a number in $BASELINE is NOT a fix; counts may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — the file no longer carries"
    echo "        this shape. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} *.sh files scanned, ${#COUNT_ROWS[@]} carrying the shape, $total_sites total, $baseline_count baselined file(s) summing to $baseline_sum/$CEILING, ${#tolerated[@]} tolerated, no allow-comment mechanism exists)"
