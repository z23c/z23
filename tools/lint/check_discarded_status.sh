#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_discarded_status.sh — refuse a shell decision whose exit status the
# shell throws away, so the check reads as PASS whatever it found.
#
# Sibling of check_pipefail_status_pipe.sh. That gate covers ONE shape (a
# status-carrying `printf | grep -q` under pipefail, where a MATCH surfaces
# printf's SIGPIPE 141). This gate covers two more, both measured live in this
# tree, both of which make a check that cannot fail look like a check that
# passed.
#
# ── PRONG A: a bare `! cmd` statement under `set -e` NEVER fails the script ──
# Bash does not exit for a failing command "if the command's return value is
# being inverted with !" — and the ERR trap is exempt for the same reason, so
# `set -E` plus `trap ... ERR` does not rescue it either. A negative assertion
# written as
#
#     ! verify_source_epoch "$a" "$b" "$a" >/dev/null 2>&1
#
# is therefore DECORATIVE: whatever the command returns, the script continues
# to its "PASS" line. Measured on this tree 2026-08-29, five such assertions
# were live in two selftests:
#
#   tools/scripts/build_c23_portable_release.sh  2 negative controls
#   tools/scripts/gen_core_seal_root.sh          3 negative controls
#
# — every one of them a check on a security-relevant predicate (source-epoch
# agreement; exact 64-lowercase-hex validation) that could not have failed the
# run. tools/ship.sh hit the identical class earlier the same day and fixed it
# by introducing `refute()`; nothing stopped it coming back anywhere else.
#
# THE FIX, and it is one line:
#
#     refute() { if "$@"; then printf '...expected non-zero from: %s\n' "$*" >&2; exit 1; fi; }
#     refute verify_source_epoch "$a" "$b" "$a"
#
# `refute` exits by itself, so a violated negative assertion stops the run and
# names itself. See tools/ship.sh's --selftest for the reference spelling.
#
# WHAT IS NOT A VIOLATION, and why the distinction is exact rather than
# heuristic: `!` is exempt from set -e only when NOTHING ELSE consumes the
# status. Where the status IS consumed the inversion is correct and idiomatic.
# The scanner joins continuation lines first (a trailing `\`, `&&`, `||`, `|`,
# or an unterminated quote continues the statement), splits each logical line
# into statements on the shell separators, and then exempts a `!` statement on
# exactly four grounds — each of which is a place the status goes somewhere:
#
#   1. It is inside a CONDITION LIST. `cond` is a running flag set by
#      if/elif/while/until and cleared by then/do, not "the keyword
#      immediately before", because `if A && ! B; then` puts `&&` next to the
#      negation while the `if` is still what consumes it.
#          if ! cmd; then …    while ! cmd; do …    until ! cmd; do …
#          if [ -n "$x" ] && ! cmd; then …
#   2. The separator that CLOSED it is `&&` or `||`.
#          ! cmd || die "…"        ! cmd && echo "absent"
#   3. It is the LAST command of a brace group, so its inverted value is the
#      RETURN VALUE of the enclosing function and the caller consumes exactly
#      what `!` produced — the idiomatic negated predicate:
#          json_not_has_key() { ! json_has_key "$1" "$2"; }
#      Checked both on the same logical line and against a `}` on the next
#      significant source line.
#   4. The word after `!` starts with `-`, so it is a find/test PREDICATE
#      negation continued onto its own line (`! -path '*/test/*'`), not a
#      shell pipeline negation. Shell negation is followed by a command name.
#
# Nothing anchors to a column, an indent level, or one-statement-per-line:
# reindenting a violation, moving the `!` onto its own line, or cramming the
# whole thing after a `then` all still count. Measured against the real tree,
# these four exemptions take the scan from 22 hits to the 5 genuine ones.
#
# ── PRONG B: `make ... | tail` in a script with no pipefail ──────────────────
# Without pipefail a pipeline reports the LAST stage's status, and `tail`/
# `head` succeed on any input. So
#
#     make dev-bin 2>&1 | tail -20
#
# reports 0 after a failed build, and a `set -e` script sails past it. This is
# the single most-repeated trap in agent transcripts: the output looks like a
# build log, the status says everything is fine, and the next step runs against
# a binary that was never relinked. Zero sites exist today, so this prong is
# HARD with no baseline — the first one to appear fails the gate.
#
# THE FIX: keep the status. Any of
#
#     make dev-bin > build.log 2>&1 || { tail -20 build.log; exit 1; }
#     set -o pipefail; make dev-bin 2>&1 | tail -20
#     make dev-bin 2>&1 | tail -20; rc=${PIPESTATUS[0]}
#
# NO ALLOW-COMMENT ESCAPE HATCH, for the same reason check_pipefail_status_pipe
# .sh has none: a per-line marker turns the gate into a suggestion, and the one
# case it would be spent on is the case that needs a human.
#
# Usage:
#   tools/lint/check_discarded_status.sh            # the gate
#   tools/lint/check_discarded_status.sh --selftest # prove it catches each
#                                                   # class before trusting it
# Env:
#   ZCL_DISCARD_GATE_SCAN_GLOB  literal glob of files to scan (selftest only)
#   ZCL_DISCARD_GATE_FILE_FLOOR minimum files that must be found (fail-closed)
#
# Exit: 0 clean, 1 on any violation, 2 on a broken scan.
set -euo pipefail
# Source trees are ASCII; the caller's UTF-8 locale makes BSD awk abort on any
# high-byte it meets mid-scan. Pin the scan locale.
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# Pipeline-free substring predicates — this gate must not carry the bug its
# sibling detects.
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh || {
    echo "check_discarded_status: cannot source tools/scripts/sh_str.sh" >&2
    exit 2
}

GATE=check_discarded_status

# ── the detector ─────────────────────────────────────────────────────────
# Emits one row per violation: path<TAB>line<TAB>prong<TAB>excerpt
#
# The walk is a quote-aware character scan, deliberately NOT a line-shape
# match: a gate in this tree was defeated by a plain reindent once already
# (see check_status_reason_single.sh's header), so nothing below anchors to a
# column, an indent level, or one-statement-per-line.
scan_violations() {
    awk '
        # ── per-file state ───────────────────────────────────────────────
        function reset_file() {
            seen_e = 0; seen_pipefail = 0
            logical = ""; logical_line = 0
            insq = 0; indq = 0; hd_delim = ""; hd_tabs = 0
        }
        # Strip a comment quote-aware and report whether the line continues.
        function strip_comment(line,   n, i, c, out, prevc) {
            n = length(line); out = ""; prevc = ""
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
                # `#` opens a comment only at the start of a WORD (POSIX).
                if (c == "#" && (prevc == "" || prevc ~ /[ \t;&|()\{\}]/)) break
                out = out c; prevc = c
            }
            return out
        }
        # Does this (comment-stripped) text continue onto the next line?
        function continues(t) {
            gsub(/[ \t]+$/, "", t)
            return (t ~ /\\$/) || (t ~ /(&&|\|\||\|)$/)
        }
        # ── statement split of one LOGICAL line ──────────────────────────
        # Fills stmt[]/cond[]/after[]/at[] and returns the count. after[i] is
        # the separator that CLOSED statement i; cond[i] records whether
        # statement i sits inside the condition list of a conditional — the two
        # facts that decide whether a `!` there discards anything.
        #
        # cond is a running flag rather than "the keyword immediately before",
        # because `if A && ! B; then` puts `&&` immediately before the
        # negation while the `if` is still what consumes its status. It is set
        # by if/elif/while/until and cleared by then/do, exactly as the shell
        # grammar delimits a condition list.
        function split_stmts(t, stmt, cond, after, at, base,
                             n, i, c, two, buf, j, d, q, cur, curline, cnt, w, incond,
                             prevch, nextch, depth) {
            n = length(t); i = 1; cnt = 0; cur = ""; curline = base; incond = 0
            while (i <= n) {
                c = substr(t, i, 1)
                if (c == "\047" || c == "\"") {
                    q = c; j = i + 1; buf = c
                    while (j <= n) {
                        d = substr(t, j, 1)
                        if (q == "\"" && d == "\\") { buf = buf d substr(t, j + 1, 1); j += 2; continue }
                        buf = buf d; j++
                        if (d == q) break
                    }
                    cur = cur buf; i = j; continue
                }
                two = substr(t, i, 2)
                # `${...}` is one word, not a brace group. Splitting inside it
                # turned every `${!ARR[@]}` indirect expansion into a bare
                # negation. Consume the whole expansion, nesting included.
                if (two == "${") {
                    depth = 1; j = i + 2; buf = two
                    while (j <= n && depth > 0) {
                        d = substr(t, j, 1)
                        if (d == "{") depth++
                        else if (d == "}") depth--
                        buf = buf d; j++
                    }
                    cur = cur buf; i = j; continue
                }
                if (two == "&&" || two == "||") {
                    cnt++; stmt[cnt] = cur; cond[cnt] = incond; after[cnt] = two; at[cnt] = curline
                    cur = ""; i += 2; continue
                }
                # A lone `&` backgrounds a job and ends a statement — but the
                # same character spells a redirection duplicate (`2>&1`,
                # `&>log`, `>&2`), and splitting there tore `make x 2>&1 |
                # tail` into two statements and hid prong B entirely.
                if (c == "&") {
                    prevch = (i > 1) ? substr(t, i - 1, 1) : ""
                    nextch = substr(t, i + 1, 1)
                    if (prevch == ">" || prevch == "<" || nextch == ">" ||
                        nextch ~ /[0-9-]/) { cur = cur c; i++; continue }
                }
                if (c == ";" || c == "&" || c == "(" || c == ")" || c == "{" || c == "}") {
                    cnt++; stmt[cnt] = cur; cond[cnt] = incond; after[cnt] = c; at[cnt] = curline
                    cur = ""; i++; continue
                }
                # if / elif / while / until / then / do / else as WORDS both
                # end the preceding statement and open or close a condition.
                if (match(substr(t, i), /^(if|elif|while|until|then|do|else)([ \t;&|()]|$)/)) {
                    w = substr(t, i, RLENGTH)
                    sub(/[ \t;&|()]$/, "", w)
                    cnt++; stmt[cnt] = cur; cond[cnt] = incond; after[cnt] = w; at[cnt] = curline
                    if (w == "if" || w == "elif" || w == "while" || w == "until") incond = 1
                    else if (w == "then" || w == "do") incond = 0
                    cur = ""; i += length(w); continue
                }
                cur = cur c; i++
            }
            cnt++; stmt[cnt] = cur; cond[cnt] = incond; after[cnt] = ""; at[cnt] = curline
            return cnt
        }
        # ── prong B, per statement ──────────────────────────────────────
        # A pipeline HEADED by make whose LAST stage is head/tail, in a file
        # that never sets pipefail: the pipeline reports the 0 from head/tail and the
        # build failure is erased. Run on a STATEMENT, not on the whole
        # logical line, so `||` and `&&` have already been consumed as
        # separators and cannot be mistaken for pipe stages.
        function check_make_pipe(s, base,   parts, np, headw, lastw, ex) {
            if (seen_pipefail) return
            np = split(s, parts, /[ \t]*\|[ \t]*/)
            if (np < 2) return
            headw = parts[1]
            gsub(/^[ \t]+/, "", headw)
            while (match(headw, /^(!|time)[ \t]+/)) {
                headw = substr(headw, RLENGTH + 1)
                gsub(/^[ \t]+/, "", headw)
            }
            # Environment assignments may precede the command word.
            while (match(headw, /^[A-Za-z_][A-Za-z0-9_]*=[^ \t]*[ \t]+/)) {
                headw = substr(headw, RLENGTH + 1)
                gsub(/^[ \t]+/, "", headw)
            }
            if (headw !~ /^(make|gmake|\$MAKE|\$\{MAKE\}|\$\(MAKE\))([ \t]|$)/) return
            lastw = parts[np]
            gsub(/^[ \t]+/, "", lastw)
            if (lastw !~ /^(head|tail)([ \t]|$)/) return
            ex = s
            gsub(/^[ \t]+|[ \t]+$/, "", ex)
            if (length(ex) > 90) ex = substr(ex, 1, 87) "..."
            printf "%s\t%d\tB\t%s\n", FILENAME, base, ex
        }
        # Is this statement the LAST command of a brace group? If so its
        # inverted status is the return value of the enclosing function —
        #     json_not_has_key() { ! json_has_key "$1" "$2"; }
        # is the idiomatic spelling of a negated predicate, and the caller
        # consumes exactly the value `!` produced. Returns 1 yes, 0 no,
        # -1 "the logical line ran out, ask the source lookahead".
        function trailing_close(stmt, after, cnt, i,   j, s) {
            if (after[i] == "}") return 1
            for (j = i + 1; j <= cnt; j++) {
                s = stmt[j]
                gsub(/^[ \t]+|[ \t]+$/, "", s)
                if (s != "") return 0
                if (after[j] == "}") return 1
                if (after[j] != "" && after[j] != ";") return 0
            }
            return -1
        }
        # The same question when the `}` is on a LATER source line: is the next
        # significant line of the file a lone closing brace?
        function next_line_closes(endline,   j) {
            for (j = endline + 1; j <= src_n; j++) {
                if (src[j] == "") continue
                return (src[j] == "}" || src[j] == "};")
            }
            return 0
        }
        # ── prong A, plus the per-statement prong B walk ────────────────
        function check_statements(t, base, endline,
                                  stmt, cond, after, at, cnt, i, s, ex, tc) {
            cnt = split_stmts(t, stmt, cond, after, at, base)
            for (i = 1; i <= cnt; i++) {
                s = stmt[i]
                gsub(/^[ \t]+|[ \t]+$/, "", s)
                check_make_pipe(s, at[i])
                if (!seen_e) continue
                # A statement that IS the negation: `!` then a command word.
                if (s !~ /^![ \t]*[^ \t=]/) continue
                # `!=` inside a test is not a negation operator.
                if (s ~ /^!=/) continue
                # `! -path`, `! -name`, `! -type`: a find/test PREDICATE
                # negation continued onto its own line, not a shell pipeline
                # negation. Shell negation is followed by a command name; an
                # option word can only belong to the enclosing utility.
                if (s ~ /^![ \t]*-/) continue
                # Status consumed by the conditional whose condition list this
                # statement is part of.
                if (cond[i]) continue
                # Status consumed by the operator that closed it.
                if (after[i] == "&&" || after[i] == "||") continue
                # Status RETURNED: the last command of a brace group.
                tc = trailing_close(stmt, after, cnt, i)
                if (tc == 1) continue
                if (tc == -1 && next_line_closes(endline)) continue
                ex = s
                if (length(ex) > 90) ex = substr(ex, 1, 87) "..."
                printf "%s\t%d\tA\t%s\n", FILENAME, at[i], ex
            }
        }
        function flush_logical(endline) {
            if (logical == "") { logical_line = 0; return }
            check_statements(logical, logical_line, endline)
            logical = ""; logical_line = 0
        }
        FNR == 1 {
            if (NR > 1) flush_logical(src_n)
            reset_file()
            # One cheap pre-read answers three questions: does the file set -e,
            # does it set pipefail, and (src[]) what is on each line — needed
            # to see a `}` that closes a function body on the line AFTER a
            # negation, which makes that negation a return value.
            src_n = 0
            delete src
            while ((getline probe < FILENAME) > 0) {
                if (probe ~ /^[ \t]*set[ \t]+-[a-zA-Z]*e/) seen_e = 1
                if (probe ~ /^[ \t]*set[ \t]+-o[ \t]+errexit/) seen_e = 1
                if (probe ~ /pipefail/) seen_pipefail = 1
                src_n++
                gsub(/^[ \t]+|[ \t]+$/, "", probe)
                if (probe ~ /^#/) probe = ""
                src[src_n] = probe
            }
            close(FILENAME)
        }
        {
            # A HEREDOC BODY is data, not executed shell — planted fixtures in
            # gate selftests are the common case in this tree.
            if (hd_delim != "") {
                probe2 = $0
                if (hd_tabs) sub(/^\t+/, "", probe2)
                if (probe2 == hd_delim) hd_delim = ""
                next
            }
            out = strip_comment($0)
            if (logical_line == 0 && out ~ /[^ \t]/) logical_line = FNR
            # Joining: drop a trailing backslash, keep a trailing &&/||/| —
            # those ARE the separators the statement split needs to see.
            joined = out
            sub(/\\[ \t]*$/, " ", joined)
            logical = logical " " joined
            if (match($0, /<<-?[ \t]*[\047"]?[A-Za-z_][A-Za-z0-9_]*/)) {
                hd = substr($0, RSTART, RLENGTH)
                if (hd !~ /^<<</) {
                    hd_tabs = (hd ~ /^<<-/)
                    sub(/^<<-?[ \t]*[\047"]?/, "", hd)
                    hd_delim = hd
                }
            }
            # A quote still OPEN at end of line continues the statement. This
            # is not cosmetic: a multi-line single-quoted awk program is ONE
            # shell word, and flushing mid-quote handed its awk source to the
            # shell statement splitter, where `!/^\\s/` and `!bad` read as bare
            # negations. Six such phantoms disappeared with this line.
            if (insq || indq) next
            if (continues(out)) next
            flush_logical(FNR)
        }
        END { flush_logical(src_n) }
    ' "$@"
}

existing_files()
{
    local path
    for path in "$@"; do
        [ -f "$path" ] && printf '%s\n' "$path"
    done
    return 0
}

# ── --selftest ───────────────────────────────────────────────────────────
# A gate nobody has watched fail is a gate nobody should trust. Each fixture
# below plants ONE shape and asserts the verdict, and the CLEAN fixture carries
# every legitimate spelling of the same syntax so a gate that failed
# unconditionally could not pass.
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/sh"

    bare_negation="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
a="$(compute a)"
b="$(compute b)"
verify_epoch "$a" "$a" "$a"
! verify_epoch "$a" "$b" "$a" >/dev/null 2>&1
echo "selftest PASS"
FIXTURE
)"
    # The SAME dead assertion, reindented and crammed after a `then` on one
    # line. A line-shape matcher misses this; a statement split does not.
    bare_negation_reshaped="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
if [ -n "$mode" ]; then     ! verify_epoch "$a" "$b" "$a"   ; fi
echo "selftest PASS"
FIXTURE
)"
    make_pipe="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -eu
echo "building"
make dev-bin 2>&1 | tail -20
echo "built"
FIXTURE
)"
    # Every LEGITIMATE spelling of the same two syntaxes. None may count, or
    # this gate is noise that will be switched off.
    clean="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
refute() { if "$@"; then echo "expected non-zero from: $*" >&2; exit 1; fi; }
refute verify_epoch "$a" "$b" "$a"
if ! verify_epoch "$a" "$b" "$a"; then echo "good"; fi
while ! ready; do sleep 1; done
until ! draining; do sleep 1; done
! verify_epoch "$a" "$b" "$a" || die "epoch check inverted"
! verify_epoch "$a" "$b" "$a" && echo "correctly rejected"
if [ "$x" != "$y" ] && \
   ! verify_epoch "$a" "$b" "$a"; then
    echo "multi-line condition"
fi
make dev-bin > build.log 2>&1 || { tail -20 build.log; exit 1; }
version="$(make --version | head -n1)"
# ! verify_epoch "$a" "$b" "$a"    <- a commented-out one is not a violation
FIXTURE
)"
    # The identical `make | tail` in a script that DOES set pipefail: the
    # status survives, so it is not a violation.
    make_pipe_pipefail="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
make dev-bin 2>&1 | tail -20
FIXTURE
)"
    # The identical bare negation in a script with NO set -e: without errexit
    # nothing was going to exit anyway, so `!` discards no decision the script
    # was relying on.
    negation_no_errexit="$(cat <<'FIXTURE'
#!/usr/bin/env bash
set -u
! verify_epoch "$a" "$b" "$a"
echo "done"
FIXTURE
)"

    # ── HOLLOWNESS GUARDS on the fixtures themselves ────────────────────
    # A fixture that quietly stopped carrying the shape it claims turns every
    # assertion below into a tautology. Assert the claims, not just the files.
    if [ "$bare_negation_reshaped" = "$bare_negation" ]; then
        echo "$GATE: SELFTEST FAILED — the reshaped fixture is byte-identical to the plain one; the reindent-dodge assertion is hollow" >&2
        exit 2
    fi
    for pair in "bare_negation:$bare_negation" \
                "bare_negation_reshaped:$bare_negation_reshaped" \
                "negation_no_errexit:$negation_no_errexit"; do
        nm="${pair%%:*}"; body="${pair#*:}"
        if str_lacks "$body" '! verify_epoch'; then
            echo "$GATE: SELFTEST FAILED — the $nm fixture no longer carries a bare '! cmd'; it cannot prove anything" >&2
            exit 2
        fi
    done
    for pair in "make_pipe:$make_pipe" "make_pipe_pipefail:$make_pipe_pipefail"; do
        nm="${pair%%:*}"; body="${pair#*:}"
        if str_lacks "$body" 'make dev-bin 2>&1 | tail'; then
            echo "$GATE: SELFTEST FAILED — the $nm fixture no longer pipes make into tail; the assertion is hollow" >&2
            exit 2
        fi
    done
    if str_lacks "$negation_no_errexit" 'set -u'; then
        echo "$GATE: SELFTEST FAILED — the no-errexit fixture's set line changed; it may now set -e and the assertion would invert" >&2
        exit 2
    fi
    case "$negation_no_errexit" in
        *"set -e"*|*errexit*)
            echo "$GATE: SELFTEST FAILED — the no-errexit fixture sets errexit; it cannot test the exemption" >&2
            exit 2 ;;
    esac
    case "$make_pipe" in
        *pipefail*)
            echo "$GATE: SELFTEST FAILED — the make_pipe fixture sets pipefail; the status would survive and the assertion inverts" >&2
            exit 2 ;;
    esac
    if str_lacks "$clean" '# ! verify_epoch'; then
        echo "$GATE: SELFTEST FAILED — the clean fixture no longer carries a commented-out negation; the comment-stripping assertion is hollow" >&2
        exit 2
    fi
    if str_lacks "$clean" 'refute verify_epoch'; then
        echo "$GATE: SELFTEST FAILED — the clean fixture no longer shows the refute() fix the gate points at" >&2
        exit 2
    fi

    plant() { printf '%s\n' "$1" > "$tmp/sh/sandbox_probe.sh"; }
    self="$PWD/tools/lint/$GATE.sh"

    run_sandbox() {
        ZCL_DISCARD_GATE_SCAN_GLOB="$tmp/sh/*.sh" \
        ZCL_DISCARD_GATE_FILE_FLOOR=1 \
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

    expect pass "the clean fixture — refute(), 'if !', 'while !', 'until !', '! .. ||', '! .. &&', a multi-line condition, a redirected make and a value pipeline — was reported as a violation" \
        "$clean"
    expect fail "a bare '! cmd' statement under set -e did not fail the gate; that assertion can never fire" \
        "$bare_negation"
    expect pass "removing the planted bare negation did not clear it" \
        "$clean"
    expect fail "the SAME bare negation reindented after a 'then' on one line did not fail the gate; the reshape dodge is not closed" \
        "$bare_negation_reshaped"
    expect pass "removing the reshaped negation did not clear it" \
        "$clean"
    expect pass "a bare '! cmd' in a script with no set -e was counted; without errexit it discards no decision" \
        "$negation_no_errexit"
    expect fail "'make ... | tail' in a script with no pipefail did not fail the gate; a failed build reports 0 there" \
        "$make_pipe"
    expect pass "the same 'make | tail' in a script that sets pipefail was counted; the status survives" \
        "$make_pipe_pipefail"

    # This gate must not carry either bug it detects.
    if [ -n "$(scan_violations "$self")" ]; then
        echo "$GATE: SELFTEST FAILED — this gate itself carries a shape it exists to refuse" >&2
        scan_violations "$self" >&2
        exit 2
    fi

    echo "[$GATE] SELFTEST PASS (a bare '! cmd' under set -e and a pipefail-less 'make | tail' both fail, including the reindented spelling; refute(), if/while/until !, '! .. ||', '! .. &&', a commented-out negation, a redirected make, a value pipeline, a no-errexit script and a pipefail script are all clean; this gate is clean)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
if [ -n "${ZCL_DISCARD_GATE_SCAN_GLOB:-}" ]; then
    # Sandbox path (--selftest): a literal glob over a temp tree.
    # shellcheck disable=SC2206
    scan_files=( $(ls -1 ${ZCL_DISCARD_GATE_SCAN_GLOB} 2>/dev/null || true) )
    FILE_FLOOR="${ZCL_DISCARD_GATE_FILE_FLOOR:-1}"
else
    mapfile -t tracked_shell_files < <(git ls-files '*.sh')
    mapfile -t scan_files < <(existing_files "${tracked_shell_files[@]}")
    FILE_FLOOR="${ZCL_DISCARD_GATE_FILE_FLOOR:-200}"
fi

if [ "${#scan_files[@]}" -lt "$FILE_FLOOR" ]; then
    echo "[$GATE] FATAL — scanned ${#scan_files[@]} file(s), expected at least $FILE_FLOOR." >&2
    echo "        The scan set (git ls-files '*.sh') moved or emptied; refusing to" >&2
    echo "        report clean off a broken scan." >&2
    exit 2
fi

mapfile -t ROWS < <(scan_violations "${scan_files[@]}")

neg=()
mkpipe=()
for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r path line prong excerpt <<< "$row"
    case "$prong" in
        A) neg+=("$path:$line — $excerpt") ;;
        B) mkpipe+=("$path:$line — $excerpt") ;;
    esac
done

fail=0
if [ "${#neg[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#neg[@]} bare \`! cmd\` statement(s) under \`set -e\` — each one is"
    echo "        a DECORATIVE assertion that cannot fail the script:"
    printf '  %s\n' "${neg[@]}" | sort
    echo ""
    echo "  Bash does not exit for a failing command whose return value is being"
    echo "  inverted with '!', and the ERR trap is exempt for the same reason — so"
    echo "  'set -E; trap ... ERR' does not rescue it either. Whatever that command"
    echo "  returns, the script continues to its PASS line."
    echo ""
    echo "  Fix: make the negative assertion exit for itself."
    echo "      refute() { if \"\$@\"; then printf 'expected non-zero from: %s\\n' \"\$*\" >&2; exit 1; fi; }"
    echo "      refute verify_epoch \"\$a\" \"\$b\" \"\$a\""
    echo "  Reference spelling: tools/ship.sh --selftest."
    echo "  If the status really is consumed, say so in the syntax — 'if ! cmd; then',"
    echo "  '! cmd || die ...', '! cmd && ...' are all fine and none of them count."
    fail=1
fi

if [ "${#mkpipe[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#mkpipe[@]} \`make ... | head/tail\` pipeline(s) in a script that never"
    echo "        sets pipefail — a FAILED build reports 0 there:"
    printf '  %s\n' "${mkpipe[@]}" | sort
    echo ""
    echo "  Without pipefail a pipeline reports the LAST stage's status, and"
    echo "  head/tail succeed on any input. The build log looks right and the"
    echo "  next step runs against a binary that was never relinked."
    echo ""
    echo "  Fix — keep the status. Any of:"
    echo "      make <goal> > build.log 2>&1 || { tail -20 build.log; exit 1; }"
    echo "      set -o pipefail   # then the pipeline reports make's status"
    echo "      make <goal> 2>&1 | tail -20; rc=\${PIPESTATUS[0]}"
    fail=1
fi

if [ "$fail" != 0 ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} *.sh files scanned; no bare \`! cmd\` assertion under set -e, no pipefail-less \`make | head/tail\`; no allow-comment mechanism exists)"
