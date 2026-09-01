# shellcheck shell=bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# gate_lib.sh — shared helpers that make lint gates FAIL-LOUD instead of
# fail-silent. See docs/work/lint-gate-hollowness-audit.md.
#
# A hollow gate reports "clean" exit 0 while a real violation is present:
# its scan set silently emptied (a renamed/moved dir, a `for f in glob`
# that found nothing, a non-GNU grep that exited >=2) and the violation
# loop ran zero times. This file provides two primitives every gate should
# reach for so that "scanned nothing" becomes a LOUD exit 2, never a quiet
# pass:
#
#   gate_require_scanned <count> <floor> <gate-name> [hint]
#       Abort (exit 2) when the realized scan count is below a known floor.
#       Use floor=1 for "must scan at least one file" or a higher integer
#       for a known-population gate.
#
#   gate_grep <args...>
#       A `grep` wrapper that treats exit >=2 (a real grep error: bad flag,
#       unreadable file, broken regex on a non-GNU grep) as FATAL (exit 2)
#       instead of masking it as "no match" the way `grep ... || true` does.
#       Exit 0 (match) and 1 (no match) pass through unchanged. Captures
#       and re-emits grep's stdout so callers can `gate_grep ... < <(...)`.
#
#   gate_load_list_file <path> <array-name> [<count-var-name>]
#       Load a baseline/allowlist file into the nameref'd associative array
#       as a set: one entry per non-blank, non-`#`-comment line, trimmed,
#       ARRAY["<line>"]=1. A missing <path> leaves the array empty (no
#       error) — callers that need the file to exist for a later append
#       should `touch` it themselves before calling. If <count-var-name> is
#       given, that nameref'd variable is set to the number of entries
#       loaded. This is the ~9-line `declare -A ...; while IFS= read -r
#       line; do ...; done < "$FILE"` block that used to be hand-rolled in
#       most gates.
#
#   gate_load_kv_file <path> <array-name>
#       Same file format and comment/blank handling as gate_load_list_file,
#       but for baselines of the form "<key> <value>" per line (e.g. a
#       recorded legacy-count): ARRAY["<first token>"]="<last token>".
#
#   gate_count_and_report <matches> <count-var-name>
#       Print each non-blank line of <matches> to stderr; set the nameref'd
#       <count-var-name> to the line count. Replaces the hand-rolled
#       "violations=0; while read; do … done <<< $matches" block.
#
#   gate_git_oracle <out-file> <gate-name> <pathspec>...
#       Write the set of git-TRACKED paths matching the pathspecs to
#       <out-file>, sorted and unique. An independent expectation for a
#       coverage check: the git index knows nothing about the gate’s own
#       find/glob, so the two cannot fail together. A git error or an
#       empty result is exit 2, never an expectation of nothing.
#
#   gate_require_coverage <actual-file> <expected-file> <allowance> \
#                         <gate-name> <allowance-var-name> <fix-hint>
#       The check gate_require_scanned is NOT. Floors catch "nothing
#       happened"; this catches "less happened than should have". Names
#       the missing entries. Below expectation by more than <allowance>
#       is UNPROVEN (exit 2) — a third answer, neither pass nor
#       violation. Below the allowance is a VIOLATION (exit 1): the
#       allowance is a shrink-only ratchet and must be lowered.
#
#   gate_require_git_coverage <actual-file> <allowance> <gate-name> \
#                             <allowance-var-name> <fix-hint> -- <pathspec>...
#       The two above composed, for the common case of a gate scanning
#       tracked sources. See the long comment above gate_git_oracle.
#
# Sourcing contract: a gate sources this AFTER `set -euo pipefail` and its
# own `cd` to the repo root. These helpers do not change cwd.

# Abort LOUD if the scan set is smaller than a known floor. This is the
# single most important anti-hollow primitive: a gate that derives its scan
# set from find/glob/grep -rl and never asserts non-emptiness will silently
# pass when the producer empties.
gate_require_scanned() {
    # Audit hook, off unless ZCL_GATE_SCAN_LOG names a file: append one
    # "<gate> <realized> <floor> <call site>" row per check, so a single
    # `ZCL_GATE_SCAN_LOG=/path make lint` measures every floor in the tree
    # against what it actually scans. That is how the numbers quoted in the
    # coverage comments below were taken, and how the next person can
    # retake them instead of trusting a stale figure.
    if [ -n "${ZCL_GATE_SCAN_LOG:-}" ]; then printf '%s\t%s\t%s\t%s\n' "${3:-?}" "${1:-?}" "${2:-?}" "${BASH_SOURCE[1]:-?}:${BASH_LINENO[0]:-?}" >> "$ZCL_GATE_SCAN_LOG" 2>/dev/null || true; fi
    local count="$1" floor="$2" name="$3" hint="${4:-}"
    if ! [ "$count" -ge "$floor" ] 2>/dev/null; then
        echo "$name: FATAL — scan set is '${count}' (< floor ${floor})." >&2
        echo "  The scan producer (find/glob/grep) returned too little; a" >&2
        echo "  scanned dir/file was likely renamed, moved, or deleted." >&2
        echo "  Refusing to report 'clean' off a hollow (empty) scan." >&2
        [ -n "$hint" ] && echo "  $hint" >&2
        exit 2
    fi
}

# grep wrapper: exit 0/1 pass through; exit >=2 (real error) is FATAL.
# Echoes grep's stdout so it composes in pipelines / process substitution.
gate_grep() {
    local out rc
    set +e
    out=$(grep "$@")
    rc=$?
    set -e
    if [ "$rc" -ge 2 ]; then
        echo "gate_grep: FATAL — grep failed (exit $rc) for: grep $*" >&2
        echo "  A grep error (bad flag, unreadable file, regex unsupported by" >&2
        echo "  this grep) was about to be masked as 'no match'. Refusing to" >&2
        echo "  report 'clean' off a broken scan." >&2
        exit 2
    fi
    [ -n "$out" ] && printf '%s\n' "$out"
    return "$rc"
}

# Load a baseline/allowlist file into the nameref'd associative array as a
# set: one entry per non-blank, non-`#`-comment line, trimmed, ARRAY["<line
# >"]=1. Missing FILE leaves the array empty — no error, no side effect.
gate_load_list_file() {
    local file="$1" _array_name="$2" _count_name="${3:-}"
    local -n _gllf_arr="$_array_name"
    local line _gllf_count=0
    # bash nameref quirk (reproduced on 5.2): a `local -n` array ref that is
    # never actually written through before the function returns leaves the
    # CALLER's array unbound under `set -u` — even though it was already
    # `declare -A`'d. Force one real write+delete so the nameref always
    # resolves, whether or not FILE exists or has any real (non-comment,
    # non-blank) lines.
    _gllf_arr["__gate_lib_probe__"]=1
    unset '_gllf_arr[__gate_lib_probe__]'
    if [[ -f "$file" ]]; then
        while IFS= read -r line; do
            line="${line%%#*}"
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "$line" ]] && continue
            _gllf_arr["$line"]=1
            _gllf_count=$((_gllf_count + 1))
        done < "$file"
    fi
    if [[ -n "$_count_name" ]]; then
        local -n _gllf_cnt="$_count_name"
        _gllf_cnt="$_gllf_count"
    fi
}

# Same file format/comment/blank handling as gate_load_list_file, but for
# "<key> <value>" baselines (e.g. a recorded legacy count): the nameref'd
# associative array gets ARRAY["<first token>"]="<last token>" per line.
gate_load_kv_file() {
    local file="$1" _array_name="$2"
    local -n _glkf_arr="$_array_name"
    local line key val
    # See the nameref-probe comment in gate_load_list_file above — same fix.
    _glkf_arr["__gate_lib_probe__"]=1
    unset '_glkf_arr[__gate_lib_probe__]'
    if [[ -f "$file" ]]; then
        while IFS= read -r line; do
            line="${line%%#*}"
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "$line" ]] && continue
            key="${line%% *}"
            val="${line##* }"
            _glkf_arr["$key"]="$val"
        done < "$file"
    fi
}

# Print each non-blank line of MATCHES to stderr; set the nameref'd
# COUNT-VAR-NAME to the number of lines printed.
gate_count_and_report() {
    local matches="$1" _count_name="$2"
    local -n _gcar_count="$_count_name"
    _gcar_count=0
    if [[ -n "${matches//[[:space:]]/}" ]]; then
        local line
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            _gcar_count=$((_gcar_count + 1))
            echo "$line" >&2
        done <<< "$matches"
    fi
}

# ── coverage, as distinct from hollowness ───────────────────────────────────
#
# gate_require_scanned() above answers ONE question: "did the scan produce
# anything at all?" It is calibrated to catch "nothing happened". It cannot
# catch "less happened than should have", and 60-odd gates lean on it as
# though it could. Worked example, measured 2026-08-30:
# check_arm_symbol_single.sh scans 3250 .c files under its declared roots
# behind a floor of 2500 — a scan that silently lost 750 of them (23% of the
# gate's own surface) still reports clean. The floor was never wrong; it was
# answering a different question.
#
# A COVERAGE check compares the realized scan set against an INDEPENDENTLY
# DERIVED expectation — derived by a different mechanism than the gate's own
# find/glob, so the two cannot fail together. For a gate scanning tracked
# sources the natural independent oracle is the git index (gate_git_oracle
# below): it knows nothing about the gate's globbing, so a find that dies
# mid-walk, a filter that over-prunes, a root that stops matching, or a
# truncated mapfile all surface as NAMED missing files.
#
# Three answers, not two. Actual below expectation is UNPROVEN (exit 2) —
# not a pass, and not a violation. A scan that did not happen is its own
# verdict; grading it either way is the lie this whole file exists to stop.
#
# The allowance is a SHRINK-ONLY RATCHET, both directions enforced, exactly
# as CAP_CLOSURE_COVERAGE_BASELINE is in check_capability_closure.sh: an
# allowance sitting ABOVE the true shortfall is a VIOLATION (exit 1) telling
# the operator to lower it. An allowance that may only ever be raised stops
# meaning "what we measured" and starts meaning "whatever nobody bothered to
# lower" — that is how a ratchet rusts shut. Every caller here records 0.
#
# What a coverage check is NOT: it does not widen a gate's scope. The
# expectation must be derived for the set the gate INTENDS to scan. A gate
# that deliberately covers one subtree gets an expectation for that subtree.
# An expectation that fires on files the gate never meant to read trains
# people to ignore the gate, which is worse than the floor it replaced.

# Shared scratch for the coverage helpers. `exit` from a function ends the
# whole shell, so a cleanup line placed after a failing call never runs —
# every exit path below calls _gate_lib_tmp_done itself.
_gate_lib_tmp_new() {
    _GATE_LIB_TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-gate-lib.XXXXXX")" || {
        echo "gate_lib: FATAL — mktemp failed." >&2; exit 2; }
}
_gate_lib_tmp_done() {
    [ -n "${_GATE_LIB_TMP:-}" ] && rm -rf "$_GATE_LIB_TMP"
    _GATE_LIB_TMP=""
    return 0
}

# Derive the expected scan set from the git index — a mechanism wholly
# independent of any find/glob a gate runs — into OUT-FILE, LC_ALL=C sorted
# and unique. Every argument after GATE-NAME is a git pathspec (magic
# pathspecs such as ':!:tests/harness/include/test/*' work).
#
# Deliberately not `git ls-files -z`: bash command substitution drops NUL
# bytes, which would fuse the whole listing into one line. Plain output is
# safe here because git quotes any path holding a newline, and a quoted path
# simply reads as missing — fail-closed, which is the correct direction.
#
# The oracle itself must never fail open: git erroring, git being absent, or
# the pathspec set matching nothing would each turn "I cannot vouch for this
# scan" into a silent clean bill of health. All three are exit 2.
#
#   gate_git_oracle <out-file> <gate-name> <pathspec>...
gate_git_oracle() {
    local out="$1" name="$2" rc=0
    shift 2
    local raw
    raw="$(git ls-files --cached -- "$@" 2>/dev/null)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "$name: UNPROVEN — the coverage oracle could not run:" >&2
        echo "  'git ls-files -- $*' exited $rc." >&2
        echo "  Without an independent expectation this gate cannot tell a" >&2
        echo "  complete scan from a partial one, so it refuses to grade" >&2
        echo "  either way. Run it from inside the checkout." >&2
        _gate_lib_tmp_done
        exit 2
    fi
    printf '%s\n' "$raw" | LC_ALL=C sort -u | sed '/^$/d' > "$out"
    local n
    n="$(wc -l < "$out")"
    if [ "$n" -eq 0 ]; then
        echo "$name: UNPROVEN — the coverage oracle is empty: git tracks no" >&2
        echo "  file matching: $*" >&2
        echo "  An empty expectation would pass every scan, including a scan" >&2
        echo "  of nothing. Refusing to vouch for coverage off a hollow" >&2
        echo "  oracle. Fix the pathspec, or drop the coverage check if the" >&2
        echo "  set is genuinely gone." >&2
        _gate_lib_tmp_done
        exit 2
    fi
}

# Compare a realized scan set against an independently derived expectation.
# Both files hold one entry per line (paths, roots, module names — whatever
# the gate scans by); neither needs to be pre-sorted.
#
#   gate_require_coverage <actual-file> <expected-file> <allowance> \
#                         <gate-name> <allowance-var-name> <fix-hint>
#
# ALLOWANCE is the number of expected entries this gate is knowingly and
# documentedly allowed not to reach. ALLOWANCE-VAR-NAME names the variable
# holding it, so the failure text can say exactly what to edit.
#
#   missing >  allowance  -> UNPROVEN, exit 2 (a partial scan, files named)
#   missing <  allowance  -> VIOLATION, exit 1 (stale ratchet, lower it)
#   missing == allowance  -> return 0
gate_require_coverage() {
    local actual="$1" expected="$2" allowance="$3" name="$4" var="$5" hint="$6"
    local cw
    cw="$(mktemp -d "${TMPDIR:-/tmp}/zcl-gate-cov.XXXXXX")" || {
        echo "$name: FATAL — mktemp failed for the coverage check." >&2
        _gate_lib_tmp_done; exit 2; }
    # ACTUAL-FILE may be "-": read the realized scan set from stdin, so a
    # caller with the set in an array needs no temp file of its own.
    if [ "$actual" = "-" ]; then cat > "$cw/stdin.txt"; actual="$cw/stdin.txt"; fi
    LC_ALL=C sort -u "$actual"   > "$cw/a.txt"
    LC_ALL=C sort -u "$expected" > "$cw/e.txt"
    LC_ALL=C comm -13 "$cw/a.txt" "$cw/e.txt" > "$cw/missing.txt"
    local n_missing n_expected n_actual
    n_missing="$(wc -l < "$cw/missing.txt")"
    n_expected="$(wc -l < "$cw/e.txt")"
    n_actual="$(wc -l < "$cw/a.txt")"

    if [ "$n_missing" -gt "$allowance" ]; then
        echo "$name: UNPROVEN — the scan reached $n_actual of the $n_expected" >&2
        echo "  entries an independent oracle says it should have reached;" >&2
        echo "  $n_missing missing, above the shrink-only allowance of" >&2
        echo "  $allowance recorded in $var." >&2
        echo "  This is a PARTIAL scan: not a clean one, and not a violating" >&2
        echo "  one. 'I scanned less than my subject' is a third answer — the" >&2
        echo "  gate never ran over the code it claims to cover, so it cannot" >&2
        echo "  report either verdict. A file-count floor cannot see this;" >&2
        echo "  the count stayed large." >&2
        echo "  Not reached (first 20 of $n_missing):" >&2
        sed -n '1,20p' "$cw/missing.txt" | sed 's/^/    /' >&2
        if [ "$n_missing" -gt 20 ]; then
            echo "    ... and $((n_missing - 20)) more" >&2
        fi
        echo "  $hint" >&2
        rm -rf "$cw"; _gate_lib_tmp_done
        exit 2
    fi

    if [ "$n_missing" -lt "$allowance" ]; then
        echo "$name: VIOLATION — the coverage allowance is stale: the scan now" >&2
        echo "  misses only $n_missing of $n_expected expected entries, below" >&2
        echo "  $var=$allowance." >&2
        echo "  Coverage improved without lowering the allowance. An allowance" >&2
        echo "  that may only ever rise stops meaning 'what we measured' and" >&2
        echo "  starts meaning 'whatever nobody lowered' — a ratchet that" >&2
        echo "  rusts shut. Lower $var to $n_missing, with the reason, in the" >&2
        echo "  same commit." >&2
        rm -rf "$cw"; _gate_lib_tmp_done
        exit 1
    fi
    rm -rf "$cw"
    return 0
}

# Both halves together, for the common case of a gate scanning tracked files:
# derive the expectation from the git index, then compare against it.
#
#   gate_require_git_coverage <actual-file> <allowance> <gate-name> \
#                             <allowance-var-name> <fix-hint> -- <pathspec>...
gate_require_git_coverage() {
    local actual="$1" allowance="$2" name="$3" var="$4" hint="$5"
    shift 5
    [ "${1:-}" = "--" ] && shift
    _gate_lib_tmp_new
    gate_git_oracle "$_GATE_LIB_TMP/expected.txt" "$name" "$@"
    gate_require_coverage "$actual" "$_GATE_LIB_TMP/expected.txt" \
        "$allowance" "$name" "$var" "$hint"
    _gate_lib_tmp_done
}
