#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_operator_paths — RATCHET gate (shrink-only).
#
# THE RULE THIS ENFORCES: a committed file names no clearnet address,
# hostname, operator username, or local filesystem path. Onion addresses are
# the committed network identity precisely because they reveal nothing about
# where a node or a contributor physically is. A tracked file that says
# `/home/<user>/...` hands every reader of the repository the operator's
# account name, their directory layout, and (with a username that matches a
# handle elsewhere) a way to correlate the two.
#
# THE LEAK THAT MOTIVATED IT, measured 2026-08-26 before the fix: 162 tracked
# files carried an absolute home path, essentially all of them committed
# census evidence under corpus/. The producer wrote the package store's
# absolute datadir into corpus/scopes.def; the census then copied that line
# VERBATIM into every evidence record (`scopes_def_line`, 1,151 copies),
# emitted the field again as `"store"` (2,302 copies) in both the evidence
# and the KPI report, and the package factory wrote it a third time as
# `"datadir"` in each of the 73 tracked corpus/factory/*.report.json. None of
# it was load-bearing: every census root is computed over CONTENT HASHES, and
# the def `root` (a package manifest root, re-derived from the store and
# refused on mismatch) is what actually binds the bytes. The path only said
# which local store to read. It is now a LABEL resolved at run time through
# --store-root / $ZCL_CORPUS_STORE_ROOT / $HOME, and both producers REFUSE a
# path-shaped store field (tools/corpus_census.c store_label_valid(),
# tools/package_factory.c pf_store_label()). This gate is the backstop for
# every OTHER way a path can reach a commit.
#
# ── THE THREE PRONGS ───────────────────────────────────────────────────────
#
# A. ABSOLUTE HOME PATH (universal — catches every operator, on any host).
#    A tracked text file containing `/home/<component>` or `/Users/<component>`.
#    This is the durable half of the gate: it does not depend on who is
#    running it, so it protects a contributor whose username this host has
#    never seen.
#
#    `/root/...` is deliberately NOT matched. Measured: 14 tracked files
#    contain the substring and every one of them is `hash/root/count`,
#    `append/root/prove`, or similar — zero real hits, so including it would
#    buy nothing and cost 14 baseline rows that teach a reader to ignore the
#    gate.
#
# B. THE OPERATOR'S USERNAME as a standalone word, derived at run time from
#    `id -un`. This catches the shapes prong A cannot: `<user>@host` in a
#    documented ssh command, `${ZCL_HOST_WATCHDOG_USER:-<user>}` as a shell
#    default, `"host":"<user>-dev"` in a release ledger.
#
# C. THE HOST'S NAME, from `hostname` and `hostname -s`, as standalone words.
#
#    HONEST LIMIT on B and C, stated because it decides how to read a green
#    run: they are HOST-DERIVED, so this gate is only as wide as the machine
#    it runs on. It cannot know another contributor's username or hostname.
#    That is not a reason to skip them — the leak this repository actually
#    ships is the maintainer's — but a green B/C on a CI runner named
#    `runner` proves nothing about the maintainer's identity, and a reviewer
#    must not read it as if it did. Prong A is the one that travels. Both are
#    skipped (loudly, in the PASS line) when the derived token is shorter
#    than 3 characters or is a common word that would fire on ordinary
#    prose — a username of `dev` or `test` would otherwise flag hundreds of
#    files and the gate would be turned off within a day.
#
# ── RATCHET ────────────────────────────────────────────────────────────────
# tools/lint/operator_paths_baseline.txt records, per prong and path, the
# OCCURRENCE count at the time the gate landed. Counts may only SHRINK.
#   * a path/prong pair absent from the baseline with a nonzero count -> FAIL
#   * a count above its baseline                                      -> FAIL
#   * a baseline row whose count is now zero                          -> FAIL
#     (stale; delete the row — that is how the ratchet tightens)
# Occurrences, not lines: the corpus records are single-line JSON, so a
# line-count ratchet would read 1 for a file holding 60 leaked paths and
# would never notice 59 of them being removed.
#
# The baseline file itself is not scanned: it is a LEDGER OF the leaks, and a
# row's hand-written note explaining why a path is there would re-trip the
# gate on the gate's own bookkeeping.
#
# THIS SCRIPT, however, IS scanned like any other tracked file, and that is
# deliberate — a gate exempt from itself is a place to hide. It therefore
# writes no literal identity token anywhere: the prong A regex is assembled
# from the HOME_ROOT_* tokens below, the prong B/C tokens come from `id -un`
# and `hostname`, and every doc example spells the operator `<user>`. This is
# not hypothetical: the first commit of this gate used a real username in the
# prong B example three lines above, and the gate failed on itself the moment
# the file became tracked.
#
# ── PIPEFAIL ───────────────────────────────────────────────────────────────
# Every status-carrying substring test here goes through str_contains from
# tools/scripts/sh_str.sh. `printf | grep -q` under `set -o pipefail` reports
# a MATCH as 141, which in a lint gate reads a FOUND VIOLATION as CLEAN — the
# exact failure mode that would make this gate hollow. Value extraction
# through a pipe is fine (the value still arrives); only an exit status can
# invert.
#
# Usage:
#   ./tools/lint/check_no_operator_paths.sh              # FAIL mode (CI/lint)
#   ./tools/lint/check_no_operator_paths.sh --selftest   # planted-violation proof
#   ZCL_LINT_MODE=UPDATE ./tools/lint/check_no_operator_paths.sh  # shrink baseline
#
# Exit: 0 clean, 1 violation, 2 the gate could not scan (loud, never quiet).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2
# shellcheck source=tools/scripts/sh_str.sh
source "$ROOT/tools/scripts/sh_str.sh"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"

GATE="check-no-operator-paths"
BASELINE="tools/lint/operator_paths_baseline.txt"
MODE="${ZCL_LINT_MODE:-FAIL}"

# The gate never contains a literal absolute home path, so it cannot flag
# itself. The regex is assembled from these tokens instead.
HOME_ROOT_A="home"
HOME_ROOT_B="Users"
RE_ABS="/(${HOME_ROOT_A}|${HOME_ROOT_B})/[A-Za-z0-9][A-Za-z0-9._-]*"

# Words too generic to match as an identity token. A username or hostname in
# this set disables its prong rather than flooding the baseline.
GENERIC_TOKENS=" dev test build user admin node home root local host runner \
ubuntu debian docker ci app main src lib bin tmp data work "

# ── --selftest: a gate nobody has seen FAIL is not a gate ──────────────────
# Plants each prong's violation in a mktemp sandbox, runs the gate against
# ONLY that sandbox (ZCL_OPERATOR_PATHS_SCAN_FILES, so the real index is
# never touched), and requires exit 1. Then removes the violation and
# requires exit 0. The third assertion is the one that catches the pipefail
# inversion this repository has been bitten by: a gate that reports a found
# violation as CLEAN would pass assertion 2 and fail here.
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    st_user="$(id -un 2>/dev/null || true)"
    fails=0

    st_run() {  # st_run <expect-rc> <label> <file>...
        local want="$1" label="$2"; shift 2
        local list="" f rc
        for f in "$@"; do list="$list$f"$'\n'; done
        ZCL_OPERATOR_PATHS_SCAN_FILES="$list" ZCL_LINT_MODE=FAIL \
            "$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")" >/dev/null 2>&1
        rc=$?
        if [ "$rc" != "$want" ]; then
            echo "[$GATE] SELFTEST FAIL: $label expected rc=$want, got rc=$rc"
            fails=1
        else
            echo "[$GATE]   selftest ok: $label (rc=$rc)"
        fi
    }

    # Assertion 1: a clean file passes. Guards against a gate that fails on
    # everything, which would make assertion 2 meaningless.
    printf 'store label = zcl-store-a\npath = corpus/scopes.def\n' \
        > "$tmp/clean.txt"
    st_run 0 "clean file" "$tmp/clean.txt"

    # Assertion 2 (prong A): an absolute home path is REJECTED. The literal
    # is assembled here so this script never itself contains one.
    printf 'datadir = /%s/%s/.zclassic-c23-commons-factory-a\n' \
        "$HOME_ROOT_A" "planted-operator" > "$tmp/planted_a.txt"
    st_run 1 "prong A — planted absolute home path" "$tmp/planted_a.txt"

    # Assertion 3 (prong A, macOS shape).
    printf 'store = /%s/%s/Library/zcode\n' "$HOME_ROOT_B" "planted-operator" \
        > "$tmp/planted_a2.txt"
    st_run 1 "prong A — planted /Users path" "$tmp/planted_a2.txt"

    # Assertion 4 (prong B): the operator's username as a bare word, when
    # this host's username is specific enough for the prong to be armed.
    if [ -n "$st_user" ] && [ "${#st_user}" -ge 3 ] && \
       str_lacks "$GENERIC_TOKENS" " $st_user "; then
        printf 'ssh %s@some-box\n' "$st_user" > "$tmp/planted_b.txt"
        st_run 1 "prong B — planted operator username" "$tmp/planted_b.txt"
    else
        echo "[$GATE]   selftest skip: prong B (username '$st_user' is" \
             "generic or too short on this host — the prong is disarmed)"
    fi

    # Assertion 5: removing the violation restores PASS, so the failures
    # above were caused by the planted bytes and nothing else.
    printf 'datadir = $HOME/.zclassic-c23-commons-factory-a\n' \
        > "$tmp/planted_a.txt"
    st_run 0 "prong A — violation removed" "$tmp/planted_a.txt"

    if [ "$fails" != "0" ]; then
        echo "[$GATE] SELFTEST FAILED"
        exit 1
    fi
    echo "[$GATE] selftest: PASS"
    exit 0
fi

# ── scan set ───────────────────────────────────────────────────────────────
# Tracked, text-only (git grep -I), minus the gate's own baseline ledger.
# ZCL_OPERATOR_PATHS_SCAN_FILES (newline-separated paths) overrides the scan
# set for --selftest, so the self-proof never touches the real index.
SCAN_OVERRIDE="${ZCL_OPERATOR_PATHS_SCAN_FILES:-}"

# count_hits <extended-regex> — print "<count> <path>" per tracked file that
# matches, counting OCCURRENCES. Uses `git grep -oIE` (-I skips binaries) so
# the scan set is exactly the tracked tree.
count_hits() {
    local re="$1" out
    if [ -n "$SCAN_OVERRIDE" ]; then
        # Selftest path: plain files, not necessarily tracked.
        out="$(printf '%s\n' "$SCAN_OVERRIDE" \
               | while IFS= read -r f; do
                     [ -n "$f" ] && [ -f "$f" ] || continue
                     grep -oIE -e "$re" "$f" 2>/dev/null \
                         | sed "s|^.*$|$f|"
                 done)"
    else
        out="$(git grep -oIE -e "$re" -- . ':!'"$BASELINE" 2>/dev/null \
               | sed 's|:.*||')"
    fi
    # `sort | uniq -c` yields "<count> <path>"; flip to "<path> <count>".
    # $1 is cleared rather than printed as $2 so a path containing a space
    # survives (no tracked path has one today; a gate that would silently
    # mis-key the first one that does is not worth the two saved characters).
    printf '%s\n' "$out" | grep -v '^$' | sort | uniq -c \
        | awk '{ n = $1; $1 = ""; sub(/^[ \t]+/, ""); print $0, n }' | sort
}

# word_regex <token> — a standalone-word match for an identity token.
#
# The boundary class treats '-' as a SEPARATOR, not a word character, on
# purpose: `"host":"<user>-dev"` in deploy/release-candidates.jsonl is a real
# hostname leak and a boundary that swallowed the hyphen would miss it. The
# token itself is regex-escaped (a username or hostname legitimately contains
# '.', which unescaped would match any character and turn a near-miss into a
# false hit).
word_regex() {
    local esc
    esc="$(printf '%s' "$1" | sed 's|[][\\.^$*+?(){}|/-]|\\&|g')"
    printf '(^|[^A-Za-z0-9_])%s([^A-Za-z0-9_]|$)' "$esc"
}

# token_usable <token> — true when the token is long enough and not generic.
token_usable() {
    local t="$1"
    [ -n "$t" ] || return 1
    [ "${#t}" -ge 3 ] || return 1
    str_lacks "$GENERIC_TOKENS" " $t "
}

OP_USER="$(id -un 2>/dev/null || true)"
HOST_FQDN="$(hostname 2>/dev/null || true)"
HOST_SHORT="$(hostname -s 2>/dev/null || true)"

declare -A CUR=()
prong_note_b="skipped"
prong_note_c="skipped"

while IFS= read -r row; do
    [ -n "$row" ] || continue
    CUR["A ${row% *}"]="${row##* }"
done < <(count_hits "$RE_ABS")

if token_usable "$OP_USER"; then
    prong_note_b="username '$OP_USER'"
    while IFS= read -r row; do
        [ -n "$row" ] || continue
        CUR["B ${row% *}"]="${row##* }"
    done < <(count_hits "$(word_regex "$OP_USER")")
fi

# Prong C tokens, deduped against the username (a host commonly shares it).
c_tokens=()
for t in "$HOST_FQDN" "$HOST_SHORT"; do
    token_usable "$t" || continue
    [ "$t" = "$OP_USER" ] && continue
    already=0
    for seen in ${c_tokens[@]+"${c_tokens[@]}"}; do
        [ "$seen" = "$t" ] && already=1
    done
    [ "$already" = "1" ] && continue
    c_tokens+=("$t")
done
if [ "${#c_tokens[@]}" -gt 0 ]; then
    prong_note_c="hostname $(printf "'%s' " "${c_tokens[@]}")"
    for t in "${c_tokens[@]}"; do
        while IFS= read -r row; do
            [ -n "$row" ] || continue
            key="C ${row% *}"
            n="${row##* }"
            CUR["$key"]=$(( ${CUR["$key"]:-0} + n ))
        done < <(count_hits "$(word_regex "$t")")
    done
fi

# ── fail-loud: the scan set must not have silently emptied ─────────────────
if [ -z "$SCAN_OVERRIDE" ]; then
    tracked_n="$(git ls-files | wc -l)"
    gate_require_scanned "$tracked_n" 100 "$GATE" \
        "git ls-files returned almost nothing — wrong cwd, or not a checkout"
fi

# ── UPDATE mode ────────────────────────────────────────────────────────────
if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# check_no_operator_paths RATCHET baseline — SHRINK-ONLY."
        echo "#"
        echo "# Format: <prong> <path> <occurrences>"
        echo "#   A  absolute home path (/home/<x>, /Users/<x>) — universal"
        echo "#   B  the operator's username as a standalone word (host-derived)"
        echo "#   C  the host's name as a standalone word (host-derived)"
        echo "#"
        echo "# Counts may only DECREASE. A new path/prong pair fails HARD; a row"
        echo "# whose count reaches zero is STALE and must be deleted — that is"
        echo "# how the ratchet tightens. Raising a number is never a fix."
        echo "#"
        echo "# Regenerate after removing some:"
        echo "#   ZCL_LINT_MODE=UPDATE ./tools/lint/check_no_operator_paths.sh"
        for k in "${!CUR[@]}"; do printf '%s %s\n' "$k" "${CUR[$k]}"; done \
            | sort -k1,1 -k2,2
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED (${#CUR[@]} rows)"
    exit 0
fi

# ── compare ────────────────────────────────────────────────────────────────
# A sandbox scan (--selftest) is judged with NO grandfathering: the baseline
# describes the real tree, so applying it to planted fixtures would both let
# a planted violation through (if it happened to share a path) and mark every
# real row stale. Zero baseline, zero stale check — any hit is a violation.
declare -A BASE=()
if [ -n "$SCAN_OVERRIDE" ]; then
    :
elif [ -f "$BASELINE" ]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | sed 's|^[[:space:]]*||; s|[[:space:]]*$||')"
        [ -n "$line" ] || continue
        set -- $line
        [ "$#" -ge 3 ] || continue
        BASE["$1 $2"]="$3"
    done < "$BASELINE"
fi

new_rows=(); grown_rows=(); stale_rows=()
for k in "${!CUR[@]}"; do
    n="${CUR[$k]}"
    b="${BASE[$k]:-}"
    if [ -z "$b" ]; then
        new_rows+=("$k ($n occurrence(s))")
    elif [ "$n" -gt "$b" ]; then
        grown_rows+=("$k ($b -> $n)")
    fi
done
if [ -z "$SCAN_OVERRIDE" ]; then
    for k in "${!BASE[@]}"; do
        [ -n "${CUR[$k]:-}" ] && continue
        stale_rows+=("$k (baseline ${BASE[$k]}, now 0)")
    done
fi

fail=0
if [ "${#new_rows[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#new_rows[@]} NEW operator-identity leak(s) in tracked files:"
    printf '  %s\n' "${new_rows[@]}" | sort
    echo "  A committed file must name no local filesystem path, operator"
    echo "  username, or hostname. Use a repo-relative path, a stable opaque"
    echo "  label resolved at run time, \$HOME/\$USER, or omit the field."
    echo "  Adding a row to $BASELINE is not a fix; the baseline only shrinks."
    fail=1
fi
if [ "${#grown_rows[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#grown_rows[@]} baselined file(s) leak MORE than before:"
    printf '  %s\n' "${grown_rows[@]}" | sort
    echo "  Grandfathered debt may shrink, never grow."
    fail=1
fi
if [ "${#stale_rows[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale_rows[@]} STALE baseline row(s) — delete them from $BASELINE:"
    printf '  %s\n' "${stale_rows[@]}" | sort
    echo "  The leak is gone; leaving the row would let it come back for free."
    fail=1
fi

[ "$fail" = "0" ] || exit 1

a=0; b=0; c=0
for k in "${!CUR[@]}"; do
    case "$k" in
        "A "*) a=$(( a + CUR[$k] )) ;;
        "B "*) b=$(( b + CUR[$k] )) ;;
        "C "*) c=$(( c + CUR[$k] )) ;;
    esac
done
echo "[$GATE] PASS (${#CUR[@]} baselined row(s): prong A $a absolute-home-path" \
     "occurrence(s); prong B $b — $prong_note_b; prong C $c — $prong_note_c)"
exit 0
