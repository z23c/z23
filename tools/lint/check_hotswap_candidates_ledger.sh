#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_candidates_ledger.sh — the agent-facing hot-swap ledger must
# agree with the gates, and `make hotswap` must still refuse what it refused.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# tools/dev/hotswap-candidates.sh is the tool an agent asks "is this file
# hot-swappable, and if not, why?" before it decides between a ~9 second module
# rebuild and a ~4m45s whole-program relink. It answers by re-parsing the same
# config/*.def manifests the lint gates parse — with its OWN awk walkers.
#
# Two independent parsers of one manifest set is exactly the shape that rots
# quietly. If the tool's walk drifts (a renamed macro, a reformatted row, a
# multi-line invocation it stops seeing) it does not crash: it under-reports.
# It says "BLOCKED — owns no READY_READ leaf" about a file that is registered,
# or reports 3% coverage when the real number is 14%, and the agent believes
# it and pays the slow loop. A tool that advises has to be held to the numbers
# the gates already publish.
#
# ── WHAT IS ASSERTED (all fail-closed) ──────────────────────────────────────
#   A. COUNT PARITY. check_hotswap_swappable_shape.sh publishes, from its own
#      parse: the swappable file count, the swappable leaf count, the island
#      member count, and the ZCL_COMMAND_READY_READ population. The tool's
#      --summary line must report the same four numbers. Either parser
#      drifting is a failure; agreement off two independent walks is the point.
#   B. THE DENYLIST HOLDS IN THE ADVICE, not just in the manifests. Every
#      engine/composition/hotswap_denied_leaves.def leaf, asked of the tool with --leaf,
#      must come back BLOCKED (exit 2). check-hotswap-denied-leaves already
#      keeps denied leaves out of the .def files; this keeps them out of the
#      tool's RECOMMENDATIONS, which is a separate surface an agent acts on.
#   C. THE REFUSAL SURVIVES. `make hotswap` was widened from a dead-end refusal
#      to a ledger. The dangerous form it was refusing — FILES=/PROBE=, the
#      runtime-publication + resident-probing path — must still hit the same
#      refusal and exit 3. Asserted as text against the Makefile recipe so it
#      costs no build: the message and the `exit 3` must both still be there,
#      guarded by FILES/PROBE.
#
# Usage:
#   tools/lint/check_hotswap_candidates_ledger.sh            # the gate
#   tools/lint/check_hotswap_candidates_ledger.sh --selftest # prove it fires
#
# Env:
#   ZCL_HOTSWAP_CANDIDATES_TOOL  path to the tool (default tools/dev/...);
#                                the selftest points it at a seeded stub.
#   ZCL_HOTSWAP_CANDIDATES_MAKEFILE  Makefile to scan (default ./Makefile);
#                                the selftest points it at a seeded fixture.
#
# Exit: 0 clean, 1 on any violation, 2 on a hollow/unreadable scan.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh

# Resolved INSIDE run_check, never at top level: the selftest re-runs run_check
# with these env vars set, and a top-level expansion would freeze the real
# paths in before the seeded fixture could take effect.
SHAPE_GATE="tools/lint/check_hotswap_swappable_shape.sh"
DENIED_DEF="engine/composition/hotswap_denied_leaves.def"

run_check() {
    local TOOL="${ZCL_HOTSWAP_CANDIDATES_TOOL:-tools/dev/hotswap-candidates.sh}"
    local MAKEFILE="${ZCL_HOTSWAP_CANDIDATES_MAKEFILE:-Makefile}"
    local fail=0

    for f in "$TOOL" "$SHAPE_GATE" "$DENIED_DEF" "$MAKEFILE"; do
        if [ ! -r "$f" ]; then
            echo "check_hotswap_candidates_ledger: FATAL — '$f' missing/unreadable." >&2
            echo "  Refusing to certify an advisory tool off an unreadable input." >&2
            return 2
        fi
    done

    # ── A. count parity against the gate's own published numbers ────────────
    local shape_out shape_rc summary_out summary_rc
    shape_out="$(bash "$SHAPE_GATE" 2>&1)"
    shape_rc=$?
    if [ "$shape_rc" -ne 0 ]; then
        echo "check_hotswap_candidates_ledger: FATAL — $SHAPE_GATE itself failed (exit $shape_rc)." >&2
        echo "  The reference numbers are not trustworthy; fix that gate first." >&2
        printf '%s\n' "$shape_out" | sed 's/^/    /' >&2
        return 2
    fi

    local g_files g_leaves g_island g_ready
    g_files="$(printf '%s\n' "$shape_out" | LC_ALL=C sed -n 's/.*OK: \([0-9][0-9]*\) swappable file(s).*/\1/p' | head -1)"
    g_leaves="$(printf '%s\n' "$shape_out" | LC_ALL=C sed -n 's/.*swappable file(s), \([0-9][0-9]*\) READY read-only leaf.*/\1/p' | head -1)"
    g_island="$(printf '%s\n' "$shape_out" | LC_ALL=C sed -n 's/.*leaf\/leaves, \([0-9][0-9]*\) stateless island member.*/\1/p' | head -1)"
    g_ready="$(printf '%s\n' "$shape_out" | LC_ALL=C sed -n 's/.*cross-checked against \([0-9][0-9]*\) ZCL_COMMAND_READY_READ.*/\1/p' | head -1)"

    local n
    for n in "$g_files" "$g_leaves" "$g_island" "$g_ready"; do
        if [ -z "$n" ]; then
            echo "check_hotswap_candidates_ledger: FATAL — could not read the reference counts" >&2
            echo "  out of $SHAPE_GATE's OK line. Its output shape changed; this gate" >&2
            echo "  refuses to certify parity it cannot measure." >&2
            printf '%s\n' "$shape_out" | sed 's/^/    /' >&2
            return 2
        fi
    done
    gate_require_scanned "$g_leaves" 1 check_hotswap_candidates_ledger \
        "$SHAPE_GATE reported zero swappable leaves"

    summary_out="$(bash "$TOOL" --summary 2>&1)"
    summary_rc=$?
    if [ "$summary_rc" -ne 0 ]; then
        echo "FAIL: '$TOOL --summary' exited $summary_rc."
        printf '%s\n' "$summary_out" | sed 's/^/    /'
        fail=1
    fi

    local t_leaves t_ready t_files t_island
    t_leaves="$(printf '%s\n' "$summary_out" | LC_ALL=C sed -n 's/^SUMMARY: leaves \([0-9][0-9]*\)\/[0-9][0-9]*.*/\1/p' | head -1)"
    t_ready="$(printf '%s\n' "$summary_out" | LC_ALL=C sed -n 's/^SUMMARY: leaves [0-9][0-9]*\/\([0-9][0-9]*\).*/\1/p' | head -1)"
    t_files="$(printf '%s\n' "$summary_out" | LC_ALL=C sed -n 's/.*| TUs \([0-9][0-9]*\)\/[0-9][0-9]*.*/\1/p' | head -1)"
    t_island="$(printf '%s\n' "$summary_out" | LC_ALL=C sed -n 's/.*+ \([0-9][0-9]*\) island member(s).*/\1/p' | head -1)"

    if [ -z "$t_leaves$t_ready$t_files$t_island" ] \
       || [ -z "$t_leaves" ] || [ -z "$t_ready" ] || [ -z "$t_files" ] || [ -z "$t_island" ]; then
        echo "FAIL: could not parse the coverage numbers out of '$TOOL --summary'."
        echo "      Expected a line shaped:"
        echo "        SUMMARY: leaves <n>/<n> READY_READ covered (..%) | TUs <n>/<n> ... + <n> island member(s) | ..."
        printf '%s\n' "$summary_out" | sed 's/^/    /'
        return 1
    fi

    local mismatch=""
    [ "$t_files"  = "$g_files"  ] || mismatch="${mismatch}    swappable TU count:  tool=$t_files  gate=$g_files"$'\n'
    [ "$t_leaves" = "$g_leaves" ] || mismatch="${mismatch}    swappable leaf count: tool=$t_leaves  gate=$g_leaves"$'\n'
    [ "$t_island" = "$g_island" ] || mismatch="${mismatch}    island member count: tool=$t_island  gate=$g_island"$'\n'
    [ "$t_ready"  = "$g_ready"  ] || mismatch="${mismatch}    READY_READ population: tool=$t_ready  gate=$g_ready"$'\n'
    if [ -n "${mismatch//[[:space:]]/}" ]; then
        echo "FAIL: $TOOL disagrees with $SHAPE_GATE about what the manifests say."
        printf '%s' "$mismatch"
        echo "  Two independent parsers of one manifest set have drifted. The tool"
        echo "  advises agents which loop to use; a tool that under-reports coverage"
        echo "  sends them to the 4m45s rebuild for a file that swaps in 9 seconds."
        fail=1
    fi

    # ── B. the denylist holds in the ADVICE ─────────────────────────────────
    local denied denied_n=0 leaf out rc
    denied="$(LC_ALL=C awk '
        { buf = buf $0 "\n" }
        END {
            n = length(buf); TOK = "HOTSWAP_DENIED_LEAF("; L = length(TOK); i = 1
            while (i <= n) {
                if (substr(buf, i, L) != TOK || (i > 1 && substr(buf, i - 1, 1) != "\n")) { i++; continue }
                j = i + L; depth = 1; in_str = 0; esc = 0; spec = ""
                while (j <= n && depth > 0) {
                    c = substr(buf, j, 1)
                    if (in_str) {
                        if (esc) { esc = 0 } else if (c == "\\") { esc = 1 } else if (c == "\"") { in_str = 0 }
                    } else {
                        if (c == "\"") { in_str = 1 } else if (c == "(") { depth++ } else if (c == ")") { depth-- }
                    }
                    if (depth > 0) spec = spec c
                    j++
                }
                if (match(spec, /"[^"]*"/)) print substr(spec, RSTART + 1, RLENGTH - 2)
                i = j
            }
        }' "$DENIED_DEF")"
    while IFS= read -r leaf; do
        [ -n "$leaf" ] || continue
        denied_n=$((denied_n + 1))
        out="$(bash "$TOOL" --leaf "$leaf" 2>&1)"
        rc=$?
        if [ "$rc" -ne 2 ] || ! str_contains "$out" "VERDICT: BLOCKED"; then
            echo "FAIL: '$TOOL --leaf $leaf' did not report BLOCKED (exit $rc)."
            echo "      That leaf is on $DENIED_DEF. The tool must never advise a"
            echo "      swap of a denied leaf, whatever the mechanical rules say."
            printf '%s\n' "$out" | sed 's/^/    /'
            fail=1
        fi
    done <<< "$denied"
    gate_require_scanned "$denied_n" 1 check_hotswap_candidates_ledger \
        "no HOTSWAP_DENIED_LEAF rows parsed from $DENIED_DEF — the denylist fails CLOSED"

    # ── C. the refusal survives ─────────────────────────────────────────────
    local recipe
    recipe="$(LC_ALL=C awk '
        /^hotswap:/ { inb = 1; next }
        inb {
            if ($0 ~ /^[^\t ]/ && $0 !~ /^#/) exit
            print
        }' "$MAKEFILE")"
    if [ -z "${recipe//[[:space:]]/}" ]; then
        echo "FAIL: no 'hotswap:' recipe found in $MAKEFILE."
        echo "      This gate exists to prove that recipe still refuses runtime"
        echo "      publication; it cannot certify a recipe it cannot read."
        fail=1
    else
        local missing=""
        str_contains "$recipe" "REFUSING" || missing="${missing} the refusal message"
        str_contains "$recipe" "exit 3"   || missing="${missing}, 'exit 3'"
        str_contains "$recipe" 'FILES'    || missing="${missing}, the FILES= guard"
        str_contains "$recipe" 'PROBE'    || missing="${missing}, the PROBE= guard"
        if [ -n "${missing//[[:space:]]/}" ]; then
            echo "FAIL: the 'hotswap:' recipe no longer refuses runtime publication."
            echo "      Missing:$missing"
            echo "      \`make hotswap FILES=... [PROBE=...]\` is the RUNTIME PUBLICATION"
            echo "      form — build a generation .so and hand it to the resident"
            echo "      dev_hotswap RPC for in-process publication and resident probing."
            echo "      Widening the bare goal into a read-only ledger must never make"
            echo "      that form reachable. Restore the guarded refusal + exit 3."
            fail=1
        fi
    fi

    if [ "$fail" -ne 0 ]; then
        return 1
    fi
    echo "  OK: ledger agrees with $SHAPE_GATE ($g_files TU(s), $g_leaves leaf/leaves,"
    echo "      $g_island island member(s), $g_ready READY_READ leaves); $denied_n denied"
    echo "      leaf/leaves refused by the tool; 'make hotswap' still refuses FILES=/PROBE=."
    return 0
}

# ── selftest: prove each class fires before trusting the gate ───────────────
selftest() {
    local rc bad=0
    _selftest_tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-hotswap-ledger-selftest.XXXXXX")" || return 2
    trap 'rm -rf "${_selftest_tmp:-}"' EXIT HUP INT TERM

    echo "── selftest 1/2: a tool that under-reports coverage must FAIL ──"
    cat > "${_selftest_tmp}/stub-tool.sh" <<'STUB'
#!/usr/bin/env bash
# Seeded violation: reports coverage numbers that do not match the manifests.
if [ "${1:-}" = "--summary" ]; then
  echo "SUMMARY: leaves 1/1 READY_READ covered (100.0%) | TUs 1/1 app/controllers TUs registered (100.0%) + 1 island member(s) | eligible-not-registered 0 TU(s)/0 leaf/leaves | blocked 0 TU(s) | 0 leaf/leaves owned by a registered TU but unlisted and unexplained"
  exit 0
fi
if [ "${1:-}" = "--leaf" ]; then echo "VERDICT: BLOCKED"; exit 2; fi
exit 0
STUB
    chmod +x "${_selftest_tmp}/stub-tool.sh"
    ( ZCL_HOTSWAP_CANDIDATES_TOOL="${_selftest_tmp}/stub-tool.sh" run_check ) >"${_selftest_tmp}/out1" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "  SELFTEST FAIL: the gate passed a tool whose counts disagree with the manifests." >&2
        bad=1
    else
        echo "  ok (exit $rc)"
    fi

    echo "── selftest 2/2: a hotswap: recipe with the refusal removed must FAIL ──"
    {
        echo "hotswap:"
        printf '\t@tools/dev/hotswap-candidates.sh --all\n'
        echo ""
    } > "${_selftest_tmp}/Makefile.seeded"
    ( ZCL_HOTSWAP_CANDIDATES_MAKEFILE="${_selftest_tmp}/Makefile.seeded" run_check ) >"${_selftest_tmp}/out2" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "  SELFTEST FAIL: the gate passed a recipe that no longer refuses FILES=/PROBE=." >&2
        bad=1
    else
        echo "  ok (exit $rc)"
    fi

    if [ "$bad" -ne 0 ]; then
        echo "SELFTEST FAILED — this gate cannot be trusted." >&2
        return 1
    fi
    echo "  selftest OK: both seeded violations were caught."
    return 0
}

echo "══ LINT: hot-swap candidate ledger agrees with the gates; make hotswap still refuses ══"

if [ "${1:-}" = "--selftest" ]; then
    selftest
    exit $?
fi

run_check
exit $?
