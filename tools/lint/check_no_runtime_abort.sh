#!/usr/bin/env bash
# Gate — no NEW runtime abort primitive in network-reachable code
# (ratchet, shrink-only counts).
#
# What it enforces
# ----------------
# `assert()` IS LIVE IN THIS BUILD. `-DNDEBUG` appears in exactly two places
# in the tree, both of them the vendored LevelDB compile
# (tools/scripts/build_vendor.sh:222 and :566); the node's own CFLAGS
# (Makefile, `CFLAGS = -std=c23 -g -O3 ...`) never define it. So every
# `assert()` compiled into the node is a live `abort()` on failure, and every
# `assert()` sitting on a path that a peer, an RPC argument, an explorer URL
# segment or a stored blob can reach is a remote process-kill primitive.
#
# That is not hypothetical. The Base58 codec under every address, WIF,
# extended key and explorer lookup enforced its assumptions with assert()
# until 2026-07-28; so did BIP32 public child derivation, and so did
# extended-public-key serialization. One malformed input took the whole
# process down. They now return false and log a reason. This gate exists so
# that pile cannot re-form.
#
# Unit of measurement
# -------------------
# Per FILE: the number of RUNTIME `assert(` / `abort(` sites. A file's count
# may only shrink. A file absent from the baseline may have zero.
#
# What is NOT a site
# ------------------
#   * `_Static_assert(...)` / `static_assert(...)` — compile-time, and GOOD.
#     They are the correct replacement for a runtime assertion about a
#     layout or a constant, so a gate that flagged them would push the
#     codebase in exactly the wrong direction. The `[^_[:alnum:]]` prefix
#     guard is what separates them; ~32 of the ~44 naive `assert` hits in
#     the scan set are static assertions.
#   * Anything inside a comment. Note that a per-line `sub(/\/\*.*/, "")`
#     is NOT sufficient: the rationale comments this project writes are
#     multi-line block comments, and the word `assert()` lands on a
#     CONTINUATION line that carries no `/*` of its own (see
#     platform/domain/encoding/src/base58.c, contexts/wallet/modules/keys/src/key.c,
#     contexts/wallet/modules/keys/src/pubkey.c, core/modules/sapling/src/incremental_merkle_tree.c).
#     This gate therefore carries a real block-comment state machine.
#   * Anything inside a string literal.
#   * A site carrying the inline escape hatch (below).
#
# The escape hatch:  // abort-ok:<reason>
# -----------------------------------------
# Mirrors the established `// raw-return-ok:<reason>` idiom in
# check_silent_error_returns.sh. Some aborts are CORRECT and must not be
# softened into a `return false`:
#
#   core/modules/sapling/src/note_encryption.c — an `esk` repeat means the AEAD key is
#     about to be reused under the fixed zero nonce. Continuing leaks
#     plaintext; a crash does not.
#   contexts/wallet/modules/keys/src/key.c, contexts/wallet/modules/keys/src/pubkey.c — creation and teardown of the
#     process-wide secp256k1 signing/verification contexts, and a failure of
#     the entropy source feeding them. No external input reaches these, both
#     run exactly once, and a node that carried on would silently accept or
#     reject signatures.
#   core/modules/sapling/src/sapling.c — a fixed Jubjub generator that failed to
#     derive from hard-coded inputs. Every subsequent scalar multiplication
#     would produce garbage.
#
# Those are annotated in place rather than buried in the baseline, so the
# baseline stays a list of genuine debt that may only shrink, and nobody is
# ever pressured into "fixing" a correct abort to lower a number.
# The hatch requires a reason of at least 6 characters; `// abort-ok:` alone
# is not accepted.
#
# Scan set
# --------
# Named network-reachable roots only, not the whole tree. A whole-tree scan
# produces a baseline dominated by boot-only and tooling code, which dilutes
# the signal until nobody reads it. `core/` IS counted and frozen — it holds
# the consensus predicates and is byte-sealed, so forbidding new assertions
# there is exactly right even though the existing ones cannot be edited
# without the owner unseal ritual.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# --selftest plants each case into a sandbox and asserts the verdict, so a
# gate that has quietly stopped matching cannot report PASS. The
# `_Static_assert` case is a NEGATIVE control and is non-negotiable.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
. tools/lint/scan_exclusions.sh

GATE=check_no_runtime_abort
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_NO_RUNTIME_ABORT_BASELINE:-tools/lint/no_runtime_abort_baseline.txt}"

# Network-reachable roots. Every one of these is verified to exist at the
# time of writing; a root that disappears is skipped here and caught by the
# file floor below rather than silently shrinking the scan.
SCAN_ROOTS_DEFAULT="core/modules/crypto contexts/wallet/modules/keys core/modules/script core/modules/sapling core/modules/validation \
core/modules/net core/modules/sync contexts/wallet/modules/zid contexts/naming/modules/znam contexts/market/modules/zslp contexts/naming/modules/zdir engine/modules/storage core/modules/mining \
core/modules/core platform/modules/platform platform/modules/util engine/modules/rpc \
domain/encoding domain/wallet \
core/consensus core/math core/params core/chainparams"
read -r -a SCAN_ROOTS <<< "${ZCL_NO_RUNTIME_ABORT_SCAN_ROOTS:-$SCAN_ROOTS_DEFAULT}"

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/lib/probe/src"

    plant() { # $1 = body line(s) placed inside a function
        cat > "$tmp/lib/probe/src/selftest_probe.c" <<EOF
#include <assert.h>
#include <stdlib.h>
bool probe_check(int x)
{
$1
    return true;
}
EOF
    }

    # The gate cd's to the repo root, so the sandbox must be reached by an
    # ABSOLUTE scan root. A relative sandbox path is silently ignored and
    # every case then "passes" for the wrong reason.
    self="$PWD/tools/lint/$GATE.sh"
    : > "$tmp/empty_baseline.txt"

    run_sandbox() { # $1 = site floor override
        ZCL_NO_RUNTIME_ABORT_SCAN_ROOTS="$tmp/lib" \
        ZCL_NO_RUNTIME_ABORT_FILE_FLOOR=1 \
        ZCL_NO_RUNTIME_ABORT_SITE_FLOOR="${1:-0}" \
        ZCL_NO_RUNTIME_ABORT_BASELINE="$tmp/empty_baseline.txt" \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1
    }

    expect() { # $1 = pass|fail, $2 = message, $3 = planted body
        local want="$1" msg="$2" body="$3" rc=0
        plant "$body"
        run_sandbox || rc=$?
        if [ "$want" = "fail" ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
        if [ "$want" = "pass" ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg (rc=$rc)" >&2; exit 2
        fi
    }

    expect fail "a runtime assert() did not fail the gate" \
        '    assert(x > 0);'
    expect pass "a LOG_FAIL rejection was reported as an abort primitive" \
        '    if (x <= 0) LOG_FAIL("probe", "x out of range");'
    # NEGATIVE CONTROL. _Static_assert is compile-time and is the CORRECT
    # replacement for a runtime assertion; a gate that flags it makes the
    # codebase worse. Non-negotiable.
    expect pass "a _Static_assert was flagged — the prefix guard is broken" \
        '    _Static_assert(sizeof(int) == 4, "m");'
    expect pass "a C23 static_assert was flagged — the prefix guard is broken" \
        '    static_assert(sizeof(int) == 4, "m");'
    expect fail "a bare abort() did not fail the gate" \
        '    if (x < 0) abort();'
    expect pass "the // abort-ok escape hatch was not honoured" \
        '    if (x < 0) abort(); // abort-ok: entropy failure, keys would be forgeable'
    expect pass "the /* abort-ok */ escape hatch was not honoured" \
        '    if (x < 0) abort(); /* abort-ok: entropy failure, keys forgeable */'
    expect fail "an empty abort-ok reason was accepted" \
        '    if (x < 0) abort(); // abort-ok:'
    expect pass "a line comment mentioning assert() was counted" \
        '    /* we used to assert(x > 0) here; it is a return now. */'
    # THE case a naive per-line sub(/\/\*.*/) gets wrong: the word lands on a
    # block-comment CONTINUATION line that carries no comment opener at all.
    expect pass "a block-comment continuation mentioning assert() was counted" \
        '    /* Rationale:
     * the old assert(x > 0) let one hostile RPC argument abort the node,
     * and abort() on that path is a remote process kill.
     */'
    expect pass "a string literal containing assert( was counted" \
        '    const char *m = "assert(x) was removed";'
    # A scan that matches nothing must be LOUD, never a quiet PASS.
    plant '    return x > 0;'
    rc=0; run_sandbox 999 || rc=$?
    [ "$rc" -eq 2 ] || {
        echo "$GATE: SELFTEST FAILED — an empty scan did not abort on the site floor (rc=$rc)" >&2
        exit 2; }

    echo "[$GATE] SELFTEST PASS (runtime assert/abort and an empty hatch reason FAIL;"
    echo "        LOG_FAIL, _Static_assert, static_assert, both hatch forms, line and"
    echo "        block comments and string literals PASS; empty scan aborts loud)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
# Production source only: lib/test is excluded (fixtures assert on purpose),
# as are vendor, build and the shared transient-fixture glob (via
# scan_exclusions.sh, active under ZCL_LINT_PRODUCTION_SCAN=1) so a sibling
# gate's selftest fixture can never trip this gate mid-race.
collect_files() {
    local root
    for root in "${SCAN_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        find "$root" -type f \( -name '*.c' -o -name '*.h' \) \
            ! -path '*/test/*' \
            "${LINT_FIND_PRUNE_ARGS[@]}" \
            2>/dev/null
    done
}

mapfile -t scan_files < <(collect_files | sort)
gate_require_scanned "${#scan_files[@]}" "${ZCL_NO_RUNTIME_ABORT_FILE_FLOOR:-400}" "$GATE" \
    "no production .c/.h under: ${SCAN_ROOTS[*]}"

# ── Per-site scan ────────────────────────────────────────────────────────
# Emits one line per site:
#   SITE<TAB>path<TAB>lineno<TAB>text      — counted debt
#   HATCH<TAB>path<TAB>lineno<TAB>text     — annotated, not counted
scan_sites() {
    awk '
        # ── comment + string scrubbing ───────────────────────────────────
        # String literals go first, so a "//" or "/*" inside one cannot open
        # a phantom comment. Then a real left-to-right comment scan that
        # carries block state ACROSS lines — the continuation lines of a
        # multi-line rationale comment are the exact case a per-line
        # sub(/\/\*.*/, "") gets wrong, and this repo is full of them.
        function strip_strings(s) {
            gsub(/"([^"\\]|\\.)*"/, "\"\"", s)
            gsub(/'"'"'([^'"'"'\\]|\\.)*'"'"'/, "0", s)
            return s
        }
        function scrub(s,   out, a, b, la, lb) {
            out = ""
            while (length(s) > 0) {
                if (inblock) {
                    b = index(s, "*/")
                    if (b == 0) return out
                    s = substr(s, b + 2); inblock = 0; continue
                }
                la = index(s, "//")
                lb = index(s, "/*")
                if (la == 0 && lb == 0) return out s
                if (lb == 0 || (la > 0 && la < lb)) return out substr(s, 1, la - 1)
                out = out substr(s, 1, lb - 1) " "
                s = substr(s, lb + 2)
                inblock = 1
            }
            return out
        }
        # ── escape hatch ────────────────────────────────────────────────
        # "// abort-ok:<reason>" or "/* abort-ok:<reason> */", the marker
        # inside a comment, with a reason of at least 6 characters.
        function has_hatch(s,   p, c1, c2, co, r) {
            p = index(s, "abort-ok:")
            if (p == 0) return 0
            c1 = index(s, "//"); c2 = index(s, "/*")
            co = (c1 > 0 && c2 > 0) ? ((c1 < c2) ? c1 : c2) : ((c1 > 0) ? c1 : c2)
            if (co == 0 || co > p) return 0
            r = substr(s, p + 9)
            sub(/^[ \t]*/, "", r)
            sub(/[ \t]*\*\/[ \t]*$/, "", r)
            sub(/[ \t]+$/, "", r)
            return (length(r) >= 6)
        }
        function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }

        FNR == 1 { inblock = 0 }
        {
            line = scrub(strip_strings($0))
            # The prefix guard is load-bearing: it is the only thing that
            # separates a runtime assert() from _Static_assert/static_assert,
            # which are compile-time and GOOD.
            if (line ~ /(^|[^_[:alnum:]])(assert|abort)[ \t]*\(/) {
                printf "%s\t%s\t%d\t%s\n", \
                    (has_hatch($0) ? "HATCH" : "SITE"), FILENAME, FNR, trim($0)
            }
        }
    ' "${scan_files[@]}"
}

mapfile -t ROWS < <(scan_sites)
gate_require_scanned "${#ROWS[@]}" "${ZCL_NO_RUNTIME_ABORT_SITE_FLOOR:-15}" "$GATE" \
    "no assert(/abort( sites found at all — the scan or the matcher moved"

declare -A COUNTS=()
declare -A DETAIL=()
hatched=0
total_sites=0
for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r kind path lineno text <<< "$row"
    if [ "$kind" = "HATCH" ]; then
        hatched=$((hatched + 1))
        continue
    fi
    total_sites=$((total_sites + 1))
    COUNTS["$path"]=$(( ${COUNTS[$path]:-0} + 1 ))
    DETAIL["$path"]+="      $path:$lineno: $text"$'\n'
done

declare -A BASELINED=()
gate_load_kv_file "$BASELINE" BASELINED
baseline_count="${#BASELINED[@]}"

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# $GATE baseline — files in network-reachable code that still"
        echo "# hold RUNTIME assert()/abort() sites. assert() is LIVE in this"
        echo "# build (-DNDEBUG is set only for vendored LevelDB), so each of"
        echo "# these is a process kill on a failed assumption."
        echo "# Format: <path> <site-count>.  COUNTS MAY ONLY SHRINK."
        echo "#"
        echo "# Fix a row by returning an error instead: fail the call, log the"
        echo "# reason with LOG_FAIL/LOG_ERR, and let the caller reject the"
        echo "# input — then lower (or delete) the number here. Adding a row is"
        echo "# not a fix. An assertion about a layout or a constant becomes"
        echo "# _Static_assert, which this gate deliberately does not count."
        echo "#"
        echo "# An abort that is CORRECT (softening it would trade a crash for"
        echo "# a key compromise or a plaintext leak) does not belong here at"
        echo "# all — annotate it in place with // abort-ok:<reason>."
        echo "#"
        echo "# core/ is byte-sealed: its rows are counted and frozen, and are"
        echo "# only editable through the owner unseal ritual (make core-unseal)."
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        for path in "${!COUNTS[@]}"; do
            echo "$path ${COUNTS[$path]}"
        done | LC_ALL=C sort
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED: $BASELINE (${#COUNTS[@]} files, $total_sites sites, $hatched annotated)"
    exit 0
fi

violations=()
tolerated=0
for path in "${!COUNTS[@]}"; do
    n="${COUNTS[$path]}"
    allowed="${BASELINED[$path]:-}"
    if [ -z "$allowed" ]; then
        violations+=("$(lint_annotate_stray "$path") — $n runtime abort site(s), not in the baseline"$'\n'"${DETAIL[$path]%$'\n'}")
    elif [ "$n" -gt "$allowed" ]; then
        violations+=("$path — $n runtime abort site(s), baseline allows $allowed"$'\n'"${DETAIL[$path]%$'\n'}")
    else
        tolerated=$((tolerated + 1))
    fi
done

# A baseline row whose file has no sites left must be deleted; otherwise the
# ratchet rusts shut at a stale number and the next regression hides under it.
stale=()
for path in "${!BASELINED[@]}"; do
    [ -z "${COUNTS[$path]+x}" ] && stale+=("$path")
done

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} file(s) gained a runtime abort primitive on a"
    echo "        network-reachable path. assert() is LIVE in this build, so each"
    echo "        of these kills the process on a failed assumption:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  Reject the input instead of aborting on it:"
    echo "    return false / -1, log the reason with LOG_FAIL/LOG_ERR/LOG_NULL,"
    echo "    and let the caller report it. That is how every other rejection"
    echo "    in this tree behaves, and the node keeps running."
    echo "  An assertion about a LAYOUT or a CONSTANT becomes _Static_assert,"
    echo "  which this gate deliberately does not count."
    echo "  An abort that is CORRECT — where continuing would leak plaintext,"
    echo "  forge a key, or silently mis-verify a signature — is annotated in"
    echo "  place with:  // abort-ok:<reason>   (reason required, >= 6 chars)."
    echo "  Worked examples: core/modules/sapling/src/note_encryption.c (esk repeat),"
    echo "  contexts/wallet/modules/keys/src/pubkey.c (process-wide verify context lifecycle)."
    echo "  Raising a number in $BASELINE is NOT a fix; counts may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — the file has no runtime"
    echo "        abort sites left. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} files scanned, $total_sites runtime site(s) across ${#COUNTS[@]} file(s), $tolerated of $baseline_count baselined row(s) tolerated, $hatched annotated abort-ok)"
