#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — OFFLINE-ONLY FENCE for the FAST-MINT crypto pass-through.
#
# WHY
# ---
# jobs/mint_skip_crypto.h adds a process-global toggle that, when ON, makes
# script_validate skip its per-input ECDSA verify_script loop and proof_validate
# skip its Groth16/Ed25519/PHGR13/binding-sig verification. That is SOUND only
# for PRODUCING the one anchor snapshot, whose correctness is certified by the
# terminal SHA3==checkpoint hard-assert (engine/composition/src/boot_mint_anchor.c). It must
# NEVER be reachable on a running node: if the SETTER (mint_skip_crypto_set)
# were ever called outside the offline -mint-anchor mint driver — e.g. from a
# P2P/RPC/relay/connect_block path — a signature bypass on a live node would
# open. This gate freezes the invariant: the SETTER is referenced ONLY from the
# mint driver TUs.
#
# WHAT IS SCANNED (non-empty by construction — the gate FAILS LOUD if the scan
# set is empty, the MEMORY "fail-silent lint gate" trap)
# -----------------------------------------------------------------------------
#   - Every .c under app/, config/, src/, tools/, domain/, engine/application/,
#     platform/adapters/, plus the module .c itself, comments stripped.
#   - Any line that CALLS the setter `mint_skip_crypto_set(` is a hit UNLESS it
#     is in one of the ALLOWED files (the mint driver + the module + its test).
#   - The READER (mint_skip_crypto_get) may be called from the two crypto
#     stages and is NOT fenced — reading the toggle changes no behavior when it
#     is OFF (the default).
#
# ALLOWED setter call sites (the offline mint driver TUs + the module + test):
#   engine/composition/src/boot_refold_staged.c   boot_mint_anchor_reset (gated on -mint-anchor)
#   engine/composition/src/boot_mint_anchor.c     the one-shot mint driver
#   engine/jobs/src/mint_skip_crypto.c   the module definition
#   tests/harness/src/test_mint_skip_crypto.c  the equivalence test
#
# Exit 0 = pass; non-zero + message = fail. PASSES on the current tree by
# construction; FAILS the instant the setter is called from any other TU.
set -euo pipefail

# Repo root: argv[1], or the dir this script is wired into, or git toplevel.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "${1:-}" != "" ] && [ -d "$1/app" ]; then
    ROOT="$1"
elif [ -d "$SCRIPT_DIR/../../app" ]; then
    ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
    ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi
cd "$ROOT" || { echo "check_mint_skip_crypto_offline_only: bad root '$ROOT'" >&2; exit 2; }
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

SETTER='mint_skip_crypto_set'

# The ONLY files allowed to call the setter.
ALLOW=(
    "engine/composition/src/boot_refold_staged.c"
    "engine/composition/src/boot_mint_anchor.c"
    "engine/jobs/src/mint_skip_crypto.c"
    "tests/harness/src/test_mint_skip_crypto.c"
)

is_allowed() {
    local f="$1"
    local a
    for a in "${ALLOW[@]}"; do
        [ "$f" = "$a" ] && return 0
    done
    return 1
}

# Build the scan set: every .c in the code trees. FAIL LOUD if empty.
mapfile -t SCAN < <(find app config src tools domain application adapters \
                        -name '*.c' -type f "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)
if [ "${#SCAN[@]}" -eq 0 ]; then
    echo "check_mint_skip_crypto_offline_only: FAIL — empty scan set (no .c found)" >&2
    echo "  This gate must scan a non-empty set; refusing to pass silently." >&2
    exit 1
fi

# Confirm the module + the allowed driver TU actually exist and the setter is
# defined/declared — a rename must break the gate, not silently pass.
if [ ! -f "engine/jobs/src/mint_skip_crypto.c" ]; then
    echo "check_mint_skip_crypto_offline_only: FAIL — module engine/jobs/src/mint_skip_crypto.c missing" >&2
    exit 1
fi
if ! grep -q "${SETTER}" "engine/jobs/src/mint_skip_crypto.c"; then
    echo "check_mint_skip_crypto_offline_only: FAIL — ${SETTER} not defined in the module" >&2
    echo "  The setter was renamed; update this gate deliberately." >&2
    exit 1
fi
# The mint driver TU must actually CALL the setter — proves the fence has teeth
# (a non-empty allowed reference exists), not just an empty allowlist.
if ! grep -q "${SETTER}(" "engine/composition/src/boot_refold_staged.c"; then
    echo "check_mint_skip_crypto_offline_only: FAIL — the mint driver" >&2
    echo "  engine/composition/src/boot_refold_staged.c no longer calls ${SETTER}(. Either the" >&2
    echo "  wiring regressed or it moved — update this gate deliberately." >&2
    exit 1
fi

# Dependency-free comment strip (awk block-comment state machine + sed line).
strip_comments() {
    awk '
    {
        line=$0; out=""
        while (length(line) > 0) {
            if (inblk) {
                p=index(line, "*/")
                if (p == 0) { line=""; break }
                line=substr(line, p+2); inblk=0
            } else {
                p=index(line, "/*")
                if (p == 0) { out=out line; line="" }
                else { out=out substr(line, 1, p-1); line=substr(line, p+2); inblk=1 }
            }
        }
        print out
    }' | sed 's://.*$::'
}

fail=0
hits=""
for f in "${SCAN[@]}"; do
    is_allowed "$f" && continue
    # Match a CALL to the setter: "mint_skip_crypto_set(" after comment strip.
    fhits="$(strip_comments < "$f" | grep -nE "${SETTER}[[:space:]]*\(" || true)"
    if [ -n "$fhits" ]; then
        fail=1
        while IFS= read -r h; do
            [ -z "$h" ] && continue
            hits="${hits}  ${f}: ${h}"$'\n'
        done <<< "$fhits"
    fi
done

if [ "$fail" = "0" ]; then
    echo "check_mint_skip_crypto_offline_only: OK — ${SETTER} called only from the offline mint driver TUs (scanned ${#SCAN[@]} files)"
    exit 0
fi

echo ""
echo "check_mint_skip_crypto_offline_only: FAIL — OFFLINE-ONLY FENCE violated"
echo ""
echo "${SETTER}() was called outside the offline -mint-anchor mint driver. The"
echo "crypto pass-through is SOUND only for PRODUCING the fingerprint-certified"
echo "anchor snapshot offline; arming it anywhere a running node can reach it is a"
echo "signature/proof bypass on the live chain."
echo ""
echo "Offending call site(s):"
printf '%s' "$hits"
echo ""
echo "FIX: only the offline mint driver may call ${SETTER}. Allowed TUs:"
for a in "${ALLOW[@]}"; do echo "  - $a"; done
echo "If you genuinely added a new mint-driver TU, add it to ALLOW in this gate"
echo "deliberately AND keep it gated under ctx->mint_anchor — never relax the fence."
exit 1
