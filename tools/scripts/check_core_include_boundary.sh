#!/usr/bin/env bash
# Lint gate — sealed consensus-core include boundary (Wave 1.1 / W0).
#
# The sealed core (top-level core/) holds ONLY "what makes a block/tx valid":
# pure predicates + static height-keyed parameter tables + consensus math. It
# is the innermost layer of the layered build and must NOT depend upward or
# sideways on the orchestration surface (drive/persist/fetch/reorg). In
# particular it must not include from core/modules/validation — validation SEQUENCES
# consensus, it is not consensus, and letting core reach into it would recreate
# the very coupling the physical split exists to break.
#
# This gate is a parameterized clone of check_domain_purity.sh, scanning the
# core/ subdirs instead of domain/. A core/ file may ONLY #include:
#
#   (1) its own headers, reached through preserved include tokens —
#         "domain/consensus/<x>.h"  (core/consensus keeps this token)
#         "consensus/<x>.h"         (core/params keeps this token)
#         "core/<x>.h"              (core/math, absorbed from core/modules/core in W3)
#         "chainparams/<x>.h"       (core/chainparams, later wave)
#   (2) C / POSIX system headers  — #include <...>
#   (3) bare domain-local siblings — a quoted include with NO slash
#       (e.g. "reject_out.h", "oversize_grandfather_table.inc")
#   (4) a fixed allow set of leaf lib subsystems that consensus math legitimately
#       depends DOWN on (crypto/keys/primitives/script/... — pure leaves), but
#       NOT validation (forbidden — the whole point of the seal).
#
# FORBIDDEN (no baseline): any quoted slash-include whose top-level prefix is
# not in the allow set — this catches "validation/...", "app/...", any
# controllers/models/services/views leak, and any unlisted lib subsystem.
#
# EXCEPTION-FREE (Pre-W5 content fix landed): there are no grandfathered
# exceptions. The two former leaks were both redirected downward —
# check_block.c calls the core sigops predicate instead of validation/sigops.h,
# and chainparams.h gets MESSAGE_START_SIZE from chain/chainparamsbase.h instead
# of net/protocol.h. Any forbidden include now fails HARD.
#
# W0 posture: core/ is near-empty (only MANIFEST.sha3 + UNSEAL.md). The gate is
# GREEN when a listed subdir is absent (nothing to scan yet — TODO ratchet: it
# begins enforcing as each move wave lands the subdir). It fails LOUD only if a
# listed subdir EXISTS but cannot be read.
#
# Per-line override (deliberate, reviewed): add `// core-boundary-ok:<tag>`
# after the include directive. Every override is a debt marker — use sparingly.
set -euo pipefail

cd "$(dirname "$0")/../.."

# The core/ subdirs this gate governs (populated across move waves W1–W4).
CORE_SUBDIRS=(core/consensus core/params core/chainparams core/math)

# Allow set: include-token top-level prefixes a sealed-core file may depend on.
# Mirrors check_domain_purity.sh's 12 lib subsystems MINUS `validation`
# (forbidden), PLUS `domain`, `chainparams`, and `math` (preserved core tokens),
# PLUS `encoding` and `json` — the pure leaf libs the absorbed core/modules/core math
# primitives depend DOWN on (uint256/core_io use encoding/utilstrencodings +
# encoding/utilmoneystr for hex/money string conversion and json/json for
# core_io serialization; both leaves themselves reach only core/encoding/util/
# json, never validation or app — verified in W3),
# PLUS `platform` — the clock/rng leaf (platform/modules/platform reaches only platform/util);
# core/chainparams/checkpoints.c reads a single clock via platform/time_compat.h
# (verified pure leaf in W4).
# core/math keeps the `core` token (absorbed from core/modules/core in W3); core/params keeps `consensus`.
declare -A allow
for p in domain consensus core chainparams math \
         bloom chain coins crypto encoding json keys platform primitives script support util; do
    allow["$p"]=1
done

# Known ratchet exception: (path, included-header) pairs grandfathered pre-W5.
# Redirected by the Pre-W5 content-fix commit, not this lane.
declare -A known_exception
# EXCEPTION-FREE (Pre-W5 content fix landed): the two grandfathered leaks are
# both resolved — core/consensus/src/check_block.c now calls the core sigops
# predicate domain_consensus_tx_legacy_sig_op_count instead of including
# validation/sigops.h, and core/chainparams/include/chain/chainparams.h gets
# MESSAGE_START_SIZE from the co-located chain/chainparamsbase.h instead of
# net/protocol.h. The map is intentionally empty; any new leak fails HARD.

fail=0
violations=()
warn_notes=()
scanned_any=0

for d in "${CORE_SUBDIRS[@]}"; do
    if [ ! -e "$d" ]; then
        # Absent at this wave — nothing to seal yet. (TODO ratchet: enforced
        # once the move wave lands this subdir.)
        continue
    fi
    if [ ! -r "$d" ]; then
        echo "check_core_include_boundary: FATAL — '$d' exists but is unreadable." >&2
        exit 2
    fi
    scanned_any=1

    while IFS= read -r f; do
        while IFS= read -r match; do
            lineno="${match%%:*}"
            line_content="${match#*:}"

            # Per-line override marker: skip immediately.
            if echo "$line_content" | grep -qE '//[[:space:]]*core-boundary-ok:[A-Za-z][A-Za-z0-9_-]*'; then
                continue
            fi

            hdr=$(echo "$line_content" | sed -E 's@^[^"]*"@@; s@".*$@@')
            prefix="${hdr%%/*}"

            # Known grandfathered exception → WARN note, not a failure.
            if [ -n "${known_exception["$f|$hdr"]+x}" ]; then
                warn_notes+=("$f:$lineno known ratchet exception: includes $hdr (Pre-W5 content fix)")
                continue
            fi

            if [ -n "${allow[$prefix]+x}" ]; then
                continue
            fi

            violations+=("$f:$lineno core may not include $hdr")
            fail=1
        done < <(grep -nE '^[[:space:]]*#include[[:space:]]+"[^"]+/' "$f" || true)
    done < <(find "$d" -type f \( -name '*.c' -o -name '*.h' -o -name '*.inc' \) ! -path '*/test/*')
done

# Emit WARN ratchet notes (non-fatal) so the grandfathered leak stays visible.
if [ "${#warn_notes[@]}" -gt 0 ]; then
    for w in "${warn_notes[@]}"; do
        echo "WARN (ratchet): $w"
    done
fi

if [ "$fail" = "0" ]; then
    if [ "$scanned_any" = "0" ]; then
        echo "check_core_include_boundary: clean — no core/ subdirs present yet (W0 posture)"
    else
        echo "check_core_include_boundary: clean — sealed core has no forbidden includes"
    fi
    exit 0
fi

echo ""
echo "check_core_include_boundary: ${#violations[@]} forbidden include(s) in core/"
echo ""
for v in "${violations[@]}"; do
    echo "FAIL: $v"
done
echo ""
echo "The sealed core (core/) is the innermost consensus layer. It may only"
echo "include its own headers, C/system headers, bare siblings, and pure leaf"
echo "lib subsystems — NEVER core/modules/validation (validation drives consensus, it is"
echo "not consensus) or any app/ shape."
echo ""
echo "Fix options (HARD gate — no baseline):"
echo "  1. Delete the include if it's unused."
echo "  2. Move the needed predicate/constant DOWN into core/ or a pure leaf lib."
echo "  3. Invert the dependency: make the orchestration layer call core, not the"
echo "     other way around."
echo "  4. As a deliberate, reviewed exception only, add '// core-boundary-ok:<tag>'."
exit 1
