#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_promotion_receipt_chain.sh — the promotion receipt ledger stays a
# chain: append-only, hash-linked, signed, replicated, and verifiable by
# someone who does not trust us.
#
# WHY THIS GATE EXISTS. Promotion evidence used to be one LOCAL, MUTABLE,
# UNSIGNED git tag (tools/scripts/proof_server_pin.sh). Tags are never pushed —
# origin holds only `main` — so the record died with the machine, and
# `git tag -d` erased it with no trace. platform/deploy/promotion-receipts.jsonl replaces
# it as the authority: tracked (so it replicates on every push), hash-chained
# (so an edited or removed record is detectable), and signed with
# `ssh-keygen -Y sign` (so authorship is checkable offline from the committed
# allowed-signers file, with no private key).
#
# Five things checked, each guarding one of those properties:
#
#   1. tools/scripts/promotion_receipt.sh --self-test passes. Hermetic: its own
#      throwaway git repo and its own throwaway signing key under /tmp. It
#      builds a chain and then tampers with it six ways — edit, delete,
#      re-order, corrupt a signature, RE-SIGN an edited record with a valid
#      key, and swap in an unlisted signer — asserting the EXACT first break
#      message for each. The re-signed case is the one that proves the hash
#      chain is load-bearing rather than decorative: per-record signatures
#      alone cannot catch it.
#   2. The in-tree ledger itself verifies, run with ZCL_RECEIPT_KEY pointed at
#      a path that does not exist. That is the offline-third-party contract:
#      verification must need the allowed-signers file and nothing else.
#   3. The allowed-signers file exists, and it names a key whenever the ledger
#      holds a record. Zero keys plus zero records is the SHIPPED state and is
#      fine: the evidence-signing identity is the owner's decision, not a
#      default. A record with no listed key would be unverifiable, which is an
#      assertion rather than evidence, so that combination fails.
#   4. APPEND-ONLY, enforced against git rather than a hand-maintained
#      baseline: whatever is committed at HEAD must still be a byte-exact
#      PREFIX of the working file. Rewriting or dropping a committed record
#      fails here even when the rewrite is internally consistent (re-chained
#      and re-signed), because git remembers the old bytes.
#   5. Anti-rot: tools/ship.sh's promotion path still CALLS
#      `promotion_receipt.sh append`. This is the literal shape of the original
#      defect — prose that described a recording nothing performed — so it is
#      grepped, never inferred.
#
# What this gate deliberately does NOT check: that any record exists. The
# ledger ships with ZERO records, not even genesis, because the chain's root of
# trust is the owner's decision — `init` is run once by the owner under a key
# they choose (docs/PROMOTION_RECEIPTS.md, "Owner setup"). And no receipt exists
# for the build currently on the proof server, because that build cannot be
# identified: `agentbuild` reports `"build_commit":"external"` and
# tools/dev/source-identity.sh hashes host-local, git-ignored inputs, so its
# source_id does not resolve backwards to a commit. Inventing one would be a
# fabricated evidence record. An empty ledger verifies clean, and both `verify`
# and `latest` say "NO PROMOTION RECORDED" — the honest answer, not a failure.

set -uo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=tools/lint/gate_lib.sh
source "$ROOT/tools/lint/gate_lib.sh"

TOOL=tools/scripts/promotion_receipt.sh
LEDGER=platform/deploy/promotion-receipts.jsonl
SIGNERS=platform/deploy/promotion-signers
SHIP=tools/ship.sh

fail=0

# 1. Hermetic self-test — the tamper-detection proof.
if [ ! -r "$TOOL" ]; then
    echo "FAIL: $TOOL is missing — the promotion receipt ledger has no writer or verifier"
    fail=1
else
    out=""
    rc=0
    out="$(bash "$TOOL" --self-test 2>&1)" || rc=$?
    # The verdict is the extracted PASS line, not a pipeline's exit status:
    # under pipefail a matching `printf | grep -q` can report printf's SIGPIPE
    # 141 instead of grep's 0, turning a genuine PASS into "no PASS line".
    # MEASURED 2026-07-30: a passing transcript is 33 bytes, so the inversion
    # is NOT reachable at this size — a shape fix, not a live-bug fix. Kept
    # because the transcript is unbounded on failure and nobody re-measures.
    # Regex unchanged; without -q grep drains stdin so printf completes.
    pass_line="$(printf '%s\n' "$out" | grep '^PROMOTION RECEIPT SELF-TEST: PASS$' || true)"
    if [ "$rc" != "0" ] || [ -z "$pass_line" ]; then
        echo "FAIL: $TOOL --self-test (rc=$rc; no 'PROMOTION RECEIPT SELF-TEST: PASS' line)"
        printf '%s\n' "$out"
        fail=1
    else
        echo "  ok: $TOOL --self-test (chain + signature tamper detection)"
    fi
fi

# 3. Trust anchor, COUPLED to the record count rather than demanded outright.
#    The repository ships with zero keys here on purpose: the evidence-signing
#    identity is the owner's decision (see the file's own header), and choosing
#    one on their behalf — by defaulting to a login key, as an earlier draft of
#    the writer did — is the defect. So:
#      zero records + zero keys -> fine, and the ledger says "unrecorded";
#      any record at all        -> a key MUST be listed, or that record is
#                                  unverifiable and therefore not evidence.
#    The anti-hollow floor is on the SCAN, not on the key count: the header
#    documentation guarantees the file has content, so reading zero lines from
#    it means the scan itself broke.
signer_keys=0
ledger_records=0
[ -r "$LEDGER" ] && ledger_records="$(grep -c . "$LEDGER" || true)"
if [ ! -r "$SIGNERS" ]; then
    echo "FAIL: $SIGNERS is missing — nothing could verify a receipt's authorship"
    fail=1
else
    signers_lines="$(grep -c . "$SIGNERS" || true)"
    gate_require_scanned "$signers_lines" 1 check-promotion-receipt-chain \
        "$SIGNERS read as empty; the scan producer broke (the file carries a documented header)"
    signer_keys="$(grep -cE '^[^#[:space:]]+[[:space:]]+(ssh|sk-ssh|ecdsa)[^[:space:]]*[[:space:]]+[A-Za-z0-9+/=]+' "$SIGNERS" || true)"
    if [ "$signer_keys" -eq 0 ] && [ "$ledger_records" -gt 0 ]; then
        echo "FAIL: $LEDGER holds $ledger_records record(s) but $SIGNERS lists no public key."
        echo "      Those records cannot be verified by anyone, which makes them assertions"
        echo "      rather than evidence. Add the signing identity that produced them."
        fail=1
    elif [ "$signer_keys" -eq 0 ]; then
        echo "  ok: $SIGNERS lists no key yet and $LEDGER holds no records — consistent, unrecorded"
        echo "      (the evidence-signing identity is an owner decision: docs/PROMOTION_RECEIPTS.md, \"Owner setup\")"
    else
        echo "  ok: $SIGNERS names $signer_keys signing identity/identities for $ledger_records record(s)"
    fi
fi

# 2. The real ledger verifies, WITHOUT a private key in reach.
if [ ! -e "$LEDGER" ]; then
    echo "FAIL: $LEDGER does not exist. The ledger file itself is the replication"
    echo "      story — it ships tracked and empty so a promotion has somewhere to land"
    echo "      that reaches origin. Recreate it (an empty file is the correct shipped"
    echo "      state) rather than letting the path disappear."
    fail=1
elif [ ! -r "$LEDGER" ]; then
    echo "FAIL: $LEDGER exists but is not readable"
    fail=1
else
    out=""
    rc=0
    out="$(ZCL_RECEIPT_KEY=/nonexistent/no-private-key-here bash "$TOOL" verify 2>&1)" || rc=$?
    if [ "$rc" != "0" ]; then
        echo "FAIL: $TOOL verify on the in-tree ledger (rc=$rc)"
        printf '%s\n' "$out"
        fail=1
    else
        echo "  ok: $LEDGER verifies with no private key present"
        printf '%s\n' "$out" | grep -E 'chain intact|NO PROMOTION RECORDED' | sed 's/^/      /'
    fi
fi

# 4. Append-only against git. Skipped (loudly, as a note) only when this
#    directory is not the toplevel of the repo git would answer for — the
#    lint sandbox runs gates inside a hardlink COPY with no .git of its own,
#    and check_doc_accuracy.sh documents the same trap.
top="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -n "$top" ] && [ "$top" -ef . ] 2>/dev/null && [ -r "$LEDGER" ]; then
    # `git show` returning empty is ambiguous — an empty blob and a missing
    # path look identical — and the shipped ledger IS an empty blob, so the
    # existence test has to be its own call.
    committed=""
    committed_lines=-1
    if git cat-file -e "HEAD:$LEDGER" 2>/dev/null; then
        committed="$(git show "HEAD:$LEDGER" 2>/dev/null || true)"
        committed_lines="$(printf '%s' "$committed" | grep -c . || true)"
    fi
    if [ "$committed_lines" -lt 0 ]; then
        echo "  note: $LEDGER is not in HEAD yet (first commit of the ledger) — append-only check starts next commit"
    elif [ "$committed_lines" -eq 0 ]; then
        echo "  ok: $LEDGER is append-only vs HEAD (HEAD holds no records — nothing can have been dropped)"
    elif [ "$(head -n "$committed_lines" "$LEDGER")" != "$committed" ]; then
        echo "FAIL: $LEDGER is not append-only — the $committed_lines record(s) committed at HEAD are no"
        echo "      longer a byte-exact prefix of the working file. A receipt ledger is evidence:"
        echo "      records are appended, never edited or removed. Restore the committed prefix"
        echo "      (git diff -- $LEDGER shows what moved) and append instead."
        fail=1
    else
        echo "  ok: $LEDGER is append-only vs HEAD ($committed_lines committed record(s) unchanged)"
    fi
    if ! git ls-files --error-unmatch "$LEDGER" >/dev/null 2>&1; then
        echo "FAIL: $LEDGER is not tracked by git. Tracking is the whole replication story —"
        echo "      an untracked ledger never reaches origin and dies with this machine,"
        echo "      which is exactly the defect the local proof-server/* tag had."
        fail=1
    fi
    if ! git ls-files --error-unmatch "$SIGNERS" >/dev/null 2>&1; then
        echo "FAIL: $SIGNERS is not tracked by git — a third party would receive a ledger with no trust anchor"
        fail=1
    fi
else
    echo "  note: not at a git toplevel here — append-only-vs-HEAD and tracked-file checks skipped"
fi

# 6. THE ROOT OF TRUST IS NEVER A DEFAULT — asserted from HERE, in a different
#    file from the message it checks, deliberately.
#
#    The writer's own self-test also asserts this refusal, and that was NOT
#    enough: a mutation test reworded the refusal text and the self-test still
#    passed, because the expected string and the emitted string live in the same
#    file and a single careless edit moves both. Two files that must agree is
#    what makes a rewording visible. (Measured, not theorised — this prong was
#    added after that mutation went green.)
#
#    Two independent shapes of the same rule:
#      6a. behavioural — with no ZCL_RECEIPT_KEY, `init` refuses with exactly
#          this line and creates nothing;
#      6b. textual — SIGN_KEY has no fallback value at all, which is the
#          specific regression shape (an earlier draft defaulted to the
#          operator's personal ~/.ssh/id_ed25519 push key).
WANT_NOKEY='promotion_receipt: refuse — no signing key configured; set ZCL_RECEIPT_KEY to a key whose only purpose is signing promotion evidence'
if [ -r "$TOOL" ]; then
    nokey_dir="$(mktemp -d "${TMPDIR:-/tmp}/zcl_receipt_gate.XXXXXX")"
    got_nokey="$(env -u ZCL_RECEIPT_KEY \
        "ZCL_RECEIPT_LEDGER=$nokey_dir/ledger.jsonl" \
        "ZCL_RECEIPT_SIGNERS=$SIGNERS" \
        bash "$TOOL" init 2>&1 >/dev/null | head -1)"
    if [ "$got_nokey" != "$WANT_NOKEY" ]; then
        echo "FAIL: $TOOL init with no ZCL_RECEIPT_KEY must refuse with an exact message."
        echo "      got:  $got_nokey"
        echo "      want: $WANT_NOKEY"
        echo "      The evidence-signing identity must be an explicit owner decision, never a"
        echo "      default. If you reworded the refusal on purpose, update BOTH this gate and"
        echo "      the writer's self-test — that two files must agree is the point."
        fail=1
    elif [ -e "$nokey_dir/ledger.jsonl" ]; then
        echo "FAIL: $TOOL init refused but still created a ledger at the target path"
        fail=1
    else
        echo "  ok: $TOOL refuses to write without an explicitly configured signing key"
    fi
    rm -rf "$nokey_dir"

    if gate_grep -qE '^[^#]*ZCL_RECEIPT_KEY:-[^}]' "$TOOL"; then
        echo "FAIL: $TOOL gives ZCL_RECEIPT_KEY a fallback value:"
        gate_grep -nE '^[^#]*ZCL_RECEIPT_KEY:-[^}]' "$TOOL" | sed 's/^/          /'
        echo "      There must be no default signing key. A login/push key as the evidence"
        echo "      authority means anyone who can push can mint receipts, and rotating it for"
        echo "      an ordinary git-access reason invalidates the chain."
        fail=1
    else
        echo "  ok: $TOOL declares no fallback signing key"
    fi
fi

# 5. Anti-rot: ship.sh still records a receipt on promotion.
if [ ! -r "$SHIP" ]; then
    echo "FAIL: $SHIP is missing"
    fail=1
elif ! grep -qE 'promotion_receipt\.sh[[:space:]]+append\b' "$SHIP"; then
    echo "FAIL: $SHIP no longer calls 'promotion_receipt.sh append' — a promotion would"
    echo "      again leave nothing behind that survives this machine. Wire the call back"
    echo "      in after the remote health check confirms the running daemon reports the"
    echo "      candidate's source id, next to the proof_server_pin.sh record call."
    fail=1
else
    echo "  ok: $SHIP calls 'promotion_receipt.sh append'"
fi

if [ "$fail" != 0 ]; then
    exit 1
fi
echo "check_promotion_receipt_chain: clean — chain verifies, tamper detection proven, append-only vs HEAD, and ship.sh still records"
