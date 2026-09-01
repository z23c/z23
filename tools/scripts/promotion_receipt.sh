#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# promotion_receipt.sh — the append-only, hash-chained, signed receipt ledger
# for proof-server promotions.
#
# WHY THIS EXISTS. tools/scripts/proof_server_pin.sh records a promotion as a
# LOCAL ANNOTATED GIT TAG. That was the right shape for "self-recording at the
# moment ship.sh holds the binding," and the wrong shape for evidence:
#
#   - it never leaves this machine — origin holds only `main`, tags are not
#     pushed, so a disk failure or a fresh clone erases the whole record;
#   - it is mutable with no trace — `git tag -d` / `git tag -f` rewrites
#     history silently, and nothing downstream can tell a deleted pin from a
#     promotion that never happened;
#   - it is unsigned — nothing ties a record to an author, so a third party
#     has to trust whoever hands them the repository.
#
# This ledger fixes all three, and it is the AUTHORITY. The tag stays as a
# convenience index for `git log --decorate`; it proves nothing on its own.
#
#   1. APPEND-ONLY + HASH-CHAINED. Every record carries prev_hash — the
#      SHA-256 of the previous record's exact bytes, signature included.
#      Editing, deleting, inserting, or re-ordering any past record breaks the
#      chain at a nameable line. The chain starts at a genesis record which
#      asserts NOTHING about any build, minted once by `init`.
#   2. SIGNED. Every record is signed with `ssh-keygen -Y sign` under the
#      namespace $SIG_NAMESPACE. Verification needs only the committed
#      allowed-signers file — never a private key — so a third party can check
#      authorship offline with stock OpenSSH and no cooperation from the
#      author. No new dependency: this repository already runs ssh/scp for
#      every fleet operation. THE SIGNING IDENTITY IS AN EXPLICIT DECISION:
#      there is no default key, and the write paths refuse until
#      ZCL_RECEIPT_KEY names one (see the SIGN_KEY comment below for the
#      defect that rule exists to prevent).
#   3. REPLICATED. The ledger is a TRACKED file. It reaches GitHub with every
#      push of `main`, which is exactly the property a local tag cannot have.
#   4. VERIFIABLE + GATED. `verify` walks the whole chain, checks every link
#      hash and every signature, and names the FIRST break precisely. The lint
#      gate check-promotion-receipt-chain runs it on the in-tree ledger plus a
#      hermetic self-test that proves tampering is detected.
#
# What is NOT in here, deliberately: any receipt for the build currently
# running on the proof server. Its commit is unknown — `agentbuild` answers
# `"build_commit":"external"` and tools/dev/source-identity.sh hashes
# host-local, git-ignored build inputs, so the running source_id does not
# resolve backwards to a revision. There is strong circumstantial evidence and
# that is not proof. A guessed receipt would be a FABRICATED evidence record,
# strictly worse than no record. The honest state is "no promotion recorded,"
# `latest` says exactly that, and it is not an error.
#
# THE LEDGER SHIPS WITH ZERO RECORDS. Not even genesis: the chain's root of
# trust is the owner's decision, so `init` is run once by the owner under a key
# the owner chose, and committed. Until then `verify` reports 0 records as CLEAN
# and prints "NO PROMOTION RECORDED" — which is the truth, and is not an error.
#
# Modes:
#   init
#       Mint the single genesis record. Refuses if the ledger already has
#       records. Requires ZCL_RECEIPT_KEY. Signed like any other record.
#
#   append <commit-sha> <source_id> <artifact_sha256> <host>
#       Sign and append one promotion receipt. Validates every argument,
#       re-verifies the freshly written record's own signature and the whole
#       chain before it is allowed to stand, and never rewrites an existing
#       line. Called by tools/ship.sh right after the running daemon proves it
#       reports the candidate's source id.
#
#   verify [ledger]
#       Walk the chain from genesis. Exit 0 = intact (including the zero-record
#       and genesis-only cases), 1 = broken (first break reported), 2 = the
#       ledger exists but cannot be read. Needs no private key.
#
#   latest
#       Print the newest PROMOTION receipt. Exit 2 with an honest "no
#       promotion recorded" when the ledger carries none.
#
#   --self-test
#       Hermetic. Builds a throwaway git repo and its own throwaway signing
#       key under ${TMPDIR:-/tmp}, appends a chain, then tampers with it six
#       ways and asserts verify catches each with an exact message. Touches no
#       network, no proof server, never this repository's own ledger, and never
#       the operator's own keys.
#
# Environment (paths default to the in-repo files; the self-test overrides them):
#   ZCL_RECEIPT_LEDGER       ledger path      (default platform/deploy/promotion-receipts.jsonl)
#   ZCL_RECEIPT_SIGNERS      allowed-signers  (default platform/deploy/promotion-signers)
#   ZCL_RECEIPT_KEY          private key used to SIGN. NO DEFAULT — init/append
#                            refuse without it, on purpose. Never point this at
#                            a login/push key.
#   ZCL_RECEIPT_RECORDED_BY  who ran it (default: the ledger repo's branch)
set -uo pipefail
export LC_ALL=C

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pipeline-free substring predicates. REQUIRED, not optional: `printf | grep -q`
# under the `set -o pipefail` above reports a successful match as 141, so a
# decision written that way can silently invert. See tools/scripts/sh_str.sh.
# shellcheck source=tools/scripts/sh_str.sh
. "$SELF_DIR/sh_str.sh" || { echo "promotion_receipt: cannot source sh_str.sh" >&2; exit 2; }
ROOT="$(cd "$SELF_DIR/../.." && pwd)"

SCHEMA='zcl.promotion_receipt.v1'
SIG_NAMESPACE='zcl-promotion-receipt'
ZERO_HASH='0000000000000000000000000000000000000000000000000000000000000000'

LEDGER="${ZCL_RECEIPT_LEDGER:-$ROOT/platform/deploy/promotion-receipts.jsonl}"
SIGNERS="${ZCL_RECEIPT_SIGNERS:-$ROOT/platform/deploy/promotion-signers}"

# NO DEFAULT SIGNING KEY, deliberately. An earlier draft of this script
# defaulted to $HOME/.ssh/id_ed25519 — the operator's personal SSH
# AUTHENTICATION key, the one `git push` and `gh` use. That is wrong twice
# over. It conflates two authorities: anyone who can push could then mint
# evidence, and rotating the key for an ordinary git-access reason would
# silently invalidate the whole evidence chain. And it made the root of trust
# a DEFAULT rather than a decision — the first run picked an identity nobody
# had chosen. So the write paths refuse until ZCL_RECEIPT_KEY names a key
# whose only job is signing promotion evidence. Verification never reads a
# private key at all, so `verify` is unaffected by this being empty.
SIGN_KEY="${ZCL_RECEIPT_KEY:-}"

# Token charset for the free-ish string fields (host, recorded_by, signer).
# It excludes `"`, `,` and backslash on purpose: that is what makes the
# payload-vs-signature split below a pure suffix strip with no JSON parser,
# and what stops a crafted host string from forging a second sig_b64 field.
TOKEN_RE='^[A-Za-z0-9][A-Za-z0-9._@:+/-]*$'
HEX40_RE='^[0-9a-f]{40}$'
HEX64_RE='^[0-9a-f]{64}$'
UTC_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'

# The one strict shape a record line must have. Fixed key order, so the bytes
# a signature covers are reproducible without canonicalising JSON.
LINE_RE='^\{"schema":"zcl\.promotion_receipt\.v1","seq":[0-9]+,"prev_hash":"[0-9a-f]{64}","kind":"(genesis|promotion)","host":"([A-Za-z0-9][A-Za-z0-9._@:+/-]*)?","commit":"([0-9a-f]{40})?","source_id_sha256":"([0-9a-f]{64})?","artifact_sha256":"([0-9a-f]{64})?","recorded_utc":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z","recorded_by":"[A-Za-z0-9][A-Za-z0-9._@:+/-]*","signer":"[A-Za-z0-9][A-Za-z0-9._@:+/-]*","sig_b64":"[A-Za-z0-9+/=]+"\}$'

err() { printf 'promotion_receipt: %s\n' "$*" >&2; }

# ── primitives ───────────────────────────────────────────────────────────
line_sha256() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

# jfield <line> <key> — value of a fixed-order, quote-free field. Anchored on
# the FIRST occurrence of the key (same discipline as
# tools/scripts/source_identity_lib.sh: a greedy match once produced a false
# "identical identities" report in this repo).
jfield() {
    local v
    v="$(printf '%s' "$1" | grep -oE "\"$2\":(\"[^\"]*\"|[0-9]+)" | head -1)"
    v="${v#*:}"
    v="${v%\"}"
    v="${v#\"}"
    printf '%s' "$v"
}

# payload_of <line> — the exact bytes the signature covers: the record with
# its own sig_b64 field removed, still a well-formed JSON object.
payload_of() {
    local p="${1%%,\"sig_b64\":\"*}"
    printf '%s}' "$p"
}

# armor_sig <one-line base64> <out-file> — rebuild the sshsig PEM wrapper.
# OpenSSH does not care how the base64 body is wrapped, so the ledger stores
# it unwrapped: no newline escaping, and the line stays greppable.
armor_sig() {
    {
        printf -- '-----BEGIN SSH SIGNATURE-----\n'
        printf '%s\n' "$1"
        printf -- '-----END SSH SIGNATURE-----\n'
    } > "$2"
}

# signer_principal_for_key <privkey> — the allowed-signers principal that owns
# this key. Derived, never configured: sign-time and verify-time therefore
# cannot disagree about who the author is.
signer_principal_for_key() {
    local key="$1" pub=""
    pub="$(ssh-keygen -y -f "$key" 2>/dev/null | cut -d' ' -f1-2)"
    [ -n "$pub" ] || return 1
    local ktype="${pub%% *}" kblob="${pub##* }"
    local principal=""
    while IFS= read -r sline; do
        case "$sline" in ''|'#'*) continue ;; esac
        # <principal> <keytype> <base64>
        set -- $sline
        [ "$#" -ge 3 ] || continue
        if [ "$2" = "$ktype" ] && [ "$3" = "$kblob" ]; then
            principal="$1"
            break
        fi
    done < "$SIGNERS"
    [ -n "$principal" ] || return 1
    printf '%s' "$principal"
}

# signer_listed <principal> — exit 0 iff the allowed-signers file names this
# principal in its first field. A field-exact loop, not `grep "^$signer"`: a
# principal legitimately contains `.` `+` `@`, which are ERE metacharacters, so
# a grep form would be a sloppy pattern match rather than an identity check.
signer_listed() {
    local want="$1" sline
    while IFS= read -r sline; do
        case "$sline" in ''|'#'*) continue ;; esac
        set -- $sline
        [ "$#" -ge 1 ] || continue
        [ "$1" = "$want" ] && return 0
    done < "$SIGNERS"
    return 1
}

# verify_one <payload> <sig_b64> <signer> — exit 0 iff the signature is good.
# Uses only the allowed-signers file; no private key is read or needed.
verify_one() {
    local payload="$1" sig_b64="$2" signer="$3"
    local tmpd
    tmpd="$(mktemp -d "${TMPDIR:-/tmp}/zcl_receipt_v.XXXXXX")" || return 1
    printf '%s' "$payload" > "$tmpd/payload"
    armor_sig "$sig_b64" "$tmpd/payload.sig"
    local rc=0
    ssh-keygen -Y verify -f "$SIGNERS" -I "$signer" -n "$SIG_NAMESPACE" \
        -s "$tmpd/payload.sig" < "$tmpd/payload" >/dev/null 2>&1 || rc=$?
    rm -rf "$tmpd"
    return "$rc"
}

# ── verify ───────────────────────────────────────────────────────────────
# Walks the chain and stops at the FIRST break. Check order is
# shape -> genesis-invariants -> seq -> prev_hash -> signature, cheapest and
# most specific first, so the reported break is the closest cause.
#
# Each failure's FIRST stderr line is fixed text (no hashes) so a caller can
# assert it exactly; the numbers go on the following lines. That matters: a
# self-test that only asserts "exit non-zero" passes for the wrong reason, and
# this repository has already shipped one that did.
cmd_verify() {
    local ledger="${1:-$LEDGER}"

    # ZERO RECORDS IS A CLEAN STATE, NOT A FAILURE. The ledger ships with no
    # records at all: the chain's genesis is minted by the owner under a key
    # the owner chose (see "Owner setup" in docs/PROMOTION_RECEIPTS.md), and
    # until then the only truthful thing to say is that nothing has been
    # recorded. An empty chain has nothing to contradict, so it verifies.
    #
    # Detecting a ledger that was DELETED is not this function's job and cannot
    # be — an absent file and a never-created file are the same bytes. That is
    # the lint gate's job: check-promotion-receipt-chain requires the file to
    # exist, to be tracked by git, and to keep HEAD's records as a byte-exact
    # prefix.
    if [ ! -e "$ledger" ] || [ ! -s "$ledger" ]; then
        if [ -e "$ledger" ] && [ ! -r "$ledger" ]; then
            err "cannot read ledger $ledger"
            return 2
        fi
        echo "promotion_receipt: chain intact — 0 record(s), 0 promotion(s); nothing to verify yet"
        echo "  ledger          $ledger"
        echo "promotion_receipt: NO PROMOTION RECORDED — the ledger holds no records at all."
        echo "  The chain has not been started: its genesis record is minted once, by the"
        echo "  owner, under a signing key the owner chooses (docs/PROMOTION_RECEIPTS.md,"
        echo "  \"Owner setup\"). Nothing has been promoted to a proof server through this"
        echo "  path, so no build on any proof server can be tied to a reviewed commit."
        echo "  That is this repository's honest state, not a defect and not a failure."
        return 0
    fi
    if [ ! -r "$ledger" ]; then
        err "cannot read ledger $ledger"
        return 2
    fi

    local lineno=0 expect_seq=0 expect_prev="$ZERO_HASH" promotions=0
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))

        if [ -z "$line" ]; then
            err "BREAK at line $lineno — blank line (the ledger is one record per line, no blanks)"
            return 1
        fi
        if ! printf '%s' "$line" | grep -qE "$LINE_RE"; then
            err "BREAK at line $lineno — record does not match the $SCHEMA line shape"
            printf '  record: %s\n' "$line" >&2
            return 1
        fi

        local seq kind host commit srcid artsha rec_by signer prev sig
        seq="$(jfield "$line" seq)"
        kind="$(jfield "$line" kind)"
        host="$(jfield "$line" host)"
        commit="$(jfield "$line" commit)"
        srcid="$(jfield "$line" source_id_sha256)"
        artsha="$(jfield "$line" artifact_sha256)"
        rec_by="$(jfield "$line" recorded_by)"
        signer="$(jfield "$line" signer)"
        prev="$(jfield "$line" prev_hash)"
        sig="$(jfield "$line" sig_b64)"

        if [ "$lineno" -eq 1 ] && [ "$kind" != "genesis" ]; then
            err "BREAK at line 1 — the first record must be kind=genesis"
            return 1
        fi
        if [ "$lineno" -gt 1 ] && [ "$kind" = "genesis" ]; then
            err "BREAK at line $lineno — a second genesis record cannot exist in one chain"
            return 1
        fi
        case "$kind" in
            genesis)
                if [ -n "$host$commit$srcid$artsha" ]; then
                    err "BREAK at line $lineno — a genesis record must leave host/commit/source_id_sha256/artifact_sha256 empty (it asserts nothing about any build)"
                    return 1
                fi
                ;;
            promotion)
                if [ -z "$host" ] || [ -z "$commit" ] || [ -z "$srcid" ] || [ -z "$artsha" ]; then
                    err "BREAK at line $lineno — a promotion record must carry host, commit, source_id_sha256 and artifact_sha256"
                    return 1
                fi
                promotions=$((promotions + 1))
                ;;
        esac

        if [ "$seq" != "$expect_seq" ]; then
            err "BREAK at line $lineno — seq is out of sequence (a record was deleted, inserted, or re-ordered)"
            printf '  seq in record   %s\n' "$seq" >&2
            printf '  expected        %s\n' "$expect_seq" >&2
            return 1
        fi

        if [ "$prev" != "$expect_prev" ]; then
            err "BREAK at line $lineno — prev_hash does not match the sha256 of the preceding record (it was edited, deleted, or re-ordered)"
            printf '  prev_hash in record  %s\n' "$prev" >&2
            printf '  sha256 of line %-6s%s\n' "$((lineno - 1))" "$expect_prev" >&2
            return 1
        fi

        if [ ! -r "$SIGNERS" ]; then
            err "BREAK at line $lineno — the allowed-signers file is missing, so no signature can be checked"
            printf '  allowed-signers %s\n' "$SIGNERS" >&2
            return 1
        fi
        if ! signer_listed "$signer"; then
            err "BREAK at line $lineno — signer is not listed in the allowed-signers file"
            printf '  signer          %s\n' "$signer" >&2
            printf '  allowed-signers %s\n' "$SIGNERS" >&2
            return 1
        fi
        if ! verify_one "$(payload_of "$line")" "$sig" "$signer"; then
            err "BREAK at line $lineno — signature does not verify (record content edited, or signature corrupted)"
            printf '  signer          %s\n' "$signer" >&2
            printf '  recorded_by     %s\n' "$rec_by" >&2
            return 1
        fi

        expect_prev="$(line_sha256 "$line")"
        expect_seq=$((expect_seq + 1))
    done < "$ledger"

    echo "promotion_receipt: chain intact — $lineno record(s), $promotions promotion(s); every link hash and every signature verified"
    echo "  ledger          $ledger"
    echo "  head sha256     $expect_prev"
    if [ "$promotions" -eq 0 ]; then
        echo "promotion_receipt: NO PROMOTION RECORDED — the chain is genuine and holds no promotion receipt."
        echo "  Nothing has been promoted to a proof server through this path, so no"
        echo "  build on any proof server can be tied to a reviewed commit. That is"
        echo "  this repository's honest state, not a defect and not a failure."
    fi
    return 0
}

# ── latest ───────────────────────────────────────────────────────────────
cmd_latest() {
    # A receipt read out of an unverified ledger is not evidence, so the chain
    # is walked first and a break is reported instead of a receipt.
    local rc=0
    cmd_verify "$LEDGER" >/dev/null || rc=$?
    if [ "$rc" != 0 ]; then
        err "refusing to report a latest receipt from a ledger that does not verify (run 'verify' for the break)"
        return "$rc"
    fi
    local last=""
    [ -s "$LEDGER" ] && last="$(grep '"kind":"promotion"' "$LEDGER" 2>/dev/null | tail -1)"
    if [ -z "$last" ]; then
        cat >&2 <<EOF
promotion_receipt: NO PROMOTION RECORDED — the receipt chain verifies clean and
  carries no promotion receipt. No promotion has ever been recorded, so whatever
  any proof server is running cannot be tied to a reviewed commit. This is the
  honest state of the ledger, not an error in it.
EOF
        return 2
    fi
    echo "promotion_receipt: latest promotion receipt"
    printf '  seq             %s\n' "$(jfield "$last" seq)"
    printf '  host            %s\n' "$(jfield "$last" host)"
    printf '  commit          %s\n' "$(jfield "$last" commit)"
    printf '  source_id       %s\n' "$(jfield "$last" source_id_sha256)"
    printf '  artifact_sha256 %s\n' "$(jfield "$last" artifact_sha256)"
    printf '  recorded_utc    %s\n' "$(jfield "$last" recorded_utc)"
    printf '  signer          %s\n' "$(jfield "$last" signer)"
    return 0
}

# ── record construction (shared by genesis and append) ───────────────────
# ledger_repo — the git repo that owns the ledger. Commit resolution is tied
# to it rather than to $PWD, so a receipt's commit= is always a revision of
# the repository the ledger will be committed into.
ledger_repo() { dirname "$LEDGER"; }

# recorded_by_value — env override, else the ledger repo's branch.
recorded_by_value() {
    local v="${ZCL_RECEIPT_RECORDED_BY:-}"
    if [ -z "$v" ]; then
        v="$(git -C "$(ledger_repo)" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    fi
    [ -n "$v" ] && [ "$v" != "HEAD" ] || v="detached-head"
    printf '%s' "$v"
}

# emit_record <kind> <host> <commit> <srcid> <artsha> — build, sign, and
# append one record. Every append re-verifies the WHOLE chain afterwards and
# rolls the file back on failure, so a malformed or unverifiable record can
# never come to rest in the ledger.
emit_record() {
    local kind="$1" host="$2" commit="$3" srcid="$4" artsha="$5"

    # The root of trust is an explicit decision, never a default. See the
    # SIGN_KEY comment at the top of this file for what went wrong when it was
    # a default.
    if [ -z "$SIGN_KEY" ]; then
        err "refuse — no signing key configured; set ZCL_RECEIPT_KEY to a key whose only purpose is signing promotion evidence"
        cat >&2 <<EOF
  There is deliberately no fallback. A login/push key must not be the evidence
  authority: anyone who can push could then mint receipts, and rotating that key
  for an ordinary git-access reason would invalidate the evidence chain.
  One-time setup, owner decision:
      ssh-keygen -t ed25519 -C 'zclassic23 promotion receipts' -f ~/.ssh/zcl-promotion-receipt
      printf '%s %s\\n' <principal> "\$(cut -d' ' -f1-2 ~/.ssh/zcl-promotion-receipt.pub)" >> $SIGNERS
      ZCL_RECEIPT_KEY=~/.ssh/zcl-promotion-receipt $SELF init
      git add $SIGNERS $LEDGER && git commit
  See docs/PROMOTION_RECEIPTS.md, "Owner setup".
EOF
        return 1
    fi
    if [ ! -r "$SIGNERS" ]; then
        err "refuse — allowed-signers file $SIGNERS is missing; a record nobody can verify is not evidence"
        return 1
    fi
    if [ ! -r "$SIGN_KEY" ]; then
        err "refuse — signing key $SIGN_KEY is not readable (check ZCL_RECEIPT_KEY)"
        return 1
    fi
    local signer
    if ! signer="$(signer_principal_for_key "$SIGN_KEY")"; then
        err "refuse — the public key of $SIGN_KEY is not listed in $SIGNERS, so nothing could verify the record it signs"
        return 1
    fi

    local rec_by
    rec_by="$(recorded_by_value)"
    if ! printf '%s' "$rec_by" | grep -qE "$TOKEN_RE"; then
        err "refuse — recorded_by '$rec_by' is not a plain token (set ZCL_RECEIPT_RECORDED_BY)"
        return 1
    fi

    local seq prev
    if [ -s "$LEDGER" ]; then
        local lastline
        lastline="$(tail -1 "$LEDGER")"
        seq=$(( $(jfield "$lastline" seq) + 1 ))
        prev="$(line_sha256 "$lastline")"
    else
        seq=0
        prev="$ZERO_HASH"
    fi

    local ts payload
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    payload="{\"schema\":\"$SCHEMA\",\"seq\":$seq,\"prev_hash\":\"$prev\",\"kind\":\"$kind\",\"host\":\"$host\",\"commit\":\"$commit\",\"source_id_sha256\":\"$srcid\",\"artifact_sha256\":\"$artsha\",\"recorded_utc\":\"$ts\",\"recorded_by\":\"$rec_by\",\"signer\":\"$signer\"}"

    local tmpd
    tmpd="$(mktemp -d "${TMPDIR:-/tmp}/zcl_receipt_s.XXXXXX")" || {
        err "refuse — no writable temp dir for signing"
        return 1
    }
    printf '%s' "$payload" > "$tmpd/payload"
    if ! ssh-keygen -Y sign -f "$SIGN_KEY" -n "$SIG_NAMESPACE" "$tmpd/payload" >/dev/null 2>&1; then
        rm -rf "$tmpd"
        err "refuse — could not sign the record with $SIGN_KEY (passphrase-protected keys need an ssh-agent)"
        return 1
    fi
    local sig_b64
    sig_b64="$(sed -e '1d' -e '$d' "$tmpd/payload.sig" | tr -d '\n')"
    rm -rf "$tmpd"
    if ! printf '%s' "$sig_b64" | grep -qE '^[A-Za-z0-9+/=]+$'; then
        err "refuse — the produced signature is not plain base64"
        return 1
    fi

    local line="${payload%\}}"
    line="${line},\"sig_b64\":\"$sig_b64\"}"

    if ! printf '%s' "$line" | grep -qE "$LINE_RE"; then
        err "refuse — the record just built does not match the $SCHEMA line shape; nothing appended"
        printf '  record: %s\n' "$line" >&2
        return 1
    fi

    # Append, then prove the whole chain still verifies. A failure rolls the
    # file back to the exact bytes it had, so a bad append leaves no residue.
    local backup=""
    if [ -f "$LEDGER" ]; then
        backup="$(mktemp "${TMPDIR:-/tmp}/zcl_receipt_bk.XXXXXX")"
        cp -f "$LEDGER" "$backup"
    fi
    mkdir -p "$(dirname "$LEDGER")"
    printf '%s\n' "$line" >> "$LEDGER"

    local vout rc=0
    vout="$(cmd_verify "$LEDGER" 2>&1)" || rc=$?
    if [ "$rc" != 0 ]; then
        if [ -n "$backup" ]; then cp -f "$backup" "$LEDGER"; else rm -f "$LEDGER"; fi
        [ -z "$backup" ] || rm -f "$backup"
        err "refuse — the appended record did not verify; the ledger was rolled back unchanged"
        printf '%s\n' "$vout" >&2
        return 1
    fi
    [ -z "$backup" ] || rm -f "$backup"

    echo "promotion_receipt: appended seq=$seq kind=$kind signer=$signer"
    printf '  ledger  %s\n' "$LEDGER"
    printf '  sha256  %s\n' "$(line_sha256 "$line")"
    return 0
}

# ── init ─────────────────────────────────────────────────────────────────
# Mints the one genesis record, under the key ZCL_RECEIPT_KEY names. This is
# the owner's one-time root-of-trust decision and nothing else in the tooling
# performs it — ship.sh only ever appends.
cmd_init() {
    if [ -s "$LEDGER" ]; then
        err "refuse — $LEDGER already has records; a chain has exactly one genesis record"
        return 1
    fi
    emit_record genesis "" "" "" ""
}

# ── append ───────────────────────────────────────────────────────────────
cmd_append() {
    if [ "$#" -ne 4 ]; then
        err "append requires exactly 4 args: <commit-sha> <source_id> <artifact_sha256> <host>"
        return 2
    fi
    local commit="$1" srcid="$2" artsha="$3" host="$4"

    if [ ! -s "$LEDGER" ]; then
        err "refuse — $LEDGER has no genesis record yet; run 'promotion_receipt.sh init' first"
        return 1
    fi

    local resolved
    if ! resolved="$(git -C "$(ledger_repo)" rev-parse --verify -q "${commit}^{commit}" 2>/dev/null)"; then
        err "refuse — '$commit' does not resolve to a commit in the repo that owns the ledger"
        return 1
    fi
    if ! printf '%s' "$resolved" | grep -qE "$HEX40_RE"; then
        err "refuse — resolved commit '$resolved' is not 40 lowercase hex characters"
        return 1
    fi
    if ! printf '%s' "$srcid" | grep -qE "$HEX64_RE"; then
        err "refuse — source_id '$srcid' is not 64 lowercase hex characters"
        return 1
    fi
    if ! printf '%s' "$artsha" | grep -qE "$HEX64_RE"; then
        err "refuse — artifact_sha256 '$artsha' is not 64 lowercase hex characters"
        return 1
    fi
    if ! printf '%s' "$host" | grep -qE "$TOKEN_RE"; then
        err "refuse — host '$host' is not a plain token"
        return 1
    fi

    emit_record promotion "$host" "$resolved" "$srcid" "$artsha"
}

# ── self-test ────────────────────────────────────────────────────────────
st_fail=0
st_note() {
    echo "promotion_receipt: SELF-TEST FAIL — $1" >&2
    st_fail=$((st_fail + 1))
}

# st_expect_break <label> <ledger> <expected first stderr line>
# Asserts verify exits 1 AND its first stderr line is EXACTLY the expected
# text. Exit-code-only assertions are how a previous receipt self-test in this
# repository passed while checking nothing.
st_expect_break() {
    local label="$1" ledger="$2" want="$3"
    local out rc=0
    out="$(ZCL_RECEIPT_LEDGER="$ledger" ZCL_RECEIPT_SIGNERS="$SIGNERS" \
           "$SELF_DIR/promotion_receipt.sh" verify 2>&1 >/dev/null)" || rc=$?
    local got
    got="$(printf '%s\n' "$out" | head -1)"
    if [ "$rc" != 1 ]; then
        st_note "$label: verify should exit 1 (got $rc)"
    fi
    if [ "$got" != "$want" ]; then
        st_note "$label: first stderr line was
    got:  $got
    want: $want"
    fi
}

st_expect_clean() {
    local label="$1" ledger="$2"
    local out rc=0
    out="$(ZCL_RECEIPT_LEDGER="$ledger" ZCL_RECEIPT_SIGNERS="$SIGNERS" \
           "$SELF_DIR/promotion_receipt.sh" verify 2>&1)" || rc=$?
    if [ "$rc" != 0 ]; then
        st_note "$label: verify should exit 0 (got $rc):
$out"
    fi
    str_lacks "$out" 'chain intact' && \
        st_note "$label: verify should report 'chain intact'"
}

run_self_test() {
    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl_receipt_selftest.XXXXXX" 2>/dev/null || true)"
    if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
        err "SELF-TEST SKIPPED — no writable temp dir"
        return 0
    fi
    trap 'rm -rf "$tmp"' EXIT HUP INT TERM

    # Fixture: a throwaway git repo (so `append` can resolve a commit), a
    # throwaway ed25519 signing key, and an allowed-signers file naming it.
    # Nothing here reads this repository's ledger, signers, or key.
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        git init -q "$tmp/repo" >/dev/null 2>&1 || {
        err "SELF-TEST SKIPPED — cannot build a fixture git repo here"
        return 0
    }
    echo fixture > "$tmp/repo/f.txt"
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        git -C "$tmp/repo" add -A >/dev/null 2>&1
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        GIT_AUTHOR_NAME=selftest GIT_AUTHOR_EMAIL=selftest@invalid \
        GIT_COMMITTER_NAME=selftest GIT_COMMITTER_EMAIL=selftest@invalid \
        git -C "$tmp/repo" -c commit.gpgsign=false commit -qm fixture >/dev/null 2>&1
    local commit
    commit="$(env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        git -C "$tmp/repo" rev-parse HEAD)"

    ssh-keygen -q -t ed25519 -N '' -C selftest@invalid -f "$tmp/key" >/dev/null 2>&1 || {
        err "SELF-TEST SKIPPED — ssh-keygen cannot generate a fixture key here"
        return 0
    }
    local principal='receipt-selftest@invalid'
    printf '%s %s\n' "$principal" "$(cut -d' ' -f1-2 "$tmp/key.pub")" > "$tmp/signers"

    # From here on the fixture's signers file is the one every verify uses.
    SIGNERS="$tmp/signers"

    local L="$tmp/repo/ledger.jsonl"
    local run_env=(env
        "ZCL_RECEIPT_LEDGER=$L"
        "ZCL_RECEIPT_SIGNERS=$tmp/signers"
        "ZCL_RECEIPT_KEY=$tmp/key"
        "ZCL_RECEIPT_RECORDED_BY=selftest-lane"
        GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null)
    local rc

    # (0) refusals — each must print EXACTLY the expected message. This is the
    #     mutation-resistant form: a validator that silently stopped running
    #     but happened to fail downstream would still exit non-zero, so exit
    #     code alone proves nothing.
    rc=0
    local out
    out="$("${run_env[@]}" "$SELF" append "$commit" deadbeef 2>&1 >/dev/null)" || rc=$?
    [ "$rc" != 0 ] || st_note "append with too few args should refuse"
    [ "$out" = "promotion_receipt: append requires exactly 4 args: <commit-sha> <source_id> <artifact_sha256> <host>" ] || \
        st_note "append arity refusal text was '$out'"

    rc=0
    out="$("${run_env[@]}" "$SELF" append "$commit" x y z 2>&1 >/dev/null)" || rc=$?
    [ "$rc" != 0 ] || st_note "append before init should refuse"
    [ "$out" = "promotion_receipt: refuse — $L has no genesis record yet; run 'promotion_receipt.sh init' first" ] || \
        st_note "append-before-init refusal text was '$out'"

    # (0b) NO SIGNING KEY CONFIGURED — the root-of-trust rule. Both write
    #      paths must refuse, with the FIRST stderr line exactly as expected,
    #      and leave no ledger behind. An earlier draft silently fell back to
    #      $HOME/.ssh/id_ed25519 (the operator's personal push key); this pair
    #      of assertions is what makes that regression impossible to reland.
    local nokey_env=(env
        "ZCL_RECEIPT_LEDGER=$tmp/nokey.jsonl"
        "ZCL_RECEIPT_SIGNERS=$tmp/signers"
        "ZCL_RECEIPT_RECORDED_BY=selftest-lane"
        GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null)
    local want_nokey="promotion_receipt: refuse — no signing key configured; set ZCL_RECEIPT_KEY to a key whose only purpose is signing promotion evidence"
    rc=0
    out="$("${nokey_env[@]}" "$SELF" init 2>&1 >/dev/null | head -1)" || rc=$?
    [ "$out" = "$want_nokey" ] || \
        st_note "init with no ZCL_RECEIPT_KEY: first stderr line was
    got:  $out
    want: $want_nokey"
    [ ! -e "$tmp/nokey.jsonl" ] || st_note "init with no key must not create a ledger"
    rc=0
    "${nokey_env[@]}" "$SELF" init >/dev/null 2>&1 || rc=$?
    [ "$rc" != 0 ] || st_note "init with no ZCL_RECEIPT_KEY should refuse (got exit 0)"

    # Same for append, on a ledger that DOES have a genesis, so the refusal
    # cannot be the has-no-genesis one wearing a different hat.
    rc=0
    out="$(env "ZCL_RECEIPT_LEDGER=$tmp/repo/nokey2.jsonl" "ZCL_RECEIPT_SIGNERS=$tmp/signers" \
        "ZCL_RECEIPT_KEY=$tmp/key" "ZCL_RECEIPT_RECORDED_BY=selftest-lane" \
        GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        "$SELF" init 2>&1 >/dev/null)" || rc=$?
    [ "$rc" = 0 ] || st_note "fixture: init on nokey2 ledger should succeed (got $rc: $out)"
    rc=0
    out="$(env "ZCL_RECEIPT_LEDGER=$tmp/repo/nokey2.jsonl" "ZCL_RECEIPT_SIGNERS=$tmp/signers" \
        "ZCL_RECEIPT_RECORDED_BY=selftest-lane" \
        GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        "$SELF" append "$commit" \
        1111111111111111111111111111111111111111111111111111111111111111 \
        2222222222222222222222222222222222222222222222222222222222222222 h 2>&1 >/dev/null | head -1)" || rc=$?
    [ "$out" = "$want_nokey" ] || \
        st_note "append with no ZCL_RECEIPT_KEY: first stderr line was
    got:  $out
    want: $want_nokey"
    [ "$(wc -l < "$tmp/repo/nokey2.jsonl")" = "1" ] || \
        st_note "append with no key must not extend the ledger (expected 1 line, got $(wc -l < "$tmp/repo/nokey2.jsonl"))"

    # (0c) ZERO RECORDS is a CLEAN, UNRECORDED state — both absent and empty.
    #      This is what the repository ships, so it has to verify green and it
    #      must not read as a success that implies a promotion.
    st_expect_clean "absent ledger" "$tmp/does-not-exist.jsonl"
    out="$(ZCL_RECEIPT_LEDGER="$tmp/does-not-exist.jsonl" ZCL_RECEIPT_SIGNERS="$SIGNERS" \
        "$SELF" verify 2>&1)"
    str_lacks "$out" 'NO PROMOTION RECORDED' && \
        st_note "an absent ledger must report NO PROMOTION RECORDED"
    str_lacks "$out" '0 record(s), 0 promotion(s)' && \
        st_note "an absent ledger must report 0 records and 0 promotions"
    : > "$tmp/empty.jsonl"
    st_expect_clean "zero-record ledger" "$tmp/empty.jsonl"
    out="$(ZCL_RECEIPT_LEDGER="$tmp/empty.jsonl" ZCL_RECEIPT_SIGNERS="$SIGNERS" \
        "$SELF" verify 2>&1)"
    str_lacks "$out" 'NO PROMOTION RECORDED' && \
        st_note "a zero-record ledger must report NO PROMOTION RECORDED"
    rc=0
    out="$(ZCL_RECEIPT_LEDGER="$tmp/empty.jsonl" ZCL_RECEIPT_SIGNERS="$SIGNERS" \
        "$SELF" latest 2>&1 >/dev/null)" || rc=$?
    [ "$rc" = 2 ] || st_note "latest on a zero-record ledger should exit 2 (got $rc)"
    str_lacks "$out" 'NO PROMOTION RECORDED' && \
        st_note "latest on a zero-record ledger must say NO PROMOTION RECORDED"

    # (1) init, then the genesis-only contract: verifies clean AND says no
    #     promotion is recorded, rather than reading as a success that implies
    #     one.
    rc=0
    "${run_env[@]}" "$SELF" init >/dev/null 2>&1 || rc=$?
    [ "$rc" = 0 ] || st_note "init should succeed (got $rc)"
    st_expect_clean "genesis-only" "$L"
    out="$("${run_env[@]}" "$SELF" verify 2>&1)"
    str_lacks "$out" 'NO PROMOTION RECORDED' && \
        st_note "a genesis-only ledger must report NO PROMOTION RECORDED"
    str_lacks "$out" '0 promotion(s)' && \
        st_note "a genesis-only ledger must report 0 promotions"
    rc=0
    out="$("${run_env[@]}" "$SELF" latest 2>&1 >/dev/null)" || rc=$?
    [ "$rc" = 2 ] || st_note "latest on a genesis-only ledger should exit 2 (got $rc)"
    str_lacks "$out" 'NO PROMOTION RECORDED' && \
        st_note "latest on a genesis-only ledger must say NO PROMOTION RECORDED"

    rc=0
    out="$("${run_env[@]}" "$SELF" init 2>&1 >/dev/null)" || rc=$?
    [ "$rc" != 0 ] || st_note "a second init should refuse"
    [ "$out" = "promotion_receipt: refuse — $L already has records; a chain has exactly one genesis record" ] || \
        st_note "second-init refusal text was '$out'"

    rc=0
    out="$("${run_env[@]}" "$SELF" append "$commit" not-hex \
        1111111111111111111111111111111111111111111111111111111111111111 h 2>&1 >/dev/null)" || rc=$?
    [ "$rc" != 0 ] || st_note "append with a malformed source_id should refuse"
    [ "$out" = "promotion_receipt: refuse — source_id 'not-hex' is not 64 lowercase hex characters" ] || \
        st_note "source_id refusal text was '$out'"

    rc=0
    out="$("${run_env[@]}" "$SELF" append 0000000000000000000000000000000000000000 \
        1111111111111111111111111111111111111111111111111111111111111111 \
        2222222222222222222222222222222222222222222222222222222222222222 h 2>&1 >/dev/null)" || rc=$?
    [ "$rc" != 0 ] || st_note "append with an unresolvable commit should refuse"
    [ "$out" = "promotion_receipt: refuse — '0000000000000000000000000000000000000000' does not resolve to a commit in the repo that owns the ledger" ] || \
        st_note "commit refusal text was '$out'"

    # (2) a real chain of 4 records (genesis + 3 promotions).
    local n
    for n in 1 2 3; do
        local s="$(printf '%064d' "$n")" a="$(printf '%064d' "$((n + 100))")"
        rc=0
        out="$("${run_env[@]}" "$SELF" append "$commit" "$s" "$a" "host-$n" 2>&1 >/dev/null)" || rc=$?
        [ "$rc" = 0 ] || st_note "append #$n should succeed (got $rc: $out)"
    done
    st_expect_clean "4-record chain" "$L"
    [ "$(wc -l < "$L")" = "4" ] || st_note "expected 4 ledger lines, got $(wc -l < "$L")"
    out="$("${run_env[@]}" "$SELF" verify 2>&1)"
    str_lacks "$out" '3 promotion(s)' && st_note "verify should report 3 promotions"
    rc=0
    "${run_env[@]}" "$SELF" latest >/dev/null 2>&1 || rc=$?
    [ "$rc" = 0 ] || st_note "latest on a 3-promotion ledger should exit 0 (got $rc)"

    # (3) verify with NO PRIVATE KEY PRESENT — the whole point of signing is
    #     that a third party who has only the public allowed-signers file can
    #     check authorship. Delete the key and prove verify still passes.
    cp "$tmp/key" "$tmp/key.saved"
    rm -f "$tmp/key" "$tmp/key.pub"
    st_expect_clean "no-private-key verify" "$L"
    [ ! -f "$tmp/key" ] || st_note "fixture private key should be gone for the no-key case"
    cp "$tmp/key.saved" "$tmp/key"
    chmod 600 "$tmp/key"

    # (4) TAMPER CASES. Each starts from a pristine copy of the good chain.
    local good="$tmp/good.jsonl"
    cp "$L" "$good"

    # (a) edit a middle record's content (host-2 -> host-X): the record's own
    #     signature no longer covers its bytes.
    local t="$tmp/t_edit.jsonl"
    sed '3s/host-2/host-X/' "$good" > "$t"
    cmp -s "$good" "$t" && st_note "tamper (a) did not change the ledger"
    st_expect_break "tamper (a) edited middle record" "$t" \
        "promotion_receipt: BREAK at line 3 — signature does not verify (record content edited, or signature corrupted)"

    # (b) delete a middle record: the survivors' seq numbering has a hole.
    t="$tmp/t_delete.jsonl"
    sed '3d' "$good" > "$t"
    [ "$(wc -l < "$t")" = "3" ] || st_note "tamper (b) should leave 3 lines"
    st_expect_break "tamper (b) deleted middle record" "$t" \
        "promotion_receipt: BREAK at line 3 — seq is out of sequence (a record was deleted, inserted, or re-ordered)"

    # (c) re-order two records (swap lines 3 and 4).
    t="$tmp/t_reorder.jsonl"
    { sed -n '1,2p' "$good"; sed -n '4p' "$good"; sed -n '3p' "$good"; } > "$t"
    [ "$(wc -l < "$t")" = "4" ] || st_note "tamper (c) should leave 4 lines"
    cmp -s "$good" "$t" && st_note "tamper (c) did not change the ledger"
    st_expect_break "tamper (c) re-ordered records" "$t" \
        "promotion_receipt: BREAK at line 3 — seq is out of sequence (a record was deleted, inserted, or re-ordered)"

    # (d) corrupt one signature, leaving everything else byte-identical.
    t="$tmp/t_badsig.jsonl"
    # Flip one character in the MIDDLE of the base64 body, so the corruption
    # lands inside the ed25519 signature bytes rather than in the sshsig magic
    # or its trailing padding — the realistic shape of a mangled signature.
    awk 'NR==3 {
             k = "\"sig_b64\":\""
             s = index($0, k) + length(k)
             e = length($0) - 2
             i = int((s + e) / 2)
             c = substr($0, i, 1)
             nc = (c == "A" ? "B" : "A")
             $0 = substr($0, 1, i - 1) nc substr($0, i + 1)
         } { print }' "$good" > "$t"
    cmp -s "$good" "$t" && st_note "tamper (d) did not change the ledger"
    st_expect_break "tamper (d) corrupted signature" "$t" \
        "promotion_receipt: BREAK at line 3 — signature does not verify (record content edited, or signature corrupted)"

    # (e) THE CASE THAT MAKES THE CHAIN LOAD-BEARING: an author who HOLDS the
    #     signing key edits a middle record and re-signs it. Shape, seq and
    #     that record's own signature are all valid — signatures alone cannot
    #     catch this. Only the NEXT record's prev_hash does. If this case ever
    #     stops being caught, the ledger has degraded to a pile of independent
    #     signatures with no history.
    t="$tmp/t_resigned.jsonl"
    local line3 p3 newp3
    line3="$(sed -n '3p' "$good")"
    p3="$(payload_of "$line3")"
    newp3="${p3//host-2/host-X}"
    [ "$newp3" != "$p3" ] || st_note "tamper (e) fixture: payload edit did not apply"
    printf '%s' "$newp3" > "$tmp/resign_payload"
    ssh-keygen -Y sign -f "$tmp/key" -n "$SIG_NAMESPACE" "$tmp/resign_payload" >/dev/null 2>&1 || \
        st_note "tamper (e) fixture: could not re-sign with the fixture key"
    local newsig
    newsig="$(sed -e '1d' -e '$d' "$tmp/resign_payload.sig" | tr -d '\n')"
    {
        sed -n '1,2p' "$good"
        printf '%s,"sig_b64":"%s"}\n' "${newp3%\}}" "$newsig"
        sed -n '4p' "$good"
    } > "$t"
    [ "$(wc -l < "$t")" = "4" ] || st_note "tamper (e) should leave 4 lines"
    # Sanity: line 3 must itself be a VALID signed record, or this case is not
    # testing what it claims to test.
    local re_line3 re_signer
    re_line3="$(sed -n '3p' "$t")"
    re_signer="$(jfield "$re_line3" signer)"
    verify_one "$(payload_of "$re_line3")" "$(jfield "$re_line3" sig_b64)" "$re_signer" || \
        st_note "tamper (e) fixture: the re-signed record should itself verify — otherwise this case proves nothing about the hash chain"
    st_expect_break "tamper (e) re-signed middle record" "$t" \
        "promotion_receipt: BREAK at line 4 — prev_hash does not match the sha256 of the preceding record (it was edited, deleted, or re-ordered)"

    # (f) an unknown signer cannot smuggle a record in, even with a valid
    #     signature of its own.
    t="$tmp/t_stranger.jsonl"
    sed '3s/"signer":"[^"]*"/"signer":"stranger@invalid"/' "$good" > "$t"
    cmp -s "$good" "$t" && st_note "tamper (f) did not change the ledger"
    st_expect_break "tamper (f) unknown signer" "$t" \
        "promotion_receipt: BREAK at line 3 — signer is not listed in the allowed-signers file"

    rm -rf "$tmp"
    trap - EXIT HUP INT TERM

    if [ "$st_fail" -ne 0 ]; then
        echo "PROMOTION RECEIPT SELF-TEST: FAIL ($st_fail assertion(s))" >&2
        return 1
    fi
    echo "PROMOTION RECEIPT SELF-TEST: PASS"
    return 0
}

SELF="$SELF_DIR/$(basename "${BASH_SOURCE[0]}")"

# ── dispatch ─────────────────────────────────────────────────────────────
case "${1-}" in
    init)    shift; cmd_init    "$@"; exit $? ;;
    append)  shift; cmd_append  "$@"; exit $? ;;
    verify)  shift; cmd_verify  "$@"; exit $? ;;
    latest)  shift; cmd_latest  "$@"; exit $? ;;
    --self-test) run_self_test; exit $? ;;
    *)
        cat >&2 <<EOF
usage:
  promotion_receipt.sh init      (once, by the owner; needs ZCL_RECEIPT_KEY)
  promotion_receipt.sh append <commit-sha> <source_id> <artifact_sha256> <host>
  promotion_receipt.sh verify [ledger]
  promotion_receipt.sh latest
  promotion_receipt.sh --self-test

Writing (init/append) requires ZCL_RECEIPT_KEY to name a signing key whose only
purpose is signing promotion evidence. There is no default: see "Owner setup" in
docs/PROMOTION_RECEIPTS.md. Verifying needs no private key.
EOF
        exit 2
        ;;
esac
