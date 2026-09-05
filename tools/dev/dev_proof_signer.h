/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Per-box Ed25519 identity and signer allowlist for push-proof
 *          receipts.
 *
 * A development acceptance receipt used to be sealed with a keyless SHA3-256
 * digest, so every process that could write .cache/zcl-dev-proof/ could write
 * an admitting one, and no other box could ever hand this box evidence it
 * could attribute. This module gives the receipt an identity:
 *
 *   - one Ed25519 keypair per box, stored outside every worktree under
 *     platform_state_root()/proof-signer/signer.ed25519, mode 0600, created
 *     on first use by the producer and never by the verifier;
 *   - one allowlist, platform_state_root()/proof-signer/signers.allow, a
 *     64-hex public key per line with `#` comments, this box's own key always
 *     trusted whether it is listed or not;
 *   - four named refusals and no crash on any input.
 *
 * It is deliberately the same shape as the fleet's worker identity
 * (engine/services/src/build_fabric_worker_identity.c plus the
 * signer_pubkey allowlist in build_fabric_worker.c): operator-local trust,
 * Ed25519, hex on the wire, no chain fee and no network.
 */

#ifndef ZCL_TOOLS_DEV_PROOF_SIGNER_H
#define ZCL_TOOLS_DEV_PROOF_SIGNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES 32u
#define ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES 64u
#define ZCL_DEV_PROOF_SIGNER_PUBKEY_HEX 65u /* 64 hex digits + NUL */
#define ZCL_DEV_PROOF_SIGNER_PATH_MAX 4096u

/* Refusal tokens. These are the exact strings written into a receipt
 * validation `why` buffer and printed by the pre-push hook, so a reader —
 * human or small model — can act on the line without reading this file. */
#define ZCL_DEV_PROOF_SIGNER_WHY_UNSIGNED "receipt_unsigned"
#define ZCL_DEV_PROOF_SIGNER_WHY_SIGNATURE_INVALID "signature_invalid"
#define ZCL_DEV_PROOF_SIGNER_WHY_SIGNER_UNKNOWN "signer_unknown"
#define ZCL_DEV_PROOF_SIGNER_WHY_KEY_UNREADABLE "signer_key_unreadable"
/* Caller error rather than trust judgement: a NULL buffer or a message with
 * no bytes behind it. Named too, so no path returns an anonymous false. */
#define ZCL_DEV_PROOF_SIGNER_WHY_ARGUMENTS_INVALID "signer_arguments_invalid"

/* Where this box keeps its signing identity and its trust list. Both are
 * absolute and both live under the state root, never inside a checkout.
 * Either output may be NULL when the caller wants only the other. */
bool zcl_dev_proof_signer_paths(char *key_path, size_t key_cap,
                                char *allow_path, size_t allow_cap);

/* Sign `message` with this box's key, creating the keypair on first use.
 * Key creation emits one typed line to the log; it is never silent. On
 * failure returns false and, when `why` is non-NULL, points it at
 * ZCL_DEV_PROOF_SIGNER_WHY_KEY_UNREADABLE. Never falls back to no signature. */
bool zcl_dev_proof_signer_sign(
    const uint8_t *message, size_t message_len,
    uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES],
    uint8_t signature[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES],
    const char **why);

/* Verify `signature` over `message` by `pubkey`, and only accept `pubkey`
 * when this box trusts it: it is this box's own key, or it is listed in
 * signers.allow. Refuses by name — signer_key_unreadable when this box has a
 * key file it cannot read, signer_unknown when the key is trusted by nobody
 * here, signature_invalid when the bytes do not verify. Reading no allowlist
 * at all is not an error; it means only this box's own key is trusted. */
bool zcl_dev_proof_signer_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES],
    const uint8_t signature[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES],
    const char **why);

/* This box's public key, without ever creating one. `present` is false when
 * no key file exists yet — the normal state of a box that has only ever
 * verified. Returns false (and names why) when a key file exists but cannot
 * be read as a private 32-byte seed. */
bool zcl_dev_proof_signer_public(
    uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES], bool *present,
    const char **why);

/* Same, but creating the keypair on first use, so an operator can ask for
 * the key they are about to hand another box. */
bool zcl_dev_proof_signer_public_ensure(
    uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES], const char **why);

struct zcl_dev_proof_allowlist_state {
    bool present;        /* signers.allow exists and was read */
    uint32_t trusted;    /* well-formed 64-hex keys accepted from the file */
    uint32_t malformed;  /* lines counted and skipped, never fatal */
    bool self_listed;    /* this box's own key also appears in the file */
};

/* Read the allowlist for reporting. A missing file is a state, not a
 * failure: `present` false, zero counts. Returns false only when the state
 * root itself cannot be resolved. */
bool zcl_dev_proof_signer_allowlist_state(
    struct zcl_dev_proof_allowlist_state *out, const char **why);

#endif
