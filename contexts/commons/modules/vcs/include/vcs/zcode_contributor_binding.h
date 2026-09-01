/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical dual-signed ZCODE contributor-binding wire
 * (contributor_binding.v1, ZCODE Scientific Metaverse slice S2).
 *
 * A contributor_binding binds an existing ZID Ed25519 identity to a fresh
 * ZCL secp256k1 address/key on one network. It is not a second identity
 * system: the ZID side reuses the ZID master Ed25519 key, the ZCL side
 * reuses the wallet secp256k1 key/address primitives, and the same SHA3-256
 * domain-separated root conventions as the rest of contexts/commons/modules/vcs.
 *
 * Wire layout (exact, fixed width, little-endian integers):
 *   body (184 bytes):
 *     magic                       8   {'Z','C','B','I','N','D','\r','\n'}
 *     schema_version              2   == VCS_ZCODE_CONTRIBUTOR_BINDING_VERSION
 *     network_genesis_root       32   chain the binding lives on
 *     zid_pubkey                 32   ZID master Ed25519 public key
 *     zcl_pubkey                 33   compressed secp256k1 public key
 *     zcl_key_id                 20   hash160(zcl_pubkey), the ZCL address hash
 *     predecessor_root           32   full root of the prior binding, zero for
 *                                     ACTIVE
 *     sequence                    8   1 for ACTIVE, prior+1 for successors
 *     issued_unix                 8   > 0
 *     expires_unix                8   > issued_unix
 *     operation                   1   ACTIVE=1, ROTATE=2, REVOKE=3
 *   zid_signature                64   Ed25519 over body_root by zid_pubkey
 *   zcl_signature                64   secp256k1 r||s low-S over body_root
 * Total wire: 312 bytes.
 *
 * body_root = SHA3-256("zcl.zcode.contributor_binding.v1" || NUL || body) is
 * the exact statement both keys sign. The binding's own root — what a
 * successor's predecessor_root references — commits the full wire including
 * both signatures:
 *   root = SHA3-256("zcl.zcode.contributor_binding.root.v1" || NUL || wire).
 *
 * Semantics:
 *   ACTIVE opens a chain (sequence 1, zero predecessor).
 *   ROTATE carries a NEW zcl key and points at the prior binding.
 *   REVOKE carries the SAME zcl key it retires (so it stays standalone
 *   verifiable), points at the prior binding, and is terminal: revocation
 *   cannot create a replacement key implicitly, and no successor may
 *   reference a revoked binding. Both rules are enforced by
 *   vcs_zcode_contributor_binding_validate_successor().
 *
 * ── contributor_binding.v2 (three-signature rotation + delayed recovery) ──
 *
 * v2 strengthens rotation and runs ALONGSIDE v1: the v1 codec, semantics,
 * and KAT vectors above are frozen for compatibility and never altered.
 *
 * Wire v2 (exact, fixed width, little-endian integers):
 *   body (192 bytes): the v1 body fields with schema_version == 2, magic
 *     {'Z','C','B','N','D','2','\r','\n'}, and one appended field:
 *       activation_unix             8   0 for all ops except RECOVER
 *   zid_signature                  64   Ed25519 over body_root_v2
 *   zcl_current_signature          64   secp256k1 r||s low-S over body_root_v2
 *   zcl_new_signature              64   secp256k1 r||s low-S over body_root_v2
 * Total wire: 384 bytes. Domains:
 *   body_root = SHA3-256("zcl.zcode.contributor_binding.v2" || NUL || body)
 *   root      = SHA3-256("zcl.zcode.contributor_binding.root.v2" || NUL ||
 *               wire)
 * All three signatures sign the same body_root statement.
 *
 * Per-operation signature slots:
 *   ACTIVE:  BOTH zcl slots signed by the initial zcl key.
 *   ROTATE:  current slot signed by the OLD key (the prior link's
 *            zcl_pubkey), new slot by the NEW key (this link's zcl_pubkey) —
 *            a normal rotation proves control of three keys: ZID + old ZCL +
 *            new ZCL.
 *   REVOKE:  keeps the retiring key in zcl_pubkey; current slot signed by
 *            it; new slot MUST be 64 zero bytes. Terminal as in v1.
 *   RECOVER: the lost-key path. The old key is presumed lost, so the current
 *            slot MUST be 64 zero bytes; the new slot is signed by the new
 *            zcl_pubkey. activation_unix must be at least
 *            VCS_ZCODE_BINDING_RECOVERY_DELAY_SECS after issued_unix, and
 *            the link is not effective until now >= activation_unix
 *            (ERR_RECOVERY_PENDING). This delay is the window in which the
 *            legitimate owner can still revoke with the old key.
 * A slot that must be signed carries a non-zero signature; a slot that must
 * be zero carries 64 zero bytes — any other shape is ERR_SIG_SLOT.
 *
 * Retired-key reuse ban (vcs_zcode_contributor_binding_validate_chain_v2):
 * every zcl_pubkey retired by a ROTATE, revoked by a REVOKE, or abandoned
 * by a RECOVER is permanently banned from reappearing as the zcl_pubkey of
 * any later link (ERR_RETIRED_KEY_REUSE) — a retired key must never quietly
 * return to control the chain.
 */

#ifndef ZCL_VCS_ZCODE_CONTRIBUTOR_BINDING_H
#define ZCL_VCS_ZCODE_CONTRIBUTOR_BINDING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_CONTRIBUTOR_BINDING_VERSION 1u
#define VCS_ZCODE_CONTRIBUTOR_BINDING_DOMAIN "zcl.zcode.contributor_binding.v1"
#define VCS_ZCODE_CONTRIBUTOR_BINDING_ROOT_DOMAIN \
    "zcl.zcode.contributor_binding.root.v1"

#define VCS_ZCODE_CONTRIBUTOR_BINDING_BODY_BYTES 184u
#define VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES 312u

#define VCS_ZCODE_CONTRIBUTOR_BINDING_V2_VERSION 2u
#define VCS_ZCODE_CONTRIBUTOR_BINDING_V2_DOMAIN \
    "zcl.zcode.contributor_binding.v2"
#define VCS_ZCODE_CONTRIBUTOR_BINDING_V2_ROOT_DOMAIN \
    "zcl.zcode.contributor_binding.root.v2"

#define VCS_ZCODE_CONTRIBUTOR_BINDING_V2_BODY_BYTES 192u
#define VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES 384u

/* Minimum wall-clock delay between a RECOVER link's issued_unix and its
 * activation_unix: 7 days. The legitimate owner can still revoke with the
 * old key inside this window. */
#define VCS_ZCODE_BINDING_RECOVERY_DELAY_SECS (7LL * 86400LL)

enum vcs_zcode_binding_operation {
    VCS_ZCODE_BINDING_ACTIVE = 1,
    VCS_ZCODE_BINDING_ROTATE = 2,
    VCS_ZCODE_BINDING_REVOKE = 3,
    VCS_ZCODE_BINDING_RECOVER = 4, /* v2 only; v1 validation rejects it */
};

enum vcs_zcode_binding_error {
    VCS_ZCODE_BINDING_OK = 0,
    VCS_ZCODE_BINDING_ERR_NULL,
    VCS_ZCODE_BINDING_ERR_VERSION,
    VCS_ZCODE_BINDING_ERR_WIRE_SIZE,
    VCS_ZCODE_BINDING_ERR_WIRE_MAGIC,
    VCS_ZCODE_BINDING_ERR_ROOT_ZERO,
    VCS_ZCODE_BINDING_ERR_PUBKEY_ZERO,
    VCS_ZCODE_BINDING_ERR_PUBKEY_INVALID,
    VCS_ZCODE_BINDING_ERR_KEY_ID_MISMATCH,
    VCS_ZCODE_BINDING_ERR_PREDECESSOR,
    VCS_ZCODE_BINDING_ERR_SEQUENCE,
    VCS_ZCODE_BINDING_ERR_OPERATION,
    VCS_ZCODE_BINDING_ERR_TIME_ORDER,
    VCS_ZCODE_BINDING_ERR_SIGNATURE,
    VCS_ZCODE_BINDING_ERR_KEY_MISMATCH,
    VCS_ZCODE_BINDING_ERR_NETWORK_MISMATCH,
    VCS_ZCODE_BINDING_ERR_IDENTITY_MISMATCH,
    VCS_ZCODE_BINDING_ERR_EXPIRED,
    VCS_ZCODE_BINDING_ERR_REVOKED,
    VCS_ZCODE_BINDING_ERR_LINKAGE,
    VCS_ZCODE_BINDING_ERR_NOT_YET_VALID,
    /* v2 additions — append-only, never renumber. */
    VCS_ZCODE_BINDING_ERR_RECOVERY_DELAY,
    VCS_ZCODE_BINDING_ERR_RECOVERY_PENDING,
    VCS_ZCODE_BINDING_ERR_RETIRED_KEY_REUSE,
    VCS_ZCODE_BINDING_ERR_SIG_SLOT,
};

const char *vcs_zcode_binding_error_string(enum vcs_zcode_binding_error error);

struct vcs_zcode_contributor_binding_v1 {
    uint16_t schema_version;
    uint8_t network_genesis_root[32];
    uint8_t zid_pubkey[32];
    uint8_t zcl_pubkey[33];
    uint8_t zcl_key_id[20];
    uint8_t predecessor_root[32];
    uint64_t sequence;
    int64_t issued_unix;
    int64_t expires_unix;
    uint8_t operation;
    uint8_t zid_signature[64];
    uint8_t zcl_signature[64];
};

/* Structural validation. validate() requires both signatures to be
 * non-zero; validate_at() additionally rejects use before issued_unix
 * (NOT_YET_VALID) or at/after expires_unix (EXPIRED). Neither checks the
 * signatures cryptographically — that is verify()'s job. */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate(
    const struct vcs_zcode_contributor_binding_v1 *binding);
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_at(
    const struct vcs_zcode_contributor_binding_v1 *binding, int64_t now_unix);

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_serialize(
    const struct vcs_zcode_contributor_binding_v1 *binding,
    uint8_t out[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES]);
/* Exact-size only: a short or trailing wire is WIRE_SIZE, a wrong leading
 * magic is WIRE_MAGIC, an unsupported schema_version is VERSION. On any
 * error *out is zeroed. */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_contributor_binding_v1 *out);

/* The 32-byte statement both signatures sign (body only). */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_body_root(
    const struct vcs_zcode_contributor_binding_v1 *binding, uint8_t out[32]);
/* The binding's own id: commits the full signed wire. A successor's
 * predecessor_root must equal this value for its predecessor. */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_root(
    const struct vcs_zcode_contributor_binding_v1 *binding, uint8_t out[32]);

/* Sign the body root with both keys. The ZID public key is re-derived from
 * zid_secret and must equal both zid_pubkey and binding->zid_pubkey; for
 * ACTIVE/ROTATE, binding->zcl_pubkey must be the key derived from
 * zcl_secret (any mismatch is KEY_MISMATCH). The secp256k1 signature
 * is normalized to low-S before serialization, so sealing is byte
 * deterministic. */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_seal(
    struct vcs_zcode_contributor_binding_v1 *binding,
    const uint8_t zid_secret[32], const uint8_t zid_pubkey[32],
    const uint8_t zcl_secret[32]);

/* Full verification: structural validity at now_unix, the expected network
 * genesis root and ZID master key are pinned, and BOTH signatures verify
 * over the body root (the secp256k1 signature must be low-S canonical and
 * verify under the embedded zcl_pubkey). */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_verify(
    const struct vcs_zcode_contributor_binding_v1 *binding,
    const uint8_t expected_network_genesis[32],
    const uint8_t expected_zid_pubkey[32], int64_t now_unix);

/* Chain gate: next is a valid successor of prior. Requires prior and next
 * on the same network and ZID; prior not revoked (revocation is terminal);
 * next not ACTIVE; next->predecessor_root == root(prior);
 * next->sequence == prior->sequence + 1 (replay and skips rejected);
 * next->issued_unix > prior->issued_unix (reorderings rejected);
 * ROTATE must change the zcl key; REVOKE must keep it (no implicit
 * replacement); both bindings' signatures verify (prior structurally,
 * next at now_unix). */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_successor(
    const struct vcs_zcode_contributor_binding_v1 *prior,
    const struct vcs_zcode_contributor_binding_v1 *next, int64_t now_unix);

/* ── contributor_binding.v2 ───────────────────────────────────────────── */

struct vcs_zcode_contributor_binding_v2 {
    uint16_t schema_version;
    uint8_t network_genesis_root[32];
    uint8_t zid_pubkey[32];
    uint8_t zcl_pubkey[33];
    uint8_t zcl_key_id[20];
    uint8_t predecessor_root[32];
    uint64_t sequence;
    int64_t issued_unix;
    int64_t expires_unix;
    uint8_t operation;
    int64_t activation_unix; /* 0 for all ops except RECOVER */
    uint8_t zid_signature[64];
    uint8_t zcl_current_signature[64];
    uint8_t zcl_new_signature[64];
};

/* Structural validation, v2 signature-slot shape included: every slot that
 * must be signed must be non-zero, every slot that must be zero must be 64
 * zero bytes (ERR_SIG_SLOT otherwise), and a RECOVER activation must be at
 * least VCS_ZCODE_BINDING_RECOVERY_DELAY_SECS after issued_unix
 * (ERR_RECOVERY_DELAY). validate_at() additionally rejects use before
 * issued_unix (NOT_YET_VALID) or at/after expires_unix (EXPIRED). Neither
 * checks the signatures cryptographically — that is verify()'s job. */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding);
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_at_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding, int64_t now_unix);

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_serialize_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding,
    uint8_t out[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES]);
/* Exact-size only: a short or trailing wire is WIRE_SIZE, a wrong leading
 * magic is WIRE_MAGIC, an unsupported schema_version is VERSION. On any
 * error *out is zeroed. */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_parse_v2(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_contributor_binding_v2 *out);

/* The 32-byte statement all three signatures sign (body only). */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_body_root_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding, uint8_t out[32]);
/* The binding's own id: commits the full signed wire. A successor's
 * predecessor_root must equal this value for its predecessor. */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_root_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding, uint8_t out[32]);

/* Sign the v2 body root with the ZID key plus the operation's zcl slots.
 * The ZID public key is re-derived from zid_secret and must equal both
 * zid_pubkey and binding->zid_pubkey (KEY_MISMATCH otherwise). Per
 * operation:
 *   ACTIVE:  both secrets required, both must derive binding->zcl_pubkey.
 *   ROTATE:  both secrets required; new_zcl_secret must derive
 *            binding->zcl_pubkey (current_zcl_secret is the old key, pinned
 *            by the chain gate against the predecessor, not here).
 *   REVOKE:  current_zcl_secret required and must derive the embedded
 *            (retiring) key; new_zcl_secret is ignored and the new slot is
 *            zeroed.
 *   RECOVER: current_zcl_secret MUST be NULL (the old key is presumed lost)
 *            and the current slot is zeroed; new_zcl_secret must derive
 *            binding->zcl_pubkey.
 * The secp256k1 signatures are normalized to low-S before serialization,
 * so sealing is byte deterministic. */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_seal_v2(
    struct vcs_zcode_contributor_binding_v2 *binding,
    const uint8_t zid_secret[32], const uint8_t zid_pubkey[32],
    const uint8_t current_zcl_secret[32], const uint8_t new_zcl_secret[32]);

/* Full standalone verification: structural validity at now_unix, the
 * expected network genesis root and ZID master key are pinned, and the
 * signatures verify over the body root. The ZID signature verifies under
 * the embedded zid_pubkey; the new slot verifies under the embedded
 * zcl_pubkey where it must be signed; the current slot verifies under the
 * embedded key for ACTIVE/REVOKE. A standalone ROTATE's current slot signs
 * under the PREDECESSOR's key, which is not in the binding — only the
 * chain gate (validate_successor_v2) checks that slot. */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_verify_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding,
    const uint8_t expected_network_genesis[32],
    const uint8_t expected_zid_pubkey[32], int64_t now_unix);

/* Chain gate, v2: every v1 successor rule carried forward (same network
 * and ZID; prior not revoked; next not ACTIVE; predecessor_root ==
 * root_v2(prior); exact +1 sequence; strictly increasing issued_unix;
 * ROTATE must change the zcl key; REVOKE must keep it) plus the v2 rules:
 * RECOVER must also change the key, a RECOVER successor requires now >=
 * next->activation_unix (ERR_RECOVERY_PENDING), and the per-operation
 * signature slots verify — a ROTATE's current slot under the PRIOR link's
 * zcl_pubkey, its new slot under the new key; a REVOKE's current slot
 * under the retiring key; a RECOVER's new slot under the new key. */
enum vcs_zcode_binding_error
vcs_zcode_contributor_binding_validate_successor_v2(
    const struct vcs_zcode_contributor_binding_v2 *prior,
    const struct vcs_zcode_contributor_binding_v2 *next, int64_t now_unix);

/* Whole-chain gate: links[0] must be ACTIVE (ERR_OPERATION otherwise),
 * every adjacent pair must pass validate_successor_v2, and the retired-key
 * reuse ban holds: any zcl_pubkey retired by a ROTATE, revoked by a
 * REVOKE, or abandoned by a RECOVER must never reappear as the zcl_pubkey
 * of a later link (ERR_RETIRED_KEY_REUSE). */
enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_chain_v2(
    const struct vcs_zcode_contributor_binding_v2 *links, size_t count,
    int64_t now_unix);

#endif /* ZCL_VCS_ZCODE_CONTRIBUTOR_BINDING_H */
