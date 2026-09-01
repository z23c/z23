/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical human confirmation and inert build-release evidence. */

#include "vcs/build_release_qualification.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t k_confirmation_magic[8] = {
    'Z', 'B', 'R', 'C', 'F', 'M', '2', '\0'
};
static const uint8_t k_qualification_magic[8] = {
    'Z', 'B', 'R', 'Q', 'U', 'A', '2', '\0'
};

static bool brq_distinct3(const uint8_t a[32], const uint8_t b[32],
                          const uint8_t c[32])
{
    return memcmp(a, b, 32) != 0 && memcmp(a, c, 32) != 0 &&
           memcmp(b, c, 32) != 0;
}

static enum vcs_build_release_evidence_error brq_confirmation_valid(
    const struct vcs_build_release_confirmation_v2 *c)
{
    if (!c) return VCS_BUILD_RELEASE_EVIDENCE_NULL;
    if (c->schema_version != VCS_BUILD_RELEASE_CONFIRMATION_VERSION)
        return VCS_BUILD_RELEASE_EVIDENCE_VERSION;
    if (c->flags != VCS_BUILD_RELEASE_CONFIRM_REQUIRED_FLAGS)
        return VCS_BUILD_RELEASE_EVIDENCE_FLAGS;
    if (c->decision != VCS_BUILD_RELEASE_DECISION_CONFIRM &&
        c->decision != VCS_BUILD_RELEASE_DECISION_CANCEL)
        return VCS_BUILD_RELEASE_EVIDENCE_DECISION;
    const uint8_t *const roots[] = {
        c->action_root, c->artifact_root, c->candidate_receipt_root,
        c->shadow_receipt_root, c->reproduction_receipt_root,
        c->candidate_machine_evidence_root,
        c->shadow_machine_evidence_root,
        c->reproduction_machine_evidence_root,
        c->regression_action_root, c->regression_proof_set_root,
        c->confirmer_pubkey,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_BUILD_RELEASE_EVIDENCE_ROOT;
    if (!brq_distinct3(c->candidate_receipt_root, c->shadow_receipt_root,
                       c->reproduction_receipt_root) ||
        !brq_distinct3(c->candidate_machine_evidence_root,
                       c->shadow_machine_evidence_root,
                       c->reproduction_machine_evidence_root))
        return VCS_BUILD_RELEASE_EVIDENCE_DUPLICATE;
    return c->confirmed_unix > 0 ? VCS_BUILD_RELEASE_EVIDENCE_OK
                                 : VCS_BUILD_RELEASE_EVIDENCE_TIME;
}

void vcs_build_release_confirmation_v2_init(
    struct vcs_build_release_confirmation_v2 *confirmation)
{
    if (!confirmation) return;
    memset(confirmation, 0, sizeof(*confirmation));
    confirmation->schema_version = VCS_BUILD_RELEASE_CONFIRMATION_VERSION;
    confirmation->flags = VCS_BUILD_RELEASE_CONFIRM_REQUIRED_FLAGS;
}

static enum vcs_build_release_evidence_error brq_confirmation_encode(
    const struct vcs_build_release_confirmation_v2 *c,
    uint8_t out[VCS_BUILD_RELEASE_CONFIRMATION_WIRE_BYTES])
{
    enum vcs_build_release_evidence_error error = brq_confirmation_valid(c);
    if (error != VCS_BUILD_RELEASE_EVIDENCE_OK || !out)
        return out ? error : VCS_BUILD_RELEASE_EVIDENCE_NULL;
    memset(out, 0, VCS_BUILD_RELEASE_CONFIRMATION_WIRE_BYTES);
    memcpy(out, k_confirmation_magic, 8);
    zcl_write_u16_le(out + 8, c->schema_version);
    zcl_write_u16_le(out + 10, c->flags);
    out[12] = c->decision;
    size_t at = 16;
    const uint8_t *const roots[] = {
        c->action_root, c->artifact_root, c->candidate_receipt_root,
        c->shadow_receipt_root, c->reproduction_receipt_root,
        c->candidate_machine_evidence_root,
        c->shadow_machine_evidence_root,
        c->reproduction_machine_evidence_root,
        c->regression_action_root, c->regression_proof_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(out + at, roots[i], 32);
        at += 32;
    }
    zcl_write_i64_le(out + at, c->confirmed_unix);
    at += 8;
    memcpy(out + at, c->confirmer_pubkey, 32);
    at += 32;
    memcpy(out + at, c->signature, 64);
    return at + 64 == 440 ? VCS_BUILD_RELEASE_EVIDENCE_OK
                          : VCS_BUILD_RELEASE_EVIDENCE_WIRE;
}

enum vcs_build_release_evidence_error
vcs_build_release_confirmation_v2_serialize(
    const struct vcs_build_release_confirmation_v2 *confirmation,
    uint8_t out[VCS_BUILD_RELEASE_CONFIRMATION_WIRE_BYTES])
{
    return brq_confirmation_encode(confirmation, out);
}

enum vcs_build_release_evidence_error vcs_build_release_confirmation_v2_root(
    const struct vcs_build_release_confirmation_v2 *confirmation,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!confirmation || !out) return VCS_BUILD_RELEASE_EVIDENCE_NULL;
    uint8_t wire[VCS_BUILD_RELEASE_CONFIRMATION_WIRE_BYTES];
    enum vcs_build_release_evidence_error error =
        brq_confirmation_encode(confirmation, wire);
    if (error != VCS_BUILD_RELEASE_EVIDENCE_OK) return error;
    static const char domain[] = "zcl.build_release_confirmation.v2";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    /* Signature and the trailing reserved bytes are not the signed preimage. */
    sha3_256_write(&sha, wire, 376);
    sha3_256_finalize(&sha, out);
    return VCS_BUILD_RELEASE_EVIDENCE_OK;
}

enum vcs_build_release_evidence_error vcs_build_release_confirmation_v2_seal(
    struct vcs_build_release_confirmation_v2 *confirmation,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!confirmation || !secret || !pubkey)
        return VCS_BUILD_RELEASE_EVIDENCE_NULL;
    memcpy(confirmation->confirmer_pubkey, pubkey, 32);
    uint8_t root[32];
    enum vcs_build_release_evidence_error error =
        vcs_build_release_confirmation_v2_root(confirmation, root);
    if (error != VCS_BUILD_RELEASE_EVIDENCE_OK) return error;
    ed25519_sign(confirmation->signature, root, sizeof(root), secret, pubkey);
    return ed25519_verify(confirmation->signature, root, sizeof(root), pubkey)
        ? VCS_BUILD_RELEASE_EVIDENCE_OK
        : VCS_BUILD_RELEASE_EVIDENCE_SIGNATURE;
}

enum vcs_build_release_evidence_error vcs_build_release_confirmation_v2_verify(
    const struct vcs_build_release_confirmation_v2 *confirmation)
{
    uint8_t root[32];
    enum vcs_build_release_evidence_error error =
        vcs_build_release_confirmation_v2_root(confirmation, root);
    if (error != VCS_BUILD_RELEASE_EVIDENCE_OK) return error;
    return ed25519_verify(confirmation->signature, root, sizeof(root),
                          confirmation->confirmer_pubkey)
        ? VCS_BUILD_RELEASE_EVIDENCE_OK
        : VCS_BUILD_RELEASE_EVIDENCE_SIGNATURE;
}

enum vcs_build_release_evidence_error vcs_build_release_confirmation_v2_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_build_release_confirmation_v2 *out)
{
    if (!wire || !out) return VCS_BUILD_RELEASE_EVIDENCE_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_BUILD_RELEASE_CONFIRMATION_WIRE_BYTES)
        return VCS_BUILD_RELEASE_EVIDENCE_WIRE;
    if (memcmp(wire, k_confirmation_magic, 8) != 0)
        return VCS_BUILD_RELEASE_EVIDENCE_MAGIC;
    if (memcmp(wire + 13, (const uint8_t[3]){0}, 3) != 0 ||
        memcmp(wire + 440, (const uint8_t[8]){0}, 8) != 0)
        return VCS_BUILD_RELEASE_EVIDENCE_WIRE;
    out->schema_version = zcl_read_u16_le(wire + 8);
    out->flags = zcl_read_u16_le(wire + 10);
    out->decision = wire[12];
    size_t at = 16;
    uint8_t *const roots[] = {
        out->action_root, out->artifact_root,
        out->candidate_receipt_root, out->shadow_receipt_root,
        out->reproduction_receipt_root,
        out->candidate_machine_evidence_root,
        out->shadow_machine_evidence_root,
        out->reproduction_machine_evidence_root,
        out->regression_action_root, out->regression_proof_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(roots[i], wire + at, 32);
        at += 32;
    }
    out->confirmed_unix = zcl_read_i64_le(wire + at);
    at += 8;
    memcpy(out->confirmer_pubkey, wire + at, 32);
    at += 32;
    memcpy(out->signature, wire + at, 64);
    enum vcs_build_release_evidence_error error = brq_confirmation_valid(out);
    if (error != VCS_BUILD_RELEASE_EVIDENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

static enum vcs_build_release_evidence_error brq_qualification_valid(
    const struct vcs_build_release_qualification_v2 *q)
{
    if (!q) return VCS_BUILD_RELEASE_EVIDENCE_NULL;
    if (q->schema_version != VCS_BUILD_RELEASE_QUALIFICATION_VERSION)
        return VCS_BUILD_RELEASE_EVIDENCE_VERSION;
    if (q->flags != VCS_BUILD_RELEASE_QUAL_REQUIRED_FLAGS)
        return VCS_BUILD_RELEASE_EVIDENCE_FLAGS;
    const uint8_t *const roots[] = {
        q->action_root, q->artifact_root, q->observation_root,
        q->candidate_receipt_root, q->shadow_receipt_root,
        q->reproduction_receipt_root, q->confirmation_root,
        q->proof_set_root,
        q->regression_action_root, q->regression_proof_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_BUILD_RELEASE_EVIDENCE_ROOT;
    if (!brq_distinct3(q->candidate_receipt_root, q->shadow_receipt_root,
                       q->reproduction_receipt_root))
        return VCS_BUILD_RELEASE_EVIDENCE_DUPLICATE;
    return q->qualified_unix > 0 ? VCS_BUILD_RELEASE_EVIDENCE_OK
                                 : VCS_BUILD_RELEASE_EVIDENCE_TIME;
}

enum vcs_build_release_evidence_error
vcs_build_release_qualification_v2_serialize(
    const struct vcs_build_release_qualification_v2 *q,
    uint8_t out[VCS_BUILD_RELEASE_QUALIFICATION_WIRE_BYTES])
{
    enum vcs_build_release_evidence_error error = brq_qualification_valid(q);
    if (error != VCS_BUILD_RELEASE_EVIDENCE_OK || !out)
        return out ? error : VCS_BUILD_RELEASE_EVIDENCE_NULL;
    memset(out, 0, VCS_BUILD_RELEASE_QUALIFICATION_WIRE_BYTES);
    memcpy(out, k_qualification_magic, 8);
    zcl_write_u16_le(out + 8, q->schema_version);
    zcl_write_u16_le(out + 10, q->flags);
    size_t at = 16;
    const uint8_t *const roots[] = {
        q->action_root, q->artifact_root, q->observation_root,
        q->candidate_receipt_root, q->shadow_receipt_root,
        q->reproduction_receipt_root, q->confirmation_root,
        q->proof_set_root,
        q->regression_action_root, q->regression_proof_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(out + at, roots[i], 32);
        at += 32;
    }
    zcl_write_i64_le(out + at, q->qualified_unix);
    return at + 8 == 344 ? VCS_BUILD_RELEASE_EVIDENCE_OK
                         : VCS_BUILD_RELEASE_EVIDENCE_WIRE;
}

enum vcs_build_release_evidence_error
vcs_build_release_qualification_v2_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_build_release_qualification_v2 *out)
{
    if (!wire || !out) return VCS_BUILD_RELEASE_EVIDENCE_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_BUILD_RELEASE_QUALIFICATION_WIRE_BYTES)
        return VCS_BUILD_RELEASE_EVIDENCE_WIRE;
    if (memcmp(wire, k_qualification_magic, 8) != 0)
        return VCS_BUILD_RELEASE_EVIDENCE_MAGIC;
    if (memcmp(wire + 12, (const uint8_t[4]){0}, 4) != 0 ||
        memcmp(wire + 344, (const uint8_t[24]){0}, 24) != 0)
        return VCS_BUILD_RELEASE_EVIDENCE_WIRE;
    out->schema_version = zcl_read_u16_le(wire + 8);
    out->flags = zcl_read_u16_le(wire + 10);
    size_t at = 16;
    uint8_t *const roots[] = {
        out->action_root, out->artifact_root, out->observation_root,
        out->candidate_receipt_root, out->shadow_receipt_root,
        out->reproduction_receipt_root, out->confirmation_root,
        out->proof_set_root,
        out->regression_action_root, out->regression_proof_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(roots[i], wire + at, 32);
        at += 32;
    }
    out->qualified_unix = zcl_read_i64_le(wire + at);
    enum vcs_build_release_evidence_error error = brq_qualification_valid(out);
    if (error != VCS_BUILD_RELEASE_EVIDENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_build_release_evidence_error vcs_build_release_qualification_v2_root(
    const struct vcs_build_release_qualification_v2 *qualification,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!qualification || !out) return VCS_BUILD_RELEASE_EVIDENCE_NULL;
    uint8_t wire[VCS_BUILD_RELEASE_QUALIFICATION_WIRE_BYTES];
    enum vcs_build_release_evidence_error error =
        vcs_build_release_qualification_v2_serialize(qualification, wire);
    if (error != VCS_BUILD_RELEASE_EVIDENCE_OK) return error;
    static const char domain[] = "zcl.build_release_qualification.v2";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return VCS_BUILD_RELEASE_EVIDENCE_OK;
}
