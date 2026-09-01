/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Strict allocation-free capability-lifecycle frame codec. */

#include "session/mesh_capability_proto.h"

#include "base/bytes.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <stdbool.h>
#include <string.h>

static const uint8_t frame_magic[4] = {'Z', 'C', 'A', 'P'};
static const char *const signing_domains[] = {
    NULL,
    "zcl.mesh.capability.proposal.signature.v1",
    "zcl.mesh.capability.commit.signature.v1",
    "zcl.mesh.capability.grant.signature.v1",
    "zcl.mesh.capability.refusal.signature.v1",
    "zcl.mesh.capability.renew.signature.v1",
    "zcl.mesh.capability.cancel.signature.v1",
    "zcl.mesh.capability.ack.signature.v1",
};
static const char *const root_domains[] = {
    NULL,
    "zcl.mesh.capability.proposal.v1",
    "zcl.mesh.capability.commit.v1",
    "zcl.mesh.capability.grant.v1",
    "zcl.mesh.capability.refusal.v1",
    "zcl.mesh.capability.renew.v1",
    "zcl.mesh.capability.cancel.v1",
    "zcl.mesh.capability.ack.v1",
};

static_assert(MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES == 440u);
static_assert(MESH_CAPABILITY_COMMIT_V1_WIRE_BYTES == 320u);
static_assert(MESH_CAPABILITY_GRANT_V1_WIRE_BYTES == 360u);
static_assert(MESH_CAPABILITY_REFUSAL_V1_WIRE_BYTES == 220u);
static_assert(MESH_CAPABILITY_RENEW_V1_WIRE_BYTES == 320u);
static_assert(MESH_CAPABILITY_CANCEL_V1_WIRE_BYTES == 272u);
static_assert(MESH_CAPABILITY_ACK_V1_WIRE_BYTES == 284u);
static_assert(MESH_CAPABILITY_FRAME_V1_MAX < 4096u);

const char *mesh_capability_proto_error_string(
    enum mesh_capability_proto_error error)
{
    switch (error) {
    case MESH_CAPABILITY_PROTO_OK: return "ok";
    case MESH_CAPABILITY_PROTO_NULL: return "null";
    case MESH_CAPABILITY_PROTO_SIZE: return "size";
    case MESH_CAPABILITY_PROTO_MAGIC: return "magic";
    case MESH_CAPABILITY_PROTO_VERSION_INVALID: return "version";
    case MESH_CAPABILITY_PROTO_FLAGS: return "flags";
    case MESH_CAPABILITY_PROTO_KIND_INVALID: return "kind";
    case MESH_CAPABILITY_PROTO_FIELD: return "field";
    case MESH_CAPABILITY_PROTO_LIMIT: return "limit";
    case MESH_CAPABILITY_PROTO_TIME: return "time";
    case MESH_CAPABILITY_PROTO_STATUS: return "status";
    case MESH_CAPABILITY_PROTO_KEY_MISMATCH: return "key-mismatch";
    case MESH_CAPABILITY_PROTO_SIGNATURE: return "signature";
    }
    return "unknown";
}

static bool fields_nonzero(const uint8_t *const *fields, size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (!zcl_bytes_any_set(fields[i], 32))
            return false;
    return true;
}

static bool lifetime_valid(uint64_t start, uint64_t expires)
{
    return start != 0 && expires > start &&
           expires - start <= MESH_CAPABILITY_MAX_LIFETIME_SECONDS;
}

static bool one_bit(uint64_t value)
{
    return value != 0 && (value & (value - 1u)) == 0;
}

static bool signed_fields_valid(const uint8_t public_key[32],
                                const uint8_t signature[64],
                                bool require_signature)
{
    return zcl_bytes_any_set(public_key, 32) &&
           (!require_signature || zcl_bytes_any_set(signature, 64));
}

static enum mesh_capability_proto_error proposal_shape(
    const struct mesh_capability_proposal_v1 *frame, bool require_signature)
{
    if (!frame)
        return MESH_CAPABILITY_PROTO_NULL;
    const uint8_t *fields[] = {
        frame->network_genesis, frame->proposal_id,
        frame->target_master_pubkey, frame->subject_master_pubkey,
        frame->subject_noise_static, frame->input_root, frame->nonce,
        frame->idempotency_key,
    };
    if (!fields_nonzero(fields, sizeof(fields) / sizeof(fields[0])) ||
        !one_bit(frame->capability) ||
        (frame->capability & MESH_CAPABILITY_KIND_KNOWN) == 0 ||
        !signed_fields_valid(frame->signer_online_pubkey, frame->signature,
                             require_signature))
        return MESH_CAPABILITY_PROTO_FIELD;
    if (frame->result_mask == 0 ||
        (frame->result_mask & ~MESH_CAPABILITY_RESULT_KNOWN) != 0 ||
        (frame->deny_mask & MESH_CAPABILITY_POLICY_DENY_REQUIRED) !=
            MESH_CAPABILITY_POLICY_DENY_REQUIRED ||
        (frame->deny_mask & ~MESH_CAPABILITY_POLICY_DENY_KNOWN) != 0)
        return MESH_CAPABILITY_PROTO_FIELD;
    if (frame->max_bytes == 0 ||
        frame->max_bytes > MESH_CAPABILITY_MAX_BYTES ||
        frame->max_cpu_milliseconds == 0 ||
        frame->max_cpu_milliseconds >
            MESH_CAPABILITY_MAX_CPU_MILLISECONDS ||
        frame->max_memory_bytes == 0 ||
        frame->max_memory_bytes > MESH_CAPABILITY_MAX_MEMORY_BYTES ||
        frame->max_processes == 0 ||
        frame->max_processes > MESH_CAPABILITY_MAX_PROCESSES ||
        frame->max_concurrency == 0 ||
        frame->max_concurrency > MESH_CAPABILITY_MAX_CONCURRENCY ||
        frame->max_wall_milliseconds == 0 ||
        frame->max_wall_milliseconds >
            MESH_CAPABILITY_MAX_WALL_MILLISECONDS)
        return MESH_CAPABILITY_PROTO_LIMIT;
    return lifetime_valid(frame->not_before_unix, frame->expires_unix)
               ? MESH_CAPABILITY_PROTO_OK
               : MESH_CAPABILITY_PROTO_TIME;
}

static enum mesh_capability_proto_error commit_shape(
    const struct mesh_capability_commit_v1 *frame, bool require_signature)
{
    if (!frame)
        return MESH_CAPABILITY_PROTO_NULL;
    const uint8_t *fields[] = {
        frame->proposal_id, frame->proposal_root, frame->commit_id,
        frame->target_master_pubkey, frame->subject_master_pubkey,
        frame->transcript_hash,
    };
    return fields_nonzero(fields, sizeof(fields) / sizeof(fields[0])) &&
                   frame->connection_generation != 0 &&
                   frame->committed_unix != 0 &&
                   signed_fields_valid(frame->signer_online_pubkey,
                                       frame->signature, require_signature)
               ? MESH_CAPABILITY_PROTO_OK
               : MESH_CAPABILITY_PROTO_FIELD;
}

static enum mesh_capability_proto_error grant_shape(
    const struct mesh_capability_grant_v1 *frame, bool require_signature)
{
    if (!frame)
        return MESH_CAPABILITY_PROTO_NULL;
    const uint8_t *fields[] = {
        frame->proposal_id, frame->proposal_root, frame->commit_id,
        frame->grant_id, frame->grant_nonce, frame->target_master_pubkey,
        frame->subject_master_pubkey,
    };
    if (!fields_nonzero(fields, sizeof(fields) / sizeof(fields[0])) ||
        frame->issued_unix == 0 ||
        !signed_fields_valid(frame->signer_online_pubkey, frame->signature,
                             require_signature))
        return MESH_CAPABILITY_PROTO_FIELD;
    if (!lifetime_valid(frame->not_before_unix, frame->expires_unix) ||
        frame->issued_unix > frame->not_before_unix)
        return MESH_CAPABILITY_PROTO_TIME;
    return MESH_CAPABILITY_PROTO_OK;
}

static bool refusal_reason_valid(enum mesh_capability_refusal_reason reason)
{
    return reason >= MESH_CAPABILITY_REFUSAL_BAD_PROPOSAL &&
           reason <= MESH_CAPABILITY_REFUSAL_INTERNAL;
}

static enum mesh_capability_proto_error refusal_shape(
    const struct mesh_capability_refusal_v1 *frame, bool require_signature)
{
    if (!frame)
        return MESH_CAPABILITY_PROTO_NULL;
    const uint8_t *fields[] = {
        frame->request_id, frame->request_root, frame->target_master_pubkey,
    };
    if (!fields_nonzero(fields, sizeof(fields) / sizeof(fields[0])) ||
        frame->observed_unix == 0 ||
        !signed_fields_valid(frame->signer_online_pubkey, frame->signature,
                             require_signature))
        return MESH_CAPABILITY_PROTO_FIELD;
    return refusal_reason_valid(frame->reason) ? MESH_CAPABILITY_PROTO_OK
                                                : MESH_CAPABILITY_PROTO_STATUS;
}

static enum mesh_capability_proto_error renew_shape(
    const struct mesh_capability_renew_v1 *frame, bool require_signature)
{
    if (!frame)
        return MESH_CAPABILITY_PROTO_NULL;
    const uint8_t *fields[] = {
        frame->request_id, frame->prior_grant_id,
        frame->replacement_proposal_id, frame->replacement_proposal_root,
        frame->target_master_pubkey, frame->subject_master_pubkey,
    };
    if (!fields_nonzero(fields, sizeof(fields) / sizeof(fields[0])) ||
        !signed_fields_valid(frame->signer_online_pubkey, frame->signature,
                             require_signature))
        return MESH_CAPABILITY_PROTO_FIELD;
    return lifetime_valid(frame->requested_not_before_unix,
                          frame->requested_expires_unix)
               ? MESH_CAPABILITY_PROTO_OK
               : MESH_CAPABILITY_PROTO_TIME;
}

static enum mesh_capability_proto_error cancel_shape(
    const struct mesh_capability_cancel_v1 *frame, bool require_signature)
{
    if (!frame)
        return MESH_CAPABILITY_PROTO_NULL;
    const uint8_t *fields[] = {
        frame->cancel_id, frame->grant_id, frame->operation_id,
        frame->target_master_pubkey, frame->subject_master_pubkey,
    };
    return fields_nonzero(fields, sizeof(fields) / sizeof(fields[0])) &&
                   frame->requested_unix != 0 &&
                   signed_fields_valid(frame->signer_online_pubkey,
                                       frame->signature, require_signature)
               ? MESH_CAPABILITY_PROTO_OK
               : MESH_CAPABILITY_PROTO_FIELD;
}

static enum mesh_capability_proto_error ack_shape(
    const struct mesh_capability_ack_v1 *frame, bool require_signature)
{
    if (!frame)
        return MESH_CAPABILITY_PROTO_NULL;
    const uint8_t *fields[] = {
        frame->ack_id, frame->request_id, frame->request_root,
        frame->target_master_pubkey, frame->subject_master_pubkey,
    };
    if (!fields_nonzero(fields, sizeof(fields) / sizeof(fields[0])) ||
        frame->observed_unix == 0 ||
        !signed_fields_valid(frame->signer_online_pubkey, frame->signature,
                             require_signature))
        return MESH_CAPABILITY_PROTO_FIELD;
    if (frame->acknowledged_kind < MESH_CAPABILITY_FRAME_PROPOSAL ||
        frame->acknowledged_kind >= MESH_CAPABILITY_FRAME_ACK ||
        (frame->status != MESH_CAPABILITY_ACK_APPLIED &&
         frame->status != MESH_CAPABILITY_ACK_ALREADY_APPLIED))
        return MESH_CAPABILITY_PROTO_STATUS;
    return MESH_CAPABILITY_PROTO_OK;
}

static enum mesh_capability_proto_error frame_begin(
    enum mesh_capability_frame_kind kind, uint8_t *out, size_t out_capacity,
    size_t need, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!out || !out_len)
        return MESH_CAPABILITY_PROTO_NULL;
    if (out_capacity < need)
        return MESH_CAPABILITY_PROTO_SIZE;
    memcpy(out, frame_magic, sizeof(frame_magic));
    zcl_write_u16_le(out + 4, MESH_CAPABILITY_PROTO_VERSION);
    out[6] = (uint8_t)kind;
    out[7] = MESH_CAPABILITY_PROTO_FLAGS_NONE;
    return MESH_CAPABILITY_PROTO_OK;
}

#define PUT32(frame, field) do { \
    memcpy(out + off, (frame)->field, 32); off += 32; \
} while (0)

static enum mesh_capability_proto_error verify_body(
    enum mesh_capability_frame_kind kind, const void *body);

static enum mesh_capability_proto_error proposal_encode(
    const struct mesh_capability_proposal_v1 *frame, uint8_t *out,
    size_t out_capacity, size_t *out_len, bool verify_signature)
{
    if (out_len)
        *out_len = 0;
    if (!frame || !out || !out_len)
        return MESH_CAPABILITY_PROTO_NULL;
    enum mesh_capability_proto_error error =
        proposal_shape(frame, verify_signature);
    if (error != MESH_CAPABILITY_PROTO_OK)
        return error;
    if (verify_signature &&
        (error = verify_body(MESH_CAPABILITY_FRAME_PROPOSAL, frame)) !=
            MESH_CAPABILITY_PROTO_OK)
        return error;
    error = frame_begin(MESH_CAPABILITY_FRAME_PROPOSAL, out, out_capacity,
                        MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES, out_len);
    if (error != MESH_CAPABILITY_PROTO_OK) return error;
    size_t off = 8;
    PUT32(frame, network_genesis); PUT32(frame, proposal_id);
    PUT32(frame, target_master_pubkey); PUT32(frame, subject_master_pubkey);
    PUT32(frame, subject_noise_static); PUT32(frame, input_root);
    PUT32(frame, nonce); PUT32(frame, idempotency_key);
    zcl_write_u64_le(out + off, frame->capability); off += 8;
    zcl_write_u64_le(out + off, frame->result_mask); off += 8;
    zcl_write_u64_le(out + off, frame->max_bytes); off += 8;
    zcl_write_u64_le(out + off, frame->max_cpu_milliseconds); off += 8;
    zcl_write_u64_le(out + off, frame->max_memory_bytes); off += 8;
    zcl_write_u32_le(out + off, frame->max_processes); off += 4;
    zcl_write_u32_le(out + off, frame->max_concurrency); off += 4;
    zcl_write_u64_le(out + off, frame->max_wall_milliseconds); off += 8;
    zcl_write_u64_le(out + off, frame->not_before_unix); off += 8;
    zcl_write_u64_le(out + off, frame->expires_unix); off += 8;
    zcl_write_u64_le(out + off, frame->deny_mask); off += 8;
    PUT32(frame, signer_online_pubkey);
    memcpy(out + off, frame->signature, 64); off += 64;
    if (off != MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    *out_len = off;
    return MESH_CAPABILITY_PROTO_OK;
}

static enum mesh_capability_proto_error commit_encode(
    const struct mesh_capability_commit_v1 *frame, uint8_t *out,
    size_t out_capacity, size_t *out_len, bool verify_signature)
{
    if (out_len)
        *out_len = 0;
    if (!frame || !out || !out_len)
        return MESH_CAPABILITY_PROTO_NULL;
    enum mesh_capability_proto_error error =
        commit_shape(frame, verify_signature);
    if (error != MESH_CAPABILITY_PROTO_OK)
        return error;
    if (verify_signature &&
        (error = verify_body(MESH_CAPABILITY_FRAME_COMMIT, frame)) !=
            MESH_CAPABILITY_PROTO_OK)
        return error;
    error = frame_begin(MESH_CAPABILITY_FRAME_COMMIT, out, out_capacity,
                        MESH_CAPABILITY_COMMIT_V1_WIRE_BYTES, out_len);
    if (error != MESH_CAPABILITY_PROTO_OK) return error;
    size_t off = 8;
    PUT32(frame, proposal_id); PUT32(frame, proposal_root);
    PUT32(frame, commit_id); PUT32(frame, target_master_pubkey);
    PUT32(frame, subject_master_pubkey); PUT32(frame, transcript_hash);
    zcl_write_u64_le(out + off, frame->connection_generation); off += 8;
    zcl_write_u64_le(out + off, frame->plan_generation); off += 8;
    zcl_write_u64_le(out + off, frame->committed_unix); off += 8;
    PUT32(frame, signer_online_pubkey);
    memcpy(out + off, frame->signature, 64); off += 64;
    if (off != MESH_CAPABILITY_COMMIT_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    *out_len = off;
    return MESH_CAPABILITY_PROTO_OK;
}

static enum mesh_capability_proto_error grant_encode(
    const struct mesh_capability_grant_v1 *frame, uint8_t *out,
    size_t out_capacity, size_t *out_len, bool verify_signature)
{
    if (out_len)
        *out_len = 0;
    if (!frame || !out || !out_len)
        return MESH_CAPABILITY_PROTO_NULL;
    enum mesh_capability_proto_error error =
        grant_shape(frame, verify_signature);
    if (error != MESH_CAPABILITY_PROTO_OK)
        return error;
    if (verify_signature &&
        (error = verify_body(MESH_CAPABILITY_FRAME_GRANT, frame)) !=
            MESH_CAPABILITY_PROTO_OK)
        return error;
    error = frame_begin(MESH_CAPABILITY_FRAME_GRANT, out, out_capacity,
                        MESH_CAPABILITY_GRANT_V1_WIRE_BYTES, out_len);
    if (error != MESH_CAPABILITY_PROTO_OK) return error;
    size_t off = 8;
    PUT32(frame, proposal_id); PUT32(frame, proposal_root);
    PUT32(frame, commit_id); PUT32(frame, grant_id); PUT32(frame, grant_nonce);
    PUT32(frame, target_master_pubkey); PUT32(frame, subject_master_pubkey);
    zcl_write_u64_le(out + off, frame->issued_unix); off += 8;
    zcl_write_u64_le(out + off, frame->not_before_unix); off += 8;
    zcl_write_u64_le(out + off, frame->expires_unix); off += 8;
    zcl_write_u64_le(out + off, frame->revocation_generation); off += 8;
    PUT32(frame, signer_online_pubkey);
    memcpy(out + off, frame->signature, 64); off += 64;
    if (off != MESH_CAPABILITY_GRANT_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    *out_len = off;
    return MESH_CAPABILITY_PROTO_OK;
}

static enum mesh_capability_proto_error refusal_encode(
    const struct mesh_capability_refusal_v1 *frame, uint8_t *out,
    size_t out_capacity, size_t *out_len, bool verify_signature)
{
    if (out_len)
        *out_len = 0;
    if (!frame || !out || !out_len)
        return MESH_CAPABILITY_PROTO_NULL;
    enum mesh_capability_proto_error error =
        refusal_shape(frame, verify_signature);
    if (error != MESH_CAPABILITY_PROTO_OK)
        return error;
    if (verify_signature &&
        (error = verify_body(MESH_CAPABILITY_FRAME_REFUSAL, frame)) !=
            MESH_CAPABILITY_PROTO_OK)
        return error;
    error = frame_begin(MESH_CAPABILITY_FRAME_REFUSAL, out, out_capacity,
                        MESH_CAPABILITY_REFUSAL_V1_WIRE_BYTES, out_len);
    if (error != MESH_CAPABILITY_PROTO_OK) return error;
    size_t off = 8;
    PUT32(frame, request_id); PUT32(frame, request_root);
    PUT32(frame, target_master_pubkey);
    zcl_write_u16_le(out + off, (uint16_t)frame->reason); off += 2;
    zcl_write_u16_le(out + off, 0); off += 2;
    zcl_write_u64_le(out + off, frame->observed_unix); off += 8;
    zcl_write_u64_le(out + off, frame->authority_generation); off += 8;
    PUT32(frame, signer_online_pubkey);
    memcpy(out + off, frame->signature, 64); off += 64;
    if (off != MESH_CAPABILITY_REFUSAL_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    *out_len = off;
    return MESH_CAPABILITY_PROTO_OK;
}

static enum mesh_capability_proto_error renew_encode(
    const struct mesh_capability_renew_v1 *frame, uint8_t *out,
    size_t out_capacity, size_t *out_len, bool verify_signature)
{
    if (out_len)
        *out_len = 0;
    if (!frame || !out || !out_len)
        return MESH_CAPABILITY_PROTO_NULL;
    enum mesh_capability_proto_error error =
        renew_shape(frame, verify_signature);
    if (error != MESH_CAPABILITY_PROTO_OK)
        return error;
    if (verify_signature &&
        (error = verify_body(MESH_CAPABILITY_FRAME_RENEW, frame)) !=
            MESH_CAPABILITY_PROTO_OK)
        return error;
    error = frame_begin(MESH_CAPABILITY_FRAME_RENEW, out, out_capacity,
                        MESH_CAPABILITY_RENEW_V1_WIRE_BYTES, out_len);
    if (error != MESH_CAPABILITY_PROTO_OK) return error;
    size_t off = 8;
    PUT32(frame, request_id); PUT32(frame, prior_grant_id);
    PUT32(frame, replacement_proposal_id);
    PUT32(frame, replacement_proposal_root);
    PUT32(frame, target_master_pubkey); PUT32(frame, subject_master_pubkey);
    zcl_write_u64_le(out + off, frame->requested_not_before_unix); off += 8;
    zcl_write_u64_le(out + off, frame->requested_expires_unix); off += 8;
    zcl_write_u64_le(out + off, frame->revocation_generation); off += 8;
    PUT32(frame, signer_online_pubkey);
    memcpy(out + off, frame->signature, 64); off += 64;
    if (off != MESH_CAPABILITY_RENEW_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    *out_len = off;
    return MESH_CAPABILITY_PROTO_OK;
}

static enum mesh_capability_proto_error cancel_encode(
    const struct mesh_capability_cancel_v1 *frame, uint8_t *out,
    size_t out_capacity, size_t *out_len, bool verify_signature)
{
    if (out_len)
        *out_len = 0;
    if (!frame || !out || !out_len)
        return MESH_CAPABILITY_PROTO_NULL;
    enum mesh_capability_proto_error error =
        cancel_shape(frame, verify_signature);
    if (error != MESH_CAPABILITY_PROTO_OK)
        return error;
    if (verify_signature &&
        (error = verify_body(MESH_CAPABILITY_FRAME_CANCEL, frame)) !=
            MESH_CAPABILITY_PROTO_OK)
        return error;
    error = frame_begin(MESH_CAPABILITY_FRAME_CANCEL, out, out_capacity,
                        MESH_CAPABILITY_CANCEL_V1_WIRE_BYTES, out_len);
    if (error != MESH_CAPABILITY_PROTO_OK) return error;
    size_t off = 8;
    PUT32(frame, cancel_id); PUT32(frame, grant_id); PUT32(frame, operation_id);
    PUT32(frame, target_master_pubkey); PUT32(frame, subject_master_pubkey);
    zcl_write_u64_le(out + off, frame->requested_unix); off += 8;
    PUT32(frame, signer_online_pubkey);
    memcpy(out + off, frame->signature, 64); off += 64;
    if (off != MESH_CAPABILITY_CANCEL_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    *out_len = off;
    return MESH_CAPABILITY_PROTO_OK;
}

static enum mesh_capability_proto_error ack_encode(
    const struct mesh_capability_ack_v1 *frame, uint8_t *out,
    size_t out_capacity, size_t *out_len, bool verify_signature)
{
    if (out_len)
        *out_len = 0;
    if (!frame || !out || !out_len)
        return MESH_CAPABILITY_PROTO_NULL;
    enum mesh_capability_proto_error error =
        ack_shape(frame, verify_signature);
    if (error != MESH_CAPABILITY_PROTO_OK)
        return error;
    if (verify_signature &&
        (error = verify_body(MESH_CAPABILITY_FRAME_ACK, frame)) !=
            MESH_CAPABILITY_PROTO_OK)
        return error;
    error = frame_begin(MESH_CAPABILITY_FRAME_ACK, out, out_capacity,
                        MESH_CAPABILITY_ACK_V1_WIRE_BYTES, out_len);
    if (error != MESH_CAPABILITY_PROTO_OK) return error;
    size_t off = 8;
    PUT32(frame, ack_id); PUT32(frame, request_id); PUT32(frame, request_root);
    PUT32(frame, target_master_pubkey); PUT32(frame, subject_master_pubkey);
    out[off++] = (uint8_t)frame->acknowledged_kind;
    out[off++] = (uint8_t)frame->status;
    zcl_write_u16_le(out + off, 0); off += 2;
    zcl_write_u64_le(out + off, frame->observed_unix); off += 8;
    zcl_write_u64_le(out + off, frame->authority_generation); off += 8;
    PUT32(frame, signer_online_pubkey);
    memcpy(out + off, frame->signature, 64); off += 64;
    if (off != MESH_CAPABILITY_ACK_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    *out_len = off;
    return MESH_CAPABILITY_PROTO_OK;
}

#undef PUT32

static enum mesh_capability_proto_error encode_view_raw(
    const struct mesh_capability_frame_view_v1 *frame, uint8_t *out,
    size_t out_capacity, size_t *out_len, bool verify_signature)
{
    if (!frame)
        return MESH_CAPABILITY_PROTO_NULL;
    switch (frame->kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        return proposal_encode(&frame->body.proposal, out, out_capacity,
                               out_len, verify_signature);
    case MESH_CAPABILITY_FRAME_COMMIT:
        return commit_encode(&frame->body.commit, out, out_capacity, out_len,
                             verify_signature);
    case MESH_CAPABILITY_FRAME_GRANT:
        return grant_encode(&frame->body.grant, out, out_capacity, out_len,
                            verify_signature);
    case MESH_CAPABILITY_FRAME_REFUSAL:
        return refusal_encode(&frame->body.refusal, out, out_capacity, out_len,
                              verify_signature);
    case MESH_CAPABILITY_FRAME_RENEW:
        return renew_encode(&frame->body.renew, out, out_capacity, out_len,
                            verify_signature);
    case MESH_CAPABILITY_FRAME_CANCEL:
        return cancel_encode(&frame->body.cancel, out, out_capacity, out_len,
                             verify_signature);
    case MESH_CAPABILITY_FRAME_ACK:
        return ack_encode(&frame->body.ack, out, out_capacity, out_len,
                          verify_signature);
    }
    return MESH_CAPABILITY_PROTO_KIND_INVALID;
}

static uint8_t *frame_public_key(struct mesh_capability_frame_view_v1 *frame)
{
    switch (frame->kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        return frame->body.proposal.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_COMMIT:
        return frame->body.commit.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_GRANT:
        return frame->body.grant.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_REFUSAL:
        return frame->body.refusal.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_RENEW:
        return frame->body.renew.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_CANCEL:
        return frame->body.cancel.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_ACK:
        return frame->body.ack.signer_online_pubkey;
    }
    return NULL;
}

static uint8_t *frame_signature(struct mesh_capability_frame_view_v1 *frame)
{
    switch (frame->kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL: return frame->body.proposal.signature;
    case MESH_CAPABILITY_FRAME_COMMIT: return frame->body.commit.signature;
    case MESH_CAPABILITY_FRAME_GRANT: return frame->body.grant.signature;
    case MESH_CAPABILITY_FRAME_REFUSAL: return frame->body.refusal.signature;
    case MESH_CAPABILITY_FRAME_RENEW: return frame->body.renew.signature;
    case MESH_CAPABILITY_FRAME_CANCEL: return frame->body.cancel.signature;
    case MESH_CAPABILITY_FRAME_ACK: return frame->body.ack.signature;
    }
    return NULL;
}

static void hash_domain(const char *domain, const uint8_t *wire,
                        size_t wire_len, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    memory_cleanse(&sha, sizeof(sha));
}

static enum mesh_capability_proto_error signing_root(
    const struct mesh_capability_frame_view_v1 *frame, uint8_t out[32])
{
    if (!frame || !out)
        return MESH_CAPABILITY_PROTO_NULL;
    if (frame->kind < MESH_CAPABILITY_FRAME_PROPOSAL ||
        frame->kind > MESH_CAPABILITY_FRAME_ACK)
        return MESH_CAPABILITY_PROTO_KIND_INVALID;
    uint8_t wire[MESH_CAPABILITY_FRAME_V1_MAX];
    size_t wire_len = 0;
    enum mesh_capability_proto_error error = encode_view_raw(
        frame, wire, sizeof(wire), &wire_len, false);
    if (error == MESH_CAPABILITY_PROTO_OK) {
        if (wire_len < 64u)
            error = MESH_CAPABILITY_PROTO_SIZE;
        else
            hash_domain(signing_domains[frame->kind], wire, wire_len - 64u,
                        out);
    }
    memory_cleanse(wire, sizeof(wire));
    return error;
}

static enum mesh_capability_proto_error verify_body(
    enum mesh_capability_frame_kind kind, const void *body)
{
    if (!body)
        return MESH_CAPABILITY_PROTO_NULL;
    struct mesh_capability_frame_view_v1 frame = {.kind = kind};
    size_t body_size = 0;
    switch (kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        body_size = sizeof(frame.body.proposal); break;
    case MESH_CAPABILITY_FRAME_COMMIT:
        body_size = sizeof(frame.body.commit); break;
    case MESH_CAPABILITY_FRAME_GRANT:
        body_size = sizeof(frame.body.grant); break;
    case MESH_CAPABILITY_FRAME_REFUSAL:
        body_size = sizeof(frame.body.refusal); break;
    case MESH_CAPABILITY_FRAME_RENEW:
        body_size = sizeof(frame.body.renew); break;
    case MESH_CAPABILITY_FRAME_CANCEL:
        body_size = sizeof(frame.body.cancel); break;
    case MESH_CAPABILITY_FRAME_ACK:
        body_size = sizeof(frame.body.ack); break;
    default:
        return MESH_CAPABILITY_PROTO_KIND_INVALID;
    }
    memcpy(&frame.body, body, body_size);
    uint8_t root[32];
    enum mesh_capability_proto_error error = signing_root(&frame, root);
    uint8_t *signature = frame_signature(&frame);
    uint8_t *public_key = frame_public_key(&frame);
    bool valid = error == MESH_CAPABILITY_PROTO_OK && signature && public_key &&
                 ed25519_verify(signature, root, sizeof(root), public_key);
    memory_cleanse(root, sizeof(root));
    memory_cleanse(&frame, sizeof(frame));
    return valid ? MESH_CAPABILITY_PROTO_OK :
           error != MESH_CAPABILITY_PROTO_OK ? error
                                             : MESH_CAPABILITY_PROTO_SIGNATURE;
}

enum mesh_capability_proto_error mesh_capability_frame_v1_validate(
    const struct mesh_capability_frame_view_v1 *frame)
{
    if (!frame)
        return MESH_CAPABILITY_PROTO_NULL;
    return verify_body(frame->kind, &frame->body);
}

enum mesh_capability_proto_error mesh_capability_frame_v1_sign(
    struct mesh_capability_frame_view_v1 *frame,
    const uint8_t signer_online_seed[32])
{
    if (!frame || !signer_online_seed)
        return MESH_CAPABILITY_PROTO_NULL;
    uint8_t *public_key = frame_public_key(frame);
    uint8_t *signature = frame_signature(frame);
    if (!public_key || !signature)
        return MESH_CAPABILITY_PROTO_KIND_INVALID;
    memset(signature, 0, 64);
    uint8_t derived_public[32], secret[32], root[32];
    ed25519_keypair(derived_public, secret, signer_online_seed);
    if (memcmp(derived_public, public_key, 32) != 0) {
        memory_cleanse(secret, sizeof(secret));
        return MESH_CAPABILITY_PROTO_KEY_MISMATCH;
    }
    enum mesh_capability_proto_error error = signing_root(frame, root);
    if (error == MESH_CAPABILITY_PROTO_OK)
        ed25519_sign(signature, root, sizeof(root), secret, derived_public);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(root, sizeof(root));
    memory_cleanse(derived_public, sizeof(derived_public));
    return error == MESH_CAPABILITY_PROTO_OK
               ? mesh_capability_frame_v1_validate(frame) : error;
}

enum mesh_capability_proto_error mesh_capability_frame_v1_root(
    const struct mesh_capability_frame_view_v1 *frame, uint8_t out[32])
{
    if (!frame || !out)
        return MESH_CAPABILITY_PROTO_NULL;
    memset(out, 0, 32);
    enum mesh_capability_proto_error error =
        mesh_capability_frame_v1_validate(frame);
    if (error != MESH_CAPABILITY_PROTO_OK)
        return error;
    uint8_t wire[MESH_CAPABILITY_FRAME_V1_MAX];
    size_t wire_len = 0;
    error = encode_view_raw(frame, wire, sizeof(wire), &wire_len, false);
    if (error == MESH_CAPABILITY_PROTO_OK)
        hash_domain(root_domains[frame->kind], wire, wire_len, out);
    memory_cleanse(wire, sizeof(wire));
    return error;
}

#define DEFINE_PUBLIC_ENCODER(name) \
enum mesh_capability_proto_error mesh_capability_##name##_v1_encode( \
    const struct mesh_capability_##name##_v1 *frame, uint8_t *out, \
    size_t out_capacity, size_t *out_len) \
{ \
    return name##_encode(frame, out, out_capacity, out_len, true); \
}

DEFINE_PUBLIC_ENCODER(proposal)
DEFINE_PUBLIC_ENCODER(commit)
DEFINE_PUBLIC_ENCODER(grant)
DEFINE_PUBLIC_ENCODER(refusal)
DEFINE_PUBLIC_ENCODER(renew)
DEFINE_PUBLIC_ENCODER(cancel)
DEFINE_PUBLIC_ENCODER(ack)
#undef DEFINE_PUBLIC_ENCODER

static enum mesh_capability_proto_error decode_header(
    const uint8_t *wire, size_t wire_len,
    enum mesh_capability_frame_kind *kind)
{
    if (wire_len < 8)
        return MESH_CAPABILITY_PROTO_SIZE;
    if (memcmp(wire, frame_magic, sizeof(frame_magic)) != 0)
        return MESH_CAPABILITY_PROTO_MAGIC;
    if (zcl_read_u16_le(wire + 4) != MESH_CAPABILITY_PROTO_VERSION)
        return MESH_CAPABILITY_PROTO_VERSION_INVALID;
    if (wire[7] != MESH_CAPABILITY_PROTO_FLAGS_NONE)
        return MESH_CAPABILITY_PROTO_FLAGS;
    if (wire[6] < MESH_CAPABILITY_FRAME_PROPOSAL ||
        wire[6] > MESH_CAPABILITY_FRAME_ACK)
        return MESH_CAPABILITY_PROTO_KIND_INVALID;
    *kind = (enum mesh_capability_frame_kind)wire[6];
    return MESH_CAPABILITY_PROTO_OK;
}

#define GET32(frame, field) do { \
    memcpy((frame)->field, wire + off, 32); off += 32; \
} while (0)

static enum mesh_capability_proto_error decode_proposal(
    struct mesh_capability_proposal_v1 *frame, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len != MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    size_t off = 8;
    GET32(frame, network_genesis); GET32(frame, proposal_id);
    GET32(frame, target_master_pubkey); GET32(frame, subject_master_pubkey);
    GET32(frame, subject_noise_static); GET32(frame, input_root);
    GET32(frame, nonce); GET32(frame, idempotency_key);
    frame->capability = zcl_read_u64_le(wire + off); off += 8;
    frame->result_mask = zcl_read_u64_le(wire + off); off += 8;
    frame->max_bytes = zcl_read_u64_le(wire + off); off += 8;
    frame->max_cpu_milliseconds = zcl_read_u64_le(wire + off); off += 8;
    frame->max_memory_bytes = zcl_read_u64_le(wire + off); off += 8;
    frame->max_processes = zcl_read_u32_le(wire + off); off += 4;
    frame->max_concurrency = zcl_read_u32_le(wire + off); off += 4;
    frame->max_wall_milliseconds = zcl_read_u64_le(wire + off); off += 8;
    frame->not_before_unix = zcl_read_u64_le(wire + off); off += 8;
    frame->expires_unix = zcl_read_u64_le(wire + off); off += 8;
    frame->deny_mask = zcl_read_u64_le(wire + off); off += 8;
    GET32(frame, signer_online_pubkey);
    memcpy(frame->signature, wire + off, 64); off += 64;
    return off == wire_len ? proposal_shape(frame, true)
                           : MESH_CAPABILITY_PROTO_SIZE;
}

static enum mesh_capability_proto_error decode_commit(
    struct mesh_capability_commit_v1 *frame, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len != MESH_CAPABILITY_COMMIT_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    size_t off = 8;
    GET32(frame, proposal_id); GET32(frame, proposal_root);
    GET32(frame, commit_id); GET32(frame, target_master_pubkey);
    GET32(frame, subject_master_pubkey); GET32(frame, transcript_hash);
    frame->connection_generation = zcl_read_u64_le(wire + off); off += 8;
    frame->plan_generation = zcl_read_u64_le(wire + off); off += 8;
    frame->committed_unix = zcl_read_u64_le(wire + off); off += 8;
    GET32(frame, signer_online_pubkey);
    memcpy(frame->signature, wire + off, 64); off += 64;
    return off == wire_len ? commit_shape(frame, true)
                           : MESH_CAPABILITY_PROTO_SIZE;
}

static enum mesh_capability_proto_error decode_grant(
    struct mesh_capability_grant_v1 *frame, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len != MESH_CAPABILITY_GRANT_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    size_t off = 8;
    GET32(frame, proposal_id); GET32(frame, proposal_root);
    GET32(frame, commit_id); GET32(frame, grant_id); GET32(frame, grant_nonce);
    GET32(frame, target_master_pubkey); GET32(frame, subject_master_pubkey);
    frame->issued_unix = zcl_read_u64_le(wire + off); off += 8;
    frame->not_before_unix = zcl_read_u64_le(wire + off); off += 8;
    frame->expires_unix = zcl_read_u64_le(wire + off); off += 8;
    frame->revocation_generation = zcl_read_u64_le(wire + off); off += 8;
    GET32(frame, signer_online_pubkey);
    memcpy(frame->signature, wire + off, 64); off += 64;
    return off == wire_len ? grant_shape(frame, true)
                           : MESH_CAPABILITY_PROTO_SIZE;
}

static enum mesh_capability_proto_error decode_refusal(
    struct mesh_capability_refusal_v1 *frame, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len != MESH_CAPABILITY_REFUSAL_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    size_t off = 8;
    GET32(frame, request_id); GET32(frame, request_root);
    GET32(frame, target_master_pubkey);
    frame->reason = (enum mesh_capability_refusal_reason)
        zcl_read_u16_le(wire + off); off += 2;
    if (zcl_read_u16_le(wire + off) != 0)
        return MESH_CAPABILITY_PROTO_FLAGS;
    off += 2;
    frame->observed_unix = zcl_read_u64_le(wire + off); off += 8;
    frame->authority_generation = zcl_read_u64_le(wire + off); off += 8;
    GET32(frame, signer_online_pubkey);
    memcpy(frame->signature, wire + off, 64); off += 64;
    return off == wire_len ? refusal_shape(frame, true)
                           : MESH_CAPABILITY_PROTO_SIZE;
}

static enum mesh_capability_proto_error decode_renew(
    struct mesh_capability_renew_v1 *frame, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len != MESH_CAPABILITY_RENEW_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    size_t off = 8;
    GET32(frame, request_id); GET32(frame, prior_grant_id);
    GET32(frame, replacement_proposal_id);
    GET32(frame, replacement_proposal_root);
    GET32(frame, target_master_pubkey); GET32(frame, subject_master_pubkey);
    frame->requested_not_before_unix = zcl_read_u64_le(wire + off); off += 8;
    frame->requested_expires_unix = zcl_read_u64_le(wire + off); off += 8;
    frame->revocation_generation = zcl_read_u64_le(wire + off); off += 8;
    GET32(frame, signer_online_pubkey);
    memcpy(frame->signature, wire + off, 64); off += 64;
    return off == wire_len ? renew_shape(frame, true)
                           : MESH_CAPABILITY_PROTO_SIZE;
}

static enum mesh_capability_proto_error decode_cancel(
    struct mesh_capability_cancel_v1 *frame, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len != MESH_CAPABILITY_CANCEL_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    size_t off = 8;
    GET32(frame, cancel_id); GET32(frame, grant_id); GET32(frame, operation_id);
    GET32(frame, target_master_pubkey); GET32(frame, subject_master_pubkey);
    frame->requested_unix = zcl_read_u64_le(wire + off); off += 8;
    GET32(frame, signer_online_pubkey);
    memcpy(frame->signature, wire + off, 64); off += 64;
    return off == wire_len ? cancel_shape(frame, true)
                           : MESH_CAPABILITY_PROTO_SIZE;
}

static enum mesh_capability_proto_error decode_ack(
    struct mesh_capability_ack_v1 *frame, const uint8_t *wire,
    size_t wire_len)
{
    if (wire_len != MESH_CAPABILITY_ACK_V1_WIRE_BYTES)
        return MESH_CAPABILITY_PROTO_SIZE;
    size_t off = 8;
    GET32(frame, ack_id); GET32(frame, request_id); GET32(frame, request_root);
    GET32(frame, target_master_pubkey); GET32(frame, subject_master_pubkey);
    frame->acknowledged_kind =
        (enum mesh_capability_frame_kind)wire[off++];
    frame->status = (enum mesh_capability_ack_status)wire[off++];
    if (zcl_read_u16_le(wire + off) != 0)
        return MESH_CAPABILITY_PROTO_FLAGS;
    off += 2;
    frame->observed_unix = zcl_read_u64_le(wire + off); off += 8;
    frame->authority_generation = zcl_read_u64_le(wire + off); off += 8;
    GET32(frame, signer_online_pubkey);
    memcpy(frame->signature, wire + off, 64); off += 64;
    return off == wire_len ? ack_shape(frame, true)
                           : MESH_CAPABILITY_PROTO_SIZE;
}

#undef GET32

enum mesh_capability_proto_error mesh_capability_frame_v1_decode(
    struct mesh_capability_frame_view_v1 *out, const uint8_t *wire,
    size_t wire_len)
{
    if (!out)
        return MESH_CAPABILITY_PROTO_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire)
        return MESH_CAPABILITY_PROTO_NULL;
    enum mesh_capability_frame_kind kind;
    enum mesh_capability_proto_error error =
        decode_header(wire, wire_len, &kind);
    if (error != MESH_CAPABILITY_PROTO_OK)
        return error;
    out->kind = kind;
    switch (kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        error = decode_proposal(&out->body.proposal, wire, wire_len); break;
    case MESH_CAPABILITY_FRAME_COMMIT:
        error = decode_commit(&out->body.commit, wire, wire_len); break;
    case MESH_CAPABILITY_FRAME_GRANT:
        error = decode_grant(&out->body.grant, wire, wire_len); break;
    case MESH_CAPABILITY_FRAME_REFUSAL:
        error = decode_refusal(&out->body.refusal, wire, wire_len); break;
    case MESH_CAPABILITY_FRAME_RENEW:
        error = decode_renew(&out->body.renew, wire, wire_len); break;
    case MESH_CAPABILITY_FRAME_CANCEL:
        error = decode_cancel(&out->body.cancel, wire, wire_len); break;
    case MESH_CAPABILITY_FRAME_ACK:
        error = decode_ack(&out->body.ack, wire, wire_len); break;
    default:
        error = MESH_CAPABILITY_PROTO_KIND_INVALID; break;
    }
    if (error == MESH_CAPABILITY_PROTO_OK)
        error = mesh_capability_frame_v1_validate(out);
    if (error != MESH_CAPABILITY_PROTO_OK)
        memset(out, 0, sizeof(*out));
    return error;
}
