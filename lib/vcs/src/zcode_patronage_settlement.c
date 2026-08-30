/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulated patronage settlement and refund receipts. */
#include "vcs/zcode_patronage_settlement.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "vcs/signed_evidence.h"

#include <string.h>

static const uint8_t settlement_magic[8] =
    {'Z','C','P','S','E','T','\r','\n'};

const char *vcs_zcode_patronage_settlement_error_string(
    enum vcs_zcode_patronage_settlement_error error)
{
    switch (error) {
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_OK: return "ok";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL: return "null-argument";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_MAGIC: return "wire-magic";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_SHAPE: return "simulation-shape";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_ROOT: return "required-root";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_AMOUNT: return "amount-mismatch";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME: return "time-order";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_SIGNATURE: return "signature";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_CONTEXT:
        return "validation-context";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT: return "intent-mismatch";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_FUNDING: return "funding-mismatch";
    case VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE:
        return "evidence-mismatch";
    }
    return "unknown";
}

static enum vcs_zcode_patronage_settlement_error settlement_fields(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    bool signed_wire)
{
    if (!settlement) return VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
    uint8_t flags = VCS_ZCODE_PATRONAGE_SETTLEMENT_SIMULATION_ONLY |
        VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_LIVE_FUNDS |
        VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_TRANSACTION_BYTES;
    if (settlement->schema_version !=
            VCS_ZCODE_PATRONAGE_SETTLEMENT_VERSION ||
        (settlement->action != VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED &&
         settlement->action != VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED) ||
        settlement->flags != flags)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_SHAPE;
    const uint8_t *common[] = {
        settlement->network_genesis_root,
        settlement->patronage_intent_root,
        settlement->patronage_funding_root,
        settlement->recipient_contributor_binding_root,
        settlement->settler_zid_pubkey,
    };
    for (size_t i = 0; i < sizeof(common) / sizeof(common[0]); i++)
        if (!zcl_bytes_any_set(common[i], 32))
            return VCS_ZCODE_PATRONAGE_SETTLEMENT_ROOT;
    const uint8_t *evidence[] = {
        settlement->creation_attribution_root, settlement->task_root,
        settlement->candidate_root, settlement->proof_policy_root,
        settlement->proof_set_root, settlement->proven_lane_root,
        settlement->score_receipt_root,
    };
    size_t evidence_count = 0;
    for (size_t i = 0; i < sizeof(evidence) / sizeof(evidence[0]); i++)
        evidence_count += zcl_bytes_any_set(evidence[i], 32) ? 1u : 0u;
    /* Direct gifts carry no proof chain.  Proof-conditioned settlements carry
     * the complete chain; partial evidence can never be canonical. */
    if ((settlement->action == VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED &&
         evidence_count != 0 &&
         evidence_count != sizeof(evidence) / sizeof(evidence[0])) ||
        (settlement->action == VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED &&
         evidence_count != 0))
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_SHAPE;
    if (settlement->amount_atoms == 0)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_AMOUNT;
    if (settlement->created_unix <= 0 || settlement->observed_height == 0 ||
        settlement->observed_mtp <= 0 || settlement->sequence == 0)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME;
    if (signed_wire && !zcl_bytes_any_set(settlement->signature, 64))
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_SIGNATURE;
    return VCS_ZCODE_PATRONAGE_SETTLEMENT_OK;
}

enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_validate(
    const struct vcs_zcode_patronage_settlement_v1 *settlement)
{
    return settlement_fields(settlement, true);
}

static enum vcs_zcode_patronage_settlement_error settlement_body(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    uint8_t out[VCS_ZCODE_PATRONAGE_SETTLEMENT_BODY_BYTES])
{
    enum vcs_zcode_patronage_settlement_error error =
        settlement_fields(settlement, false);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK || !out)
        return out ? error : VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out,
                          VCS_ZCODE_PATRONAGE_SETTLEMENT_BODY_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, settlement_magic, 8) &&
        zcl_codec_write_u16le(&writer, settlement->schema_version) &&
        zcl_codec_write_u8(&writer, settlement->action) &&
        zcl_codec_write_u8(&writer, settlement->flags) &&
        zcl_codec_write_u32le(&writer, 0) &&
        zcl_codec_write_bytes(&writer,
            settlement->network_genesis_root, 32) &&
        zcl_codec_write_bytes(&writer,
            settlement->patronage_intent_root, 32) &&
        zcl_codec_write_bytes(&writer,
            settlement->patronage_funding_root, 32) &&
        zcl_codec_write_bytes(&writer,
            settlement->creation_attribution_root, 32) &&
        zcl_codec_write_bytes(&writer, settlement->task_root, 32) &&
        zcl_codec_write_bytes(&writer, settlement->candidate_root, 32) &&
        zcl_codec_write_bytes(&writer, settlement->proof_policy_root, 32) &&
        zcl_codec_write_bytes(&writer, settlement->proof_set_root, 32) &&
        zcl_codec_write_bytes(&writer, settlement->proven_lane_root, 32) &&
        zcl_codec_write_bytes(&writer, settlement->score_receipt_root, 32) &&
        zcl_codec_write_bytes(&writer,
            settlement->recipient_contributor_binding_root, 32) &&
        zcl_codec_write_bytes(&writer, settlement->settler_zid_pubkey, 32) &&
        zcl_codec_write_u64le(&writer, settlement->amount_atoms) &&
        zcl_codec_write_i64le(&writer, settlement->created_unix) &&
        zcl_codec_write_u64le(&writer, settlement->observed_height) &&
        zcl_codec_write_i64le(&writer, settlement->observed_mtp) &&
        zcl_codec_write_u64le(&writer, settlement->sequence);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_PATRONAGE_SETTLEMENT_BODY_BYTES
        ? VCS_ZCODE_PATRONAGE_SETTLEMENT_OK
        : VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_SIZE;
}

static enum vcs_zcode_patronage_settlement_error settlement_signing_root(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_PATRONAGE_SETTLEMENT_BODY_BYTES];
    enum vcs_zcode_patronage_settlement_error error =
        settlement_body(settlement, body);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK || !out)
        return out ? error : VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
    static const char domain[] = VCS_ZCODE_PATRONAGE_SETTLEMENT_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_PATRONAGE_SETTLEMENT_OK
        : VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
}

enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_serialize(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    uint8_t out[VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
    enum vcs_zcode_patronage_settlement_error error =
        settlement_fields(settlement, true);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) return error;
    error = settlement_body(settlement, out);
    if (error == VCS_ZCODE_PATRONAGE_SETTLEMENT_OK)
        memcpy(out + VCS_ZCODE_PATRONAGE_SETTLEMENT_BODY_BYTES,
               settlement->signature, 64);
    return error;
}

enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_patronage_settlement_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8]; uint32_t reserved = 0;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u8(&reader, &out->action) &&
        zcl_codec_read_u8(&reader, &out->flags) &&
        zcl_codec_read_u32le(&reader, &reserved) &&
        zcl_codec_read_bytes(&reader, out->network_genesis_root, 32) &&
        zcl_codec_read_bytes(&reader, out->patronage_intent_root, 32) &&
        zcl_codec_read_bytes(&reader, out->patronage_funding_root, 32) &&
        zcl_codec_read_bytes(&reader, out->creation_attribution_root, 32) &&
        zcl_codec_read_bytes(&reader, out->task_root, 32) &&
        zcl_codec_read_bytes(&reader, out->candidate_root, 32) &&
        zcl_codec_read_bytes(&reader, out->proof_policy_root, 32) &&
        zcl_codec_read_bytes(&reader, out->proof_set_root, 32) &&
        zcl_codec_read_bytes(&reader, out->proven_lane_root, 32) &&
        zcl_codec_read_bytes(&reader, out->score_receipt_root, 32) &&
        zcl_codec_read_bytes(&reader,
            out->recipient_contributor_binding_root, 32) &&
        zcl_codec_read_bytes(&reader, out->settler_zid_pubkey, 32) &&
        zcl_codec_read_u64le(&reader, &out->amount_atoms) &&
        zcl_codec_read_i64le(&reader, &out->created_unix) &&
        zcl_codec_read_u64le(&reader, &out->observed_height) &&
        zcl_codec_read_i64le(&reader, &out->observed_mtp) &&
        zcl_codec_read_u64le(&reader, &out->sequence) &&
        zcl_codec_read_bytes(&reader, out->signature, 64) &&
        zcl_codec_reader_finish(&reader);
    enum vcs_zcode_patronage_settlement_error error = !ok
        ? VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_SIZE
        : memcmp(magic, settlement_magic, 8) != 0
            ? VCS_ZCODE_PATRONAGE_SETTLEMENT_MAGIC
            : reserved != 0 ? VCS_ZCODE_PATRONAGE_SETTLEMENT_SHAPE
                            : settlement_fields(out, true);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_root(
    const struct vcs_zcode_patronage_settlement_v1 *settlement,
    uint8_t out[32])
{
    if (!out) return VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
    uint8_t wire[VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES];
    enum vcs_zcode_patronage_settlement_error error =
        vcs_zcode_patronage_settlement_serialize(settlement, wire);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) return error;
    static const char domain[] = VCS_ZCODE_PATRONAGE_SETTLEMENT_ROOT_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_PATRONAGE_SETTLEMENT_OK
        : VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
}

enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_seal(
    struct vcs_zcode_patronage_settlement_v1 *settlement,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!settlement || !secret || !pubkey)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
    if (memcmp(settlement->settler_zid_pubkey, pubkey, 32) != 0)
        return VCS_ZCODE_PATRONAGE_SETTLEMENT_SIGNATURE;
    uint8_t root[32];
    enum vcs_zcode_patronage_settlement_error error =
        settlement_signing_root(settlement, root);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) return error;
    return vcs_signed_evidence_seal_root(
               root, secret, pubkey, settlement->signature)
        ? VCS_ZCODE_PATRONAGE_SETTLEMENT_OK
        : VCS_ZCODE_PATRONAGE_SETTLEMENT_NULL;
}

enum vcs_zcode_patronage_settlement_error
vcs_zcode_patronage_settlement_verify(
    const struct vcs_zcode_patronage_settlement_v1 *settlement)
{
    enum vcs_zcode_patronage_settlement_error error =
        settlement_fields(settlement, true);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) return error;
    uint8_t root[32];
    error = settlement_signing_root(settlement, root);
    if (error != VCS_ZCODE_PATRONAGE_SETTLEMENT_OK) return error;
    return vcs_signed_evidence_verify_root(
               root, settlement->signature, settlement->settler_zid_pubkey,
               settlement->settler_zid_pubkey)
        ? VCS_ZCODE_PATRONAGE_SETTLEMENT_OK
        : VCS_ZCODE_PATRONAGE_SETTLEMENT_SIGNATURE;
}
