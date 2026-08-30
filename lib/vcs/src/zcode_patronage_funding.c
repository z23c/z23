/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical fully simulated ZC23 patronage funding receipts. */
#include "vcs/zcode_patronage_funding.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "vcs/signed_evidence.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t funding_magic[8] =
    {'Z','C','P','F','U','N','\r','\n'};

const char *vcs_zcode_patronage_funding_error_string(
    enum vcs_zcode_patronage_funding_error error)
{
    switch (error) {
    case VCS_ZCODE_PATRONAGE_FUNDING_OK: return "ok";
    case VCS_ZCODE_PATRONAGE_FUNDING_NULL: return "null-argument";
    case VCS_ZCODE_PATRONAGE_FUNDING_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_PATRONAGE_FUNDING_MAGIC: return "wire-magic";
    case VCS_ZCODE_PATRONAGE_FUNDING_SHAPE: return "simulation-shape";
    case VCS_ZCODE_PATRONAGE_FUNDING_ROOT: return "required-root";
    case VCS_ZCODE_PATRONAGE_FUNDING_AMOUNT: return "amount-mismatch";
    case VCS_ZCODE_PATRONAGE_FUNDING_TIME: return "time-order";
    case VCS_ZCODE_PATRONAGE_FUNDING_SIGNATURE: return "signature";
    case VCS_ZCODE_PATRONAGE_FUNDING_INTENT: return "intent-mismatch";
    case VCS_ZCODE_PATRONAGE_FUNDING_CONTEXT: return "validation-context";
    }
    return "unknown";
}

enum vcs_zcode_patronage_funding_error
vcs_zcode_patronage_simulation_plan_root(
    const uint8_t patronage_intent_root[32], uint64_t amount_atoms,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!patronage_intent_root || !out)
        return VCS_ZCODE_PATRONAGE_FUNDING_NULL;
    if (!zcl_bytes_any_set(patronage_intent_root, 32))
        return VCS_ZCODE_PATRONAGE_FUNDING_ROOT;
    if (amount_atoms == 0) return VCS_ZCODE_PATRONAGE_FUNDING_AMOUNT;
    uint8_t amount[8]; zcl_write_u64_le(amount, amount_atoms);
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_PATRONAGE_SIMULATION_PLAN_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, patronage_intent_root, 32);
    sha3_256_write(&sha, amount, sizeof(amount));
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_PATRONAGE_FUNDING_OK;
}

static enum vcs_zcode_patronage_funding_error funding_fields(
    const struct vcs_zcode_patronage_funding_v1 *funding, bool signed_wire)
{
    if (!funding) return VCS_ZCODE_PATRONAGE_FUNDING_NULL;
    if (funding->schema_version != VCS_ZCODE_PATRONAGE_FUNDING_VERSION ||
        funding->funding_kind !=
            VCS_ZCODE_PATRONAGE_FUNDING_FULLY_SIMULATED ||
        funding->flags != (VCS_ZCODE_PATRONAGE_FUNDING_NO_LIVE_FUNDS |
                           VCS_ZCODE_PATRONAGE_FUNDING_NO_TRANSACTION_BYTES))
        return VCS_ZCODE_PATRONAGE_FUNDING_SHAPE;
    const uint8_t *roots[] = {
        funding->network_genesis_root, funding->patronage_intent_root,
        funding->simulation_plan_root,
        funding->funder_contributor_binding_root, funding->funder_zid_pubkey,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_PATRONAGE_FUNDING_ROOT;
    if (funding->amount_atoms == 0)
        return VCS_ZCODE_PATRONAGE_FUNDING_AMOUNT;
    if (funding->created_unix <= 0 || funding->sequence == 0)
        return VCS_ZCODE_PATRONAGE_FUNDING_TIME;
    uint8_t expected[32];
    if (vcs_zcode_patronage_simulation_plan_root(
            funding->patronage_intent_root, funding->amount_atoms,
            expected) != VCS_ZCODE_PATRONAGE_FUNDING_OK ||
        memcmp(expected, funding->simulation_plan_root, 32) != 0)
        return VCS_ZCODE_PATRONAGE_FUNDING_ROOT;
    if (signed_wire && !zcl_bytes_any_set(funding->signature, 32))
        return VCS_ZCODE_PATRONAGE_FUNDING_SIGNATURE;
    return VCS_ZCODE_PATRONAGE_FUNDING_OK;
}

enum vcs_zcode_patronage_funding_error
vcs_zcode_patronage_funding_validate(
    const struct vcs_zcode_patronage_funding_v1 *funding)
{
    return funding_fields(funding, true);
}

static enum vcs_zcode_patronage_funding_error funding_body(
    const struct vcs_zcode_patronage_funding_v1 *funding,
    uint8_t out[VCS_ZCODE_PATRONAGE_FUNDING_BODY_BYTES])
{
    enum vcs_zcode_patronage_funding_error error =
        funding_fields(funding, false);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK || !out)
        return out ? error : VCS_ZCODE_PATRONAGE_FUNDING_NULL;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_PATRONAGE_FUNDING_BODY_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, funding_magic, 8) &&
        zcl_codec_write_u16le(&writer, funding->schema_version) &&
        zcl_codec_write_u8(&writer, funding->funding_kind) &&
        zcl_codec_write_u8(&writer, funding->flags) &&
        zcl_codec_write_u32le(&writer, 0) &&
        zcl_codec_write_bytes(&writer, funding->network_genesis_root, 32) &&
        zcl_codec_write_bytes(&writer, funding->patronage_intent_root, 32) &&
        zcl_codec_write_bytes(&writer, funding->simulation_plan_root, 32) &&
        zcl_codec_write_bytes(&writer,
            funding->funder_contributor_binding_root, 32) &&
        zcl_codec_write_bytes(&writer, funding->funder_zid_pubkey, 32) &&
        zcl_codec_write_u64le(&writer, funding->amount_atoms) &&
        zcl_codec_write_i64le(&writer, funding->created_unix) &&
        zcl_codec_write_u64le(&writer, funding->sequence);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_PATRONAGE_FUNDING_BODY_BYTES
        ? VCS_ZCODE_PATRONAGE_FUNDING_OK
        : VCS_ZCODE_PATRONAGE_FUNDING_WIRE_SIZE;
}

static enum vcs_zcode_patronage_funding_error funding_signing_root(
    const struct vcs_zcode_patronage_funding_v1 *funding, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_PATRONAGE_FUNDING_BODY_BYTES];
    enum vcs_zcode_patronage_funding_error error =
        funding_body(funding, body);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK || !out)
        return out ? error : VCS_ZCODE_PATRONAGE_FUNDING_NULL;
    static const char domain[] = VCS_ZCODE_PATRONAGE_FUNDING_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_PATRONAGE_FUNDING_OK
        : VCS_ZCODE_PATRONAGE_FUNDING_NULL;
}

enum vcs_zcode_patronage_funding_error
vcs_zcode_patronage_funding_serialize(
    const struct vcs_zcode_patronage_funding_v1 *funding,
    uint8_t out[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_PATRONAGE_FUNDING_NULL;
    enum vcs_zcode_patronage_funding_error error =
        funding_fields(funding, true);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK) return error;
    error = funding_body(funding, out);
    if (error == VCS_ZCODE_PATRONAGE_FUNDING_OK)
        memcpy(out + VCS_ZCODE_PATRONAGE_FUNDING_BODY_BYTES,
               funding->signature, 64);
    return error;
}

enum vcs_zcode_patronage_funding_error vcs_zcode_patronage_funding_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_patronage_funding_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_PATRONAGE_FUNDING_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES)
        return VCS_ZCODE_PATRONAGE_FUNDING_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8]; uint32_t reserved = 0;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u8(&reader, &out->funding_kind) &&
        zcl_codec_read_u8(&reader, &out->flags) &&
        zcl_codec_read_u32le(&reader, &reserved) &&
        zcl_codec_read_bytes(&reader, out->network_genesis_root, 32) &&
        zcl_codec_read_bytes(&reader, out->patronage_intent_root, 32) &&
        zcl_codec_read_bytes(&reader, out->simulation_plan_root, 32) &&
        zcl_codec_read_bytes(&reader,
            out->funder_contributor_binding_root, 32) &&
        zcl_codec_read_bytes(&reader, out->funder_zid_pubkey, 32) &&
        zcl_codec_read_u64le(&reader, &out->amount_atoms) &&
        zcl_codec_read_i64le(&reader, &out->created_unix) &&
        zcl_codec_read_u64le(&reader, &out->sequence) &&
        zcl_codec_read_bytes(&reader, out->signature, 64) &&
        zcl_codec_reader_finish(&reader);
    enum vcs_zcode_patronage_funding_error error = !ok
        ? VCS_ZCODE_PATRONAGE_FUNDING_WIRE_SIZE
        : memcmp(magic, funding_magic, 8) != 0
            ? VCS_ZCODE_PATRONAGE_FUNDING_MAGIC
            : reserved != 0 ? VCS_ZCODE_PATRONAGE_FUNDING_SHAPE
                            : funding_fields(out, true);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_patronage_funding_error vcs_zcode_patronage_funding_root(
    const struct vcs_zcode_patronage_funding_v1 *funding, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_PATRONAGE_FUNDING_NULL;
    uint8_t wire[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES];
    enum vcs_zcode_patronage_funding_error error =
        vcs_zcode_patronage_funding_serialize(funding, wire);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK) return error;
    static const char domain[] = VCS_ZCODE_PATRONAGE_FUNDING_ROOT_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_PATRONAGE_FUNDING_OK
        : VCS_ZCODE_PATRONAGE_FUNDING_NULL;
}

enum vcs_zcode_patronage_funding_error vcs_zcode_patronage_funding_seal(
    struct vcs_zcode_patronage_funding_v1 *funding,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!funding || !secret || !pubkey)
        return VCS_ZCODE_PATRONAGE_FUNDING_NULL;
    if (memcmp(funding->funder_zid_pubkey, pubkey, 32) != 0)
        return VCS_ZCODE_PATRONAGE_FUNDING_SIGNATURE;
    uint8_t root[32];
    enum vcs_zcode_patronage_funding_error error =
        funding_signing_root(funding, root);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK) return error;
    return vcs_signed_evidence_seal_root(
               root, secret, pubkey, funding->signature)
        ? VCS_ZCODE_PATRONAGE_FUNDING_OK
        : VCS_ZCODE_PATRONAGE_FUNDING_NULL;
}

enum vcs_zcode_patronage_funding_error vcs_zcode_patronage_funding_verify(
    const struct vcs_zcode_patronage_funding_v1 *funding)
{
    enum vcs_zcode_patronage_funding_error error =
        funding_fields(funding, true);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK) return error;
    uint8_t root[32];
    error = funding_signing_root(funding, root);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK) return error;
    return vcs_signed_evidence_verify_root(
               root, funding->signature, funding->funder_zid_pubkey,
               funding->funder_zid_pubkey)
        ? VCS_ZCODE_PATRONAGE_FUNDING_OK
        : VCS_ZCODE_PATRONAGE_FUNDING_SIGNATURE;
}

enum vcs_zcode_patronage_funding_error
vcs_zcode_patronage_funding_verify_cas(
    const struct vcs_zcode_patronage_funding_v1 *funding,
    const struct vcs_zcode_patronage_validation_context *context)
{
    enum vcs_zcode_patronage_funding_error error =
        vcs_zcode_patronage_funding_verify(funding);
    if (error != VCS_ZCODE_PATRONAGE_FUNDING_OK) return error;
    if (!context || !context->workspace ||
        !context->expected_network_genesis_root || context->now_unix <= 0)
        return VCS_ZCODE_PATRONAGE_FUNDING_CONTEXT;
    if (funding->created_unix > context->now_unix)
        return VCS_ZCODE_PATRONAGE_FUNDING_TIME;
    uint8_t *wire = NULL, derived[32]; size_t wire_len = 0;
    struct vcs_zcode_patronage_intent_v1 intent;
    if (vcs_object_load_raw_bounded(
            context->workspace, funding->patronage_intent_root,
            VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES,
            &wire, &wire_len) != 0 ||
        vcs_zcode_patronage_intent_parse(wire, wire_len, &intent) !=
            VCS_ZCODE_PATRONAGE_OK ||
        vcs_zcode_patronage_intent_root(&intent, derived) !=
            VCS_ZCODE_PATRONAGE_OK ||
        memcmp(derived, funding->patronage_intent_root, 32) != 0 ||
        vcs_zcode_patronage_intent_verify_cas(&intent, context) !=
            VCS_ZCODE_PATRONAGE_OK) {
        free(wire);
        return VCS_ZCODE_PATRONAGE_FUNDING_INTENT;
    }
    free(wire);
    if (intent.settlement_trust_mode !=
            VCS_ZCODE_PATRONAGE_SIMULATED_FUNDING ||
        memcmp(intent.network_genesis_root,
               funding->network_genesis_root, 32) != 0 ||
        memcmp(intent.patron_contributor_binding_root,
               funding->funder_contributor_binding_root, 32) != 0 ||
        memcmp(intent.patron_zid_pubkey,
               funding->funder_zid_pubkey, 32) != 0)
        return VCS_ZCODE_PATRONAGE_FUNDING_INTENT;
    if (intent.amount_atoms != funding->amount_atoms)
        return VCS_ZCODE_PATRONAGE_FUNDING_AMOUNT;
    if (funding->created_unix < intent.created_unix ||
        funding->created_unix >= intent.expires_unix)
        return VCS_ZCODE_PATRONAGE_FUNDING_TIME;
    return VCS_ZCODE_PATRONAGE_FUNDING_OK;
}
