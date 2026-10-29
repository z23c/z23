/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only ZC23 patronage intents. */
#include "vcs/zcode_patronage.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "vcs/signed_evidence.h"

#include <string.h>

static const uint8_t patronage_magic[8] =
    {'Z','C','P','A','T','R','\r','\n'};

static const struct {
    enum vcs_zcode_patronage_error error;
    const char *name;
} patronage_error_names[] = {
    {VCS_ZCODE_PATRONAGE_OK, "ok"},
    {VCS_ZCODE_PATRONAGE_NULL, "null-argument"},
    {VCS_ZCODE_PATRONAGE_WIRE_SIZE, "wire-size"},
    {VCS_ZCODE_PATRONAGE_MAGIC, "wire-magic"},
    {VCS_ZCODE_PATRONAGE_VERSION, "schema-version"},
    {VCS_ZCODE_PATRONAGE_ENUM, "closed-enum"},
    {VCS_ZCODE_PATRONAGE_FLAGS, "authority-or-simulation-flags"},
    {VCS_ZCODE_PATRONAGE_ROOT, "required-root"},
    {VCS_ZCODE_PATRONAGE_AMOUNT, "amount"},
    {VCS_ZCODE_PATRONAGE_TIME, "time-order"},
    {VCS_ZCODE_PATRONAGE_SEQUENCE, "sequence"},
    {VCS_ZCODE_PATRONAGE_SHAPE, "mode-shape"},
    {VCS_ZCODE_PATRONAGE_SIGNATURE, "signature"},
    {VCS_ZCODE_PATRONAGE_CONTEXT, "validation-context"},
    {VCS_ZCODE_PATRONAGE_CAS, "canonical-cas"},
    {VCS_ZCODE_PATRONAGE_NETWORK, "network-mismatch"},
    {VCS_ZCODE_PATRONAGE_CONTRIBUTOR, "contributor-binding"},
    {VCS_ZCODE_PATRONAGE_TASK, "task-binding"},
    {VCS_ZCODE_PATRONAGE_POLICY, "proof-policy-binding"},
    {VCS_ZCODE_PATRONAGE_TARGET, "target-binding"},
};

const char *vcs_zcode_patronage_error_string(
    enum vcs_zcode_patronage_error error)
{
    for (size_t i = 0;
         i < sizeof(patronage_error_names) / sizeof(patronage_error_names[0]);
         i++)
        if (patronage_error_names[i].error == error)
            return patronage_error_names[i].name;
    return "unknown";
}

static enum vcs_zcode_patronage_error patronage_enum_error(
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    if (intent->mode < VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION ||
        intent->mode > VCS_ZCODE_PATRONAGE_DIRECT_GIFT ||
        intent->target_kind < VCS_ZCODE_PATRONAGE_TARGET_TASK ||
        intent->target_kind > VCS_ZCODE_PATRONAGE_TARGET_CONTRIBUTOR ||
        intent->settlement_trust_mode < VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER ||
        intent->settlement_trust_mode >
            VCS_ZCODE_PATRONAGE_FUTURE_ASSISTED_2OF3)
        return VCS_ZCODE_PATRONAGE_ENUM;
    return VCS_ZCODE_PATRONAGE_OK;
}

static enum vcs_zcode_patronage_error patronage_flags_error(
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    uint8_t allowed = VCS_ZCODE_PATRONAGE_NO_AUTHORITY |
        VCS_ZCODE_PATRONAGE_ANONYMOUS_DISPLAY |
        VCS_ZCODE_PATRONAGE_SIMULATION_ONLY;
    if ((intent->flags & ~allowed) != 0 ||
        (intent->flags & VCS_ZCODE_PATRONAGE_NO_AUTHORITY) == 0 ||
        (intent->flags & VCS_ZCODE_PATRONAGE_SIMULATION_ONLY) == 0)
        return VCS_ZCODE_PATRONAGE_FLAGS;
    return VCS_ZCODE_PATRONAGE_OK;
}

static enum vcs_zcode_patronage_error patronage_head_error(
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    if (!intent) return VCS_ZCODE_PATRONAGE_NULL;
    if (intent->schema_version != VCS_ZCODE_PATRONAGE_INTENT_VERSION)
        return VCS_ZCODE_PATRONAGE_VERSION;
    enum vcs_zcode_patronage_error error = patronage_enum_error(intent);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    return patronage_flags_error(intent);
}

static enum vcs_zcode_patronage_error patronage_root_time_error(
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    const uint8_t *required[] = {
        intent->network_genesis_root,
        intent->zc23_token_or_simulation_root,
        intent->patron_contributor_binding_root, intent->patron_zid_pubkey,
        intent->target_root, intent->intended_recipient_binding_root,
    };
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++)
        if (!zcl_bytes_any_set(required[i], 32)) return VCS_ZCODE_PATRONAGE_ROOT;
    if (intent->amount_atoms == 0) return VCS_ZCODE_PATRONAGE_AMOUNT;
    if (intent->sequence == 0) return VCS_ZCODE_PATRONAGE_SEQUENCE;
    if (intent->created_unix <= 0 ||
        intent->expires_unix <= intent->created_unix)
        return VCS_ZCODE_PATRONAGE_TIME;
    return VCS_ZCODE_PATRONAGE_OK;
}

static enum vcs_zcode_patronage_error patronage_exact_shape_error(
    const struct vcs_zcode_patronage_intent_v1 *intent, bool task, bool policy)
{
    if (intent->target_kind != VCS_ZCODE_PATRONAGE_TARGET_TASK ||
        !task || !policy || memcmp(intent->target_root,
                                  intent->task_root, 32) != 0)
        return VCS_ZCODE_PATRONAGE_SHAPE;
    return VCS_ZCODE_PATRONAGE_OK;
}

static enum vcs_zcode_patronage_error patronage_shape_error(
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    bool task = zcl_bytes_any_set(intent->task_root, 32);
    bool policy = zcl_bytes_any_set(intent->proof_policy_root, 32);
    if (intent->mode == VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION)
        return patronage_exact_shape_error(intent, task, policy);
    if (intent->mode == VCS_ZCODE_PATRONAGE_PACKAGE_CONTINUITY) {
        if (intent->target_kind != VCS_ZCODE_PATRONAGE_TARGET_PACKAGE ||
            task || !policy)
            return VCS_ZCODE_PATRONAGE_SHAPE;
        return VCS_ZCODE_PATRONAGE_OK;
    }
    if (intent->target_kind == VCS_ZCODE_PATRONAGE_TARGET_TASK ||
        task || policy)
        return VCS_ZCODE_PATRONAGE_SHAPE;
    return VCS_ZCODE_PATRONAGE_OK;
}

static enum vcs_zcode_patronage_error patronage_refund_error(
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    if (intent->mode != VCS_ZCODE_PATRONAGE_DIRECT_GIFT &&
        (intent->refund_height == 0 ||
         intent->refund_unix < intent->expires_unix))
        return VCS_ZCODE_PATRONAGE_TIME;
    if (intent->mode == VCS_ZCODE_PATRONAGE_DIRECT_GIFT &&
        (intent->refund_height != 0 || intent->refund_unix != 0))
        return VCS_ZCODE_PATRONAGE_SHAPE;
    return VCS_ZCODE_PATRONAGE_OK;
}

static enum vcs_zcode_patronage_error patronage_fields(
    const struct vcs_zcode_patronage_intent_v1 *intent, bool signed_wire)
{
    enum vcs_zcode_patronage_error error = patronage_head_error(intent);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    error = patronage_root_time_error(intent);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    error = patronage_shape_error(intent);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    error = patronage_refund_error(intent);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    if (signed_wire && !zcl_bytes_any_set(intent->signature, 32))
        return VCS_ZCODE_PATRONAGE_SIGNATURE;
    return VCS_ZCODE_PATRONAGE_OK;
}

enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_validate(
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    return patronage_fields(intent, true);
}

static bool patronage_write_header(struct zcl_codec_writer *writer,
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    return zcl_codec_write_bytes(writer, patronage_magic, 8) &&
        zcl_codec_write_u16le(writer, intent->schema_version) &&
        zcl_codec_write_u8(writer, intent->mode) &&
        zcl_codec_write_u8(writer, intent->target_kind) &&
        zcl_codec_write_u8(writer, intent->settlement_trust_mode) &&
        zcl_codec_write_u8(writer, intent->flags) &&
        zcl_codec_write_u16le(writer, 0);
}

static bool patronage_write_roots(struct zcl_codec_writer *writer,
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    return zcl_codec_write_bytes(writer, intent->network_genesis_root, 32) &&
        zcl_codec_write_bytes(writer,
            intent->zc23_token_or_simulation_root, 32) &&
        zcl_codec_write_bytes(writer,
            intent->patron_contributor_binding_root, 32) &&
        zcl_codec_write_bytes(writer, intent->patron_zid_pubkey, 32) &&
        zcl_codec_write_bytes(writer, intent->target_root, 32) &&
        zcl_codec_write_bytes(writer, intent->task_root, 32) &&
        zcl_codec_write_bytes(writer, intent->proof_policy_root, 32) &&
        zcl_codec_write_bytes(writer,
            intent->intended_recipient_binding_root, 32);
}

static bool patronage_write_tail(struct zcl_codec_writer *writer,
    const struct vcs_zcode_patronage_intent_v1 *intent)
{
    return zcl_codec_write_u64le(writer, intent->amount_atoms) &&
        zcl_codec_write_i64le(writer, intent->created_unix) &&
        zcl_codec_write_i64le(writer, intent->expires_unix) &&
        zcl_codec_write_u64le(writer, intent->refund_height) &&
        zcl_codec_write_i64le(writer, intent->refund_unix) &&
        zcl_codec_write_u64le(writer, intent->sequence) &&
        zcl_codec_write_u64le(writer, intent->maximum_zcl_fee_zat);
}

static enum vcs_zcode_patronage_error patronage_body(
    const struct vcs_zcode_patronage_intent_v1 *intent,
    uint8_t out[VCS_ZCODE_PATRONAGE_INTENT_BODY_BYTES])
{
    enum vcs_zcode_patronage_error error = patronage_fields(intent, false);
    if (error != VCS_ZCODE_PATRONAGE_OK || !out)
        return out ? error : VCS_ZCODE_PATRONAGE_NULL;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_PATRONAGE_INTENT_BODY_BYTES);
    bool ok = patronage_write_header(&writer, intent) &&
        patronage_write_roots(&writer, intent) &&
        patronage_write_tail(&writer, intent);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_PATRONAGE_INTENT_BODY_BYTES
        ? VCS_ZCODE_PATRONAGE_OK : VCS_ZCODE_PATRONAGE_WIRE_SIZE;
}

enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_signing_root(
    const struct vcs_zcode_patronage_intent_v1 *intent, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_PATRONAGE_NULL;
    uint8_t body[VCS_ZCODE_PATRONAGE_INTENT_BODY_BYTES];
    enum vcs_zcode_patronage_error error = patronage_body(intent, body);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    static const char domain[] = VCS_ZCODE_PATRONAGE_INTENT_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_PATRONAGE_OK : VCS_ZCODE_PATRONAGE_NULL;
}

enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_serialize(
    const struct vcs_zcode_patronage_intent_v1 *intent,
    uint8_t out[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_PATRONAGE_NULL;
    enum vcs_zcode_patronage_error error = patronage_fields(intent, true);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    error = patronage_body(intent, out);
    if (error == VCS_ZCODE_PATRONAGE_OK)
        memcpy(out + VCS_ZCODE_PATRONAGE_INTENT_BODY_BYTES,
               intent->signature, 64);
    return error;
}

static bool patronage_read_header(struct zcl_codec_reader *reader,
    struct vcs_zcode_patronage_intent_v1 *out, uint8_t magic[8],
    uint16_t *reserved)
{
    return zcl_codec_read_bytes(reader, magic, 8) &&
        zcl_codec_read_u16le(reader, &out->schema_version) &&
        zcl_codec_read_u8(reader, &out->mode) &&
        zcl_codec_read_u8(reader, &out->target_kind) &&
        zcl_codec_read_u8(reader, &out->settlement_trust_mode) &&
        zcl_codec_read_u8(reader, &out->flags) &&
        zcl_codec_read_u16le(reader, reserved);
}

static bool patronage_read_roots(struct zcl_codec_reader *reader,
    struct vcs_zcode_patronage_intent_v1 *out)
{
    return zcl_codec_read_bytes(reader, out->network_genesis_root, 32) &&
        zcl_codec_read_bytes(reader,
            out->zc23_token_or_simulation_root, 32) &&
        zcl_codec_read_bytes(reader,
            out->patron_contributor_binding_root, 32) &&
        zcl_codec_read_bytes(reader, out->patron_zid_pubkey, 32) &&
        zcl_codec_read_bytes(reader, out->target_root, 32) &&
        zcl_codec_read_bytes(reader, out->task_root, 32) &&
        zcl_codec_read_bytes(reader, out->proof_policy_root, 32) &&
        zcl_codec_read_bytes(reader,
            out->intended_recipient_binding_root, 32);
}

static bool patronage_read_tail(struct zcl_codec_reader *reader,
    struct vcs_zcode_patronage_intent_v1 *out)
{
    return zcl_codec_read_u64le(reader, &out->amount_atoms) &&
        zcl_codec_read_i64le(reader, &out->created_unix) &&
        zcl_codec_read_i64le(reader, &out->expires_unix) &&
        zcl_codec_read_u64le(reader, &out->refund_height) &&
        zcl_codec_read_i64le(reader, &out->refund_unix) &&
        zcl_codec_read_u64le(reader, &out->sequence) &&
        zcl_codec_read_u64le(reader, &out->maximum_zcl_fee_zat) &&
        zcl_codec_read_bytes(reader, out->signature, 64) &&
        zcl_codec_reader_finish(reader);
}

enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_patronage_intent_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_PATRONAGE_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES)
        return VCS_ZCODE_PATRONAGE_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8]; uint16_t reserved = 0;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = patronage_read_header(&reader, out, magic, &reserved) &&
        patronage_read_roots(&reader, out) &&
        patronage_read_tail(&reader, out);
    enum vcs_zcode_patronage_error error = !ok
        ? VCS_ZCODE_PATRONAGE_WIRE_SIZE
        : memcmp(magic, patronage_magic, 8) != 0
            ? VCS_ZCODE_PATRONAGE_MAGIC
            : reserved != 0 ? VCS_ZCODE_PATRONAGE_SHAPE
                            : patronage_fields(out, true);
    if (error != VCS_ZCODE_PATRONAGE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_root(
    const struct vcs_zcode_patronage_intent_v1 *intent, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_PATRONAGE_NULL;
    uint8_t wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES];
    enum vcs_zcode_patronage_error error =
        vcs_zcode_patronage_intent_serialize(intent, wire);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    static const char domain[] = VCS_ZCODE_PATRONAGE_INTENT_ROOT_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_PATRONAGE_OK : VCS_ZCODE_PATRONAGE_NULL;
}

enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_seal(
    struct vcs_zcode_patronage_intent_v1 *intent,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!intent || !secret || !pubkey) return VCS_ZCODE_PATRONAGE_NULL;
    if (memcmp(intent->patron_zid_pubkey, pubkey, 32) != 0)
        return VCS_ZCODE_PATRONAGE_SIGNATURE;
    uint8_t root[32];
    enum vcs_zcode_patronage_error error =
        vcs_zcode_patronage_intent_signing_root(intent, root);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    return vcs_signed_evidence_seal_root(
               root, secret, pubkey, intent->signature)
        ? VCS_ZCODE_PATRONAGE_OK : VCS_ZCODE_PATRONAGE_NULL;
}

enum vcs_zcode_patronage_error vcs_zcode_patronage_intent_verify(
    const struct vcs_zcode_patronage_intent_v1 *intent, int64_t now_unix)
{
    enum vcs_zcode_patronage_error error = patronage_fields(intent, true);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    if (now_unix < intent->created_unix || now_unix >= intent->expires_unix)
        return VCS_ZCODE_PATRONAGE_TIME;
    uint8_t root[32];
    error = vcs_zcode_patronage_intent_signing_root(intent, root);
    if (error != VCS_ZCODE_PATRONAGE_OK) return error;
    return vcs_signed_evidence_verify_root(
               root, intent->signature, intent->patron_zid_pubkey,
               intent->patron_zid_pubkey)
        ? VCS_ZCODE_PATRONAGE_OK : VCS_ZCODE_PATRONAGE_SIGNATURE;
}
