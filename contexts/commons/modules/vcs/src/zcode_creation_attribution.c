/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical factual attribution for policy-eligible ZC23 creation. */
#include "vcs/zcode_creation_attribution.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"

#include <limits.h>
#include <stdbool.h>
#include <string.h>

static const uint8_t creation_magic[8] = {
    'Z', 'C', 'C', 'R', 'E', 'A', '\r', '\n'
};

static bool creation_root_zero(const uint8_t root[32])
{
    return !zcl_bytes_any_set(root, 32);
}

struct creation_error_name {
    enum vcs_zcode_creation_error error;
    const char *message;
};

static const struct creation_error_name creation_error_names[] = {
    { VCS_ZCODE_CREATION_OK, "ok" },
    { VCS_ZCODE_CREATION_NULL, "null-argument" },
    { VCS_ZCODE_CREATION_WIRE_SIZE, "wire-size" },
    { VCS_ZCODE_CREATION_MAGIC, "wire-magic" },
    { VCS_ZCODE_CREATION_VERSION, "schema-version" },
    { VCS_ZCODE_CREATION_RESERVED, "reserved-byte" },
    { VCS_ZCODE_CREATION_CATEGORY, "creation-category" },
    { VCS_ZCODE_CREATION_LINEAGE, "creation-lineage" },
    { VCS_ZCODE_CREATION_ROOT, "zero-authority-root" },
    { VCS_ZCODE_CREATION_AMOUNT, "award-amount" },
    { VCS_ZCODE_CREATION_TIME, "challenge-time" },
    { VCS_ZCODE_CREATION_OVERFLOW, "checked-overflow" },
    { VCS_ZCODE_CREATION_CONTEXT, "validation-context" },
    { VCS_ZCODE_CREATION_CAS, "cas-object" },
    { VCS_ZCODE_CREATION_NETWORK, "network-genesis-mismatch" },
    { VCS_ZCODE_CREATION_POLICY, "zc23-policy-mismatch" },
    { VCS_ZCODE_CREATION_EPOCH, "epoch-mismatch" },
    { VCS_ZCODE_CREATION_CONTRIBUTOR, "contributor-binding" },
    { VCS_ZCODE_CREATION_TASK, "task-object" },
    { VCS_ZCODE_CREATION_CANDIDATE, "candidate-object" },
    { VCS_ZCODE_CREATION_PROOF_POLICY, "proof-policy-object" },
    { VCS_ZCODE_CREATION_PROOF_SET, "proof-set-object" },
    { VCS_ZCODE_CREATION_LANE, "proven-lane-object" },
    { VCS_ZCODE_CREATION_SCORE, "score-receipt-object" },
    { VCS_ZCODE_CREATION_PACKAGE, "package-object" },
    { VCS_ZCODE_CREATION_RELEASE, "release-object" },
    { VCS_ZCODE_CREATION_LICENSE, "license-evidence" },
    { VCS_ZCODE_CREATION_CONTINUITY, "continuity-policy-or-event" },
    { VCS_ZCODE_CREATION_IMMATURE, "challenge-immature" },
    { VCS_ZCODE_CREATION_REORG, "challenge-anchor-reorged" },
    { VCS_ZCODE_CREATION_DUPLICATE, "duplicate-contribution" },
};

const char *vcs_zcode_creation_error_string(
    enum vcs_zcode_creation_error error)
{
    for (size_t i = 0;
         i < sizeof(creation_error_names) / sizeof(creation_error_names[0]);
         i++) {
        if (creation_error_names[i].error == error)
            return creation_error_names[i].message;
    }
    return "unknown-creation-error";
}

static enum vcs_zcode_creation_error creation_validate_shape(
    const struct vcs_zcode_creation_attribution_v1 *a)
{
    if (!a)
        return VCS_ZCODE_CREATION_NULL;
    if (a->schema_version != VCS_ZCODE_CREATION_ATTRIBUTION_VERSION)
        return VCS_ZCODE_CREATION_VERSION;
    if (a->category < VCS_ZCODE_CREATION_PUBLIC_SOURCE ||
        a->category > VCS_ZCODE_CREATION_PRESERVATION)
        return VCS_ZCODE_CREATION_CATEGORY;
    if (a->lineage_kind > VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY)
        return VCS_ZCODE_CREATION_LINEAGE;
    if ((a->lineage_kind == VCS_ZCODE_CREATION_LINEAGE_NONE) !=
        creation_root_zero(a->lineage_root))
        return VCS_ZCODE_CREATION_LINEAGE;
    if (a->category == VCS_ZCODE_CREATION_PUBLIC_SOURCE &&
        a->lineage_kind ==
            VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY)
        return VCS_ZCODE_CREATION_LINEAGE;
    if (a->category != VCS_ZCODE_CREATION_PUBLIC_SOURCE &&
        a->lineage_kind == VCS_ZCODE_CREATION_LINEAGE_NONE)
        return VCS_ZCODE_CREATION_LINEAGE;
    return VCS_ZCODE_CREATION_OK;
}

static enum vcs_zcode_creation_error creation_validate_award_roots(
    const struct vcs_zcode_creation_attribution_v1 *a)
{
    if (a->award_atoms == 0 ||
        a->award_atoms > VCS_ZC23_MAX_SUPPLY_ATOMS)
        return VCS_ZCODE_CREATION_AMOUNT;

    const uint8_t *roots[] = {
        a->challenge_opening_hash,
        a->network_genesis_root,
        a->zc23_policy_root,
        a->contributor_binding_root,
        a->task_root,
        a->candidate_root,
        a->proof_policy_root,
        a->proof_set_root,
        a->proven_lane_root,
        a->score_receipt_root,
        a->package_root,
        a->release_root,
        a->license_evidence_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_CREATION_ROOT;
    return VCS_ZCODE_CREATION_OK;
}

static enum vcs_zcode_creation_error creation_validate_challenge_time(
    const struct vcs_zcode_creation_attribution_v1 *a)
{
    uint64_t expected_height = 0;
    if (!zcl_u64_add(a->challenge_opening_height,
                     VCS_ZC23_CHALLENGE_BLOCKS, &expected_height))
        return VCS_ZCODE_CREATION_OVERFLOW;
    if (a->challenge_opening_mtp <= 0 ||
        a->challenge_opening_mtp >
            INT64_MAX - VCS_ZC23_CHALLENGE_SECONDS)
        return VCS_ZCODE_CREATION_OVERFLOW;
    int64_t expected_mtp =
        a->challenge_opening_mtp + VCS_ZC23_CHALLENGE_SECONDS;
    if (a->challenge_maturity_height != expected_height ||
        a->challenge_maturity_mtp != expected_mtp ||
        a->created_unix < expected_mtp)
        return VCS_ZCODE_CREATION_TIME;
    return VCS_ZCODE_CREATION_OK;
}

enum vcs_zcode_creation_error vcs_zcode_creation_attribution_validate(
    const struct vcs_zcode_creation_attribution_v1 *a)
{
    enum vcs_zcode_creation_error error = creation_validate_shape(a);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    error = creation_validate_award_roots(a);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    return creation_validate_challenge_time(a);
}

static bool creation_write_header(
    struct zcl_codec_writer *writer,
    const struct vcs_zcode_creation_attribution_v1 *a)
{
    return zcl_codec_write_bytes(writer, creation_magic,
                                 sizeof(creation_magic)) &&
        zcl_codec_write_u16le(writer, a->schema_version) &&
        zcl_codec_write_u16le(writer, a->category) &&
        zcl_codec_write_u8(writer, a->lineage_kind) &&
        zcl_codec_write_u8(writer, 0) &&
        zcl_codec_write_u8(writer, 0) &&
        zcl_codec_write_u8(writer, 0) &&
        zcl_codec_write_u64le(writer, a->epoch) &&
        zcl_codec_write_u64le(writer, a->award_atoms);
}

static bool creation_write_challenge(
    struct zcl_codec_writer *writer,
    const struct vcs_zcode_creation_attribution_v1 *a)
{
    return zcl_codec_write_u64le(writer, a->challenge_opening_height) &&
        zcl_codec_write_bytes(writer, a->challenge_opening_hash, 32) &&
        zcl_codec_write_i64le(writer, a->challenge_opening_mtp) &&
        zcl_codec_write_u64le(writer, a->challenge_maturity_height) &&
        zcl_codec_write_i64le(writer, a->challenge_maturity_mtp) &&
        zcl_codec_write_i64le(writer, a->created_unix) &&
        zcl_codec_write_bytes(writer, a->network_genesis_root, 32) &&
        zcl_codec_write_bytes(writer, a->zc23_policy_root, 32) &&
        zcl_codec_write_bytes(writer, a->contributor_binding_root, 32);
}

static bool creation_transfer_roots(
    struct zcl_codec_writer *writer, struct zcl_codec_reader *reader,
    struct vcs_zcode_creation_attribution_v1 *a)
{
    uint8_t *roots[] = {
        a->task_root,
        a->candidate_root,
        a->proof_policy_root,
        a->proof_set_root,
        a->proven_lane_root,
        a->score_receipt_root,
        a->package_root,
        a->release_root,
        a->license_evidence_root,
        a->lineage_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        bool moved = writer
            ? zcl_codec_write_bytes(writer, roots[i], 32)
            : zcl_codec_read_bytes(reader, roots[i], 32);
        if (!moved)
            return false;
    }
    return true;
}

static enum vcs_zcode_creation_error creation_write(
    const struct vcs_zcode_creation_attribution_v1 *a,
    uint8_t out[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES])
{
    enum vcs_zcode_creation_error error =
        vcs_zcode_creation_attribution_validate(a);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    if (!out)
        return VCS_ZCODE_CREATION_NULL;

    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out,
                          VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES);
    /* The roots transfer takes non-const field addresses; this copy is only
     * read. */
    struct vcs_zcode_creation_attribution_v1 fields;
    memcpy(&fields, a, sizeof(fields));
    bool ok = creation_write_header(&writer, a) &&
        creation_write_challenge(&writer, a) &&
        creation_transfer_roots(&writer, NULL, &fields);
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) ||
        written != VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES)
        return VCS_ZCODE_CREATION_WIRE_SIZE;
    return VCS_ZCODE_CREATION_OK;
}

enum vcs_zcode_creation_error vcs_zcode_creation_attribution_serialize(
    const struct vcs_zcode_creation_attribution_v1 *a,
    uint8_t out[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES])
{
    if (!out)
        return VCS_ZCODE_CREATION_NULL;
    memset(out, 0, VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES);
    enum vcs_zcode_creation_error error = creation_write(a, out);
    if (error != VCS_ZCODE_CREATION_OK)
        memset(out, 0, VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES);
    return error;
}

static bool creation_read_header(
    struct zcl_codec_reader *reader,
    struct vcs_zcode_creation_attribution_v1 *decoded,
    uint8_t magic[8], uint8_t reserved[3])
{
    return zcl_codec_read_bytes(reader, magic, sizeof(creation_magic)) &&
        zcl_codec_read_u16le(reader, &decoded->schema_version) &&
        zcl_codec_read_u16le(reader, &decoded->category) &&
        zcl_codec_read_u8(reader, &decoded->lineage_kind) &&
        zcl_codec_read_bytes(reader, reserved, 3) &&
        zcl_codec_read_u64le(reader, &decoded->epoch) &&
        zcl_codec_read_u64le(reader, &decoded->award_atoms);
}

static bool creation_read_challenge(
    struct zcl_codec_reader *reader,
    struct vcs_zcode_creation_attribution_v1 *decoded)
{
    return zcl_codec_read_u64le(reader, &decoded->challenge_opening_height) &&
        zcl_codec_read_bytes(reader, decoded->challenge_opening_hash, 32) &&
        zcl_codec_read_i64le(reader, &decoded->challenge_opening_mtp) &&
        zcl_codec_read_u64le(reader, &decoded->challenge_maturity_height) &&
        zcl_codec_read_i64le(reader, &decoded->challenge_maturity_mtp) &&
        zcl_codec_read_i64le(reader, &decoded->created_unix) &&
        zcl_codec_read_bytes(reader, decoded->network_genesis_root, 32) &&
        zcl_codec_read_bytes(reader, decoded->zc23_policy_root, 32) &&
        zcl_codec_read_bytes(reader, decoded->contributor_binding_root, 32);
}

static enum vcs_zcode_creation_error creation_check_envelope(
    const uint8_t magic[8], const uint8_t reserved[3])
{
    if (memcmp(magic, creation_magic, sizeof(creation_magic)) != 0)
        return VCS_ZCODE_CREATION_MAGIC;
    if (reserved[0] != 0 || reserved[1] != 0 || reserved[2] != 0)
        return VCS_ZCODE_CREATION_RESERVED;
    return VCS_ZCODE_CREATION_OK;
}

enum vcs_zcode_creation_error vcs_zcode_creation_attribution_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_creation_attribution_v1 *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!wire || !out)
        return VCS_ZCODE_CREATION_NULL;
    if (wire_len != VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES)
        return VCS_ZCODE_CREATION_WIRE_SIZE;

    struct vcs_zcode_creation_attribution_v1 decoded;
    memset(&decoded, 0, sizeof(decoded));
    struct zcl_codec_reader reader;
    uint8_t magic[8], reserved[3];
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = creation_read_header(&reader, &decoded, magic, reserved) &&
        creation_read_challenge(&reader, &decoded) &&
        creation_transfer_roots(NULL, &reader, &decoded) &&
        zcl_codec_reader_finish(&reader);
    if (!ok)
        return VCS_ZCODE_CREATION_WIRE_SIZE;
    enum vcs_zcode_creation_error error =
        creation_check_envelope(magic, reserved);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    error = vcs_zcode_creation_attribution_validate(&decoded);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    *out = decoded;
    return VCS_ZCODE_CREATION_OK;
}

enum vcs_zcode_creation_error vcs_zcode_creation_attribution_root(
    const struct vcs_zcode_creation_attribution_v1 *a, uint8_t out[32])
{
    if (out)
        memset(out, 0, 32);
    if (!a || !out)
        return VCS_ZCODE_CREATION_NULL;
    uint8_t wire[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
    enum vcs_zcode_creation_error error = creation_write(a, wire);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_CREATION_ATTRIBUTION_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_CREATION_OK;
}

enum vcs_zcode_creation_error vcs_zc23_epoch_cap_atoms(
    uint64_t era, uint64_t *out_atoms)
{
    if (!out_atoms)
        return VCS_ZCODE_CREATION_NULL;
    *out_atoms = 0;
    uint64_t whole_tokens = era >= 16 ? 0 : (UINT64_C(50000) >> era);
    if (!zcl_u64_mul(whole_tokens, VCS_ZC23_ATOMS_PER_TOKEN, out_atoms))
        return VCS_ZCODE_CREATION_OVERFLOW;
    return VCS_ZCODE_CREATION_OK;
}

enum vcs_zcode_creation_error vcs_zc23_max_supply_atoms(uint64_t *out_atoms)
{
    if (!out_atoms)
        return VCS_ZCODE_CREATION_NULL;
    *out_atoms = 0;
    uint64_t total = VCS_ZC23_INITIAL_SUPPLY_ATOMS;
    for (uint64_t era = 0; era < 16; era++) {
        uint64_t epoch_cap = 0, era_cap = 0;
        if (vcs_zc23_epoch_cap_atoms(era, &epoch_cap) !=
                VCS_ZCODE_CREATION_OK ||
            !zcl_u64_mul(epoch_cap, VCS_ZC23_EPOCHS_PER_ERA, &era_cap) ||
            !zcl_u64_add(total, era_cap, &total))
            return VCS_ZCODE_CREATION_OVERFLOW;
    }
    if (total != VCS_ZC23_MAX_SUPPLY_ATOMS)
        return VCS_ZCODE_CREATION_AMOUNT;
    *out_atoms = total;
    return VCS_ZCODE_CREATION_OK;
}
