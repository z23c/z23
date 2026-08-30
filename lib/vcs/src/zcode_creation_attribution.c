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

const char *vcs_zcode_creation_error_string(
    enum vcs_zcode_creation_error error)
{
    switch (error) {
    case VCS_ZCODE_CREATION_OK: return "ok";
    case VCS_ZCODE_CREATION_NULL: return "null-argument";
    case VCS_ZCODE_CREATION_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_CREATION_MAGIC: return "wire-magic";
    case VCS_ZCODE_CREATION_VERSION: return "schema-version";
    case VCS_ZCODE_CREATION_RESERVED: return "reserved-byte";
    case VCS_ZCODE_CREATION_CATEGORY: return "creation-category";
    case VCS_ZCODE_CREATION_LINEAGE: return "creation-lineage";
    case VCS_ZCODE_CREATION_ROOT: return "zero-authority-root";
    case VCS_ZCODE_CREATION_AMOUNT: return "award-amount";
    case VCS_ZCODE_CREATION_TIME: return "challenge-time";
    case VCS_ZCODE_CREATION_OVERFLOW: return "checked-overflow";
    case VCS_ZCODE_CREATION_CONTEXT: return "validation-context";
    case VCS_ZCODE_CREATION_CAS: return "cas-object";
    case VCS_ZCODE_CREATION_NETWORK: return "network-genesis-mismatch";
    case VCS_ZCODE_CREATION_POLICY: return "zc23-policy-mismatch";
    case VCS_ZCODE_CREATION_EPOCH: return "epoch-mismatch";
    case VCS_ZCODE_CREATION_CONTRIBUTOR: return "contributor-binding";
    case VCS_ZCODE_CREATION_TASK: return "task-object";
    case VCS_ZCODE_CREATION_CANDIDATE: return "candidate-object";
    case VCS_ZCODE_CREATION_PROOF_POLICY: return "proof-policy-object";
    case VCS_ZCODE_CREATION_PROOF_SET: return "proof-set-object";
    case VCS_ZCODE_CREATION_LANE: return "proven-lane-object";
    case VCS_ZCODE_CREATION_SCORE: return "score-receipt-object";
    case VCS_ZCODE_CREATION_PACKAGE: return "package-object";
    case VCS_ZCODE_CREATION_RELEASE: return "release-object";
    case VCS_ZCODE_CREATION_LICENSE: return "license-evidence";
    case VCS_ZCODE_CREATION_CONTINUITY: return "continuity-policy-or-event";
    case VCS_ZCODE_CREATION_IMMATURE: return "challenge-immature";
    case VCS_ZCODE_CREATION_REORG: return "challenge-anchor-reorged";
    case VCS_ZCODE_CREATION_DUPLICATE: return "duplicate-contribution";
    }
    return "unknown-creation-error";
}

enum vcs_zcode_creation_error vcs_zcode_creation_attribution_validate(
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
    bool ok = zcl_codec_write_bytes(&writer, creation_magic,
                                    sizeof(creation_magic)) &&
        zcl_codec_write_u16le(&writer, a->schema_version) &&
        zcl_codec_write_u16le(&writer, a->category) &&
        zcl_codec_write_u8(&writer, a->lineage_kind) &&
        zcl_codec_write_u8(&writer, 0) &&
        zcl_codec_write_u8(&writer, 0) &&
        zcl_codec_write_u8(&writer, 0) &&
        zcl_codec_write_u64le(&writer, a->epoch) &&
        zcl_codec_write_u64le(&writer, a->award_atoms) &&
        zcl_codec_write_u64le(&writer, a->challenge_opening_height) &&
        zcl_codec_write_bytes(&writer, a->challenge_opening_hash, 32) &&
        zcl_codec_write_i64le(&writer, a->challenge_opening_mtp) &&
        zcl_codec_write_u64le(&writer, a->challenge_maturity_height) &&
        zcl_codec_write_i64le(&writer, a->challenge_maturity_mtp) &&
        zcl_codec_write_i64le(&writer, a->created_unix) &&
        zcl_codec_write_bytes(&writer, a->network_genesis_root, 32) &&
        zcl_codec_write_bytes(&writer, a->zc23_policy_root, 32) &&
        zcl_codec_write_bytes(&writer, a->contributor_binding_root, 32) &&
        zcl_codec_write_bytes(&writer, a->task_root, 32) &&
        zcl_codec_write_bytes(&writer, a->candidate_root, 32) &&
        zcl_codec_write_bytes(&writer, a->proof_policy_root, 32) &&
        zcl_codec_write_bytes(&writer, a->proof_set_root, 32) &&
        zcl_codec_write_bytes(&writer, a->proven_lane_root, 32) &&
        zcl_codec_write_bytes(&writer, a->score_receipt_root, 32) &&
        zcl_codec_write_bytes(&writer, a->package_root, 32) &&
        zcl_codec_write_bytes(&writer, a->release_root, 32) &&
        zcl_codec_write_bytes(&writer, a->license_evidence_root, 32) &&
        zcl_codec_write_bytes(&writer, a->lineage_root, 32);
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
    bool ok = zcl_codec_read_bytes(&reader, magic, sizeof(magic)) &&
        zcl_codec_read_u16le(&reader, &decoded.schema_version) &&
        zcl_codec_read_u16le(&reader, &decoded.category) &&
        zcl_codec_read_u8(&reader, &decoded.lineage_kind) &&
        zcl_codec_read_bytes(&reader, reserved, sizeof(reserved)) &&
        zcl_codec_read_u64le(&reader, &decoded.epoch) &&
        zcl_codec_read_u64le(&reader, &decoded.award_atoms) &&
        zcl_codec_read_u64le(&reader, &decoded.challenge_opening_height) &&
        zcl_codec_read_bytes(&reader, decoded.challenge_opening_hash, 32) &&
        zcl_codec_read_i64le(&reader, &decoded.challenge_opening_mtp) &&
        zcl_codec_read_u64le(&reader, &decoded.challenge_maturity_height) &&
        zcl_codec_read_i64le(&reader, &decoded.challenge_maturity_mtp) &&
        zcl_codec_read_i64le(&reader, &decoded.created_unix) &&
        zcl_codec_read_bytes(&reader, decoded.network_genesis_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.zc23_policy_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.contributor_binding_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.task_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.candidate_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.proof_policy_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.proof_set_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.proven_lane_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.score_receipt_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.package_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.release_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.license_evidence_root, 32) &&
        zcl_codec_read_bytes(&reader, decoded.lineage_root, 32) &&
        zcl_codec_reader_finish(&reader);
    if (!ok)
        return VCS_ZCODE_CREATION_WIRE_SIZE;
    if (memcmp(magic, creation_magic, sizeof(magic)) != 0)
        return VCS_ZCODE_CREATION_MAGIC;
    if (reserved[0] != 0 || reserved[1] != 0 || reserved[2] != 0)
        return VCS_ZCODE_CREATION_RESERVED;
    enum vcs_zcode_creation_error error =
        vcs_zcode_creation_attribution_validate(&decoded);
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
