/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical signed ZCODE durability-lane receipts. */

#include "vcs/zcode_lane.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "vcs/signed_evidence.h"

#include <string.h>

static const uint8_t lane_magic[8] = {
    'Z', 'C', 'L', 'A', 'N', 'E', '\r', '\n'
};

const char *vcs_zcode_lane_name(uint8_t lane)
{
    if (lane == VCS_ZCODE_LANE_FRONTIER) return "FRONTIER";
    if (lane == VCS_ZCODE_LANE_CANDIDATE) return "CANDIDATE";
    if (lane == VCS_ZCODE_LANE_PROVEN) return "PROVEN";
    return "UNKNOWN";
}

static enum vcs_zcode_dev_error lane_fields(
    const struct vcs_zcode_lane_receipt_v1 *receipt, bool signature)
{
    if (!receipt) return VCS_ZCODE_DEV_ERR_NULL;
    if (receipt->schema_version != VCS_ZCODE_DEV_VERSION)
        return VCS_ZCODE_DEV_ERR_VERSION;
    if (receipt->lane < VCS_ZCODE_LANE_FRONTIER ||
        receipt->lane > VCS_ZCODE_LANE_PROVEN)
        return VCS_ZCODE_DEV_ERR_VERDICT;
    if (!zcl_bytes_any_set(receipt->source_root, 32) ||
        !zcl_bytes_any_set(receipt->task_root, 32) ||
        !zcl_bytes_any_set(receipt->candidate_root, 32) ||
        !zcl_bytes_any_set(receipt->proof_policy_root, 32) ||
        !zcl_bytes_any_set(receipt->signer_pubkey, 32))
        return VCS_ZCODE_DEV_ERR_ROOT_ZERO;
    bool proof = zcl_bytes_any_set(receipt->proof_set_root, 32);
    bool prior = zcl_bytes_any_set(receipt->prior_receipt_root, 32);
    if ((receipt->lane == VCS_ZCODE_LANE_FRONTIER && (proof || prior)) ||
        (receipt->lane != VCS_ZCODE_LANE_FRONTIER && (!proof || !prior)))
        return VCS_ZCODE_DEV_ERR_POLICY;
    if (receipt->created_unix <= 0)
        return VCS_ZCODE_DEV_ERR_TIME_ORDER;
    if (signature && !zcl_bytes_any_set(receipt->signature,
                                        sizeof(receipt->signature)))
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_lane_receipt_validate(
    const struct vcs_zcode_lane_receipt_v1 *receipt)
{
    return lane_fields(receipt, true);
}

enum vcs_zcode_dev_error vcs_zcode_lane_receipt_validate_for_candidate(
    const struct vcs_zcode_lane_receipt_v1 *receipt,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy)
{
    if (!receipt || !task || !candidate || !policy)
        return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error err = lane_fields(receipt, true);
    if (err != VCS_ZCODE_DEV_OK) return err;
    uint8_t task_root[32], candidate_root[32], policy_root[32];
    if (vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
        memcmp(task_root, receipt->task_root, 32) != 0)
        return VCS_ZCODE_DEV_ERR_TASK_MISMATCH;
    if (vcs_zcode_candidate_root(candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        memcmp(candidate_root, receipt->candidate_root, 32) != 0 ||
        memcmp(candidate->candidate_source_root,
               receipt->source_root, 32) != 0)
        return VCS_ZCODE_DEV_ERR_SOURCE_STALE;
    if (vcs_zcode_proof_policy_root(policy, policy_root) !=
            VCS_ZCODE_DEV_OK ||
        memcmp(policy_root, receipt->proof_policy_root, 32) != 0 ||
        memcmp(task->proof_policy_root, policy_root, 32) != 0)
        return VCS_ZCODE_DEV_ERR_POLICY_MISMATCH;
    return VCS_ZCODE_DEV_OK;
}

static enum vcs_zcode_dev_error lane_body(
    const struct vcs_zcode_lane_receipt_v1 *receipt,
    uint8_t out[VCS_ZCODE_LANE_BODY_BYTES])
{
    enum vcs_zcode_dev_error err = lane_fields(receipt, false);
    if (err != VCS_ZCODE_DEV_OK) return err;
    static const uint8_t reserved[5] = {0};
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_LANE_BODY_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, lane_magic, sizeof(lane_magic)) &&
        zcl_codec_write_u16le(&writer, receipt->schema_version) &&
        zcl_codec_write_u8(&writer, receipt->lane) &&
        zcl_codec_write_bytes(&writer, reserved, sizeof(reserved)) &&
        zcl_codec_write_bytes(&writer, receipt->source_root, 32) &&
        zcl_codec_write_bytes(&writer, receipt->task_root, 32) &&
        zcl_codec_write_bytes(&writer, receipt->candidate_root, 32) &&
        zcl_codec_write_bytes(&writer, receipt->proof_policy_root, 32) &&
        zcl_codec_write_bytes(&writer, receipt->proof_set_root, 32) &&
        zcl_codec_write_bytes(&writer, receipt->prior_receipt_root, 32) &&
        zcl_codec_write_i64le(&writer, receipt->created_unix) &&
        zcl_codec_write_bytes(&writer, receipt->signer_pubkey, 32);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_LANE_BODY_BYTES
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_WIRE_SIZE;
}

enum vcs_zcode_dev_error vcs_zcode_lane_receipt_serialize(
    const struct vcs_zcode_lane_receipt_v1 *receipt,
    uint8_t out[VCS_ZCODE_LANE_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error err = lane_body(receipt, out);
    if (err != VCS_ZCODE_DEV_OK) return err;
    if (lane_fields(receipt, true) != VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    memcpy(out + VCS_ZCODE_LANE_BODY_BYTES, receipt->signature, 64);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_lane_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_lane_receipt_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_DEV_ERR_NULL;
    if (wire_len != VCS_ZCODE_LANE_WIRE_BYTES)
        return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    if (memcmp(wire, lane_magic, 8) != 0)
        return VCS_ZCODE_DEV_ERR_WIRE_MAGIC;
    memset(out, 0, sizeof(*out));
    uint8_t reserved[5];
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire + sizeof(lane_magic),
                          wire_len - sizeof(lane_magic));
    bool ok = zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u8(&reader, &out->lane) &&
        zcl_codec_read_bytes(&reader, reserved, sizeof(reserved)) &&
        zcl_codec_read_bytes(&reader, out->source_root, 32) &&
        zcl_codec_read_bytes(&reader, out->task_root, 32) &&
        zcl_codec_read_bytes(&reader, out->candidate_root, 32) &&
        zcl_codec_read_bytes(&reader, out->proof_policy_root, 32) &&
        zcl_codec_read_bytes(&reader, out->proof_set_root, 32) &&
        zcl_codec_read_bytes(&reader, out->prior_receipt_root, 32) &&
        zcl_codec_read_i64le(&reader, &out->created_unix) &&
        zcl_codec_read_bytes(&reader, out->signer_pubkey, 32) &&
        zcl_codec_read_bytes(&reader, out->signature, 64) &&
        zcl_codec_reader_finish(&reader);
    for (size_t i = 0; ok && i < sizeof(reserved); i++) ok = reserved[i] == 0;
    if (!ok) { memset(out, 0, sizeof(*out)); return VCS_ZCODE_DEV_ERR_WIRE_MAGIC; }
    return vcs_zcode_lane_receipt_validate(out);
}

enum vcs_zcode_dev_error vcs_zcode_lane_receipt_id(
    const struct vcs_zcode_lane_receipt_v1 *receipt, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    uint8_t body[VCS_ZCODE_LANE_BODY_BYTES];
    enum vcs_zcode_dev_error err = lane_body(receipt, body);
    if (err != VCS_ZCODE_DEV_OK) return err;
    static const char domain[] = VCS_ZCODE_LANE_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), body,
                                    sizeof(body), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

enum vcs_zcode_dev_error vcs_zcode_lane_receipt_seal(
    struct vcs_zcode_lane_receipt_v1 *receipt,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!receipt || !secret || !pubkey) return VCS_ZCODE_DEV_ERR_NULL;
    memcpy(receipt->signer_pubkey, pubkey, 32);
    uint8_t id[32];
    enum vcs_zcode_dev_error err = vcs_zcode_lane_receipt_id(receipt, id);
    if (err != VCS_ZCODE_DEV_OK) return err;
    return vcs_signed_evidence_seal_root(id, secret, pubkey,
                                         receipt->signature)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

enum vcs_zcode_dev_error vcs_zcode_lane_receipt_verify(
    const struct vcs_zcode_lane_receipt_v1 *receipt,
    const uint8_t expected_signer[32])
{
    enum vcs_zcode_dev_error err = vcs_zcode_lane_receipt_validate(receipt);
    if (err != VCS_ZCODE_DEV_OK) return err;
    uint8_t id[32];
    err = vcs_zcode_lane_receipt_id(receipt, id);
    if (err != VCS_ZCODE_DEV_OK) return err;
    return vcs_signed_evidence_verify_root(
               id, receipt->signature, receipt->signer_pubkey,
               expected_signer)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}
