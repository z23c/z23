/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical compact specialist report codec. */
#include "vcs/zcode_focus.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t report_magic[8] = {
    'Z', 'C', 'S', 'P', 'R', 'E', 'P', '\n'
};

static bool report_status_valid(uint8_t status)
{
    return status >= ZCL_ONTOLOGY_PROVED &&
           status <= ZCL_ONTOLOGY_INCOMPLETE;
}

static bool report_role_valid(uint8_t role)
{
    return role >= VCS_ZCODE_SPECIALIST_RETRIEVAL &&
           role <= VCS_ZCODE_SPECIALIST_INTEGRATION;
}

enum vcs_zcode_focus_error vcs_zcode_specialist_report_validate(
    const struct vcs_zcode_specialist_report_v1 *report)
{
    if (!report) return VCS_ZCODE_FOCUS_NULL;
    if (report->schema_version != VCS_ZCODE_FOCUS_VERSION)
        return VCS_ZCODE_FOCUS_VERSION_ERROR;
    if (!report_role_valid(report->role) ||
        !report_status_valid(report->status) || report->flags != 0 ||
        report->reserved != 0)
        return VCS_ZCODE_FOCUS_SHAPE;
    if (report->context_bytes == 0 || report->latency_us == 0 ||
        report->tool_calls == 0 ||
        report->duplicate_actions > report->tool_calls ||
        report->proof_reuse_count > report->tool_calls)
        return VCS_ZCODE_FOCUS_LIMIT;
    const uint8_t *roots[] = {
        report->focus_root, report->claim_root, report->specialist_root,
        report->evidence_root, report->result_root,
        report->next_experiment_root, report->evaluator_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_FOCUS_ROOT_ZERO;
    return VCS_ZCODE_FOCUS_OK;
}

enum vcs_zcode_focus_error vcs_zcode_specialist_report_serialize(
    const struct vcs_zcode_specialist_report_v1 *report,
    uint8_t out[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_FOCUS_NULL;
    enum vcs_zcode_focus_error error =
        vcs_zcode_specialist_report_validate(report);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, report_magic, 8) &&
        zcl_codec_write_u16le(&writer, report->schema_version) &&
        zcl_codec_write_u8(&writer, report->role) &&
        zcl_codec_write_u8(&writer, report->status) &&
        zcl_codec_write_u16le(&writer, report->flags) &&
        zcl_codec_write_u16le(&writer, report->reserved) &&
        zcl_codec_write_u64le(&writer, report->context_bytes) &&
        zcl_codec_write_u64le(&writer, report->latency_us) &&
        zcl_codec_write_u32le(&writer, report->files_opened) &&
        zcl_codec_write_u32le(&writer, report->tool_calls) &&
        zcl_codec_write_u32le(&writer, report->duplicate_actions) &&
        zcl_codec_write_u32le(&writer, report->proof_reuse_count) &&
        zcl_codec_write_bytes(&writer, report->focus_root, 32) &&
        zcl_codec_write_bytes(&writer, report->claim_root, 32) &&
        zcl_codec_write_bytes(&writer, report->specialist_root, 32) &&
        zcl_codec_write_bytes(&writer, report->evidence_root, 32) &&
        zcl_codec_write_bytes(&writer, report->result_root, 32) &&
        zcl_codec_write_bytes(&writer, report->next_experiment_root, 32) &&
        zcl_codec_write_bytes(&writer, report->evaluator_root, 32);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES
        ? VCS_ZCODE_FOCUS_OK : VCS_ZCODE_FOCUS_SHAPE;
}

enum vcs_zcode_focus_error vcs_zcode_specialist_report_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_specialist_report_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_FOCUS_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES)
        return VCS_ZCODE_FOCUS_SHAPE;
    struct zcl_codec_reader reader;
    uint8_t magic[8];
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u8(&reader, &out->role) &&
        zcl_codec_read_u8(&reader, &out->status) &&
        zcl_codec_read_u16le(&reader, &out->flags) &&
        zcl_codec_read_u16le(&reader, &out->reserved) &&
        zcl_codec_read_u64le(&reader, &out->context_bytes) &&
        zcl_codec_read_u64le(&reader, &out->latency_us) &&
        zcl_codec_read_u32le(&reader, &out->files_opened) &&
        zcl_codec_read_u32le(&reader, &out->tool_calls) &&
        zcl_codec_read_u32le(&reader, &out->duplicate_actions) &&
        zcl_codec_read_u32le(&reader, &out->proof_reuse_count) &&
        zcl_codec_read_bytes(&reader, out->focus_root, 32) &&
        zcl_codec_read_bytes(&reader, out->claim_root, 32) &&
        zcl_codec_read_bytes(&reader, out->specialist_root, 32) &&
        zcl_codec_read_bytes(&reader, out->evidence_root, 32) &&
        zcl_codec_read_bytes(&reader, out->result_root, 32) &&
        zcl_codec_read_bytes(&reader, out->next_experiment_root, 32) &&
        zcl_codec_read_bytes(&reader, out->evaluator_root, 32) &&
        zcl_codec_reader_finish(&reader) &&
        memcmp(magic, report_magic, 8) == 0;
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_FOCUS_SHAPE;
    }
    return vcs_zcode_specialist_report_validate(out);
}

enum vcs_zcode_focus_error vcs_zcode_specialist_report_root(
    const struct vcs_zcode_specialist_report_v1 *report, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_FOCUS_NULL;
    uint8_t wire[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
    enum vcs_zcode_focus_error error = vcs_zcode_specialist_report_serialize(
        report, wire);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    static const char domain[] = VCS_ZCODE_SPECIALIST_REPORT_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_FOCUS_OK;
}
