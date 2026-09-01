/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical transcript-free focus handoff codec and chain check. */
#include "vcs/zcode_focus.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t handoff_magic[8] = {
    'Z', 'C', 'F', 'H', 'A', 'N', 'D', '\n'
};

static bool handoff_status_valid(uint8_t status)
{
    return status >= ZCL_ONTOLOGY_PROVED &&
           status <= ZCL_ONTOLOGY_INCOMPLETE;
}

enum vcs_zcode_focus_error vcs_zcode_focus_handoff_validate(
    const struct vcs_zcode_focus_handoff_v1 *handoff)
{
    if (!handoff) return VCS_ZCODE_FOCUS_NULL;
    if (handoff->schema_version != VCS_ZCODE_FOCUS_VERSION)
        return VCS_ZCODE_FOCUS_VERSION_ERROR;
    if (!handoff_status_valid(handoff->status) || handoff->flags != 0 ||
        handoff->reserved != 0)
        return VCS_ZCODE_FOCUS_SHAPE;
    const uint8_t *roots[] = {
        handoff->focus_root, handoff->report_root,
        handoff->from_claim_root, handoff->to_specialist_root,
        handoff->next_claim_root, handoff->required_evidence_root,
        handoff->continuation_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_FOCUS_ROOT_ZERO;
    return VCS_ZCODE_FOCUS_OK;
}

enum vcs_zcode_focus_error vcs_zcode_focus_handoff_serialize(
    const struct vcs_zcode_focus_handoff_v1 *handoff,
    uint8_t out[VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_FOCUS_NULL;
    enum vcs_zcode_focus_error error =
        vcs_zcode_focus_handoff_validate(handoff);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, handoff_magic, 8) &&
        zcl_codec_write_u16le(&writer, handoff->schema_version) &&
        zcl_codec_write_u8(&writer, handoff->status) &&
        zcl_codec_write_u8(&writer, handoff->flags) &&
        zcl_codec_write_u32le(&writer, handoff->reserved) &&
        zcl_codec_write_bytes(&writer, handoff->focus_root, 32) &&
        zcl_codec_write_bytes(&writer, handoff->report_root, 32) &&
        zcl_codec_write_bytes(&writer, handoff->from_claim_root, 32) &&
        zcl_codec_write_bytes(&writer, handoff->to_specialist_root, 32) &&
        zcl_codec_write_bytes(&writer, handoff->next_claim_root, 32) &&
        zcl_codec_write_bytes(&writer, handoff->required_evidence_root, 32) &&
        zcl_codec_write_bytes(&writer, handoff->continuation_root, 32);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES
        ? VCS_ZCODE_FOCUS_OK : VCS_ZCODE_FOCUS_SHAPE;
}

enum vcs_zcode_focus_error vcs_zcode_focus_handoff_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_focus_handoff_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_FOCUS_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES)
        return VCS_ZCODE_FOCUS_SHAPE;
    struct zcl_codec_reader reader;
    uint8_t magic[8];
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u8(&reader, &out->status) &&
        zcl_codec_read_u8(&reader, &out->flags) &&
        zcl_codec_read_u32le(&reader, &out->reserved) &&
        zcl_codec_read_bytes(&reader, out->focus_root, 32) &&
        zcl_codec_read_bytes(&reader, out->report_root, 32) &&
        zcl_codec_read_bytes(&reader, out->from_claim_root, 32) &&
        zcl_codec_read_bytes(&reader, out->to_specialist_root, 32) &&
        zcl_codec_read_bytes(&reader, out->next_claim_root, 32) &&
        zcl_codec_read_bytes(&reader, out->required_evidence_root, 32) &&
        zcl_codec_read_bytes(&reader, out->continuation_root, 32) &&
        zcl_codec_reader_finish(&reader) &&
        memcmp(magic, handoff_magic, 8) == 0;
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_FOCUS_SHAPE;
    }
    return vcs_zcode_focus_handoff_validate(out);
}

enum vcs_zcode_focus_error vcs_zcode_focus_handoff_root(
    const struct vcs_zcode_focus_handoff_v1 *handoff, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_FOCUS_NULL;
    uint8_t wire[VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES];
    enum vcs_zcode_focus_error error = vcs_zcode_focus_handoff_serialize(
        handoff, wire);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    static const char domain[] = VCS_ZCODE_FOCUS_HANDOFF_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_FOCUS_OK;
}

enum vcs_zcode_focus_error vcs_zcode_focus_handoff_validate_chain(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_focus_claim_v1 *from_claim,
    const struct vcs_zcode_specialist_report_v1 *report,
    const struct vcs_zcode_focus_handoff_v1 *handoff,
    const struct vcs_zcode_focus_claim_v1 *next_claim)
{
    if (!focus || !from_claim || !report || !handoff || !next_claim)
        return VCS_ZCODE_FOCUS_NULL;
    if (vcs_zcode_focus_validate(focus) != VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_specialist_report_validate(report) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_handoff_validate(handoff) != VCS_ZCODE_FOCUS_OK)
        return VCS_ZCODE_FOCUS_SHAPE;
    uint8_t focus_root[32], situation_root[32], from_root[32];
    uint8_t report_root[32], next_root[32];
    if (vcs_zcode_focus_root(focus, focus_root) != VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_situation_root(focus, situation_root) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_claim_root(from_claim, from_root) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_specialist_report_root(report, report_root) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_claim_root(next_claim, next_root) !=
            VCS_ZCODE_FOCUS_OK)
        return VCS_ZCODE_FOCUS_SHAPE;
    bool bound = memcmp(from_claim->situation_root, situation_root, 32) == 0 &&
        memcmp(next_claim->situation_root, situation_root, 32) == 0 &&
        memcmp(report->focus_root, focus_root, 32) == 0 &&
        memcmp(handoff->focus_root, focus_root, 32) == 0 &&
        memcmp(report->claim_root, from_root, 32) == 0 &&
        memcmp(handoff->from_claim_root, from_root, 32) == 0 &&
        memcmp(handoff->report_root, report_root, 32) == 0 &&
        memcmp(handoff->next_claim_root, next_root, 32) == 0 &&
        memcmp(report->specialist_root, from_claim->claimant_root, 32) == 0 &&
        memcmp(handoff->to_specialist_root,
               next_claim->claimant_root, 32) == 0 &&
        memcmp(handoff->required_evidence_root,
               focus->required_evidence_root, 32) == 0 &&
        memcmp(handoff->continuation_root,
               report->next_experiment_root, 32) == 0 &&
        handoff->status == report->status;
    return bound ? VCS_ZCODE_FOCUS_OK : VCS_ZCODE_FOCUS_BINDING;
}

enum vcs_zcode_focus_error vcs_zcode_focus_handoff_validate_for_work(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_agent_context_v1 *context,
    const struct vcs_zcode_write_scope_v1 *task_scope,
    const struct vcs_zcode_focus_claim_v1 *claims,
    const struct vcs_zcode_write_scope_v1 *scopes,
    size_t claim_count, size_t from_index, size_t next_index,
    const struct vcs_zcode_work_request_v1 *from_request,
    const struct vcs_zcode_work_admission_v1 *from_admission,
    const struct vcs_zcode_work_request_v1 *next_request,
    const struct vcs_zcode_work_admission_v1 *next_admission,
    const struct vcs_zcode_work_receipt_v1 *from_receipt,
    const struct vcs_zcode_specialist_report_v1 *report,
    const struct vcs_zcode_focus_handoff_v1 *handoff,
    int64_t now_unix)
{
    if (!focus || !task || !context || !task_scope || !claims || !scopes ||
        !from_request || !from_admission || !next_request ||
        !next_admission || !from_receipt || !report || !handoff)
        return VCS_ZCODE_FOCUS_NULL;
    if (claim_count == 0 || claim_count > VCS_ZCODE_FOCUS_MAX_CLAIMS ||
        from_index >= claim_count || next_index >= claim_count ||
        from_index == next_index)
        return VCS_ZCODE_FOCUS_LIMIT;
    uint8_t claim_roots[VCS_ZCODE_FOCUS_MAX_CLAIMS][32];
    for (size_t i = 0; i < claim_count; i++)
        if (vcs_zcode_focus_claim_root(&claims[i], claim_roots[i]) !=
            VCS_ZCODE_FOCUS_OK)
            return VCS_ZCODE_FOCUS_SHAPE;
    enum vcs_zcode_focus_error context_error =
        vcs_zcode_focus_validate_for_context(
            focus, task, context, claim_roots, claim_count, true);
    if (context_error != VCS_ZCODE_FOCUS_OK) return context_error;
    if (vcs_zcode_focus_claim_set_status(
            focus, claims, scopes, claim_count, now_unix) !=
            ZCL_ONTOLOGY_PROVED)
        return VCS_ZCODE_FOCUS_BINDING;

    for (size_t i = 0; i < claim_count; i++)
        if (vcs_zcode_focus_claim_authority_status(
                focus, task, task_scope, &claims[i], &scopes[i],
                now_unix) != ZCL_ONTOLOGY_PROVED)
            return VCS_ZCODE_FOCUS_BINDING;

    if (vcs_zcode_focus_claim_work_status(
            focus, task, task_scope, &claims[from_index],
            &scopes[from_index], claim_roots, claim_count,
            from_request, from_admission, now_unix) !=
            ZCL_ONTOLOGY_PROVED ||
        vcs_zcode_focus_claim_work_status(
            focus, task, task_scope, &claims[next_index],
            &scopes[next_index], claim_roots, claim_count,
            next_request, next_admission, now_unix) !=
            ZCL_ONTOLOGY_PROVED)
        return VCS_ZCODE_FOCUS_BINDING;
    if (vcs_zcode_specialist_report_validate_for_work(
            focus, &claims[from_index], claim_roots, claim_count,
            task, from_request, from_receipt, report) !=
            VCS_ZCODE_FOCUS_OK)
        return VCS_ZCODE_FOCUS_BINDING;
    return vcs_zcode_focus_handoff_validate_chain(
        focus, &claims[from_index], report, handoff, &claims[next_index]);
}
