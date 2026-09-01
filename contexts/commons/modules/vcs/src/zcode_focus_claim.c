/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical shared-focus claim codec and scope relation. */
#include "vcs/zcode_focus.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t claim_magic[8] = {
    'Z', 'C', 'F', 'C', 'L', 'A', 'M', '\n'
};

static void claim_hash(const uint8_t *wire, size_t wire_len, uint8_t out[32])
{
    static const char domain[] = VCS_ZCODE_FOCUS_CLAIM_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
}

static enum vcs_zcode_focus_error claim_validate(
    const struct vcs_zcode_focus_claim_v1 *claim)
{
    if (!claim) return VCS_ZCODE_FOCUS_NULL;
    if (claim->schema_version != VCS_ZCODE_FOCUS_VERSION)
        return VCS_ZCODE_FOCUS_VERSION_ERROR;
    if (claim->flags != 0 || claim->reserved != 0)
        return VCS_ZCODE_FOCUS_SHAPE;
    if (claim->created_unix <= 0 ||
        claim->expires_unix <= claim->created_unix)
        return VCS_ZCODE_FOCUS_LIMIT;
    const uint8_t *roots[] = {
        claim->situation_root, claim->claimant_root,
        claim->write_scope_root, claim->intent_root,
        claim->evidence_plan_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_FOCUS_ROOT_ZERO;
    return VCS_ZCODE_FOCUS_OK;
}

enum vcs_zcode_focus_error vcs_zcode_focus_claim_validate_at(
    const struct vcs_zcode_focus_claim_v1 *claim, int64_t now_unix)
{
    enum vcs_zcode_focus_error error = claim_validate(claim);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    return now_unix > 0 && now_unix >= claim->created_unix &&
           now_unix < claim->expires_unix
        ? VCS_ZCODE_FOCUS_OK : VCS_ZCODE_FOCUS_EXPIRED;
}

enum vcs_zcode_focus_error vcs_zcode_focus_claim_serialize(
    const struct vcs_zcode_focus_claim_v1 *claim,
    uint8_t out[VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_FOCUS_NULL;
    enum vcs_zcode_focus_error error = claim_validate(claim);
    if (error != VCS_ZCODE_FOCUS_OK) return error;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, claim_magic, 8) &&
        zcl_codec_write_u16le(&writer, claim->schema_version) &&
        zcl_codec_write_u16le(&writer, claim->flags) &&
        zcl_codec_write_u32le(&writer, claim->reserved) &&
        zcl_codec_write_u64le(&writer, (uint64_t)claim->created_unix) &&
        zcl_codec_write_u64le(&writer, (uint64_t)claim->expires_unix) &&
        zcl_codec_write_bytes(&writer, claim->situation_root, 32) &&
        zcl_codec_write_bytes(&writer, claim->claimant_root, 32) &&
        zcl_codec_write_bytes(&writer, claim->write_scope_root, 32) &&
        zcl_codec_write_bytes(&writer, claim->intent_root, 32) &&
        zcl_codec_write_bytes(&writer, claim->evidence_plan_root, 32);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES
        ? VCS_ZCODE_FOCUS_OK : VCS_ZCODE_FOCUS_SHAPE;
}

enum vcs_zcode_focus_error vcs_zcode_focus_claim_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_focus_claim_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_FOCUS_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES)
        return VCS_ZCODE_FOCUS_SHAPE;
    struct zcl_codec_reader reader;
    uint8_t magic[8]; uint64_t created, expires;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u16le(&reader, &out->flags) &&
        zcl_codec_read_u32le(&reader, &out->reserved) &&
        zcl_codec_read_u64le(&reader, &created) &&
        zcl_codec_read_u64le(&reader, &expires) &&
        zcl_codec_read_bytes(&reader, out->situation_root, 32) &&
        zcl_codec_read_bytes(&reader, out->claimant_root, 32) &&
        zcl_codec_read_bytes(&reader, out->write_scope_root, 32) &&
        zcl_codec_read_bytes(&reader, out->intent_root, 32) &&
        zcl_codec_read_bytes(&reader, out->evidence_plan_root, 32) &&
        zcl_codec_reader_finish(&reader) &&
        memcmp(magic, claim_magic, 8) == 0 &&
        created <= INT64_MAX && expires <= INT64_MAX;
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_FOCUS_SHAPE;
    }
    out->created_unix = (int64_t)created;
    out->expires_unix = (int64_t)expires;
    return claim_validate(out);
}

enum vcs_zcode_focus_error vcs_zcode_focus_claim_root(
    const struct vcs_zcode_focus_claim_v1 *claim, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_FOCUS_NULL;
    uint8_t wire[VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES];
    enum vcs_zcode_focus_error error = vcs_zcode_focus_claim_serialize(
        claim, wire);
    if (error == VCS_ZCODE_FOCUS_OK)
        claim_hash(wire, sizeof(wire), out);
    return error;
}

enum zcl_ontology_status vcs_zcode_focus_claim_disjoint_status(
    const struct vcs_zcode_focus_claim_v1 *a,
    const struct vcs_zcode_write_scope_v1 *scope_a,
    const struct vcs_zcode_focus_claim_v1 *b,
    const struct vcs_zcode_write_scope_v1 *scope_b, int64_t now_unix)
{
    if (vcs_zcode_focus_claim_validate_at(a, now_unix) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_claim_validate_at(b, now_unix) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_write_scope_validate(scope_a) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_validate(scope_b) !=
            VCS_ZCODE_WRITE_SCOPE_OK)
        return ZCL_ONTOLOGY_INCOMPLETE;
    if (memcmp(a->situation_root, b->situation_root, 32) != 0)
        return ZCL_ONTOLOGY_UNKNOWN;
    uint8_t root_a[32], root_b[32];
    if (vcs_zcode_write_scope_root(scope_a, root_a) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_root(scope_b, root_b) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        memcmp(root_a, a->write_scope_root, 32) != 0 ||
        memcmp(root_b, b->write_scope_root, 32) != 0)
        return ZCL_ONTOLOGY_INCOMPLETE;
    return vcs_zcode_write_scope_overlaps(scope_a, scope_b)
        ? ZCL_ONTOLOGY_DISPROVED : ZCL_ONTOLOGY_PROVED;
}

enum zcl_ontology_status vcs_zcode_focus_claim_authority_status(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_write_scope_v1 *task_scope,
    const struct vcs_zcode_focus_claim_v1 *claim,
    const struct vcs_zcode_write_scope_v1 *claim_scope, int64_t now_unix)
{
    if (vcs_zcode_focus_validate(focus) != VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_task_validate(task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_focus_claim_validate_at(claim, now_unix) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_write_scope_validate(task_scope) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_validate(claim_scope) !=
            VCS_ZCODE_WRITE_SCOPE_OK)
        return ZCL_ONTOLOGY_INCOMPLETE;
    uint8_t task_root[32], task_scope_root[32], claim_scope_root[32];
    uint8_t situation_root[32];
    if (vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_write_scope_root(task_scope, task_scope_root) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_root(claim_scope, claim_scope_root) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_focus_situation_root(focus, situation_root) !=
            VCS_ZCODE_FOCUS_OK ||
        memcmp(task_root, focus->task_root, 32) != 0 ||
        memcmp(task_scope_root, task->write_scope_root, 32) != 0 ||
        memcmp(claim_scope_root, claim->write_scope_root, 32) != 0 ||
        memcmp(situation_root, claim->situation_root, 32) != 0 ||
        memcmp(task->source_root, focus->source_universe_root, 32) != 0 ||
        memcmp(task->goal_root, focus->goal_root, 32) != 0)
        return ZCL_ONTOLOGY_INCOMPLETE;
    for (size_t i = 0; i < claim_scope->count; i++)
        if (!vcs_zcode_write_scope_contains(task_scope,
                                             claim_scope->paths[i]))
            return ZCL_ONTOLOGY_DISPROVED;
    return ZCL_ONTOLOGY_PROVED;
}

enum zcl_ontology_status vcs_zcode_focus_claim_set_status(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_focus_claim_v1 *claims,
    const struct vcs_zcode_write_scope_v1 *scopes,
    size_t claim_count, int64_t now_unix)
{
    if (vcs_zcode_focus_validate(focus) != VCS_ZCODE_FOCUS_OK ||
        claim_count != focus->claim_count ||
        claim_count > VCS_ZCODE_FOCUS_MAX_CLAIMS ||
        (claim_count > 0 && (!claims || !scopes)))
        return ZCL_ONTOLOGY_INCOMPLETE;
    uint8_t situation_root[32];
    uint8_t roots[VCS_ZCODE_FOCUS_MAX_CLAIMS][32];
    if (vcs_zcode_focus_situation_root(focus, situation_root) !=
        VCS_ZCODE_FOCUS_OK)
        return ZCL_ONTOLOGY_INCOMPLETE;
    for (size_t i = 0; i < claim_count; i++) {
        uint8_t scope_root[32];
        if (vcs_zcode_focus_claim_validate_at(&claims[i], now_unix) !=
                VCS_ZCODE_FOCUS_OK ||
            vcs_zcode_write_scope_root(&scopes[i], scope_root) !=
                VCS_ZCODE_WRITE_SCOPE_OK ||
            vcs_zcode_focus_claim_root(&claims[i], roots[i]) !=
                VCS_ZCODE_FOCUS_OK ||
            memcmp(claims[i].situation_root, situation_root, 32) != 0 ||
            memcmp(claims[i].write_scope_root, scope_root, 32) != 0 ||
            (i > 0 && memcmp(roots[i - 1u], roots[i], 32) >= 0))
            return ZCL_ONTOLOGY_INCOMPLETE;
    }
    uint8_t set_root[32];
    if (vcs_zcode_focus_claim_set_root(roots, claim_count, set_root) !=
            VCS_ZCODE_FOCUS_OK ||
        memcmp(set_root, focus->claim_set_root, 32) != 0)
        return ZCL_ONTOLOGY_INCOMPLETE;
    for (size_t i = 0; i < claim_count; i++)
        for (size_t j = i + 1u; j < claim_count; j++)
            if (vcs_zcode_write_scope_overlaps(&scopes[i], &scopes[j]))
                return ZCL_ONTOLOGY_DISPROVED;
    return ZCL_ONTOLOGY_PROVED;
}

enum zcl_ontology_status vcs_zcode_focus_claim_membership_status(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_focus_claim_v1 *claim,
    const uint8_t (*claim_roots)[32], size_t claim_count)
{
    if (vcs_zcode_focus_validate(focus) != VCS_ZCODE_FOCUS_OK ||
        !claim || claim_count != focus->claim_count ||
        claim_count > VCS_ZCODE_FOCUS_MAX_CLAIMS ||
        (claim_count > 0 && !claim_roots))
        return ZCL_ONTOLOGY_INCOMPLETE;
    uint8_t claim_root[32], set_root[32];
    if (vcs_zcode_focus_claim_root(claim, claim_root) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_claim_set_root(claim_roots, claim_count, set_root) !=
            VCS_ZCODE_FOCUS_OK ||
        memcmp(set_root, focus->claim_set_root, 32) != 0)
        return ZCL_ONTOLOGY_INCOMPLETE;
    for (size_t i = 0; i < claim_count; i++)
        if (memcmp(claim_root, claim_roots[i], 32) == 0)
            return ZCL_ONTOLOGY_PROVED;
    return ZCL_ONTOLOGY_DISPROVED;
}

enum zcl_ontology_status vcs_zcode_focus_claim_work_status(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_write_scope_v1 *task_scope,
    const struct vcs_zcode_focus_claim_v1 *claim,
    const struct vcs_zcode_write_scope_v1 *claim_scope,
    const uint8_t (*claim_roots)[32], size_t claim_count,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_admission_v1 *admission,
    int64_t now_unix)
{
    enum zcl_ontology_status authority =
        vcs_zcode_focus_claim_authority_status(
            focus, task, task_scope, claim, claim_scope, now_unix);
    if (authority != ZCL_ONTOLOGY_PROVED) return authority;
    enum zcl_ontology_status membership =
        vcs_zcode_focus_claim_membership_status(
            focus, claim, claim_roots, claim_count);
    if (membership != ZCL_ONTOLOGY_PROVED) return membership;
    if (!request || !admission ||
        !vcs_zcode_work_request_verify(request) ||
        !vcs_zcode_work_admission_verify_for_request(
            request, admission, claim->claimant_root))
        return ZCL_ONTOLOGY_INCOMPLETE;
    if (admission->disposition != VCS_ZCODE_WORK_ADMISSION_GRANTED &&
        admission->disposition != VCS_ZCODE_WORK_ADMISSION_ATTACHED)
        return ZCL_ONTOLOGY_DISPROVED;
    uint8_t request_root[32];
    if (!vcs_zcode_work_request_id(request, request_root))
        return ZCL_ONTOLOGY_INCOMPLETE;
    bool bound = memcmp(request_root, claim->intent_root, 32) == 0 &&
        memcmp(request->task_root, focus->task_root, 32) == 0 &&
        memcmp(request->proof_policy_root,
               claim->evidence_plan_root, 32) == 0 &&
        memcmp(request->proof_policy_root, task->proof_policy_root, 32) == 0 &&
        memcmp(request->toolchain_capsule_root,
               task->toolchain_capsule_root, 32) == 0 &&
        request->max_cpu_seconds <= task->max_cpu_seconds &&
        request->max_memory_bytes <= task->max_memory_bytes &&
        request->max_output_bytes <= task->max_output_bytes &&
        request->deadline_unix <= task->expires_unix &&
        claim->expires_unix <= request->deadline_unix &&
        now_unix < admission->deadline_unix &&
        claim->expires_unix <= admission->deadline_unix &&
        admission->deadline_unix <= request->deadline_unix;
    return bound ? ZCL_ONTOLOGY_PROVED : ZCL_ONTOLOGY_DISPROVED;
}
