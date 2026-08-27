/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Self-contained transfer of an accepted ZCODE proof chain. */

#include "vcs/zcode_accepted_work_bundle.h"

#include "vcs_priv.h"

#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_task_authority_bundle.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ACCEPTED_BUNDLE_HEADER_BYTES 88u
#define ACCEPTED_BUNDLE_RECORD_HEADER_BYTES 36u
#define ACCEPTED_BUNDLE_MAX_OBJECTS \
    (8u + 2u * VCS_ZCODE_PROOF_SET_MAX_RECEIPTS)

static const uint8_t accepted_bundle_magic[8] = {
    'Z', 'C', 'A', 'W', 'B', '1', '\r', '\n'
};

struct accepted_bundle_object {
    uint8_t root[32];
    uint8_t *bytes;
    size_t len;
};

struct accepted_bundle_view {
    const uint8_t *root;
    const uint8_t *bytes;
    size_t len;
};

const char *vcs_zcode_accepted_work_bundle_result_string(
    enum vcs_zcode_accepted_work_bundle_result result)
{
    switch (result) {
    case VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK: return "ok";
    case VCS_ZCODE_ACCEPTED_WORK_BUNDLE_NULL: return "null-argument";
    case VCS_ZCODE_ACCEPTED_WORK_BUNDLE_SHAPE: return "noncanonical-bundle";
    case VCS_ZCODE_ACCEPTED_WORK_BUNDLE_LIMIT: return "bundle-limit";
    case VCS_ZCODE_ACCEPTED_WORK_BUNDLE_CAS: return "cas-miss-or-corrupt";
    case VCS_ZCODE_ACCEPTED_WORK_BUNDLE_AUTHORITY:
        return "accepted-work-authority-mismatch";
    case VCS_ZCODE_ACCEPTED_WORK_BUNDLE_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

static void accepted_objects_free(struct accepted_bundle_object *objects,
                                  size_t count)
{
    if (!objects) return;
    for (size_t i = 0; i < count; i++) free(objects[i].bytes);
    free(objects);
}

static int accepted_object_compare(const void *a, const void *b)
{
    const struct accepted_bundle_object *left = a, *right = b;
    return memcmp(left->root, right->root, 32);
}

static bool accepted_object_add(
    const char *workspace, const uint8_t root[32],
    struct accepted_bundle_object *objects, size_t *count)
{
    for (size_t i = 0; i < *count; i++)
        if (memcmp(objects[i].root, root, 32) == 0) return true;
    if (*count >= ACCEPTED_BUNDLE_MAX_OBJECTS) return false;
    uint8_t *bytes = NULL;
    size_t len = 0;
    if (vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_ACCEPTED_WORK_BUNDLE_MAX_BYTES,
            &bytes, &len) != 0 || len == 0) {
        free(bytes);
        return false;
    }
    memcpy(objects[*count].root, root, 32);
    objects[*count].bytes = bytes;
    objects[*count].len = len;
    (*count)++;
    return true;
}

static bool accepted_add_proof_set(
    const char *workspace, const uint8_t root[32],
    struct accepted_bundle_object *objects, size_t *count)
{
    if (!accepted_object_add(workspace, root, objects, count)) return false;
    uint8_t *wire = NULL;
    size_t len = 0, receipt_count = 0;
    uint8_t receipts[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    bool ok = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_PROOF_SET_WIRE_MAX,
            &wire, &len) == 0 &&
        vcs_zcode_proof_set_parse(
            wire, len, receipts, VCS_ZCODE_PROOF_SET_MAX_RECEIPTS,
            &receipt_count) == VCS_ZCODE_DEV_OK && receipt_count > 0;
    free(wire);
    for (size_t i = 0; ok && i < receipt_count; i++)
        ok = accepted_object_add(workspace, receipts[i], objects, count);
    return ok;
}

enum vcs_zcode_accepted_work_bundle_result
vcs_zcode_accepted_work_bundle_export(
    const char *workspace, const uint8_t accepted_work_root[32],
    int64_t now_unix, uint8_t **wire_out, size_t *wire_len,
    struct vcs_zcode_accepted_work_v1 *accepted_out)
{
    if (wire_out) *wire_out = NULL;
    if (wire_len) *wire_len = 0;
    if (!workspace || !accepted_work_root || now_unix <= 0 ||
        !wire_out || !wire_len)
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_NULL;
    struct vcs_zcode_accepted_work_v1 accepted;
    if (!vcs_zcode_accepted_work_resolve(
            workspace, accepted_work_root, now_unix, &accepted))
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_AUTHORITY;
    struct accepted_bundle_object *objects = zcl_calloc(
        ACCEPTED_BUNDLE_MAX_OBJECTS, sizeof(*objects),
        "zcode.accepted_bundle.objects");
    if (!objects) return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_ALLOC;
    size_t count = 0;
    bool ok = accepted_object_add(
            workspace, accepted.task_root, objects, &count) &&
        accepted_object_add(
            workspace, accepted.candidate_root, objects, &count) &&
        accepted_object_add(
            workspace, accepted.proof_policy_root, objects, &count) &&
        accepted_object_add(
            workspace, accepted.frontier_root, objects, &count) &&
        accepted_object_add(
            workspace, accepted.candidate_lane_root, objects, &count) &&
        accepted_object_add(
            workspace, accepted.accepted_work_root, objects, &count) &&
        accepted_add_proof_set(
            workspace, accepted.candidate_lane.proof_set_root,
            objects, &count) &&
        accepted_add_proof_set(
            workspace, accepted.proven.proof_set_root, objects, &count);
    uint8_t *task_authority = NULL;
    size_t task_authority_len = 0;
    ok = ok && vcs_zcode_task_authority_bundle_export(
            workspace, &accepted.task, &task_authority,
            &task_authority_len) == VCS_ZCODE_TASK_AUTHORITY_OK;
    if (!ok) {
        free(task_authority);
        accepted_objects_free(objects, count);
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_CAS;
    }
    qsort(objects, count, sizeof(*objects), accepted_object_compare);
    size_t total = ACCEPTED_BUNDLE_HEADER_BYTES;
    for (size_t i = 0; i < count; i++) {
        if (objects[i].len > UINT32_MAX ||
            SIZE_MAX - total < ACCEPTED_BUNDLE_RECORD_HEADER_BYTES ||
            SIZE_MAX - total - ACCEPTED_BUNDLE_RECORD_HEADER_BYTES <
                objects[i].len) {
            free(task_authority);
            accepted_objects_free(objects, count);
            return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_LIMIT;
        }
        total += ACCEPTED_BUNDLE_RECORD_HEADER_BYTES + objects[i].len;
    }
    if (SIZE_MAX - total < task_authority_len ||
        total + task_authority_len >
            VCS_ZCODE_ACCEPTED_WORK_BUNDLE_MAX_BYTES) {
        free(task_authority);
        accepted_objects_free(objects, count);
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_LIMIT;
    }
    total += task_authority_len;
    uint8_t *wire = zcl_malloc(total, "zcode.accepted_bundle.wire");
    if (!wire) {
        free(task_authority);
        accepted_objects_free(objects, count);
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_ALLOC;
    }
    memcpy(wire, accepted_bundle_magic, 8);
    vcs_wr_u16le(wire + 8, VCS_ZCODE_ACCEPTED_WORK_BUNDLE_VERSION);
    vcs_wr_u16le(wire + 10, 0);
    vcs_wr_u32le(wire + 12, (uint32_t)count);
    memcpy(wire + 16, accepted_work_root, 32);
    memcpy(wire + 48, accepted.candidate.candidate_source_root, 32);
    vcs_wr_u64le(wire + 80, task_authority_len);
    size_t off = ACCEPTED_BUNDLE_HEADER_BYTES;
    for (size_t i = 0; i < count; i++) {
        memcpy(wire + off, objects[i].root, 32); off += 32;
        vcs_wr_u32le(wire + off, (uint32_t)objects[i].len); off += 4;
        memcpy(wire + off, objects[i].bytes, objects[i].len);
        off += objects[i].len;
    }
    memcpy(wire + off, task_authority, task_authority_len);
    off += task_authority_len;
    free(task_authority);
    accepted_objects_free(objects, count);
    if (off != total) {
        free(wire);
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_SHAPE;
    }
    *wire_out = wire;
    *wire_len = total;
    if (accepted_out) *accepted_out = accepted;
    return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK;
}

static enum vcs_zcode_accepted_work_bundle_result accepted_bundle_parse(
    const uint8_t accepted_work_root[32], const uint8_t source_root[32],
    const uint8_t *wire, size_t wire_len,
    struct accepted_bundle_view *views, size_t *count_out,
    const uint8_t **task_authority, size_t *task_authority_len)
{
    if (wire_len < ACCEPTED_BUNDLE_HEADER_BYTES ||
        wire_len > VCS_ZCODE_ACCEPTED_WORK_BUNDLE_MAX_BYTES ||
        memcmp(wire, accepted_bundle_magic, 8) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_ZCODE_ACCEPTED_WORK_BUNDLE_VERSION ||
        vcs_rd_u16le(wire + 10) != 0 ||
        memcmp(wire + 16, accepted_work_root, 32) != 0 ||
        memcmp(wire + 48, source_root, 32) != 0)
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_SHAPE;
    uint32_t count = vcs_rd_u32le(wire + 12);
    uint64_t authority_len64 = vcs_rd_u64le(wire + 80);
    if (count == 0 || count > ACCEPTED_BUNDLE_MAX_OBJECTS ||
        authority_len64 == 0 || authority_len64 > SIZE_MAX)
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_LIMIT;
    size_t off = ACCEPTED_BUNDLE_HEADER_BYTES;
    bool found_accepted = false;
    for (uint32_t i = 0; i < count; i++) {
        if (wire_len - off < ACCEPTED_BUNDLE_RECORD_HEADER_BYTES)
            return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_SHAPE;
        views[i].root = wire + off;
        uint32_t len = vcs_rd_u32le(wire + off + 32);
        off += ACCEPTED_BUNDLE_RECORD_HEADER_BYTES;
        if (len == 0 || len > wire_len - off ||
            (i > 0 && memcmp(views[i - 1].root, views[i].root, 32) >= 0))
            return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_SHAPE;
        views[i].bytes = wire + off;
        views[i].len = len;
        found_accepted = found_accepted ||
            memcmp(views[i].root, accepted_work_root, 32) == 0;
        off += len;
    }
    size_t authority_len = (size_t)authority_len64;
    if (!found_accepted || authority_len != wire_len - off)
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_SHAPE;
    *count_out = count;
    *task_authority = wire + off;
    *task_authority_len = authority_len;
    return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK;
}

static bool accepted_bundle_store(
    const char *workspace, const struct accepted_bundle_view *views,
    size_t count)
{
    if (!vcs_object_store_init(workspace)) return false;
    for (size_t i = 0; i < count; i++)
        if (!vcs_object_put_addressed(
                workspace, views[i].root, views[i].bytes, views[i].len))
            return false;
    return true;
}

static bool accepted_bundle_proven_time(
    const struct accepted_bundle_view *views, size_t count,
    const uint8_t accepted_work_root[32], int64_t *created_out)
{
    for (size_t i = 0; i < count; i++) {
        if (memcmp(views[i].root, accepted_work_root, 32) != 0) continue;
        struct vcs_zcode_lane_receipt_v1 proven;
        if (vcs_zcode_lane_receipt_parse(
                views[i].bytes, views[i].len, &proven) != VCS_ZCODE_DEV_OK ||
            proven.lane != VCS_ZCODE_LANE_PROVEN || proven.created_unix <= 0)
            return false;
        *created_out = proven.created_unix;
        return true;
    }
    return false;
}

static uint32_t accepted_bundle_work_receipt_count(
    const struct accepted_bundle_view *views, size_t count)
{
    uint32_t receipts = 0;
    for (size_t i = 0; i < count; i++) {
        struct vcs_zcode_work_receipt_v1 receipt;
        if (views[i].len == VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES &&
            vcs_zcode_work_receipt_parse(
                views[i].bytes, views[i].len, &receipt) == VCS_ZCODE_DEV_OK)
            receipts++;
    }
    return receipts;
}

enum vcs_zcode_accepted_work_bundle_result
vcs_zcode_accepted_work_bundle_import(
    const char *workspace, const uint8_t accepted_work_root[32],
    const uint8_t source_root[32], const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_accepted_work_v1 *accepted_out,
    uint32_t *object_count_out, uint32_t *work_receipt_count_out)
{
    if (object_count_out) *object_count_out = 0;
    if (work_receipt_count_out) *work_receipt_count_out = 0;
    if (!workspace || !accepted_work_root || !source_root || !wire)
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_NULL;
    struct accepted_bundle_view views[ACCEPTED_BUNDLE_MAX_OBJECTS];
    memset(views, 0, sizeof(views));
    size_t count = 0, task_authority_len = 0;
    const uint8_t *task_authority = NULL;
    enum vcs_zcode_accepted_work_bundle_result result = accepted_bundle_parse(
        accepted_work_root, source_root, wire, wire_len, views, &count,
        &task_authority, &task_authority_len);
    if (result != VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK) return result;
    int64_t accepted_unix = 0;
    if (!accepted_bundle_proven_time(
            views, count, accepted_work_root, &accepted_unix))
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_AUTHORITY;

    char scratch[] = "/tmp/zcl-accepted-work.XXXXXX";
    if (!mkdtemp(scratch)) return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_CAS;
    bool staged = accepted_bundle_store(scratch, views, count);
    struct vcs_zcode_accepted_work_v1 accepted;
    staged = staged && vcs_zcode_accepted_work_resolve(
        scratch, accepted_work_root, accepted_unix, &accepted);
    staged = staged && memcmp(
        accepted.candidate.candidate_source_root, source_root, 32) == 0;
    staged = staged && vcs_zcode_task_authority_bundle_import(
        scratch, &accepted.task, task_authority, task_authority_len) ==
            VCS_ZCODE_TASK_AUTHORITY_OK;
    struct zcl_result removed = zcl_tree_remove(scratch);
    if (!removed.ok || !staged)
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_AUTHORITY;
    if (vcs_zcode_task_authority_bundle_validate_for_candidate(
            workspace, &accepted.task, &accepted.candidate,
            task_authority, task_authority_len) !=
            VCS_ZCODE_TASK_AUTHORITY_OK)
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_AUTHORITY;

    if (!accepted_bundle_store(workspace, views, count) ||
        vcs_zcode_task_authority_bundle_import(
            workspace, &accepted.task, task_authority,
            task_authority_len) != VCS_ZCODE_TASK_AUTHORITY_OK)
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_CAS;
    struct vcs_zcode_accepted_work_v1 final;
    if (!vcs_zcode_accepted_work_resolve(
            workspace, accepted_work_root, accepted_unix, &final) ||
        memcmp(final.candidate.candidate_source_root, source_root, 32) != 0)
        return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_AUTHORITY;
    if (accepted_out) *accepted_out = final;
    if (object_count_out) *object_count_out = (uint32_t)count;
    if (work_receipt_count_out)
        *work_receipt_count_out = accepted_bundle_work_receipt_count(
            views, count);
    return VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK;
}
