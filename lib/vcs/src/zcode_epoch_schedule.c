/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: owner-decided Proof-of-Participation emission schedule, encoded
 * as a simulation-only epoch proposer alongside the frozen era curve. */
#include "vcs/zcode_epoch_schedule.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/safe_alloc.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_commons_projection.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t epoch_schedule_magic[8] = {
    'Z', 'C', 'E', 'S', 'P', 'O', '\r', '\n'
};

const char *vcs_zcode_epoch_schedule_error_string(
    enum vcs_zcode_epoch_schedule_error error)
{
    switch (error) {
    case VCS_ZCODE_EPOCH_SCHEDULE_OK: return "ok";
    case VCS_ZCODE_EPOCH_SCHEDULE_NULL: return "null-argument";
    case VCS_ZCODE_EPOCH_SCHEDULE_ALLOC: return "allocation-failed";
    case VCS_ZCODE_EPOCH_SCHEDULE_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_EPOCH_SCHEDULE_MAGIC: return "wire-magic";
    case VCS_ZCODE_EPOCH_SCHEDULE_SCHEMA: return "schema-version";
    case VCS_ZCODE_EPOCH_SCHEDULE_RESERVED: return "reserved-field";
    case VCS_ZCODE_EPOCH_SCHEDULE_EPOCH: return "schedule-epoch";
    case VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR: return "schedule-predecessor";
    case VCS_ZCODE_EPOCH_SCHEDULE_CAP: return "schedule-cap";
    case VCS_ZCODE_EPOCH_SCHEDULE_SUM: return "schedule-sum";
    case VCS_ZCODE_EPOCH_SCHEDULE_ORDER: return "allocation-order";
    case VCS_ZCODE_EPOCH_SCHEDULE_CLASS: return "schedule-class";
    case VCS_ZCODE_EPOCH_SCHEDULE_OVERFLOW: return "checked-overflow";
    case VCS_ZCODE_EPOCH_SCHEDULE_CAS: return "cas-object";
    }
    return "unknown-epoch-schedule-error";
}

enum vcs_zcode_epoch_schedule_class vcs_zcode_epoch_schedule_class_for_category(
    uint16_t category)
{
    switch (category) {
    case VCS_ZCODE_CREATION_PUBLIC_SOURCE:
        return VCS_ZCODE_EPOCH_SCHEDULE_CLASS_CREATION;
    case VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION:
        return VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPRODUCTION;
    case VCS_ZCODE_CREATION_BORN_RED_FIX:
    case VCS_ZCODE_CREATION_SECURITY_FIX:
    case VCS_ZCODE_CREATION_COMPATIBILITY:
        return VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPAIR;
    case VCS_ZCODE_CREATION_PRESERVATION:
        return VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION;
    }
    return 0;
}

bool vcs_zcode_epoch_schedule_class_weight(
    enum vcs_zcode_epoch_schedule_class schedule_class, uint64_t *out_weight)
{
    if (!out_weight)
        return false;
    *out_weight = 0;
    switch (schedule_class) {
    case VCS_ZCODE_EPOCH_SCHEDULE_CLASS_CREATION: *out_weight = 100; break;
    case VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPRODUCTION: *out_weight = 40; break;
    case VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPAIR: *out_weight = 20; break;
    case VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION: *out_weight = 5; break;
    default: return false;
    }
    return true;
}

enum vcs_zcode_epoch_schedule_error vcs_zc23_schedule_epoch_budget_atoms(
    uint64_t already_emitted_atoms, uint64_t *out_atoms)
{
    if (!out_atoms)
        return VCS_ZCODE_EPOCH_SCHEDULE_NULL;
    *out_atoms = 0;
    if (already_emitted_atoms > VCS_ZC23_SCHEDULE_CAP_ATOMS)
        return VCS_ZCODE_EPOCH_SCHEDULE_CAP;
    *out_atoms =
        (VCS_ZC23_SCHEDULE_CAP_ATOMS - already_emitted_atoms) /
        VCS_ZC23_SCHEDULE_TOTAL_EPOCHS;
    return VCS_ZCODE_EPOCH_SCHEDULE_OK;
}

void vcs_zcode_epoch_schedule_proposal_init(
    struct vcs_zcode_epoch_schedule_proposal_v1 *proposal)
{
    if (proposal)
        memset(proposal, 0, sizeof(*proposal));
}

void vcs_zcode_epoch_schedule_proposal_free(
    struct vcs_zcode_epoch_schedule_proposal_v1 *proposal)
{
    if (!proposal)
        return;
    free(proposal->allocations);
    memset(proposal, 0, sizeof(*proposal));
}

enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_validate(
    const struct vcs_zcode_epoch_schedule_proposal_v1 *proposal)
{
    if (!proposal)
        return VCS_ZCODE_EPOCH_SCHEDULE_NULL;
    if (proposal->schema_version != VCS_ZCODE_EPOCH_SCHEDULE_VERSION)
        return VCS_ZCODE_EPOCH_SCHEDULE_SCHEMA;
    if (proposal->epoch == 0)
        return VCS_ZCODE_EPOCH_SCHEDULE_EPOCH;
    bool has_previous =
        zcl_bytes_any_set(proposal->previous_proposal_root, 32);
    if ((proposal->epoch == 1 && has_previous) ||
        (proposal->epoch != 1 && !has_previous))
        return VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR;

    uint64_t expected_budget = 0;
    if (vcs_zc23_schedule_epoch_budget_atoms(
            proposal->already_emitted_atoms, &expected_budget) !=
            VCS_ZCODE_EPOCH_SCHEDULE_OK ||
        proposal->budget_atoms != expected_budget)
        return VCS_ZCODE_EPOCH_SCHEDULE_CAP;
    uint64_t emitted_after = 0;
    if (!zcl_u64_add(proposal->already_emitted_atoms,
                     proposal->proposed_mint_atoms, &emitted_after) ||
        emitted_after > VCS_ZC23_SCHEDULE_CAP_ATOMS)
        return VCS_ZCODE_EPOCH_SCHEDULE_CAP;
    if (proposal->proposed_mint_atoms > proposal->budget_atoms ||
        proposal->unissued_atoms !=
            proposal->budget_atoms - proposal->proposed_mint_atoms ||
        (proposal->proposed_mint_atoms == 0) !=
            (proposal->allocation_count == 0) ||
        proposal->evidence_count !=
            proposal->eligible_count + proposal->preservation_skipped)
        return VCS_ZCODE_EPOCH_SCHEDULE_SUM;
    if (proposal->allocation_count >
            VCS_ZCODE_EPOCH_SCHEDULE_MAX_ALLOCATIONS ||
        (proposal->allocation_count != 0 && !proposal->allocations))
        return VCS_ZCODE_EPOCH_SCHEDULE_ORDER;

    uint64_t award_sum = 0;
    for (size_t i = 0; i < proposal->allocation_count; i++) {
        const struct vcs_zcode_epoch_schedule_allocation *allocation =
            &proposal->allocations[i];
        if (!zcl_bytes_any_set(allocation->contributor_binding_root, 32) ||
            allocation->award_atoms == 0)
            return VCS_ZCODE_EPOCH_SCHEDULE_ORDER;
        if (allocation->schedule_class ==
                VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION ||
            allocation->schedule_class == 0 ||
            allocation->schedule_class >
                VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION)
            return VCS_ZCODE_EPOCH_SCHEDULE_CLASS;
        if (i != 0) {
            const struct vcs_zcode_epoch_schedule_allocation *previous =
                &proposal->allocations[i - 1];
            int order = memcmp(previous->contributor_binding_root,
                               allocation->contributor_binding_root, 32);
            if (order > 0 ||
                (order == 0 && previous->schedule_class >=
                                   allocation->schedule_class))
                return VCS_ZCODE_EPOCH_SCHEDULE_ORDER;
        }
        if (!zcl_u64_add(award_sum, allocation->award_atoms, &award_sum))
            return VCS_ZCODE_EPOCH_SCHEDULE_OVERFLOW;
    }
    if (award_sum != proposal->proposed_mint_atoms)
        return VCS_ZCODE_EPOCH_SCHEDULE_SUM;
    return VCS_ZCODE_EPOCH_SCHEDULE_OK;
}

enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_serialize(
    const struct vcs_zcode_epoch_schedule_proposal_v1 *proposal,
    uint8_t **out, size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!proposal || !out || !out_len)
        return VCS_ZCODE_EPOCH_SCHEDULE_NULL;
    enum vcs_zcode_epoch_schedule_error error =
        vcs_zcode_epoch_schedule_validate(proposal);
    if (error != VCS_ZCODE_EPOCH_SCHEDULE_OK)
        return error;
    size_t rows_bytes = 0, wire_len = 0;
    if (!zcl_size_mul(proposal->allocation_count,
                      VCS_ZCODE_EPOCH_SCHEDULE_ALLOCATION_BYTES,
                      &rows_bytes) ||
        !zcl_size_add(VCS_ZCODE_EPOCH_SCHEDULE_HEADER_BYTES, rows_bytes,
                      &wire_len))
        return VCS_ZCODE_EPOCH_SCHEDULE_OVERFLOW;
    uint8_t *wire = zcl_malloc(wire_len, "zcode_epoch_schedule_wire");
    if (!wire)
        return VCS_ZCODE_EPOCH_SCHEDULE_ALLOC;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, wire_len);
    bool ok = zcl_codec_write_bytes(&writer, epoch_schedule_magic, 8) &&
        zcl_codec_write_u16le(&writer, proposal->schema_version) &&
        zcl_codec_write_u16le(&writer, 0) &&
        zcl_codec_write_u64le(&writer, proposal->epoch) &&
        zcl_codec_write_u32le(&writer, proposal->evidence_count) &&
        zcl_codec_write_u32le(&writer, proposal->eligible_count) &&
        zcl_codec_write_u32le(&writer, proposal->preservation_skipped) &&
        zcl_codec_write_u32le(&writer, (uint32_t)proposal->allocation_count) &&
        zcl_codec_write_u64le(&writer, proposal->budget_atoms) &&
        zcl_codec_write_u64le(&writer, proposal->already_emitted_atoms) &&
        zcl_codec_write_u64le(&writer, proposal->proposed_mint_atoms) &&
        zcl_codec_write_u64le(&writer, proposal->unissued_atoms) &&
        zcl_codec_write_bytes(&writer, proposal->previous_proposal_root, 32);
    for (size_t i = 0; ok && i < proposal->allocation_count; i++) {
        const struct vcs_zcode_epoch_schedule_allocation *allocation =
            &proposal->allocations[i];
        ok = zcl_codec_write_bytes(
                 &writer, allocation->contributor_binding_root, 32) &&
             zcl_codec_write_u16le(&writer, allocation->schedule_class) &&
             zcl_codec_write_u16le(&writer, 0) &&
             zcl_codec_write_u64le(&writer, allocation->award_atoms);
    }
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) ||
        written != wire_len) {
        free(wire);
        return VCS_ZCODE_EPOCH_SCHEDULE_WIRE_SIZE;
    }
    *out = wire;
    *out_len = wire_len;
    return VCS_ZCODE_EPOCH_SCHEDULE_OK;
}

enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_epoch_schedule_proposal_v1 *out)
{
    if (out)
        vcs_zcode_epoch_schedule_proposal_init(out);
    if (!wire || !out)
        return VCS_ZCODE_EPOCH_SCHEDULE_NULL;
    if (wire_len < VCS_ZCODE_EPOCH_SCHEDULE_HEADER_BYTES ||
        wire_len > VCS_ZCODE_EPOCH_SCHEDULE_MAX_WIRE_BYTES)
        return VCS_ZCODE_EPOCH_SCHEDULE_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8]; uint16_t reserved16; uint32_t count;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u16le(&reader, &reserved16) &&
        zcl_codec_read_u64le(&reader, &out->epoch) &&
        zcl_codec_read_u32le(&reader, &out->evidence_count) &&
        zcl_codec_read_u32le(&reader, &out->eligible_count) &&
        zcl_codec_read_u32le(&reader, &out->preservation_skipped) &&
        zcl_codec_read_u32le(&reader, &count) &&
        zcl_codec_read_u64le(&reader, &out->budget_atoms) &&
        zcl_codec_read_u64le(&reader, &out->already_emitted_atoms) &&
        zcl_codec_read_u64le(&reader, &out->proposed_mint_atoms) &&
        zcl_codec_read_u64le(&reader, &out->unissued_atoms) &&
        zcl_codec_read_bytes(&reader, out->previous_proposal_root, 32);
    size_t rows_bytes = 0, expected = 0;
    if (!ok || count > VCS_ZCODE_EPOCH_SCHEDULE_MAX_ALLOCATIONS ||
        !zcl_size_mul(count, VCS_ZCODE_EPOCH_SCHEDULE_ALLOCATION_BYTES,
                      &rows_bytes) ||
        !zcl_size_add(VCS_ZCODE_EPOCH_SCHEDULE_HEADER_BYTES, rows_bytes,
                      &expected) || expected != wire_len) {
        vcs_zcode_epoch_schedule_proposal_free(out);
        return VCS_ZCODE_EPOCH_SCHEDULE_WIRE_SIZE;
    }
    if (count != 0) {
        out->allocations = zcl_calloc(
            count, sizeof(*out->allocations),
            "zcode_epoch_schedule_allocations");
        if (!out->allocations) {
            vcs_zcode_epoch_schedule_proposal_free(out);
            return VCS_ZCODE_EPOCH_SCHEDULE_ALLOC;
        }
    }
    out->allocation_count = count;
    for (size_t i = 0; ok && i < count; i++) {
        uint16_t row_reserved = 0;
        ok = zcl_codec_read_bytes(
                 &reader, out->allocations[i].contributor_binding_root,
                 32) &&
             zcl_codec_read_u16le(&reader,
                                  &out->allocations[i].schedule_class) &&
             zcl_codec_read_u16le(&reader, &row_reserved) &&
             zcl_codec_read_u64le(&reader,
                                  &out->allocations[i].award_atoms);
        if (ok && row_reserved != 0) {
            vcs_zcode_epoch_schedule_proposal_free(out);
            return VCS_ZCODE_EPOCH_SCHEDULE_RESERVED;
        }
    }
    ok = ok && zcl_codec_reader_finish(&reader);
    if (!ok) {
        vcs_zcode_epoch_schedule_proposal_free(out);
        return VCS_ZCODE_EPOCH_SCHEDULE_WIRE_SIZE;
    }
    if (memcmp(magic, epoch_schedule_magic, 8) != 0) {
        vcs_zcode_epoch_schedule_proposal_free(out);
        return VCS_ZCODE_EPOCH_SCHEDULE_MAGIC;
    }
    if (reserved16 != 0) {
        vcs_zcode_epoch_schedule_proposal_free(out);
        return VCS_ZCODE_EPOCH_SCHEDULE_RESERVED;
    }
    enum vcs_zcode_epoch_schedule_error error =
        vcs_zcode_epoch_schedule_validate(out);
    if (error != VCS_ZCODE_EPOCH_SCHEDULE_OK)
        vcs_zcode_epoch_schedule_proposal_free(out);
    return error;
}

enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_root(
    const struct vcs_zcode_epoch_schedule_proposal_v1 *proposal,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!proposal || !out)
        return VCS_ZCODE_EPOCH_SCHEDULE_NULL;
    uint8_t *wire = NULL; size_t wire_len = 0;
    enum vcs_zcode_epoch_schedule_error error =
        vcs_zcode_epoch_schedule_serialize(proposal, &wire, &wire_len);
    if (error != VCS_ZCODE_EPOCH_SCHEDULE_OK)
        return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_EPOCH_SCHEDULE_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    free(wire);
    return VCS_ZCODE_EPOCH_SCHEDULE_OK;
}

/* One eligible evidence row: the creation entry plus its class weight. The
 * planner sorts these by (binding root, class) so equal groups are adjacent
 * and the allocation order is canonical. */
struct schedule_evidence_row {
    uint8_t contributor_binding_root[32];
    uint16_t schedule_class;
    uint64_t weight;
};

static int schedule_row_compare(const void *left, const void *right)
{
    const struct schedule_evidence_row *a = left, *b = right;
    int order = memcmp(a->contributor_binding_root,
                       b->contributor_binding_root, 32);
    if (order != 0)
        return order;
    if (a->schedule_class != b->schedule_class)
        return a->schedule_class < b->schedule_class ? -1 : 1;
    return 0;
}

static enum vcs_zcode_epoch_schedule_error schedule_check_predecessor(
    const struct vcs_zcode_epoch_schedule_input *input)
{
    bool has_previous = zcl_bytes_any_set(input->previous_proposal_root, 32);
    if (input->epoch == 1)
        return has_previous ? VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR
                            : VCS_ZCODE_EPOCH_SCHEDULE_OK;
    if (!has_previous)
        return VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR;
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    struct vcs_zcode_epoch_schedule_proposal_v1 previous;
    vcs_zcode_epoch_schedule_proposal_init(&previous);
    bool ok = vcs_object_load_raw_bounded(
                  input->workspace, input->previous_proposal_root,
                  VCS_ZCODE_EPOCH_SCHEDULE_MAX_WIRE_BYTES, &wire,
                  &wire_len) == 0 &&
        vcs_zcode_epoch_schedule_parse(wire, wire_len, &previous) ==
            VCS_ZCODE_EPOCH_SCHEDULE_OK &&
        vcs_zcode_epoch_schedule_root(&previous, observed) ==
            VCS_ZCODE_EPOCH_SCHEDULE_OK &&
        memcmp(observed, input->previous_proposal_root, 32) == 0 &&
        previous.epoch != UINT64_MAX &&
        previous.epoch + 1u == input->epoch;
    free(wire);
    vcs_zcode_epoch_schedule_proposal_free(&previous);
    return ok ? VCS_ZCODE_EPOCH_SCHEDULE_OK
              : VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR;
}

enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_propose_cas(
    const struct vcs_zcode_epoch_schedule_input *input,
    struct vcs_zcode_epoch_schedule_proposal_v1 *out)
{
    if (out)
        vcs_zcode_epoch_schedule_proposal_init(out);
    if (!input || !out || !input->workspace ||
        !input->previous_proposal_root)
        return VCS_ZCODE_EPOCH_SCHEDULE_NULL;
    if (input->epoch == 0)
        return VCS_ZCODE_EPOCH_SCHEDULE_EPOCH;
    enum vcs_zcode_epoch_schedule_error error =
        schedule_check_predecessor(input);
    if (error != VCS_ZCODE_EPOCH_SCHEDULE_OK)
        return error;

    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(input->workspace);
    if (!projection)
        return VCS_ZCODE_EPOCH_SCHEDULE_CAS;
    out->schema_version = VCS_ZCODE_EPOCH_SCHEDULE_VERSION;
    out->epoch = input->epoch;
    out->already_emitted_atoms =
        vcs_zcode_commons_projection_minted_atoms(projection);
    memcpy(out->previous_proposal_root, input->previous_proposal_root, 32);
    error = vcs_zc23_schedule_epoch_budget_atoms(
        out->already_emitted_atoms, &out->budget_atoms);
    if (error != VCS_ZCODE_EPOCH_SCHEDULE_OK) {
        vcs_zcode_commons_projection_free(projection);
        vcs_zcode_epoch_schedule_proposal_free(out);
        return error;
    }

    size_t creation_count =
        vcs_zcode_commons_projection_creation_count(projection);
    struct schedule_evidence_row *rows = NULL;
    if (creation_count != 0) {
        rows = zcl_calloc(creation_count, sizeof(*rows),
                          "zcode_epoch_schedule_rows");
        if (!rows) {
            vcs_zcode_commons_projection_free(projection);
            vcs_zcode_epoch_schedule_proposal_free(out);
            return VCS_ZCODE_EPOCH_SCHEDULE_ALLOC;
        }
    }
    uint64_t total_weight = 0;
    for (size_t i = 0; i < creation_count; i++) {
        const struct vcs_zcode_commons_creation_entry *entry =
            vcs_zcode_commons_projection_creation_at(projection, i);
        if (!entry || entry->epoch != input->epoch)
            continue;
        if (out->evidence_count == UINT32_MAX) {
            free(rows);
            vcs_zcode_commons_projection_free(projection);
            vcs_zcode_epoch_schedule_proposal_free(out);
            return VCS_ZCODE_EPOCH_SCHEDULE_OVERFLOW;
        }
        out->evidence_count++;
        enum vcs_zcode_epoch_schedule_class schedule_class =
            vcs_zcode_epoch_schedule_class_for_category(entry->category);
        if (schedule_class == VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION) {
            out->preservation_skipped++;
            continue;
        }
        uint64_t weight = 0;
        if (schedule_class == 0 ||
            !vcs_zcode_epoch_schedule_class_weight(schedule_class,
                                                   &weight) ||
            !zcl_u64_add(total_weight, weight, &total_weight)) {
            free(rows);
            vcs_zcode_commons_projection_free(projection);
            vcs_zcode_epoch_schedule_proposal_free(out);
            return VCS_ZCODE_EPOCH_SCHEDULE_OVERFLOW;
        }
        memcpy(rows[out->eligible_count].contributor_binding_root,
               entry->contributor_binding_root, 32);
        rows[out->eligible_count].schedule_class =
            (uint16_t)schedule_class;
        rows[out->eligible_count].weight = weight;
        out->eligible_count++;
    }
    vcs_zcode_commons_projection_free(projection);

    /* Non-issuance is not redistribution: no eligible evidence means the
     * whole budget stays unissued in the remaining pool. */
    if (out->eligible_count == 0 || out->budget_atoms == 0) {
        out->unissued_atoms = out->budget_atoms;
        free(rows);
        return VCS_ZCODE_EPOCH_SCHEDULE_OK;
    }
    qsort(rows, out->eligible_count, sizeof(*rows), schedule_row_compare);

    struct vcs_zcode_epoch_schedule_allocation *allocations = zcl_calloc(
        out->eligible_count, sizeof(*allocations),
        "zcode_epoch_schedule_allocations");
    if (!allocations) {
        free(rows);
        vcs_zcode_epoch_schedule_proposal_free(out);
        return VCS_ZCODE_EPOCH_SCHEDULE_ALLOC;
    }
    for (size_t i = 0; i < out->eligible_count;) {
        size_t group_end = i + 1;
        uint64_t group_weight = rows[i].weight;
        while (group_end < out->eligible_count &&
               schedule_row_compare(&rows[i], &rows[group_end]) == 0) {
            if (!zcl_u64_add(group_weight, rows[group_end].weight,
                             &group_weight)) {
                free(allocations);
                free(rows);
                vcs_zcode_epoch_schedule_proposal_free(out);
                return VCS_ZCODE_EPOCH_SCHEDULE_OVERFLOW;
            }
            group_end++;
        }
        uint64_t scaled = 0;
        if (!zcl_u64_mul(out->budget_atoms, group_weight, &scaled)) {
            free(allocations);
            free(rows);
            vcs_zcode_epoch_schedule_proposal_free(out);
            return VCS_ZCODE_EPOCH_SCHEDULE_OVERFLOW;
        }
        uint64_t award = scaled / total_weight;
        if (award != 0) {
            struct vcs_zcode_epoch_schedule_allocation *allocation =
                &allocations[out->allocation_count];
            memcpy(allocation->contributor_binding_root,
                   rows[i].contributor_binding_root, 32);
            allocation->schedule_class = rows[i].schedule_class;
            allocation->award_atoms = award;
            out->allocation_count++;
            out->proposed_mint_atoms += award;
        }
        i = group_end;
    }
    free(rows);
    out->unissued_atoms = out->budget_atoms - out->proposed_mint_atoms;
    if (out->allocation_count == 0) {
        free(allocations);
    } else {
        out->allocations = allocations;
    }
    return VCS_ZCODE_EPOCH_SCHEDULE_OK;
}
