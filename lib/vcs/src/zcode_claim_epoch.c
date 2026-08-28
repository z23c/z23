/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only epoch proposal over signed v2 claims. */

#include "vcs/zcode_claim_epoch.h"

#include "base/checked.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t claim_epoch_magic[8] =
    {'Z','C','C','E','P','2',0,0};

static bool claim_epoch_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    if (!root) return false;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

const char *vcs_zcode_claim_epoch_error_string(
    enum vcs_zcode_claim_epoch_error error)
{
    switch (error) {
    case VCS_ZCODE_CLAIM_EPOCH_OK: return "ok";
    case VCS_ZCODE_CLAIM_EPOCH_NULL: return "null-argument";
    case VCS_ZCODE_CLAIM_EPOCH_ALLOC: return "allocation";
    case VCS_ZCODE_CLAIM_EPOCH_SIZE: return "wire-size";
    case VCS_ZCODE_CLAIM_EPOCH_MAGIC: return "wire-magic";
    case VCS_ZCODE_CLAIM_EPOCH_VERSION_ERROR: return "schema-version";
    case VCS_ZCODE_CLAIM_EPOCH_FLAGS: return "flags";
    case VCS_ZCODE_CLAIM_EPOCH_RESERVED: return "reserved";
    case VCS_ZCODE_CLAIM_EPOCH_ROOT: return "root";
    case VCS_ZCODE_CLAIM_EPOCH_TIME: return "cutoff";
    case VCS_ZCODE_CLAIM_EPOCH_COUNT: return "count";
    case VCS_ZCODE_CLAIM_EPOCH_SUM: return "accounting-sum";
    case VCS_ZCODE_CLAIM_EPOCH_DUPLICATE: return "duplicate-claim";
    case VCS_ZCODE_CLAIM_EPOCH_SELECTION: return "selection";
    }
    return "unknown-claim-epoch-error";
}

void vcs_zcode_claim_epoch_init(
    struct vcs_zcode_claim_epoch_proposal_v2 *proposal)
{
    if (proposal) memset(proposal, 0, sizeof(*proposal));
}

void vcs_zcode_claim_epoch_free(
    struct vcs_zcode_claim_epoch_proposal_v2 *proposal)
{
    if (!proposal) return;
    free(proposal->selected_claim_roots);
    memset(proposal, 0, sizeof(*proposal));
}

enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_validate(
    const struct vcs_zcode_claim_epoch_proposal_v2 *proposal)
{
    if (!proposal) return VCS_ZCODE_CLAIM_EPOCH_NULL;
    if (proposal->schema_version != VCS_ZCODE_CLAIM_EPOCH_VERSION)
        return VCS_ZCODE_CLAIM_EPOCH_VERSION_ERROR;
    if (proposal->flags != VCS_ZCODE_COMMONS_REQUIRED_FLAGS)
        return VCS_ZCODE_CLAIM_EPOCH_FLAGS;
    if (proposal->epoch == 0 || proposal->cutoff_height == 0 ||
        proposal->cutoff_mtp <= 0 || proposal->epoch_capacity_atoms == 0)
        return VCS_ZCODE_CLAIM_EPOCH_TIME;
    if (proposal->claim_count > VCS_ZCODE_COMMONS_MAX_CLAIMS ||
        proposal->selected_count > proposal->claim_count ||
        proposal->selected_count > VCS_ZCODE_CLAIM_EPOCH_MAX_SELECTED ||
        (proposal->selected_count != 0 &&
         !proposal->selected_claim_roots))
        return VCS_ZCODE_CLAIM_EPOCH_COUNT;
    uint64_t classified = (uint64_t)proposal->selected_count +
                          proposal->deferred_count + proposal->invalid_count;
    if (classified != proposal->claim_count)
        return VCS_ZCODE_CLAIM_EPOCH_COUNT;
    uint64_t accounted = 0;
    if (!zcl_u64_add(proposal->selected_atoms,
                     proposal->expired_capacity_atoms, &accounted) ||
        accounted != proposal->epoch_capacity_atoms ||
        (proposal->selected_count == 0) != (proposal->selected_atoms == 0))
        return VCS_ZCODE_CLAIM_EPOCH_SUM;
    if (proposal->recipient_cap_atoms == 0 ||
        proposal->recipient_cap_atoms > proposal->epoch_capacity_atoms ||
        proposal->lineage_cap_atoms != proposal->recipient_cap_atoms ||
        proposal->first_category >= VCS_ZCODE_COMMONS_CATEGORY_COUNT)
        return VCS_ZCODE_CLAIM_EPOCH_SELECTION;
    if (!claim_epoch_nonzero(proposal->policy_root) ||
        !claim_epoch_nonzero(proposal->claim_projection_root) ||
        !claim_epoch_nonzero(proposal->epoch_selection_root))
        return VCS_ZCODE_CLAIM_EPOCH_ROOT;
    for (size_t i = 0; i < proposal->selected_count; i++) {
        if (!claim_epoch_nonzero(proposal->selected_claim_roots[i]))
            return VCS_ZCODE_CLAIM_EPOCH_ROOT;
        for (size_t j = 0; j < i; j++)
            if (memcmp(proposal->selected_claim_roots[i],
                       proposal->selected_claim_roots[j], 32) == 0)
                return VCS_ZCODE_CLAIM_EPOCH_DUPLICATE;
    }
    return VCS_ZCODE_CLAIM_EPOCH_OK;
}

enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_encode(
    const struct vcs_zcode_claim_epoch_proposal_v2 *proposal,
    uint8_t **wire_out, size_t *wire_len_out)
{
    if (wire_out) *wire_out = NULL;
    if (wire_len_out) *wire_len_out = 0;
    if (!wire_out || !wire_len_out)
        return VCS_ZCODE_CLAIM_EPOCH_NULL;
    enum vcs_zcode_claim_epoch_error error =
        vcs_zcode_claim_epoch_validate(proposal);
    if (error != VCS_ZCODE_CLAIM_EPOCH_OK) return error;
    size_t wire_len = VCS_ZCODE_CLAIM_EPOCH_HEADER_BYTES +
                      (size_t)proposal->selected_count * 32u;
    uint8_t *wire = zcl_calloc(wire_len, 1, "ZCODE_claim_epoch_wire");
    if (!wire) return VCS_ZCODE_CLAIM_EPOCH_ALLOC;
    size_t off = 0;
    memcpy(wire + off, claim_epoch_magic, 8); off += 8;
    zcl_write_u16_le(wire + off, proposal->schema_version); off += 2;
    zcl_write_u16_le(wire + off, proposal->flags); off += 2;
    zcl_write_u64_le(wire + off, proposal->epoch); off += 8;
    zcl_write_u64_le(wire + off, proposal->cutoff_height); off += 8;
    zcl_write_u64_le(wire + off, (uint64_t)proposal->cutoff_mtp); off += 8;
    zcl_write_u64_le(wire + off, proposal->epoch_capacity_atoms); off += 8;
    zcl_write_u64_le(wire + off, proposal->selected_atoms); off += 8;
    zcl_write_u64_le(wire + off, proposal->expired_capacity_atoms); off += 8;
    zcl_write_u64_le(wire + off, proposal->recipient_cap_atoms); off += 8;
    zcl_write_u64_le(wire + off, proposal->lineage_cap_atoms); off += 8;
    zcl_write_u32_le(wire + off, proposal->claim_count); off += 4;
    zcl_write_u32_le(wire + off, proposal->selected_count); off += 4;
    zcl_write_u32_le(wire + off, proposal->deferred_count); off += 4;
    zcl_write_u32_le(wire + off, proposal->invalid_count); off += 4;
    wire[off++] = proposal->first_category;
    off += 7; /* reserved, already zero from calloc */
    memcpy(wire + off, proposal->previous_epoch_root, 32); off += 32;
    memcpy(wire + off, proposal->policy_root, 32); off += 32;
    memcpy(wire + off, proposal->claim_projection_root, 32); off += 32;
    memcpy(wire + off, proposal->epoch_selection_root, 32); off += 32;
    for (size_t i = 0; i < proposal->selected_count; i++) {
        memcpy(wire + off, proposal->selected_claim_roots[i], 32);
        off += 32;
    }
    if (off != wire_len) {
        free(wire);
        return VCS_ZCODE_CLAIM_EPOCH_SIZE;
    }
    *wire_out = wire;
    *wire_len_out = wire_len;
    return VCS_ZCODE_CLAIM_EPOCH_OK;
}

enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_decode(
    struct vcs_zcode_claim_epoch_proposal_v2 *out,
    const uint8_t *wire, size_t wire_len)
{
    if (out) vcs_zcode_claim_epoch_init(out);
    if (!out || !wire) return VCS_ZCODE_CLAIM_EPOCH_NULL;
    if (wire_len < VCS_ZCODE_CLAIM_EPOCH_HEADER_BYTES ||
        wire_len > VCS_ZCODE_CLAIM_EPOCH_MAX_WIRE_BYTES)
        return VCS_ZCODE_CLAIM_EPOCH_SIZE;
    if (memcmp(wire, claim_epoch_magic, 8) != 0)
        return VCS_ZCODE_CLAIM_EPOCH_MAGIC;
    struct vcs_zcode_claim_epoch_proposal_v2 decoded;
    vcs_zcode_claim_epoch_init(&decoded);
    size_t off = 8;
    decoded.schema_version = zcl_read_u16_le(wire + off); off += 2;
    decoded.flags = zcl_read_u16_le(wire + off); off += 2;
    decoded.epoch = zcl_read_u64_le(wire + off); off += 8;
    decoded.cutoff_height = zcl_read_u64_le(wire + off); off += 8;
    decoded.cutoff_mtp = (int64_t)zcl_read_u64_le(wire + off); off += 8;
    decoded.epoch_capacity_atoms = zcl_read_u64_le(wire + off); off += 8;
    decoded.selected_atoms = zcl_read_u64_le(wire + off); off += 8;
    decoded.expired_capacity_atoms = zcl_read_u64_le(wire + off); off += 8;
    decoded.recipient_cap_atoms = zcl_read_u64_le(wire + off); off += 8;
    decoded.lineage_cap_atoms = zcl_read_u64_le(wire + off); off += 8;
    decoded.claim_count = zcl_read_u32_le(wire + off); off += 4;
    decoded.selected_count = zcl_read_u32_le(wire + off); off += 4;
    decoded.deferred_count = zcl_read_u32_le(wire + off); off += 4;
    decoded.invalid_count = zcl_read_u32_le(wire + off); off += 4;
    decoded.first_category = wire[off++];
    for (size_t i = 0; i < 7; i++)
        if (wire[off + i] != 0)
            return VCS_ZCODE_CLAIM_EPOCH_RESERVED;
    off += 7;
    memcpy(decoded.previous_epoch_root, wire + off, 32); off += 32;
    memcpy(decoded.policy_root, wire + off, 32); off += 32;
    memcpy(decoded.claim_projection_root, wire + off, 32); off += 32;
    memcpy(decoded.epoch_selection_root, wire + off, 32); off += 32;
    size_t expected = VCS_ZCODE_CLAIM_EPOCH_HEADER_BYTES +
                      (size_t)decoded.selected_count * 32u;
    if (decoded.selected_count > VCS_ZCODE_CLAIM_EPOCH_MAX_SELECTED ||
        expected != wire_len)
        return VCS_ZCODE_CLAIM_EPOCH_SIZE;
    if (decoded.selected_count != 0) {
        decoded.selected_claim_roots = zcl_calloc(
            decoded.selected_count, sizeof(*decoded.selected_claim_roots),
            "ZCODE_claim_epoch_roots");
        if (!decoded.selected_claim_roots)
            return VCS_ZCODE_CLAIM_EPOCH_ALLOC;
        memcpy(decoded.selected_claim_roots, wire + off,
               (size_t)decoded.selected_count * 32u);
        off += (size_t)decoded.selected_count * 32u;
    }
    enum vcs_zcode_claim_epoch_error error =
        vcs_zcode_claim_epoch_validate(&decoded);
    if (error != VCS_ZCODE_CLAIM_EPOCH_OK || off != wire_len) {
        vcs_zcode_claim_epoch_free(&decoded);
        return error != VCS_ZCODE_CLAIM_EPOCH_OK
            ? error : VCS_ZCODE_CLAIM_EPOCH_SIZE;
    }
    *out = decoded;
    return VCS_ZCODE_CLAIM_EPOCH_OK;
}

enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_root(
    const struct vcs_zcode_claim_epoch_proposal_v2 *proposal,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!out) return VCS_ZCODE_CLAIM_EPOCH_NULL;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_zcode_claim_epoch_error error =
        vcs_zcode_claim_epoch_encode(proposal, &wire, &wire_len);
    if (error != VCS_ZCODE_CLAIM_EPOCH_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_CLAIM_EPOCH_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    free(wire);
    return VCS_ZCODE_CLAIM_EPOCH_OK;
}

enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_from_selection(
    const struct vcs_zcode_epoch_selection_v2 *input,
    const uint8_t policy_root[32],
    const uint8_t claim_projection_root[32],
    const struct vcs_zcode_epoch_selection_result_v2 *result,
    struct vcs_zcode_claim_epoch_proposal_v2 *out)
{
    if (out) vcs_zcode_claim_epoch_init(out);
    if (!input || !policy_root || !claim_projection_root || !result || !out ||
        (input->claim_count != 0 && !input->claims) ||
        input->claim_count > UINT32_MAX ||
        result->selected_count > UINT32_MAX ||
        result->deferred_count > UINT32_MAX ||
        result->invalid_count > UINT32_MAX)
        return VCS_ZCODE_CLAIM_EPOCH_NULL;
    out->schema_version = VCS_ZCODE_CLAIM_EPOCH_VERSION;
    out->flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
    out->epoch = input->epoch;
    out->cutoff_height = input->cutoff_height;
    out->cutoff_mtp = input->cutoff_mtp;
    out->epoch_capacity_atoms = input->epoch_capacity_atoms;
    out->selected_atoms = result->selected_atoms;
    out->expired_capacity_atoms = result->expired_capacity_atoms;
    out->recipient_cap_atoms = result->recipient_cap_atoms;
    out->lineage_cap_atoms = result->lineage_cap_atoms;
    out->claim_count = (uint32_t)input->claim_count;
    out->selected_count = (uint32_t)result->selected_count;
    out->deferred_count = (uint32_t)result->deferred_count;
    out->invalid_count = (uint32_t)result->invalid_count;
    out->first_category = result->first_category;
    memcpy(out->previous_epoch_root, input->previous_epoch_root, 32);
    memcpy(out->policy_root, policy_root, 32);
    memcpy(out->claim_projection_root, claim_projection_root, 32);
    memcpy(out->epoch_selection_root, result->epoch_creation_root, 32);
    if (out->selected_count != 0) {
        out->selected_claim_roots = zcl_calloc(
            out->selected_count, sizeof(*out->selected_claim_roots),
            "ZCODE_claim_epoch_selected");
        if (!out->selected_claim_roots) {
            vcs_zcode_claim_epoch_free(out);
            return VCS_ZCODE_CLAIM_EPOCH_ALLOC;
        }
        for (size_t i = 0; i < result->selected_count; i++) {
            size_t selected = result->selected_indices[i];
            if (selected >= input->claim_count) {
                vcs_zcode_claim_epoch_free(out);
                return VCS_ZCODE_CLAIM_EPOCH_SELECTION;
            }
            memcpy(out->selected_claim_roots[i],
                   input->claims[selected].claim_root, 32);
        }
    }
    enum vcs_zcode_claim_epoch_error error =
        vcs_zcode_claim_epoch_validate(out);
    if (error != VCS_ZCODE_CLAIM_EPOCH_OK)
        vcs_zcode_claim_epoch_free(out);
    return error;
}
