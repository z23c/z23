/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic fixture-only C23 evidence snapshots and elections. */
#include "vcs/zcode_shadow_election.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

#define C23_EVIDENCE_SET_DOMAIN "zcl.zcode.c23.evidence_set.v1"

struct shadow_candidate {
    const struct vcs_c23_seed_v1 *seed;
    uint8_t seed_root[32];
    uint8_t zid_pubkey[32];
    uint64_t weight;
    bool selected;
};

struct shadow_evidence {
    uint8_t contribution_root[32];
    uint8_t zid_pubkey[32];
    uint64_t event_epoch;
    uint32_t points;
};

static int shadow_candidate_cmp(const void *a, const void *b)
{
    const struct shadow_candidate *ca = a;
    const struct shadow_candidate *cb = b;
    return memcmp(ca->zid_pubkey, cb->zid_pubkey, 32);
}

static int shadow_evidence_cmp(const void *a, const void *b)
{
    const struct shadow_evidence *ea = a;
    const struct shadow_evidence *eb = b;
    return memcmp(ea->contribution_root, eb->contribution_root, 32);
}

static void shadow_hash_begin(struct sha3_256_ctx *sha, const char *domain,
                              size_t domain_len)
{
    sha3_256_init(sha);
    sha3_256_write(sha, (const uint8_t *)domain, domain_len);
}

static void shadow_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t bytes[8];
    zcl_write_u64_le(bytes, value);
    sha3_256_write(sha, bytes, sizeof(bytes));
}

const char *vcs_c23_shadow_election_error_string(
    enum vcs_c23_shadow_election_error error)
{
    switch (error) {
    case VCS_C23_SHADOW_ELECTION_OK: return "ok";
    case VCS_C23_SHADOW_ELECTION_NULL: return "null";
    case VCS_C23_SHADOW_ELECTION_LIMIT: return "limit";
    case VCS_C23_SHADOW_ELECTION_ROOT: return "root";
    case VCS_C23_SHADOW_ELECTION_NETWORK: return "network";
    case VCS_C23_SHADOW_ELECTION_EPOCH: return "epoch";
    case VCS_C23_SHADOW_ELECTION_DUPLICATE: return "duplicate";
    case VCS_C23_SHADOW_ELECTION_IDENTITY: return "identity";
    case VCS_C23_SHADOW_ELECTION_EVIDENCE: return "evidence";
    case VCS_C23_SHADOW_ELECTION_OVERFLOW: return "overflow";
    case VCS_C23_SHADOW_ELECTION_ANCHOR: return "anchor";
    case VCS_C23_SHADOW_ELECTION_IMMATURE: return "immature";
    case VCS_C23_SHADOW_ELECTION_ALLOCATION: return "allocation";
    case VCS_C23_SHADOW_ELECTION_SEATS: return "seats";
    }
    return "unknown";
}

static struct shadow_candidate *shadow_find_candidate(
    struct shadow_candidate *candidates, size_t count,
    const uint8_t zid_pubkey[32])
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(zid_pubkey, candidates[mid].zid_pubkey, 32);
        if (cmp == 0) return &candidates[mid];
        if (cmp < 0) hi = mid;
        else lo = mid + 1;
    }
    return NULL;
}

static bool shadow_evidence_credit(uint32_t points, uint64_t age,
                                   uint64_t *out)
{
    uint64_t scaled = 0;
    if (age == 0 || age > VCS_C23_SHADOW_HISTORY_EPOCHS || points == 0 ||
        points > VCS_C23_SHADOW_MAX_WEIGHT ||
        !zcl_u64_mul(points,
                     VCS_C23_SHADOW_HISTORY_EPOCHS + 1u - age,
                     &scaled) ||
        !zcl_u64_add(scaled, VCS_C23_SHADOW_HISTORY_EPOCHS - 1u,
                     &scaled))
        return false;
    *out = scaled / VCS_C23_SHADOW_HISTORY_EPOCHS;
    return *out != 0;
}

static void shadow_evidence_set_root(
    const struct shadow_evidence *evidence, size_t evidence_count,
    uint8_t out[32])
{
    static const char domain[] = C23_EVIDENCE_SET_DOMAIN;
    struct sha3_256_ctx sha;
    shadow_hash_begin(&sha, domain, sizeof(domain));
    shadow_hash_u64(&sha, evidence_count);
    for (size_t i = 0; i < evidence_count; i++) {
        sha3_256_write(&sha, evidence[i].contribution_root, 32);
        sha3_256_write(&sha, evidence[i].zid_pubkey, 32);
        shadow_hash_u64(&sha, evidence[i].event_epoch);
        shadow_hash_u64(&sha, evidence[i].points);
    }
    sha3_256_finalize(&sha, out);
}

static void shadow_snapshot_root(
    const struct vcs_c23_evidence_snapshot_v1 *snapshot, uint8_t out[32])
{
    static const char domain[] = VCS_C23_EVIDENCE_SNAPSHOT_DOMAIN;
    struct sha3_256_ctx sha;
    shadow_hash_begin(&sha, domain, sizeof(domain));
    shadow_hash_u64(&sha, snapshot->schema_version);
    shadow_hash_u64(&sha, snapshot->election_epoch);
    shadow_hash_u64(&sha, snapshot->freeze_height);
    sha3_256_write(&sha, snapshot->freeze_hash, 32);
    sha3_256_write(&sha, snapshot->network_genesis_root, 32);
    sha3_256_write(&sha, snapshot->policy_root, 32);
    sha3_256_write(&sha, snapshot->evidence_set_root, 32);
    shadow_hash_u64(&sha, snapshot->candidate_count);
    shadow_hash_u64(&sha, snapshot->total_weight);
    for (size_t i = 0; i < snapshot->candidate_count; i++) {
        sha3_256_write(&sha, snapshot->rows[i].seed_root, 32);
        sha3_256_write(&sha, snapshot->rows[i].zid_pubkey, 32);
        shadow_hash_u64(&sha, snapshot->rows[i].weight);
    }
    sha3_256_finalize(&sha, out);
}

enum vcs_c23_shadow_election_error vcs_c23_evidence_snapshot_build(
    const struct vcs_c23_evidence_snapshot_input *input,
    struct vcs_c23_evidence_snapshot_row *rows, size_t row_capacity,
    struct vcs_c23_evidence_snapshot_v1 *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (rows && row_capacity)
        memset(rows, 0, row_capacity * sizeof(*rows));
    if (!input || !rows || !out || !input->network_genesis_root ||
        !input->policy_root || !input->seeds || !input->freeze_hash ||
        !input->anchor_is_active)
        return VCS_C23_SHADOW_ELECTION_NULL;
    if (!zcl_bytes_any_set(input->network_genesis_root, 32) ||
        !zcl_bytes_any_set(input->policy_root, 32) ||
        !zcl_bytes_any_set(input->freeze_hash, 32))
        return VCS_C23_SHADOW_ELECTION_ROOT;
    if (input->seed_count == 0 ||
        input->seed_count > VCS_C23_SHADOW_MAX_CANDIDATES ||
        input->seed_count > row_capacity ||
        input->evidence_count > VCS_C23_SHADOW_MAX_EVIDENCE ||
        (input->evidence_count != 0 && !input->evidence))
        return VCS_C23_SHADOW_ELECTION_LIMIT;
    if (input->active_height < input->freeze_height)
        return VCS_C23_SHADOW_ELECTION_IMMATURE;
    if (!input->anchor_is_active(input->anchor_opaque,
                                 input->freeze_height,
                                 input->freeze_hash))
        return VCS_C23_SHADOW_ELECTION_ANCHOR;

    struct shadow_candidate *candidates = zcl_calloc(
        input->seed_count, sizeof(*candidates), "c23_shadow_candidates");
    if (!candidates) return VCS_C23_SHADOW_ELECTION_ALLOCATION;
    enum vcs_c23_shadow_election_error error =
        VCS_C23_SHADOW_ELECTION_OK;
    for (size_t i = 0; i < input->seed_count; i++) {
        const struct vcs_c23_seed_v1 *seed = input->seeds[i].seed;
        uint64_t maturity_height = 0; int64_t maturity_mtp = 0;
        if (!seed || vcs_c23_seed_root(seed, candidates[i].seed_root) !=
                         VCS_C23_SEED_OK) {
            error = VCS_C23_SHADOW_ELECTION_ROOT;
            goto done;
        }
        if (memcmp(seed->network_genesis_root,
                   input->network_genesis_root, 32) != 0) {
            error = VCS_C23_SHADOW_ELECTION_NETWORK;
            goto done;
        }
        enum vcs_c23_seed_error maturity = vcs_c23_seed_maturity(
            seed, input->active_height, input->active_mtp,
            input->anchor_is_active, input->anchor_opaque,
            &maturity_height, &maturity_mtp);
        (void)maturity_height; (void)maturity_mtp;
        if (maturity != VCS_C23_SEED_OK) {
            if (maturity == VCS_C23_SEED_ERR_IMMATURE)
                error = VCS_C23_SHADOW_ELECTION_IMMATURE;
            else if (maturity == VCS_C23_SEED_ERR_REORG)
                error = VCS_C23_SHADOW_ELECTION_ANCHOR;
            else
                error = VCS_C23_SHADOW_ELECTION_EVIDENCE;
            goto done;
        }
        candidates[i].seed = seed;
        memcpy(candidates[i].zid_pubkey, seed->zid_pubkey, 32);
        candidates[i].weight = 1;
    }
    qsort(candidates, input->seed_count, sizeof(*candidates),
          shadow_candidate_cmp);
    for (size_t i = 1; i < input->seed_count; i++) {
        if (memcmp(candidates[i - 1].zid_pubkey,
                   candidates[i].zid_pubkey, 32) == 0) {
            error = VCS_C23_SHADOW_ELECTION_DUPLICATE;
            goto done;
        }
    }

    struct shadow_evidence *evidence = NULL;
    if (input->evidence_count != 0) {
        evidence = zcl_calloc(input->evidence_count, sizeof(*evidence),
                              "c23_shadow_evidence");
        if (!evidence) {
            error = VCS_C23_SHADOW_ELECTION_ALLOCATION;
            goto done;
        }
    }
    for (size_t i = 0; i < input->evidence_count; i++) {
        memcpy(evidence[i].contribution_root,
               input->evidence[i].contribution_root, 32);
        memcpy(evidence[i].zid_pubkey, input->evidence[i].zid_pubkey, 32);
        evidence[i].event_epoch = input->evidence[i].event_epoch;
        evidence[i].points = input->evidence[i].points;
        if (!zcl_bytes_any_set(evidence[i].contribution_root, 32) ||
            !zcl_bytes_any_set(evidence[i].zid_pubkey, 32) ||
            evidence[i].event_epoch >= input->election_epoch) {
            error = VCS_C23_SHADOW_ELECTION_EVIDENCE;
            goto evidence_done;
        }
    }
    qsort(evidence, input->evidence_count, sizeof(*evidence),
          shadow_evidence_cmp);
    for (size_t i = 0; i < input->evidence_count; i++) {
        if (i != 0 && memcmp(evidence[i - 1].contribution_root,
                             evidence[i].contribution_root, 32) == 0) {
            error = VCS_C23_SHADOW_ELECTION_DUPLICATE;
            goto evidence_done;
        }
        struct shadow_candidate *candidate = shadow_find_candidate(
            candidates, input->seed_count, evidence[i].zid_pubkey);
        if (!candidate) {
            error = VCS_C23_SHADOW_ELECTION_IDENTITY;
            goto evidence_done;
        }
        uint64_t credit = 0;
        if (!shadow_evidence_credit(
                evidence[i].points,
                input->election_epoch - evidence[i].event_epoch,
                &credit)) {
            error = VCS_C23_SHADOW_ELECTION_EVIDENCE;
            goto evidence_done;
        }
        uint64_t weight = 0;
        if (!zcl_u64_add(candidate->weight, credit, &weight)) {
            error = VCS_C23_SHADOW_ELECTION_OVERFLOW;
            goto evidence_done;
        }
        candidate->weight = weight > VCS_C23_SHADOW_MAX_WEIGHT
            ? VCS_C23_SHADOW_MAX_WEIGHT : weight;
    }

    out->schema_version = VCS_C23_SHADOW_ELECTION_VERSION;
    out->election_epoch = input->election_epoch;
    out->freeze_height = input->freeze_height;
    memcpy(out->freeze_hash, input->freeze_hash, 32);
    memcpy(out->network_genesis_root, input->network_genesis_root, 32);
    memcpy(out->policy_root, input->policy_root, 32);
    shadow_evidence_set_root(evidence, input->evidence_count,
                             out->evidence_set_root);
    out->candidate_count = input->seed_count;
    out->rows = rows;
    for (size_t i = 0; i < input->seed_count; i++) {
        memcpy(rows[i].seed_root, candidates[i].seed_root, 32);
        memcpy(rows[i].zid_pubkey, candidates[i].zid_pubkey, 32);
        rows[i].weight = candidates[i].weight;
        if (!zcl_u64_add(out->total_weight, rows[i].weight,
                         &out->total_weight)) {
            error = VCS_C23_SHADOW_ELECTION_OVERFLOW;
            goto evidence_done;
        }
    }
    shadow_snapshot_root(out, out->snapshot_root);

evidence_done:
    free(evidence);
done:
    free(candidates);
    if (error != VCS_C23_SHADOW_ELECTION_OK) {
        memset(out, 0, sizeof(*out));
        memset(rows, 0, row_capacity * sizeof(*rows));
    }
    return error;
}

static bool shadow_snapshot_valid(
    const struct vcs_c23_evidence_snapshot_v1 *snapshot)
{
    if (!snapshot || snapshot->schema_version !=
            VCS_C23_SHADOW_ELECTION_VERSION || !snapshot->rows ||
        snapshot->candidate_count == 0 ||
        snapshot->candidate_count > VCS_C23_SHADOW_MAX_CANDIDATES ||
        !zcl_bytes_any_set(snapshot->snapshot_root, 32) ||
        !zcl_bytes_any_set(snapshot->evidence_set_root, 32) ||
        snapshot->total_weight == 0)
        return false;
    uint64_t total = 0;
    for (size_t i = 0; i < snapshot->candidate_count; i++) {
        if (!zcl_bytes_any_set(snapshot->rows[i].seed_root, 32) ||
            !zcl_bytes_any_set(snapshot->rows[i].zid_pubkey, 32) ||
            snapshot->rows[i].weight == 0 ||
            snapshot->rows[i].weight > VCS_C23_SHADOW_MAX_WEIGHT ||
            (i != 0 && memcmp(snapshot->rows[i - 1].zid_pubkey,
                              snapshot->rows[i].zid_pubkey, 32) >= 0) ||
            !zcl_u64_add(total, snapshot->rows[i].weight, &total))
            return false;
    }
    uint8_t root[32];
    shadow_snapshot_root(snapshot, root);
    return total == snapshot->total_weight &&
           memcmp(root, snapshot->snapshot_root, 32) == 0;
}

static void shadow_election_seed_root(
    const struct vcs_c23_shadow_election_input *input, uint8_t out[32])
{
    static const char domain[] = VCS_C23_SHADOW_ELECTION_SEED_DOMAIN;
    struct sha3_256_ctx sha;
    shadow_hash_begin(&sha, domain, sizeof(domain));
    shadow_hash_u64(&sha, input->snapshot->election_epoch);
    shadow_hash_u64(&sha, input->seed_start_height);
    for (size_t i = 0; i < VCS_C23_SHADOW_ELECTION_BLOCKS; i++)
        sha3_256_write(&sha, input->seed_block_hashes[i], 32);
    sha3_256_finalize(&sha, out);
}

static bool shadow_draw(const uint8_t seed_root[32], size_t seat,
                        uint64_t total_weight, uint64_t *draw_out)
{
    static const char domain[] = VCS_C23_SHADOW_ELECTION_DOMAIN;
    uint64_t threshold = (uint64_t)(0u - total_weight) % total_weight;
    for (uint64_t attempt = 0; attempt < 1024u; attempt++) {
        struct sha3_256_ctx sha;
        uint8_t digest[32];
        shadow_hash_begin(&sha, domain, sizeof(domain));
        sha3_256_write(&sha, seed_root, 32);
        shadow_hash_u64(&sha, seat);
        shadow_hash_u64(&sha, attempt);
        sha3_256_finalize(&sha, digest);
        uint64_t random = zcl_read_u64_le(digest);
        if (random >= threshold) {
            *draw_out = random % total_weight;
            return true;
        }
    }
    return false;
}

static bool shadow_concentration(
    const struct vcs_c23_evidence_snapshot_v1 *snapshot,
    uint64_t *maximum, uint64_t *maximum_ppm, uint64_t *concentration_ppm)
{
    uint64_t max = 0, sum_squares = 0;
    for (size_t i = 0; i < snapshot->candidate_count; i++) {
        uint64_t square = 0;
        uint64_t weight = snapshot->rows[i].weight;
        if (weight > max) max = weight;
        if (!zcl_u64_mul(weight, weight, &square) ||
            !zcl_u64_add(sum_squares, square, &sum_squares))
            return false;
    }
    uint64_t numerator = 0, denominator = 0;
    if (!zcl_u64_mul(max, VCS_C23_SHADOW_CONCENTRATION_SCALE,
                     &numerator))
        return false;
    *maximum_ppm = numerator / snapshot->total_weight;
    if (!zcl_u64_mul(sum_squares, VCS_C23_SHADOW_CONCENTRATION_SCALE,
                     &numerator) ||
        !zcl_u64_mul(snapshot->total_weight, snapshot->total_weight,
                     &denominator) || denominator == 0)
        return false;
    *maximum = max;
    *concentration_ppm = numerator / denominator;
    return true;
}

static void shadow_election_root(
    const struct vcs_c23_shadow_election_v1 *election, uint8_t out[32])
{
    static const char domain[] = VCS_C23_SHADOW_ELECTION_DOMAIN;
    struct sha3_256_ctx sha;
    shadow_hash_begin(&sha, domain, sizeof(domain));
    shadow_hash_u64(&sha, election->schema_version);
    shadow_hash_u64(&sha, election->election_epoch);
    shadow_hash_u64(&sha, election->seed_start_height);
    sha3_256_write(&sha, election->snapshot_root, 32);
    sha3_256_write(&sha, election->election_seed_root, 32);
    shadow_hash_u64(&sha, election->total_candidate_weight);
    shadow_hash_u64(&sha, election->maximum_candidate_weight);
    shadow_hash_u64(&sha, election->maximum_weight_ppm);
    shadow_hash_u64(&sha, election->concentration_ppm);
    shadow_hash_u64(&sha, election->seat_count);
    for (size_t i = 0; i < election->seat_count; i++) {
        sha3_256_write(&sha, election->seats[i].seed_root, 32);
        sha3_256_write(&sha, election->seats[i].zid_pubkey, 32);
        shadow_hash_u64(&sha, election->seats[i].weight);
    }
    uint8_t flags[2] = {
        election->simulation_only ? 1u : 0u,
        election->authority_conferred ? 1u : 0u,
    };
    sha3_256_write(&sha, flags, sizeof(flags));
    sha3_256_finalize(&sha, out);
}

enum vcs_c23_shadow_election_error vcs_c23_shadow_election_build(
    const struct vcs_c23_shadow_election_input *input,
    struct vcs_c23_shadow_election_seat *seats, size_t seat_capacity,
    struct vcs_c23_shadow_election_v1 *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (seats && seat_capacity)
        memset(seats, 0, seat_capacity * sizeof(*seats));
    if (!input || !seats || !out || !input->snapshot ||
        !input->seed_block_hashes)
        return VCS_C23_SHADOW_ELECTION_NULL;
    if (!shadow_snapshot_valid(input->snapshot))
        return VCS_C23_SHADOW_ELECTION_EVIDENCE;
    if (input->seat_count == 0 ||
        input->seat_count > VCS_C23_SHADOW_MAX_SEATS ||
        input->seat_count > input->snapshot->candidate_count ||
        input->seat_count > seat_capacity)
        return VCS_C23_SHADOW_ELECTION_SEATS;
    for (size_t i = 0; i < VCS_C23_SHADOW_ELECTION_BLOCKS; i++)
        if (!zcl_bytes_any_set(input->seed_block_hashes[i], 32))
            return VCS_C23_SHADOW_ELECTION_ROOT;

    struct shadow_candidate *candidates = zcl_calloc(
        input->snapshot->candidate_count, sizeof(*candidates),
        "c23_shadow_election_candidates");
    if (!candidates) return VCS_C23_SHADOW_ELECTION_ALLOCATION;
    for (size_t i = 0; i < input->snapshot->candidate_count; i++) {
        memcpy(candidates[i].seed_root,
               input->snapshot->rows[i].seed_root, 32);
        memcpy(candidates[i].zid_pubkey,
               input->snapshot->rows[i].zid_pubkey, 32);
        candidates[i].weight = input->snapshot->rows[i].weight;
    }

    out->schema_version = VCS_C23_SHADOW_ELECTION_VERSION;
    out->election_epoch = input->snapshot->election_epoch;
    out->seed_start_height = input->seed_start_height;
    memcpy(out->snapshot_root, input->snapshot->snapshot_root, 32);
    shadow_election_seed_root(input, out->election_seed_root);
    out->total_candidate_weight = input->snapshot->total_weight;
    out->seat_count = input->seat_count;
    out->seats = seats;
    out->simulation_only = true;
    out->authority_conferred = false;
    enum vcs_c23_shadow_election_error error =
        VCS_C23_SHADOW_ELECTION_OK;
    if (!shadow_concentration(
            input->snapshot, &out->maximum_candidate_weight,
            &out->maximum_weight_ppm, &out->concentration_ppm)) {
        error = VCS_C23_SHADOW_ELECTION_OVERFLOW;
        goto done;
    }

    uint64_t remaining_weight = input->snapshot->total_weight;
    for (size_t seat = 0; seat < input->seat_count; seat++) {
        uint64_t draw = 0;
        if (!shadow_draw(out->election_seed_root, seat,
                         remaining_weight, &draw)) {
            error = VCS_C23_SHADOW_ELECTION_OVERFLOW;
            goto done;
        }
        uint64_t cumulative = 0;
        size_t selected = input->snapshot->candidate_count;
        for (size_t i = 0; i < input->snapshot->candidate_count; i++) {
            if (candidates[i].selected) continue;
            if (!zcl_u64_add(cumulative, candidates[i].weight,
                             &cumulative)) {
                error = VCS_C23_SHADOW_ELECTION_OVERFLOW;
                goto done;
            }
            if (draw < cumulative) {
                selected = i;
                break;
            }
        }
        if (selected == input->snapshot->candidate_count) {
            error = VCS_C23_SHADOW_ELECTION_SEATS;
            goto done;
        }
        candidates[selected].selected = true;
        memcpy(seats[seat].seed_root, candidates[selected].seed_root, 32);
        memcpy(seats[seat].zid_pubkey,
               candidates[selected].zid_pubkey, 32);
        seats[seat].weight = candidates[selected].weight;
        remaining_weight -= candidates[selected].weight;
    }
    shadow_election_root(out, out->election_root);

done:
    free(candidates);
    if (error != VCS_C23_SHADOW_ELECTION_OK) {
        memset(out, 0, sizeof(*out));
        memset(seats, 0, seat_capacity * sizeof(*seats));
    }
    return error;
}
