/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Domain-separated MMR append and signed checkpoint verification. */
#include "vcs/zcode_observation_mmr.h"

#include "base/bytes.h"
#include "vcs/signed_evidence.h"

#include <string.h>

#define ZOM_BODY_BYTES 1104u

static void zom_u32(uint8_t out[4], uint32_t value)
{
    for (unsigned i = 0; i < 4; i++) out[i] = (uint8_t)(value >> (8u * i));
}

static void zom_u64(uint8_t out[8], uint64_t value)
{
    for (unsigned i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (8u * i));
}

static uint32_t zom_read_u32(const uint8_t in[4])
{
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; i++) value |= (uint32_t)in[i] << (8u * i);
    return value;
}

static uint64_t zom_read_u64(const uint8_t in[8])
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value |= (uint64_t)in[i] << (8u * i);
    return value;
}

static bool zom_shape(const struct vcs_zcode_observation_mmr_checkpoint *c)
{
    if (!c || c->schema_version != 1 || c->leaf_count == 0 ||
        c->observed_unix <= 0 || !zcl_bytes_any_set(c->issuer, 32)) return false;
    for (unsigned level = 0; level < VCS_ZCODE_OBSERVATION_MMR_LEVELS; level++) {
        bool occupied = ((c->leaf_count >> level) & 1u) != 0;
        if (zcl_bytes_any_set(c->peaks[level], 32) != occupied) return false;
    }
    return true;
}

static bool zom_leaf(uint32_t index, const uint8_t root[32], uint8_t out[32])
{
    static const char domain[] = "zcl.zcode.observation_mmr.leaf.v1";
    uint8_t body[36];
    if (!root || !zcl_bytes_any_set(root, 32) || !out) return false;
    zom_u32(body, index);
    memcpy(body + 4, root, 32);
    return vcs_signed_evidence_root(domain, sizeof(domain), body, sizeof(body), out);
}

static bool zom_parent(unsigned level, const uint8_t left[32],
                       const uint8_t right[32], uint8_t out[32])
{
    static const char domain[] = "zcl.zcode.observation_mmr.parent.v1";
    uint8_t body[68];
    zom_u32(body, level);
    memcpy(body + 4, left, 32);
    memcpy(body + 36, right, 32);
    return vcs_signed_evidence_root(domain, sizeof(domain), body, sizeof(body), out);
}

static bool zom_append(struct vcs_zcode_observation_mmr_checkpoint *c,
                       const uint8_t root[32])
{
    uint8_t node[32], parent[32];
    uint32_t old_count = c->leaf_count;
    if (old_count == UINT32_MAX || !zom_leaf(old_count, root, node)) return false;
    for (unsigned level = 0; level < VCS_ZCODE_OBSERVATION_MMR_LEVELS; level++) {
        if (((old_count >> level) & 1u) == 0) {
            memcpy(c->peaks[level], node, 32);
            c->leaf_count++;
            return true;
        }
        if (!zom_parent(level, c->peaks[level], node, parent)) return false;
        memset(c->peaks[level], 0, 32);
        memcpy(node, parent, 32);
    }
    return false;
}

bool vcs_zcode_observation_mmr_root(
    const struct vcs_zcode_observation_mmr_checkpoint *c, uint8_t out[32])
{
    static const char domain[] = "zcl.zcode.observation_mmr.checkpoint.v1";
    uint8_t body[ZOM_BODY_BYTES];
    if (!out || !zom_shape(c)) return false;
    zom_u32(body, c->schema_version);
    memcpy(body + 4, c->issuer, 32);
    zom_u32(body + 36, c->leaf_count);
    zom_u64(body + 40, (uint64_t)c->observed_unix);
    memcpy(body + 48, c->previous_checkpoint_root, 32);
    memcpy(body + 80, c->peaks, sizeof(c->peaks));
    return vcs_signed_evidence_root(domain, sizeof(domain), body, sizeof(body), out);
}

bool vcs_zcode_observation_mmr_verify(
    const struct vcs_zcode_observation_mmr_checkpoint *c,
    const uint8_t expected_issuer[32])
{
    uint8_t root[32];
    return c && expected_issuer &&
        vcs_zcode_observation_mmr_root(c, root) &&
        vcs_signed_evidence_verify_root(root, c->signature, c->issuer,
                                        expected_issuer);
}

bool vcs_zcode_observation_mmr_serialize(
    const struct vcs_zcode_observation_mmr_checkpoint *c,
    uint8_t wire[VCS_ZCODE_OBSERVATION_MMR_WIRE_BYTES])
{
    if (!wire || !c || !vcs_zcode_observation_mmr_verify(c, c->issuer))
        return false;
    zom_u32(wire, c->schema_version);
    memcpy(wire + 4, c->issuer, 32);
    zom_u32(wire + 36, c->leaf_count);
    zom_u64(wire + 40, (uint64_t)c->observed_unix);
    memcpy(wire + 48, c->previous_checkpoint_root, 32);
    memcpy(wire + 80, c->peaks, sizeof(c->peaks));
    memcpy(wire + ZOM_BODY_BYTES, c->signature, 64);
    return true;
}

bool vcs_zcode_observation_mmr_parse(
    const uint8_t *wire, size_t wire_len, const uint8_t expected_issuer[32],
    struct vcs_zcode_observation_mmr_checkpoint *out)
{
    struct vcs_zcode_observation_mmr_checkpoint c = {0};
    if (!wire || wire_len != VCS_ZCODE_OBSERVATION_MMR_WIRE_BYTES ||
        !expected_issuer || !out) return false;
    if (zom_read_u64(wire + 40) > INT64_MAX) return false;
    c.schema_version = zom_read_u32(wire);
    memcpy(c.issuer, wire + 4, 32);
    c.leaf_count = zom_read_u32(wire + 36);
    c.observed_unix = (int64_t)zom_read_u64(wire + 40);
    memcpy(c.previous_checkpoint_root, wire + 48, 32);
    memcpy(c.peaks, wire + 80, sizeof(c.peaks));
    memcpy(c.signature, wire + ZOM_BODY_BYTES, 64);
    if (!vcs_zcode_observation_mmr_verify(&c, expected_issuer)) return false;
    *out = c;
    return true;
}

bool vcs_zcode_observation_mmr_extend(
    const struct vcs_zcode_observation_mmr_checkpoint *previous,
    const uint8_t *roots, size_t root_count, int64_t observed_unix,
    const uint8_t secret[32], const uint8_t issuer[32],
    struct vcs_zcode_observation_mmr_checkpoint *out)
{
    struct vcs_zcode_observation_mmr_checkpoint next = { .schema_version = 1 };
    uint8_t prior_root[32], root[32];
    if (!roots || !secret || !issuer || !out || !zcl_bytes_any_set(issuer, 32) ||
        root_count == 0 || root_count > VCS_ZCODE_OBSERVATION_MMR_BATCH_MAX ||
        observed_unix <= 0) return false;
    if (previous) {
        if (!vcs_zcode_observation_mmr_verify(previous, issuer) ||
            previous->observed_unix > observed_unix ||
            root_count > UINT32_MAX - previous->leaf_count ||
            !vcs_zcode_observation_mmr_root(previous, prior_root)) return false;
        next = *previous;
        memcpy(next.previous_checkpoint_root, prior_root, 32);
    }
    memcpy(next.issuer, issuer, 32);
    next.observed_unix = observed_unix;
    for (size_t i = 0; i < root_count; i++)
        if (!zom_append(&next, roots + i * 32)) return false;
    if (!vcs_zcode_observation_mmr_root(&next, root) ||
        !vcs_signed_evidence_seal_root(root, secret, issuer, next.signature) ||
        !vcs_zcode_observation_mmr_verify(&next, issuer))
        return false;
    *out = next;
    return true;
}

bool vcs_zcode_observation_mmr_verify_extension(
    const struct vcs_zcode_observation_mmr_checkpoint *previous,
    const struct vcs_zcode_observation_mmr_checkpoint *next,
    const uint8_t *roots, size_t root_count, const uint8_t expected_issuer[32])
{
    struct vcs_zcode_observation_mmr_checkpoint computed = {
        .schema_version = 1
    };
    uint8_t prior_root[32];
    if (!next || !roots || !expected_issuer ||
        root_count == 0 || root_count > VCS_ZCODE_OBSERVATION_MMR_BATCH_MAX ||
        !vcs_zcode_observation_mmr_verify(next, expected_issuer)) return false;
    if (!previous) {
        if (next->leaf_count != root_count ||
            zcl_bytes_any_set(next->previous_checkpoint_root, 32)) return false;
        memcpy(computed.issuer, expected_issuer, 32);
    } else {
        if (!vcs_zcode_observation_mmr_verify(previous, expected_issuer) ||
            next->observed_unix < previous->observed_unix ||
            root_count > UINT32_MAX - previous->leaf_count ||
            next->leaf_count != previous->leaf_count + root_count ||
            !vcs_zcode_observation_mmr_root(previous, prior_root) ||
            memcmp(next->previous_checkpoint_root, prior_root, 32) != 0)
            return false;
        computed = *previous;
    }
    for (size_t i = 0; i < root_count; i++)
        if (!zom_append(&computed, roots + i * 32)) return false;
    return memcmp(computed.peaks, next->peaks, sizeof(next->peaks)) == 0;
}
