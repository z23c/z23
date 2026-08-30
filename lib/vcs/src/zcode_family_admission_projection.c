/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: CAS-derived immutable Family admission projection snapshots. */

#include "vcs/zcode_family_admission.h"

#include "base/bytes.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

struct vcs_zcode_family_admission_projection {
    struct vcs_zcode_family_projection_config_v1 config;
    struct vcs_zcode_family_admission_projection_entry_v1 *entries;
    size_t count;
    uint8_t root[32];
};

static bool projection_pass_state(uint16_t state)
{
    return state >= VCS_ZCODE_ADMISSION_SELF_SCREENED &&
           state <= VCS_ZCODE_ADMISSION_RESILIENT_PASS;
}

static int source_compare(const void *left_ptr, const void *right_ptr)
{
    const struct vcs_zcode_family_admission_source_v1 *left = left_ptr;
    const struct vcs_zcode_family_admission_source_v1 *right = right_ptr;
    int cmp = memcmp(left->admission.content_root,
                     right->admission.content_root, 32);
    if (cmp != 0) return cmp;
    cmp = memcmp(left->admission.dependency_closure_root,
                 right->admission.dependency_closure_root, 32);
    if (cmp != 0) return cmp;
    if (left->admission.sequence != right->admission.sequence)
        return left->admission.sequence < right->admission.sequence ? -1 : 1;
    return memcmp(left->object_root, right->object_root, 32);
}

static bool same_key(
    const struct vcs_zcode_family_admission_source_v1 *left,
    const struct vcs_zcode_family_admission_source_v1 *right)
{
    return memcmp(left->admission.content_root,
                  right->admission.content_root, 32) == 0 &&
           memcmp(left->admission.dependency_closure_root,
                  right->admission.dependency_closure_root, 32) == 0;
}

static const struct vcs_zcode_family_admission_source_v1 *find_root(
    const struct vcs_zcode_family_admission_source_v1 *sources,
    size_t begin, size_t end, const uint8_t root[32], uint64_t sequence)
{
    for (size_t i = begin; i < end; i++)
        if (sources[i].admission.sequence == sequence &&
            memcmp(sources[i].object_root, root, 32) == 0)
            return &sources[i];
    return NULL;
}

static bool selected_chain_complete(
    const struct vcs_zcode_family_admission_source_v1 *sources,
    size_t begin, size_t end,
    const struct vcs_zcode_family_admission_source_v1 *selected)
{
    const struct vcs_zcode_family_admission_source_v1 *cursor = selected;
    while (cursor->admission.sequence > 1) {
        cursor = find_root(sources, begin, end,
                           cursor->admission.predecessor_admission_root,
                           cursor->admission.sequence - 1u);
        if (!cursor) return false;
    }
    return true;
}

static bool admission_within_cutoff(
    const struct vcs_zcode_commons_admission_v1 *admission,
    const struct vcs_zcode_family_projection_config_v1 *config)
{
    return admission->decided_height <= config->cutoff_height &&
           admission->decided_mtp <= config->cutoff_mtp &&
           admission->expires_height >= config->cutoff_height &&
           admission->expires_mtp >= config->cutoff_mtp;
}

static void projection_derive_entry(
    const struct vcs_zcode_family_admission_source_v1 *sources,
    size_t begin, size_t end,
    const struct vcs_zcode_family_projection_config_v1 *config,
    struct vcs_zcode_family_admission_projection_entry_v1 *entry)
{
    const struct vcs_zcode_family_admission_source_v1 *last =
        &sources[end - 1u];
    uint64_t highest = last->admission.sequence;
    size_t highest_count = 0;
    size_t selected_index = end - 1u;
    while (selected_index > begin &&
           sources[selected_index - 1u].admission.sequence == highest)
        selected_index--;
    highest_count = end - selected_index;
    const struct vcs_zcode_family_admission_source_v1 *selected =
        &sources[selected_index];
    memset(entry, 0, sizeof(*entry));
    memcpy(entry->content_root, selected->admission.content_root, 32);
    memcpy(entry->dependency_closure_root,
           selected->admission.dependency_closure_root, 32);
    memcpy(entry->admission_root, selected->object_root, 32);
    entry->sequence = highest;
    entry->tier = (enum vcs_zcode_moderation_tier_v1)selected->admission.tier;
    entry->coverage_complete = selected->admission.coverage_complete != 0;
    entry->closure_complete = selected->admission.closure_complete != 0;
    entry->chain_complete = highest_count == 1 &&
        selected_chain_complete(sources, begin, end, selected);
    entry->state = highest_count == 1
        ? (enum vcs_zcode_commons_admission_state_v1)selected->admission.state
        : VCS_ZCODE_ADMISSION_CONFLICTED;
    entry->current = config->chain_current && entry->chain_complete &&
        admission_within_cutoff(&selected->admission, config) &&
        (!projection_pass_state(selected->admission.state) ||
         entry->tier == config->required_tier);
    entry->family_public =
        vcs_zcode_commons_admission_is_default_visible_v1(
            entry->state, entry->current,
            entry->coverage_complete && entry->closure_complete);
}

static void projection_hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t le[2];
    zcl_write_u16_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void projection_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t le[8];
    zcl_write_u64_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void projection_derive_root(
    struct vcs_zcode_family_admission_projection *projection)
{
    static const char domain[] = VCS_ZCODE_FAMILY_PROJECTION_V1_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    projection_hash_u16(&sha, 1);
    projection_hash_u16(&sha, VCS_ZCODE_COMMONS_REQUIRED_FLAGS);
    sha3_256_write(&sha, projection->config.family_policy_root, 32);
    sha3_256_write(&sha, projection->config.moderation_set_root, 32);
    sha3_256_write(&sha, projection->config.chain_tip_root, 32);
    projection_hash_u64(&sha, projection->config.cutoff_height);
    projection_hash_u64(&sha, (uint64_t)projection->config.cutoff_mtp);
    projection_hash_u16(&sha, (uint16_t)projection->config.required_tier);
    uint8_t current = projection->config.chain_current ? 1u : 0u;
    sha3_256_write(&sha, &current, 1);
    projection_hash_u64(&sha, projection->count);
    for (size_t i = 0; i < projection->count; i++) {
        const struct vcs_zcode_family_admission_projection_entry_v1 *entry =
            &projection->entries[i];
        sha3_256_write(&sha, entry->content_root, 32);
        sha3_256_write(&sha, entry->dependency_closure_root, 32);
        sha3_256_write(&sha, entry->admission_root, 32);
        projection_hash_u64(&sha, entry->sequence);
        projection_hash_u16(&sha, (uint16_t)entry->state);
        projection_hash_u16(&sha, (uint16_t)entry->tier);
        uint8_t bits = (uint8_t)(entry->coverage_complete |
            (entry->closure_complete << 1) |
            (entry->chain_complete << 2) | (entry->current << 3) |
            (entry->family_public << 4));
        sha3_256_write(&sha, &bits, 1);
    }
    sha3_256_finalize(&sha, projection->root);
}

static enum vcs_zcode_family_admission_error projection_config_validate(
    const struct vcs_zcode_family_projection_config_v1 *config)
{
    if (!config) return VCS_ZCODE_FAMILY_ADMISSION_NULL;
    if (!zcl_bytes_any_set(config->family_policy_root, 32) ||
        !zcl_bytes_any_set(config->moderation_set_root, 32) ||
        !zcl_bytes_any_set(config->chain_tip_root, 32))
        return VCS_ZCODE_FAMILY_ADMISSION_ROOT;
    if (!config->cutoff_height || config->cutoff_mtp <= 0)
        return VCS_ZCODE_FAMILY_ADMISSION_TIME;
    if (config->required_tier > VCS_ZCODE_MODERATION_TIER_RESILIENT_PASS)
        return VCS_ZCODE_FAMILY_ADMISSION_ENUM;
    return VCS_ZCODE_FAMILY_ADMISSION_OK;
}

static enum vcs_zcode_family_admission_error projection_sources_validate(
    const struct vcs_zcode_family_projection_config_v1 *config,
    struct vcs_zcode_family_admission_source_v1 *sources, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        enum vcs_zcode_family_admission_error error =
            vcs_zcode_commons_admission_v1_validate(&sources[i].admission);
        if (error != VCS_ZCODE_FAMILY_ADMISSION_OK) return error;
        uint8_t derived[32];
        error = vcs_zcode_commons_admission_v1_root(
            &sources[i].admission, derived);
        if (error != VCS_ZCODE_FAMILY_ADMISSION_OK) return error;
        if (memcmp(derived, sources[i].object_root, 32) != 0 ||
            memcmp(sources[i].admission.family_policy_root,
                   config->family_policy_root, 32) != 0 ||
            memcmp(sources[i].admission.moderation_set_root,
                   config->moderation_set_root, 32) != 0)
            return VCS_ZCODE_FAMILY_ADMISSION_ROOT;
    }
    qsort(sources, count, sizeof(*sources), source_compare);
    for (size_t i = 1; i < count; i++)
        if (memcmp(sources[i - 1u].object_root,
                   sources[i].object_root, 32) == 0)
            return VCS_ZCODE_FAMILY_ADMISSION_ORDER;
    return VCS_ZCODE_FAMILY_ADMISSION_OK;
}

enum vcs_zcode_family_admission_error
vcs_zcode_family_admission_projection_build_v1(
    const struct vcs_zcode_family_projection_config_v1 *config,
    const struct vcs_zcode_family_admission_source_v1 *sources,
    size_t source_count,
    struct vcs_zcode_family_admission_projection **out)
{
    if (out) *out = NULL;
    if (!out || (!sources && source_count))
        return VCS_ZCODE_FAMILY_ADMISSION_NULL;
    enum vcs_zcode_family_admission_error error =
        projection_config_validate(config);
    if (error != VCS_ZCODE_FAMILY_ADMISSION_OK) return error;
    if (source_count > VCS_ZCODE_FAMILY_ADMISSION_MAX_SOURCES)
        return VCS_ZCODE_FAMILY_ADMISSION_LIMIT;
    struct vcs_zcode_family_admission_source_v1 *sorted = NULL;
    if (source_count) {
        sorted = zcl_calloc(source_count, sizeof(*sorted),
                            "family admission sources");
        if (!sorted) return VCS_ZCODE_FAMILY_ADMISSION_NOMEM;
        memcpy(sorted, sources, source_count * sizeof(*sorted));
        error = projection_sources_validate(config, sorted, source_count);
        if (error != VCS_ZCODE_FAMILY_ADMISSION_OK) {
            free(sorted);
            return error;
        }
    }
    struct vcs_zcode_family_admission_projection *projection =
        zcl_calloc(1, sizeof(*projection), "family admission projection");
    if (!projection) {
        free(sorted);
        return VCS_ZCODE_FAMILY_ADMISSION_NOMEM;
    }
    projection->config = *config;
    if (source_count) {
        projection->entries = zcl_calloc(
            source_count, sizeof(*projection->entries),
            "family admission projection entries");
        if (!projection->entries) {
            free(sorted);
            free(projection);
            return VCS_ZCODE_FAMILY_ADMISSION_NOMEM;
        }
    }
    for (size_t begin = 0; begin < source_count;) {
        size_t end = begin + 1u;
        while (end < source_count && same_key(&sorted[begin], &sorted[end]))
            end++;
        projection_derive_entry(sorted, begin, end, config,
                                &projection->entries[projection->count++]);
        begin = end;
    }
    free(sorted);
    projection_derive_root(projection);
    *out = projection;
    return VCS_ZCODE_FAMILY_ADMISSION_OK;
}

void vcs_zcode_family_admission_projection_free_v1(
    struct vcs_zcode_family_admission_projection *projection)
{
    if (!projection) return;
    free(projection->entries);
    free(projection);
}

size_t vcs_zcode_family_admission_projection_count_v1(
    const struct vcs_zcode_family_admission_projection *projection)
{
    return projection ? projection->count : 0;
}

const struct vcs_zcode_family_admission_projection_entry_v1 *
vcs_zcode_family_admission_projection_at_v1(
    const struct vcs_zcode_family_admission_projection *projection,
    size_t index)
{
    return projection && index < projection->count
        ? &projection->entries[index] : NULL;
}

static int entry_key_compare(
    const struct vcs_zcode_family_admission_projection_entry_v1 *entry,
    const uint8_t content_root[32], const uint8_t closure_root[32])
{
    int cmp = memcmp(entry->content_root, content_root, 32);
    return cmp != 0 ? cmp
                    : memcmp(entry->dependency_closure_root, closure_root, 32);
}

const struct vcs_zcode_family_admission_projection_entry_v1 *
vcs_zcode_family_admission_projection_find_v1(
    const struct vcs_zcode_family_admission_projection *projection,
    const uint8_t content_root[32], const uint8_t closure_root[32])
{
    if (!projection || !content_root || !closure_root) return NULL;
    size_t low = 0, high = projection->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2u;
        int cmp = entry_key_compare(&projection->entries[mid], content_root,
                                    closure_root);
        if (cmp < 0) low = mid + 1u;
        else if (cmp > 0) high = mid;
        else return &projection->entries[mid];
    }
    return NULL;
}

void vcs_zcode_family_admission_projection_root_v1(
    const struct vcs_zcode_family_admission_projection *projection,
    uint8_t out[32])
{
    if (!out) return;
    memset(out, 0, 32);
    if (projection) memcpy(out, projection->root, 32);
}
