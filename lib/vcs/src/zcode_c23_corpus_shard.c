/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical bounded shards for the verified C23 corpus projection. */

#include "vcs/zcode_c23_corpus.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t shard_magic[8] = {'Z','C','C','S','1',0,0,0};

size_t vcs_zcode_c23_corpus_shard_v1_wire_size(size_t entry_count)
{
    if (entry_count > VCS_ZCODE_C23_SHARD_ENTRY_MAX) return 0;
    return VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES +
           entry_count * VCS_ZCODE_C23_SHARD_ENTRY_WIRE_BYTES;
}

static enum vcs_zcode_c23_error entry_validate(
    const struct vcs_zcode_c23_corpus_entry_v1 *entry)
{
    if (!zcl_bytes_any_set(entry->semantic_lineage_root, 32) ||
        !zcl_bytes_any_set(entry->release_root, 32) || !entry->release_sequence)
        return VCS_ZCODE_C23_ROOT;
    if (entry->flags & ~(VCS_ZCODE_C23_ENTRY_COUNTED |
                         VCS_ZCODE_C23_ENTRY_DURABLE))
        return VCS_ZCODE_C23_FLAGS;
    if (entry->exclusion_mask & ~VCS_ZCODE_C23_EXCLUSION_MASK)
        return VCS_ZCODE_C23_ENUM;
    uint64_t total_loc = 0;
    if (!zcl_u64_add(entry->production_loc, entry->test_loc, &total_loc))
        return VCS_ZCODE_C23_OVERFLOW;
    bool counted = (entry->flags & VCS_ZCODE_C23_ENTRY_COUNTED) != 0;
    bool durable = (entry->flags & VCS_ZCODE_C23_ENTRY_DURABLE) != 0;
    if (counted) {
        const uint8_t *roots[] = {
            entry->passport_root, entry->proof_root,
            entry->source_assignment_root, entry->admission_root,
        };
        for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
            if (!zcl_bytes_any_set(roots[i], 32)) return VCS_ZCODE_C23_ROOT;
        if (!total_loc || entry->exclusion_mask != 0 ||
            entry->evidence_mask != VCS_ZCODE_C23_EVIDENCE_REQUIRED_MASK)
            return VCS_ZCODE_C23_POLICY;
    } else if (total_loc != 0 || entry->exclusion_mask == 0 || durable) {
        return VCS_ZCODE_C23_POLICY;
    }
    if (durable && !zcl_bytes_any_set(entry->possession_root, 32))
        return VCS_ZCODE_C23_ROOT;
    if (!durable && zcl_bytes_any_set(entry->possession_root, 32))
        return VCS_ZCODE_C23_POLICY;
    return VCS_ZCODE_C23_OK;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_validate(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard)
{
    if (!shard) return VCS_ZCODE_C23_NULL;
    if (shard->schema_version != 1) return VCS_ZCODE_C23_VERSION;
    if (shard->flags != VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS)
        return VCS_ZCODE_C23_FLAGS;
    if (!zcl_bytes_any_set(shard->rules_root, 32) ||
        !zcl_bytes_any_set(shard->family_policy_root, 32) ||
        !zcl_bytes_any_set(shard->moderation_set_root, 32))
        return VCS_ZCODE_C23_ROOT;
    if (!shard->entries || shard->entry_count == 0 ||
        shard->entry_count > VCS_ZCODE_C23_SHARD_ENTRY_MAX)
        return VCS_ZCODE_C23_SIZE;
    for (size_t i = 0; i < shard->entry_count; i++) {
        enum vcs_zcode_c23_error error = entry_validate(&shard->entries[i]);
        if (error != VCS_ZCODE_C23_OK) return error;
        if (i > 0 && memcmp(shard->entries[i - 1u].semantic_lineage_root,
                            shard->entries[i].semantic_lineage_root, 32) >= 0)
            return VCS_ZCODE_C23_ORDER;
    }
    return VCS_ZCODE_C23_OK;
}

static size_t entry_write(const struct vcs_zcode_c23_corpus_entry_v1 *entry,
                          uint8_t *wire)
{
    size_t off = 0;
    memcpy(wire + off, entry->semantic_lineage_root, 32); off += 32;
    memcpy(wire + off, entry->release_root, 32); off += 32;
    memcpy(wire + off, entry->passport_root, 32); off += 32;
    memcpy(wire + off, entry->proof_root, 32); off += 32;
    memcpy(wire + off, entry->source_assignment_root, 32); off += 32;
    memcpy(wire + off, entry->admission_root, 32); off += 32;
    memcpy(wire + off, entry->possession_root, 32); off += 32;
    zcl_write_u64_le(wire + off, entry->release_sequence); off += 8;
    zcl_write_u64_le(wire + off, entry->production_loc); off += 8;
    zcl_write_u64_le(wire + off, entry->test_loc); off += 8;
    zcl_write_u64_le(wire + off, entry->physical_lines); off += 8;
    zcl_write_u64_le(wire + off, entry->unique_semantic_units); off += 8;
    zcl_write_u64_le(wire + off, entry->evidence_mask); off += 8;
    zcl_write_u32_le(wire + off, entry->exclusion_mask); off += 4;
    zcl_write_u32_le(wire + off, entry->flags); off += 4;
    return off;
}

static size_t shard_write(const struct vcs_zcode_c23_corpus_shard_v1 *shard,
                          uint8_t *wire)
{
    size_t off = 0;
    memcpy(wire + off, shard_magic, sizeof(shard_magic)); off += 8;
    zcl_write_u16_le(wire + off, shard->schema_version); off += 2;
    zcl_write_u16_le(wire + off, shard->flags); off += 2;
    memcpy(wire + off, shard->rules_root, 32); off += 32;
    memcpy(wire + off, shard->family_policy_root, 32); off += 32;
    memcpy(wire + off, shard->moderation_set_root, 32); off += 32;
    zcl_write_u16_le(wire + off, (uint16_t)shard->entry_count); off += 2;
    zcl_write_u16_le(wire + off, 0); off += 2;
    for (size_t i = 0; i < shard->entry_count; i++)
        off += entry_write(&shard->entries[i], wire + off);
    return off;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_encode(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len) return VCS_ZCODE_C23_NULL;
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_shard_v1_validate(shard);
    if (error != VCS_ZCODE_C23_OK) return error;
    size_t needed = vcs_zcode_c23_corpus_shard_v1_wire_size(
        shard->entry_count);
    if (!needed || wire_capacity < needed) return VCS_ZCODE_C23_SIZE;
    *wire_len = shard_write(shard, wire);
    return *wire_len == needed ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_SIZE;
}

static size_t entry_read(struct vcs_zcode_c23_corpus_entry_v1 *entry,
                         const uint8_t *wire)
{
    size_t off = 0;
    memcpy(entry->semantic_lineage_root, wire + off, 32); off += 32;
    memcpy(entry->release_root, wire + off, 32); off += 32;
    memcpy(entry->passport_root, wire + off, 32); off += 32;
    memcpy(entry->proof_root, wire + off, 32); off += 32;
    memcpy(entry->source_assignment_root, wire + off, 32); off += 32;
    memcpy(entry->admission_root, wire + off, 32); off += 32;
    memcpy(entry->possession_root, wire + off, 32); off += 32;
    entry->release_sequence = zcl_read_u64_le(wire + off); off += 8;
    entry->production_loc = zcl_read_u64_le(wire + off); off += 8;
    entry->test_loc = zcl_read_u64_le(wire + off); off += 8;
    entry->physical_lines = zcl_read_u64_le(wire + off); off += 8;
    entry->unique_semantic_units = zcl_read_u64_le(wire + off); off += 8;
    entry->evidence_mask = zcl_read_u64_le(wire + off); off += 8;
    entry->exclusion_mask = zcl_read_u32_le(wire + off); off += 4;
    entry->flags = zcl_read_u32_le(wire + off); off += 4;
    return off;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_decode(
    struct vcs_zcode_c23_corpus_shard_v1 *out,
    struct vcs_zcode_c23_corpus_entry_v1 *entries, size_t entry_capacity,
    const uint8_t *wire, size_t wire_len)
{
    if (!out || !entries || !wire) return VCS_ZCODE_C23_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES ||
        memcmp(wire, shard_magic, sizeof(shard_magic)) != 0)
        return wire_len < VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES
            ? VCS_ZCODE_C23_SIZE : VCS_ZCODE_C23_MAGIC;
    size_t off = sizeof(shard_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    memcpy(out->rules_root, wire + off, 32); off += 32;
    memcpy(out->family_policy_root, wire + off, 32); off += 32;
    memcpy(out->moderation_set_root, wire + off, 32); off += 32;
    size_t count = zcl_read_u16_le(wire + off); off += 2;
    uint16_t reserved = zcl_read_u16_le(wire + off); off += 2;
    size_t needed = vcs_zcode_c23_corpus_shard_v1_wire_size(count);
    if (reserved != 0 || !count || count > entry_capacity ||
        !needed || needed != wire_len) {
        memset(out, 0, sizeof(*out));
        return reserved ? VCS_ZCODE_C23_ENUM : VCS_ZCODE_C23_SIZE;
    }
    memset(entries, 0, count * sizeof(*entries));
    for (size_t i = 0; i < count; i++)
        off += entry_read(&entries[i], wire + off);
    out->entries = entries;
    out->entry_count = count;
    enum vcs_zcode_c23_error error = off == wire_len
        ? vcs_zcode_c23_corpus_shard_v1_validate(out)
        : VCS_ZCODE_C23_SIZE;
    if (error != VCS_ZCODE_C23_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_root(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!shard || !out) return VCS_ZCODE_C23_NULL;
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_shard_v1_validate(shard);
    if (error != VCS_ZCODE_C23_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_C23_CORPUS_SHARD_V1_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    uint8_t header[VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES];
    size_t off = 0;
    memcpy(header + off, shard_magic, 8); off += 8;
    zcl_write_u16_le(header + off, shard->schema_version); off += 2;
    zcl_write_u16_le(header + off, shard->flags); off += 2;
    memcpy(header + off, shard->rules_root, 32); off += 32;
    memcpy(header + off, shard->family_policy_root, 32); off += 32;
    memcpy(header + off, shard->moderation_set_root, 32); off += 32;
    zcl_write_u16_le(header + off, (uint16_t)shard->entry_count); off += 2;
    zcl_write_u16_le(header + off, 0); off += 2;
    sha3_256_write(&sha, header, off);
    uint8_t entry_wire[VCS_ZCODE_C23_SHARD_ENTRY_WIRE_BYTES];
    for (size_t i = 0; i < shard->entry_count; i++) {
        size_t n = entry_write(&shard->entries[i], entry_wire);
        sha3_256_write(&sha, entry_wire, n);
    }
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_C23_OK;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_page(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard,
    const struct vcs_zcode_c23_page_cursor_v1 *cursor, size_t page_size,
    size_t *first_index, size_t *item_count,
    struct vcs_zcode_c23_page_cursor_v1 *next_cursor, bool *has_more)
{
    if (!first_index || !item_count || !next_cursor || !has_more)
        return VCS_ZCODE_C23_NULL;
    struct vcs_zcode_c23_page_cursor_v1 cursor_copy;
    const struct vcs_zcode_c23_page_cursor_v1 *effective_cursor = cursor;
    if (cursor) {
        cursor_copy = *cursor;
        effective_cursor = &cursor_copy;
    }
    *first_index = 0; *item_count = 0; *has_more = false;
    memset(next_cursor, 0, sizeof(*next_cursor));
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_shard_v1_validate(shard);
    if (error != VCS_ZCODE_C23_OK) return error;
    if (!page_size || page_size > VCS_ZCODE_C23_PAGE_MAX)
        return VCS_ZCODE_C23_SIZE;
    uint8_t shard_root[32];
    error = vcs_zcode_c23_corpus_shard_v1_root(shard, shard_root);
    if (error != VCS_ZCODE_C23_OK) return error;
    size_t start = 0;
    if (effective_cursor) {
        if (memcmp(effective_cursor->shard_root, shard_root, 32) != 0 ||
            effective_cursor->next_index >= shard->entry_count)
            return VCS_ZCODE_C23_CURSOR;
        start = effective_cursor->next_index;
    }
    size_t remaining = shard->entry_count - start;
    size_t count = remaining < page_size ? remaining : page_size;
    *first_index = start;
    *item_count = count;
    *has_more = count < remaining;
    if (*has_more) {
        memcpy(next_cursor->shard_root, shard_root, 32);
        next_cursor->next_index = (uint16_t)(start + count);
    }
    return VCS_ZCODE_C23_OK;
}
