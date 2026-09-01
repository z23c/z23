/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Incremental ZVCS-blob to content.v2 chunk mapping evidence. */

#include "vcs/package_mapping.h"

#include "base/bytes.h"
#include "vcs/package_manifest.h"
#include "vcs/vcs.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_manifest.h"
#include "vcs/vcs_object.h"

#include "base/serialize_le.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PACKAGE_BLOB_MAP_HEADER_BYTES 56u
#define PACKAGE_MAPPING_SET_HEADER_BYTES 80u
#define PACKAGE_MAPPING_SET_ENTRY_BYTES 64u

static const uint8_t blob_map_magic[8] = {'Z','P','B','M','1',0,0,0};
static const uint8_t mapping_set_magic[8] = {'Z','P','M','S','1',0,0,0};

struct package_mapping_work {
    uint8_t blob_root[32];
    uint8_t mapping_root[32];
    uint64_t size;
    uint32_t chunk_count;
    bool cache_miss;
};

static bool mapping_expected_chunks(uint64_t size, uint32_t *out)
{
    uint64_t chunks = size == 0 ? 0 :
        1u + (size - 1u) / VCS_PACKAGE_CHUNK_BYTES;
    if (!out || chunks > UINT32_MAX ||
        chunks > VCS_PACKAGE_MAX_TOTAL_CHUNKS)
        return false;
    *out = (uint32_t)chunks;
    return true;
}

static bool blob_map_serialize(
    const uint8_t blob_root[32], uint64_t size, const uint8_t *hashes,
    uint32_t chunk_count, uint8_t **wire_out, size_t *wire_len_out)
{
    if (wire_out) *wire_out = NULL;
    if (wire_len_out) *wire_len_out = 0;
    uint32_t expected = 0;
    if (!blob_root || !wire_out || !wire_len_out ||
        !zcl_bytes_any_set(blob_root, 32) ||
        !mapping_expected_chunks(size, &expected) || expected != chunk_count ||
        (chunk_count > 0 && !hashes))
        return false;
    size_t wire_len = PACKAGE_BLOB_MAP_HEADER_BYTES +
        (size_t)chunk_count * 32u;
    uint8_t *wire = zcl_calloc(wire_len, 1u, "vcs.package.blob_map");
    if (!wire) return false;
    size_t off = 0;
    memcpy(wire + off, blob_map_magic, 8); off += 8;
    zcl_write_u32_le(wire + off, VCS_PACKAGE_MAPPING_VERSION); off += 4;
    memcpy(wire + off, blob_root, 32); off += 32;
    zcl_write_u64_le(wire + off, size); off += 8;
    zcl_write_u32_le(wire + off, chunk_count); off += 4;
    if (chunk_count > 0) {
        memcpy(wire + off, hashes, (size_t)chunk_count * 32u);
        off += (size_t)chunk_count * 32u;
    }
    if (off != wire_len) {
        free(wire);
        return false;
    }
    *wire_out = wire;
    *wire_len_out = wire_len;
    return true;
}

static bool blob_map_parse(
    const uint8_t *wire, size_t wire_len, const uint8_t expected_blob[32],
    uint64_t expected_size, uint8_t **hashes_out, uint32_t *chunk_count_out)
{
    if (hashes_out) *hashes_out = NULL;
    if (chunk_count_out) *chunk_count_out = 0;
    if (!wire || !expected_blob || !hashes_out || !chunk_count_out ||
        wire_len < PACKAGE_BLOB_MAP_HEADER_BYTES ||
        memcmp(wire, blob_map_magic, 8) != 0 ||
        zcl_read_u32_le(wire + 8) != VCS_PACKAGE_MAPPING_VERSION ||
        memcmp(wire + 12, expected_blob, 32) != 0 ||
        zcl_read_u64_le(wire + 44) != expected_size)
        return false;
    uint32_t count = zcl_read_u32_le(wire + 52), expected = 0;
    if (!mapping_expected_chunks(expected_size, &expected) ||
        count != expected ||
        wire_len != PACKAGE_BLOB_MAP_HEADER_BYTES + (size_t)count * 32u)
        return false;
    uint8_t *hashes = count > 0
        ? zcl_malloc((size_t)count * 32u, "vcs.package.map_hashes") : NULL;
    if (count > 0 && !hashes) return false;
    if (count > 0)
        memcpy(hashes, wire + PACKAGE_BLOB_MAP_HEADER_BYTES,
               (size_t)count * 32u);
    *hashes_out = hashes;
    *chunk_count_out = count;
    return true;
}

static bool blob_map_load(
    const char *repo_root, const uint8_t mapping_root[32],
    const uint8_t blob_root[32], uint64_t size,
    uint8_t **hashes_out, uint32_t *chunk_count_out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = vcs_object_get(repo_root, mapping_root,
                             VCS_TAG_PACKAGE_BLOB_MAP,
                             &wire, &wire_len) == 0 &&
        blob_map_parse(wire, wire_len, blob_root, size,
                       hashes_out, chunk_count_out);
    free(wire);
    return ok;
}

static bool blob_map_build(
    const char *repo_root, const uint8_t blob_root[32], uint64_t size,
    uint8_t mapping_root[32], uint32_t *chunk_count_out)
{
    uint8_t *bytes = NULL, *hashes = NULL, *wire = NULL;
    size_t len = 0, wire_len = 0;
    uint32_t chunks = 0;
    bool ok = size <= SIZE_MAX && mapping_expected_chunks(size, &chunks) &&
        vcs_object_get(repo_root, blob_root, VCS_TAG_BLOB,
                       &bytes, &len) == 0 && len == (size_t)size;
    if (ok && chunks > 0) {
        hashes = zcl_malloc((size_t)chunks * 32u,
                            "vcs.package.new_map_hashes");
        ok = hashes != NULL;
    }
    for (uint32_t i = 0; ok && i < chunks; i++) {
        size_t off = (size_t)i * VCS_PACKAGE_CHUNK_BYTES;
        size_t take = len - off;
        if (take > VCS_PACKAGE_CHUNK_BYTES) take = VCS_PACKAGE_CHUNK_BYTES;
        ok = vcs_package_chunk_hash(bytes + off, take, hashes + i * 32u);
    }
    ok = ok && blob_map_serialize(blob_root, size, hashes, chunks,
                                  &wire, &wire_len) &&
        vcs_object_put(repo_root, wire, wire_len,
                       VCS_TAG_PACKAGE_BLOB_MAP, mapping_root);
    free(wire);
    free(hashes);
    free(bytes);
    if (ok) *chunk_count_out = chunks;
    return ok;
}

static int mapping_work_cmp(const void *a, const void *b)
{
    const struct package_mapping_work *wa = a, *wb = b;
    return memcmp(wa->blob_root, wb->blob_root, 32);
}

static bool mapping_work_from_tree(
    const struct vcs_manifest *tree, struct package_mapping_work **work_out,
    size_t *count_out)
{
    *work_out = NULL;
    *count_out = 0;
    if (!tree || tree->count == 0 || tree->count > VCS_PACKAGE_MAX_FILES)
        return false;
    struct package_mapping_work *work = zcl_calloc(
        tree->count, sizeof(*work), "vcs.package.mapping_work");
    if (!work) return false;
    for (size_t i = 0; i < tree->count; i++) {
        const struct vcs_entry *entry = &tree->entries[i];
        if (!S_ISREG(entry->mode) || entry->size > SIZE_MAX ||
            !vcs_package_path_valid(entry->path)) {
            free(work);
            return false;
        }
        memcpy(work[i].blob_root, entry->blob, 32);
        work[i].size = entry->size;
    }
    qsort(work, tree->count, sizeof(*work), mapping_work_cmp);
    size_t unique = 0;
    for (size_t i = 0; i < tree->count; i++) {
        if (unique > 0 &&
            memcmp(work[unique - 1u].blob_root, work[i].blob_root, 32) == 0) {
            if (work[unique - 1u].size != work[i].size) {
                free(work);
                return false;
            }
            continue;
        }
        if (unique != i) work[unique] = work[i];
        unique++;
    }
    *work_out = work;
    *count_out = unique;
    return true;
}

static bool mapping_set_serialize(
    const struct vcs_package_mapping_set *set,
    uint8_t **wire_out, size_t *wire_len_out)
{
    if (wire_out) *wire_out = NULL;
    if (wire_len_out) *wire_len_out = 0;
    if (!set || !wire_out || !wire_len_out ||
        set->version != VCS_PACKAGE_MAPPING_VERSION ||
        !zcl_bytes_any_set(set->source_tree_root, 32) ||
        !zcl_bytes_any_set(set->lane_receipt_root, 32) ||
        !set->entries || set->count == 0 ||
        set->count > VCS_PACKAGE_MAX_FILES ||
        set->count > (SIZE_MAX - PACKAGE_MAPPING_SET_HEADER_BYTES) /
                         PACKAGE_MAPPING_SET_ENTRY_BYTES)
        return false;
    size_t wire_len = PACKAGE_MAPPING_SET_HEADER_BYTES +
        set->count * PACKAGE_MAPPING_SET_ENTRY_BYTES;
    uint8_t *wire = zcl_calloc(wire_len, 1u, "vcs.package.mapping_set");
    if (!wire) return false;
    size_t off = 0;
    memcpy(wire + off, mapping_set_magic, 8); off += 8;
    zcl_write_u32_le(wire + off, set->version); off += 4;
    memcpy(wire + off, set->source_tree_root, 32); off += 32;
    memcpy(wire + off, set->lane_receipt_root, 32); off += 32;
    zcl_write_u32_le(wire + off, (uint32_t)set->count); off += 4;
    for (size_t i = 0; i < set->count; i++) {
        if (!zcl_bytes_any_set(set->entries[i].blob_root, 32) ||
            !zcl_bytes_any_set(set->entries[i].mapping_root, 32) ||
            (i > 0 && memcmp(set->entries[i - 1u].blob_root,
                             set->entries[i].blob_root, 32) >= 0)) {
            free(wire);
            return false;
        }
        memcpy(wire + off, set->entries[i].blob_root, 32); off += 32;
        memcpy(wire + off, set->entries[i].mapping_root, 32); off += 32;
    }
    if (off != wire_len) {
        free(wire);
        return false;
    }
    *wire_out = wire;
    *wire_len_out = wire_len;
    return true;
}

void vcs_package_mapping_set_init(struct vcs_package_mapping_set *set)
{
    if (set) memset(set, 0, sizeof(*set));
}

void vcs_package_mapping_set_free(struct vcs_package_mapping_set *set)
{
    if (!set) return;
    free(set->entries);
    memset(set, 0, sizeof(*set));
}

static bool mapping_set_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_package_mapping_set *out)
{
    if (!wire || !out || wire_len < PACKAGE_MAPPING_SET_HEADER_BYTES ||
        memcmp(wire, mapping_set_magic, 8) != 0 ||
        zcl_read_u32_le(wire + 8) != VCS_PACKAGE_MAPPING_VERSION)
        return false;
    uint32_t count = zcl_read_u32_le(wire + 76);
    if (count == 0 || count > VCS_PACKAGE_MAX_FILES ||
        wire_len != PACKAGE_MAPPING_SET_HEADER_BYTES +
                        (size_t)count * PACKAGE_MAPPING_SET_ENTRY_BYTES)
        return false;
    struct vcs_package_mapping_set parsed = {
        .version = VCS_PACKAGE_MAPPING_VERSION,
        .count = count,
    };
    memcpy(parsed.source_tree_root, wire + 12, 32);
    memcpy(parsed.lane_receipt_root, wire + 44, 32);
    parsed.entries = zcl_calloc(count, sizeof(*parsed.entries),
                                "vcs.package.mapping_entries");
    if (!parsed.entries) return false;
    size_t off = PACKAGE_MAPPING_SET_HEADER_BYTES;
    for (size_t i = 0; i < count; i++) {
        memcpy(parsed.entries[i].blob_root, wire + off, 32); off += 32;
        memcpy(parsed.entries[i].mapping_root, wire + off, 32); off += 32;
    }
    uint8_t *checked = NULL;
    size_t checked_len = 0;
    bool ok = mapping_set_serialize(&parsed, &checked, &checked_len) &&
        checked_len == wire_len && memcmp(checked, wire, wire_len) == 0;
    free(checked);
    if (!ok) {
        vcs_package_mapping_set_free(&parsed);
        return false;
    }
    *out = parsed;
    return true;
}

bool vcs_package_mapping_set_load(
    const char *repo_root, const uint8_t mapping_set_root[32],
    struct vcs_package_mapping_set *out)
{
    if (!repo_root || !repo_root[0] || !mapping_set_root || !out)
        return false;
    vcs_package_mapping_set_init(out);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = vcs_object_get(repo_root, mapping_set_root,
                             VCS_TAG_PACKAGE_MAPPING_SET,
                             &wire, &wire_len) == 0 &&
        mapping_set_parse(wire, wire_len, out);
    free(wire);
    return ok;
}

static bool mapping_work_resolve(
    const char *repo_root, struct vcs_index *index,
    struct package_mapping_work *work,
    struct vcs_package_mapping_metrics *metrics)
{
    bool found = false;
    uint8_t *hashes = NULL;
    uint32_t chunks = 0;
    if (!vcs_index_package_map_get(index, work->blob_root,
                                   work->mapping_root, &found))
        return false;
    bool hit = found && blob_map_load(
        repo_root, work->mapping_root, work->blob_root, work->size,
        &hashes, &chunks);
    free(hashes);
    if (hit) {
        work->chunk_count = chunks;
        metrics->blob_hits++;
        if (UINT32_MAX - metrics->reused_chunks < chunks) return false;
        metrics->reused_chunks += chunks;
        return true;
    }
    if (!blob_map_build(repo_root, work->blob_root, work->size,
                        work->mapping_root, &work->chunk_count) ||
        UINT64_MAX - metrics->bytes_scanned < work->size ||
        UINT32_MAX - metrics->new_chunks < work->chunk_count)
        return false;
    work->cache_miss = true;
    metrics->blob_misses++;
    metrics->bytes_scanned += work->size;
    metrics->new_chunks += work->chunk_count;
    return true;
}

static bool mapping_index_commit(struct vcs_index *index,
                                 const struct package_mapping_work *work,
                                 size_t count)
{
    bool have_miss = false;
    for (size_t i = 0; i < count; i++) have_miss |= work[i].cache_miss;
    if (!have_miss) return true;
    if (!vcs_index_begin(index)) return false;
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++)
        if (work[i].cache_miss)
            ok = vcs_index_package_map_put_in_tx(
                index, work[i].blob_root, work[i].mapping_root);
    if (!ok) {
        (void)vcs_index_rollback(index);
        return false;
    }
    return vcs_index_commit(index);
}

bool vcs_package_mapping_set_build(
    const char *repo_root, const uint8_t source_tree_root[32],
    const uint8_t lane_receipt_root[32],
    struct vcs_package_mapping_metrics *metrics,
    uint8_t mapping_set_root[32])
{
    if (!repo_root || !repo_root[0] || !source_tree_root ||
        !lane_receipt_root || !metrics || !mapping_set_root ||
        !zcl_bytes_any_set(source_tree_root, 32) ||
        !zcl_bytes_any_set(lane_receipt_root, 32))
        return false;
    memset(metrics, 0, sizeof(*metrics));
    struct vcs_manifest tree;
    if (!vcs_tree_load(repo_root, source_tree_root, &tree)) return false;
    struct package_mapping_work *work = NULL;
    size_t count = 0;
    bool ok = mapping_work_from_tree(&tree, &work, &count);
    struct vcs_index *index = ok ? vcs_index_open(repo_root) : NULL;
    ok = ok && index != NULL;
    for (size_t i = 0; ok && i < count; i++)
        ok = mapping_work_resolve(repo_root, index, &work[i], metrics);
    if (ok) ok = mapping_index_commit(index, work, count);
    struct vcs_package_mapping_entry *entries = ok ? zcl_calloc(
        count, sizeof(*entries), "vcs.package.mapping_set_entries") : NULL;
    ok = ok && entries != NULL;
    for (size_t i = 0; ok && i < count; i++) {
        memcpy(entries[i].blob_root, work[i].blob_root, 32);
        memcpy(entries[i].mapping_root, work[i].mapping_root, 32);
    }
    struct vcs_package_mapping_set set = {
        .version = VCS_PACKAGE_MAPPING_VERSION,
        .entries = entries,
        .count = count,
    };
    memcpy(set.source_tree_root, source_tree_root, 32);
    memcpy(set.lane_receipt_root, lane_receipt_root, 32);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (ok) ok = mapping_set_serialize(&set, &wire, &wire_len) &&
        vcs_object_put(repo_root, wire, wire_len,
                       VCS_TAG_PACKAGE_MAPPING_SET, mapping_set_root);
    free(wire);
    if (index) vcs_index_close(index);
    free(entries);
    free(work);
    vcs_manifest_free(&tree);
    return ok;
}

bool vcs_package_mapping_set_find(
    const char *repo_root, const struct vcs_package_mapping_set *set,
    const uint8_t blob_root[32], uint64_t expected_size,
    uint8_t **chunk_hashes_out, uint32_t *chunk_count_out)
{
    if (chunk_hashes_out) *chunk_hashes_out = NULL;
    if (chunk_count_out) *chunk_count_out = 0;
    if (!repo_root || !repo_root[0] || !set || !set->entries ||
        !blob_root || !chunk_hashes_out || !chunk_count_out)
        return false;
    size_t lo = 0, hi = set->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = memcmp(blob_root, set->entries[mid].blob_root, 32);
        if (cmp == 0)
            return blob_map_load(
                repo_root, set->entries[mid].mapping_root, blob_root,
                expected_size, chunk_hashes_out, chunk_count_out);
        if (cmp < 0) hi = mid;
        else lo = mid + 1u;
    }
    return false;
}
