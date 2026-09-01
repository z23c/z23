/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blocks_index_legacy_reader.c — see header.
 *
 * Bitcoin Core 0.8+ blocks/index/ LevelDB schema (used unchanged by
 * zclassicd):
 *   key:   'b' || <32-byte block hash, raw byte order>
 *   value: serialized CDiskBlockIndex — same wire format we use
 *          ourselves (see disk_block_index_serialize/deserialize in
 *          engine/modules/storage/src/block_index_db.c).
 *
 * Other keys ('f' for file-info, 't' for txindex, etc.) are skipped.
 */

#include "storage/blocks_index_legacy_reader.h"

#include "chain/chain.h"
#include "core/serialize.h"
#include "storage/block_index_db.h"
#include "storage/dbwrapper.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct bilr {
    struct db_wrapper db;
};

struct bilr_candidate {
    struct uint256 hash;
    struct uint256 hashPrev;
    int32_t height;
    int32_t nFile;
    uint32_t nDataPos;
    uint32_t nUndoPos;
    uint32_t nStatus;
};

static int bilr_validity_level(uint32_t status)
{
    return (int)(status & BLOCK_VALID_MASK);
}

static void bilr_loc_from_candidate(struct legacy_block_loc *loc,
                                    const struct bilr_candidate *cand)
{
    loc->hash = cand->hash;
    loc->hashPrev = cand->hashPrev;
    loc->height = cand->height;
    loc->nFile = cand->nFile;
    loc->nDataPos = cand->nDataPos;
    loc->nUndoPos = cand->nUndoPos;
    loc->nStatus = cand->nStatus;
}

static size_t bilr_hash_table_cap(size_t n)
{
    size_t cap = 1;
    while (cap < n * 2)
        cap <<= 1;
    return cap < 16 ? 16 : cap;
}

static void bilr_int32_fill(int32_t *p, size_t n, int32_t v)
{
    for (size_t i = 0; i < n; i++)
        p[i] = v;
}

static bool bilr_hash_insert(int32_t *table,
                             size_t cap,
                             const struct bilr_candidate *cands,
                             int32_t idx)
{
    size_t slot = (size_t)uint256_get_cheap_hash(&cands[idx].hash) & (cap - 1);
    for (size_t probe = 0; probe < cap; probe++) {
        int32_t cur = table[slot];
        if (cur < 0) {
            table[slot] = idx;
            return true;
        }
        if (uint256_eq(&cands[cur].hash, &cands[idx].hash))
            return false;
        slot = (slot + 1) & (cap - 1);
    }
    return false;
}

static int32_t bilr_hash_lookup(const int32_t *table,
                                size_t cap,
                                const struct bilr_candidate *cands,
                                const struct uint256 *hash)
{
    size_t slot = (size_t)uint256_get_cheap_hash(hash) & (cap - 1);
    for (size_t probe = 0; probe < cap; probe++) {
        int32_t cur = table[slot];
        if (cur < 0)
            return -1;
        if (uint256_eq(&cands[cur].hash, hash))
            return cur;
        slot = (slot + 1) & (cap - 1);
    }
    return -1;
}

static bool bilr_resolve_chain_from_tip(
    struct legacy_block_loc *arr,
    size_t arr_count,
    const struct bilr_candidate *cands,
    size_t cand_count,
    const int32_t *hash_table,
    size_t hash_cap,
    int32_t tip_idx)
{
    if (tip_idx < 0 || (size_t)tip_idx >= cand_count)
        return false;
    const struct bilr_candidate *tip = &cands[tip_idx];
    if (tip->height < 0 || (size_t)tip->height >= arr_count)
        return false;

    int32_t cur = tip_idx;
    int expected_height = tip->height;
    while (expected_height >= 0) {
        const struct bilr_candidate *cand = &cands[cur];
        if (cand->height != expected_height) {
            fprintf(stderr, // obs-ok:legacy-map-diagnostic
                    "[bilr] tip-chain resolve failed: expected h=%d "
                    "but candidate h=%d\n",
                    expected_height, cand->height);
            return false;
        }
        bilr_loc_from_candidate(&arr[(size_t)expected_height], cand);
        if (expected_height == 0)
            return true;
        cur = bilr_hash_lookup(hash_table, hash_cap, cands, &cand->hashPrev);
        if (cur < 0) {
            fprintf(stderr, // obs-ok:legacy-map-diagnostic
                    "[bilr] tip-chain resolve failed: missing parent "
                    "for h=%d\n",
                    expected_height);
            return false;
        }
        expected_height--;
    }
    return true;
}

static void bilr_report_height_map_continuity(
    const struct legacy_block_loc *arr,
    size_t count)
{
    int64_t missing = 0;
    int64_t parent_mismatch = 0;
    int first_missing = -1;
    int first_parent_mismatch = -1;

    for (size_t i = 0; i < count; i++) {
        if (arr[i].height < 0) {
            missing++;
            if (first_missing < 0)
                first_missing = (int)i;
            continue;
        }
        if (i == 0)
            continue;
        if (arr[i - 1].height < 0)
            continue;
        if (!uint256_eq(&arr[i].hashPrev, &arr[i - 1].hash)) {
            parent_mismatch++;
            if (first_parent_mismatch < 0)
                first_parent_mismatch = (int)i;
        }
    }

    fprintf(stderr, // obs-ok:legacy-map-diagnostic
            "[bilr] selected map continuity: missing=%lld "
            "first_missing=%d parent_mismatch=%lld "
            "first_parent_mismatch=%d\n",
            (long long)missing, first_missing,
            (long long)parent_mismatch, first_parent_mismatch);
}

bool bilr_open(const char *blocks_index_dir, struct bilr **out)
{
    if (!blocks_index_dir || !out)
        return false;
    *out = NULL;

    struct bilr *r = zcl_malloc(sizeof(*r), "bilr");
    if (!r)
        return false;
    memset(r, 0, sizeof(*r));

    /* 16 MB cache — plenty for a one-shot scan; cache hit-rate is
     * effectively zero since we read every record once. */
    if (!db_wrapper_open(&r->db, blocks_index_dir,
                         16u << 20, false, false)) {
        fprintf(stderr,
                "[bilr] open failed: %s "
                "(LOCK held? stop zclassicd or snapshot the dir first)\n",
                blocks_index_dir);
        free(r);
        return false;
    }

    *out = r;
    return true;
}

void bilr_close(struct bilr *r)
{
    if (!r) return;
    db_wrapper_close(&r->db);
    free(r);
}

bool bilr_load_height_map_for_tip(struct bilr *r,
                                  const struct uint256 *tip_hash,
                                  struct legacy_block_loc **out_array,
                                  size_t *out_count)
{
    if (!r || !tip_hash || !out_array || !out_count)
        return false;
    *out_array = NULL;
    *out_count = 0;

    /* Two-pass to avoid wasting an entire 200 MB allocation on a
     * sparse / corrupt LevelDB. Pass 1 finds max_height + counts
     * usable records; pass 2 fills the array.
     *
     * In practice this doubles the LevelDB scan cost; if it becomes
     * a problem we can switch to a doubling-strategy single-pass. */

    int max_height = -1;
    int64_t scanned = 0;
    int64_t usable  = 0;
    int64_t duplicate_heights = 0;
    struct bilr_candidate *cands = NULL;
    size_t cand_count = 0;
    int32_t *hash_table = NULL;
    size_t hash_cap = 0;
    int32_t *height_seen = NULL;

    for (int pass = 0; pass < 2; pass++) {
        if (pass == 1) {
            if (max_height < 0) {
                fprintf(stderr,
                        "[bilr] no usable block-index records found\n");
                return false;
            }
            size_t count = (size_t)max_height + 1;
            struct legacy_block_loc *arr =
                zcl_malloc(count * sizeof(*arr), "bilr_height_map");
            if (!arr)
                return false;
            cands = zcl_malloc((size_t)usable * sizeof(*cands),
                               "bilr_candidates");
            if (!cands) {
                free(arr);
                return false;
            }
            hash_cap = bilr_hash_table_cap((size_t)usable);
            hash_table = zcl_malloc(hash_cap * sizeof(*hash_table),
                                    "bilr_hash_table");
            if (!hash_table) {
                free(cands);
                free(arr);
                return false;
            }
            height_seen = zcl_malloc(count * sizeof(*height_seen),
                                     "bilr_height_seen");
            if (!height_seen) {
                free(hash_table);
                free(cands);
                free(arr);
                return false;
            }
            bilr_int32_fill(hash_table, hash_cap, -1);
            bilr_int32_fill(height_seen, count, -1);
            for (size_t i = 0; i < count; i++) {
                uint256_set_null(&arr[i].hash);
                uint256_set_null(&arr[i].hashPrev);
                arr[i].height = -1;
                arr[i].nFile = -1;
                arr[i].nDataPos = 0;
                arr[i].nUndoPos = 0;
                arr[i].nStatus = 0;
            }
            *out_array = arr;
            *out_count = count;
        }

        struct db_iterator it;
        db_iter_init(&it, &r->db);
        const char seek_key = 'b';
        db_iter_seek(&it, &seek_key, 1);

        while (db_iter_valid(&it)) {
            size_t klen = 0;
            const char *k = db_iter_key(&it, &klen);
            if (klen < 1 || k[0] != 'b')
                break;  /* end of 'b' keyspace */
            if (klen != 33) {
                db_iter_next(&it);
                continue;
            }
            if (pass == 0) scanned++;

            size_t vlen = 0;
            const char *v = db_iter_value(&it, &vlen);
            if (!v || vlen == 0) {
                db_iter_next(&it);
                continue;
            }

            struct disk_block_index dbi;
            disk_block_index_init(&dbi);
            struct byte_stream s;
            stream_init_from_data(&s, (unsigned char *)v, vlen);

            if (!disk_block_index_deserialize(&dbi, &s)) {
                stream_free(&s);
                db_iter_next(&it);
                continue;
            }
            stream_free(&s);

            /* Only keep entries that are usable for body-pull:
             * BLOCK_HAVE_DATA must be set (we need an nFile/nDataPos),
             * and the entry must not be FAILED. */
            bool have_data = (dbi.nStatus & BLOCK_HAVE_DATA) != 0;
            bool failed    = (dbi.nStatus & BLOCK_FAILED_MASK) != 0;
            if (!have_data || failed || dbi.nHeight < 0) {
                db_iter_next(&it);
                continue;
            }

            if (pass == 0) {
                if (dbi.nHeight > max_height)
                    max_height = dbi.nHeight;
                usable++;
            } else {
                if (cand_count >= (size_t)usable) {
                    db_iter_free(&it);
                    free(height_seen);
                    free(hash_table);
                    free(cands);
                    free(*out_array);
                    *out_array = NULL;
                    *out_count = 0;
                    fprintf(stderr,
                            "[bilr] candidate overflow while loading map\n");
                    return false;
                }
                if (height_seen[(size_t)dbi.nHeight] >= 0)
                    duplicate_heights++;
                height_seen[(size_t)dbi.nHeight] = (int32_t)cand_count;
                struct bilr_candidate *cand = &cands[cand_count];
                cand->height   = dbi.nHeight;
                cand->nFile    = dbi.nFile;
                cand->nDataPos = dbi.nDataPos;
                cand->nUndoPos = dbi.nUndoPos;
                cand->nStatus  = dbi.nStatus;
                cand->hashPrev = dbi.hashPrev;
                /* Hash is encoded in the LevelDB key bytes 1..32 in
                 * native byte order; copy direct to avoid recomputing
                 * the double-SHA256 from the deserialized header. */
                memcpy(cand->hash.data, k + 1, 32);
                if (!bilr_hash_insert(hash_table, hash_cap, cands,
                                      (int32_t)cand_count)) {
                    db_iter_free(&it);
                    free(height_seen);
                    free(hash_table);
                    free(cands);
                    free(*out_array);
                    *out_array = NULL;
                    *out_count = 0;
                    fprintf(stderr,
                            "[bilr] duplicate block hash in legacy index\n");
                    return false;
                }
                cand_count++;
            }

            db_iter_next(&it);
        }

        db_iter_free(&it);
    }

    fprintf(stderr,
            "[bilr] scanned=%lld usable=%lld max_height=%d\n",
            (long long)scanned, (long long)usable, max_height);
    fprintf(stderr, // obs-ok:legacy-map-diagnostic
            "[bilr] duplicate heights: seen=%lld\n",
            (long long)duplicate_heights);

    int32_t tip_idx = bilr_hash_lookup(hash_table, hash_cap, cands, tip_hash);
    if (tip_idx < 0) {
        fprintf(stderr, // obs-ok:legacy-map-diagnostic
                "[bilr] chainstate best block not found in blocks/index\n");
        free(height_seen);
        free(hash_table);
        free(cands);
        free(*out_array);
        *out_array = NULL;
        *out_count = 0;
        return false;
    }
    if (!bilr_resolve_chain_from_tip(*out_array, *out_count, cands,
                                     cand_count, hash_table, hash_cap,
                                     tip_idx)) {
        free(height_seen);
        free(hash_table);
        free(cands);
        free(*out_array);
        *out_array = NULL;
        *out_count = 0;
        return false;
    }
    fprintf(stderr, // obs-ok:legacy-map-diagnostic
            "[bilr] selected chain anchored at h=%d\n",
            cands[tip_idx].height);
    bilr_report_height_map_continuity(*out_array, *out_count);
    free(height_seen);
    free(hash_table);
    free(cands);
    return true;
}

bool bilr_load_height_map(struct bilr *r,
                          struct legacy_block_loc **out_array,
                          size_t *out_count)
{
    if (!r || !out_array || !out_count)
        return false;
    *out_array = NULL;
    *out_count = 0;

    int32_t best_idx = -1;
    struct bilr_candidate *cands = NULL;
    size_t cand_count = 0;
    size_t cand_cap = 0;

    struct db_iterator it;
    db_iter_init(&it, &r->db);
    const char seek_key = 'b';
    db_iter_seek(&it, &seek_key, 1);

    while (db_iter_valid(&it)) {
        size_t klen = 0;
        const char *k = db_iter_key(&it, &klen);
        if (klen < 1 || k[0] != 'b')
            break;
        if (klen != 33) {
            db_iter_next(&it);
            continue;
        }
        size_t vlen = 0;
        const char *v = db_iter_value(&it, &vlen);
        if (!v || vlen == 0) {
            db_iter_next(&it);
            continue;
        }
        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        struct byte_stream s;
        stream_init_from_data(&s, (unsigned char *)v, vlen);
        bool ok = disk_block_index_deserialize(&dbi, &s);
        stream_free(&s);
        if (!ok) {
            db_iter_next(&it);
            continue;
        }
        bool have_data = (dbi.nStatus & BLOCK_HAVE_DATA) != 0;
        bool failed    = (dbi.nStatus & BLOCK_FAILED_MASK) != 0;
        if (!have_data || failed || dbi.nHeight < 0) {
            db_iter_next(&it);
            continue;
        }
        if (cand_count == cand_cap) {
            size_t next_cap = cand_cap ? cand_cap * 2 : 1024;
            struct bilr_candidate *next =
                zcl_realloc(cands, next_cap * sizeof(*next),
                            "bilr_fallback_candidates");
            if (!next) {
                free(cands);
                db_iter_free(&it);
                return false;
            }
            cands = next;
            cand_cap = next_cap;
        }
        struct bilr_candidate *cand = &cands[cand_count];
        cand->height = dbi.nHeight;
        cand->nFile = dbi.nFile;
        cand->nDataPos = dbi.nDataPos;
        cand->nUndoPos = dbi.nUndoPos;
        cand->nStatus = dbi.nStatus;
        cand->hashPrev = dbi.hashPrev;
        memcpy(cand->hash.data, k + 1, 32);
        int32_t idx = (int32_t)cand_count;
        cand_count++;
        if (best_idx < 0 ||
            cand->height > cands[best_idx].height ||
            (cand->height == cands[best_idx].height &&
             bilr_validity_level(cand->nStatus) >
             bilr_validity_level(cands[best_idx].nStatus)))
            best_idx = idx;
        db_iter_next(&it);
    }
    db_iter_free(&it);

    if (best_idx < 0) {
        free(cands);
        return false;
    }
    struct uint256 tip_hash = cands[best_idx].hash;
    free(cands);
    return bilr_load_height_map_for_tip(r, &tip_hash, out_array, out_count);
}

void bilr_free_height_map(struct legacy_block_loc *array)
{
    free(array);
}
