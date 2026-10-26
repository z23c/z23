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

/* Mutable state shared by the two passes of the tip-directed height-map
 * scan in bilr_load_height_map_for_tip. */
struct bilr_tip_scan {
    int max_height;
    int64_t scanned;
    int64_t usable;
    int64_t duplicate_heights;
    struct bilr_candidate *cands;
    size_t cand_count;
    int32_t *hash_table;
    size_t hash_cap;
    int32_t *height_seen;
};

/* Result codes for one tip-scan pass, and for one record within it. */
enum bilr_tip_scan_status {
    BILR_TIP_SCAN_OK = 0,
    BILR_TIP_SCAN_STOP,         /* key left the 'b' keyspace: end pass */
    BILR_TIP_SCAN_SKIP_RECORD,  /* record not usable: advance iterator */
    BILR_TIP_SCAN_OVERFLOW,     /* pass 2 saw more usable records than pass 1 */
    BILR_TIP_SCAN_DUP_HASH,     /* duplicate block hash in the index */
    BILR_TIP_SCAN_EMPTY_INDEX,  /* pass 1 found no usable records */
    BILR_TIP_SCAN_ALLOC_FAILED  /* height-map buffer allocation failed */
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

/* True when key k still sits in the blocks/index 'b' keyspace. */
static bool bilr_key_is_block_entry(const char *k, size_t klen)
{
    return klen >= 1 && k[0] == 'b';
}

/* Decode one 'b'-record value into dbi. Returns 0 when the record is
 * usable, non-zero when it must be skipped. */
static int bilr_decode_candidate_value(const char *v, size_t vlen,
                                       struct disk_block_index *dbi)
{
    if (!v || vlen == 0)
        return 1;
    disk_block_index_init(dbi);
    struct byte_stream s;
    stream_init_from_data(&s, (unsigned char *)v, vlen);

    /* Only keep entries that are usable for body-pull:
     * BLOCK_HAVE_DATA must be set (we need an nFile/nDataPos),
     * and the entry must not be FAILED. */
    bool usable = disk_block_index_deserialize(dbi, &s) &&
                  (dbi->nStatus & BLOCK_HAVE_DATA) != 0 &&
                  (dbi->nStatus & BLOCK_FAILED_MASK) == 0 &&
                  dbi->nHeight >= 0;
    stream_free(&s);
    return usable ? 0 : 1;
}

/* True when candidate idx should replace the current best candidate. */
static bool bilr_candidate_beats_best(const struct bilr_candidate *cands,
                                      int32_t best_idx, int32_t idx)
{
    if (best_idx < 0)
        return true;
    if (cands[idx].height > cands[best_idx].height)
        return true;
    return cands[idx].height == cands[best_idx].height &&
           bilr_validity_level(cands[idx].nStatus) >
           bilr_validity_level(cands[best_idx].nStatus);
}

/* Make room for one more fallback candidate; returns 0 on success, -1 on
 * allocation failure (with *cands left unchanged). */
static int bilr_grow_candidate_array(struct bilr_candidate **cands,
                                     size_t *cap, size_t count)
{
    if (count != *cap)
        return 0;
    size_t next_cap = *cap ? *cap * 2 : 1024;
    struct bilr_candidate *next =
        zcl_realloc(*cands, next_cap * sizeof(*next),
                    "bilr_fallback_candidates");
    if (!next)
        return -1;
    *cands = next;
    *cap = next_cap;
    return 0;
}

/* Allocate and initialise the pass-2 buffers (height-map array, candidate
 * store, hash table, height_seen); returns 0 on success, -1 on failure
 * (with any partial allocations freed). */
static int bilr_alloc_tip_scan_buffers(struct bilr_tip_scan *st,
                                       struct legacy_block_loc **out_array,
                                       size_t *out_count)
{
    size_t count = (size_t)st->max_height + 1;
    struct legacy_block_loc *arr =
        zcl_malloc(count * sizeof(*arr), "bilr_height_map");
    if (!arr)
        return -1;
    st->cands = zcl_malloc((size_t)st->usable * sizeof(*st->cands),
                           "bilr_candidates");
    if (!st->cands) {
        free(arr);
        return -1;
    }
    st->hash_cap = bilr_hash_table_cap((size_t)st->usable);
    st->hash_table = zcl_malloc(st->hash_cap * sizeof(*st->hash_table),
                                "bilr_hash_table");
    if (!st->hash_table) {
        free(st->cands);
        free(arr);
        return -1;
    }
    st->height_seen = zcl_malloc(count * sizeof(*st->height_seen),
                                 "bilr_height_seen");
    if (!st->height_seen) {
        free(st->hash_table);
        free(st->cands);
        free(arr);
        return -1;
    }
    bilr_int32_fill(st->hash_table, st->hash_cap, -1);
    bilr_int32_fill(st->height_seen, count, -1);
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
    return 0;
}

/* Handle one blocks/index record for the pass in progress: count it
 * (pass 0) or store it as a candidate (pass 1). Never advances the
 * iterator; returns a bilr_tip_scan_status code. */
static int bilr_process_tip_scan_record(int pass,
                                        struct db_iterator *it,
                                        struct bilr_tip_scan *st)
{
    size_t klen = 0;
    const char *k = db_iter_key(it, &klen);
    if (!bilr_key_is_block_entry(k, klen))
        return BILR_TIP_SCAN_STOP;  /* end of 'b' keyspace */
    if (klen != 33)
        return BILR_TIP_SCAN_SKIP_RECORD;
    if (pass == 0)
        st->scanned++;

    size_t vlen = 0;
    const char *v = db_iter_value(it, &vlen);
    struct disk_block_index dbi;
    if (bilr_decode_candidate_value(v, vlen, &dbi) != 0)
        return BILR_TIP_SCAN_SKIP_RECORD;

    if (pass == 0) {
        if (dbi.nHeight > st->max_height)
            st->max_height = dbi.nHeight;
        st->usable++;
        return BILR_TIP_SCAN_OK;
    }

    if (st->cand_count >= (size_t)st->usable)
        return BILR_TIP_SCAN_OVERFLOW;
    if (st->height_seen[(size_t)dbi.nHeight] >= 0)
        st->duplicate_heights++;
    st->height_seen[(size_t)dbi.nHeight] = (int32_t)st->cand_count;
    struct bilr_candidate *cand = &st->cands[st->cand_count];
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
    if (!bilr_hash_insert(st->hash_table, st->hash_cap, st->cands,
                          (int32_t)st->cand_count))
        return BILR_TIP_SCAN_DUP_HASH;
    st->cand_count++;
    return BILR_TIP_SCAN_OK;
}

/* Run one scan pass over the 'b' keyspace. Returns BILR_TIP_SCAN_OK, a
 * pass-level failure code, or a record-level overflow/duplicate code
 * (in which case the iterator has already been released). */
static int bilr_run_tip_scan_pass(struct bilr *r, int pass,
                                  struct bilr_tip_scan *st,
                                  struct legacy_block_loc **out_array,
                                  size_t *out_count)
{
    if (pass == 1) {
        if (st->max_height < 0)
            return BILR_TIP_SCAN_EMPTY_INDEX;
        if (bilr_alloc_tip_scan_buffers(st, out_array, out_count) != 0)
            return BILR_TIP_SCAN_ALLOC_FAILED;
    }

    struct db_iterator it;
    db_iter_init(&it, &r->db);
    const char seek_key = 'b';
    db_iter_seek(&it, &seek_key, 1);

    while (db_iter_valid(&it)) {
        int rc = bilr_process_tip_scan_record(pass, &it, st);
        if (rc == BILR_TIP_SCAN_STOP)
            break;
        if (rc == BILR_TIP_SCAN_SKIP_RECORD) {
            db_iter_next(&it);
            continue;
        }
        if (rc != BILR_TIP_SCAN_OK) {
            db_iter_free(&it);
            return rc;
        }
        db_iter_next(&it);
    }

    db_iter_free(&it);
    return BILR_TIP_SCAN_OK;
}

/* Release the scan buffers and reset the caller's outputs after a
 * failed tip-directed load. */
static void bilr_discard_tip_scan_state(struct bilr_tip_scan *st,
                                        struct legacy_block_loc **out_array,
                                        size_t *out_count)
{
    free(st->height_seen);
    free(st->hash_table);
    free(st->cands);
    free(*out_array);
    *out_array = NULL;
    *out_count = 0;
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

    struct bilr_tip_scan st = {
        .max_height = -1,
        .scanned = 0,
        .usable = 0,
        .duplicate_heights = 0,
        .cands = NULL,
        .cand_count = 0,
        .hash_table = NULL,
        .hash_cap = 0,
        .height_seen = NULL,
    };

    for (int pass = 0; pass < 2; pass++) {
        int rc = bilr_run_tip_scan_pass(r, pass, &st, out_array, out_count);
        if (rc != BILR_TIP_SCAN_OK) {
            if (rc == BILR_TIP_SCAN_EMPTY_INDEX) {
                fprintf(stderr,
                        "[bilr] no usable block-index records found\n");
                return false;
            }
            if (rc == BILR_TIP_SCAN_ALLOC_FAILED)
                return false;
            bilr_discard_tip_scan_state(&st, out_array, out_count);
            if (rc == BILR_TIP_SCAN_OVERFLOW) {
                fprintf(stderr,
                        "[bilr] candidate overflow while loading map\n");
            } else {
                fprintf(stderr,
                        "[bilr] duplicate block hash in legacy index\n");
            }
            return false;
        }
    }

    fprintf(stderr,
            "[bilr] scanned=%lld usable=%lld max_height=%d\n",
            (long long)st.scanned, (long long)st.usable, st.max_height);
    fprintf(stderr, // obs-ok:legacy-map-diagnostic
            "[bilr] duplicate heights: seen=%lld\n",
            (long long)st.duplicate_heights);

    int32_t tip_idx = bilr_hash_lookup(st.hash_table, st.hash_cap,
                                       st.cands, tip_hash);
    if (tip_idx < 0) {
        fprintf(stderr, // obs-ok:legacy-map-diagnostic
                "[bilr] chainstate best block not found in blocks/index\n");
        bilr_discard_tip_scan_state(&st, out_array, out_count);
        return false;
    }
    if (!bilr_resolve_chain_from_tip(*out_array, *out_count, st.cands,
                                     st.cand_count, st.hash_table,
                                     st.hash_cap, tip_idx)) {
        bilr_discard_tip_scan_state(&st, out_array, out_count);
        return false;
    }
    fprintf(stderr, // obs-ok:legacy-map-diagnostic
            "[bilr] selected chain anchored at h=%d\n",
            st.cands[tip_idx].height);
    bilr_report_height_map_continuity(*out_array, *out_count);
    free(st.height_seen);
    free(st.hash_table);
    free(st.cands);
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
        if (!bilr_key_is_block_entry(k, klen))
            break;
        if (klen != 33) {
            db_iter_next(&it);
            continue;
        }
        size_t vlen = 0;
        const char *v = db_iter_value(&it, &vlen);
        struct disk_block_index dbi;
        if (bilr_decode_candidate_value(v, vlen, &dbi) != 0) {
            db_iter_next(&it);
            continue;
        }
        if (bilr_grow_candidate_array(&cands, &cand_cap, cand_count) != 0) {
            free(cands);
            db_iter_free(&it);
            return false;
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
        if (bilr_candidate_beats_best(cands, best_idx, idx))
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
