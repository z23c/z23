/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Restore Disk Repair — disk-backed active-chain reconstruction helpers. */

// one-result-type-ok:count-of-populated-entries — both public functions
// (rebuild_active_chain_from_disk / _from_block_files) return int = the
// number of active-chain entries populated, which IS the payload, not a
// fail-vs-ok bool. Partial progress is a valid, expected outcome (a torn
// ancestry rebuilds as far as disk allows); the early-stop reason is
// already logged with full context via printf. Wrapping the count in
// zcl_result would discard the count. Internal helpers return bool but
// are static and not part of the service surface.

#include "services/chain_restore_disk_repair.h"
#include "services/chain_restore_repair.h"

#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "util/boot_scan.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Slot store under the active_chain writer lock: a concurrent window grow
 * republishes c->chain, so an unlocked store could land in a just-retired
 * array and be lost. The store itself stays a plain pointer write per the
 * active_chain contract. */
static void chain_restore_disk_store_slot(struct active_chain *c, int h,
                                          struct block_index *bi)
{
    zcl_mutex_lock(&c->write_lock);
    c->chain[h] = bi;
    zcl_mutex_unlock(&c->write_lock);
}

static bool chain_restore_read_header_at_index(
    const struct block_index *bi,
    const char *datadir,
    FILE **cached,
    int *cached_file,
    struct block_header *hdr,
    struct uint256 *disk_hash_out,
    bool *hash_matches_out)
{
    if (!bi || !datadir || !datadir[0] || !hdr)
        return false;
    if (hash_matches_out)
        *hash_matches_out = false;
    if (!(bi->nStatus & BLOCK_HAVE_DATA) || bi->nFile < 0 || bi->nDataPos == 0)
        return false;

    if (!*cached || *cached_file != bi->nFile) {
        if (*cached) {
            fclose(*cached);
            *cached = NULL;
        }
        char path[576];
        snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                 datadir, bi->nFile);
        *cached = fopen(path, "rb");
        if (!*cached)
            return false;
        *cached_file = bi->nFile;
    }

    unsigned char buf[4 + 32 + 32 + 32 + 4 + 4 + 32 + 9 + MAX_SOLUTION_SIZE];
    if (fseek(*cached, (long)bi->nDataPos, SEEK_SET) != 0)
        return false;
    size_t nread = fread(buf, 1, sizeof(buf), *cached); // disk-io-lock: boot-local repair
    if (nread < 4 + 32 + 32 + 32 + 4 + 4 + 32 + 1)
        return false;

    struct byte_stream s;
    stream_init_from_data(&s, buf, nread);
    block_header_init(hdr);
    bool ok = block_header_deserialize(hdr, &s);
    stream_free(&s);
    if (!ok)
        return false;

    struct uint256 disk_hash;
    block_header_get_hash(hdr, &disk_hash);
    if (disk_hash_out)
        *disk_hash_out = disk_hash;
    if (hash_matches_out)
        *hash_matches_out = !bi->phashBlock ||
            uint256_cmp(&disk_hash, bi->phashBlock) == 0;

    return true;
}

int chain_restore_rebuild_active_chain_from_disk(
    struct main_state *ms,
    struct block_index *tip,
    const char *datadir)
{
    if (!ms || !tip || !datadir || !datadir[0])
        return 0;

    struct active_chain *c = &ms->chain_active;
    struct block_index *cur = tip;
    FILE *cached = NULL;
    int cached_file = -1;
    int populated = 0;
    int read_errors = 0;
    int repaired_heights = 0;
    int repaired_hashes = 0;
    char stop_reason[160] = "";
    int stop_height = -1;

    /* O(chain) witness (util/boot_scan.h): the disk-backed active-chain rebuild
     * walks tip->genesis reading one header per height — the bound is
     * tip->nHeight+1, NOT a delta above any durable cursor (see the loop below;
     * there is no last-flushed-height floor). This is NOT a cold-seed-only
     * path: boot reaches it on every UNCLEAN warm restart (crash / kill -9 /
     * OOM). engine/composition/src/boot.c:2743-2744 runs utxo_recovery_restore_chain_tip
     * whenever the boot is NOT a -reindex AND fast_restart was NOT taken, and
     * fast_restart requires a clean-shutdown marker
     * (engine/composition/src/boot_shutdown_marker.c: any WAL-present-without-clean-marker
     * stop sets unclean=true). That restore calls chain_restore_finalize with
     * the real datadir (engine/services/src/utxo_recovery_restore.c:737 ->
     * engine/services/src/chain_restore_repair.c:686 ->
     * chain_restore_rebuild_active_chain), which enters this O(chain) walk
     * unless chain_restore_trust_index_fastpath() is engaged. That fastpath is
     * set on a clean fast_restart (engine/composition/src/boot_fast_restart.c) and by
     * chain_restore_finalize_verified when the index is verified-consistent
     * (engine/composition/src/boot.c:3785) — but NOT around the 2744 restore, so an unclean
     * restart with an intact index STILL walks the full chain here (~74s
     * measured, chain_restore_executor.c comment). A non-zero count on a warm
     * restart is therefore EXPECTED after any unclean stop, and it being
     * O(chain) rather than O(delta) is a known slow-boot defect (docs/
     * AGENT_TRAPS.md; proven by test_rebuild_active_chain_is_o_chain_not_delta).
     * Registered once; bumped per height read. */
    atomic_uint_least64_t *scan_ctr =
        boot_scan_counter("chain_restore.disk_rebuild_rows");
    for (int h = tip->nHeight; h >= 0 && cur; h--) {
        boot_scan_bump(scan_ctr);
        if (cur->nHeight != h) {
            read_errors++;
            break;
        }

        struct block_header hdr;
        struct uint256 disk_hash;
        bool hash_matches = false;
        if (!chain_restore_read_header_at_index(cur, datadir,
                                                &cached, &cached_file, &hdr,
                                                &disk_hash, &hash_matches)) {
            read_errors++;
            stop_height = h;
            snprintf(stop_reason, sizeof(stop_reason),
                     "read_header_io_failed hash=%s",
                     cur->phashBlock ? "present" : "null");
            break;
        }
        if (!hash_matches) {
            struct block_index *replacement =
                block_map_find(&ms->map_block_index, &disk_hash);
            if (!replacement) {
                read_errors++;
                stop_height = h;
                char got_hex[65] = {0};
                char want_hex[65] = {0};
                uint256_get_hex(&disk_hash, got_hex);
                if (cur->phashBlock)
                    uint256_get_hex(cur->phashBlock, want_hex);
                snprintf(stop_reason, sizeof(stop_reason),
                         "disk_hash_unindexed got=%s want=%s",
                         got_hex, want_hex[0] ? want_hex : "<null>");
                break;
            }

            if (replacement != cur) {
                replacement->nFile = cur->nFile;
                replacement->nDataPos = cur->nDataPos;
                replacement->nStatus |= cur->nStatus & BLOCK_HAVE_DATA;
                replacement->nHeight = h;
                replacement->pskip = NULL;
                cur = replacement;
            }
            /* Option A: point phashBlock at cur's own stable per-node
             * hash storage rather than into the reallocatable bucket
             * array. Seed it from the disk hash. */
            cur->hashBlock = disk_hash;
            cur->phashBlock = &cur->hashBlock;
            if (h < tip->nHeight && c->chain[h + 1])
                c->chain[h + 1]->pprev = cur;
            repaired_hashes++;
        }

        chain_restore_disk_store_slot(c, h, cur);
        populated++;

        if (h == 0) {
            cur->pprev = NULL;
            break;
        }

        struct block_index *prev =
            block_map_find(&ms->map_block_index, &hdr.hashPrevBlock);
        if (!prev) {
            read_errors++;
            stop_height = h;
            char prev_hex[65] = {0};
            uint256_get_hex(&hdr.hashPrevBlock, prev_hex);
            snprintf(stop_reason, sizeof(stop_reason),
                     "prev_lookup_failed prev=%s found=0 want_h=%d",
                     prev_hex, h - 1);
            break;
        }
        if (prev->nHeight != h - 1) {
            prev->nHeight = h - 1;
            prev->pskip = NULL;
            repaired_heights++;
        }
        cur->pprev = prev;
        if (cur->pskip == NULL)
            block_index_build_skip(cur);
        cur = prev;
    }

    if (cached)
        fclose(cached);

    if (read_errors > 0)
        printf("[chain-restore] disk ancestry rebuild stopped early: "
               "tip_h=%d populated=%d repaired_heights=%d repaired_hashes=%d "
               "read_errors=%d stop_h=%d reason=%s\n",
               tip->nHeight, populated, repaired_heights, repaired_hashes,
               read_errors,
               stop_height, stop_reason[0] ? stop_reason : "unknown");
    else
        printf("[chain-restore] disk ancestry rebuilt active chain: "
               "tip_h=%d populated=%d repaired_heights=%d "
               "repaired_hashes=%d\n",
               tip->nHeight, populated, repaired_heights, repaired_hashes);

    return populated;
}

struct chain_restore_disk_pos_entry {
    struct uint256 hash;
    int file;
    unsigned int pos;
    bool occupied;
};

struct chain_restore_disk_pos_map {
    struct chain_restore_disk_pos_entry *entries;
    size_t capacity;
    size_t size;
};

static uint64_t chain_restore_hash_key(const struct uint256 *h)
{
    uint64_t v;
    memcpy(&v, h->data, sizeof(v));
    return v;
}

static bool chain_restore_disk_pos_map_init(
    struct chain_restore_disk_pos_map *m,
    size_t expected)
{
    size_t cap = 4096;
    while (cap < expected * 2)
        cap *= 2;
    m->entries = zcl_calloc(cap, sizeof(*m->entries),
                            "chain_restore/disk_pos_map");
    if (!m->entries)
        return false;
    m->capacity = cap;
    m->size = 0;
    return true;
}

static void chain_restore_disk_pos_map_free(
    struct chain_restore_disk_pos_map *m)
{
    if (!m)
        return;
    free(m->entries);
    m->entries = NULL;
    m->capacity = 0;
    m->size = 0;
}

static bool chain_restore_disk_pos_map_put(
    struct chain_restore_disk_pos_map *m,
    const struct uint256 *hash,
    int file,
    unsigned int pos)
{
    if (!m || !m->entries || m->capacity == 0)
        return false;
    size_t idx = chain_restore_hash_key(hash) & (m->capacity - 1);
    for (size_t i = 0; i < m->capacity; i++) {
        size_t slot = (idx + i) & (m->capacity - 1);
        struct chain_restore_disk_pos_entry *e = &m->entries[slot];
        if (!e->occupied) {
            e->hash = *hash;
            e->file = file;
            e->pos = pos;
            e->occupied = true;
            m->size++;
            return true;
        }
        if (uint256_eq(&e->hash, hash)) {
            e->file = file;
            e->pos = pos;
            return true;
        }
    }
    return false;
}

static const struct chain_restore_disk_pos_entry *
chain_restore_disk_pos_map_find(
    const struct chain_restore_disk_pos_map *m,
    const struct uint256 *hash)
{
    if (!m || !m->entries || m->capacity == 0)
        return NULL;
    size_t idx = chain_restore_hash_key(hash) & (m->capacity - 1);
    for (size_t i = 0; i < m->capacity; i++) {
        size_t slot = (idx + i) & (m->capacity - 1);
        const struct chain_restore_disk_pos_entry *e = &m->entries[slot];
        if (!e->occupied)
            return NULL;
        if (uint256_eq(&e->hash, hash))
            return e;
    }
    return NULL;
}

static bool chain_restore_scan_block_files(
    const char *datadir,
    struct chain_restore_disk_pos_map *map)
{
    if (!datadir || !datadir[0] || !map)
        return false;
    const struct chain_params *cp = chain_params_get();
    const unsigned char *magic = cp->pchMessageStart;
    int files = 0;
    int blocks = 0;

    for (int file_num = 0; file_num < 9999; file_num++) {
        char path[576];
        snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                 datadir, file_num);
        FILE *f = fopen(path, "rb");
        if (!f)
            break;
        files++;
        unsigned char prefix[8];
        while (fread(prefix, 1, sizeof(prefix), f) == sizeof(prefix)) {
            if (memcmp(prefix, magic, 4) != 0) {
                if (fseek(f, -7L, SEEK_CUR) != 0)
                    break;
                continue;
            }
            uint32_t block_size;
            memcpy(&block_size, prefix + 4, sizeof(block_size));
            if (block_size < 4 + 32 + 32 + 32 + 4 + 4 + 32 + 1 ||
                block_size > 4000000) {
                if (fseek(f, -7L, SEEK_CUR) != 0)
                    break;
                continue;
            }
            long data_pos = ftell(f);
            if (data_pos < 0)
                break;
            unsigned char hdr_buf[4 + 32 + 32 + 32 + 4 + 4 + 32 + 9 +
                                  MAX_SOLUTION_SIZE];
            size_t want = block_size < sizeof(hdr_buf)
                ? (size_t)block_size : sizeof(hdr_buf);
            size_t nread = fread(hdr_buf, 1, want, f);
            if (nread < 4 + 32 + 32 + 32 + 4 + 4 + 32 + 1)
                break;
            struct byte_stream s;
            stream_init_from_data(&s, hdr_buf, nread);
            struct block_header hdr;
            block_header_init(&hdr);
            bool ok = block_header_deserialize(&hdr, &s);
            stream_free(&s);
            if (ok) {
                struct uint256 hash;
                block_header_get_hash(&hdr, &hash);
                if (!chain_restore_disk_pos_map_put(map, &hash, file_num,
                                                    (unsigned int)data_pos)) {
                    fclose(f);
                    return false;
                }
                blocks++;
            }
            long next_pos = data_pos + (long)block_size;
            if (fseek(f, next_pos, SEEK_SET) != 0)
                break;
        }
        fclose(f);
    }

    printf("[chain-restore] scanned block files for canonical positions: "
           "files=%d blocks=%d indexed=%zu\n",
           files, blocks, map->size);
    return map->size > 0;
}

static bool chain_restore_read_header_at_pos(
    const char *datadir,
    int file,
    unsigned int pos,
    struct block_header *hdr)
{
    if (!datadir || !datadir[0] || file < 0 || pos == 0 || !hdr)
        return false;
    char path[576];
    snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", datadir, file);
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    unsigned char buf[4 + 32 + 32 + 32 + 4 + 4 + 32 + 9 + MAX_SOLUTION_SIZE];
    bool ok = false;
    if (fseek(f, (long)pos, SEEK_SET) == 0) {
        size_t nread = fread(buf, 1, sizeof(buf), f); // disk-io-lock: boot-local repair
        if (nread >= 4 + 32 + 32 + 32 + 4 + 4 + 32 + 1) {
            struct byte_stream s;
            stream_init_from_data(&s, buf, nread);
            block_header_init(hdr);
            ok = block_header_deserialize(hdr, &s);
            stream_free(&s);
        }
    }
    fclose(f);
    return ok;
}

int chain_restore_rebuild_active_chain_from_block_files(
    struct main_state *ms,
    struct block_index *tip,
    const char *datadir)
{
    if (!ms || !tip || !tip->phashBlock || !datadir || !datadir[0])
        return 0;

    struct chain_restore_disk_pos_map pos_map = {0};
    size_t expected = block_map_count(&ms->map_block_index);
    if (!chain_restore_disk_pos_map_init(&pos_map, expected ? expected : 4096))
        return 0;
    if (!chain_restore_scan_block_files(datadir, &pos_map)) {
        chain_restore_disk_pos_map_free(&pos_map);
        return 0;
    }

    struct active_chain *c = &ms->chain_active;
    struct uint256 want = *tip->phashBlock;
    struct block_index *child = NULL;
    int populated = 0;
    int repaired = 0;

    /* Same O(chain) witness as _from_disk (and its FULL block-file scan above,
     * chain_restore_scan_block_files, is itself O(all blocks on disk)): this
     * variant also walks tip->genesis, bounded by tip->nHeight+1, never a delta.
     * Shares the counter so the total names the boot's rebuild. Reached on the
     * SAME unclean-warm-restart path documented on _from_disk's counter above —
     * not cold seeds only. */
    atomic_uint_least64_t *scan_ctr =
        boot_scan_counter("chain_restore.disk_rebuild_rows");
    for (int h = tip->nHeight; h >= 0; h--) {
        boot_scan_bump(scan_ctr);
        const struct chain_restore_disk_pos_entry *pos =
            chain_restore_disk_pos_map_find(&pos_map, &want);
        if (!pos)
            break;
        struct block_header hdr;
        if (!chain_restore_read_header_at_pos(datadir, pos->file, pos->pos,
                                              &hdr))
            break;
        struct uint256 disk_hash;
        block_header_get_hash(&hdr, &disk_hash);
        if (!uint256_eq(&disk_hash, &want))
            break;
        struct block_index *cur =
            block_map_find(&ms->map_block_index, &want);
        if (!cur)
            break;

        cur->nHeight = h;
        cur->nFile = pos->file;
        cur->nDataPos = pos->pos;
        cur->nStatus |= BLOCK_HAVE_DATA;
        cur->nVersion = hdr.nVersion;
        cur->hashMerkleRoot = hdr.hashMerkleRoot;
        cur->hashFinalSaplingRoot = hdr.hashFinalSaplingRoot;
        cur->nTime = hdr.nTime;
        cur->nBits = hdr.nBits;
        cur->nNonce = hdr.nNonce;
        cur->pskip = NULL;
        cur->pprev = NULL;
        if (child) {
            child->pprev = cur;
            block_index_build_skip(child);
        }
        chain_restore_disk_store_slot(c, h, cur);
        populated++;
        repaired++;
        child = cur;
        want = hdr.hashPrevBlock;
    }

    if (child)
        child->pprev = NULL;
    chain_restore_disk_pos_map_free(&pos_map);
    printf("[chain-restore] block-file ancestry rebuilt active chain: "
           "tip_h=%d populated=%d repaired=%d\n",
           tip->nHeight, populated, repaired);
    return populated;
}
