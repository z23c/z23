/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Block-file scan: parse blk*.dat, mark BLOCK_HAVE_DATA, propagate
 * nChainTx/nChainWork, and recompute the block index from genesis.
 *
 * Part of the boot composition root (config/src/), extracted from
 * boot_index.c. Owns the on-disk block-file scan cluster: it parses
 * ZClassic block headers out of the raw blk*.dat files (in parallel),
 * creates missing block_index entries, marks BLOCK_HAVE_DATA, resolves
 * orphan pprev links from disk, and propagates cumulative chain metadata
 * so find_most_work_chain can pick the best tip. It owns its own scan
 * structs (boot_scan_*) and the block-file magic / header-read-size
 * macros; none are shared with the reindex/rebuild core in boot_index.c.
 *
 * Consensus-adjacent: touches the block-index load surface. Moved
 * byte-identically from boot_index.c — no logic change. */

#include "platform/time_compat.h"
#include "platform/file_advice.h"
#include "config/boot_internal.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "validation/chainstate.h"
#include "primitives/block.h"
#include "core/serialize.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

/* ZClassic mainnet block file magic (little-endian 0x6427e924) */
#define ZCL_BLOCK_MAGIC 0x6427e924

/* Max bytes to read from a block for header parsing + tx count.
 * ZClassic header = 140 fixed + ~1347 equihash solution = ~1487 bytes.
 * 1600 gives margin for the compact_size tx count after the header. */
#define BLOCK_HEADER_READ_SIZE 1600

/* ── scan_block_files_mark_data helpers ──────────────────────── */

struct boot_scan_block_meta {
    struct uint256 hash;
    struct uint256 hashPrevBlock;
    struct uint256 hashMerkleRoot;
    struct uint256 hashFinalSaplingRoot;
    struct uint256 nNonce;
    int32_t nVersion;
    uint32_t nTime;
    uint32_t nBits;
    unsigned int nTx;
    unsigned int nDataPos;
};

struct boot_scan_file_result {
    char path[576];
    int file_idx;
    long file_size;
    struct boot_scan_block_meta *blocks;
    size_t count;
    size_t cap;
    int skipped;
    int corrupt;
    bool ok;
};

struct boot_scan_apply_counts {
    int marked;
    int created;
    int header_fixed;
};

/* Create a block_index entry directly from a parsed header.
 * Skips PoW/equihash validation here; local disk blocks are checked
 * later against the SHA3 UTXO checkpoint. This is 1000x faster than
 * accept_block_header (no equihash solve check). On a map-insert
 * collision the fresh node is freed and the existing map entry is
 * returned, so the caller must not assume it owns the result. */
static struct block_index *create_block_index_fast(
    struct main_state *ms, const struct boot_scan_block_meta *meta)
{
    struct block_index *pindex = zcl_calloc(1, sizeof(struct block_index), "boot.index.block_index");
    if (!pindex) return NULL;
    block_index_init(pindex);

    pindex->nVersion = meta->nVersion;
    pindex->hashMerkleRoot = meta->hashMerkleRoot;
    pindex->hashFinalSaplingRoot = meta->hashFinalSaplingRoot;
    pindex->nTime = meta->nTime;
    pindex->nBits = meta->nBits;
    pindex->nNonce = meta->nNonce;
    /* Don't store solution in block_index — saves 1.3KB per entry
     * (4GB total for 3M entries). Read from disk when needed. */
    pindex->nSolution = NULL;
    pindex->nSolutionSize = 0;

    /* Option A: stable per-node hash storage (never freed by bucket
     * realloc), seeded before publishing pindex into the map. */
    pindex->hashBlock = meta->hash;
    pindex->phashBlock = &pindex->hashBlock;

    if (!block_map_insert(&ms->map_block_index, &meta->hash, pindex)) {
        free(pindex);
        return block_map_find(&ms->map_block_index, &meta->hash);
    }

    /* Link to previous block */
    struct block_index *pprev = block_map_find(
        &ms->map_block_index, &meta->hashPrevBlock);
    if (pprev) {
        pindex->pprev = pprev;
        pindex->nHeight = pprev->nHeight + 1;
        block_index_build_skip(pindex);
        struct arith_uint256 proof = GetBlockProof(pindex);
        arith_uint256_add(&pindex->nChainWork,
                          &pprev->nChainWork, &proof);
    } else {
        /* Genesis or orphan — height determined on retry pass */
        pindex->nHeight = 0;
        pindex->nChainWork = GetBlockProof(pindex);
    }

    pindex->nStatus = BLOCK_VALID_TREE;
    return pindex;
}

/* recompute_index_from_genesis and resolve_orphan_pprev_from_disk —
 * the genesis-rooted ancestry repair passes this scan runs after every
 * block is in the map — live in config/src/boot_block_index_ancestry.c
 * (declared in config/boot_internal.h). */

static uint32_t scan_read_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static long scan_find_next_magic(const uint8_t *data, long start, long size)
{
    const uint8_t m0 = (uint8_t)(ZCL_BLOCK_MAGIC & 0xFF);
    const uint8_t m1 = (uint8_t)((ZCL_BLOCK_MAGIC >> 8) & 0xFF);
    const uint8_t m2 = (uint8_t)((ZCL_BLOCK_MAGIC >> 16) & 0xFF);
    const uint8_t m3 = (uint8_t)((ZCL_BLOCK_MAGIC >> 24) & 0xFF);

    for (long pos = start; pos + 8 + 140 <= size; pos++) {
        if (data[pos] == m0 && data[pos + 1] == m1 &&
            data[pos + 2] == m2 && data[pos + 3] == m3)
            return pos;
    }
    return -1;
}

static bool scan_file_append_meta(struct boot_scan_file_result *r,
                                  const struct boot_scan_block_meta *meta)
{
    if (r->count == r->cap) {
        size_t new_cap = r->cap ? r->cap * 2 : 4096;
        struct boot_scan_block_meta *tmp = zcl_realloc(
            r->blocks, new_cap * sizeof(*r->blocks),
            "boot.index.scan_file_blocks");
        if (!tmp)
            return false;
        r->blocks = tmp;
        r->cap = new_cap;
    }
    r->blocks[r->count++] = *meta;
    return true;
}

static void scan_parse_one_file(struct boot_scan_file_result *r)
{
    r->ok = false;
    int fd = open(r->path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "scan: cannot open %s: %s\n", r->path, strerror(errno));
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        r->ok = true;
        return;
    }
    r->file_size = (long)st.st_size;

    /* This scan walks the whole blk*.dat front-to-back (the `pos` cursor
     * below only ever advances) during boot index rebuild / import — tell
     * the kernel to read ahead aggressively instead of caching for random
     * access. Advisory only: a denied/unsupported call just forgoes the
     * readahead hint, never fails the scan. */
    platform_file_advise_sequential(fd, st.st_size);

    uint8_t *data = mmap(NULL, (size_t)st.st_size, PROT_READ,
                         MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) {
        fprintf(stderr, "scan: mmap failed for %s: %s\n",
                r->path, strerror(errno));
        return;
    }

    bool complete = true;
    int consec_errors = 0;
    long pos = 0;
    while (pos + 8 + 140 <= r->file_size) {
        uint32_t magic = scan_read_u32_le(data + pos);
        uint32_t blk_size = scan_read_u32_le(data + pos + 4);

        if (magic != ZCL_BLOCK_MAGIC) {
            long next = scan_find_next_magic(data, pos + 1, r->file_size);
            if (next < 0)
                break;
            pos = next;
            r->skipped++;
            continue;
        }

        if (blk_size < 140 || blk_size > 2000000 ||
            pos + 8 + (long)blk_size > r->file_size) {
            pos += 8;
            continue;
        }

        size_t read_sz = (blk_size < BLOCK_HEADER_READ_SIZE)
                             ? blk_size
                             : BLOCK_HEADER_READ_SIZE;
        struct block_header bhdr;
        block_header_init(&bhdr);
        struct byte_stream bs;
        stream_init_from_data(&bs, data + pos + 8, read_sz);
        if (!block_header_deserialize(&bhdr, &bs)) {
            consec_errors++;
            r->corrupt++;
            if (consec_errors > 20) {
                fprintf(stderr, "scan: %d consecutive corrupt blocks in "
                        "blk%05d.dat at pos %ld — aborting file\n",
                        consec_errors, r->file_idx, pos);
                break;
            }
            pos += 8 + (long)blk_size;
            continue;
        }
        consec_errors = 0;

        uint64_t num_tx = 0;
        if (!stream_read_compact_size(&bs, &num_tx) || num_tx == 0)
            num_tx = 1;
        if (num_tx > 100000) {
            fprintf(stderr, "scan: suspicious num_tx=%llu at file %d pos %ld, "
                    "clamping to 1\n", (unsigned long long)num_tx,
                    r->file_idx, pos);
            num_tx = 1;
        }

        struct boot_scan_block_meta meta;
        memset(&meta, 0, sizeof(meta));
        block_header_get_hash(&bhdr, &meta.hash);
        meta.hashPrevBlock = bhdr.hashPrevBlock;
        meta.hashMerkleRoot = bhdr.hashMerkleRoot;
        meta.hashFinalSaplingRoot = bhdr.hashFinalSaplingRoot;
        meta.nNonce = bhdr.nNonce;
        meta.nVersion = bhdr.nVersion;
        meta.nTime = bhdr.nTime;
        meta.nBits = bhdr.nBits;
        meta.nTx = (unsigned int)num_tx;
        meta.nDataPos = (unsigned int)(pos + 8);
        if (!scan_file_append_meta(r, &meta)) {
            fprintf(stderr, "scan: out of memory while parsing %s at pos %ld\n",
                    r->path, pos);
            complete = false;
            break;
        }

        pos += 8 + (long)blk_size;
    }

    munmap(data, (size_t)st.st_size);
    r->ok = complete;
}

struct boot_scan_parallel_ctx {
    struct boot_scan_file_result *files;
    int nfiles;
    _Atomic int next;
};

static void *scan_parse_worker(void *arg)
{
    struct boot_scan_parallel_ctx *ctx = arg;
    for (;;) {
        int i = atomic_fetch_add(&ctx->next, 1);
        if (i >= ctx->nfiles)
            break;
        scan_parse_one_file(&ctx->files[i]);
    }
    return NULL;
}

static int scan_worker_count(int nfiles)
{
    const char *override = getenv("ZCL_BLOCK_SCAN_WORKERS");
    if (override && override[0]) {
        char *end = NULL;
        long requested = strtol(override, &end, 10);
        if (end && *end == '\0' && requested > 0) {
            if (requested > nfiles) requested = nfiles;
            if (requested > 64) requested = 64;
            if (requested < 1) requested = 1;
            return (int)requested;
        }
        fprintf(stderr, "scan: ignoring invalid ZCL_BLOCK_SCAN_WORKERS=%s\n",
                override);
    }

    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int n = cpus > 0 ? (int)cpus : 1;
    if (n > nfiles) n = nfiles;
    if (n > 16) n = 16;
    if (n < 1) n = 1;
    return n;
}

static int scan_parse_files_parallel(struct boot_scan_file_result *files,
                                     int nfiles)
{
    if (nfiles <= 0)
        return 0;

    int workers = scan_worker_count(nfiles);
    printf("  parallel block-file parse: %d files, %d workers\n",
           nfiles, workers);
    if (workers == 1) {
        for (int i = 0; i < nfiles; i++)
            scan_parse_one_file(&files[i]);
        return workers;
    }

    pthread_t *threads = zcl_calloc((size_t)workers, sizeof(*threads),
                                    "boot.index.scan_threads");
    if (!threads) {
        for (int i = 0; i < nfiles; i++)
            scan_parse_one_file(&files[i]);
        return 1;
    }

    struct boot_scan_parallel_ctx ctx = {
        .files = files,
        .nfiles = nfiles,
        .next = 0,
    };
    int started = 0;
    for (int i = 0; i < workers; i++) {
        if (thread_registry_spawn("zcl_blk_scan", scan_parse_worker,
                                     &ctx, &threads[started]) == 0)
            started++;
    }
    if (started == 0) {
        free(threads);
        for (int i = 0; i < nfiles; i++)
            scan_parse_one_file(&files[i]);
        return 1;
    }
    for (int i = 0; i < started; i++)
        pthread_join(threads[i], NULL);
    free(threads);
    return started;
}

static struct boot_scan_apply_counts scan_apply_one_file(
    struct main_state *ms,
    const struct boot_scan_file_result *r,
    const struct chain_params *params)
{
    struct boot_scan_apply_counts counts = {0};
    for (size_t i = 0; i < r->count; i++) {
        const struct boot_scan_block_meta *meta = &r->blocks[i];
        struct block_index *bi = block_map_find(&ms->map_block_index,
                                                &meta->hash);

        if (!bi && params) {
            bi = create_block_index_fast(ms, meta);
            if (bi)
                counts.created++;
        }

        if (!bi)
            continue;

        if (bi->nVersion == 0 || bi->nTime == 0 || bi->nBits == 0) {
            bi->nVersion = meta->nVersion;
            bi->hashMerkleRoot = meta->hashMerkleRoot;
            bi->hashFinalSaplingRoot = meta->hashFinalSaplingRoot;
            bi->nTime = meta->nTime;
            bi->nBits = meta->nBits;
            bi->nNonce = meta->nNonce;
            counts.header_fixed++;
        }

        if (!bi->pprev && bi->nHeight == 0 && params) {
            struct block_index *pprev = block_map_find(
                &ms->map_block_index, &meta->hashPrevBlock);
            if (pprev) {
                bi->pprev = pprev;
                bi->nHeight = pprev->nHeight + 1;
                block_index_build_skip(bi);
                struct arith_uint256 proof = GetBlockProof(bi);
                arith_uint256_add(&bi->nChainWork,
                                  &pprev->nChainWork, &proof);
            }
        }

        if (!(bi->nStatus & BLOCK_HAVE_DATA)) {
            bi->nStatus |= BLOCK_HAVE_DATA;
            bi->nStatus = (bi->nStatus & ~(unsigned)BLOCK_VALID_MASK) |
                           BLOCK_VALID_TRANSACTIONS;
            bi->nFile = r->file_idx;
            bi->nDataPos = meta->nDataPos;
            if (bi->nTx == 0)
                bi->nTx = meta->nTx;
            counts.marked++;
        } else {
            /* Duplicate record: keep the EARLIEST copy. Append/rewrite
             * frontiers advance upward through a blk file (a foreign writer
             * on a hardlinked file — e.g. a live zclassicd sharing the inode
             * — or our own appends), so the lowest-offset copy is the most
             * durable; last-copy-wins picked exactly the copy most likely to
             * be overwritten later (2026-08 producer-fold wedge: 314 stale
             * tail positions). A torn entry (nFile < 0) always takes the
             * fresh record. */
            if (bi->nFile != r->file_idx ||
                bi->nDataPos != meta->nDataPos) {
                if (bi->nFile < 0 || r->file_idx < bi->nFile ||
                    (r->file_idx == bi->nFile &&
                     meta->nDataPos < bi->nDataPos)) {
                    bi->nFile = r->file_idx;
                    bi->nDataPos = meta->nDataPos;
                }
            }
            if (bi->nTx == 0)
                bi->nTx = meta->nTx;
        }
    }
    return counts;
}

static void scan_free_file_results(struct boot_scan_file_result *files,
                                   int nfiles)
{
    for (int i = 0; i < nfiles; i++)
        free(files[i].blocks);
}

/* Scan block files on disk, parse proper ZClassic headers (with
 * equihash solution), create block_index entries if missing, set
 * nTx, mark BLOCK_HAVE_DATA, and propagate nChainTx so
 * find_most_work_chain can find the best tip.
 *
 * This is the critical bridge between file_service (downloads block files)
 * and reducer activation (needs BLOCK_HAVE_DATA + nChainTx > 0 to connect
 * blocks). Without this, downloaded blocks sit unused on disk while P2P
 * re-downloads them. */
int scan_block_files_mark_data(struct main_state *ms, const char *datadir,
                                const struct chain_params *params)
{
    if (!ms || !datadir) {
        fprintf(stderr, "scan_block_files_mark_data: NULL argument\n");
        return 0;
    }

    int marked = 0, created = 0;
    char path[576];
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    struct boot_scan_file_result files[257];
    int nfiles = 0;
    memset(files, 0, sizeof(files));

    /* Pass 1: parse all block files in parallel.
     * Don't break on first gap — blk00000.dat may be empty (0 bytes)
     * while blk00001.dat+ have data. Stop after 3 consecutive misses. */
    int consecutive_misses = 0;
    for (int file_idx = 0; file_idx < 256; file_idx++) {
        snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                 datadir, file_idx);
        struct stat st;
        if (stat(path, &st) != 0 || st.st_size == 0) {
            if (++consecutive_misses >= 3) break;
            continue;
        }
        consecutive_misses = 0;

        /* Hardlink tripwire: st_nlink > 1 means another path shares this
         * inode — potentially a live foreign writer (e.g. a zclassicd
         * oracle datadir hardlinked into this one) whose own append pointer
         * can overwrite records this scan is about to index. Positions in
         * the last blk file are provisional on such a layout. */
        if (st.st_nlink > 1)
            fprintf(stderr,  // obs-ok:hardlink-tripwire-boot-scan-foreign-writer-warning
                    "scan: %s has %lu hard links — shared blk file; "
                    "a foreign writer may invalidate indexed positions\n",
                    path, (unsigned long)st.st_nlink);

        struct boot_scan_file_result *r = &files[nfiles++];
        snprintf(r->path, sizeof(r->path), "%s", path);
        r->file_idx = file_idx;
    }

    /* Also scan blk_sync.dat when it exists.
     * File-service bootstrap does not always create it, so missing
     * sync spool should not look like a scan failure. */
    snprintf(path, sizeof(path), "%s/blocks/blk_sync.dat", datadir);
    struct stat sync_st;
    if (stat(path, &sync_st) == 0 && sync_st.st_size > 0) {
        struct boot_scan_file_result *r = &files[nfiles++];
        snprintf(r->path, sizeof(r->path), "%s", path);
        r->file_idx = 255;
    }

    int64_t parse_t0 = (int64_t)platform_time_wall_time_t();
    int scan_workers = scan_parse_files_parallel(files, nfiles);
    int64_t parse_elapsed = (int64_t)platform_time_wall_time_t() - parse_t0;

    int64_t apply_t0 = (int64_t)platform_time_wall_time_t();
    for (int i = 0; i < nfiles; i++) {
        struct boot_scan_file_result *r = &files[i];
        if (!r->ok) {
            fprintf(stderr, "scan: parse failed for %s; skipping partial "
                    "metadata\n", r->path);
            continue;
        }
        struct boot_scan_apply_counts c =
            scan_apply_one_file(ms, r, params);
        marked += c.marked + c.header_fixed;
        created += c.created;
        if (c.marked > 0 || c.created > 0 || c.header_fixed > 0) {
            printf("  %s: %d marked, %d created, %d headers fixed, "
                   "%d skipped (%ld MB)\n",
                   strrchr(r->path, '/') ? strrchr(r->path, '/') + 1 : r->path,
                   c.marked, c.created, c.header_fixed, r->skipped,
                   r->file_size / (1024 * 1024));
        }
    }

    /* Pass 2: retry for out-of-order blocks (prevblock now in map).
     * Block files from zclassicd are 99%+ in order, so pass 1 catches
     * nearly everything. Pass 2 picks up stragglers without re-reading
     * disk: the parsed metadata is deterministic and immutable. */
    if (created > 0 && params) {
        for (int retry = 0; retry < 3; retry++) {
            int prev_marked = marked;
            for (int i = 0; i < nfiles; i++) {
                if (!files[i].ok)
                    continue;
                struct boot_scan_apply_counts c =
                    scan_apply_one_file(ms, &files[i], params);
                marked += c.marked + c.header_fixed;
                created += c.created;
            }
            int delta = marked - prev_marked;
            if (delta == 0) break;
            printf("  Retry pass %d: %d additional blocks\n", retry + 1, delta);
        }
    }
    int64_t apply_elapsed = (int64_t)platform_time_wall_time_t() - apply_t0;

    /* Resolve orphan pprev links by reading hashPrevBlock from disk.
     * All blocks are now in the map — pprev lookup will succeed for
     * any block whose parent exists on disk. This fixes the case where
     * create_block_index_fast couldn't link pprev at insertion time
     * because the parent hadn't been scanned yet. */
    if (created > 0 && params) {
        size_t orphan_before = 0;
        { size_t ci = 0; struct block_index *cb;
          while (block_map_next(&ms->map_block_index, &ci, NULL, &cb))
              if (cb && !cb->pprev && cb->nHeight == 0 && cb->nFile >= 0)
                  orphan_before++;
        }
        printf("  orphan check: %zu entries with pprev==NULL, nHeight==0, nFile>=0\n",
               orphan_before);
        if (orphan_before > 0) {
            printf("  %zu orphan blocks — resolving pprev from disk...\n",
                   orphan_before);
            fflush(stdout);
            int resolved = resolve_orphan_pprev_from_disk(ms, datadir, params);
            printf("  pprev resolved for %d blocks from disk\n", resolved);
            fflush(stdout);
        }
    }

    scan_free_file_results(files, nfiles);

    if (marked > 0 && params)
        recompute_index_from_genesis(ms, params);

    /* Propagate nChainTx along the chain. This is REQUIRED for
     * find_most_work_chain to consider these blocks as candidates.
     * Collect all blocks with BLOCK_HAVE_DATA, sort by height,
     * compute nChainTx = pprev->nChainTx + nTx.
     * Multiple passes handle gaps (e.g., retry-created blocks
     * whose pprev was missing in earlier passes). */
    if (marked > 0) {
        size_t total = ms->map_block_index.size;
        struct block_index **sorted = zcl_malloc(total * sizeof(struct block_index *), "boot.index.sorted");
        if (sorted) {
            size_t n = 0, iter = 0;
            struct block_index *bi;
            while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
                /* Include ALL blocks with pprev or data — header-only blocks
                 * (no BLOCK_HAVE_DATA) can still propagate nChainTx through
                 * the chain, bridging gaps where block files are missing. */
                if (bi && (bi->pprev || (bi->nStatus & BLOCK_HAVE_DATA)))
                    sorted[n++] = bi;
            }

            qsort(sorted, n, sizeof(struct block_index *), block_index_cmp_height);

            int total_propagated = 0;
            for (int pass = 0; pass < 50; pass++) {
                int propagated = 0;
                for (size_t i = 0; i < n; i++) {
                    struct block_index *b = sorted[i];
                    if (b->nHeight == 0) {
                        if (b->nChainTx == 0) {
                            b->nChainTx = b->nTx > 0 ? b->nTx : 1;
                            propagated++;
                        }
                        /* Also set chain_work for h=0 blocks (genesis) */
                        if (arith_uint256_is_zero(&b->nChainWork)) {
                            b->nChainWork = GetBlockProof(b);
                            propagated++;
                        }
                    } else if (b->pprev && b->pprev->nChainTx > 0) {
                        unsigned int ntx = b->nTx > 0 ? b->nTx : 1;
                        unsigned int expected = b->pprev->nChainTx + ntx;
                        if (b->nChainTx != expected) {
                            b->nChainTx = expected;
                            propagated++;
                        }
                    } else if (b->pprev && b->pprev->nChainTx == 0) {
                        /* pprev hasn't been reached yet — force-propagate */
                        unsigned int ntx = b->pprev->nTx > 0 ? b->pprev->nTx : 1;
                        b->pprev->nChainTx = b->pprev->nHeight > 0 ?
                            (unsigned)(b->pprev->nHeight) : ntx;
                        unsigned int btx = b->nTx > 0 ? b->nTx : 1;
                        b->nChainTx = b->pprev->nChainTx + btx;
                        /* Also force chain_work if pprev has none */
                        if (arith_uint256_is_zero(&b->pprev->nChainWork)) {
                            b->pprev->nChainWork = GetBlockProof(b->pprev);
                            if (b->pprev->pprev &&
                                !arith_uint256_is_zero(&b->pprev->pprev->nChainWork))
                                arith_uint256_add(&b->pprev->nChainWork,
                                    &b->pprev->pprev->nChainWork,
                                    &b->pprev->nChainWork);
                        }
                        propagated += 2;
                    }
                    /* Also propagate nChainWork alongside nChainTx */
                    if (b->pprev && !arith_uint256_is_zero(&b->pprev->nChainWork) &&
                        arith_uint256_is_zero(&b->nChainWork)) {
                        struct arith_uint256 proof = GetBlockProof(b);
                        arith_uint256_add(&b->nChainWork,
                                          &b->pprev->nChainWork, &proof);
                        propagated++;
                    }
                }
                total_propagated += propagated;
                if (propagated == 0) break;
                if (pass == 49)
                    fprintf(stderr, "WARNING: nChainTx did not converge in "
                            "50 passes (%d blocks still pending) — possible "
                            "gap in block chain\n", propagated);
                if (pass < 3 || pass % 10 == 0)
                    printf("  nChainTx pass %d: +%d blocks\n",
                           pass + 1, propagated);
            }

            /* Find first gap in chain — diagnostic for pprev breaks */
            {
                struct block_index *genesis_bi = NULL;
                size_t gi = 0;
                struct block_index *gb;
                while (block_map_next(&ms->map_block_index, &gi, NULL, &gb))
                    if (gb && gb->nHeight == 0 && gb->nChainTx > 0) {
                        genesis_bi = gb; break;
                    }
                if (genesis_bi) {
                    /* Walk forward from genesis via the active chain */
                    int gap_h = -1;
                    struct block_index *walk = genesis_bi;
                    for (int h = 1; h < 1000 && gap_h < 0; h++) {
                        bool found_next = false;
                        size_t fi = 0;
                        struct block_index *fb;
                        while (block_map_next(&ms->map_block_index, &fi, NULL, &fb)) {
                            if (fb && fb->pprev == walk && fb->nHeight == h) {
                                walk = fb;
                                found_next = true;
                                break;
                            }
                        }
                        if (!found_next) {
                            /* Try finding ANY block at height h */
                            fi = 0;
                            struct block_index *alt = NULL;
                            while (block_map_next(&ms->map_block_index, &fi, NULL, &fb)) {
                                if (fb && fb->nHeight == h) { alt = fb; break; }
                            }
                            printf("  Chain gap at h=%d: pprev_child=%s "
                                   "alt_at_h=%s have_data=%d nTx=%u\n",
                                   h,
                                   found_next ? "yes" : "no",
                                   alt ? "yes" : "no",
                                   alt ? !!(alt->nStatus & BLOCK_HAVE_DATA) : 0,
                                   alt ? alt->nTx : 0);
                            gap_h = h;
                        }
                    }
                    if (gap_h < 0)
                        printf("  Chain contiguous from genesis to h=999+\n");
                }
            }

            /* Count blocks with HAVE_DATA but no nChainTx — these are
             * unreachable from genesis (orphans or broken pprev links) */
            int orphans = 0;
            int no_pprev = 0, pprev_no_data = 0, pprev_no_tx = 0;
            for (size_t i = 0; i < n; i++) {
                if (sorted[i]->nChainTx == 0 && sorted[i]->nHeight > 0) {
                    orphans++;
                    if (!sorted[i]->pprev) no_pprev++;
                    else if (!(sorted[i]->pprev->nStatus & BLOCK_HAVE_DATA))
                        pprev_no_data++;
                    else if (sorted[i]->pprev->nTx == 0)
                        pprev_no_tx++;
                }
            }
            /* Note: chain_work is NOT re-propagated here to avoid
             * overwriting correct values from P2P-synced blocks. */

            free(sorted);
            if (total_propagated > 0)
                printf("  nChainTx propagated for %d blocks",
                       total_propagated);
            if (orphans > 0)
                printf(" (%d orphan: %d no_pprev, %d pprev_no_data, %d pprev_no_tx)",
                       orphans, no_pprev, pprev_no_data, pprev_no_tx);
            if (total_propagated > 0 || orphans > 0)
                printf("\n");
        }
    }

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;

    /* Summary stats: how many index entries have BLOCK_HAVE_DATA vs total */
    size_t total_entries = 0, have_data_entries = 0;
    {
        size_t si = 0;
        struct block_index *sb;
        while (block_map_next(&ms->map_block_index, &si, NULL, &sb)) {
            if (!sb) continue;
            total_entries++;
            if (sb->nStatus & BLOCK_HAVE_DATA)
                have_data_entries++;
        }
    }

    printf("Block file scan: %d marked, %d created in %llds  "
           "[parse=%llds apply=%llds workers=%d index: %zu entries, "
           "%zu have data]\n",
           marked, created, (long long)elapsed,
           (long long)parse_elapsed, (long long)apply_elapsed,
           scan_workers,
           total_entries, have_data_entries);

    return marked;
}
