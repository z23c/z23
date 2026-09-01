/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast wallet block scanner. Two-pass design:
 *
 * Pass 1 — Raw byte scan (no deserialization):
 *   mmap each block file and scan for P2PKH (76a914) / P2SH (a914)
 *   script patterns. Extract the 20-byte hash, check against hash table.
 *   Record file offsets of blocks that contain wallet matches.
 *   Speed: memory bandwidth limited (~10 GB/s on modern CPUs).
 *
 * Pass 2 — Selective deserialization:
 *   Only deserialize blocks identified in pass 1.
 *   Full tx parsing for correct UTXO create/spend tracking.
 *
 * Result: skips 99.9%+ of block deserialization. */

#include "platform/time_compat.h"
#include "platform/read_mapping.h"
#include "views/format_helpers.h"
#include "controllers/wallet_scan.h"
#include "controllers/sync_controller.h"
#include "services/wallet_scan_service.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "validation/chainstate.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "core/serialize.h"
#include "util/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include "controllers/scan_util.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

/* --- Pass 1: Raw byte pattern scan --- */

/* Scan context for parallel file scanning */
struct file_scan_result {
    bool has_match;
};

/* Scan a single mmap'd block file for P2PKH/P2SH patterns
 * matching our address hash table. */
static bool scan_file_raw(const uint8_t *data, size_t size,
                           const struct addr_ht *ht)
{
    /* Scan for P2PKH: 76 a9 14 [20 bytes] 88 ac (25 bytes total)
     * Scan for P2SH:  a9 14 [20 bytes] 87      (23 bytes total) */
    for (size_t i = 0; i + 25 <= size; i++) {
        /* P2PKH check */
        if (data[i] == 0x76 && data[i + 1] == 0xa9 &&
            data[i + 2] == 0x14 &&
            data[i + 23] == 0x88 && data[i + 24] == 0xac) {
            if (aht_has(ht, data + i + 3))
                return true;
        }
        /* P2SH check */
        if (data[i] == 0xa9 && data[i + 1] == 0x14 &&
            i + 23 <= size && data[i + 22] == 0x87) {
            if (aht_has(ht, data + i + 2))
                return true;
        }
    }
    return false;
}

/* Parallel file scanner thread argument */
struct scan_thread_arg {
    const char *datadir;
    int file_num;
    const struct addr_ht *ht;
    bool result;
};

static void *scan_file_thread(void *arg)
{
    struct scan_thread_arg *a = (struct scan_thread_arg *)arg;
    char path[512];
    int path_len = snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                            a->datadir, a->file_num);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        a->result = false;
        LOG_NULL("wallet_scan", "path too long for blk%05d.dat",
                 a->file_num);
    }
    int flags = O_RDONLY;
#ifdef O_BINARY
    flags |= O_BINARY;
#endif
    int fd = open(path, flags);
    if (fd < 0) { a->result = false; LOG_NULL("wallet_scan", "open failed for blk%05d.dat", a->file_num); }
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); a->result = false; LOG_NULL("wallet_scan", "fstat failed for blk%05d.dat", a->file_num); }
    if (st.st_size <= 0 || (uintmax_t)st.st_size > (uintmax_t)SIZE_MAX) {
        close(fd);
        a->result = false;
        LOG_NULL("wallet_scan", "invalid size for blk%05d.dat",
                 a->file_num);
    }
    size_t sz = (size_t)st.st_size;
    struct platform_read_mapping mapping;
    platform_read_mapping_init(&mapping);
    if (!platform_read_mapping_open(&mapping, fd, sz)) {
        close(fd);
        a->result = false;
        LOG_NULL("wallet_scan", "mapping failed for blk%05d.dat (size=%zu)",
                 a->file_num, sz);
    }
    platform_read_mapping_advise_sequential(&mapping);

    a->result = scan_file_raw(mapping.data, mapping.size, a->ht);

    platform_read_mapping_close(&mapping);
    close(fd);
    return NULL;
}

/* --- OS-S2 #4: Pass-1 file-match cache -----------------------------------
 * Pass-1 (raw byte scan of every blk*.dat) is the dominant wallet-scan cost.
 * Pass-2 REBUILDS the wallet tables from the full [0,tip] range (DELETE +
 * re-insert), so the range can NOT be truncated without losing funds. Instead
 * we cache each file's match bit keyed on (keyset fingerprint, tip height,
 * per-file size): a warm boot re-reads only files that grew/changed since the
 * last scan and reuses cached bits for the rest, turning Pass-1's disk reads
 * O(delta) while Pass-2 stays a full, correctness-preserving rebuild. */
#define WSCAN_FILECACHE_KEY   "wallet_scan_pass1_filecache"
#define WSCAN_FILECACHE_MAGIC 0x57534331u   /* 'WSC1' */
#define WSCAN_FILECACHE_VER   1u
#define WSCAN_MAX_FILES       200

struct wscan_filecache {
    uint32_t magic;
    uint32_t version;
    uint64_t keyset_fp;
    int32_t  tip_height;
    int32_t  num_files;
    uint64_t sizes[WSCAN_MAX_FILES];
    uint8_t  match[WSCAN_MAX_FILES];
};

/* FNV-1a fold over every live key/script id + counts. Any keyset change
 * (import/remove) flips the fingerprint and invalidates every cached bit,
 * because a file with no match under the old keys may match new keys. */
uint64_t wallet_scan_keyset_fp(const struct wallet *w)
{
    uint64_t fp = 1469598103934665603ULL;
    const uint64_t prime = 1099511628211ULL;
    for (size_t i = 0; i < w->keystore.num_keys; i++) {
        if (!w->keystore.keys[i].used) continue;
        const uint8_t *id = w->keystore.keys[i].keyid.id.data;
        for (int b = 0; b < 20; b++) { fp ^= id[b]; fp *= prime; }
    }
    for (size_t i = 0; i < w->keystore.num_scripts; i++) {
        if (!w->keystore.scripts[i].used) continue;
        const uint8_t *id = w->keystore.scripts[i].script_id.data;
        for (int b = 0; b < 20; b++) { fp ^= id[b]; fp *= prime; }
    }
    fp ^= (uint64_t)w->keystore.num_keys << 32;
    fp ^= (uint64_t)w->keystore.num_scripts;
    return fp;
}

bool wallet_scan_cache_valid(uint64_t cached_fp, uint64_t cur_fp,
                             int cached_tip, int cur_tip)
{
    return cached_fp == cur_fp && cur_tip >= cached_tip;
}

/* True iff `c` is a usable cache for this keyset+tip. A tip LOWER than the
 * cached one signals a reorg rewind — invalidate everything. Per-file size
 * checks (below) catch the far-more-common file-grew case. */
static bool wscan_cache_usable(const struct wscan_filecache *c,
                               uint64_t keyset_fp, int tip_height)
{
    return c->magic == WSCAN_FILECACHE_MAGIC &&
           c->version == WSCAN_FILECACHE_VER &&
           wallet_scan_cache_valid(c->keyset_fp, keyset_fp,
                                   c->tip_height, tip_height);
}

/* --- Main entry point --- */

int wallet_scan_blocks(struct node_db *ndb,
                       const struct active_chain *chain,
                       const struct wallet *w,
                       const char *datadir,
                       int start_height,
                       int end_height)
{
    if (!ndb || !ndb->open || !chain || !w || !datadir)
        LOG_ERR("wallet_scan", "scan_blocks: invalid args (ndb=%p chain=%p w=%p datadir=%p)",
                (void *)ndb, (void *)chain, (void *)w, (void *)datadir);

    /* blk files live under GetDataDir(true) — the NET-SPECIFIC datadir
     * (<base>/regtest on regtest/testnet; ==base on mainnet, same
     * convention as reducer_ingest_service.c body persist). Boot/rescan
     * callers pass the BASE datadir, so on a subdir net the file glob
     * below finds 0 files and the wallet comes up believing it has no
     * UTXOs. Resolve the canonical dir; byte-identical on mainnet. */
    char net_dir[2048];
    GetDataDir(true, net_dir, sizeof(net_dir));
    if (net_dir[0])
        datadir = net_dir;

    /* range fast-path. Empty range = nothing to do. */
    if (start_height > end_height) {
        printf("wallet_scan: range empty (start=%d > end=%d), "
               "replacing with empty result\n", start_height, end_height);
        return wallet_scan_pass2_execute(ndb, chain, datadir,
                                         start_height, end_height,
                                         NULL, NULL, 0, NULL, NULL);
    }

    struct timespec ts_start, ts_p1;
    platform_time_monotonic_timespec(&ts_start);

    /* Build address hash table */
    struct addr_ht aht;
    aht_init(&aht);
    for (size_t i = 0; i < w->keystore.num_keys; i++)
        if (w->keystore.keys[i].used)
            aht_insert(&aht, w->keystore.keys[i].keyid.id.data);
    for (size_t i = 0; i < w->keystore.num_scripts; i++)
        if (w->keystore.scripts[i].used)
            aht_insert(&aht, w->keystore.scripts[i].script_id.data);

    printf("wallet_scan: %d address hashes loaded\n", aht.count);
    fflush(stdout);

    /* zero-keys fast-path. Without any keys to
     * match, the parallel raw scan would read every block file
     * looking for hashes that aren't in the set — minutes of
     * pointless disk I/O. */
    if (aht.count == 0) {
        printf("wallet_scan: no wallet keys, skipping block scan\n");
        int empty_result = wallet_scan_pass2_execute(
            ndb, chain, datadir, start_height, end_height,
            &aht, NULL, 0, NULL, NULL);
        aht_free(&aht);
        return empty_result;
    }

    /* Determine which block files exist + capture their current sizes. */
    int num_files = 0;
    uint64_t cur_sizes[WSCAN_MAX_FILES];
    for (int f = 0; f < WSCAN_MAX_FILES; f++) {
        char path[2080];
        int written = snprintf(path, sizeof(path),
                               "%s/blocks/blk%05d.dat", datadir, f);
        if (written < 0 || (size_t)written >= sizeof(path))
            break;
        struct stat fst;
        if (stat(path, &fst) != 0 || !S_ISREG(fst.st_mode)) break;
        cur_sizes[f] = (uint64_t)fst.st_size;
        num_files = f + 1;
    }
    printf("wallet_scan: %d block files to scan\n", num_files);
    fflush(stdout);

    /* OS-S2 #4: load the Pass-1 file-match cache; decide per file whether the
     * cached bit can be reused (same keyset, tip not lower, size unchanged) or
     * the file must be re-scanned. */
    uint64_t keyset_fp = wallet_scan_keyset_fp(w);
    int tip_height = active_chain_height(chain);
    struct wscan_filecache cache;
    memset(&cache, 0, sizeof(cache));
    bool cache_ok = false;
    if (ndb->open) {
        size_t got = 0;
        if (node_db_state_get(ndb, WSCAN_FILECACHE_KEY, &cache, sizeof(cache),
                              &got) && got == sizeof(cache))
            cache_ok = wscan_cache_usable(&cache, keyset_fp, tip_height);
    }

    /* ========== PASS 1: Parallel raw byte scan (delta files only) ======= */
    printf("wallet_scan: pass 1 — parallel raw byte scan...\n");
    fflush(stdout);

    /* Launch threads — up to 8 at a time */
    bool *file_has_match = zcl_calloc((size_t)num_files, sizeof(bool), "wallet scan file match");
    bool *need_scan = zcl_calloc((size_t)num_files, sizeof(bool), "wallet scan need");
    if (!file_has_match || !need_scan) {
        /* zcl_calloc already logged the OOM; release the address hash table
         * and fail the scan rather than dereferencing NULL at the join loop. */
        aht_free(&aht);
        free(file_has_match);
        free(need_scan);
        return -1; /* raw-return-ok:zcl_calloc-logged */
    }
    int reused = 0;
    for (int f = 0; f < num_files; f++) {
        bool can_reuse = cache_ok && f < cache.num_files &&
                         cache.sizes[f] == cur_sizes[f];
        if (can_reuse) {
            file_has_match[f] = (cache.match[f] != 0);
            reused++;
        } else {
            need_scan[f] = true;
        }
    }
    printf("wallet_scan: pass 1 — reusing %d/%d cached file results, "
           "scanning %d\n", reused, num_files, num_files - reused);
    fflush(stdout);

    int batch = 8;

    for (int base = 0; base < num_files; base += batch) {
        int n = num_files - base;
        if (n > batch) n = batch;

        struct scan_thread_arg args[8];
        pthread_t threads[8];
        bool launched[8] = { false };

        for (int i = 0; i < n; i++) {
            if (!need_scan[base + i])
                continue;
            args[i].datadir = datadir;
            args[i].file_num = base + i;
            args[i].ht = &aht;
            args[i].result = false;
            /* raw-pthread-ok: short-burst-joined-immediately */
            if (pthread_create(&threads[i], NULL,
                               scan_file_thread, &args[i]) != 0) {
                LOG_WARN("wallet_scan", "wallet_scan: failed to start pass-1 scan thread");
                for (int j = 0; j < n; j++)
                    if (launched[j]) pthread_join(threads[j], NULL);
                aht_free(&aht);
                free(file_has_match);
                free(need_scan);
                return -1; // raw-return-ok:logged-above
            }
            launched[i] = true;
        }
        for (int i = 0; i < n; i++) {
            if (!launched[i])
                continue;
            pthread_join(threads[i], NULL);
            file_has_match[base + i] = args[i].result;
        }
    }

    /* Persist the refreshed cache for the next boot. */
    if (ndb->open) {
        struct wscan_filecache nc;
        memset(&nc, 0, sizeof(nc));
        nc.magic = WSCAN_FILECACHE_MAGIC;
        nc.version = WSCAN_FILECACHE_VER;
        nc.keyset_fp = keyset_fp;
        nc.tip_height = tip_height;
        nc.num_files = num_files;
        for (int f = 0; f < num_files && f < WSCAN_MAX_FILES; f++) {
            nc.sizes[f] = cur_sizes[f];
            nc.match[f] = file_has_match[f] ? 1u : 0u;
        }
        if (!node_db_state_set(ndb, WSCAN_FILECACHE_KEY, &nc, sizeof(nc)))
            LOG_WARN("wallet_scan", "wallet_scan: pass-1 filecache persist failed");
    }
    free(need_scan);

    platform_time_monotonic_timespec(&ts_p1);
    double p1_ms = (double)(ts_p1.tv_sec - ts_start.tv_sec) * 1000.0 +
                   (double)(ts_p1.tv_nsec - ts_start.tv_nsec) / 1e6;

    int matched_files = 0;
    for (int i = 0; i < num_files; i++)
        if (file_has_match[i]) matched_files++;

    printf("wallet_scan: pass 1 done in %.1f ms — %d/%d files contain wallet data\n",
           p1_ms, matched_files, num_files);
    fflush(stdout);

    if (matched_files == 0) {
        printf("wallet_scan: no wallet transactions found\n");
    }

    /* ========== PASS 2: Selective block deserialization ========== */
    printf("wallet_scan: pass 2 — deserializing blocks in %d matched files...\n",
           matched_files);
    fflush(stdout);

    /* Pass 2 — the selective-deserialize loop, balance compute, and the
     * SQLite result-write transaction — is a Service. The Controller owns the
     * address hash table and the Pass-1 match array; it hands them to the
     * Service by const reference and frees them afterward. */
    int found = wallet_scan_pass2_execute(ndb, chain, datadir,
                                          start_height, end_height,
                                          &aht, file_has_match, matched_files,
                                          &ts_start, &ts_p1);

    /* Cleanup */
    aht_free(&aht);
    free(file_has_match);

    return found;
}
