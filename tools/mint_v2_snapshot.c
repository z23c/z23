/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mint_v2_snapshot — write a VERSION-2 ZCLUTXO snapshot that embeds the
 * Sapling commitment-tree frontier at the seed height, so a FRESH node can
 * seed coins_kv AND install a verified Sapling tree WITHOUT the multi-GB
 * blocks/ directory.
 *
 * It reuses the node's own machinery (load_block_index_flat +
 * sapling_tree_rebuild) on a datadir that HAS blocks/ + block_index.bin:
 *
 *   1. progress_store_open(datadir)          — the coins_kv home.
 *   2. load_block_index_flat(datadir, &ms)   — in-memory block index map.
 *   3. install the active tip at the seed height + extend the window so
 *      active_chain_at(seed_h) resolves the PoW-proven block_index.
 *   4. node_db_open(<datadir>/node.db)        — node_state["sapling_tree"] home.
 *   5. clear any stale sapling_tree resume markers, then drive
 *      sapling_tree_rebuild(): it replays note commitments from Sapling
 *      activation up to the (capped) endpoint and VERIFIES the final root
 *      against hashFinalSaplingRoot at the seed height, persisting the
 *      serialized frontier into node_state["sapling_tree"].
 *   6. read that frontier blob back + write the v2 snapshot via the canonical
 *      coins_kv_snapshot_write with a Sapling-only shielded arg (UTXO records +
 *      [u32 len][frontier], format version 2).
 *
 * The seed height must be <= the durable coins-applied frontier
 * (coins_applied_height - 1) so the UTXO set and the frontier are coherent at
 * the SAME height. sapling_tree_rebuild already caps its endpoint to the
 * coins-applied frontier; we pass the requested height and let it cap.
 *
 * Usage:
 *   mint_v2_snapshot <datadir> <seed_height> <out_path>
 */

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>

#include <sqlite3.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "storage/snapshot_shielded.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/utxo_snapshot_loader.h"
#include "models/database.h"
#include "services/block_index_loader.h"
#include "controllers/sync_controller.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "chain/chainparams.h"
#include "crypto/sha256.h"
#include "util/clientversion.h"

/* Read the REAL hashFinalSaplingRoot from a block body on disk (node.db's
 * blocks.sapling_root is a zeroed projection artifact, so we cannot trust it).
 * Returns true and fills root32 on success. */
static bool read_body_sapling_root(const char *datadir, int file_num,
                                   uint32_t data_pos, uint8_t root32[32])
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", datadir, file_num);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || (off_t)data_pos >= st.st_size) {
        close(fd);
        return false;
    }
    void *mp = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mp == MAP_FAILED) return false;
    bool ok = false;
    struct block blk;
    block_init(&blk);
    struct byte_stream s;
    stream_init_from_data(&s, (uint8_t *)mp + data_pos,
                          (size_t)st.st_size - data_pos);
    if (block_deserialize(&blk, &s)) {
        memcpy(root32, blk.header.hashFinalSaplingRoot.data, 32);
        ok = true;
    }
    block_free(&blk);
    munmap(mp, (size_t)st.st_size);
    return ok;
}

/* Top up the in-memory block-index map by walking the CHILD chain FORWARD from
 * `start` (the flat block-index tip) up to height `to_h`, using node.db `blocks`
 * (the stale flat block_index.bin does not reach the live coins frontier).
 *
 * The contested wedge region makes node.db's stored `height` labels unreliable
 * (a row at stored height H may have a parent that is NOT the row at stored
 * H-1), so we follow prev_hash linkage instead: at each step find the child row
 * whose prev_hash == the current block's hash, insert it with pprev linked + the
 * REAL hashFinalSaplingRoot read from the body (node.db's is zeroed), and assign
 * a sequential height. Returns the count inserted, -1 on error. */
static long topup_forward_from_node_db(struct main_state *ms, struct node_db *ndb,
                                       const char *datadir,
                                       struct block_index *start, int to_h)
{
    if (!start || start->nHeight >= to_h) return 0;

    sqlite3_stmt *child = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT hash, file_num, data_pos, status, num_tx "
            "FROM blocks WHERE prev_hash = ? LIMIT 1",
            -1, &child, NULL) != SQLITE_OK) {
        fprintf(stderr, "topup: prepare failed: %s\n", sqlite3_errmsg(ndb->db));
        return -1;
    }

    long inserted = 0;
    struct block_index *cur = start;
    int next_h = start->nHeight + 1;
    while (next_h <= to_h) {
        sqlite3_reset(child);
        sqlite3_clear_bindings(child);
        sqlite3_bind_blob(child, 1, cur->hashBlock.data, 32, SQLITE_STATIC);
        if (sqlite3_step(child) != SQLITE_ROW) {  // raw-sql-ok:standalone-dev-tool
            fprintf(stderr, "topup: no child of h=%d (hash chain ends before "
                    "seed h=%d)\n", cur->nHeight, to_h);
            inserted = -1;
            break;
        }
        const void *hb = sqlite3_column_blob(child, 0);
        if (!hb || sqlite3_column_bytes(child, 0) < 32) { inserted = -1; break; }
        int file_num = sqlite3_column_int(child, 1);
        uint32_t data_pos = (uint32_t)sqlite3_column_int64(child, 2);
        int status = sqlite3_column_int(child, 3);
        int num_tx = sqlite3_column_int(child, 4);

        struct uint256 hash;
        memcpy(hash.data, hb, 32);
        struct block_index *bi =
            chainstate_insert_block_index((struct chainstate *)ms, &hash);
        if (!bi) { inserted = -1; break; }
        bi->nHeight = next_h;
        bi->nFile = file_num;
        bi->nDataPos = data_pos;
        bi->nStatus = (uint32_t)status;
        bi->nTx = num_tx;
        bi->pprev = cur;
        uint8_t real_root[32];
        if (read_body_sapling_root(datadir, file_num, data_pos, real_root))
            memcpy(bi->hashFinalSaplingRoot.data, real_root, 32);

        cur = bi;
        next_h++;
        inserted++;
    }
    sqlite3_finalize(child);
    return inserted;
}

/* Verify the in-memory active chain is CONTIGUOUS from `seed_bi` down to the
 * canonical genesis: every step is height-1 and no pprev is NULL before genesis.
 * This is the load-bearing bundle invariant — a fresh node's from-genesis active
 * chain caps at the first pprev hole, so a holed index would leave the seed
 * unreachable. Returns true iff contiguous; logs the first gap otherwise. */
static bool verify_contiguous_to_genesis(const struct block_index *seed_bi)
{
    const struct block_index *w = seed_bi;
    int expect_h = seed_bi->nHeight;
    while (w) {
        if (w->nHeight != expect_h) {
            fprintf(stderr, "[bundle] CONTIGUITY GAP: expected h=%d but block "
                    "is h=%d\n", expect_h, w->nHeight);
            return false;
        }
        if (w->nHeight == 0)
            return true;                       /* reached genesis cleanly */
        if (!w->pprev) {
            fprintf(stderr, "[bundle] CONTIGUITY GAP: NULL pprev at h=%d "
                    "(not genesis)\n", w->nHeight);
            return false;
        }
        expect_h = w->nHeight - 1;
        w = w->pprev;
    }
    fprintf(stderr, "[bundle] CONTIGUITY GAP: walked off the chain before "
            "genesis\n");
    return false;
}

/* Copy a file byte-for-byte (snapshot -> bundle dir). Returns true on success. */
static bool copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in) { fprintf(stderr, "[bundle] open src %s failed\n", src); return false; }
    FILE *out = fopen(dst, "wb");
    if (!out) {
        fprintf(stderr, "[bundle] open dst %s failed\n", dst);
        fclose(in);
        return false;
    }
    uint8_t buf[1 << 20];
    size_t n;
    bool ok = true;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { ok = false; break; }
    }
    if (ferror(in)) ok = false;
    fclose(in);
    if (fclose(out) != 0) ok = false;
    if (!ok) fprintf(stderr, "[bundle] copy %s -> %s failed\n", src, dst);
    return ok;
}

/* SHA-256 a file's full contents into a 64-char hex string (+NUL). Returns the
 * byte size on success (>= 0) or -1 on error (logged). Uses the linked
 * crypto/sha256.h streaming API — the SAME SHA-256 the rest of the binary uses,
 * so a user's stock `sha256sum` reproduces these digests bit-for-bit. */
static long sha256_file_hex(const char *path, char hex_out[65])
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[bundle] sha256: open %s failed: %s\n", path,
                strerror(errno));
        return -1;
    }
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t buf[1 << 20];
    size_t n;
    long total = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha256_write(&ctx, buf, n);
        total += (long)n;
    }
    bool read_err = ferror(f) != 0;
    fclose(f);
    if (read_err) {
        fprintf(stderr, "[bundle] sha256: read %s failed\n", path);
        return -1;
    }
    uint8_t dg[32];
    sha256_finalize(&ctx, dg);
    for (int i = 0; i < 32; i++)
        snprintf(hex_out + i * 2, 3, "%02x", dg[i]);
    return total;
}

/* Emit the publish sidecars next to the bundle files:
 *   - SHA256SUMS  — standard "<hex>  <name>" lines (basenames) so a user can run
 *                   `cd <bundle_dir> && sha256sum -c SHA256SUMS`.
 *   - manifest.json — machine-readable provenance (heights, hashes, sizes,
 *                   authoritative source SHA-256, optional Git trace).
 * Reuses sha256_file_hex (the linked crypto lib) so the digests match stock
 * `sha256sum`. Returns true on success; logs + returns false on any I/O error.
 * `snap_sha3_hex` is the body-SHA3 the writer already computed+printed (forward
 * hex of got_sha3); `anchor_hash` is the INTERNAL-LE 32-byte block hash (we emit
 * the conventional display hex = reversed). */
static bool write_bundle_sidecars(const char *bundle_dir, const char *snap_name,
                                  int seed_h, const char *snap_sha3_hex,
                                  const uint8_t anchor_hash[32],
                                  uint64_t utxo_count, int64_t total_supply)
{
    char bi_path[1200], snap_path[1300];
    snprintf(bi_path, sizeof(bi_path), "%s/block_index.bin", bundle_dir);
    snprintf(snap_path, sizeof(snap_path), "%s/%s", bundle_dir, snap_name);

    char bi_sha[65], snap_sha[65];
    long bi_size = sha256_file_hex(bi_path, bi_sha);
    long snap_size = sha256_file_hex(snap_path, snap_sha);
    if (bi_size < 0 || snap_size < 0) {
        fprintf(stderr, "[bundle] sidecar: SHA-256 of bundle files failed\n");
        return false;
    }

    /* SHA256SUMS — two-space separator, basenames (sha256sum binary-mode form). */
    char sums_path[1240];
    snprintf(sums_path, sizeof(sums_path), "%s/SHA256SUMS", bundle_dir);
    FILE *sf = fopen(sums_path, "wb");
    if (!sf) {
        fprintf(stderr, "[bundle] sidecar: open %s failed: %s\n", sums_path,
                strerror(errno));
        return false;
    }
    fprintf(sf, "%s  block_index.bin\n", bi_sha);
    fprintf(sf, "%s  %s\n", snap_sha, snap_name);
    if (ferror(sf) || fclose(sf) != 0) {
        fprintf(stderr, "[bundle] sidecar: write %s failed\n", sums_path);
        return false;
    }

    /* anchor_block_hash display hex = reversed from the internal-LE header bytes
     * (the conventional leading-zeros PoW-hash form a user sees in explorers). */
    char anchor_disp[65];
    for (int i = 0; i < 32; i++)
        snprintf(anchor_disp + i * 2, 3, "%02x", anchor_hash[31 - i]);

    /* total_supply is zatoshi (1 ZCL = 100,000,000 zatoshi). Emit ZCL as a
     * fixed-point STRING (8 places) to avoid any float rounding in the manifest. */
    long long zwhole = (long long)(total_supply / 100000000LL);
    long long zfrac  = (long long)(total_supply % 100000000LL);
    if (zfrac < 0) zfrac = -zfrac;  /* supply is non-negative; defensive */

    char man_path[1240];
    snprintf(man_path, sizeof(man_path), "%s/manifest.json", bundle_dir);
    FILE *mf = fopen(man_path, "wb");
    if (!mf) {
        fprintf(stderr, "[bundle] sidecar: open %s failed: %s\n", man_path,
                strerror(errno));
        return false;
    }
    fprintf(mf,
            "{\n"
            "  \"schema_version\": 2,\n"
            "  \"seed_height\": %d,\n"
            "  \"anchor_block_hash\": \"%s\",\n"
            "  \"snapshot_sha3\": \"%s\",\n"
            "  \"utxo_count\": %llu,\n"
            "  \"total_supply_sat\": %lld,\n"
            "  \"total_supply_zcl\": \"%lld.%08lld\",\n"
            "  \"block_index_file\": \"block_index.bin\",\n"
            "  \"block_index_size\": %ld,\n"
            "  \"block_index_sha256\": \"%s\",\n"
            "  \"snapshot_file\": \"%s\",\n"
            "  \"snapshot_size\": %ld,\n"
            "  \"snapshot_sha256\": \"%s\",\n"
            "  \"source_identity_schema\": \"zcl.dev_source_identity.v2\",\n"
            "  \"source_id_sha256\": \"%s\",\n"
            "  \"build_commit\": \"%s\"\n"
            "}\n",
            seed_h, anchor_disp, snap_sha3_hex,
            (unsigned long long)utxo_count, (long long)total_supply,
            zwhole, zfrac,
            bi_size, bi_sha,
            snap_name, snap_size, snap_sha,
            zcl_build_source_id_sha256(),
            zcl_build_commit());
    if (ferror(mf) || fclose(mf) != 0) {
        fprintf(stderr, "[bundle] sidecar: write %s failed\n", man_path);
        return false;
    }

    fprintf(stderr,
            "[bundle] wrote SHA256SUMS + manifest.json\n"
            "         block_index.bin  %ld B  sha256=%s\n"
            "         %s  %ld B  sha256=%s\n",
            bi_size, bi_sha, snap_name, snap_size, snap_sha);
    return true;
}

/* Provided by the node binary's main.c; this standalone tool defines its own
 * so the shared object set links. */
volatile sig_atomic_t g_shutdown_requested = 0;

/* State shared by the mint phases. Each phase returns 0 on success; a phase that
 * fails after the node_state handle is open closes it through mint_abort(). */
struct mint_ctx {
    const char *datadir;
    const char *out_path;
    const char *bundle_dir;
    int32_t seed_h;
    sqlite3 *pdb;
    struct main_state ms;
    struct node_db ndb;
    struct block_index *best;
    uint8_t anchor_hash[32];
    int64_t built_h;
    uint8_t got_sha3[32];
    uint64_t got_count;
    int64_t got_supply;
    char sha3hex[65];
};

/* Closes the node_state handle on a failed phase; the caller returns 1. */
static int mint_abort(struct mint_ctx *c)
{
    node_db_close(&c->ndb);
    return 1;
}

static int mint_parse_args(int argc, char **argv, struct mint_ctx *c)
{
    if (argc != 4 && argc != 5) {
        fprintf(stderr,
                "usage: %s <datadir> <seed_height> <out_path> [bundle_dir]\n"
                "\n"
                "  Mint a v2 (UTXO + Sapling-frontier) snapshot at <seed_height>\n"
                "  from a synced source <datadir> (read from the kernel store —\n"
                "  consensus.db, or the legacy progress.kv on a pre-flip datadir —\n"
                "  + node.db + blocks/). Writes the snapshot to <out_path>.\n"
                "\n"
                "  If [bundle_dir] is given, ALSO emits a CONTIGUOUS block_index.bin\n"
                "  there (reconstructed from the densified in-memory chain, so it is\n"
                "  contiguous genesis..seed even if the source flat file had a hole)\n"
                "  and copies the snapshot in as utxo-seed-<h>.snapshot. The result is\n"
                "  a self-contained 'starter pack': drop bundle_dir/* into a fresh\n"
                "  datadir + boot with -load-snapshot-at-own-height to climb seed->tip.\n",
                argv[0]);
        return 2;
    }
    c->datadir = argv[1];
    c->seed_h = (int32_t)strtol(argv[2], NULL, 10);  /* 0 = auto */
    c->out_path = argv[3];
    c->bundle_dir = (argc == 5) ? argv[4] : NULL;

    if (c->seed_h < 0) {
        fprintf(stderr, "seed_height must be >= 0 (0 = auto-pick coins_applied-1)\n");
        return 2;
    }
    return 0;
}

/* Auto-pick the seed height from the source's coins-applied frontier when
 * the caller passes 0. The ONLY coherent mint height is coins_applied-1 (the
 * coin set is exactly as-of the last applied block; the coherence guard
 * below enforces this). Saves the caller from reading the kernel store by hand. */
static int mint_auto_seed(sqlite3 *pdb, int32_t *seed_h)
{
    int32_t ca = 0;
    bool caf = false;
    if (!coins_kv_get_applied_height(pdb, &ca, &caf) || !caf || ca <= 1) {
        fprintf(stderr, "auto-seed: could not read coins_applied_height "
                "(found=%d val=%d)\n", caf, ca);
        return 1;
    }
    *seed_h = ca - 1;
    fprintf(stderr, "[mint-v2] auto seed height = coins_applied(%d) - 1 = %d\n",
            ca, *seed_h);
    return 0;
}

/* (1) coins_kv home. */
static int mint_open_source(struct mint_ctx *c)
{
    if (!progress_store_open(c->datadir)) {
        fprintf(stderr, "progress_store_open(%s) failed\n", c->datadir);
        return 1;
    }
    c->pdb = progress_store_db();
    if (!c->pdb) {
        fprintf(stderr, "progress_store_db() returned NULL\n");
        return 1;
    }
    if (c->seed_h == 0 && mint_auto_seed(c->pdb, &c->seed_h) != 0)
        return 1;

    int64_t num_txs = 0, count = 0, supply = 0;
    if (coins_kv_setinfo(c->pdb, &num_txs, &count, &supply))
        fprintf(stderr, "coins_kv: count=%lld supply=%lld\n",
                (long long)count, (long long)supply);
    return 0;
}

/* (2) in-memory block index. */
static int mint_open_index(struct mint_ctx *c)
{
    main_state_init(&c->ms);
    if (!load_block_index_flat(c->datadir, &c->ms).ok) {
        fprintf(stderr, "load_block_index_flat(%s) failed — the source datadir "
                "has no readable block_index.bin. Point at a datadir from a "
                "synced z23 node, which writes block_index.bin itself "
                "(no zclassicd / --importblockindex step is involved).\n",
                c->datadir);
        return 1;
    }

    /* node_state home (opened early — the topup below reads node.db `blocks`). */
    char ndb_path[1100];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", c->datadir);
    memset(&c->ndb, 0, sizeof(c->ndb));
    if (!node_db_open(&c->ndb, ndb_path)) {
        fprintf(stderr, "node_db_open(%s) failed\n", ndb_path);
        return 1;
    }
    return 0;
}

/* (3) the stale flat block_index.bin may stop below the coins frontier.
 * Top up the [flat_tip+1 .. seed_h] window from node.db `blocks` (reading
 * the REAL hashFinalSaplingRoot from each body) so the active chain reaches
 * the seed height with verifiable roots. */
static int mint_topup_flat_tip(struct mint_ctx *c)
{
    int flat_tip = -1;
    struct block_index *flat_tip_bi = NULL;
    {
        size_t it = 0;
        struct block_index *p = NULL;
        while (block_map_next(&c->ms.map_block_index, &it, NULL, &p)) {
            if (!p || !p->phashBlock) continue;
            if (p->nHeight > flat_tip) { flat_tip = p->nHeight; flat_tip_bi = p; }
        }
    }
    if (flat_tip < c->seed_h) {
        fprintf(stderr, "[mint-v2] flat block_index tip h=%d < seed h=%d — "
                "topping up FORWARD by prev_hash from node.db `blocks`...\n",
                flat_tip, c->seed_h);
        long up = topup_forward_from_node_db(&c->ms, &c->ndb, c->datadir,
                                             flat_tip_bi, c->seed_h);
        if (up < 0) {
            fprintf(stderr, "topup failed\n");
            return mint_abort(c);
        }
        fprintf(stderr, "[mint-v2] topped up %ld block-index entries\n", up);
    }
    return 0;
}

/* Diagnostic: walk pprev from the tip and report the first gap (a NULL
 * pprev or a non-contiguous height step) so a densify failure is legible. */
static void mint_report_pprev_gaps(struct block_index *best)
{
    struct block_index *w = best;
    int prev_h = best->nHeight + 1;
    while (w) {
        if (w->nHeight != prev_h - 1) {
            fprintf(stderr, "[mint-v2] pprev height step gap: %d -> %d\n",
                    prev_h, w->nHeight);
            break;
        }
        if (!w->pprev) {
            if (w->nHeight != 0)
                fprintf(stderr, "[mint-v2] pprev chain breaks at h=%d "
                        "(NULL pprev, not genesis)\n", w->nHeight);
            break;
        }
        prev_h = w->nHeight;
        w = w->pprev;
    }
}

/* find the highest block in the map and install it as the active tip so
 * active_chain_extend_window can densify the [..tip] window. */
static int mint_select_tip(struct mint_ctx *c)
{
    struct block_index *best = NULL;
    {
        size_t it = 0;
        struct block_index *p = NULL;
        while (block_map_next(&c->ms.map_block_index, &it, NULL, &p)) {
            if (!p || !p->phashBlock) continue;
            if (!best || p->nHeight > best->nHeight) best = p;
        }
    }
    if (!best) {
        fprintf(stderr, "block index map empty after load\n");
        return mint_abort(c);
    }
    c->best = best;
    c->ms.pindex_best_header = best;
    mint_report_pprev_gaps(best);
    return 0;
}

/* Resolves the seed-height block and installs the densified active-chain window
 * up to it, with the historical-slot sanity check. */
static int mint_install_seed_window(struct mint_ctx *c)
{
    /* Resolve the seed-height block by walking pprev from the map tip (no
     * active-chain window needed yet). */
    struct block_index *seed_bi_mut = c->best;
    while (seed_bi_mut && seed_bi_mut->nHeight > c->seed_h)
        seed_bi_mut = seed_bi_mut->pprev;
    if (!seed_bi_mut || seed_bi_mut->nHeight != c->seed_h) {
        fprintf(stderr, "no block_index at seed height h=%d (map tip h=%d)\n",
                c->seed_h, c->best->nHeight);
        return mint_abort(c);
    }
    memcpy(c->anchor_hash, seed_bi_mut->hashBlock.data, 32);

    /* Set the active tip AT the seed height and densify the full [0..seed_h]
     * window (active_chain_move_window_tip -> active_chain_fill_window walks
     * pprev to genesis). This is what sapling_tree_rebuild's per-height
     * active_chain_at() reads, and it caps the rebuild endpoint to seed_h. */
    if (!active_chain_move_window_tip(&c->ms.chain_active, seed_bi_mut)) {
        fprintf(stderr, "failed to install+densify the active-chain window to "
                "the seed height h=%d\n", c->seed_h);
        return mint_abort(c);
    }
    /* Sanity: a few historical slots must resolve (else the bodies would be
     * skipped and the rebuild would produce a wrong root). */
    if (!active_chain_at(&c->ms.chain_active, 476969) ||
        !active_chain_at(&c->ms.chain_active, c->seed_h)) {
        fprintf(stderr, "active-chain window did not densify (slot 476969 or "
                "seed missing) — pprev chain incomplete\n");
        return mint_abort(c);
    }
    return 0;
}

/* Reuses the persisted Sapling frontier when it already sits at the seed height,
 * otherwise drives the consensus-validating rebuild from blocks/. */
static int mint_acquire_frontier(struct mint_ctx *c)
{
    /* (5) Acquire the Sapling frontier at the seed height.
     *
     * FAST PATH (reuse): a SYNCED source already persists
     * node_state["sapling_tree"] at its coins-applied height — the live fold
     * maintains it and consensus-verifies its root against every block's
     * hashFinalSaplingRoot inside connect_block. If that persisted frontier is
     * already AT the seed height, reuse it verbatim instead of replaying note
     * commitments from blocks/. This is what lets us mint from a blocks-pruned
     * source (the daily-driver lacks block bodies below its snapshot seed, so a
     * from-activation replay is impossible) — the frontier is already correct,
     * and the v2 LOADER re-verifies its root against the PoW-proven seed header
     * at load, so a bad reuse is caught there, never silently shipped. Force a
     * full from-blocks replay with ZCL_MINT_FORCE_REBUILD=1.
     *
     * SLOW PATH (rebuild): clear stale resume markers + drive the
     * consensus-validating rebuild, which replays note commitments from Sapling
     * activation to the capped endpoint, verifies the final root against
     * hashFinalSaplingRoot, and persists the serialized frontier. */
    int64_t persisted_tree_h = 0;
    bool reuse_frontier = (getenv("ZCL_MINT_FORCE_REBUILD") == NULL) &&
        node_db_state_get_int(&c->ndb, "sapling_tree_rebuild_height",
                              &persisted_tree_h) &&
        persisted_tree_h == c->seed_h;
    if (reuse_frontier) {
        uint8_t probe[8192];
        size_t probe_len = 0;
        reuse_frontier = node_db_state_get(&c->ndb, "sapling_tree", probe,
                                           sizeof(probe), &probe_len) &&
                         probe_len > 0;
    }
    if (reuse_frontier) {
        fprintf(stderr, "[mint-v2] REUSING persisted Sapling frontier already at "
                "h=%d (no blocks/ replay; the v2 loader re-verifies its root "
                "against the PoW-proven seed header at load)\n", c->seed_h);
    } else {
        (void)node_db_state_set(&c->ndb, "sapling_tree", NULL, 0);
        (void)node_db_state_set(&c->ndb, "sapling_tree_rescan_height", NULL, 0);
        (void)node_db_state_set(&c->ndb, "sapling_tree_rebuild_height", NULL, 0);

        fprintf(stderr, "[mint-v2] driving sapling_tree_rebuild to h=%d "
                "(this replays note commitments from blocks/ — minutes)...\n",
                c->seed_h);
        int appended = sapling_tree_rebuild(&c->ndb, &c->ms.chain_active, c->datadir);
        if (appended < 0) {
            fprintf(stderr, "sapling_tree_rebuild FAILED (rc=%d)\n", appended);
            return mint_abort(c);
        }
    }
    return 0;
}

/* Reads the height the Sapling rebuild actually reached. */
static int mint_read_built_height(struct mint_ctx *c)
{
    /* The rebuild may have capped its endpoint to the coins-applied frontier;
     * read the ACTUAL height it persisted so we stamp the snapshot coherently. */
    int64_t built_h = 0;
    if (!node_db_state_get_int(&c->ndb, "sapling_tree_rebuild_height", &built_h) ||
        built_h <= 0) {
        fprintf(stderr, "sapling_tree_rebuild did not persist a rebuild height\n");
        return mint_abort(c);
    }
    c->built_h = built_h;
    return 0;
}

/* COHERENCE GUARD (the utxo_collision fix). The snapshot UTXO body is the
 * ENTIRE coins table = the set AS OF the last applied block =
 * coins_applied_height - 1. The header height (seed_h) we stamp MUST equal
 * that coin-set height, else a fresh node re-applies the block whose coins
 * the snapshot ALREADY contains and utxo_apply rejects it (utxo_collision)
 * — H* pins at the seed forever. The Sapling frontier + anchor hash must be
 * at the SAME height too. So: the authoritative seed height is the coin-set
 * height; the Sapling rebuild MUST reach it (it needs the body at that
 * height on disk). If the source's block bodies stop BELOW the coin-set
 * height (a coins-ahead-of-bodies mid-sync source), the bundle cannot be
 * coherent — FAIL loudly rather than ship a colliding snapshot. */
static int mint_check_coin_set(struct mint_ctx *c)
{
    int32_t coins_applied = 0;
    bool ca_found = false;
    if (!coins_kv_get_applied_height(c->pdb, &coins_applied, &ca_found) ||
        !ca_found || coins_applied <= 0) {
        fprintf(stderr, "[mint-v2] could not read coins_applied_height "
                "(found=%d val=%d) — cannot guarantee snapshot coherence\n",
                ca_found, coins_applied);
        return mint_abort(c);
    }
    int32_t coin_set_h = coins_applied - 1;  /* the coins table is as-of here */
    if ((int32_t)c->built_h != coin_set_h) {
        fprintf(stderr,
                "[mint-v2] FATAL: incoherent source — coin set is as-of h=%d "
                "(coins_applied_height=%d) but the Sapling rebuild only reached "
                "h=%lld (block body at h=%d is absent on disk). A snapshot here "
                "would carry coins from h=%d while claiming h=%lld, and a fresh "
                "node would hit utxo_collision re-applying h=%lld. Mint from a "
                "source whose block bodies reach the coin-set height "
                "(node.db blocks max >= %d).\n",
                coin_set_h, coins_applied, (long long)c->built_h, coin_set_h,
                coin_set_h, (long long)c->built_h, (long long)c->built_h + 1,
                coin_set_h);
        return mint_abort(c);
    }
    return 0;
}

/* Re-stamps the seed height and anchor at the height the rebuild reached. */
static int mint_restamp_seed(struct mint_ctx *c)
{
    if ((int32_t)c->built_h != c->seed_h) {
        fprintf(stderr, "[mint-v2] stamping the snapshot at the coin-set height "
                "h=%lld (requested seed h=%d); UTXO set + Sapling frontier + "
                "anchor are all coherent at h=%lld.\n",
                (long long)c->built_h, c->seed_h, (long long)c->built_h);
        c->seed_h = (int32_t)c->built_h;
        const struct block_index *bh = active_chain_at(&c->ms.chain_active, c->seed_h);
        if (bh) {
            memcpy(c->anchor_hash, bh->hashBlock.data, 32);
        } else {
            fprintf(stderr, "could not resolve block_index at capped h=%d "
                    "for the anchor hash\n", c->seed_h);
            return mint_abort(c);
        }
    }
    return 0;
}

static int mint_settle_height(struct mint_ctx *c)
{
    if (mint_read_built_height(c) != 0)
        return 1;
    if (mint_check_coin_set(c) != 0)
        return 1;
    return mint_restamp_seed(c);
}

/* (6) read the frontier blob + write the v2 snapshot. */
static int mint_write_snapshot(struct mint_ctx *c)
{
    const char *out_path = c->out_path;
    uint8_t frontier[8192];
    size_t flen = 0;
    if (!node_db_state_get(&c->ndb, "sapling_tree", frontier, sizeof(frontier),
                           &flen) || flen == 0) {
        fprintf(stderr, "could not read back node_state[sapling_tree]\n");
        return mint_abort(c);
    }
    fprintf(stderr, "[mint-v2] sapling frontier built: %zu bytes at h=%d\n",
            flen, c->seed_h);

    memset(c->got_sha3, 0, sizeof(c->got_sha3));
    c->got_count = 0;
    c->got_supply = 0;
    /* Sapling-only shielded => the canonical writer emits format version 2
     * (single Sapling-frontier section), byte-identical to the historical v2. */
    struct snapshot_shielded sap_only = {
        .sapling = frontier, .sapling_len = (uint32_t)flen,
    };
    if (!coins_kv_snapshot_write(c->pdb, out_path, c->seed_h, c->anchor_hash,
                                 flen > 0 ? &sap_only : NULL,
                                 c->got_sha3, &c->got_count, &c->got_supply)) {
        fprintf(stderr, "coins_kv_snapshot_write (v2 sapling-only) FAILED\n");
        return mint_abort(c);
    }

    for (int i = 0; i < 32; i++)
        snprintf(c->sha3hex + i * 2, 3, "%02x", c->got_sha3[i]);
    fprintf(stderr,
            "WROTE v2 %s height=%d count=%llu supply=%lld frontier=%zuB sha3=%s\n",
            out_path, c->seed_h, (unsigned long long)c->got_count,
            (long long)c->got_supply, flen, c->sha3hex);
    return 0;
}

/* Re-reads the written artifact and unlinks it on any mismatch. */
static int mint_self_attest(struct mint_ctx *c)
{
    /* ── MANDATORY POST-WRITE SELF-ATTEST ──────────────────────────────────
     * Generalizes the anchor_selfmint hard-verify (write → re-open → assert
     * written == intended → unlink on mismatch). Re-open the just-written
     * artifact through the SAME reader a fresh node uses (uss_open with
     * verify_full_sha3=true): it re-reads the body FROM DISK, recomputes the
     * body SHA3, and checks it against the on-disk header. Then assert every
     * in-file header field equals what THIS mint intended. Any failure means we
     * produced a corrupt or wrong artifact — UNLINK it and exit non-zero so a
     * bad snapshot is NEVER published. */
    const char *out_path = c->out_path;
    const uint8_t *anchor_hash = c->anchor_hash;
    const uint8_t *got_sha3 = c->got_sha3;
    uint64_t got_count = c->got_count;
    int64_t got_supply = c->got_supply;
    int32_t seed_h = c->seed_h;
    {
        char verr[256] = {0};
        struct uss_header vhdr;
        struct uss_handle *vh = uss_open(out_path, /*verify_full_sha3=*/true,
                                         /*expected_sha3=*/NULL, &vhdr,
                                         verr, sizeof(verr));
        if (!vh) {
            fprintf(stderr, "[mint-v2] BODY-INTEGRITY FAILED: re-open + body-SHA3 "
                    "verify of %s failed (%s) — UNLINKING (refusing to publish a "
                    "bad artifact)\n", out_path, verr);
            unlink(out_path);
            return mint_abort(c);
        }
        bool ok_ver  = (vhdr.version == 2);
        bool ok_h    = (vhdr.height == (uint32_t)seed_h);
        bool ok_cnt  = (vhdr.count == got_count);
        bool ok_sup  = (vhdr.total_supply == got_supply);
        bool ok_anc  = (memcmp(vhdr.anchor_block_hash, anchor_hash, 32) == 0);
        bool ok_sha3 = (memcmp(vhdr.sha3_hash, got_sha3, 32) == 0);
        uss_close(vh);
        if (!ok_ver || !ok_h || !ok_cnt || !ok_sup || !ok_anc || !ok_sha3) {
            fprintf(stderr,
                    "[mint-v2] BODY-INTEGRITY FAILED: in-file header disagrees with "
                    "the mint intent (version_ok=%d height_ok=%d count_ok=%d "
                    "supply_ok=%d anchor_ok=%d sha3_ok=%d) — UNLINKING %s\n",
                    ok_ver, ok_h, ok_cnt, ok_sup, ok_anc, ok_sha3, out_path);
            unlink(out_path);
            return mint_abort(c);
        }
        fprintf(stderr, "[mint-v2] BODY-INTEGRITY OK: re-read body SHA3 matches the "
                "header, and count/supply/anchor/height equal the mint intent "
                "(count=%llu supply=%lld height=%d)\n",
                (unsigned long long)got_count, (long long)got_supply, seed_h);
    }
    return 0;
}

/* Writes the contiguous block_index.bin into the bundle and verifies it loads back. */
static int mint_bundle_index(struct mint_ctx *c)
{
    const char *bundle_dir = c->bundle_dir;
    int32_t seed_h = c->seed_h;
    const struct block_index *seed_chk =
        active_chain_at(&c->ms.chain_active, seed_h);
    if (!seed_chk) {
        fprintf(stderr, "[bundle] active_chain_at(seed h=%d) NULL — cannot "
                "verify contiguity; refusing to emit a holed bundle\n", seed_h);
        return mint_abort(c);
    }
    if (!verify_contiguous_to_genesis(seed_chk)) {
        fprintf(stderr, "[bundle] source chain is NOT contiguous genesis..%d "
                "— refusing to emit a bundle that would leave the seed "
                "unreachable. Pick a seed below the first hole.\n", seed_h);
        return mint_abort(c);
    }
    fprintf(stderr, "[bundle] contiguity verified genesis..%d\n", seed_h);

    if (mkdir(bundle_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[bundle] mkdir(%s) failed: %s\n", bundle_dir,
                strerror(errno));
        return mint_abort(c);
    }

    /* Reset the active tip to EXACTLY the seed height so the emitted index
     * is bounded at the seed (a fresh node fetches above-seed bodies via
     * P2P). save_block_index_flat dumps the whole map; entries above the
     * seed are harmless (boot drops their borrowed have-data), but trimming
     * to the seed keeps the bundle minimal and unambiguous. */
    struct block_index *seed_mut =
        (struct block_index *)active_chain_at(&c->ms.chain_active, seed_h);
    if (seed_mut)
        (void)active_chain_move_window_tip(&c->ms.chain_active, seed_mut);

    fprintf(stderr, "[bundle] writing contiguous block_index.bin to %s ...\n",
            bundle_dir);
    save_block_index_flat(bundle_dir, &c->ms);

    /* Verify the emitted index round-trips (loads + integrity-passes). */
    struct main_state vms;
    main_state_init(&vms);
    if (!load_block_index_flat(bundle_dir, &vms).ok) {
        fprintf(stderr, "[bundle] VERIFY FAILED: emitted block_index.bin "
                "did not load back\n");
        return mint_abort(c);
    }
    return 0;
}

/* Copies the snapshot into the bundle and writes the publish sidecars. */
static int mint_bundle_publish(struct mint_ctx *c)
{
    const char *bundle_dir = c->bundle_dir;
    const char *out_path = c->out_path;
    int32_t seed_h = c->seed_h;

    /* Copy the snapshot in under a canonical name. */
    char snap_name[256];
    snprintf(snap_name, sizeof(snap_name), "utxo-seed-%d.snapshot", seed_h);
    char snap_dst[1200];
    snprintf(snap_dst, sizeof(snap_dst), "%s/%s", bundle_dir, snap_name);
    if (!copy_file(out_path, snap_dst))
        return mint_abort(c);

    /* Publish sidecars: SHA256SUMS (for `sha256sum -c`) + manifest.json. */
    if (!write_bundle_sidecars(bundle_dir, snap_name, seed_h, c->sha3hex,
                               c->anchor_hash, c->got_count, c->got_supply)) {
        fprintf(stderr, "[bundle] FAILED to write publish sidecars "
                "(SHA256SUMS / manifest.json)\n");
        return mint_abort(c);
    }

    fprintf(stderr,
            "\nSTARTER-PACK BUNDLE READY in %s:\n"
            "  block_index.bin              (contiguous genesis..%d)\n"
            "  %s        (v2: UTXO+frontier, count=%llu)\n"
            "  SHA256SUMS                   (run: cd %s && sha256sum -c SHA256SUMS)\n"
            "  manifest.json                (provenance: heights, hashes, source SHA-256)\n"
            "\nFresh-node usage (zero flags — boot autodetects a dropped-in bundle):\n"
            "  cp %s/block_index.bin   <DATADIR>/\n"
            "  cp %s/%s   <DATADIR>/\n"
            "  z23 -datadir=<DATADIR>\n"
            "  (the explicit -load-snapshot-at-own-height=<DATADIR>/%s flag still\n"
            "   works as a forced override, but is not required.)\n",
            bundle_dir, seed_h, snap_name, (unsigned long long)c->got_count,
            bundle_dir, bundle_dir, bundle_dir, snap_name, snap_name);
    return 0;
}

/* ── STARTER-PACK BUNDLE (optional) ────────────────────────────────────
 * Emit a CONTIGUOUS block_index.bin (genesis..seed) + the snapshot into
 * bundle_dir. A fresh node's from-genesis active chain caps at the first
 * pprev hole, so the contiguity invariant is load-bearing: we re-resolve
 * the seed-height block in the densified map, VERIFY it walks pprev to
 * genesis with no gap, then dump the whole map via save_block_index_flat
 * (BIIE-embedded, self-verifying — no external sidecar needed). */
static int mint_emit_bundle(struct mint_ctx *c)
{
    if (mint_bundle_index(c) != 0)
        return 1;
    return mint_bundle_publish(c);
}

int main(int argc, char **argv)
{
    struct mint_ctx c;
    int rc = mint_parse_args(argc, argv, &c);
    if (rc != 0)
        return rc;
    if (mint_open_source(&c) != 0 || mint_open_index(&c) != 0)
        return 1;
    if (mint_topup_flat_tip(&c) != 0 || mint_select_tip(&c) != 0)
        return 1;
    if (mint_install_seed_window(&c) != 0 || mint_acquire_frontier(&c) != 0)
        return 1;
    if (mint_settle_height(&c) != 0 || mint_write_snapshot(&c) != 0)
        return 1;
    if (mint_self_attest(&c) != 0)
        return 1;
    if (c.bundle_dir && mint_emit_bundle(&c) != 0)
        return 1;
    node_db_close(&c.ndb);
    return 0;
}
