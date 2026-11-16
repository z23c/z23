/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_header_seed_import — the headers-as-artifact fast path
 * (engine/composition/src/boot_header_seed_import.c).
 *
 * Proves, against the REAL file-service serve path on a loopback seeder, that a
 * fresh node can pull the header-chain seed (block_index.bin,
 * ROM_ARTIFACT_HEADER_SEED) as a swarm artifact and import it into its header
 * index — replacing the serial P2P header crawl that otherwise gates the
 * checkpoint-bundle install:
 *
 *   (a) round-trip: a seeder registers a synthetic block_index.bin; the client
 *       discovers it via the directory listing, downloads it content-verified
 *       into <datadir>/bundles/, and boot_header_seed_import_maybe imports it —
 *       pindex_best_header climbs to the artifact tip, every non-genesis row is
 *       clamped header-only (HAVE_DATA stripped so bodies re-fetch + fully
 *       re-validate), and the artifact is re-homed at the datadir root so the
 *       node re-serves it.
 *   (b) bad-row: an artifact carrying a row whose stored hash fails its PoW
 *       target is QUARANTINED per-row (dropped + counter advances + typed
 *       blocker), the import CONTINUES with the remaining rows, and the boot is
 *       never aborted.
 *
 * Fixtures live under ./test-tmp and mkdtemp() dirs — never a real datadir. The
 * synthetic index uses regtest params (easy PoW target) so honest rows pass the
 * loader's frozen CheckProofOfWork gate and a crafted max-hash row fails it. */

#include "test/block_index_ext_fixture.h"
#include "test/test_core.h"

#include "config/boot_header_seed_import.h"
#include "config/boot_bundle_fetch.h"
#include "config/boot_consensus_bundle_marker.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"
#include "net/file_service.h"
#include "services/block_index_flat_anchor.h"
#include "services/block_index_loader.h"
#include "services/sync_benchmark_service.h"
#include "json/json.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "core/arith_uint256.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "platform/time_compat.h"

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static struct uint256 hsi_make_hash(int h)
{
    struct uint256 hash;
    memset(&hash, 0, sizeof(hash));
    hash.data[0] = (uint8_t)(h & 0xFF);
    hash.data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash.data[2] = (uint8_t)((h >> 16) & 0xFF);
    hash.data[3] = 0xAA;
    return hash;
}

/* Build a minimal height-linked block_index chain of `n` blocks. When
 * bad_row_at >= 0, that height's stored hash is forced to all-0xFF (numerically
 * above any regtest PoW target) so the loader's per-row gate quarantines it. */
static void hsi_build_chain(struct main_state *ms, int n, int bad_row_at,
                            bool complete_tip)
{
    int simple_count = complete_tip && n > 1 ? n - 1 : n;
    for (int h = 0; h < simple_count; h++) {
        struct uint256 hash = hsi_make_hash(h);
        if (h == bad_row_at)
            memset(hash.data, 0xFF, sizeof(hash.data));

        struct block_index *pi =
            chainstate_insert_block_index((struct chainstate *)ms, &hash);
        if (!pi)
            continue;
        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = 1000000 + (uint32_t)h * 150;
        pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
        pi->nTx = 1;
        pi->nFile = h / 1000;
        pi->nDataPos = (uint32_t)(h * 2048);
        if (h > 0) {
            struct uint256 prev_hash = hsi_make_hash(h - 1);
            if (h - 1 == bad_row_at)
                memset(prev_hash.data, 0xFF, sizeof(prev_hash.data));
            struct block_index *prev =
                block_map_find(&ms->map_block_index, &prev_hash);
            if (prev) {
                pi->pprev = prev;
                struct arith_uint256 proof = GetBlockProof(pi);
                arith_uint256_add(&pi->nChainWork, &prev->nChainWork, &proof);
                pi->nChainTx = prev->nChainTx + pi->nTx;
            }
        } else {
            pi->nChainWork = GetBlockProof(pi);
            pi->nChainTx = 1;
        }
    }

    if (complete_tip && n > 1 && bad_row_at != n - 1) {
        struct uint256 prev_hash = hsi_make_hash(n - 2);
        struct block_index *prev = block_map_find(&ms->map_block_index,
                                                  &prev_hash);
        const struct chain_params *cp = chain_params_get();
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.hashPrevBlock = prev_hash;
        blk.header.hashMerkleRoot.data[0] = 0x51;
        blk.header.nTime = 1600000000u + (uint32_t)n;
        struct arith_uint256 limit;
        uint256_to_arith(&limit, &cp->consensus.powLimit);
        blk.header.nBits = arith_uint256_get_compact(&limit, false);
        if (mine_block_pow(&blk, n - 1, cp, 0)) {
            struct uint256 full_hash;
            block_header_get_hash(&blk.header, &full_hash);
            struct block_index *pi = chainstate_insert_block_index(
                (struct chainstate *)ms, &full_hash);
            if (pi) {
                pi->nHeight = n - 1;
                pi->pprev = prev;
                pi->nVersion = blk.header.nVersion;
                tbi_ext(pi)->hashMerkleRoot = blk.header.hashMerkleRoot;
                pi->hashFinalSaplingRoot = blk.header.hashFinalSaplingRoot;
                pi->nTime = blk.header.nTime;
                pi->nBits = blk.header.nBits;
                tbi_ext(pi)->nNonce = blk.header.nNonce;
                tbi_ext(pi)->nSolution = zcl_malloc(blk.header.nSolutionSize,
                                           "header seed test solution");
                if (tbi_ext(pi)->nSolution) {
                    memcpy(tbi_ext(pi)->nSolution, blk.header.nSolution,
                           blk.header.nSolutionSize);
                    tbi_ext(pi)->nSolutionSize = blk.header.nSolutionSize;
                }
                pi->nStatus = BLOCK_VALID_TREE;
                pi->nTx = 1;
                pi->nChainWork = prev->nChainWork;
                struct arith_uint256 proof = GetBlockProof(pi);
                arith_uint256_add(&pi->nChainWork, &pi->nChainWork, &proof);
                pi->nChainTx = prev->nChainTx + 1;
            }
        }
        block_free(&blk);
    }
}

/* Override the baked checkpoint to (height, hash) with one byte of the hash
 * flipped when flip_byte >= 0. The caller resets the override. */
static struct sha3_utxo_checkpoint g_hsi_cp;

static void hsi_override_checkpoint(int32_t height, const struct uint256 *hash,
                                    int flip_byte)
{
    memset(&g_hsi_cp, 0, sizeof(g_hsi_cp));
    g_hsi_cp.height = height;
    memcpy(g_hsi_cp.block_hash, hash->data, sizeof(g_hsi_cp.block_hash));
    if (flip_byte >= 0)
        g_hsi_cp.block_hash[flip_byte] ^= 0x01;
    checkpoints_set_sha3_override_for_test(&g_hsi_cp);
}

/* Import with the baked checkpoint set to the fixture chain's own genesis, so
 * the seed owns it. Without an override the baked checkpoint is mainnet's,
 * which no regtest fixture chain can own, and an unbound seed is discarded. */
static bool hsi_import_owned(const char *cdir, struct main_state *ms)
{
    struct uint256 genesis = hsi_make_hash(0);
    hsi_override_checkpoint(0, &genesis, -1);
    bool r = boot_header_seed_import_maybe(cdir, ms);
    checkpoints_reset_sha3_override_for_test();
    return r;
}

/* Wrap the serve-side artifacts array into the {"artifacts":[...]} object the
 * picker consumes (mirrors test_boot_bundle_fetch). */
static void hsi_directory_json(char *out, size_t cap)
{
    char arts[3072];
    size_t an = rom_seed_directory_json(arts, sizeof(arts));
    snprintf(out, cap, "{\"artifacts\":%s}", (an > 0) ? arts : "[]");
}

/* Start the loopback seeder on an OS-assigned port (no cross-checkout
 * port collisions when suites run in parallel worktrees). */
static uint16_t hsi_start_seeder(const char *sdir)
{
    fs_server_start(sdir, 0, NULL);
    for (int w = 0; w < 40 && !fs_server_is_running(); w++)
        platform_sleep_ms(50);
    return fs_server_is_running() ? fs_server_get_port() : 0;
}

/* Save a synthetic header index to `sdir`/block_index.bin and register+serve it. */
static bool hsi_seed_artifact(const char *sdir, int n, int bad_row_at,
                              struct rom_artifact *out_art)
{
    struct main_state ms;
    main_state_init(&ms);
    hsi_build_chain(&ms, n, bad_row_at, bad_row_at < 0);
    if (!block_index_flat_anchor_prepare(&ms).ok) {
        main_state_free(&ms);
        return false;
    }
    if (bad_row_at < 0) {
        struct block_index *tip = NULL;
        size_t iter = 0;
        while (block_map_next(&ms.map_block_index, &iter, NULL, &tip)) {
            if (tip && tip->nHeight == n - 1) {
                free(tbi_ext(tip)->nSolution);
                tbi_ext(tip)->nSolution = NULL;
                tbi_ext(tip)->nSolutionSize = 0;
                break;
            }
        }
    }
    save_block_index_flat(sdir, &ms);
    main_state_free(&ms);

    return rom_seed_register(sdir, "block_index.bin", NULL, out_art) == ROM_REG_OK;
}

static int case_import_roundtrip(void)
{
    int failures = 0;
    TEST("boot_header_seed: swarm-download + import climbs the header frontier") {
        chain_params_select(CHAIN_REGTEST);
        rom_seed_reset();
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);

        char sroot[PATH_MAX];
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_hsi_srv");
        ASSERT(sdir != NULL);

        struct rom_artifact art;
        ASSERT(hsi_seed_artifact(sdir, 100, -1, &art));
        ASSERT(art.kind == ROM_ARTIFACT_HEADER_SEED);

        uint16_t port = hsi_start_seeder(sdir);
        ASSERT(port != 0);

        /* The client picks the header-seed manifest from the seeder's real
         * directory listing and downloads it content-verified into bundles/. */
        char dirjson[3200];
        hsi_directory_json(dirjson, sizeof(dirjson));
        struct rom_fetch_manifest hm;
        memset(&hm, 0, sizeof(hm));
        ASSERT(boot_bundle_pick_header_seed_manifest(dirjson, &hm));
        ASSERT(hm.kind == ROM_ARTIFACT_HEADER_SEED);
        ASSERT(strcmp(hm.filename, "block_index.bin") == 0);
        ASSERT(memcmp(hm.chunk_root, art.chunk_root, 32) == 0);

        char croot[PATH_MAX];
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_hsi_cli");
        ASSERT(cdir != NULL);
        struct rom_fetch_peer peers[1];
        memset(peers, 0, sizeof(peers));
        snprintf(peers[0].addr, sizeof(peers[0].addr), "%s", "127.0.0.1");
        peers[0].port = port;
        ASSERT(boot_bundle_fetch_download(cdir, peers, 1, &hm));
        char landed[1200];
        snprintf(landed, sizeof(landed), "%s/bundles/block_index.bin", cdir);
        struct stat st;
        ASSERT(stat(landed, &st) == 0);

        /* Import into a fresh client header index. */
        struct main_state cms;
        main_state_init(&cms);

        ASSERT(hsi_import_owned(cdir, &cms));

        /* Frontier climbed to the artifact tip; every row landed. */
        ASSERT(cms.map_block_index.size == 100);
        ASSERT(cms.pindex_best_header != NULL);
        ASSERT(cms.pindex_best_header->nHeight == 99);
        ASSERT(tbi_ext(cms.pindex_best_header)->nSolution != NULL);
        ASSERT(tbi_ext(cms.pindex_best_header)->nSolutionSize > 0);

        struct block_header restored;
        block_header_init(&restored);
        restored.nVersion = cms.pindex_best_header->nVersion;
        restored.hashPrevBlock = *cms.pindex_best_header->pprev->phashBlock;
        restored.hashMerkleRoot = tbi_ext(cms.pindex_best_header)->hashMerkleRoot;
        restored.hashFinalSaplingRoot =
            cms.pindex_best_header->hashFinalSaplingRoot;
        restored.nTime = cms.pindex_best_header->nTime;
        restored.nBits = cms.pindex_best_header->nBits;
        restored.nNonce = tbi_ext(cms.pindex_best_header)->nNonce;
        memcpy(restored.nSolution, tbi_ext(cms.pindex_best_header)->nSolution,
               tbi_ext(cms.pindex_best_header)->nSolutionSize);
        restored.nSolutionSize = tbi_ext(cms.pindex_best_header)->nSolutionSize;
        struct uint256 restored_hash;
        block_header_get_hash(&restored, &restored_hash);
        ASSERT(uint256_eq(&restored_hash,
                          cms.pindex_best_header->phashBlock));

        /* Header-only clamp: a non-genesis row has HAVE_DATA/UNDO stripped so
         * the body is re-fetched + fully re-validated (never trust the seeder's
         * persisted body validity). */
        struct uint256 h50 = hsi_make_hash(50);
        struct block_index *pi50 = block_map_find(&cms.map_block_index, &h50);
        ASSERT(pi50 != NULL);
        unsigned int s50 = block_index_status_load(pi50);
        ASSERT((s50 & (unsigned int)BLOCK_HAVE_DATA) == 0);
        ASSERT((s50 & (unsigned int)BLOCK_HAVE_UNDO) == 0);
        ASSERT((s50 & (unsigned int)BLOCK_VALID_MASK) <= (unsigned int)BLOCK_VALID_TREE);

        /* The artifact was re-homed at the datadir root (re-serve on this node). */
        char root_bin[1200];
        snprintf(root_bin, sizeof(root_bin), "%s/block_index.bin", cdir);
        ASSERT(stat(root_bin, &st) == 0);

        /* Idempotent: a second call no-ops (root file present, ladder-owned). */
        ASSERT(!boot_header_seed_import_maybe(cdir, &cms));

        main_state_free(&cms);
        fs_server_stop();
        test_rm_rf_recursive(cdir);
        char p[1200];
        snprintf(p, sizeof(p), "%s/block_index.bin", sdir);
        unlink(p);
        rmdir(sdir);
        rom_seed_reset();
    } _test_next:;
    return failures;
}

static int case_bad_row(void)
{
    int failures = 0;
    TEST("boot_header_seed: a bad-PoW row is quarantined, import continues") {
        chain_params_select(CHAIN_REGTEST);
        rom_seed_reset();
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);
        blocker_clear("block_index.flat_row_quarantine");

        char sroot[PATH_MAX];
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_hsi_bad_srv");
        ASSERT(sdir != NULL);

        /* 100 rows h=0..99; the TIP (h=99) carries an all-0xFF stored hash that
         * exceeds its PoW target — nothing depends on it, so the rest survives. */
        struct rom_artifact art;
        ASSERT(hsi_seed_artifact(sdir, 100, 99, &art));

        uint16_t port = hsi_start_seeder(sdir);
        ASSERT(port != 0);

        char dirjson[3200];
        hsi_directory_json(dirjson, sizeof(dirjson));
        struct rom_fetch_manifest hm;
        memset(&hm, 0, sizeof(hm));
        ASSERT(boot_bundle_pick_header_seed_manifest(dirjson, &hm));

        char croot[PATH_MAX];
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_hsi_bad_cli");
        ASSERT(cdir != NULL);
        struct rom_fetch_peer peers[1];
        memset(peers, 0, sizeof(peers));
        snprintf(peers[0].addr, sizeof(peers[0].addr), "%s", "127.0.0.1");
        peers[0].port = port;
        ASSERT(boot_bundle_fetch_download(cdir, peers, 1, &hm));

        int64_t q_before = block_index_flat_row_quarantined();

        struct main_state cms;
        main_state_init(&cms);

        /* Import CONTINUES past the bad row (never a whole-boot abort). */
        ASSERT(hsi_import_owned(cdir, &cms));

        /* The poisoned tip was dropped: 99 good rows land, frontier = h=98. */
        ASSERT(cms.map_block_index.size == 99);
        ASSERT(cms.pindex_best_header != NULL);
        ASSERT(cms.pindex_best_header->nHeight == 98);

        /* Quarantine counter advanced + typed blocker raised — not a silent
         * accept. */
        ASSERT(block_index_flat_row_quarantined() > q_before);
        struct blocker_snapshot found;
        ASSERT(blocker_find_by_id_prefix("block_index.flat_row_quarantine",
                                         &found));

        main_state_free(&cms);
        fs_server_stop();
        test_rm_rf_recursive(cdir);
        char p[1200];
        snprintf(p, sizeof(p), "%s/block_index.bin", sdir);
        unlink(p);
        rmdir(sdir);
        rom_seed_reset();
    } _test_next:;
    return failures;
}

/* zcl.sync_benchmark.v1: SYNC_BENCH_HEADERS begins only when this boot
 * genuinely attempts a header-seed import (the artifact is present), and
 * ends once the import resolves. Two cases, both on a scratch fixture
 * (test_mkdtemp — never a real datadir):
 *   (a) a no-op boot (no bundles/block_index.bin) never begins the phase.
 *   (b) a real import stamps a non-negative elapsed_ms. */
static int case_sync_benchmark_headers_phase(void)
{
    int failures = 0;
    TEST("boot_header_seed: SYNC_BENCH_HEADERS is honest about no-op vs real import") {
        chain_params_select(CHAIN_REGTEST);

        char nodir[PATH_MAX];
        ASSERT(test_mkdtemp(nodir, sizeof(nodir), "hsi_bench_noop") != NULL);

        sync_benchmark_reset_for_test();
        sync_benchmark_init(nodir);

        struct main_state noop_ms;
        main_state_init(&noop_ms);

        /* Stat-miss no-op: no artifact staged, phase never begins. */
        ASSERT(!boot_header_seed_import_maybe(nodir, &noop_ms));

        struct json_value noop_dump;
        json_init(&noop_dump);
        ASSERT(sync_benchmark_dump_state_json(&noop_dump, NULL));
        const struct json_value *noop_timings = json_get(&noop_dump, "timings_ms");
        ASSERT(noop_timings != NULL);
        ASSERT(json_is_null(json_get(noop_timings, "headers")));
        json_free(&noop_dump);

        main_state_free(&noop_ms);

        /* Real import: the phase stamps a non-negative elapsed_ms. */
        char sdir[PATH_MAX];
        ASSERT(test_mkdtemp(sdir, sizeof(sdir), "hsi_bench_src") != NULL);
        char cdir[PATH_MAX];
        ASSERT(test_mkdtemp(cdir, sizeof(cdir), "hsi_bench_dst") != NULL);

        struct main_state seed_ms;
        main_state_init(&seed_ms);
        hsi_build_chain(&seed_ms, 8, -1, true);
        ASSERT(block_index_flat_anchor_prepare(&seed_ms).ok);
        save_block_index_flat(sdir, &seed_ms);
        main_state_free(&seed_ms);

        char bundles_dir[PATH_MAX];
        snprintf(bundles_dir, sizeof(bundles_dir), "%s/bundles", cdir);
        ASSERT(mkdir(bundles_dir, 0700) == 0);
        char from[PATH_MAX + 32];
        char to[PATH_MAX + 32];
        snprintf(from, sizeof(from), "%s/block_index.bin", sdir);
        snprintf(to, sizeof(to), "%s/block_index.bin", bundles_dir);
        {
            /* Copy (not rename) — sdir is a shared fixture root, and
             * boot_header_seed_import_maybe consumes (renames) its input. */
            FILE *rf = fopen(from, "rb");
            ASSERT(rf != NULL);
            FILE *wf = fopen(to, "wb");
            ASSERT(wf != NULL);
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), rf)) > 0)
                ASSERT(fwrite(buf, 1, n, wf) == n);
            fclose(rf);
            fclose(wf);
        }

        sync_benchmark_reset_for_test();
        sync_benchmark_init(cdir);

        struct main_state cms;
        main_state_init(&cms);

        ASSERT(hsi_import_owned(cdir, &cms));

        struct json_value dump;
        json_init(&dump);
        ASSERT(sync_benchmark_dump_state_json(&dump, NULL));
        const struct json_value *timings = json_get(&dump, "timings_ms");
        ASSERT(timings != NULL);
        const struct json_value *headers = json_get(timings, "headers");
        ASSERT(headers != NULL);
        ASSERT(!json_is_null(headers));
        ASSERT(json_get_int(headers) >= 0);
        json_free(&dump);

        main_state_free(&cms);
        sync_benchmark_reset_for_test();
    } _test_next:;
    return failures;
}


/* ── Seeding-mutant tests: hostile input, refusals, clamp, checkpoint bind ──
 * Each fixture builds a real flat artifact (regtest PoW rows, mined tip) in a
 * scratch dir and stages it at <cdir>/bundles/block_index.bin, then drives
 * boot_header_seed_import_maybe against a local main_state. Nothing here
 * touches a real datadir. */

enum hsi_variant { HSI_COPY_FULL, HSI_COPY_HALF, HSI_COPY_EMPTY, HSI_COPY_FLIP };

struct hsi_fx {
    char sdir[PATH_MAX];
    char cdir[PATH_MAX];
    char bundle[PATH_MAX + 64];
    char root[PATH_MAX + 64];
    struct uint256 tip;
};

static bool hsi_copy_variant(const char *from, const char *to,
                             enum hsi_variant v)
{
    FILE *rf = fopen(from, "rb");
    if (!rf)
        return false;
    fseek(rf, 0, SEEK_END);
    long sz = ftell(rf);
    fseek(rf, 0, SEEK_SET);
    uint8_t *buf = sz > 0 ? zcl_malloc((size_t)sz, "hsi variant") : NULL;
    bool ok = buf && fread(buf, 1, (size_t)sz, rf) == (size_t)sz;
    fclose(rf);
    if (!ok) {
        free(buf);
        return false;
    }
    size_t keep = (size_t)sz;
    if (v == HSI_COPY_HALF)
        keep = (size_t)sz / 2;
    else if (v == HSI_COPY_EMPTY)
        keep = 0;
    else if (v == HSI_COPY_FLIP)
        buf[(size_t)sz / 2] ^= 0x5A;
    FILE *wf = fopen(to, "wb");
    ok = wf && (keep == 0 || fwrite(buf, 1, keep, wf) == keep);
    if (wf)
        fclose(wf);
    free(buf);
    return ok;
}

static bool hsi_find_tip_hash(struct main_state *ms, int tip_h,
                              struct uint256 *out)
{
    struct block_index *p = NULL;
    size_t it = 0;
    while (block_map_next(&ms->map_block_index, &it, NULL, &p))
        if (p && p->nHeight == tip_h && p->phashBlock) {
            *out = *p->phashBlock;
            return true;
        }
    return false;
}

static bool hsi_fx_make(struct hsi_fx *fx, int n, enum hsi_variant v)
{
    memset(fx, 0, sizeof(*fx));
    chain_params_select(CHAIN_REGTEST);
    if (!test_mkdtemp(fx->sdir, sizeof(fx->sdir), "hsi_x_src") ||
        !test_mkdtemp(fx->cdir, sizeof(fx->cdir), "hsi_x_dst"))
        return false;
    struct main_state ms;
    main_state_init(&ms);
    hsi_build_chain(&ms, n, -1, true);
    bool ok = block_index_flat_anchor_prepare(&ms).ok &&
              hsi_find_tip_hash(&ms, n - 1, &fx->tip);
    if (ok)
        save_block_index_flat(fx->sdir, &ms);
    main_state_free(&ms);
    if (!ok)
        return false;
    char bdir[PATH_MAX + 32];
    char from[PATH_MAX + 32];
    snprintf(bdir, sizeof(bdir), "%s/bundles", fx->cdir);
    snprintf(from, sizeof(from), "%s/block_index.bin", fx->sdir);
    snprintf(fx->bundle, sizeof(fx->bundle), "%s/block_index.bin", bdir);
    snprintf(fx->root, sizeof(fx->root), "%s/block_index.bin", fx->cdir);
    return mkdir(bdir, 0700) == 0 && hsi_copy_variant(from, fx->bundle, v);
}

static void hsi_fx_free(struct hsi_fx *fx)
{
    if (fx->cdir[0]) {
        (void)chmod(fx->cdir, 0700);
        test_rm_rf_recursive(fx->cdir);
    }
    if (fx->sdir[0])
        test_rm_rf_recursive(fx->sdir);
}

static bool hsi_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool hsi_blocker_named(const char *id)
{
    struct blocker_snapshot snap;
    return blocker_find_by_id_prefix(id, &snap);
}

static void hsi_clear_blockers(void)
{
    blocker_clear("header_seed.stage_failed");
    blocker_clear("header_seed.load_failed");
    blocker_clear("header_seed.checkpoint_unbound");
}

/* True when a discard ran: the unbound blocker or the never-stuck marker. A
 * refusal under hsi_import_owned must come from somewhere else. */
static bool hsi_discard_traced(const struct hsi_fx *fx)
{
    char marker[PATH_MAX + 80];
    snprintf(marker, sizeof(marker), "%s.failed", fx->bundle);
    return hsi_blocker_named("header_seed.checkpoint_unbound") ||
           hsi_exists(marker);
}

/* 1 when the headers phase carries a stamped elapsed_ms, 0 when null, -1 on
 * a dump error. */
static int hsi_headers_phase_state(void)
{
    struct json_value dump;
    json_init(&dump);
    if (!sync_benchmark_dump_state_json(&dump, NULL)) {
        json_free(&dump);
        return -1;
    }
    const struct json_value *timings = json_get(&dump, "timings_ms");
    int state = timings && !json_is_null(json_get(timings, "headers")) ? 1 : 0;
    json_free(&dump);
    return state;
}

/* Count non-genesis rows still carrying data bits, a disk position, or a
 * valid level other than TREE; *rows gets the total row count. */
static int hsi_count_unclamped(struct main_state *ms, size_t *rows)
{
    int bad = 0;
    size_t it = 0;
    struct block_index *p = NULL;
    *rows = 0;
    while (block_map_next(&ms->map_block_index, &it, NULL, &p)) {
        (*rows)++;
        if (!p || p->nHeight <= 0)
            continue;
        unsigned int st = block_index_status_load(p);
        bool data = (st & (unsigned int)(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)) != 0;
        bool pos = block_index_file_load(p) != -1 ||
                   block_index_data_pos_load(p) != 0;
        bool lvl = (st & (unsigned int)BLOCK_VALID_MASK) !=
                   (unsigned int)BLOCK_VALID_TREE;
        if (data || pos || lvl)
            bad++;
    }
    return bad;
}

static int hsi_genesis_intact(struct main_state *ms)
{
    struct uint256 gh = hsi_make_hash(0);
    struct block_index *g = block_map_find(&ms->map_block_index, &gh);
    return g && (block_index_status_load(g) & (unsigned int)BLOCK_HAVE_DATA) != 0;
}

static int case_args_and_env_refused(void)
{
    int failures = 0;
    TEST("boot_header_seed: unusable args and ZCL_NO_BUNDLE_FETCH refuse, artifact untouched") {
        struct hsi_fx fx;
        ASSERT(hsi_fx_make(&fx, 8, HSI_COPY_FULL));
        struct main_state ms;
        main_state_init(&ms);
        bool r_null = boot_header_seed_import_maybe(NULL, &ms);
        bool r_empty = boot_header_seed_import_maybe("", &ms);
        bool r_noms = boot_header_seed_import_maybe(fx.cdir, NULL);
        hsi_clear_blockers();
        setenv("ZCL_NO_BUNDLE_FETCH", "1", 1);
        /* An owned checkpoint: only the env refusal can stop it. */
        bool r_env = hsi_import_owned(fx.cdir, &ms);
        unsetenv("ZCL_NO_BUNDLE_FETCH");
        bool env_discarded = hsi_discard_traced(&fx);
        size_t n_after = block_map_count(&ms.map_block_index);
        main_state_free(&ms);
        ASSERT(!r_null);
        ASSERT(!r_empty);
        ASSERT(!r_noms);
        ASSERT(!r_env);
        ASSERT(!env_discarded);
        ASSERT(n_after == 0);
        ASSERT(hsi_exists(fx.bundle));
        ASSERT(!hsi_exists(fx.root));
        hsi_fx_free(&fx);
    } _test_next:;
    return failures;
}

static void hsi_populate(struct main_state *ms, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        struct uint256 h;
        memset(&h, 0, sizeof(h));
        h.data[0] = (uint8_t)(i & 0xFF);
        h.data[1] = (uint8_t)((i >> 8) & 0xFF);
        h.data[3] = 0xBB;
        (void)chainstate_insert_block_index((struct chainstate *)ms, &h);
    }
}

/* Runs one import over `existing` pre-populated rows with a truncated (so
 * harmlessly unloadable) artifact; reports whether the artifact left
 * bundles/ (the rename ran) and whether the root copy exists. */
static bool hsi_population_run(size_t existing, bool *bundle_left,
                               bool *root_made, size_t *entries)
{
    struct hsi_fx fx;
    if (!hsi_fx_make(&fx, 8, HSI_COPY_HALF)) {
        hsi_fx_free(&fx);
        return false;
    }
    struct main_state ms;
    main_state_init(&ms);
    hsi_populate(&ms, existing);
    *entries = block_map_count(&ms.map_block_index);
    bool r = boot_header_seed_import_maybe(fx.cdir, &ms);
    *bundle_left = hsi_exists(fx.bundle);
    *root_made = hsi_exists(fx.root);
    main_state_free(&ms);
    hsi_fx_free(&fx);
    return r;
}

static int case_population_cap_boundary(void)
{
    int failures = 0;
    TEST("boot_header_seed: a header index above 1024 entries is never seeded, 1024 still is") {
        bool over_left = false, over_root = true, at_left = true, at_root = false;
        size_t over_n = 0, at_n = 0;
        bool r_over = hsi_population_run(1025, &over_left, &over_root, &over_n);
        bool r_at = hsi_population_run(1024, &at_left, &at_root, &at_n);
        ASSERT(over_n == 1025);
        ASSERT(at_n == 1024);
        ASSERT(!r_over);
        ASSERT(over_left);   /* skipped before any move */
        ASSERT(!over_root);
        ASSERT(!r_at);       /* the half artifact cannot load ... */
        ASSERT(at_root);     /* ... but the cap let it get as far as staging */
        ASSERT(!at_left);
    } _test_next:;
    return failures;
}

struct hsi_hostile_out {
    bool result;
    size_t entries;
    bool load_failed;
    bool stage_failed;
    int phase;
};

static bool hsi_hostile_run(enum hsi_variant v, struct hsi_hostile_out *o)
{
    struct hsi_fx fx;
    memset(o, 0, sizeof(*o));
    if (!hsi_fx_make(&fx, 8, v)) {
        hsi_fx_free(&fx);
        return false;
    }
    hsi_clear_blockers();
    sync_benchmark_reset_for_test();
    sync_benchmark_init(fx.cdir);
    struct main_state ms;
    main_state_init(&ms);
    o->result = boot_header_seed_import_maybe(fx.cdir, &ms);
    o->entries = block_map_count(&ms.map_block_index);
    o->load_failed = hsi_blocker_named("header_seed.load_failed");
    o->stage_failed = hsi_blocker_named("header_seed.stage_failed");
    o->phase = hsi_headers_phase_state();
    main_state_free(&ms);
    sync_benchmark_reset_for_test();
    hsi_fx_free(&fx);
    return true;
}

static int case_hostile_artifact_rejected(void)
{
    int failures = 0;
    TEST("boot_header_seed: truncated, empty and bit-flipped artifacts import nothing") {
        static const enum hsi_variant vs[] = {HSI_COPY_HALF, HSI_COPY_EMPTY,
                                              HSI_COPY_FLIP};
        for (size_t i = 0; i < sizeof(vs) / sizeof(vs[0]); i++) {
            struct hsi_hostile_out o;
            ASSERT(hsi_hostile_run(vs[i], &o));
            ASSERT(!o.result);
            ASSERT(o.entries == 0);
            ASSERT(o.load_failed);
            ASSERT(!o.stage_failed);
            ASSERT(o.phase == 1); /* a begun phase is ended on rejection */
        }
    } _test_next:;
    return failures;
}

static int case_root_copy_present_is_left_alone(void)
{
    int failures = 0;
    TEST("boot_header_seed: a ladder-owned root copy blocks the import, nothing moves") {
        struct hsi_fx fx;
        char from[PATH_MAX + 32];
        ASSERT(hsi_fx_make(&fx, 8, HSI_COPY_FULL));
        snprintf(from, sizeof(from), "%s/block_index.bin", fx.sdir);
        ASSERT(hsi_copy_variant(from, fx.root, HSI_COPY_FULL));
        hsi_clear_blockers();
        struct main_state ms;
        main_state_init(&ms);
        /* An owned checkpoint: only the root-copy refusal can stop it. */
        bool r = hsi_import_owned(fx.cdir, &ms);
        size_t n = block_map_count(&ms.map_block_index);
        main_state_free(&ms);
        ASSERT(!r);
        ASSERT(n == 0);
        ASSERT(hsi_exists(fx.bundle));
        ASSERT(!hsi_blocker_named("header_seed.stage_failed"));
        ASSERT(!hsi_blocker_named("header_seed.load_failed"));
        ASSERT(!hsi_discard_traced(&fx));
        hsi_fx_free(&fx);
    } _test_next:;
    return failures;
}

static int case_rename_failure_named(void)
{
    int failures = 0;
    TEST("boot_header_seed: a failed move to the datadir root names stage_failed and imports nothing") {
        if (geteuid() == 0) {
            printf("skipped (root ignores directory modes)... ");
        } else {
            struct hsi_fx fx;
            ASSERT(hsi_fx_make(&fx, 8, HSI_COPY_FULL));
            hsi_clear_blockers();
            ASSERT(chmod(fx.cdir, 0500) == 0);
            struct main_state ms;
            main_state_init(&ms);
            bool r = boot_header_seed_import_maybe(fx.cdir, &ms);
            size_t n = block_map_count(&ms.map_block_index);
            main_state_free(&ms);
            (void)chmod(fx.cdir, 0700);
            ASSERT(!r);
            ASSERT(n == 0);
            ASSERT(hsi_blocker_named("header_seed.stage_failed"));
            ASSERT(!hsi_blocker_named("header_seed.load_failed"));
            ASSERT(hsi_exists(fx.bundle));
            ASSERT(!hsi_exists(fx.root));
            hsi_fx_free(&fx);
        }
    } _test_next:;
    return failures;
}

static int case_no_artifact_and_long_path_are_silent(void)
{
    int failures = 0;
    TEST("boot_header_seed: no artifact or an over-long datadir is a silent no-op") {
        chain_params_select(CHAIN_REGTEST);
        char dir[PATH_MAX];
        ASSERT(test_mkdtemp(dir, sizeof(dir), "hsi_x_silent") != NULL);
        /* "/bundles/block_index.bin" is 24 bytes: this datadir makes the
         * artifact path exactly PATH_MAX long, which does not fit. */
        char longdir[PATH_MAX];
        memset(longdir, 'a', sizeof(longdir));
        longdir[0] = '/';
        longdir[PATH_MAX - 24] = '\0';
        hsi_clear_blockers();
        sync_benchmark_reset_for_test();
        sync_benchmark_init(dir);
        struct main_state ms;
        main_state_init(&ms);
        bool r_absent = boot_header_seed_import_maybe(dir, &ms);
        bool b_absent = hsi_blocker_named("header_seed.stage_failed") ||
                        hsi_blocker_named("header_seed.load_failed");
        bool r_long = boot_header_seed_import_maybe(longdir, &ms);
        bool b_long = hsi_blocker_named("header_seed.stage_failed") ||
                      hsi_blocker_named("header_seed.load_failed");
        int phase = hsi_headers_phase_state();
        main_state_free(&ms);
        sync_benchmark_reset_for_test();
        test_rm_rf_recursive(dir);
        ASSERT(!r_absent);
        ASSERT(!b_absent);
        ASSERT(!r_long);
        ASSERT(!b_long);
        ASSERT(phase == 0);
    } _test_next:;
    return failures;
}

/* Import a 40-row artifact into a fresh map; verify the in-memory clamp on
 * every row and the durable clamp by reloading the persisted root copy. */
static int case_clamp_every_row_and_persist(void)
{
    int failures = 0;
    TEST("boot_header_seed: every non-genesis row is clamped in memory and on disk") {
        struct hsi_fx fx;
        ASSERT(hsi_fx_make(&fx, 40, HSI_COPY_FULL));
        struct main_state ms;
        main_state_init(&ms);
        bool r = hsi_import_owned(fx.cdir, &ms);
        size_t rows = 0;
        int bad = hsi_count_unclamped(&ms, &rows);
        bool genesis = hsi_genesis_intact(&ms);
        main_state_free(&ms);
        ASSERT(r);
        ASSERT(rows == 40);
        ASSERT(bad == 0);
        ASSERT(genesis);

        struct main_state again;
        main_state_init(&again);
        bool loaded = load_block_index_flat(fx.cdir, &again).ok;
        size_t rows2 = 0;
        int bad2 = hsi_count_unclamped(&again, &rows2);
        main_state_free(&again);
        ASSERT(loaded);
        ASSERT(rows2 == 40);
        ASSERT(bad2 == 0);
        hsi_fx_free(&fx);
    } _test_next:;
    return failures;
}

/* Imports an 8-row artifact while the baked checkpoint is overridden to
 * (cp_height, hash); returns 1 when the import kept the seed and owns the
 * checkpoint, 0 when it discarded the seed (not imported, nothing kept,
 * checkpoint_unbound named), -1 for any other outcome. */
static int hsi_checkpoint_run(int32_t cp_height, int hash_row, int flip_byte)
{
    struct hsi_fx fx;
    if (!hsi_fx_make(&fx, 8, HSI_COPY_FULL)) {
        hsi_fx_free(&fx);
        return -1;
    }
    struct uint256 want = hash_row < 0 ? fx.tip : hsi_make_hash(hash_row);
    hsi_clear_blockers();
    hsi_override_checkpoint(cp_height, &want, flip_byte);
    struct main_state ms;
    main_state_init(&ms);
    bool r = boot_header_seed_import_maybe(fx.cdir, &ms);
    checkpoints_reset_sha3_override_for_test();
    size_t rows = block_map_count(&ms.map_block_index);
    bool best = ms.pindex_best_header != NULL;
    main_state_free(&ms);
    bool unbound = hsi_blocker_named("header_seed.checkpoint_unbound");
    int owned = -1;
    if (r && !unbound && rows == 8 && best)
        owned = 1;
    else if (!r && unbound && rows == 0 && !best && !hsi_exists(fx.root))
        owned = 0;
    hsi_fx_free(&fx);
    return owned;
}

static int case_checkpoint_binding(void)
{
    int failures = 0;
    TEST("boot_header_seed: checkpoint ownership needs the exact hash at a reachable height; an unbound seed is not imported") {
        int at_tip = hsi_checkpoint_run(7, -1, -1);
        int at_genesis = hsi_checkpoint_run(0, 0, -1);
        int last_byte = hsi_checkpoint_run(7, -1, 31);
        int first_byte = hsi_checkpoint_run(7, -1, 0);
        int past_tip = hsi_checkpoint_run(8, -1, -1);
        int negative = hsi_checkpoint_run(-1, -1, -1);
        ASSERT(at_tip == 1);
        ASSERT(at_genesis == 1);
        ASSERT(last_byte == 0);
        ASSERT(first_byte == 0);
        ASSERT(past_tip == 0);
        ASSERT(negative == 0);
    } _test_next:;
    return failures;
}

/* ── An unbound seed is discarded whole ──────────────────────────────────
 * A seed whose chain does not own the baked checkpoint leaves nothing in
 * memory or at the datadir root, and a later boot does not import the same
 * fetched file again. */

/* The next save after a discard, then the next boot's flat load of it. */
struct hsi_resave {
    bool loaded;
    size_t rows;
    int max_height;  /* highest reloaded row; -1 when none */
    bool row_found;  /* `want` (when given) is among the reloaded rows */
};

enum hsi_discard_shape {
    HSI_DISCARD_FRESH,   /* empty header map, no frontier */
    HSI_DISCARD_GENESIS, /* the ladder seated genesis as the frontier */
};

struct hsi_discard_out {
    bool first, second;            /* the two import results */
    size_t rows_before, rows_after, rows_second;
    bool best_kept, best_kept_second;
    bool genesis_kept;             /* the resident genesis node, same pointer */
    bool seed_rows_gone;           /* no seed-only row is findable */
    bool root_absent, root_absent_second;
    bool bundle_kept, marker_written;
    bool blocker;
    struct hsi_resave resave;      /* GENESIS shape only */
};

/* Save the index after a discard, then load it as the next boot would. */
static void hsi_resave_reload(const char *cdir, struct main_state *ms,
                              const struct uint256 *want, struct hsi_resave *o)
{
    memset(o, 0, sizeof(*o));
    o->max_height = -1;
    save_block_index_flat(cdir, ms);
    struct main_state again;
    main_state_init(&again);
    o->loaded = load_block_index_flat(cdir, &again).ok;
    o->rows = block_map_count(&again.map_block_index);
    size_t it = 0;
    struct block_index *p = NULL;
    while (block_map_next(&again.map_block_index, &it, NULL, &p))
        if (p && p->nHeight > o->max_height)
            o->max_height = p->nHeight;
    o->row_found = want && block_map_find(&again.map_block_index, want);
    main_state_free(&again);
}

static bool hsi_seed_rows_gone(struct main_state *ms, const struct hsi_fx *fx)
{
    for (int h = 1; h < 7; h++) {
        struct uint256 hash = hsi_make_hash(h);
        if (block_map_find(&ms->map_block_index, &hash))
            return false;
    }
    return block_map_find(&ms->map_block_index, &fx->tip) == NULL;
}

static void hsi_discard_observe_first(struct main_state *ms,
                                      const struct hsi_fx *fx,
                                      const struct block_index *best_before,
                                      const struct block_index *genesis,
                                      struct hsi_discard_out *o)
{
    char marker[PATH_MAX + 80];
    snprintf(marker, sizeof(marker), "%s.failed", fx->bundle);
    struct uint256 g = hsi_make_hash(0);
    o->rows_after = block_map_count(&ms->map_block_index);
    o->best_kept = ms->pindex_best_header == best_before;
    o->genesis_kept = block_map_find(&ms->map_block_index, &g) == genesis;
    o->seed_rows_gone = hsi_seed_rows_gone(ms, fx);
    o->root_absent = !hsi_exists(fx->root);
    o->bundle_kept = hsi_exists(fx->bundle);
    o->marker_written = hsi_exists(marker);
    o->blocker = hsi_blocker_named("header_seed.checkpoint_unbound");
}

/* Seat genesis in the map as the frontier, as the ladder does. */
static struct block_index *hsi_seat_genesis(struct main_state *ms)
{
    hsi_build_chain(ms, 1, -1, false);
    struct uint256 g = hsi_make_hash(0);
    ms->pindex_best_header = block_map_find(&ms->map_block_index, &g);
    return ms->pindex_best_header;
}

static bool hsi_discard_run(enum hsi_discard_shape shape,
                            struct hsi_discard_out *o)
{
    memset(o, 0, sizeof(*o));
    struct hsi_fx fx;
    if (!hsi_fx_make(&fx, 8, HSI_COPY_FULL)) {
        hsi_fx_free(&fx);
        return false;
    }
    struct main_state ms;
    main_state_init(&ms);
    struct block_index *genesis =
        shape == HSI_DISCARD_GENESIS ? hsi_seat_genesis(&ms) : NULL;
    struct block_index *best_before = ms.pindex_best_header;
    o->rows_before = block_map_count(&ms.map_block_index);
    hsi_clear_blockers();
    hsi_override_checkpoint(7, &fx.tip, 0); /* the tip hash, one byte off */
    o->first = boot_header_seed_import_maybe(fx.cdir, &ms);
    hsi_discard_observe_first(&ms, &fx, best_before, genesis, o);
    /* The next boot: the same fetched seed is still in bundles/. */
    o->second = boot_header_seed_import_maybe(fx.cdir, &ms);
    checkpoints_reset_sha3_override_for_test();
    o->rows_second = block_map_count(&ms.map_block_index);
    o->best_kept_second = ms.pindex_best_header == best_before;
    o->root_absent_second = !hsi_exists(fx.root);
    if (shape == HSI_DISCARD_GENESIS)
        hsi_resave_reload(fx.cdir, &ms, &fx.tip, &o->resave);
    main_state_free(&ms);
    hsi_fx_free(&fx);
    return true;
}

static int case_unbound_seed_discarded(void)
{
    int failures = 0;
    TEST("boot_header_seed: a seed that does not own the baked checkpoint leaves nothing in memory or on disk") {
        static const enum hsi_discard_shape shapes[] = {HSI_DISCARD_FRESH,
                                                        HSI_DISCARD_GENESIS};
        for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
            struct hsi_discard_out o;
            ASSERT(hsi_discard_run(shapes[i], &o));
            ASSERT(!o.first);
            ASSERT(o.rows_after == o.rows_before);
            ASSERT(o.best_kept);
            ASSERT(o.genesis_kept);
            ASSERT(o.seed_rows_gone);
            ASSERT(o.root_absent);
            ASSERT(o.blocker);
            ASSERT(o.bundle_kept);    /* kept in bundles/: no re-fetch */
            ASSERT(o.marker_written); /* the never-stuck failure memory */
            ASSERT(!o.second);
            ASSERT(o.rows_second == o.rows_before);
            ASSERT(o.best_kept_second);
            ASSERT(o.root_absent_second);
            if (shapes[i] == HSI_DISCARD_GENESIS) {
                /* A restart after the discard sees genesis only. */
                ASSERT(o.resave.loaded);
                ASSERT(o.resave.rows == 1);
                ASSERT(o.resave.max_height == 0);
                ASSERT(!o.resave.row_found);
            }
        }
    } _test_next:;
    return failures;
}

/* ── Restart over a stub root index ──────────────────────────────────────
 * A first boot that stops (or falls back from -flysync) before the seed
 * imports leaves <datadir>/block_index.bin holding just its few P2P headers.
 * The next boot's ladder loads that stub; the downloaded seed must still
 * replace it — and every datadir that is NOT such a stub stays untouched. */

static struct uint256 hsi_fork_hash(int h)
{
    struct uint256 hash = hsi_make_hash(h);
    hash.data[3] = 0xCC; /* a side branch the artifact does not carry */
    return hash;
}

/* Header-only, like a row that arrived by P2P headers sync. */
static void hsi_make_header_only(struct block_index *pi)
{
    block_index_status_clear_bits(pi, (unsigned int)(BLOCK_HAVE_DATA |
                                                     BLOCK_HAVE_UNDO));
    block_index_disk_pos_store(pi, -1, 0);
    (void)block_index_status_set_valid_level(pi, BLOCK_VALID_TREE);
}

/* `n` side-branch header rows hanging off row 1 of the main chain. */
static bool hsi_add_fork_rows(struct main_state *ms, int n)
{
    struct uint256 h1 = hsi_make_hash(1);
    struct block_index *prev = block_map_find(&ms->map_block_index, &h1);
    for (int i = 0; i < n && prev; i++) {
        struct uint256 hash = hsi_fork_hash(2 + i);
        struct block_index *pi =
            chainstate_insert_block_index((struct chainstate *)ms, &hash);
        if (!pi)
            return false;
        pi->nHeight = 2 + i;
        pi->nBits = 0x1f07ffff;
        pi->nTime = 2000000 + (uint32_t)i * 150;
        pi->nVersion = 4;
        pi->pprev = prev;
        struct arith_uint256 proof = GetBlockProof(pi);
        arith_uint256_add(&pi->nChainWork, &prev->nChainWork, &proof);
        hsi_make_header_only(pi);
        prev = pi;
    }
    return prev != NULL;
}

/* Save a stub root index to `cdir`/block_index.bin: rows 0..n-1 of the
 * artifact's own chain plus `fork_rows` side-branch rows, every row above
 * genesis header-only except `body_row` (> 0), which keeps its body data. */
static bool hsi_write_stub_root(const char *cdir, int n, int fork_rows,
                                int body_row)
{
    struct main_state ms;
    main_state_init(&ms);
    hsi_build_chain(&ms, n, -1, false);
    size_t it = 0;
    struct block_index *p = NULL;
    while (block_map_next(&ms.map_block_index, &it, NULL, &p))
        if (p && p->nHeight > 0 && p->nHeight != body_row)
            hsi_make_header_only(p);
    bool ok = hsi_add_fork_rows(&ms, fork_rows);
    if (ok)
        save_block_index_flat(cdir, &ms);
    main_state_free(&ms);
    char root[PATH_MAX + 32];
    snprintf(root, sizeof(root), "%s/block_index.bin", cdir);
    return ok && hsi_exists(root);
}

/* Read a whole file; NULL when it cannot be read. */
static uint8_t *hsi_read_all(const char *path, size_t *len)
{
    *len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    uint8_t *buf = NULL;
    if (fseek(f, 0, SEEK_END) == 0) {
        long sz = ftell(f);
        buf = sz > 0 ? zcl_malloc((size_t)sz, "hsi read all") : NULL;
        if (buf && (fseek(f, 0, SEEK_SET) != 0 ||
                    fread(buf, 1, (size_t)sz, f) != (size_t)sz)) {
            free(buf);
            buf = NULL;
        }
        *len = buf ? (size_t)sz : 0;
    }
    fclose(f);
    return buf;
}

static bool hsi_same_bytes(const uint8_t *a, size_t alen, const char *path)
{
    size_t blen = 0;
    uint8_t *b = hsi_read_all(path, &blen);
    bool same = a && b && alen == blen && memcmp(a, b, alen) == 0;
    free(b);
    return same;
}

/* What one import over a stub root left behind. */
struct hsi_stub_out {
    bool result;
    size_t rows;
    int unclamped;
    bool best_at_tip;
    bool fork_intact;
    bool genesis;
    bool root_same;           /* unbound only: root bytes before the save */
    struct hsi_resave resave; /* unbound only: the next save + reload */
};

/* The stub's side-branch row must survive the import as the very node the
 * ladder loaded (same pointer, same hash, same height). */
static bool hsi_fork_row_intact(struct main_state *ms,
                                const struct block_index *before)
{
    struct uint256 fh = hsi_fork_hash(2);
    return before && block_map_find(&ms->map_block_index, &fh) == before &&
           before->nHeight == 2 && uint256_eq(&before->hashBlock, &fh);
}

/* `owned`: the baked checkpoint is the seed's genesis; otherwise it is the
 * seed's tip hash with one byte flipped, which the seed does not own, and the
 * run also compares the root with `stub` and saves + reloads the index. */
static bool hsi_stub_import_run(struct hsi_fx *fx, bool owned,
                                const uint8_t *stub, size_t stub_len,
                                struct hsi_stub_out *o)
{
    memset(o, 0, sizeof(*o));
    struct main_state ms;
    main_state_init(&ms);
    /* The boot ladder's flat rung (boot_blkidx_ladder.c rung_flat_load). */
    if (!load_block_index_flat(fx->cdir, &ms).ok) {
        main_state_free(&ms);
        return false;
    }
    struct uint256 fh = hsi_fork_hash(2);
    struct block_index *fork = block_map_find(&ms.map_block_index, &fh);
    if (owned) {
        o->result = hsi_import_owned(fx->cdir, &ms);
    } else {
        hsi_override_checkpoint(39, &fx->tip, 0);
        o->result = boot_header_seed_import_maybe(fx->cdir, &ms);
        checkpoints_reset_sha3_override_for_test();
    }
    o->unclamped = hsi_count_unclamped(&ms, &o->rows);
    o->best_at_tip = ms.pindex_best_header &&
                     ms.pindex_best_header->phashBlock &&
                     uint256_eq(ms.pindex_best_header->phashBlock, &fx->tip);
    o->fork_intact = hsi_fork_row_intact(&ms, fork);
    o->genesis = hsi_genesis_intact(&ms);
    if (!owned) {
        o->root_same = hsi_same_bytes(stub, stub_len, fx->root);
        hsi_resave_reload(fx->cdir, &ms, &fh, &o->resave);
    }
    main_state_free(&ms);
    return true;
}

/* Reload the root copy the import persisted; true when it carries exactly
 * `want_rows` rows, every one clamped, with the artifact tip among them. */
static bool hsi_root_is_clamped_artifact(struct hsi_fx *fx, size_t want_rows)
{
    struct main_state again;
    main_state_init(&again);
    bool loaded = load_block_index_flat(fx->cdir, &again).ok;
    size_t rows = 0;
    int bad = hsi_count_unclamped(&again, &rows);
    struct uint256 tip;
    bool has_tip = hsi_find_tip_hash(&again, 39, &tip) &&
                   uint256_eq(&tip, &fx->tip);
    main_state_free(&again);
    return loaded && rows == want_rows && bad == 0 && has_tip;
}

static int case_stub_root_replaced(void)
{
    int failures = 0;
    TEST("boot_header_seed: a stub root index from an interrupted first boot is replaced by the seed") {
        struct hsi_fx fx;
        ASSERT(hsi_fx_make(&fx, 40, HSI_COPY_FULL));
        ASSERT(hsi_write_stub_root(fx.cdir, 6, 3, -1));
        hsi_clear_blockers();
        struct hsi_stub_out o;
        ASSERT(hsi_stub_import_run(&fx, true, NULL, 0, &o));
        ASSERT(o.result);
        ASSERT(o.rows == 43); /* 40 artifact rows + the stub's 3 side rows */
        ASSERT(o.unclamped == 0);
        ASSERT(o.best_at_tip);
        ASSERT(o.fork_intact);
        ASSERT(o.genesis);
        ASSERT(!hsi_exists(fx.bundle));
        ASSERT(!hsi_blocker_named("header_seed.load_failed"));
        ASSERT(!hsi_blocker_named("header_seed.stage_failed"));
        ASSERT(hsi_root_is_clamped_artifact(&fx, 43));
        hsi_fx_free(&fx);
    } _test_next:;
    return failures;
}

/* A rejected artifact after the stub was replaced leaves the node where a
 * fresh node with a rejected artifact is today: the in-memory index intact,
 * header_seed.load_failed named, boot continuing on P2P headers. */
static int case_stub_root_rejected_artifact(void)
{
    int failures = 0;
    TEST("boot_header_seed: a rejected seed over a stub keeps the loaded stub and names load_failed") {
        struct hsi_fx fx;
        ASSERT(hsi_fx_make(&fx, 40, HSI_COPY_HALF));
        ASSERT(hsi_write_stub_root(fx.cdir, 6, 3, -1));
        hsi_clear_blockers();
        struct hsi_stub_out o;
        ASSERT(hsi_stub_import_run(&fx, true, NULL, 0, &o));
        ASSERT(!o.result);
        ASSERT(o.rows == 9); /* the stub's own 6 + 3 side rows */
        ASSERT(o.unclamped == 0);
        ASSERT(o.fork_intact);
        ASSERT(o.genesis);
        ASSERT(hsi_blocker_named("header_seed.load_failed"));
        ASSERT(!hsi_blocker_named("header_seed.stage_failed"));
        ASSERT(!hsi_exists(fx.bundle));
        hsi_fx_free(&fx);
    } _test_next:;
    return failures;
}

/* An unbound seed over a stub root: the loaded stub stays exactly as the
 * ladder left it (same rows, same side-branch node) and the stub root file is
 * the very same bytes, not the seed. */
static int case_stub_root_unbound_seed_discarded(void)
{
    int failures = 0;
    TEST("boot_header_seed: an unbound seed over a stub keeps the stub in memory and on disk") {
        struct hsi_fx fx;
        ASSERT(hsi_fx_make(&fx, 40, HSI_COPY_FULL));
        ASSERT(hsi_write_stub_root(fx.cdir, 6, 3, -1));
        size_t before_len = 0;
        uint8_t *before = hsi_read_all(fx.root, &before_len);
        ASSERT(before != NULL);
        hsi_clear_blockers();
        struct hsi_stub_out o;
        bool ran = hsi_stub_import_run(&fx, false, before, before_len, &o);
        free(before);
        char backup[PATH_MAX + 64];
        snprintf(backup, sizeof(backup), "%s/block_index.bin.pre-seed", fx.cdir);
        ASSERT(ran);
        ASSERT(!o.result);
        ASSERT(o.rows == 9); /* the stub's own 6 + 3 side rows */
        ASSERT(!o.best_at_tip);
        ASSERT(o.fork_intact);
        ASSERT(o.genesis);
        ASSERT(o.root_same);
        /* A restart after the discard sees the stub only: its 9 rows, the
         * side-branch row, nothing of the seed above the stub's height 5. */
        ASSERT(o.resave.loaded);
        ASSERT(o.resave.rows == 9);
        ASSERT(o.resave.max_height == 5);
        ASSERT(o.resave.row_found);
        ASSERT(!hsi_exists(backup));
        ASSERT(hsi_exists(fx.bundle));
        ASSERT(hsi_blocker_named("header_seed.checkpoint_unbound"));
        ASSERT(!hsi_blocker_named("header_seed.load_failed"));
        ASSERT(!hsi_blocker_named("header_seed.stage_failed"));
        hsi_fx_free(&fx);
    } _test_next:;
    return failures;
}

/* The stub backup an interrupted earlier import left behind: a hard link to
 * the stub root (a crash between keeping the stub aside and the rename). */
static bool hsi_plant_stale_backup(const struct hsi_fx *fx, char *backup,
                                   size_t cap)
{
    int n = snprintf(backup, cap, "%s/block_index.bin.pre-seed", fx->cdir);
    if (n < 0 || (size_t)n >= cap)
        return false;
#if !defined(_WIN32)
    return link(fx->root, backup) == 0;
#else
    return hsi_copy_variant(fx->root, backup, HSI_COPY_FULL);
#endif
}

static int case_stale_backup_owned_imports(void)
{
    int failures = 0;
    TEST("boot_header_seed: a stale stub backup from an interrupted import does not stop an owned seed") {
        struct hsi_fx fx;
        char backup[PATH_MAX + 64];
        ASSERT(hsi_fx_make(&fx, 40, HSI_COPY_FULL));
        ASSERT(hsi_write_stub_root(fx.cdir, 6, 3, -1));
        ASSERT(hsi_plant_stale_backup(&fx, backup, sizeof(backup)));
        hsi_clear_blockers();
        struct hsi_stub_out o;
        ASSERT(hsi_stub_import_run(&fx, true, NULL, 0, &o));
        ASSERT(o.result);
        ASSERT(o.rows == 43); /* 40 artifact rows + the stub's 3 side rows */
        ASSERT(o.best_at_tip);
        ASSERT(o.fork_intact);
        ASSERT(!hsi_blocker_named("header_seed.stage_failed"));
        ASSERT(!hsi_exists(backup));
        ASSERT(hsi_root_is_clamped_artifact(&fx, 43));
        hsi_fx_free(&fx);
    } _test_next:;
    return failures;
}

/* Keeping the stub aside over a stale hard link must never write through it:
 * the discard restores the very stub bytes. */
static int case_stale_backup_unbound_restores_stub(void)
{
    int failures = 0;
    TEST("boot_header_seed: an unbound seed over a stale stub backup restores the stub bytes") {
        struct hsi_fx fx;
        char backup[PATH_MAX + 64];
        ASSERT(hsi_fx_make(&fx, 40, HSI_COPY_FULL));
        ASSERT(hsi_write_stub_root(fx.cdir, 6, 3, -1));
        size_t before_len = 0;
        uint8_t *before = hsi_read_all(fx.root, &before_len);
        ASSERT(before != NULL);
        bool planted = hsi_plant_stale_backup(&fx, backup, sizeof(backup));
        hsi_clear_blockers();
        struct hsi_stub_out o;
        bool ran = planted &&
                   hsi_stub_import_run(&fx, false, before, before_len, &o);
        free(before);
        ASSERT(ran);
        ASSERT(!o.result);
        ASSERT(o.rows == 9); /* the stub's own 6 + 3 side rows */
        ASSERT(o.root_same);
        ASSERT(!hsi_exists(backup));
        ASSERT(hsi_blocker_named("header_seed.checkpoint_unbound"));
        ASSERT(!hsi_blocker_named("header_seed.stage_failed"));
        hsi_fx_free(&fx);
    } _test_next:;
    return failures;
}

/* The datadir conditions that must keep today's behaviour exactly. */
enum hsi_keep_case {
    HSI_KEEP_BODY_DATA,  /* a stub-sized index with body data on row 3 */
    HSI_KEEP_POPULATED,  /* 1025 header-only rows */
    HSI_KEEP_TIP,        /* the active tip is above genesis */
    HSI_KEEP_MARKER,     /* the sovereign install marker is present */
};

struct hsi_keep_out {
    bool result;
    bool root_same;
    bool bundle_left;
    size_t rows;
    bool row3_body_kept;
    bool discarded; /* the unbound blocker or the .failed marker appeared */
};

/* Row 3 still holds the body bit and disk position hsi_build_chain gave it. */
static bool hsi_row3_body_kept(struct main_state *ms)
{
    struct uint256 h3 = hsi_make_hash(3);
    struct block_index *p = block_map_find(&ms->map_block_index, &h3);
    return p && (block_index_status_load(p) & (unsigned int)BLOCK_HAVE_DATA) &&
           block_index_file_load(p) == 0 &&
           block_index_data_pos_load(p) == 3u * 2048u;
}

/* Bring the datadir/index into the `kc` shape after the ladder load. */
static bool hsi_keep_arrange(enum hsi_keep_case kc, struct hsi_fx *fx,
                             struct main_state *ms)
{
    if (kc == HSI_KEEP_TIP) {
        struct uint256 h5 = hsi_make_hash(5);
        struct block_index *t5 = block_map_find(&ms->map_block_index, &h5);
        return t5 && active_chain_move_window_tip(&ms->chain_active, t5);
    }
    if (kc == HSI_KEEP_MARKER) {
        uint8_t digest[32];
        memset(digest, 0xab, sizeof(digest));
        return boot_consensus_bundle_marker_write(fx->cdir, 7, digest);
    }
    return true;
}

static bool hsi_keep_run(enum hsi_keep_case kc, struct hsi_keep_out *o)
{
    memset(o, 0, sizeof(*o));
    struct hsi_fx fx;
    int rows = kc == HSI_KEEP_POPULATED ? 1025 : 6;
    int body_row = kc == HSI_KEEP_BODY_DATA ? 3 : -1;
    bool ok = hsi_fx_make(&fx, 40, HSI_COPY_FULL) &&
              hsi_write_stub_root(fx.cdir, rows, 0, body_row);
    size_t before_len = 0;
    uint8_t *before = ok ? hsi_read_all(fx.root, &before_len) : NULL;
    struct main_state ms;
    main_state_init(&ms);
    ok = before && load_block_index_flat(fx.cdir, &ms).ok &&
         hsi_keep_arrange(kc, &fx, &ms);
    if (ok) {
        /* The checkpoint is the fixture's own genesis, so a seed that got
         * past the verdict would import: only the verdict can refuse here. */
        o->result = hsi_import_owned(fx.cdir, &ms);
        o->discarded = hsi_discard_traced(&fx);
        o->rows = block_map_count(&ms.map_block_index);
        o->row3_body_kept = hsi_row3_body_kept(&ms);
        o->root_same = hsi_same_bytes(before, before_len, fx.root);
        o->bundle_left = hsi_exists(fx.bundle);
    }
    main_state_free(&ms);
    free(before);
    hsi_fx_free(&fx);
    return ok;
}

static int case_non_stub_root_kept(void)
{
    int failures = 0;
    TEST("boot_header_seed: body data, >1024 rows, a tip above genesis or the marker keep the root untouched") {
        static const enum hsi_keep_case kcs[] = {
            HSI_KEEP_BODY_DATA, HSI_KEEP_POPULATED, HSI_KEEP_TIP,
            HSI_KEEP_MARKER};
        static const size_t want_rows[] = {6, 1025, 6, 6};
        for (size_t i = 0; i < sizeof(kcs) / sizeof(kcs[0]); i++) {
            struct hsi_keep_out o;
            hsi_clear_blockers();
            ASSERT(hsi_keep_run(kcs[i], &o));
            ASSERT(!o.result);
            ASSERT(o.root_same);   /* root file bytes untouched */
            ASSERT(o.bundle_left); /* nothing staged */
            ASSERT(o.rows == want_rows[i]);
            ASSERT(!hsi_blocker_named("header_seed.load_failed"));
            ASSERT(!hsi_blocker_named("header_seed.stage_failed"));
            ASSERT(!o.discarded); /* refused by the verdict, not a discard */
            if (kcs[i] == HSI_KEEP_BODY_DATA)
                ASSERT(o.row3_body_kept); /* no clamp over local body data */
        }
    } _test_next:;
    return failures;
}

static int hsi_mutant_tests(void)
{
    int failures = 0;
    failures += case_stub_root_replaced();
    failures += case_stub_root_rejected_artifact();
    failures += case_stub_root_unbound_seed_discarded();
    failures += case_stale_backup_owned_imports();
    failures += case_stale_backup_unbound_restores_stub();
    failures += case_non_stub_root_kept();
    failures += case_args_and_env_refused();
    failures += case_population_cap_boundary();
    failures += case_hostile_artifact_rejected();
    failures += case_root_copy_present_is_left_alone();
    failures += case_rename_failure_named();
    failures += case_no_artifact_and_long_path_are_silent();
    failures += case_clamp_every_row_and_persist();
    failures += case_checkpoint_binding();
    failures += case_unbound_seed_discarded();
    return failures;
}

int test_boot_header_seed_import(void)
{
    printf("\n=== boot_header_seed_import ===\n");
    int failures = 0;
    failures += case_import_roundtrip();
    failures += case_bad_row();
    failures += case_sync_benchmark_headers_phase();
    failures += hsi_mutant_tests();
    printf("=== boot_header_seed_import: %d failure(s) ===\n", failures);
    return failures;
}
