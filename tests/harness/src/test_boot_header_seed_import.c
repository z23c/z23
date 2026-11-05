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

        ASSERT(boot_header_seed_import_maybe(cdir, &cms));

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
        ASSERT(boot_header_seed_import_maybe(cdir, &cms));

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

        ASSERT(boot_header_seed_import_maybe(cdir, &cms));

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
        setenv("ZCL_NO_BUNDLE_FETCH", "1", 1);
        bool r_env = boot_header_seed_import_maybe(fx.cdir, &ms);
        unsetenv("ZCL_NO_BUNDLE_FETCH");
        size_t n_after = block_map_count(&ms.map_block_index);
        main_state_free(&ms);
        ASSERT(!r_null);
        ASSERT(!r_empty);
        ASSERT(!r_noms);
        ASSERT(!r_env);
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
        bool r = boot_header_seed_import_maybe(fx.cdir, &ms);
        size_t n = block_map_count(&ms.map_block_index);
        main_state_free(&ms);
        ASSERT(!r);
        ASSERT(n == 0);
        ASSERT(hsi_exists(fx.bundle));
        ASSERT(!hsi_blocker_named("header_seed.stage_failed"));
        ASSERT(!hsi_blocker_named("header_seed.load_failed"));
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
        bool r = boot_header_seed_import_maybe(fx.cdir, &ms);
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
 * (cp_height, hash); returns 1 when the import reports it owns the
 * checkpoint, 0 when it names checkpoint_unbound, -1 when import failed. */
static int hsi_checkpoint_run(int32_t cp_height, int hash_row, int flip_byte)
{
    struct hsi_fx fx;
    if (!hsi_fx_make(&fx, 8, HSI_COPY_FULL)) {
        hsi_fx_free(&fx);
        return -1;
    }
    static struct sha3_utxo_checkpoint cp;
    memset(&cp, 0, sizeof(cp));
    cp.height = cp_height;
    struct uint256 want = hash_row < 0 ? fx.tip : hsi_make_hash(hash_row);
    memcpy(cp.block_hash, want.data, sizeof(cp.block_hash));
    if (flip_byte >= 0)
        cp.block_hash[flip_byte] ^= 0x01;
    hsi_clear_blockers();
    checkpoints_set_sha3_override_for_test(&cp);
    struct main_state ms;
    main_state_init(&ms);
    bool r = boot_header_seed_import_maybe(fx.cdir, &ms);
    checkpoints_reset_sha3_override_for_test();
    main_state_free(&ms);
    int owned = r ? !hsi_blocker_named("header_seed.checkpoint_unbound") : -1;
    hsi_fx_free(&fx);
    return owned;
}

static int case_checkpoint_binding(void)
{
    int failures = 0;
    TEST("boot_header_seed: checkpoint ownership needs the exact hash at a reachable height") {
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

static int hsi_mutant_tests(void)
{
    int failures = 0;
    failures += case_args_and_env_refused();
    failures += case_population_cap_boundary();
    failures += case_hostile_artifact_rejected();
    failures += case_root_copy_present_is_left_alone();
    failures += case_rename_failure_named();
    failures += case_no_artifact_and_long_path_are_silent();
    failures += case_clamp_every_row_and_persist();
    failures += case_checkpoint_binding();
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
