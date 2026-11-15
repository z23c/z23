/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_bundle_install_ready, legacy install at a baked rung: the 28 full
 * headers rung-27..rung must be durable (the pending boot after the install
 * does no network fetch) before the install is armed. Included once by
 * test_consensus_state_install_runtime.c. */

#ifndef CONSENSUS_STATE_RUNG_WINDOW_TEST_H
#define CONSENSUS_STATE_RUNG_WINDOW_TEST_H

#include "config/flysync_island.h"
#include "core/arith_uint256.h"
#include "jobs/stage_repair.h"
#include "net/checkpoint_header_fetch.h"
#include "services/island_anchor.h"
#include "storage/node_db_runtime.h"
#include "test/test_flysync_island_common.h"

struct crw_fixture {
    char dir[256];
    struct main_state ms;
    struct fsi_island is;
    struct block_index *own[FSI_W];          /* top first: own[0] is the rung */
    struct sha3_utxo_checkpoint cp;
    bool ready;
};

/* This node's header chain at rung-27..rung. Rows at and below `divert` carry a
 * different hash than the peers' chain (the own index differs). */
static bool crw_chain(struct crw_fixture *f, int divert)
{
    struct block_index *prev = NULL;
    for (int i = FSI_W - 1; i >= 0; i--) {
        struct uint256 hash = f->is.hash[i];
        if (divert >= 0 && i >= divert)
            hash.data[31] ^= 0x77;
        struct block_index *bi = chainstate_insert_block_index((struct chainstate *)&f->ms, &hash);
        if (!bi)
            return false;
        bi->nHeight = FSI_RUNG_H - i;
        bi->pprev = prev;
        bi->nStatus = BLOCK_VALID_TREE;
        if (i == 0)
            bi->nChainWork = f->is.rung_work;
        f->own[i] = prev = bi;
    }
    f->ms.pindex_best_header = f->own[0];
    memset(&f->cp, 0, sizeof(f->cp));
    f->cp.height = FSI_RUNG_H - (FSI_W - 1);
    memcpy(f->cp.block_hash, f->own[FSI_W - 1]->phashBlock->data, 32);
    checkpoints_set_sha3_override_for_test(&f->cp);
    return true;
}

static bool crw_open(struct crw_fixture *f, const char *tag, int divert)
{
    memset(f, 0, sizeof(*f));
    main_state_init(&f->ms);
    fsi_build_island(&f->is);
    checkpoints_set_rom_state_rungs_override_for_test(&f->is.rung, 1);
    flysync_island_test_reset();
    flysync_island_test_set_rung(&f->is.rung);
    flysync_island_test_set_frozen_verifier(fsi_accept_all);
    checkpoint_header_fetch_test_reset();
    checkpoint_bundle_install_ready_test_reset();
    checkpoint_bundle_install_ready_test_suppress_restart(true);
    test_make_tmpdir(f->dir, sizeof(f->dir), "crw", tag);
    char bundles[320], name[96];
    snprintf(bundles, sizeof(bundles), "%s/bundles", f->dir);
    snprintf(name, sizeof(name), "consensus-state-bundle-%d.sqlite", FSI_RUNG_H);
    checkpoint_bundle_install_ready_test_set_main_state(&f->ms);
    checkpoint_bundle_install_ready_test_set_datadir(f->dir);
    /* The single-header repair already persisted the rung's own solution. */
    f->ready = mkdir(bundles, 0700) == 0 && csir_touch(bundles, name) && crw_chain(f, divert) &&
        progress_store_open(f->dir) &&
        stage_repair_header_solution_save(progress_store_db(), FSI_RUNG_H, &f->is.hash[0], &f->is.w[0]);
    return f->ready;
}

static void crw_close(struct crw_fixture *f)
{
    checkpoint_bundle_install_ready_test_reset();
    checkpoint_header_fetch_test_reset();
    flysync_island_test_reset();
    checkpoints_reset_rom_state_rungs_override_for_test();
    checkpoints_reset_sha3_override_for_test();
    progress_store_close();
    test_cleanup_tmpdir(f->dir);
    main_state_free(&f->ms);
}

/* The peers' chain arrives through the existing hash-pinned window walk. */
static void crw_deliver(const struct crw_fixture *f)
{
    for (int i = 0; i < FSI_W; i++)
        checkpoint_header_fetch_offer(&f->is.w[i], &f->is.hash[i]);
}

/* Rows below the rung that load through the pending restore's loader. */
static int crw_staged(const struct crw_fixture *f)
{
    int n = 0;
    for (int i = 1; i < FSI_W; i++) {
        struct block_header h;
        n += node_db_runtime_load_header_by_hash_height(FSI_RUNG_H - i, f->is.hash[i].data, &h);
    }
    return n;
}

/* A walk armed by the condition with no reply yet still counts as progress, so
 * the bounded attempt budget does not latch before the first reply. */
static int crw_waiting_walk_progresses(const struct crw_fixture *f)
{
    int failures = 0;
    CSIR_CHECK("rung window: a walk still waiting on its first reply keeps the budget from latching",
               f->ready && checkpoint_header_fetch_window_progress() == 0 &&
               checkpoint_bundle_install_ready_test_progressing());
    return failures;
}

static int crw_case_stage_then_arm(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("rung window: fixture opens", crw_open(&f, "stage", -1));
    CSIR_CHECK("rung window: detect fires once the rung solution is durable",
               f.ready && checkpoint_bundle_install_ready_test_detect());
    CSIR_CHECK("rung window: window not durable -> walk armed, install NOT armed",
               f.ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_SKIP &&
               !boot_install_bundle_pending(f.dir) && checkpoint_header_fetch_is_armed() &&
               blocker_exists("checkpoint_rung_window_pending") && crw_staged(&f) == 0);
    failures += crw_waiting_walk_progresses(&f);
    CSIR_CHECK("rung window: a second tick does not re-arm a walk that is moving",
               f.ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_SKIP &&
               checkpoint_header_fetch_window_progress() == 0 && checkpoint_header_fetch_is_armed());
    crw_deliver(&f);
    CSIR_CHECK("rung window: the walk completes from the compiled rung hash",
               checkpoint_header_fetch_window_progress() == FSI_W);
    CSIR_CHECK("rung window: verified window staged, then the install arms",
               f.ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_OK &&
               boot_install_bundle_pending(f.dir) && crw_staged(&f) == FSI_W - 1 &&
               !blocker_exists("checkpoint_rung_window_pending"));
    CSIR_CHECK("rung window: island state stays NONE, nothing registered",
               island_anchor_state_load(progress_store_db()) == ISLAND_ANCHOR_STATE_NONE &&
               !island_anchor_registered());
    crw_close(&f);
    return failures;
}

static int crw_case_work_mismatch(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("rung work: fixture opens", crw_open(&f, "work", -1));
    if (f.ready) {
        struct arith_uint256 one, sum;
        arith_uint256_set_u64(&one, 1);
        arith_uint256_add(&sum, &f.own[0]->nChainWork, &one);
        f.own[0]->nChainWork = sum;
    }
    CSIR_CHECK("rung work: own chainwork != compiled rung chainwork -> hard refusal",
               f.ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_FAILED &&
               !boot_install_bundle_pending(f.dir) && !checkpoint_header_fetch_is_armed() &&
               crw_staged(&f) == 0);
    crw_close(&f);
    return failures;
}

static int crw_case_fetched_differs(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("own index differs: fixture opens", crw_open(&f, "differs", 5));
    CSIR_CHECK("own index differs: walk armed",
               f.ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_SKIP &&
               checkpoint_header_fetch_is_armed());
    crw_deliver(&f);
    CSIR_CHECK("own index differs: fetched window refused, nothing staged, install not armed",
               f.ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_SKIP &&
               !boot_install_bundle_pending(f.dir) && crw_staged(&f) == 0);
    CSIR_CHECK("own index differs: one refused window still waits on a re-armed walk",
               f.ready && checkpoint_header_fetch_is_armed() &&
               checkpoint_bundle_install_ready_test_progressing());
    bool refused = f.ready;
    for (int i = 0; refused && i < 2; i++) {
        crw_deliver(&f);
        refused = checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_SKIP;
    }
    CSIR_CHECK("own index differs: after 3 refused windows the walk stops counting as progress "
               "(the attempt budget latches), install never armed",
               refused && !checkpoint_bundle_install_ready_test_progressing() &&
               !boot_install_bundle_pending(f.dir) && crw_staged(&f) == 0);
    crw_close(&f);
    return failures;
}

static struct uint256 g_crw_bad;
static bool crw_reject_one(const struct uint256 *hash, const struct block_header *hdr)
{
    (void)hdr;
    return !uint256_eq(hash, &g_crw_bad);
}

static int crw_case_equihash(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("equihash: fixture opens", crw_open(&f, "equihash", -1));
    g_crw_bad = f.is.hash[3];
    flysync_island_test_set_frozen_verifier(crw_reject_one);
    CSIR_CHECK("equihash: walk armed",
               f.ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_SKIP);
    crw_deliver(&f);
    CSIR_CHECK("equihash: one failing header refuses the whole window; nothing staged",
               f.ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_SKIP &&
               !boot_install_bundle_pending(f.dir) && crw_staged(&f) == 0);
    crw_close(&f);
    return failures;
}

/* The install armed exactly as before: no window attempted, nothing staged. */
static bool crw_armed_without_window(const struct crw_fixture *f)
{
    return f->ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_OK &&
           boot_install_bundle_pending(f->dir) && !checkpoint_header_fetch_is_armed() &&
           crw_staged(f) == 0;
}

/* -flysync, a registered island and a stored island state keep their own
 * route. */
static int crw_case_flysync_route(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("route: fixture opens", crw_open(&f, "flysync", -1));
    flysync_island_set_requested(true);
    CSIR_CHECK("route: -flysync arms without a window attempt", crw_armed_without_window(&f));
    flysync_island_set_requested(false);
    crw_close(&f);
    return failures;
}

static int crw_case_island_route(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("route: second fixture opens", crw_open(&f, "island", -1));
    struct island_anchor other = {0};
    other.root_height = 100; other.rung_height = 127;
    other.root_hash.data[0] = 1; other.rung_hash.data[0] = 2; other.root_work.pn[0] = 1;
    CSIR_CHECK("route: a registered island arms without a window attempt",
               island_anchor_register(&other).ok && crw_armed_without_window(&f));
    island_anchor_unregister();
    crw_close(&f);
    return failures;
}

static int crw_case_stored_route(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("route: third fixture opens", crw_open(&f, "stored", -1));
    uint8_t seeded = ISLAND_ANCHOR_STATE_SEEDED;
    CSIR_CHECK("route: a stored island state (SEEDED, none registered) arms without a window attempt",
               f.ready && progress_meta_set(progress_store_db(), "flysync.island_state", &seeded, 1) &&
               island_anchor_state_load(progress_store_db()) == ISLAND_ANCHOR_STATE_SEEDED &&
               crw_armed_without_window(&f));
    crw_close(&f);
    return failures;
}

/* Once the window is durable the condition no longer waits on its walk, so a
 * leftover armed walk never resets the attempt budget for later rounds. */
static int crw_case_ready_stops_progress(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("budget: fixture opens", crw_open(&f, "budget", -1));
    CSIR_CHECK("budget: walk armed",
               f.ready && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_SKIP &&
               checkpoint_header_fetch_is_armed());
    bool staged = f.ready;
    for (int i = 1; staged && i < FSI_W; i++)
        staged = stage_repair_header_solution_save(progress_store_db(), FSI_RUNG_H - i,
                                                   &f.is.hash[i], &f.is.w[i]);
    CSIR_CHECK("budget: window durable without the walk, the install arms",
               staged && checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_OK &&
               boot_install_bundle_pending(f.dir));
    (void)checkpoint_bundle_install_ready_test_progressing(); /* consume the round's baseline */
    CSIR_CHECK("budget: after READY the still-armed walk no longer counts as progress",
               staged && !checkpoint_bundle_install_ready_test_progressing());
    crw_close(&f);
    return failures;
}

static int case_rung_window_condition(void)
{
    return crw_case_stage_then_arm() + crw_case_work_mismatch() + crw_case_fetched_differs() +
           crw_case_equihash() + crw_case_flysync_route() + crw_case_island_route() +
           crw_case_stored_route() + crw_case_ready_stops_progress();
}

#endif /* CONSENSUS_STATE_RUNG_WINDOW_TEST_H */
