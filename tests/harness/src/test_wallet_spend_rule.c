/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Phone spend rule (-spend-after-checkpoint): the send-time gate in
 * controllers/wallet_spend_gate.h, the funds floor on note and coin selection,
 * and the boundaries around it.
 *
 * The compiled checkpoint is replaced through the test override with one that
 * matches a synthetic header chain, so every gate check is exercised against
 * real block_index ancestry, a real progress store (Sapling anchor ledger and
 * history cursor) and the real strict guard. No private key, address, memo or
 * amount of a real wallet is involved. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "controllers/sovereignty_controller.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_shielded_controller.h"
#include "controllers/wallet_shielded_internal.h"
#include "controllers/sync_controller.h"
#include "consensus/upgrades.h"
#include "primitives/block.h"
#include "sapling/params_init.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "storage/disk_block_io.h"
#include "validation/sighash.h"
#include "core/amount.h"
#include "support/cleanse.h"
#include "controllers/wallet_spend_gate.h"
#include "controllers/wallet_controller.h"
#include "coins/coins_view.h"
#include "rpc/server.h"
#include "validation/txmempool.h"
#include "controllers/wallet_view_internal.h"
#include "config/consensus_state_snapshot_install.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/sync_trust_policy.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "wallet/wallet.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <sched.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WSR_CHECK(name, expr) do {                                          \
    if (expr) { printf("  wallet_spend_rule: %s... OK\n", (name)); }         \
    else { printf("  wallet_spend_rule: %s... FAIL\n", (name)); failures++; }\
} while (0)

#define WSR_TIP 24          /* validated tip height (hstar) */
#define WSR_KEY_H 10        /* compiled keystone height */
#define WSR_FRONTIER_H 8    /* compiled Sapling frontier height */

struct wsr_chain {
    struct block_index bi[WSR_TIP + 1];
    uint8_t frontier_root[32];
    uint8_t tip_root[32];
};

static void wsr_tree_root(int leaves, uint8_t out[32])
{
    struct incremental_merkle_tree t;
    struct uint256 root;
    sapling_tree_init(&t);
    for (int i = 0; i < leaves; i++) {
        struct uint256 cm;
        uint256_set_null(&cm);
        cm.data[0] = (uint8_t)(0x40 + i);
        incremental_tree_append(&t, &cm);
    }
    incremental_tree_root(&t, &root);
    memcpy(out, root.data, 32);
}

/* Heights 0..WSR_TIP linked by pprev. `branch` tags every block above
 * `fork_above`, so a second chain can share ancestry up to that height. */
static void wsr_build(struct wsr_chain *c, uint8_t branch, int fork_above)
{
    memset(c, 0, sizeof(*c));
    wsr_tree_root(1, c->frontier_root);
    wsr_tree_root(2, c->tip_root);
    for (int h = 0; h <= WSR_TIP; h++) {
        struct block_index *b = &c->bi[h];
        block_index_init(b);
        b->nHeight = h;
        b->hashBlock.data[0] = (uint8_t)(h + 1);
        b->hashBlock.data[1] = h > fork_above ? branch : 0;
        b->phashBlock = &b->hashBlock;
        b->pprev = h ? &c->bi[h - 1] : NULL;
        memcpy(b->hashFinalSaplingRoot.data,
               h >= WSR_FRONTIER_H ? c->frontier_root : c->tip_root, 32);
    }
    memcpy(c->bi[WSR_TIP].hashFinalSaplingRoot.data, c->tip_root, 32);
}

static void wsr_checkpoint(struct rom_state_checkpoint *cp,
                           const struct wsr_chain *c, int height,
                           int frontier_height)
{
    memset(cp, 0, sizeof(*cp));
    cp->height = height;
    memcpy(cp->block_hash, c->bi[height].hashBlock.data, 32);
    cp->sapling_frontier_height = frontier_height;
    memcpy(cp->sapling_frontier_root, c->frontier_root, 32);
}

static void wsr_state(struct main_state *ms, struct wsr_chain *c)
{
    main_state_init(ms);
    active_chain_move_window_tip(&ms->chain_active, &c->bi[WSR_TIP]);
    ms->pindex_best_header = &c->bi[WSR_TIP];
}

static bool wsr_store(const char *dir, int64_t cursor, bool init,
                      const uint8_t root[32], int64_t nf_cursor)
{
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    if (!db || !anchor_kv_ensure_schema(db) || !nullifier_kv_ensure_schema(db))
        return false;
    if (init && !anchor_kv_initialize_history(db, cursor))
        return false;
    if (nf_cursor >= 0 && !nullifier_kv_initialize_history(db, nf_cursor))
        return false;
    if (root) {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        for (int i = 0; i < 2; i++) {
            struct uint256 cm;
            uint256_set_null(&cm);
            cm.data[0] = (uint8_t)(0x40 + i);
            incremental_tree_append(&t, &cm);
        }
        if (!anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &t, WSR_TIP))
            return false;
    }
    return true;
}

/* Anchor cursor `cursor`; nullifier cursor 0 (complete) when the anchor history
 * is initialised, absent otherwise. */
static bool wsr_anchor_store(const char *dir, int64_t cursor, bool init,
                             const uint8_t root[32])
{
    return wsr_store(dir, cursor, init, root, init ? 0 : -1);
}

static bool wsr_eval(const struct main_state *ms, int32_t hstar,
                     const char *want_reason, int32_t want_floor);

/* A reader that holds the progress-store lock for `hold_ms`. */
struct wsr_hold {
    int hold_ms;
    atomic_int held;
};

static void *wsr_hold_lock(void *arg)
{
    struct wsr_hold *h = arg;
    const struct timespec nap = { h->hold_ms / 1000,
                                  (long)(h->hold_ms % 1000) * 1000000L };
    progress_store_tx_lock();
    atomic_store(&h->held, 1);
    nanosleep(&nap, NULL);
    progress_store_tx_unlock();
    return NULL;
}

/* The gate waits for a busy progress lock instead of failing on it, and
 * reports floor_unknown only when the wait runs out. Needs an open store whose
 * floor is 15 (see the caller). */
static int wsr_test_busy_progress_lock(const struct main_state *ms)
{
    int failures = 0;
    struct wsr_hold h = { .hold_ms = 150 };
    pthread_t th;
    atomic_init(&h.held, 0);
    WSR_CHECK("lock holder starts", pthread_create(&th, NULL, wsr_hold_lock,
                                                   &h) == 0);
    while (!atomic_load(&h.held))
        sched_yield();
    WSR_CHECK("a brief hold by another thread does not refuse the gate",
              wsr_eval(ms, WSR_TIP, "", 15));
    pthread_join(th, NULL);

    h.hold_ms = 400;
    atomic_store(&h.held, 0);
    sovereignty_progress_wait_ms_set(30);
    WSR_CHECK("second lock holder starts",
              pthread_create(&th, NULL, wsr_hold_lock, &h) == 0);
    while (!atomic_load(&h.held))
        sched_yield();
    WSR_CHECK("a hold that outlasts the bounded wait gives floor_unknown",
              wsr_eval(ms, WSR_TIP, "floor_unknown", 0));
    pthread_join(th, NULL);
    sovereignty_progress_wait_ms_set(SOV_PROGRESS_WAIT_MS_DEFAULT);
    WSR_CHECK("the gate passes again once the lock is free",
              wsr_eval(ms, WSR_TIP, "", 15));
    return failures;
}

/* Reasons, floors and verdicts of one evaluate call. */
static bool wsr_eval(const struct main_state *ms, int32_t hstar,
                     const char *want_reason, int32_t want_floor)
{
    char reason[WALLET_SPEND_REASON_MAX] = {0};
    int32_t floor = 12345;
    bool ok = wallet_spend_gate_evaluate(ms, hstar, &floor, reason,
                                         sizeof(reason));
    if (want_reason[0])
        return !ok && strcmp(reason, want_reason) == 0 &&
               floor == WALLET_SPEND_NO_FLOOR;
    return ok && reason[0] == '\0' && floor == want_floor;
}

static int wsr_test_gate_checks(void)
{
    int failures = 0;
    char dir[256];
    struct wsr_chain main_chain;
    struct wsr_chain fork_chain;
    struct main_state ms;
    struct rom_state_checkpoint cp;
    struct rom_state_rung no_rungs[1];
    memset(no_rungs, 0, sizeof(no_rungs));

    wsr_build(&main_chain, 0, WSR_TIP);
    wsr_state(&ms, &main_chain);
    wsr_checkpoint(&cp, &main_chain, WSR_KEY_H, WSR_FRONTIER_H);
    checkpoints_set_rom_state_override_for_test(&cp);
    checkpoints_set_rom_state_rungs_override_for_test(no_rungs, 0);

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "gate");
    WSR_CHECK("store opens with anchor ledger and cursor 12",
              wsr_anchor_store(dir, 12, true, main_chain.tip_root));
    WSR_CHECK("all checks pass; floor = max(keystone, cursor) = 12",
              wsr_eval(&ms, WSR_TIP, "", 12));

    struct rom_state_checkpoint bad = cp;
    bad.block_hash[5] ^= 0x5a;
    checkpoints_set_rom_state_override_for_test(&bad);
    WSR_CHECK("wrong checkpoint hash refuses (tip_not_descended)",
              wsr_eval(&ms, WSR_TIP, "tip_not_descended", 0));

    bad = cp;
    bad.sapling_frontier_root[7] ^= 0x33;
    checkpoints_set_rom_state_override_for_test(&bad);
    WSR_CHECK("wrong frontier root refuses (checkpoint_mismatch)",
              wsr_eval(&ms, WSR_TIP, "checkpoint_mismatch", 0));

    bad = cp;
    bad.height = WSR_TIP + 1;
    checkpoints_set_rom_state_override_for_test(&bad);
    WSR_CHECK("checkpoint above the validated tip refuses (checkpoint_missing)",
              wsr_eval(&ms, WSR_TIP, "checkpoint_missing", 0));

    memset(&bad, 0, sizeof(bad));
    checkpoints_set_rom_state_override_for_test(&bad);
    WSR_CHECK("unbaked placeholder refuses (checkpoint_missing)",
              wsr_eval(&ms, WSR_TIP, "checkpoint_missing", 0));
    checkpoints_set_rom_state_override_for_test(&cp);

    {
        struct main_state fms;
        wsr_build(&fork_chain, 7, WSR_KEY_H - 2);
        wsr_state(&fms, &fork_chain);
        WSR_CHECK("tip on a fork below the checkpoint refuses "
                  "(tip_not_descended)",
                  wsr_eval(&fms, WSR_TIP, "tip_not_descended", 0));
        main_state_free(&fms);
    }

    {
        struct block_index *saved = main_chain.bi[WSR_KEY_H - 1].pprev;
        main_chain.bi[WSR_KEY_H - 1].pprev = NULL;
        WSR_CHECK("header chain gap below the checkpoint refuses "
                  "(checkpoint_missing)",
                  wsr_eval(&ms, WSR_TIP, "checkpoint_missing", 0));
        main_chain.bi[WSR_KEY_H - 1].pprev = saved;
    }

    main_chain.bi[WSR_TIP].hashFinalSaplingRoot.data[3] ^= 0x77;
    WSR_CHECK("tip header root absent from the Sapling ledger refuses "
              "(anchor_root_mismatch)",
              wsr_eval(&ms, WSR_TIP, "anchor_root_mismatch", 0));
    main_chain.bi[WSR_TIP].hashFinalSaplingRoot.data[3] ^= 0x77;

    ms.pindex_best_header = &main_chain.bi[WSR_TIP];
    {
        struct block_index far = main_chain.bi[WSR_TIP];
        far.nHeight = WSR_TIP + WALLET_SPEND_TIP_SLACK + 1;
        ms.pindex_best_header = &far;
        WSR_CHECK("validated tip behind the best header refuses (behind_tip)",
                  wsr_eval(&ms, WSR_TIP, "behind_tip", 0));
        far.nHeight = WSR_TIP + WALLET_SPEND_TIP_SLACK;
        WSR_CHECK("within the slack the check passes",
                  wsr_eval(&ms, WSR_TIP, "", 12));
        ms.pindex_best_header = &main_chain.bi[WSR_TIP];
    }

    WSR_CHECK("no validated tip refuses (tip_not_validated)",
              wsr_eval(&ms, 0, "tip_not_validated", 0));
    WSR_CHECK("null chain state refuses (tip_not_validated)",
              wsr_eval(NULL, WSR_TIP, "tip_not_validated", 0));

    {
        struct rom_state_rung rung;
        memset(&rung, 0, sizeof(rung));
        wsr_checkpoint(&rung.cp, &main_chain, WSR_TIP - 2, WSR_FRONTIER_H);
        checkpoints_set_rom_state_rungs_override_for_test(&rung, 1);
        WSR_CHECK("a matching baked rung below the tip passes",
                  wsr_eval(&ms, WSR_TIP, "", 12));
        rung.cp.block_hash[2] ^= 0x11;
        WSR_CHECK("a baked rung off the active chain refuses",
                  wsr_eval(&ms, WSR_TIP, "tip_not_descended", 0));
        rung.cp.height = WSR_TIP + 5;
        WSR_CHECK("a baked rung above the tip is not yet required",
                  wsr_eval(&ms, WSR_TIP, "", 12));
        checkpoints_set_rom_state_rungs_override_for_test(no_rungs, 0);
    }

    progress_store_close();
    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "cursor_low");
    WSR_CHECK("store with cursor below the keystone",
              wsr_anchor_store(dir, 3, true, main_chain.tip_root));
    WSR_CHECK("floor is the keystone height when the cursor is lower",
              wsr_eval(&ms, WSR_TIP, "", WSR_KEY_H));
    progress_store_close();

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "cursor_none");
    WSR_CHECK("store without a history cursor",
              wsr_anchor_store(dir, 0, false, main_chain.tip_root));
    WSR_CHECK("unreadable cursor refuses (floor_unknown)",
              wsr_eval(&ms, WSR_TIP, "floor_unknown", 0));
    progress_store_close();

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "nf_cursor");
    WSR_CHECK("store with anchor cursor 3 and nullifier cursor 15",
              wsr_store(dir, 3, true, main_chain.tip_root, 15));
    WSR_CHECK("floor is the nullifier cursor when it is the highest (15)",
              wsr_eval(&ms, WSR_TIP, "", 15));
    failures += wsr_test_busy_progress_lock(&ms);
    progress_store_close();

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "nf_none");
    WSR_CHECK("store with an anchor cursor and no nullifier marker",
              wsr_store(dir, 3, true, main_chain.tip_root, -1));
    WSR_CHECK("absent nullifier cursor refuses (floor_unknown)",
              wsr_eval(&ms, WSR_TIP, "floor_unknown", 0));
    progress_store_close();

    {
        uint8_t good[32];
        uint8_t other[32];
        memcpy(good, main_chain.tip_root, 32);
        memcpy(other, good, 32);
        other[9] ^= 0x01;
        WSR_CHECK("witness root equal to the header root passes",
                  wallet_spend_gate_witness_root_ok(&ms, WSR_TIP, good));
        WSR_CHECK("witness root differing from the header root refuses",
                  !wallet_spend_gate_witness_root_ok(&ms, WSR_TIP, other));
        WSR_CHECK("witness at a height with no header refuses",
                  !wallet_spend_gate_witness_root_ok(&ms, WSR_TIP + 9, good));
    }

    checkpoints_reset_rom_state_override_for_test();
    checkpoints_reset_rom_state_rungs_override_for_test();
    main_state_free(&ms);
    return failures;
}

static int wsr_test_floor_filters(void)
{
    int failures = 0;
    int heights[5] = {5, 12, 13, 0, 40};
    bool want[5] = {false, false, true, false, true};
    bool ok = true, all = true;
    for (int i = 0; i < 5; i++) {
        ok &= wallet_spend_gate_height_ok(12, heights[i]) == want[i];
        all &= wallet_spend_gate_height_ok(WALLET_SPEND_NO_FLOOR, heights[i]);
    }
    WSR_CHECK("no floor admits every height", all);
    WSR_CHECK("floor 12 admits only heights above it (13 and 40); a height at "
              "the floor and an unknown height (0) are excluded", ok);

    char msg[160];
    wallet_spend_gate_shortfall_message(msg, sizeof(msg), 1000, 400);
    WSR_CHECK("shortfall message names the refusal and the shortfall",
              strstr(msg, "insufficient_post_checkpoint_funds") &&
                  strstr(msg, "short by 600 zat"));

    char dir[256];
    struct node_db ndb;
    char dbpath[320];
    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "utxo");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    WSR_CHECK("node.db opens", node_db_open(&ndb, dbpath));
    uint8_t addr[20] = {0x61};
    uint8_t script[4] = {0x76, 0xa9, 0x14, 0x00};
    struct {
        uint8_t id;
        int64_t value;
        int height;
    } coins[] = {{1, 9000, 5}, {2, 500, 12}, {3, 700, 15}};
    for (size_t i = 0; i < 3; i++) {
        struct db_wallet_utxo u;
        memset(&u, 0, sizeof(u));
        u.txid[0] = coins[i].id;
        u.vout = 0;
        u.value = coins[i].value;
        memcpy(u.address_hash, addr, 20);
        u.script = script;
        u.script_len = sizeof(script);
        u.height = coins[i].height;
        u.is_coinbase = false;
        WSR_CHECK("coin saved", db_wallet_utxo_save(&ndb, &u));
    }
    struct db_wallet_utxo sel[8];
    int n = db_wallet_utxo_select_coins_for_address(&ndb, 8000, 100, addr,
                                                    sel, 8);
    WSR_CHECK("no floor: the large pre-snapshot coin is selected",
              n >= 1 && sel[0].value == 9000);
    for (int i = 0; i < n; i++)
        db_wallet_utxo_free(&sel[i]);
    n = db_wallet_utxo_select_coins_for_address_above(&ndb, 8000, 100, addr,
                                                      12, sel, 8);
    int64_t total = 0;
    bool only_post = true;
    for (int i = 0; i < n; i++) {
        total += sel[i].value;
        if (sel[i].height <= 12)
            only_post = false;
        db_wallet_utxo_free(&sel[i]);
    }
    WSR_CHECK("floor 12: only the coin above it is a candidate",
              n == 1 && only_post && total == 700);
    WSR_CHECK("floor 12: the candidates fall short of 8000 (caller refuses, "
              "nothing is spent partly)", total < 8000);
    n = db_wallet_utxo_select_coins_for_address_above(&ndb, 600, 100, addr, 4,
                                                      sel, 8);
    for (int i = 0; i < n; i++)
        db_wallet_utxo_free(&sel[i]);
    WSR_CHECK("floor 4 admits the coins at 5, 12 and 15 largest first",
              n == 1);

    node_db_close(&ndb);
    return failures;
}

/* Opens the progress store at `dir` and initializes the coin, anchor and
 * nullifier schemas; the anchor history starts at `anchor_cursor`. */
static sqlite3 *wsr_store_prepare(const char *dir, int64_t anchor_cursor)
{
    if (!progress_store_open(dir))
        return NULL;
    sqlite3 *db = progress_store_db();
    if (!db || !coins_kv_ensure_schema(db) || !anchor_kv_ensure_schema(db) ||
        !nullifier_kv_ensure_schema(db) ||
        !anchor_kv_initialize_history(db, anchor_cursor) ||
        !nullifier_kv_initialize_history(db, 0))
        return NULL;
    return db;
}

/* A store at tip WSR_TIP. `stamp` writes the migration stamp that makes the
 * coin set borrowed; without it the strict guard reads the set as not borrowed. */
static bool wsr_seeded_store(const char *dir, bool self_folded,
                            int64_t anchor_cursor, bool stamp)
{
    sqlite3 *db = wsr_store_prepare(dir, anchor_cursor);
    if (!db)
        return false;
    uint8_t txid[32] = {0x51, 0x77};
    const unsigned char sc[4] = {0xE0, 0xE0, 0xE0, 0xE0};
    uint8_t one = 1;
    char *err = NULL;
    bool ok = coins_kv_add(db, txid, 0, 1234, WSR_TIP, true, sc, sizeof(sc)) &&
              sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
                  SQLITE_OK &&
              coins_kv_set_applied_height_in_tx(db, WSR_TIP + 1) &&
              (!stamp ||
               progress_meta_set_in_tx(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one,
                                       1)) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err)
        sqlite3_free(err);
    if (ok && self_folded)
        ok = coins_kv_mark_self_folded(db);
    return ok;
}

static bool wsr_borrowed_store_at(const char *dir, bool self_folded,
                                  int64_t anchor_cursor)
{
    return wsr_seeded_store(dir, self_folded, anchor_cursor, true);
}

static bool wsr_borrowed_store(const char *dir, bool self_folded)
{
    return wsr_borrowed_store_at(dir, self_folded, 12);
}

static int wsr_test_guard_boundaries(void)
{
    int failures = 0;
    char dir[256];
    struct wsr_chain c;
    struct main_state ms;
    struct rom_state_checkpoint cp;
    struct rom_state_rung no_rungs[1];
    memset(no_rungs, 0, sizeof(no_rungs));

    wsr_build(&c, 0, WSR_TIP);
    wsr_state(&ms, &c);
    wsr_checkpoint(&cp, &c, WSR_KEY_H, WSR_FRONTIER_H);
    checkpoints_set_rom_state_override_for_test(&cp);
    checkpoints_set_rom_state_rungs_override_for_test(no_rungs, 0);

    struct wallet_rpc_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.main_state = &ms;

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "borrowed");
    WSR_CHECK("borrowed store (migration stamp, no self-folded marker)",
              wsr_borrowed_store(dir, false));
    {
        sqlite3 *db = progress_store_db();
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        for (int i = 0; i < 2; i++) {
            struct uint256 cm;
            uint256_set_null(&cm);
            cm.data[0] = (uint8_t)(0x40 + i);
            incremental_tree_append(&t, &cm);
        }
        WSR_CHECK("Sapling ledger holds the tip root",
                  anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &t, WSR_TIP));
    }
    reducer_frontier_provable_tip_set(WSR_TIP);

    char reason[WALLET_SPEND_REASON_MAX];
    int32_t floor = 99;
    char strict[96];

    sovereignty_spend_after_checkpoint_set(false);
    WSR_CHECK("strict guard refuses the borrowed state",
              !sovereignty_guard_allow("wallet_spend", strict, sizeof(strict)));
    WSR_CHECK("option off: the gate refuses exactly as the guard does",
              !wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  strcmp(reason, "option_off") == 0 &&
                  floor == WALLET_SPEND_NO_FLOOR);

    sovereignty_spend_after_checkpoint_set(true);
    WSR_CHECK("option on, checks pass: allowed with floor 12",
              wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  floor == 12);
    WSR_CHECK("option on: the strict guard itself still refuses wallet_spend "
              "(zslp, market, vault, multisig, wallet view)",
              !sovereignty_guard_allow("wallet_spend", strict, sizeof(strict)));
    WSR_CHECK("option on: mint stays refused",
              !sovereignty_guard_allow("mint", strict, sizeof(strict)));

    enum sync_trust_state st = sync_trust_derive(true, false, false);
    WSR_CHECK("option on: policy table still refuses mine, seed and export",
              !sync_trust_cap_allowed(st, SYNC_CAP_MINE) &&
                  !sync_trust_cap_allowed(st, SYNC_CAP_SEED_BUNDLE) &&
                  !sync_trust_cap_allowed(st, SYNC_CAP_EXPORT_BUNDLE));

    ctx.main_state = NULL;
    WSR_CHECK("option on, no chain state: refused (tip_not_validated)",
              !wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  strcmp(reason, "tip_not_validated") == 0);
    ctx.main_state = &ms;

    {
        struct json_value params = {0};
        struct json_value result = {0};
        json_set_array(&params);
        WSR_CHECK("in-process rpc_z_sendmany stays refused with the option on",
                  !rpc_z_sendmany(&params, false, &result) &&
                      strstr(json_get_str(&result), "release_assisted"));
        json_free(&result);
        memset(&result, 0, sizeof(result));
        struct wallet_tx prepared;
        WSR_CHECK("z_sendmany_prepare (vault path) stays refused with the "
                  "option on",
                  !z_sendmany_prepare(&params, &prepared, &result) &&
                      strstr(json_get_str(&result), "release_assisted"));
        json_free(&result);
        json_free(&params);
    }

    {
        char verdict[48];
        sovereignty_spend_rule_last_verdict(verdict, sizeof(verdict));
        WSR_CHECK("diagnostics carry the last verdict token",
                  verdict[0] != '\0');
    }

    progress_store_close();
    sovereignty_spend_after_checkpoint_set(false);

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "selfderived");
    WSR_CHECK("self-derived store", wsr_borrowed_store(dir, true));
    reducer_frontier_provable_tip_set(WSR_TIP);
    floor = 99;
    WSR_CHECK("self-derived node: allowed with no floor, option off",
              wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  floor == WALLET_SPEND_NO_FLOOR);
    sovereignty_spend_after_checkpoint_set(true);
    floor = 99;
    WSR_CHECK("self-derived node: allowed with no floor, option on",
              wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  floor == WALLET_SPEND_NO_FLOOR);
    sovereignty_spend_after_checkpoint_set(false);

    reducer_frontier_provable_tip_reset();
    progress_store_close();
    checkpoints_reset_rom_state_override_for_test();
    checkpoints_reset_rom_state_rungs_override_for_test();
    main_state_free(&ms);
    return failures;
}

/* The ledger holds the tip root (header root at WSR_TIP). */
static bool wsr_add_tip_root(void)
{
    struct incremental_merkle_tree t;
    sapling_tree_init(&t);
    for (int i = 0; i < 2; i++) {
        struct uint256 cm;
        uint256_set_null(&cm);
        cm.data[0] = (uint8_t)(0x40 + i);
        incremental_tree_append(&t, &cm);
    }
    return anchor_kv_add_tree(progress_store_db(), ANCHOR_POOL_SAPLING, &t,
                              WSR_TIP);
}

static bool wsr_record_seam(int32_t height)
{
    sqlite3 *db = progress_store_db();
    uint8_t c[3][32] = {{1}, {2}, {3}};
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
                  SQLITE_OK &&
              consensus_state_install_record_assisted_seam(db, height, c[0],
                                                           c[1], c[2]) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err)
        sqlite3_free(err);
    return ok;
}

/* Declare (or, with a malformed blob, corrupt) the reducer seed floor, as a
 * cold import does. */
static bool wsr_put_seed_floor(int32_t height, bool malformed)
{
    sqlite3 *db = progress_store_db();
    uint8_t bad[3] = {1, 2, 3};
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
              SQLITE_OK;
    ok = ok && (malformed
        ? progress_meta_set_in_tx(db, REDUCER_SEED_FLOOR_HEIGHT_KEY, bad,
                                  sizeof(bad))
        : reducer_seed_floor_declare_if_absent(db, height));
    ok = sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, &err) ==
             SQLITE_OK && ok;
    if (err)
        sqlite3_free(err);
    return ok;
}

/* With the option on, the strict guard alone never removes the floor, and an
 * assisted install's seam height raises it. */
static int wsr_test_floor_authority(void)
{
    int failures = 0;
    char dir[256];
    char reason[WALLET_SPEND_REASON_MAX];
    char strict[96];
    int32_t floor = 99;
    struct wsr_chain c;
    struct main_state ms;
    struct rom_state_checkpoint cp;
    struct rom_state_rung no_rungs[1];
    memset(no_rungs, 0, sizeof(no_rungs));
    wsr_build(&c, 0, WSR_TIP);
    wsr_state(&ms, &c);
    wsr_checkpoint(&cp, &c, WSR_KEY_H, WSR_FRONTIER_H);
    checkpoints_set_rom_state_override_for_test(&cp);
    checkpoints_set_rom_state_rungs_override_for_test(no_rungs, 0);
    struct wallet_rpc_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.main_state = &ms;

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "unstamped");
    WSR_CHECK("store without the migration stamp and without the marker",
              wsr_seeded_store(dir, false, 12, false) && wsr_add_tip_root());
    reducer_frontier_provable_tip_set(WSR_TIP);
    WSR_CHECK("the strict guard allows it (a failed authority read looks the "
              "same)",
              sovereignty_guard_allow("wallet_spend", strict, sizeof(strict)));
    sovereignty_spend_after_checkpoint_set(false);
    WSR_CHECK("option off: allowed with no floor, as before",
              wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  floor == WALLET_SPEND_NO_FLOOR);
    sovereignty_spend_after_checkpoint_set(true);
    floor = 99;
    WSR_CHECK("option on: no marker, so the rule and its floor apply",
              wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  floor == 12);
    {
        char v[48];
        sovereignty_spend_rule_last_verdict(v, sizeof(v));
        WSR_CHECK("option on, marker absent: the verdict is not strict_guard",
                  strcmp(v, "strict_guard") != 0);
    }
    progress_store_close();

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "seam");
    WSR_CHECK("borrowed store with an assisted seam above both cursors",
              wsr_borrowed_store(dir, false) && wsr_add_tip_root() &&
                  wsr_record_seam(20));
    reducer_frontier_provable_tip_set(WSR_TIP);
    floor = 99;
    WSR_CHECK("the seam height 20 raises the floor above the cursor 12",
              wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  floor == 20);
    WSR_CHECK("a seam below the floor does not lower it",
              wsr_record_seam(3) &&
                  wallet_spend_gate_check(&ctx, &floor, reason,
                                          sizeof(reason)) &&
                  floor == 12);
    sovereignty_spend_after_checkpoint_set(false);
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    checkpoints_reset_rom_state_override_for_test();
    checkpoints_reset_rom_state_rungs_override_for_test();
    main_state_free(&ms);
    return failures;
}

/* A cold import records its seed floor and no seam, and the importer then sets
 * both cursors to 0: the seed floor is what keeps funds from the borrowed
 * state out. An unreadable seed floor refuses. */
static int wsr_test_seed_floor(void)
{
    int failures = 0;
    char dir[256];
    char reason[WALLET_SPEND_REASON_MAX];
    int32_t floor = 99;
    struct wsr_chain c;
    struct main_state ms;
    struct rom_state_checkpoint cp;
    struct rom_state_rung no_rungs[1];
    memset(no_rungs, 0, sizeof(no_rungs));
    wsr_build(&c, 0, WSR_TIP);
    wsr_state(&ms, &c);
    wsr_checkpoint(&cp, &c, WSR_KEY_H, WSR_FRONTIER_H);
    checkpoints_set_rom_state_override_for_test(&cp);
    checkpoints_set_rom_state_rungs_override_for_test(no_rungs, 0);
    struct wallet_rpc_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.main_state = &ms;
    sovereignty_spend_after_checkpoint_set(true);

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "coldimport");
    WSR_CHECK("cold-imported store: both cursors 0, no seam, seed floor 20",
              wsr_borrowed_store_at(dir, false, 0) && wsr_add_tip_root() &&
                  wsr_put_seed_floor(20, false));
    reducer_frontier_provable_tip_set(WSR_TIP);
    floor = 99;
    WSR_CHECK("the seed floor 20 is the floor when cursors are 0 and no seam "
              "is recorded (cold import)",
              wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  floor == 20);
    progress_store_close();

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "badseed");
    WSR_CHECK("store with a malformed seed floor",
              wsr_borrowed_store_at(dir, false, 12) && wsr_add_tip_root() &&
                  wsr_put_seed_floor(0, true));
    reducer_frontier_provable_tip_set(WSR_TIP);
    floor = 99;
    WSR_CHECK("an unreadable seed floor refuses with floor_unknown",
              !wallet_spend_gate_check(&ctx, &floor, reason, sizeof(reason)) &&
                  strcmp(reason, "floor_unknown") == 0 &&
                  floor == WALLET_SPEND_NO_FLOOR);
    sovereignty_spend_after_checkpoint_set(false);
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    checkpoints_reset_rom_state_override_for_test();
    checkpoints_reset_rom_state_rungs_override_for_test();
    main_state_free(&ms);
    return failures;
}

/* The wallet view's shield form spends through z_sendmany; the rule does not
 * reach it. */
static int wsr_test_shield_form(void)
{
    int failures = 0;
    char dir[256];
    static uint8_t page[262144];
    static const char body[] = "amount=1.0";
    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "shieldform");
    WSR_CHECK("borrowed store", wsr_borrowed_store(dir, false));
    sovereignty_spend_after_checkpoint_set(true);
    memset(page, 0, 4096);
    size_t n = serve_shield_confirm(page, sizeof(page),
                                    (const uint8_t *)body, strlen(body));
    page[n < sizeof(page) ? n : sizeof(page) - 1] = '\0';
    WSR_CHECK("option on: the shield form refuses, naming release_assisted",
              strstr((const char *)page, "release_assisted") != NULL &&
                  strstr((const char *)page, "Spend refused") != NULL);
    WSR_CHECK("and never reached the address lookup or the node",
              strstr((const char *)page, "No private address") == NULL &&
                  strstr((const char *)page, "Node Offline") == NULL);
    sovereignty_spend_after_checkpoint_set(false);
    progress_store_close();
    return failures;
}

/* ---- The gate against the compiled checkpoint table (no override). ---- */

#define WSR_COMPILED_KEYSTONE_H 3056758
#define WSR_COMPILED_FRONTIER_H 3056742

struct wsr_entry {
    int32_t h;
    uint8_t hash[32];
    uint8_t root[32];
};

static void wsr_entry_put(struct wsr_entry *list, size_t *count, int32_t h,
                          const uint8_t *hash, const uint8_t *root)
{
    size_t i = 0;
    while (i < *count && list[i].h != h)
        i++;
    if (i == *count) {
        memset(&list[i], 0, sizeof(list[i]));
        list[i].h = h;
        (*count)++;
    }
    if (hash)
        memcpy(list[i].hash, hash, 32);
    if (root)
        memcpy(list[i].root, root, 32);
}

static int wsr_entry_cmp(const void *a, const void *b)
{
    const struct wsr_entry *x = a, *y = b;
    return (x->h > y->h) - (x->h < y->h);
}

/* A sparse header chain through every compiled checkpoint at or below the tip
 * (the gate follows pprev, so heights need not be contiguous). */
static struct block_index *wsr_compiled_chain(struct block_index *nodes,
                                              size_t cap, int32_t tip_h,
                                              const uint8_t tip_root[32],
                                              bool wrong_frontier)
{
    struct wsr_entry list[64];
    size_t count = 0;
    const struct rom_state_checkpoint *ks = get_rom_state_checkpoint();
    uint8_t bad[32];
    memset(bad, 0x5A, sizeof(bad));
    wsr_entry_put(list, &count, ks->height, ks->block_hash, NULL);
    wsr_entry_put(list, &count, ks->sapling_frontier_height, NULL,
                  wrong_frontier ? bad : ks->sapling_frontier_root);
    for (size_t i = 0; i < get_rom_state_rung_count() && count < 60; i++) {
        const struct rom_state_rung *r = get_rom_state_rung_at(i);
        if (!r || r->cp.height > tip_h)
            continue;
        wsr_entry_put(list, &count, r->cp.height, r->cp.block_hash, NULL);
        wsr_entry_put(list, &count, r->cp.sapling_frontier_height, NULL,
                      r->cp.sapling_frontier_root);
    }
    uint8_t tip_hash[32];
    memset(tip_hash, 0xC7, sizeof(tip_hash));
    wsr_entry_put(list, &count, tip_h, tip_hash, tip_root);
    qsort(list, count, sizeof(list[0]), wsr_entry_cmp);
    if (count > cap)
        return NULL;
    for (size_t i = 0; i < count; i++) {
        struct block_index *b = &nodes[i];
        block_index_init(b);
        b->nHeight = list[i].h;
        memcpy(b->hashBlock.data, list[i].hash, 32);
        b->phashBlock = &b->hashBlock;
        b->pprev = i ? &nodes[i - 1] : NULL;
        memcpy(b->hashFinalSaplingRoot.data, list[i].root, 32);
    }
    return &nodes[count - 1];
}

static int wsr_test_compiled_table(void)
{
    int failures = 0;
    char dir[256];
    struct block_index nodes[64];
    struct main_state ms;
    uint8_t tip_root[32];
    const struct rom_state_checkpoint *ks = get_rom_state_checkpoint();
    checkpoints_reset_rom_state_override_for_test();
    checkpoints_reset_rom_state_rungs_override_for_test();
    WSR_CHECK("the compiled keystone is height 3056758 with frontier height "
              "3056742",
              ks && ks->height == WSR_COMPILED_KEYSTONE_H &&
                  ks->sapling_frontier_height == WSR_COMPILED_FRONTIER_H);
    if (!ks)
        return failures + 1;
    const int32_t tip_h = ks->height + 10;
    wsr_tree_root(2, tip_root);

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "compiled");
    WSR_CHECK("borrowed store with the tip root in the ledger",
              wsr_borrowed_store(dir, false) && wsr_add_tip_root());
    reducer_frontier_provable_tip_set(tip_h);

    main_state_init(&ms);
    struct block_index *tip =
        wsr_compiled_chain(nodes, 64, tip_h, tip_root, false);
    WSR_CHECK("sparse header chain through the compiled checkpoints",
              tip != NULL && active_chain_install_tip_slot(&ms.chain_active,
                                                           tip));
    ms.pindex_best_header = tip;
    WSR_CHECK("compiled table, matching headers: passes with the keystone "
              "height as the floor",
              wsr_eval(&ms, tip_h, "", WSR_COMPILED_KEYSTONE_H));

    tip = wsr_compiled_chain(nodes, 64, tip_h, tip_root, true);
    WSR_CHECK("compiled table, a different header root at the frontier "
              "height: checkpoint_mismatch",
              tip != NULL && wsr_eval(&ms, tip_h, "checkpoint_mismatch", 0));

    reducer_frontier_provable_tip_reset();
    progress_store_close();
    main_state_free(&ms);
    return failures;
}

static bool wsr_addr(uint8_t tag, char *out, size_t cap)
{
    struct tx_destination d;
    memset(&d, 0, sizeof(d));
    d.type = DEST_KEY_ID;
    memset(d.id.key.id.data, tag, 20);
    const struct chain_params *cp = chain_params_get();
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk = chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS,
                                                         &pk_len);
    const unsigned char *sc = chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS,
                                                         &sc_len);
    return encode_destination(&d, pk, pk_len, sc, sc_len, out, cap);
}

static bool wsr_save_coin(struct node_db *ndb, uint8_t id, int64_t value,
                          int height, uint8_t addr_tag)
{
    uint8_t script[4] = {0x76, 0xa9, 0x14, 0x00};
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    u.txid[0] = id;
    u.value = value;
    memset(u.address_hash, addr_tag, 20);
    u.script = script;
    u.script_len = sizeof(script);
    u.height = height;
    return db_wallet_utxo_save(ndb, &u);
}

/* The registered handler end to end up to coin selection: a wallet holding one
 * large coin below the floor and one small coin above it. */
static int wsr_test_rpc_selection(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[320];
    char from[128];
    char to[128];
    char body[512];
    struct wsr_chain c;
    struct main_state ms;
    struct rom_state_checkpoint cp;
    struct rom_state_rung no_rungs[1];
    struct node_db ndb;
    struct json_value params = {0};
    struct json_value result = {0};
    memset(no_rungs, 0, sizeof(no_rungs));

    wsr_build(&c, 0, WSR_TIP);
    wsr_state(&ms, &c);
    wsr_checkpoint(&cp, &c, WSR_KEY_H, WSR_FRONTIER_H);
    checkpoints_set_rom_state_override_for_test(&cp);
    checkpoints_set_rom_state_rungs_override_for_test(no_rungs, 0);

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "rpc");
    WSR_CHECK("borrowed store", wsr_borrowed_store(dir, false));
    {
        struct incremental_merkle_tree t;
        sapling_tree_init(&t);
        for (int i = 0; i < 2; i++) {
            struct uint256 cm;
            uint256_set_null(&cm);
            cm.data[0] = (uint8_t)(0x40 + i);
            incremental_tree_append(&t, &cm);
        }
        WSR_CHECK("ledger holds the tip root",
                  anchor_kv_add_tree(progress_store_db(), ANCHOR_POOL_SAPLING,
                                     &t, WSR_TIP));
    }
    reducer_frontier_provable_tip_set(WSR_TIP);

    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    WSR_CHECK("node.db opens", node_db_open(&ndb, dbpath));
    WSR_CHECK("addresses", wsr_addr(0x61, from, sizeof(from)) &&
                               wsr_addr(0x62, to, sizeof(to)));
    WSR_CHECK("pre-floor coin saved (height 5)",
              wsr_save_coin(&ndb, 1, 100000000, 5, 0x61));
    WSR_CHECK("post-floor coin saved (height 15)",
              wsr_save_coin(&ndb, 2, 20000, 15, 0x61));

    struct wallet *w = zcl_calloc(1, sizeof(*w), "wsr_wallet");
    WSR_CHECK("wallet allocated", w != NULL);
    if (!w) {
        node_db_close(&ndb);
        return failures + 1;
    }
    wallet_init(w);
    wallet_rpc_context_set_base(w, &ms, dir, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(&ndb);

    snprintf(body, sizeof(body),
             "[\"%s\",[{\"address\":\"%s\",\"amount\":0.0005}]]", from, to);
    WSR_CHECK("params parse", json_read(&params, body, strlen(body)));

    sovereignty_spend_after_checkpoint_set(false);
    json_set_null(&result);
    WSR_CHECK("option off: registered handler refuses as the strict guard",
              !rpc_z_sendmany_checkpoint(&params, false, &result) &&
                  strstr(json_get_str(&result), "release_assisted"));

    sovereignty_spend_after_checkpoint_set(true);
    json_set_null(&result);
    bool sent = rpc_z_sendmany_checkpoint(&params, false, &result);
    const char *msg = json_get_str(&result);
    WSR_CHECK("option on: the pre-floor coin is never selected; the "
              "post-floor funds fall short and nothing is spent",
              !sent && msg &&
                  strstr(msg, "insufficient_post_checkpoint_funds") &&
                  strstr(msg, "short by"));

    json_set_null(&result);
    sent = rpc_z_sendmany(&params, false, &result);
    msg = json_get_str(&result);
    WSR_CHECK("option on: the in-process entry stays on the strict guard",
              !sent && msg && strstr(msg, "release_assisted"));

    /* A request the post-floor coin covers passes selection and stops at
     * signing (this wallet holds no key), proving the floor admits it. */
    json_free(&params);
    memset(&params, 0, sizeof(params));
    snprintf(body, sizeof(body),
             "[\"%s\",[{\"address\":\"%s\",\"amount\":0.00001}]]", from, to);
    WSR_CHECK("params parse", json_read(&params, body, strlen(body)));
    json_set_null(&result);
    sent = rpc_z_sendmany_checkpoint(&params, false, &result);
    msg = json_get_str(&result);
    WSR_CHECK("option on: a send the post-floor coin covers is not refused "
              "for funds",
              !msg || !strstr(msg, "insufficient"));

    json_free(&params);
    json_free(&result);
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    wallet_free(w);
    free(w);
    node_db_close(&ndb);
    sovereignty_spend_after_checkpoint_set(false);
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    checkpoints_reset_rom_state_override_for_test();
    checkpoints_reset_rom_state_rungs_override_for_test();
    main_state_free(&ms);
    return failures;
}

/* ---- End to end: a seeded fixture (cursors 0, floor above zero) with real
 * Sapling notes, witnesses at the tip, a real block body that spends one
 * note, and the production prover and verifier. ---- */

#define WSR_NOTE_A_H 5      /* at or below the floor */
#define WSR_NOTE_B_H 15     /* above the floor, unspent */
#define WSR_NOTE_C_H 16     /* above the floor, spent in the block at 18 */
#define WSR_SPEND_H 18

struct wsr_real_note {
    uint8_t txid[32];
    uint8_t rcm[32];
    uint8_t cm[32];
    uint8_t nf[32];
    int64_t value;
    int height;
};

struct wsr_e2e {
    struct wallet *w;
    const struct sapling_key_entry *key;
    struct node_db ndb;
    struct wsr_real_note n[3];
    struct incremental_merkle_tree tree;
    uint8_t root[32];
};

static bool wsr_e2e_make_notes(struct wsr_e2e *e)
{
    static const int64_t values[3] = {9000000, 3000000, 4000000};
    static const int heights[3] = {WSR_NOTE_A_H, WSR_NOTE_B_H, WSR_NOTE_C_H};
    uint8_t ak[32], nk[32];
    struct uint256 root;
    bool ok = true;
    sapling_ask_to_ak(e->key->xsk.expsk.ask, ak);
    sapling_nsk_to_nk(e->key->xsk.expsk.nsk, nk);
    sapling_tree_init(&e->tree);
    for (int i = 0; i < 3 && ok; i++) {
        struct wsr_real_note *n = &e->n[i];
        struct uint256 cm;
        memset(n, 0, sizeof(*n));
        memset(n->txid, 0xA0 + i, 32);
        n->value = values[i];
        n->height = heights[i];
        ok = sapling_generate_r(n->rcm) &&
             sapling_compute_cm(e->key->diversifier, e->key->pk_d,
                                (uint64_t)n->value, n->rcm, n->cm);
        if (!ok)
            break;
        memcpy(cm.data, n->cm, 32);
        incremental_tree_append(&e->tree, &cm);
        ok = sapling_compute_nf(e->key->diversifier, e->key->pk_d,
                                (uint64_t)n->value, n->rcm, ak, nk,
                                (uint64_t)i, n->nf);
    }
    incremental_tree_root(&e->tree, &root);
    memcpy(e->root, root.data, 32);
    memory_cleanse(ak, sizeof(ak));
    memory_cleanse(nk, sizeof(nk));
    return ok;
}

/* Store note `i` and its witness at the tip. `bad_witness` replays one extra
 * leaf into the witness, so its root differs from the header root. */
static bool wsr_e2e_save_note(struct wsr_e2e *e, int i, bool bad_witness)
{
    const struct wsr_real_note *n = &e->n[i];
    uint8_t memo[512];
    struct incremental_merkle_tree t;
    struct incremental_witness w;
    struct byte_stream ws;
    memset(memo, 0xF6, sizeof(memo));
    if (!node_db_sync_sapling_note(&e->ndb, n->txid, 0, n->value, n->rcm,
                                   memo, sizeof(memo), e->key->ivk,
                                   e->key->diversifier, e->key->pk_d, n->cm,
                                   n->nf, n->height))
        return false;
    sapling_tree_init(&t);
    for (int j = 0; j < 3; j++) {
        struct uint256 cm;
        memcpy(cm.data, e->n[j].cm, 32);
        if (j <= i)
            incremental_tree_append(&t, &cm);
        if (j == i)
            incremental_witness_init(&w, &t);
        else if (j > i)
            incremental_witness_append(&w, &cm);
    }
    if (bad_witness) {
        struct uint256 extra;
        uint256_set_null(&extra);
        extra.data[0] = 0xEE;
        incremental_witness_append(&w, &extra);
    }
    stream_init(&ws, 4096);
    bool ok = incremental_witness_serialize(&w, &ws) &&
              db_sapling_note_save_witness_and_nullifier(
                  &e->ndb, n->txid, 0, ws.data, ws.size, WSR_TIP, n->nf);
    stream_free(&ws);
    return ok;
}

/* A block body at WSR_SPEND_H whose one transaction spends `nf`, written to
 * the datadir and registered as the active block at that height. */
static bool wsr_e2e_spend_block(struct main_state *ms, struct wsr_chain *c,
                                const char *dir, const uint8_t nf[32])
{
    struct block b;
    struct disk_block_pos pos;
    struct uint256 bh;
    const unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    block_init(&b);
    b.header.nVersion = 4;
    b.header.nTime = 1700000000u;
    b.header.nBits = 0x2000ffffu;
    memcpy(b.header.hashPrevBlock.data, c->bi[WSR_SPEND_H - 1].hashBlock.data,
           32);
    b.vtx = zcl_calloc(1, sizeof(struct transaction), "wsr_spend_block");
    if (!b.vtx)
        return false;
    b.num_vtx = 1;
    transaction_init(&b.vtx[0]);
    transaction_alloc(&b.vtx[0], 1, 1);
    b.vtx[0].overwintered = true;
    b.vtx[0].version = SAPLING_TX_VERSION;
    b.vtx[0].version_group_id = SAPLING_VERSION_GROUP_ID;
    b.vtx[0].vin[0].sequence = 0xffffffff;
    b.vtx[0].vout[0].value = COIN;
    b.vtx[0].v_shielded_spend =
        zcl_calloc(1, sizeof(struct spend_description), "wsr_spend_desc");
    if (!b.vtx[0].v_shielded_spend) {
        block_free(&b);
        return false;
    }
    b.vtx[0].num_shielded_spend = 1;
    memcpy(b.vtx[0].v_shielded_spend[0].nullifier.data, nf, 32);
    block_get_hash(&b, &bh);
    disk_block_pos_init(&pos);
    bool ok = write_block_to_disk(&b, &pos, dir, msg_start);
    block_free(&b);
    if (!ok)
        return false;
    struct block_index *bi = &c->bi[WSR_SPEND_H];
    bi->hashBlock = bh;
    bi->nStatus |= BLOCK_HAVE_DATA;
    bi->nFile = pos.nFile;
    bi->nDataPos = pos.nPos;
    bi->nTx = 1;
    return block_map_insert(&ms->map_block_index, &bi->hashBlock, bi);
}

/* The built transaction through the production verifier: every spend, every
 * output and the binding signature, over the real sighash. */
static bool wsr_e2e_verify(const struct wallet_tx *wtx,
                           const struct chain_params *cp, int height)
{
    struct precomputed_tx_data txdata;
    struct sighash_type ht;
    struct script empty;
    struct uint256 sighash;
    uint32_t branch = consensus_current_epoch_branch_id(height + 1,
                                                        &cp->consensus);
    ht.raw = SIGHASH_ALL;
    empty.size = 0;
    precompute_tx_data(&wtx->tx, &txdata);
    if (!signature_hash(&empty, &wtx->tx, NOT_AN_INPUT, ht, 0, branch, &txdata,
                        &sighash))
        return false;
    void *vc = zclassic_sapling_verification_ctx_init();
    if (!vc)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < wtx->tx.num_shielded_spend; i++) {
        const struct spend_description *s = &wtx->tx.v_shielded_spend[i];
        ok = zclassic_sapling_check_spend(vc, s->cv.data, s->anchor.data,
                                          s->nullifier.data, s->rk.data,
                                          s->zkproof, s->spend_auth_sig,
                                          sighash.data);
    }
    for (size_t i = 0; ok && i < wtx->tx.num_shielded_output; i++) {
        const struct output_description *o = &wtx->tx.v_shielded_output[i];
        ok = zclassic_sapling_check_output(vc, o->cv.data, o->cm.data,
                                           o->ephemeral_key.data, o->zkproof);
    }
    ok = ok && zclassic_sapling_final_check(vc, wtx->tx.value_balance,
                                            wtx->tx.binding_sig,
                                            sighash.data);
    zclassic_sapling_verification_ctx_free(vc);
    return ok;
}

static bool wsr_e2e_contains(const struct wsr_e2e *e, const uint8_t *txid)
{
    struct db_sapling_note out[8];
    int n = db_sapling_note_list_unspent_for_ivk(
        (struct node_db *)&e->ndb, e->key->ivk, out, 8);
    for (int i = 0; i < n; i++)
        if (memcmp(out[i].txid, txid, 32) == 0)
            return true;
    return false;
}

/* Through the registered RPC table, so the registration of the checkpoint
 * handler is what is under test. */
static struct rpc_table g_wsr_table;

/* A note at or below the floor whose nullifier the chain already shows as
 * spent, at a height whose block body this node does not have. */
#define WSR_NOTE_D_H 4
#define WSR_NOTE_D_SPENT_H 7

static bool wsr_e2e_note_d(struct wsr_e2e *e, bool add)
{
    uint8_t txid[32], rcm[32], cm[32], nf[32], memo[512];
    memset(txid, 0xD0, sizeof(txid));
    memset(rcm, 0xD1, sizeof(rcm));
    memset(cm, 0xD2, sizeof(cm));
    memset(nf, 0xD4, sizeof(nf));
    memset(memo, 0xF6, sizeof(memo));
    if (!add) {
        sqlite3_stmt *s = NULL;
        bool ok = sqlite3_prepare_v2(e->ndb.db, "DELETE FROM wallet_sapling_notes WHERE txid=?", -1, &s, NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
            ok = sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:test-fixture
        }
        sqlite3_finalize(s);
        return ok;
    }
    return node_db_sync_sapling_note(&e->ndb, txid, 0, 2000000, rcm, memo,
                                     sizeof(memo), e->key->ivk,
                                     e->key->diversifier, e->key->pk_d, cm,
                                     nf, WSR_NOTE_D_H) &&
           nullifier_kv_add(progress_store_db(), nf, NULLIFIER_POOL_SAPLING,
                            WSR_NOTE_D_SPENT_H);
}

static const char *wsr_e2e_rpc(struct json_value *params,
                               struct json_value *result, bool *sent)
{
    json_set_null(result);
    *sent = rpc_table_execute(&g_wsr_table, "z_sendmany", params, result);
    return json_get_str(result);
}

/* A coins view that only answers the Sapling anchor lookup the mempool makes
 * for a spend: the one anchor the test tree produced. */
static uint8_t g_wsr_anchor[32];

static enum coins_anchor_lookup_result wsr_view_anchor(
    void *self, enum coins_anchor_pool pool, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out)
{
    (void)self;
    (void)tree_out;
    return pool == COINS_ANCHOR_SAPLING &&
                   memcmp(root->data, g_wsr_anchor, 32) == 0
               ? COINS_ANCHOR_FOUND
               : COINS_ANCHOR_MISSING;
}

static struct coins_view_vtable g_wsr_view_vtable = {
    .get_anchor = wsr_view_anchor,
};

/* The direct build of a transaction from note B, outside the RPC layer: the
 * gate passes, the note is proved and the proofs verify. */
static int wsr_e2e_prove(struct wsr_e2e *e, const struct chain_params *cp)
{
    int failures = 0;
    struct json_value result = {0};
    WSR_CHECK("note B saved with its true witness",
              wsr_e2e_save_note(e, 1, false));
    struct wallet_tx prepared;
    memset(&prepared, 0, sizeof(prepared));
    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x62, 20);
    int64_t amount = 1000000;
    json_set_null(&result);
    bool built = z_sendmany_shielded(
        wallet_rpc_context_current(), cp, e->key, amount, &dest, &amount, 1,
        NULL, NULL, NULL, NULL, NULL, 0, 0, &prepared, &result, WSR_KEY_H);
    WSR_CHECK("an above-floor unspent note passes the gate and is proved",
              built && prepared.tx.num_shielded_spend == 1);
    if (built && prepared.tx.num_shielded_spend == 1) {
        WSR_CHECK("only note B is spent (not A below the floor, not C spent)",
                  memcmp(prepared.tx.v_shielded_spend[0].nullifier.data,
                         e->n[1].nf, 32) == 0);
        WSR_CHECK("the proofs and signatures verify under the production "
                  "verifier",
                  wsr_e2e_verify(&prepared, cp, WSR_TIP));
        transaction_free(&prepared.tx);
    }
    json_free(&result);
    return failures;
}

/* Refusals through the registered handler, then the send itself. */
static int wsr_e2e_scenarios(struct wsr_e2e *e, const struct chain_params *cp,
                             const char *from, const char *to)
{
    int failures = 0;
    char body[512];
    char last[64];
    bool sent = false;
    struct json_value params = {0};
    struct json_value result = {0};
    snprintf(body, sizeof(body),
             "[\"%s\",[{\"address\":\"%s\",\"amount\":0.01}]]", from, to);
    WSR_CHECK("params parse", json_read(&params, body, strlen(body)));

    sovereignty_spend_after_checkpoint_set(true);
    WSR_CHECK("note A (below the floor) saved", wsr_e2e_save_note(e, 0, false));
    const char *msg = wsr_e2e_rpc(&params, &result, &sent);
    WSR_CHECK("a below-floor note is refused: not usable yet, not absent",
              !sent && msg && strstr(msg, "insufficient_post_checkpoint") &&
                  strstr(msg, "not usable yet"));
    WSR_CHECK("the below-floor note stays unspent", wsr_e2e_contains(e,
                                                                     e->n[0].txid));

    WSR_CHECK("note D saved: below the floor, its nullifier in the set at a "
              "height with no block body", wsr_e2e_note_d(e, true));
    msg = wsr_e2e_rpc(&params, &result, &sent);
    WSR_CHECK("one spent note below the floor blocks every shielded send: "
              "reconciliation cannot read its block",
              !sent && msg &&
                  strstr(msg, "Canonical shielded note state is unavailable"));
    WSR_CHECK("note D removed again", wsr_e2e_note_d(e, false));

    WSR_CHECK("note B saved with a witness that differs from the header root",
              wsr_e2e_save_note(e, 1, true));
    WSR_CHECK("note C saved", wsr_e2e_save_note(e, 2, false));
    msg = wsr_e2e_rpc(&params, &result, &sent);
    sovereignty_spend_rule_last_verdict(last, sizeof(last));
    WSR_CHECK("a witness root differing from the header root stops before "
              "proving (anchor_root_mismatch)",
              !sent && msg && strstr(msg, "anchor_root_mismatch") &&
                  strcmp(last, "anchor_root_mismatch") == 0);
    WSR_CHECK("the note spent above the floor is marked spent and not "
              "selected",
              !wsr_e2e_contains(e, e->n[2].txid) &&
                  wsr_e2e_contains(e, e->n[1].txid));

    failures += wsr_e2e_prove(e, cp);

    msg = wsr_e2e_rpc(&params, &result, &sent);
    WSR_CHECK("the registered handler sends: a 64-hex txid, admitted to the "
              "mempool",
              sent && msg && strlen(msg) == 64 &&
                  strspn(msg, "0123456789abcdef") == 64 &&
                  tx_mempool_size(wallet_rpc_context_current()->mempool) == 1);
    WSR_CHECK("note B is reserved: it no longer lists as unspent, note A "
              "still does",
              !wsr_e2e_contains(e, e->n[1].txid) &&
                  wsr_e2e_contains(e, e->n[0].txid));
    json_free(&params);
    json_free(&result);
    sovereignty_spend_after_checkpoint_set(false);
    return failures;
}

static int wsr_test_send_e2e(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[320];
    char params_dir[512];
    char from[128];
    char to[128];
    struct wsr_chain c;
    struct main_state ms;
    struct rom_state_checkpoint cp;
    struct rom_state_rung no_rungs[1];
    struct wsr_e2e e;
    uint8_t seed[32];
    uint8_t d0[ZC_DIVERSIFIER_SIZE], pkd0[32];
    struct tx_mempool pool;
    struct coins_view_cache coins;
    struct network_upgrade saved_up[2];
    struct chain_params *live = (struct chain_params *)chain_params_get();
    const struct chain_params *params = chain_params_get();
    const char *home = getenv("HOME");
    memset(no_rungs, 0, sizeof(no_rungs));
    memset(&e, 0, sizeof(e));

    snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
             (home && *home) ? home : ".");
    WSR_CHECK("sapling parameters load and the prover is ready (a missing "
              "parameter set is a failure, not a skip)",
              sapling_init_params(params_dir) &&
                  zclassic_sapling_prover_is_ready());
    if (!zclassic_sapling_prover_is_ready())
        return failures + 1;

    e.w = zcl_calloc(1, sizeof(*e.w), "wsr_e2e_wallet");
    WSR_CHECK("wallet allocated", e.w != NULL);
    if (!e.w)
        return failures + 1;
    wallet_init(e.w);
    e.w->best_block_height = WSR_TIP;
    memset(seed, 0xB3, sizeof(seed));
    WSR_CHECK("real sapling key derived",
              sapling_keystore_set_seed(&e.w->sapling_keys, seed) &&
                  sapling_keystore_new_address(&e.w->sapling_keys, d0, pkd0));
    e.key = &e.w->sapling_keys.keys[0];
    WSR_CHECK("three real notes and their tree",
              wsr_e2e_make_notes(&e));

    test_make_tmpdir(dir, sizeof(dir), "wallet_spend_rule", "e2e");
    wsr_build(&c, 0, WSR_TIP);
    memcpy(c.bi[WSR_TIP].hashFinalSaplingRoot.data, e.root, 32);
    wsr_state(&ms, &c);
    WSR_CHECK("the spending block body is on disk and active",
              wsr_e2e_spend_block(&ms, &c, dir, e.n[2].nf));
    wsr_checkpoint(&cp, &c, WSR_KEY_H, WSR_FRONTIER_H);
    checkpoints_set_rom_state_override_for_test(&cp);
    checkpoints_set_rom_state_rungs_override_for_test(no_rungs, 0);

    WSR_CHECK("seeded store: cursors 0, strict guard refuses",
              wsr_borrowed_store_at(dir, false, 0));
    WSR_CHECK("ledger holds the tip root",
              anchor_kv_add_tree(progress_store_db(), ANCHOR_POOL_SAPLING,
                                 &e.tree, WSR_TIP));
    WSR_CHECK("note C's nullifier is in the set at the spending height",
              nullifier_kv_add(progress_store_db(), e.n[2].nf,
                               NULLIFIER_POOL_SAPLING, WSR_SPEND_H));
    reducer_frontier_provable_tip_set(WSR_TIP);
    WSR_CHECK("floor is the keystone height with both cursors at 0",
              wsr_eval(&ms, WSR_TIP, "", WSR_KEY_H));

    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    WSR_CHECK("node.db opens", node_db_open(&e.ndb, dbpath));
    /* The chain is 24 blocks long: Overwinter and Sapling are active from
     * height 1 for this test only, restored below. */
    saved_up[0] = live->consensus.vUpgrades[UPGRADE_OVERWINTER];
    saved_up[1] = live->consensus.vUpgrades[UPGRADE_SAPLING];
    live->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = 1;
    live->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = 1;
    memcpy(g_wsr_anchor, e.root, 32);
    tx_mempool_init(&pool, 0);
    struct coins_view backing = { .vtable = &g_wsr_view_vtable };
    coins_view_cache_init(&coins, &backing);
    rpc_table_init(&g_wsr_table);
    register_wallet_rpc_commands(&g_wsr_table);
    set_rpc_warmup_finished();
    wallet_rpc_context_set_base(e.w, &ms, dir, NULL, &pool, NULL);
    wallet_rpc_context_set_coins_tip(&coins);
    wallet_rpc_context_set_node_db(&e.ndb);
    WSR_CHECK("addresses",
              params &&
                  sapling_encode_payment_address(
                      e.key->diversifier, e.key->pk_d,
                      params->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                      from, sizeof(from)) &&
                  wsr_addr(0x62, to, sizeof(to)));
    if (params)
        failures += wsr_e2e_scenarios(&e, params, from, to);
    live->consensus.vUpgrades[UPGRADE_OVERWINTER] = saved_up[0];
    live->consensus.vUpgrades[UPGRADE_SAPLING] = saved_up[1];

    wallet_rpc_context_set_coins_tip(NULL);
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    node_db_close(&e.ndb);
    wallet_free(e.w);
    free(e.w);
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    checkpoints_reset_rom_state_override_for_test();
    checkpoints_reset_rom_state_rungs_override_for_test();
    main_state_free(&ms);
    return failures;
}

int test_wallet_spend_rule(void);
int test_wallet_spend_rule(void)
{
    printf("\n=== wallet spend rule (-spend-after-checkpoint) tests ===\n");
    int failures = 0;
    failures += wsr_test_gate_checks();
    failures += wsr_test_floor_filters();
    failures += wsr_test_guard_boundaries();
    failures += wsr_test_floor_authority();
    failures += wsr_test_seed_floor();
    failures += wsr_test_shield_form();
    failures += wsr_test_compiled_table();
    failures += wsr_test_rpc_selection();
    failures += wsr_test_send_e2e();
    return failures;
}
