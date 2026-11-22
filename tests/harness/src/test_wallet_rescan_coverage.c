/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_wallet_rescan_coverage — regression gate for the silent rescan.
 *
 * THE DEFECT: wallet_scan_block() returned a bare 0 for BOTH "this block
 * holds nothing of yours" AND "this node has no body for that block", using
 * the same statement, with no counter. rescanblockchain then returned only
 * {start_height, stop_height} — it never reported what it found or how much
 * it had actually been able to read. On a snapshot-bootstrapped node, where
 * snapshot_controller_import.c deliberately strips BLOCK_HAVE_DATA across the
 * whole imported range, a rescan therefore walked the entire chain, read
 * nothing, and reported plain success. A user restoring a wallet concluded
 * their backup was empty.
 *
 * Every assertion below drives the REAL `rescanblockchain` RPC — the exact
 * entry point `core wallet rescan` calls — so this test compiles and runs
 * against the pre-fix tree, where it fails because the counts it demands are
 * simply absent from the reply.
 *
 * Six scenarios, all against one on-disk block reused by 200 index entries:
 *
 *   A. Full coverage, wallet owns an output  -> coverage_ok, counts add up,
 *      and the untried-shielded condition is REPORTED (the wallet holds no
 *      Sapling key, the seed-only-restore state).
 *   B. No block bodies at all (the snapshot-bootstrap case) -> must FAIL with
 *      RESCAN_NO_BLOCK_DATA, never "0 found" with a success reply.
 *   C. 75% coverage -> must FAIL with RESCAN_INCOMPLETE_COVERAGE.
 *   D. 99.5% coverage but nothing found -> must FAIL with
 *      RESCAN_INCONCLUSIVE_ZERO: we cannot prove absence of funds from a
 *      range we did not fully read.
 *   E. Boot catch-up reads bodies from the network directory.
 *   F. Boot catch-up that cannot read its range keeps its last fully
 *      scanned height, persists a retry, and clears it once a later
 *      catch-up reads the range; one unread body in the range keeps the
 *      retry even when the rescan's 99% floor calls the read coverage_ok.
 *   G. Kill-restart depth re-basing: rows stored before a hard kill keep
 *      depths measured from the flushed baseline, and the boot catch-up
 *      that scans only the gap must raise them by the distance the
 *      baseline moves. The journey run that found this booted the killed
 *      publisher's wallet with every stored depth 21 short: getbalance
 *      under-reported spendable by the whole maturity boundary band
 *      (21 x 12.5) while listunspent was correct, and only a manual
 *      rescanblockchain from 0 restored the number.
 *   R. The row-replacing scan (rescanwallet, reindexdb,
 *      replaywalletfromchain, the boot catch-up scan) refuses a range with
 *      bodiless heights and keeps wallet_utxos and wallet_transactions. A
 *      fully bodied range from height 0 still replaces the rows; a catch-up
 *      delta above its cursor deletes no row and keeps the existing rows,
 *      adding what it found and marking spent a stored coin its blocks
 *      spend.
 *   U. A height whose BLOCK_HAVE_DATA body cannot be read (block file
 *      absent, cut short, or the block does not parse), or no block file at
 *      all, refuses the row replace and keeps the rows byte-equal; an intact
 *      chain still replaces them, and a block in a file Pass 1 read and ruled
 *      out is still skipped unparsed.
 */

#include "test/test_core.h"
#include "platform/directory_compat.h"

#include "controllers/wallet_controller.h"
#include "controllers/wallet_scan.h"
#include "config/boot_cursor_state.h"
#include "config/boot_internal.h"
#include "coins/coins_view.h"
#include "models/wallet_tx.h"
#include "chain/chainparams.h"
#include "util/util.h"

#include "models/database.h"

#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "wallet/sapling_keys.h"
#include "util/safe_alloc.h"
#include "util/ar_step_readonly.h"
#include "wallet/wallet_sqlite.h"

#include "storage/disk_block_io.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "bloom/merkle.h"
#include "script/standard.h"
#include "keys/pubkey.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define WRC_CHECK(name, expr) do {                        \
    printf("wallet_rescan_coverage: %s... ", (name));     \
    if ((expr)) printf("OK\n");                           \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

/* Total synthetic index entries. 200 makes the 99% coverage floor
 * (WALLET_RESCAN_MIN_COVERAGE_PCT) expressible: 199/200 clears it, 150/200
 * does not. */
#define WRC_NBLOCKS 200

/* Read an int key out of an RPC reply. Returns -1 when the key is absent —
 * which is exactly what the PRE-FIX rescanblockchain reply does for every
 * count, so the assertions below fail loudly on the parent commit. */
static int64_t wrc_int(const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    return (v && v->type == JSON_INT) ? json_get_int(v) : -1;
}

/* Read a string key; "" when absent or not a string. */
static const char *wrc_str(const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    return (v && v->type == JSON_STR) ? json_get_str(v) : "";
}

/* Read a bool key. `dflt` when absent — the pre-fix reply has no
 * coverage_ok, so callers pass a value that makes the demand fail. */
static bool wrc_bool(const struct json_value *o, const char *k, bool dflt)
{
    const struct json_value *v = json_get(o, k);
    return (v && v->type == JSON_BOOL) ? json_get_bool(v) : dflt;
}

/* Build the [start, stop] params array rescanblockchain expects. */
static void wrc_params(struct json_value *p, int start, int stop)
{
    json_init(p);
    json_set_array(p);
    struct json_value v;
    json_init(&v);
    json_set_int(&v, start);
    json_push_back(p, &v);
    json_free(&v);
    json_init(&v);
    json_set_int(&v, stop);
    json_push_back(p, &v);
    json_free(&v);
}

/* H and J. A first boot scan starts at the birthday floor, and a pending
 * marker survives a boot read that tried no Sapling key. */
static int wrc_boot_floor_and_marker(struct wallet *w, struct main_state *ms,
                                     const char *datadir)
{
    int failures = 0;
    struct wallet_rescan_report rep;
    /* H. A wallet that has scanned nothing starts at the birthday floor
     * boot gave it; a wallet that has scanned does not, whatever the floor. */
    w->best_block_height = 0;
    w->initial_scan_floor = 100;
    memset(&rep, 0, sizeof(rep));
    (void)boot_wallet_catch_up(w, &ms->chain_active, datadir, &rep);
    WRC_CHECK("H: a first scan starts at the birthday floor, not at genesis",
              rep.start_height == 100 && rep.stop_height == WRC_NBLOCKS - 1);
    w->best_block_height = 149;
    memset(&rep, 0, sizeof(rep));
    (void)boot_wallet_catch_up(w, &ms->chain_active, datadir, &rep);
    WRC_CHECK("H: a wallet that has scanned continues from its scan height",
              rep.start_height == 150);
    w->initial_scan_floor = 0;
    w->best_block_height = WRC_NBLOCKS - 1;

    /* J. The boot catch-up keeps a pending marker when it read every body but
     * tried no Sapling key; once the wallet holds one, the same read clears it. */
    w->scan_retry.pending = true;
    w->scan_retry.from = 0;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             WALLET_RESTORE_BLOCKER_UNREAD);
    w->time_first_key = 2000000000;
    memset(&rep, 0, sizeof(rep));
    (void)boot_wallet_catch_up(w, &ms->chain_active, datadir, &rep);
    WRC_CHECK("J: a pending marker overrides the key timestamp",
              rep.start_height == 0);
    w->time_first_key = 0;
    WRC_CHECK("J: a boot read that tried no Sapling key keeps the marker",
              w->scan_retry.pending && rep.blocks_scanned == rep.blocks_in_range &&
              rep.shielded_txs_unscanned > 0);
    uint8_t jseed[32], jd[11], jpk[32];
    memset(jseed, 0x3d, sizeof(jseed));
    (void)sapling_keystore_set_seed(&w->sapling_keys, jseed);
    (void)sapling_keystore_new_address(&w->sapling_keys, jd, jpk);
    memset(&rep, 0, sizeof(rep));
    (void)boot_wallet_catch_up(w, &ms->chain_active, datadir, &rep);
    WRC_CHECK("J: the same boot read with a Sapling key clears it",
              !w->scan_retry.pending && rep.shielded_txs_unscanned == 0);
    /* A stored key that cannot scan while locked keeps the marker too. */
    w->scan_retry.pending = true;
    w->scan_retry.from = 0;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             WALLET_RESTORE_BLOCKER_UNREAD);
    w->sapling_keys.num_unscannable = 1;
    memset(&rep, 0, sizeof(rep));
    (void)boot_wallet_catch_up(w, &ms->chain_active, datadir, &rep);
    WRC_CHECK("J: a boot read keeps the marker while a stored key is unscannable",
              w->scan_retry.pending && rep.shielded_txs_unscanned == 0);
    w->sapling_keys.num_unscannable = 0;
    sapling_keystore_free(&w->sapling_keys);
    sapling_keystore_init(&w->sapling_keys);
    /* K. Every key is newer than the tip: nothing to read, so the wallet is
     * level with the tip and the next live tip finds no hole to record. */
    w->scan_retry.pending = false;
    w->scan_retry.blocker[0] = 0;
    w->scan_retry.from = 0;
    w->best_block_height = 0;
    w->initial_scan_floor = 0;
    w->time_first_key = 2000000000;
    memset(&rep, 0, sizeof(rep));
    (void)boot_wallet_catch_up(w, &ms->chain_active, datadir, &rep);
    WRC_CHECK("K: keys newer than the tip level the wallet with the tip",
              w->best_block_height == WRC_NBLOCKS - 1 &&
              !w->scan_retry.pending &&
              wallet_scanned_through_height(w) == WRC_NBLOCKS - 1);
    w->time_first_key = 0;
    w->best_block_height = WRC_NBLOCKS - 1;
    return failures;
}

/* I. A rescan clears the marker only when it reads the whole marked range. */
static int wrc_rescan_marker(struct wallet *w, struct main_state *ms,
                             const char *netdir, struct block_index *idx)
{
    int failures = 0;
    struct wallet_rescan_report rep;
    /* I. The unread marker waits for a read of the whole marked range. A
     * rescan that starts above it, stops before the tip or misses a body
     * keeps it; one that reads from the marker to the tip clears it. */
    w->scan_retry.pending = true;
    w->scan_retry.from = 0;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             WALLET_RESTORE_BLOCKER_UNREAD);
    (void)wallet_rescan_report(w, &ms->chain_active, 50, -1, netdir, &rep);
    WRC_CHECK("I: a rescan starting above the marker keeps it",
              w->scan_retry.pending && rep.blocks_scanned == rep.blocks_in_range);
    (void)wallet_rescan_report(w, &ms->chain_active, 0, 100, netdir, &rep);
    WRC_CHECK("I: a rescan stopping before the tip keeps it",
              w->scan_retry.pending);
    (void)wallet_rescan_report(w, &ms->chain_active, 0, -1, netdir, &rep);
    WRC_CHECK("I: a whole rescan that tried no Sapling key keeps it",
              w->scan_retry.pending && rep.shielded_txs_unscanned > 0);
    uint8_t sapling_seed[32];
    memset(sapling_seed, 0x5c, sizeof(sapling_seed));
    uint8_t sd[11], spk[32];
    (void)sapling_keystore_set_seed(&w->sapling_keys, sapling_seed);
    (void)sapling_keystore_new_address(&w->sapling_keys, sd, spk);
    idx[100].nStatus &= ~(unsigned)BLOCK_HAVE_DATA;
    (void)wallet_rescan_report(w, &ms->chain_active, 0, -1, netdir, &rep);
    WRC_CHECK("I: a rescan that misses one body keeps it",
              w->scan_retry.pending && rep.blocks_scanned < rep.blocks_in_range);
    idx[100].nStatus |= BLOCK_HAVE_DATA;
    w->sapling_keys.num_unscannable = 1;
    (void)wallet_rescan_report(w, &ms->chain_active, 0, -1, netdir, &rep);
    WRC_CHECK("I: a whole rescan keeps it while a stored key is unscannable",
              w->scan_retry.pending && rep.blocks_scanned == WRC_NBLOCKS);
    w->sapling_keys.num_unscannable = 0;
    WRC_CHECK("I: initialize cutover pending",
              wallet_readiness_initialize(w, WALLET_READINESS_PENDING, false, 0));
    (void)wallet_rescan_report(w, &ms->chain_active, 0, -1, netdir, &rep);
    WRC_CHECK("I: complete body coverage cannot clear a cutover marker",
              w->scan_retry.pending && rep.blocks_scanned == WRC_NBLOCKS &&
              wallet_scanned_through_height(w) == -1);
    WRC_CHECK("I: fixture completes cutover", wallet_readiness_complete(w, false, 0));
    (void)wallet_rescan_report(w, &ms->chain_active, 0, -1, netdir, &rep);
    WRC_CHECK("I: a whole rescan that read every body clears it",
              !w->scan_retry.pending && rep.blocks_scanned == WRC_NBLOCKS &&
              wallet_scanned_through_height(w) == WRC_NBLOCKS - 1);
    w->scan_retry.pending = true;
    w->scan_retry.from = 100;
    w->initial_scan_floor = 100;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             WALLET_BIRTHDAY_SCAN_PENDING);
    (void)wallet_rescan_report(w, &ms->chain_active, 100, -1, netdir, &rep);
    WRC_CHECK("I: verified floor scan clears its marker",
              !w->scan_retry.pending && w->initial_scan_floor == 100);
    w->scan_retry.pending = true;
    w->scan_retry.from = 0;
    w->initial_scan_floor = WRC_NBLOCKS + 100;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             WALLET_BIRTHDAY_PENDING);
    (void)wallet_rescan_report(w, &ms->chain_active, 0, -1, netdir, &rep);
    WRC_CHECK("I: a full scan retires an unverified birthday floor",
              !w->scan_retry.pending && w->initial_scan_floor == 0);
    sapling_keystore_free(&w->sapling_keys);
    sapling_keystore_init(&w->sapling_keys);
    return failures;
}

/* E. The boot catch-up on a regtest node's own layout. node.db lives in the
 * base datadir, but every block writer puts bodies under
 * <base>/regtest/blocks. Boot hands the catch-up its base datadir. A rescan
 * that reads <base>/blocks finds no file and fails every body, and after an
 * unclean stop that left each coinbase at the depth it had at the last
 * flush: the wallet refused to spend mature coins that its own vault
 * reported as spendable. */
static int wrc_boot_catch_up_body_root(struct wallet *w,
                                       struct main_state *ms,
                                       const char *datadir,
                                       struct block_index *idx)
{
    int failures = 0;
    for (int i = 0; i < WRC_NBLOCKS; i++)
        idx[i].nStatus |= BLOCK_HAVE_DATA;
    char netdir[320], moved_from[352], moved_to[384];
    snprintf(netdir, sizeof(netdir), "%s/regtest", datadir);
    snprintf(moved_from, sizeof(moved_from), "%s/blocks", datadir);
    snprintf(moved_to, sizeof(moved_to), "%s/blocks", netdir);
    chain_params_select(CHAIN_REGTEST);
    bool relaid = SetDataDir(datadir) &&
                  rename(moved_from, moved_to) == 0;
    WRC_CHECK("E: bodies laid out under <base>/regtest/blocks", relaid);

    /* The wallet loaded scan height 0 after an unclean stop. */
    w->best_block_height = 0;
    w->time_first_key = 0;
    struct wallet_rescan_report rep;
    memset(&rep, 0, sizeof(rep));
    int found = boot_wallet_catch_up(w, &ms->chain_active, datadir, &rep);
    WRC_CHECK("E: boot catch-up rescans the whole missing range",
              rep.start_height == 0 && rep.stop_height == WRC_NBLOCKS - 1);
    WRC_CHECK("E: boot catch-up reads every body from <base>/regtest",
              rep.blocks_scanned == WRC_NBLOCKS &&
              rep.blocks_read_failed == 0);
    WRC_CHECK("E: boot catch-up finds the wallet's 200 outputs",
              found == WRC_NBLOCKS);
    WRC_CHECK("E: boot catch-up coverage_ok is true", rep.coverage_ok);
    WRC_CHECK("E: the wallet is level with the tip afterwards",
              w->best_block_height == WRC_NBLOCKS - 1);
    WRC_CHECK("E: a full read leaves no retry and scans through the tip",
              !w->scan_retry.pending &&
              wallet_scanned_through_height(w) == WRC_NBLOCKS - 1);
    WRC_CHECK("E: a wallet already at the tip runs no rescan",
              boot_wallet_catch_up(w, &ms->chain_active, datadir, NULL) == -1);

    failures += wrc_boot_floor_and_marker(w, ms, datadir);
    failures += wrc_rescan_marker(w, ms, netdir, idx);

    if (relaid)
        (void)rename(moved_to, moved_from);
    SetDataDir("");
    ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);
    test_cleanup_tmpdir(netdir);
    return failures;
}

/* One named check; returns 1 on failure so callers can sum. */
static int wrc_expect(const char *name, bool ok)
{
    printf("wallet_rescan_coverage: %s... %s\n", name, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* The one wallet transaction the shared fixture body yields, or NULL. */
static const struct wallet_tx *wrc_only_tx(const struct wallet *w)
{
    for (size_t i = 0; i < MAX_WALLET_TX; i++)
        if (w->map_wallet[i].used)
            return &w->map_wallet[i];
    return NULL;
}

/* F fixture: the bodies sit under <base>/regtest/blocks, and `hidden` is
 * where F1 moves them so every read fails. */
#define WRC_F_PREV 49      /* the wallet's last flushed scan height */
#define WRC_F_LAST (WRC_NBLOCKS - 1)
#define WRC_F_FOUND_AT 149 /* F2's last readable height holding the coin */
#define WRC_F_VALUE 1000000
struct wrc_f {
    struct wallet *w;
    const struct wallet *owner;
    const struct key_id *kid;
    struct main_state *ms;
    const char *datadir;
    struct block_index *idx;
    struct wallet_sqlite *ws;
    struct rpc_table *tbl;
    struct tx_mempool *mempool;
    char net_blocks[384];
    char hidden[400];
};

static bool wrc_accounting_balance(struct wrc_f *f, int64_t expected)
{
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    bool ok = rpc_table_execute(f->tbl, "getwalletaccounting", &params, &result);
    const struct json_value *balance = json_get(&result, "utxo_balance");
    if (balance && balance->type == JSON_REAL)
        printf(" (utxo_balance=%.8f)", json_get_real(balance));
    ok = ok && balance && balance->type == JSON_REAL && json_get_real(balance) == (double)expected;
    json_free(&params);
    json_free(&result);
    return ok;
}

static bool wrc_accounting_reserved(const struct transaction *tx, uint32_t vout, void *ctx)
{
    (void)tx; (void)ctx;
    return vout == 2;
}

static int wrc_accounting_maturity(struct wrc_f *f, struct wallet *w,
                                   const struct wallet_tx *source)
{
    int failures = 0;
    struct wallet_tx *cb = &w->map_wallet[1];
    cb->used = true;
    cb->confirms = 0;
    w->num_wallet_tx++;
    transaction_init(&cb->tx);
    bool allocated = transaction_alloc(&cb->tx, 1, 1);
    WRC_CHECK("accounting: create coinbase", allocated);
    if (allocated) {
        cb->tx.hash.data[0] = 0x71;
        cb->tx.vout[0].value = INT64_C(700000000);
        cb->tx.vout[0].script_pub_key = source->tx.vout[4].script_pub_key;
        WRC_CHECK("accounting RPC excludes immature coinbase", wrc_accounting_balance(f, 5));
        cb->confirms = 100000;
        WRC_CHECK("accounting RPC includes mature coinbase", wrc_accounting_balance(f, 12));
    }
    return failures;
}

static int wrc_accounting_policy(struct wrc_f *f, struct wallet *w,
                                 struct wallet_tx *wtx)
{
    int failures = 0;
    wtx->tx.num_vout = 6;
    wtx->tx.vout[0].value = 0;
    struct key_id watch = {0};
    watch.id.data[0] = 0xb9;
    WRC_CHECK("accounting: add watch-only key", keystore_add_watch_only_id(&w->keystore, &watch));
    script_for_p2pkh(&wtx->tx.vout[1].script_pub_key, &watch);
    wallet_set_coin_reservation_probe(wrc_accounting_reserved, NULL);
    wallet_mark_outpoint_spent(w, &wtx->tx.hash, 3);
    struct script redeem;
    script_init(&redeem);
    WRC_CHECK("accounting: build redeem script", script_push_op(&redeem, OP_TRUE));
    WRC_CHECK("accounting: add redeem script", keystore_add_cscript(&w->keystore, &redeem));
    struct script_id sid;
    script_id_from_script(&sid, &redeem);
    script_for_p2sh(&wtx->tx.vout[5].script_pub_key, &sid);
    wtx->tx.vout[5].value = INT64_C(300000000);
    struct coin_entry coins[6];
    size_t n = 0;
    wallet_available_coins(w, coins, &n, 6, false, false);
    WRC_CHECK("accounting: selection excludes reserved, spent and zero but includes watch-only",
              n == 3 && coins[0].i == 1 && !coins[0].spendable && coins[1].i == 4 && coins[2].i == 5 && !coins[2].spendable);
    WRC_CHECK("accounting RPC includes nonspendable owned script", wrc_accounting_balance(f, 5));
    wtx->confirms = 3;
    WRC_CHECK("accounting RPC includes confirmed outputs", wrc_accounting_balance(f, 5));
    failures += wrc_accounting_maturity(f, w, wtx);
    wallet_set_coin_reservation_probe(NULL, NULL);
    wallet_unmark_outpoint_spent(w, &wtx->tx.hash, 3);
    wtx->tx.num_vout = 4097;
    return failures;
}

static int wrc_accounting_overflow(struct wrc_f *f, struct wallet_tx *wtx)
{
    int failures = 0;
    wtx->tx.num_vout = 2;
    wtx->tx.vout[0].value = INT64_MAX;
    wtx->tx.vout[1].value = 1;
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    bool ok = rpc_table_execute(f->tbl, "getwalletaccounting", &params, &result);
    WRC_CHECK("accounting RPC refuses overflowing available balance", !ok);
    json_free(&params);
    json_free(&result);
    wtx->tx.num_vout = 4097;
    return failures;
}

static int wrc_accounting_boundary(struct wrc_f *f, struct wallet *original)
{
    int failures = 0;
    struct wallet *w = zcl_calloc(1, sizeof(*w), "accounting.fixture");
    if (!w) return 1;
    wallet_init(w);
    struct pubkey pk;
    bool created = wallet_generate_new_key(w, &pk);
    WRC_CHECK("accounting fixture generates a key", created);
    struct wallet_tx *wtx = &w->map_wallet[0];
    wtx->used = true;
    wtx->confirms = 0;
    w->num_wallet_tx = 1;
    transaction_init(&wtx->tx);
    bool allocated = created && transaction_alloc(&wtx->tx, 0, 4097);
    WRC_CHECK("accounting fixture allocates 4097 outputs", allocated);
    if (allocated) {
        struct key_id kid = pubkey_get_id(&pk);
        for (size_t i = 0; i < 4097; i++) {
            wtx->tx.vout[i].value = i == 4096 ? INT64_C(200000000) : INT64_C(100000000);
            script_for_p2pkh(&wtx->tx.vout[i].script_pub_key, &kid);
        }
        rpc_wallet_set_state(w, f->ms, f->datadir, f->ws, f->mempool, NULL);
        wtx->tx.num_vout = 4095;
        WRC_CHECK("accounting RPC includes 4095 outputs", wrc_accounting_balance(f, 4095));
        wtx->tx.num_vout = 4096;
        WRC_CHECK("accounting RPC includes 4096 outputs", wrc_accounting_balance(f, 4096));
        wtx->tx.num_vout = 4097;
        WRC_CHECK("accounting RPC includes distinct 4097th output", wrc_accounting_balance(f, 4098));
        failures += wrc_accounting_policy(f, w, wtx);
        failures += wrc_accounting_overflow(f, wtx);
    }
    rpc_wallet_set_state(original, f->ms, f->datadir, f->ws, f->mempool, NULL);
    wallet_free(w);
    free(w);
    return failures;
}

static bool wrc_history_null(const struct json_value *object, const char *key)
{
    const struct json_value *value = json_get(object, key);
    return value && value->type == JSON_NULL;
}

static const struct json_value *wrc_history_send(const struct json_value *result)
{
    const struct json_value *txs = json_get(result, "transactions");
    if (!txs || txs->type != JSON_ARR) return NULL;
    for (size_t i = 0; i < txs->num_children; i++)
        if (wrc_bool(&txs->children[i], "from_me", false)) return &txs->children[i];
    return NULL;
}

static int wrc_history_global_assert(const struct json_value *result, bool incomplete)
{
    int failures = 0;
    WRC_CHECK("history scope is loaded transactions",
              !strcmp(wrc_str(result, "accounting_scope"), "loaded_wallet_transactions"));
    WRC_CHECK("history coverage does not claim completeness",
              !strcmp(wrc_str(result, "history_coverage"), incomplete ? "incomplete" : "unverified"));
    WRC_CHECK("global reconciliation verdicts are unknown",
              wrc_history_null(result, "balanced") && wrc_history_null(result, "discrepancy") &&
              wrc_history_null(result, "spent_externally"));
    return failures;
}

static int wrc_history_missing_assert(const struct json_value *result, const char *label)
{
    int failures = 0;
    const struct json_value *child = wrc_history_send(result);
    WRC_CHECK("unresolved input makes fee and total input unknown", child &&
              wrc_int(result, "unresolved_inputs") == 1 &&
              wrc_history_null(result, "total_fees") &&
              wrc_history_null(child, "fee") && wrc_history_null(child, "total_in") &&
              wrc_int(child, "missing_inputs") == 1);
    const char *hash = wrc_str(child, "missing_prevout");
    const char *expected_hash = strcmp(label, "known_first_missing_second") == 0
        ? "0000000000000000000000000000000000000000000000000000000000000073"
        : "0000000000000000000000000000000000000000000000000000000000000051";
    WRC_CHECK("first unresolved prevout is recorded", strcmp(hash, expected_hash) == 0 &&
              wrc_int(child, "missing_prevout_vout") == (strcmp(label, "out_of_range") == 0 ? 1 : 0));
    const struct json_value *known = json_get(child, "known_input_subtotal");
    double expected = strcmp(label, "known_first_missing_second") == 0 ? 10.0 : 0.0;
    WRC_CHECK("known input subtotal stays visible", known && known->type == JSON_REAL &&
              json_get_real(known) == expected);
    return failures;
}

static int wrc_history_complete_assert(const struct json_value *result)
{
    int failures = 0;
    const struct json_value *in = json_get(result, "external_in");
    const struct json_value *out = json_get(result, "external_out");
    const struct json_value *bal = json_get(result, "utxo_balance");
    const struct json_value *fee = json_get(result, "total_fees");
    const struct json_value *known = json_get(result, "known_fee_subtotal");
    WRC_CHECK("complete loaded flow is 10 in, 5 out, 4 unspent, 1 fee",
              in && out && bal && fee && known && json_get_real(in) == 10.0 &&
              json_get_real(out) == 5.0 && json_get_real(bal) == 4.0 &&
              json_get_real(fee) == 1.0 && json_get_real(known) == 1.0);
    return failures;
}

static int wrc_accounting_history_read(struct wrc_f *f, const char *label,
                                       bool incomplete)
{
    int failures = 0;
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    bool ok = rpc_table_execute(f->tbl, "getwalletaccounting", &params, &result);
    WRC_CHECK("history accounting RPC succeeds", ok);
    char encoded[16384];
    size_t size = json_write(&result, encoded, sizeof(encoded));
    if (size < sizeof(encoded)) printf("ACCOUNTING_HISTORY %s %s\n", label, encoded);
    else printf("ACCOUNTING_HISTORY %s output-too-large\n", label);
    failures += wrc_history_global_assert(&result, incomplete);
    WRC_CHECK("wallet map capacity is explicit",
              wrc_bool(&result, "wallet_map_at_capacity", false) ==
              (strcmp(label, "wallet_map_limit") == 0));
    bool missing = strcmp(label, "missing_parent") == 0 ||
                   strcmp(label, "out_of_range") == 0 ||
                   strcmp(label, "known_first_missing_second") == 0;
    failures += missing ? wrc_history_missing_assert(&result, label)
                        : wrc_history_complete_assert(&result);
    json_free(&params);
    json_free(&result);
    return failures;
}

static int wrc_accounting_known_fee(struct wrc_f *f, struct wallet *w,
                                    struct wallet_tx *first_parent,
                                    const struct key_id *owned)
{
    int failures = 0;
    struct wallet_tx *parent = &w->map_wallet[2], *send = &w->map_wallet[3];
    parent->used = true; send->used = true;
    transaction_init(&parent->tx); transaction_init(&send->tx);
    bool allocated = transaction_alloc(&parent->tx, 0, 1) &&
                     transaction_alloc(&send->tx, 1, 1);
    WRC_CHECK("known-fee fixture allocates transactions", allocated);
    if (!allocated) return failures + 1;
    parent->confirms = 3; parent->tx.hash.data[0] = 0x61;
    parent->tx.vout[0].value = INT64_C(300000000);
    script_for_p2pkh(&parent->tx.vout[0].script_pub_key, owned);
    send->from_me = true; send->confirms = 3; send->tx.hash.data[0] = 0x62;
    send->tx.vin[0].prevout.hash = parent->tx.hash;
    send->tx.vin[0].prevout.n = 0;
    struct key_id other = {0}; other.id.data[0] = 0x79;
    send->tx.vout[0].value = INT64_C(200000000);
    script_for_p2pkh(&send->tx.vout[0].script_pub_key, &other);
    wallet_mark_outpoint_spent(w, &parent->tx.hash, 0);
    first_parent->used = false;
    wallet_unmark_outpoint_spent(w, &first_parent->tx.hash, 0);
    w->num_wallet_tx = 3;
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    bool ok = rpc_table_execute(f->tbl, "getwalletaccounting", &params, &result);
    const struct json_value *known = json_get(&result, "known_fee_subtotal");
    WRC_CHECK("known fee retained when another fee is unknown", ok &&
              wrc_history_null(&result, "total_fees") && known &&
              known->type == JSON_REAL && json_get_real(known) == 1.0);
    json_free(&params); json_free(&result);
    first_parent->used = true;
    w->num_wallet_tx = 4;
    return failures;
}

static int wrc_accounting_bad_fee(struct wrc_f *f, const char *label)
{
    int failures = 0;
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    bool ok = rpc_table_execute(f->tbl, "getwalletaccounting", &params, &result);
    char encoded[8192];
    if (json_write(&result, encoded, sizeof(encoded)) < sizeof(encoded))
        printf("ACCOUNTING_BAD_FEE %s %s\n", label, encoded);
    const struct json_value *child = wrc_history_send(&result);
    const struct json_value *total_in = json_get(child, "total_in");
    const struct json_value *known = json_get(&result, "known_fee_subtotal");
    WRC_CHECK("invalid fee is unknown but known input remains visible", ok && child &&
              wrc_int(&result, "unresolved_inputs") == 0 &&
              wrc_int(&result, "unresolved_fees") == 1 &&
              wrc_history_null(&result, "total_fees") && wrc_history_null(child, "fee") &&
              total_in && total_in->type == JSON_REAL && json_get_real(total_in) == 10.0 &&
              known && known->type == JSON_REAL && json_get_real(known) == 0.0);
    json_free(&params); json_free(&result);
    return failures;
}

static int wrc_accounting_history(struct wrc_f *f, struct wallet *original)
{
    int failures = 0;
    struct wallet *w = zcl_calloc(1, sizeof(*w), "accounting.history");
    if (!w) return 1;
    wallet_init(w);
    struct pubkey pk;
    bool created = wallet_generate_new_key(w, &pk);
    WRC_CHECK("history fixture generates a key", created);
    struct wallet_tx *parent = &w->map_wallet[0], *send = &w->map_wallet[1];
    transaction_init(&parent->tx);
    transaction_init(&send->tx);
    bool allocated = created && transaction_alloc(&parent->tx, 0, 1) &&
                     transaction_alloc(&send->tx, 2, 2);
    WRC_CHECK("history fixture allocates parent and send", allocated);
    if (allocated) {
        struct key_id ours = pubkey_get_id(&pk), other = {0};
        other.id.data[0] = 0x78;
        parent->used = true; parent->confirms = 3; parent->tx.hash.data[0] = 0x51;
        parent->tx.vout[0].value = INT64_C(1000000000);
        script_for_p2pkh(&parent->tx.vout[0].script_pub_key, &ours);
        send->used = true; send->confirms = 3; send->from_me = true;
        send->tx.hash.data[0] = 0x52;
        send->tx.vin[0].prevout.hash = parent->tx.hash;
        send->tx.vin[0].prevout.n = 0;
        send->tx.vin[1].prevout.hash.data[0] = 0x73;
        send->tx.vin[1].prevout.n = 0;
        send->tx.num_vin = 1;
        send->tx.vout[0].value = INT64_C(500000000);
        script_for_p2pkh(&send->tx.vout[0].script_pub_key, &other);
        send->tx.vout[1].value = INT64_C(400000000);
        script_for_p2pkh(&send->tx.vout[1].script_pub_key, &ours);
        w->num_wallet_tx = 2;
        wallet_mark_outpoint_spent(w, &parent->tx.hash, 0);
        rpc_wallet_set_state(w, f->ms, f->datadir, f->ws, f->mempool, NULL);
        failures += wrc_accounting_history_read(f, "complete", false);
        send->tx.vout[0].value = INT64_C(600000000);
        send->tx.vout[1].value = INT64_C(500000000);
        failures += wrc_accounting_bad_fee(f, "negative_fee");
        send->tx.vout[0].value = -1;
        send->tx.vout[1].value = INT64_C(400000000);
        failures += wrc_accounting_bad_fee(f, "invalid_value_out");
        send->tx.vout[0].value = INT64_C(500000000);
        parent->used = false;
        w->num_wallet_tx = 1;
        wallet_unmark_outpoint_spent(w, &parent->tx.hash, 0);
        failures += wrc_accounting_history_read(f, "missing_parent", true);
        parent->used = true;
        w->num_wallet_tx = 2;
        send->tx.vin[0].prevout.n = 1;
        failures += wrc_accounting_history_read(f, "out_of_range", true);
        send->tx.vin[0].prevout.n = 0;
        wallet_mark_outpoint_spent(w, &parent->tx.hash, 0);
        send->tx.num_vin = 2;
        failures += wrc_accounting_history_read(f, "known_first_missing_second", true);
        send->tx.num_vin = 1;
        w->scan_retry.pending = true;
        failures += wrc_accounting_history_read(f, "scan_retry_pending", true);
        w->scan_retry.pending = false;
        w->num_wallet_tx = MAX_WALLET_TX;
        failures += wrc_accounting_history_read(f, "wallet_map_limit", false);
        w->num_wallet_tx = 2;
        failures += wrc_accounting_known_fee(f, w, parent, &ours);
    }
    rpc_wallet_set_state(original, f->ms, f->datadir, f->ws, f->mempool, NULL);
    wallet_free(w);
    free(w);
    return failures;
}

static bool wrc_shielded_accounting_amounts(const struct json_value *result)
{
    const struct json_value *from = json_get(result, "from_shielded");
    const struct json_value *out = json_get(result, "external_out");
    const struct json_value *balance = json_get(result, "utxo_balance");
    const struct json_value *fee = json_get(result, "total_fees");
    const struct json_value *subtotal = json_get(result, "known_fee_subtotal");
    const struct json_value *tx_fee = json_get(wrc_history_send(result), "fee");
    return from && out && balance && fee && subtotal && tx_fee &&
        json_get_real(from) == 10.0 && json_get_real(out) == 5.0 &&
        json_get_real(balance) == 4.0 && json_get_real(fee) == 1.0 &&
        json_get_real(subtotal) == 1.0 && json_get_real(tx_fee) == 1.0;
}

static int wrc_accounting_shielded_funded(struct wrc_f *f, struct wallet *original)
{
    int failures = 0;
    struct wallet *w = zcl_calloc(1, sizeof(*w), "accounting.shielded");
    if (!w) return 1;
    wallet_init(w);
    struct pubkey pk;
    bool created = wallet_generate_new_key(w, &pk);
    struct wallet_tx *send = &w->map_wallet[0];
    transaction_init(&send->tx);
    bool allocated = created && transaction_alloc(&send->tx, 0, 2);
    WRC_CHECK("shielded-funded fixture allocates", allocated);
    if (allocated) {
        send->used = true; send->from_me = true; send->confirms = 3;
        send->tx.hash.data[0] = 0x92;
        send->tx.value_balance = INT64_C(1000000000);
        struct key_id ours = pubkey_get_id(&pk), other = {0};
        other.id.data[0] = 0x93;
        send->tx.vout[0].value = INT64_C(500000000);
        script_for_p2pkh(&send->tx.vout[0].script_pub_key, &other);
        send->tx.vout[1].value = INT64_C(400000000);
        script_for_p2pkh(&send->tx.vout[1].script_pub_key, &ours);
        w->num_wallet_tx = 1;
        rpc_wallet_set_state(w, f->ms, f->datadir, f->ws, f->mempool, NULL);
        struct json_value params = {0}, result = {0};
        json_set_array(&params);
        bool ok = rpc_table_execute(f->tbl, "getwalletaccounting", &params, &result);
        char encoded[8192];
        if (json_write(&result, encoded, sizeof(encoded)) < sizeof(encoded))
            printf("ACCOUNTING_SHIELDED_FUNDED %s\n", encoded);
        WRC_CHECK("shielded-funded RPC reports 10 in, 5 out, 4 unspent, 1 fee",
                  ok && wrc_shielded_accounting_amounts(&result));
        json_free(&result);
        zcl_mutex_lock(&w->cs);
        send->tx.vout[1].value = INT64_C(300000000);
        zcl_mutex_unlock(&w->cs);
        ok = rpc_table_execute(f->tbl, "getwalletaccounting", &params, &result);
        const struct json_value *balance = json_get(&result, "utxo_balance");
        const struct json_value *fee = json_get(&result, "total_fees");
        const struct json_value *count = json_get(&result, "tx_count");
        WRC_CHECK("accounting RPC reflects a subsequent wallet update consistently",
                  ok && balance && fee && count &&
                  json_get_real(balance) == 3.0 && json_get_real(fee) == 2.0 &&
                  json_get_int(count) == 1);
        json_free(&params); json_free(&result);
    }
    rpc_wallet_set_state(original, f->ms, f->datadir, f->ws, f->mempool, NULL);
    wallet_free(w);
    free(w);
    return failures;
}

/* A wallet as the next boot builds it: key, flushed txs, then scan state. */
static struct wallet *wrc_reboot_wallet(struct wrc_f *f)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "test-wallet");
    wallet_init(w);
    struct privkey key;
    if (wallet_dump_key(f->owner, f->kid, &key))
        (void)wallet_import_key(w, &key);
    /* The same Sapling key as the fixture wallet: a rescan with none counts
     * the shielded outputs untried and cannot clear the marker. */
    uint8_t seed[32], d[11], pk[32];
    memset(seed, 0x2e, sizeof(seed));
    (void)sapling_keystore_set_seed(&w->sapling_keys, seed);
    (void)sapling_keystore_new_address(&w->sapling_keys, d, pk);
    (void)wallet_sqlite_read_txs(f->ws, w);
    (void)wallet_sqlite_read_scan_state(f->ws, w);
    return w;
}

/* getwalletinfo's scan block for `w`: its status and blocker strings. */
static bool wrc_walletinfo_scan(struct wrc_f *f, struct wallet *w,
                                const char *status, const char *blocker)
{
    rpc_wallet_set_state(w, f->ms, f->datadir, f->ws, f->mempool, NULL);
    struct json_value params, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    bool ok = rpc_table_execute(f->tbl, "getwalletinfo", &params, &result);
    const struct json_value *scan = ok ? json_get(&result, "scan") : NULL;
    ok = scan && strcmp(wrc_str(scan, "status"), status) == 0 &&
         strcmp(wrc_str(scan, "blocker"), blocker) == 0;
    json_free(&params);
    json_free(&result);
    return ok;
}

/* F1. Zero readable bodies: every read fails, as in the journey run. */
static int wrc_f1_no_readable_body(struct wrc_f *f)
{
    int failures = 0;
    struct wallet *w = f->w;
    w->best_block_height = WRC_F_PREV;
    w->time_first_key = 0;
    bool hid = rename(f->net_blocks, f->hidden) == 0;
    failures += wrc_expect("F1: block files moved out of reach", hid);
    struct wallet_rescan_report rep;
    memset(&rep, 0, sizeof(rep));
    int found = boot_wallet_catch_up(w, &f->ms->chain_active, f->datadir,
                                     &rep);
    failures += wrc_expect("F1: the catch-up ran over the gap",
                           found == 0 && rep.start_height == WRC_F_PREV + 1 &&
                           rep.stop_height == WRC_F_LAST);
    failures += wrc_expect("F1: every body read failed",
                           rep.blocks_scanned == 0 &&
                           rep.blocks_read_failed == WRC_F_LAST - WRC_F_PREV);
    failures += wrc_expect("F1: the blocker is returned: RESCAN_NO_BLOCK_DATA",
                           !rep.coverage_ok &&
                           strcmp(rep.blocker,
                                  WALLET_RESCAN_BLOCKER_NO_BLOCK_DATA) == 0);
    failures += wrc_expect("F1: the wallet still scanned through its old height",
                           wallet_scanned_through_height(w) == WRC_F_PREV);
    failures += wrc_expect("F1: the marker holds the start, blocker and time",
                           w->scan_retry.pending &&
                           w->scan_retry.from == WRC_F_PREV + 1 &&
                           w->scan_retry.since > 0 &&
                           strcmp(w->scan_retry.blocker,
                                  WALLET_RESCAN_BLOCKER_NO_BLOCK_DATA) == 0);
    failures += wrc_expect("F1: nothing recorded from blocks not read",
                           w->num_wallet_tx == 0);
    failures += wrc_expect("F1: a later catch-up is not skipped at the tip",
                           boot_wallet_catch_up(w, &f->ms->chain_active,
                                                f->datadir, &rep) == 0 &&
                           !rep.coverage_ok &&
                           rep.start_height == WRC_F_PREV + 1);
    failures += wrc_expect("F1: getwalletinfo reports scan incomplete",
                           wrc_walletinfo_scan(f, w, "incomplete",
                                               "RESCAN_NO_BLOCK_DATA"));
    if (hid)
        (void)rename(f->hidden, f->net_blocks);
    return failures;
}

/* F1 across a restart: flush, reboot a fresh wallet, and neither the
 * durable height nor the marker may have moved. */
static int wrc_f1_restart(struct wrc_f *f)
{
    int failures = 0;
    struct zcl_result fr = wallet_sqlite_flush_transactions_r(f->ws, f->w);
    int saved = -1;
    failures += wrc_expect("F1: the flushed scan height is not advanced",
                           fr.ok &&
                           wallet_sqlite_read_scan_height(f->ws, &saved) &&
                           saved == WRC_F_PREV);
    struct wallet_scan_marker m;
    failures += wrc_expect("F1: the flushed marker holds range and blocker",
                           wallet_sqlite_read_scan_marker(f->ws, &m) &&
                           m.from == WRC_F_PREV + 1 &&
                           m.depth_height == WRC_F_LAST && m.since > 0 &&
                           strcmp(m.blocker, "RESCAN_NO_BLOCK_DATA") == 0);
    struct wallet *next = wrc_reboot_wallet(f);
    failures += wrc_expect("F1: after reboot the height is still not advanced",
                           wallet_scanned_through_height(next) == WRC_F_PREV &&
                           next->best_block_height == WRC_F_LAST);
    failures += wrc_expect("F1: after reboot the marker is still present",
                           next->scan_retry.pending &&
                           next->scan_retry.from == WRC_F_PREV + 1 &&
                           strcmp(next->scan_retry.blocker,
                                  "RESCAN_NO_BLOCK_DATA") == 0);
    wallet_free(next);
    free(next);
    return failures;
}

/* F2. Partial coverage under the floor: 50..149 read, 150..199 have no body
 * (100 of 150 = 66%). The output the read blocks carry is kept. */
static int wrc_f2_partial(struct wrc_f *f)
{
    int failures = 0;
    struct wallet *w = f->w;
    for (int i = WRC_F_FOUND_AT + 1; i < WRC_NBLOCKS; i++)
        f->idx[i].nStatus &= ~BLOCK_HAVE_DATA;
    struct wallet_rescan_report rep;
    memset(&rep, 0, sizeof(rep));
    int found = boot_wallet_catch_up(w, &f->ms->chain_active, f->datadir,
                                     &rep);
    failures += wrc_expect("F2: the retry rescans from the pending start",
                           rep.start_height == WRC_F_PREV + 1 &&
                           rep.stop_height == WRC_F_LAST);
    failures += wrc_expect("F2: 100 of 150 read, RESCAN_INCOMPLETE_COVERAGE",
                           rep.blocks_scanned == 100 &&
                           rep.blocks_missing_data == 50 && !rep.coverage_ok &&
                           strcmp(rep.blocker,
                                  WALLET_RESCAN_BLOCKER_INCOMPLETE) == 0);
    failures += wrc_expect("F2: the outputs in the read blocks were found",
                           found == 100);
    failures += wrc_expect("F2: the wallet still scanned through its old height",
                           wallet_scanned_through_height(w) == WRC_F_PREV &&
                           w->scan_retry.pending &&
                           w->scan_retry.from == WRC_F_PREV + 1);
    const struct wallet_tx *wtx = wrc_only_tx(w);
    failures += wrc_expect("F2: the found coin is kept at depth tip-149+1",
                           wtx && wtx->confirms == WRC_F_LAST - WRC_F_FOUND_AT + 1);
    struct zcl_result fr = wallet_sqlite_flush_transactions_r(f->ws, w);
    failures += wrc_expect("F2: the flush succeeds", fr.ok);
    return failures;
}

/* F2 across a restart: the coinbase found at 149 must mature exactly 100
 * blocks later. Had the reboot measured its stored depth from the durable
 * scan height (49) instead of the marker's depth height (199), the first
 * advance would add 198 instead of 48 and the coin would look mature at 247. */
static int wrc_f2_restart_maturity(struct wrc_f *f, struct wallet *w)
{
    int failures = 0;
    const struct wallet_tx *wtx = wrc_only_tx(w);
    failures += wrc_expect("F2: after reboot the coin keeps its true depth",
                           wtx && w->num_wallet_tx == 1 &&
                           wtx->confirms == WRC_F_LAST - WRC_F_FOUND_AT + 1 &&
                           w->best_block_height == WRC_F_LAST &&
                           wallet_scanned_through_height(w) == WRC_F_PREV);
    const int almost = WRC_F_FOUND_AT + COINBASE_MATURITY - 2;
    (void)wallet_advance_confirmations(w, almost);
    struct coin_entry coins[4];
    size_t ncoins = 9;
    wallet_available_coins(w, coins, &ncoins, 4, true, false);
    failures += wrc_expect("F2: one block short of maturity it is not spendable",
                           wtx && wtx->confirms == COINBASE_MATURITY - 1 &&
                           wallet_tx_get_blocks_to_maturity(wtx) == 1 &&
                           ncoins == 0 && wallet_get_balance(w) == 0);
    (void)wallet_advance_confirmations(w, almost + 1);
    wallet_available_coins(w, coins, &ncoins, 4, true, false);
    failures += wrc_expect("F2: it matures on its 100th confirmation, not before",
                           wtx && wtx->confirms == COINBASE_MATURITY &&
                           ncoins == 1 && wallet_get_balance(w) == WRC_F_VALUE);
    (void)wallet_rewind_confirmations(w, WRC_F_LAST);
    failures += wrc_expect("F2: rewinding to the tip restores the depth",
                           wtx && wtx->confirms == WRC_F_LAST - WRC_F_FOUND_AT + 1);
    (void)f;
    return failures;
}

/* F3. On the rebooted wallet, a catch-up that can read the range advances,
 * finds the coins once, and clears the marker durably. */
static int wrc_f3_readable(struct wrc_f *f, struct wallet *w)
{
    int failures = 0;
    for (int i = 0; i < WRC_NBLOCKS; i++)
        f->idx[i].nStatus |= BLOCK_HAVE_DATA;
    struct wallet_rescan_report rep;
    memset(&rep, 0, sizeof(rep));
    failures += wrc_expect("F3: initialize pending cutover",
        wallet_readiness_initialize(w, WALLET_READINESS_PENDING, false, 0));
    (void)boot_wallet_catch_up(w, &f->ms->chain_active, f->datadir, &rep);
    failures += wrc_expect("F3: full boot catchup preserves cutover marker",
        rep.blocks_scanned == WRC_F_LAST - WRC_F_PREV &&
        w->scan_retry.pending && w->scan_retry.from == WRC_F_PREV + 1);
    failures += wrc_expect("F3: fixture completes cutover",
        wallet_readiness_complete(w, false, 0));
    int found = boot_wallet_catch_up(w, &f->ms->chain_active, f->datadir,
                                     &rep);
    failures += wrc_expect("F3: the retry rereads 50..199 in full",
                           rep.start_height == WRC_F_PREV + 1 &&
                           rep.stop_height == WRC_F_LAST &&
                           rep.blocks_scanned == WRC_F_LAST - WRC_F_PREV &&
                           rep.coverage_ok && rep.blocker[0] == '\0');
    failures += wrc_expect("F3: it finds the coins",
                           found == WRC_F_LAST - WRC_F_PREV);
    failures += wrc_expect("F3: the wallet now scans through the tip",
                           !w->scan_retry.pending &&
                           wallet_scanned_through_height(w) == WRC_F_LAST &&
                           w->best_block_height == WRC_F_LAST);
    failures += wrc_expect("F3: rereading blocks F2 read counts the coin once",
                           w->num_wallet_tx == 1 &&
                           wallet_get_immature_balance(w) == WRC_F_VALUE);
    int saved = -1;
    struct wallet_scan_marker m;
    struct zcl_result fr = wallet_sqlite_flush_transactions_r(f->ws, w);
    failures += wrc_expect("F3: the flush advances the height, clears the marker",
                           fr.ok &&
                           wallet_sqlite_read_scan_height(f->ws, &saved) &&
                           saved == WRC_F_LAST &&
                           !wallet_sqlite_read_scan_marker(f->ws, &m));
    failures += wrc_expect("F3: getwalletinfo reports scan complete",
                           wrc_walletinfo_scan(f, w, "complete", ""));
    failures += wrc_expect("F3: a wallet level with the tip runs no rescan",
                           boot_wallet_catch_up(w, &f->ms->chain_active,
                                                f->datadir, NULL) == -1);
    return failures;
}

/* F4. One unread body in a 150-block gap: 149 of 150 read clears the 99%
 * floor and the read blocks hold coins, so the rescan's own coverage_ok is
 * true. The catch-up must still hold the marker: the unread block can carry
 * a coin, and the owner requires a full read before the marker clears. */
#define WRC_F4_UNREAD 120
static int wrc_f4_one_unread_body(struct wrc_f *f, struct wallet *w)
{
    int failures = 0;
    w->best_block_height = WRC_F_PREV;
    f->idx[WRC_F4_UNREAD].nStatus &= ~BLOCK_HAVE_DATA;
    struct wallet_rescan_report rep;
    memset(&rep, 0, sizeof(rep));
    int found = boot_wallet_catch_up(w, &f->ms->chain_active, f->datadir,
                                     &rep);
    failures += wrc_expect("F4: 149 of 150 read, coins found, floor cleared",
                           rep.start_height == WRC_F_PREV + 1 &&
                           rep.blocks_scanned == WRC_F_LAST - WRC_F_PREV - 1 &&
                           rep.blocks_missing_data == 1 && found > 0);
    failures += wrc_expect("F4: one unread body still leaves the marker set",
                           w->scan_retry.pending &&
                           w->scan_retry.from == WRC_F_PREV + 1 &&
                           strcmp(w->scan_retry.blocker,
                                  WALLET_RESCAN_BLOCKER_INCOMPLETE) == 0 &&
                           wallet_scanned_through_height(w) == WRC_F_PREV);
    int saved = -1;
    struct wallet_scan_marker m;
    struct zcl_result fr = wallet_sqlite_flush_transactions_r(f->ws, w);
    failures += wrc_expect("F4: the flush keeps the height and the marker",
                           fr.ok &&
                           wallet_sqlite_read_scan_height(f->ws, &saved) &&
                           saved == WRC_F_PREV &&
                           wallet_sqlite_read_scan_marker(f->ws, &m) &&
                           m.from == WRC_F_PREV + 1);
    f->idx[WRC_F4_UNREAD].nStatus |= BLOCK_HAVE_DATA;
    memset(&rep, 0, sizeof(rep));
    (void)boot_wallet_catch_up(w, &f->ms->chain_active, f->datadir, &rep);
    failures += wrc_expect("F4: a full reread clears the marker",
                           rep.blocks_scanned == WRC_F_LAST - WRC_F_PREV &&
                           !w->scan_retry.pending &&
                           wallet_scanned_through_height(w) == WRC_F_LAST);
    return failures;
}

/* F. A boot catch-up that cannot read its range must not leave the wallet
 * claiming it scanned through the tip. The journey run that found this read
 * every body from the wrong directory; the rescan failed every read, still
 * moved the wallet to the tip, and the flush made that permanent, so no
 * later boot looked at those blocks again. The wallet must keep its last
 * fully scanned height in memory and on disk across a restart, keep a
 * durable marker naming the blocker, keep what it did find at its true
 * depth, and find the coins once and clear the marker when a later
 * catch-up can read the range. */
static int wrc_f_steps(struct wrc_f *f)
{
    int failures = wrc_f1_no_readable_body(f);
    failures += wrc_f1_restart(f);
    failures += wrc_f2_partial(f);
    struct wallet *rebooted = wrc_reboot_wallet(f);
    failures += wrc_f2_restart_maturity(f, rebooted);
    failures += wrc_f3_readable(f, rebooted);
    failures += wrc_f4_one_unread_body(f, rebooted);
    wallet_free(rebooted);
    free(rebooted);
    return failures;
}

static int wrc_boot_catch_up_fail_closed(struct wrc_f *f)
{
    int failures = 0;
    f->w = zcl_calloc(1, sizeof(*f->w), "test-wallet");
    wallet_init(f->w);
    struct privkey key;
    failures += wrc_expect("F: fresh wallet holds the fixture key",
                           wallet_dump_key(f->owner, f->kid, &key) &&
                           wallet_import_key(f->w, &key));
    /* A Sapling key to try: a wallet that holds none has its shielded outputs
     * counted untried, and an untried read cannot clear the unread marker. */
    uint8_t fseed[32], fd[11], fpk[32];
    memset(fseed, 0x2e, sizeof(fseed));
    (void)sapling_keystore_set_seed(&f->w->sapling_keys, fseed);
    (void)sapling_keystore_new_address(&f->w->sapling_keys, fd, fpk);

    for (int i = 0; i < WRC_NBLOCKS; i++)
        f->idx[i].nStatus |= BLOCK_HAVE_DATA;
    char netdir[320], base_blocks[352];
    snprintf(netdir, sizeof(netdir), "%s/regtest", f->datadir);
    snprintf(base_blocks, sizeof(base_blocks), "%s/blocks", f->datadir);
    snprintf(f->net_blocks, sizeof(f->net_blocks), "%s/blocks", netdir);
    snprintf(f->hidden, sizeof(f->hidden), "%s/blocks.hidden", netdir);
    chain_params_select(CHAIN_REGTEST);
    bool relaid = SetDataDir(f->datadir) &&
                  rename(base_blocks, f->net_blocks) == 0;
    failures += wrc_expect("F: bodies laid out under <base>/regtest/blocks",
                           relaid);

    failures += wrc_f_steps(f);

    if (relaid)
        (void)rename(f->net_blocks, base_blocks);
    SetDataDir("");
    ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);
    test_cleanup_tmpdir(netdir);
    wallet_free(f->w);
    free(f->w);
    return failures;
}

/* K. A rescan that clears the unread marker reaches disk through the real
 * rescanblockchain RPC: the persisted marker is gone, not just the live one. */
static int wrc_k_cleared_marker_persists(struct wallet *w,
                                         struct wallet_sqlite *ws,
                                         struct rpc_table *tbl,
                                         struct block_index *idx, int last)
{
    int failures = 0;
    for (int i = 0; i < WRC_NBLOCKS; i++)
        idx[i].nStatus |= BLOCK_HAVE_DATA;
    uint8_t seed[32], d[11], pk[32];
    memset(seed, 0x4b, sizeof(seed));
    (void)sapling_keystore_set_seed(&w->sapling_keys, seed);
    (void)sapling_keystore_new_address(&w->sapling_keys, d, pk);
    w->scan_retry.pending = true;
    w->scan_retry.from = 0;
    w->scan_retry.since = 1;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             WALLET_RESTORE_BLOCKER_UNREAD);
    struct wallet_scan_marker m;
    WRC_CHECK("K: the pending marker is on disk before the rescan",
              wallet_sqlite_write_scan_state(ws, w) &&
              wallet_sqlite_read_scan_marker(ws, &m) && m.from == 0);
    struct json_value params, result;
    wrc_params(&params, 0, last);
    json_init(&result);
    bool ok = rpc_table_execute(tbl, "rescanblockchain", &params, &result);
    WRC_CHECK("K: a whole rescan clears the live marker", ok &&
              !w->scan_retry.pending);
    WRC_CHECK("K: and the cleared marker reaches disk",
              !wallet_sqlite_read_scan_marker(ws, &m));
    json_free(&params);
    json_free(&result);
    sapling_keystore_free(&w->sapling_keys);
    sapling_keystore_init(&w->sapling_keys);
    return failures;
}

/* G fixture: one block at WRC_G_COIN_AT pays the wallet; every other height
 * shares a body whose one coinbase pays an empty script, so the catch-up
 * gap is fully readable and holds nothing of the wallet's — the shape of
 * the journey's empty coinbase gap. The coin matures exactly at the tip. */
#define WRC_G_BLOCKS 161     /* heights 0..160 */
#define WRC_G_COIN_AT 60     /* last flushed baseline, and the coin's height */
#define WRC_G_VALUE 1000000
#define WRC_G_TIP (WRC_G_BLOCKS - 1)

static struct wallet *wrc_g_reboot(struct wallet *owner,
                                   const struct key_id *kid,
                                   struct wallet_sqlite *ws)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "test-wallet");
    wallet_init(w);
    struct privkey key;
    if (wallet_dump_key(owner, kid, &key))
        (void)wallet_import_key(w, &key);
    (void)wallet_sqlite_read_txs(ws, w);
    (void)wallet_sqlite_read_scan_state(ws, w);
    return w;
}

static bool wrc_set_merkle(struct block *block)
{
    struct uint256 hashes[2];
    if (block->num_vtx > 2) return false;
    for (size_t i = 0; i < block->num_vtx; i++) {
        transaction_compute_hash(&block->vtx[i]);
        hashes[i] = block->vtx[i].hash;
    }
    bool mutated = false;
    block->header.hashMerkleRoot = merkle_root_mutated_in_place(hashes, block->num_vtx, &mutated);
    return true;
}

/* Write one coinbase-shaped tx block to disk; `pay` selects whose output. */
static bool wrc_g_write_body(struct script *pay, struct disk_block_pos *pos,
                             const char *dir)
{
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000000u;
    blk.header.nBits = 0x2000ffffu;
    blk.num_vtx = 1;
    blk.vtx = calloc(1, sizeof(*blk.vtx)); /* raw-alloc-ok:test-fixture */
    bool wrote = false;
    if (blk.vtx) {
        struct transaction *t0 = &blk.vtx[0];
        transaction_init(t0);
        t0->version = 1;
        t0->vin = calloc(1, sizeof(*t0->vin)); /* raw-alloc-ok:test-fixture */
        t0->vout = calloc(1, sizeof(*t0->vout)); /* raw-alloc-ok:test-fixture */
        if (t0->vin && t0->vout) {
            t0->num_vin = 1;
            t0->num_vout = 1;
            outpoint_set_null(&t0->vin[0].prevout);
            script_init(&t0->vin[0].script_sig);
            t0->vin[0].sequence = 0xffffffffu;
            t0->vout[0].value = WRC_G_VALUE;
            t0->vout[0].script_pub_key = *pay;
            unsigned char msg_start[4] = { 0x24, 0xe9, 0x27, 0x64 };
            wrote = wrc_set_merkle(&blk) && write_block_to_disk(&blk, pos, dir, msg_start);
        }
    }
    block_free(&blk);
    return wrote;
}

/* Point n synthetic index entries at one shared on-disk body whose hash is
 * `hash`, as a real index entry names the block it indexes. */
static void wrc_fill_chain(struct block_index *idx, struct block_index **chain,
                           const struct disk_block_pos *pos,
                           const struct uint256 *hash, int n)
{
    for (int i = 0; i < n; i++) {
        block_index_init(&idx[i]);
        idx[i].nHeight = i;
        idx[i].nFile = pos->nFile;
        idx[i].nDataPos = pos->nPos;
        idx[i].nStatus = BLOCK_HAVE_DATA;
        idx[i].phashBlock = hash;
        chain[i] = &idx[i];
    }
}

/* Create <gdir> and its blocks subdir; blocksdir is filled only on Windows,
 * where there is no POSIX shell and the two directories are made directly. */
static bool wrc_g_make_fixture_dirs(const char *gdir, char *blocksdir,
                                    size_t blocksdir_size)
{
#if defined(_WIN32)
    snprintf(blocksdir, blocksdir_size, "%s/blocks", gdir);
    if (platform_directory_create(gdir, 0700) != 0 ||
        platform_directory_create(blocksdir, 0700) != 0)
        return false;
#else
    {
        char cmd[512];
        (void)blocksdir;
        (void)blocksdir_size;
        snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s/blocks",
                 gdir, gdir);
        if (system(cmd) != 0)
            return false;
    }
#endif
    return true;
}

/* The pre-kill scan: the coin sits at depth 1 on the baseline height,
 * immature, with nothing spendable yet. */
static bool wrc_g_prekill_state(struct wallet *w,
                                const struct wallet_tx *wtx, int found)
{
    return found == 1 && wtx && wtx->confirms == 1 &&
           w->best_block_height == WRC_G_COIN_AT &&
           wallet_get_balance(w) == 0 &&
           wallet_get_immature_balance(w) == WRC_G_VALUE;
}

/* The durable scan height still names the pre-kill baseline. */
static bool wrc_g_holds_baseline(struct wallet_sqlite *ws, bool flush_ok)
{
    int saved = -1;
    return flush_ok && wallet_sqlite_read_scan_height(ws, &saved) &&
           saved == WRC_G_COIN_AT;
}

/* The rebooted wallet: baseline 60, the coin back at depth 1, unspendable. */
static bool wrc_g_stale_baseline_restored(struct wallet *w,
                                          const struct wallet_tx *wtx)
{
    return w->best_block_height == WRC_G_COIN_AT &&
           w->num_wallet_tx == 1 && wtx && wtx->confirms == 1 &&
           wallet_get_balance(w) == 0;
}

/* The catch-up report for a fully read gap that holds nothing of ours. */
static bool wrc_g_empty_gap_read(const struct wallet_rescan_report *rep,
                                 int found)
{
    return found == 0 && rep->start_height == WRC_G_COIN_AT + 1 &&
           rep->stop_height == WRC_G_TIP &&
           rep->blocks_scanned == WRC_G_TIP - WRC_G_COIN_AT &&
           rep->coverage_ok && rep->blocker[0] == '\0';
}

/* The wallet's scan baseline stands at the tip, with no retry pending. */
static bool wrc_g_baseline_at_tip(const struct wallet *w)
{
    return w->best_block_height == WRC_G_TIP && !w->scan_retry.pending;
}

/* The coin's stored depth is measured from the tip, not the old baseline. */
static bool wrc_g_depth_from_tip(const struct wallet_tx *wtx)
{
    return wtx && wtx->confirms == WRC_G_TIP - WRC_G_COIN_AT + 1;
}

/* The real depth reaches maturity exactly at the tip. */
static bool wrc_g_mature_at_tip(const struct wallet_tx *wtx)
{
    return wtx && wallet_tx_get_blocks_to_maturity(wtx) == 0;
}

/* One wallet tx, fully spendable at the fixture value. */
static bool wrc_g_spendable_balance(struct wallet *w)
{
    return w->num_wallet_tx == 1 && wallet_get_balance(w) == WRC_G_VALUE;
}

/* The corrected depth and balance survive a flush and a reboot. */
static bool wrc_g_depth_holds_after_reboot(struct wallet *w,
                                           const struct wallet_tx *wtx,
                                           bool flush_ok)
{
    return flush_ok && wtx &&
           wtx->confirms == WRC_G_TIP - WRC_G_COIN_AT + 1 &&
           w->best_block_height == WRC_G_TIP &&
           wallet_get_balance(w) == WRC_G_VALUE;
}

static int wrc_g_kill_restart_baseline(struct wallet *owner,
                                       const struct key_id *kid,
                                       const char *basedir)
{
    int failures = 0;
    char gdir[300];
    snprintf(gdir, sizeof(gdir), "%s_g", basedir);
    char blocksdir[360];
    if (!wrc_g_make_fixture_dirs(gdir, blocksdir, sizeof(blocksdir)))
        return wrc_expect("G: fixture directory", false);

    struct node_db ndb;
    char dbpath[380];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", gdir);
    failures += wrc_expect("G: node_db_open", node_db_open(&ndb, dbpath));

    struct script pay_to_us;
    script_init(&pay_to_us);
    script_for_p2pkh(&pay_to_us, kid);
    struct script pay_to_nobody;
    script_init(&pay_to_nobody);  /* empty script: documented unclaimable */

    struct disk_block_pos pos_us, pos_empty;
    disk_block_pos_init(&pos_us);
    disk_block_pos_init(&pos_empty);
    failures += wrc_expect("G: coin body at the baseline height",
                           wrc_g_write_body(&pay_to_us, &pos_us, gdir));
    failures += wrc_expect("G: empty-coinbase bodies across the gap",
                           wrc_g_write_body(&pay_to_nobody, &pos_empty, gdir));

    struct block_index *idx =
        calloc(WRC_G_BLOCKS, sizeof(*idx)); /* raw-alloc-ok:test-fixture */
    struct block_index **chain =
        calloc(WRC_G_BLOCKS, sizeof(*chain)); /* raw-alloc-ok:test-fixture */
    wrc_fill_chain(idx, chain, &pos_empty, NULL, WRC_G_BLOCKS);
    idx[WRC_G_COIN_AT].nFile = pos_us.nFile;
    idx[WRC_G_COIN_AT].nDataPos = pos_us.nPos;

    struct main_state ms;
    main_state_init(&ms);
    free(ms.chain_active.chain);
    ms.chain_active.chain = chain;
    ms.chain_active.height = WRC_G_TIP;
    ms.chain_active.capacity = WRC_G_BLOCKS;

    struct wallet_sqlite ws;
    failures += wrc_expect("G: wallet_sqlite_open",
                           wallet_sqlite_open(&ws, ndb.db));

    /* The wallet as it ran before the kill: scanned through the coin's
     * height, depth measured from that baseline. */
    struct wallet *w = wrc_g_reboot(owner, kid, &ws);
    struct wallet_rescan_report rep;
    memset(&rep, 0, sizeof(rep));
    int found = wallet_rescan_report(w, &ms.chain_active, WRC_G_COIN_AT,
                                     WRC_G_COIN_AT, gdir, &rep);
    const struct wallet_tx *wtx = wrc_only_tx(w);
    failures += wrc_expect("G: the pre-kill scan finds the coin at depth 1",
                           wrc_g_prekill_state(w, wtx, found));
    struct zcl_result fr = wallet_sqlite_flush_transactions_r(&ws, w);
    failures += wrc_expect("G: the kill-time flush holds height 60, no marker",
                           wrc_g_holds_baseline(&ws, fr.ok));
    wallet_free(w);
    free(w);

    /* Next boot: the durable state restores the baseline, the chain grew
     * 100 blocks past it, and every gap body is readable but ours-free. */
    w = wrc_g_reboot(owner, kid, &ws);
    wtx = wrc_only_tx(w);
    failures += wrc_expect("G: reboot restores the stale baseline 60",
                           wrc_g_stale_baseline_restored(w, wtx));
    memset(&rep, 0, sizeof(rep));
    found = wallet_rescan_report(w, &ms.chain_active, WRC_G_COIN_AT + 1,
                                 WRC_G_TIP, gdir, &rep);
    wtx = wrc_only_tx(w);
    failures += wrc_expect("G: the catch-up reads the whole empty gap",
                           wrc_g_empty_gap_read(&rep, found));
    failures += wrc_expect("G: the baseline moved to the tip",
                           wrc_g_baseline_at_tip(w));
    failures += wrc_expect("G: the stored depth is measured from the tip",
                           wrc_g_depth_from_tip(wtx));
    failures += wrc_expect("G: the coin matures with the real depth",
                           wrc_g_mature_at_tip(wtx));
    failures += wrc_expect("G: getbalance spends it — no phantom immaturity",
                           wrc_g_spendable_balance(w));

    /* The corrected depth survives its own flush and reboot. */
    fr = wallet_sqlite_flush_transactions_r(&ws, w);
    wallet_free(w);
    free(w);
    w = wrc_g_reboot(owner, kid, &ws);
    wtx = wrc_only_tx(w);
    failures += wrc_expect("G: after flush+reboot the depth and balance hold",
                           wrc_g_depth_holds_after_reboot(w, wtx, fr.ok));
    wallet_free(w);
    free(w);

    wallet_sqlite_close(&ws);
    ms.chain_active.chain = NULL;
    ms.chain_active.capacity = 0;
    ms.chain_active.height = 0;
    free(chain);
    free(idx);
    node_db_close(&ndb);
#if defined(_WIN32)
    test_cleanup_tmpdir(blocksdir);
    test_cleanup_tmpdir(gdir);
#else
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", gdir);
         TEST_DISCARD(system(cmd));
    }
#endif
    return failures;
}

/* Create the fixture datadir and its blocks subdir; blocksdir is filled only
 * on Windows, where there is no POSIX shell and the two directories are made
 * directly. */
static bool wrc_create_fixture_dirs(const char *datadir, char *blocksdir,
                                    size_t blocksdir_size)
{
#if defined(_WIN32)
    /* No POSIX shell on Windows: create the two directories directly. The
     * pid suffix makes the path unique, so the rm -rf pre-clean is a no-op
     * there anyway. */
    snprintf(blocksdir, blocksdir_size, "%s/blocks", datadir);
    return platform_directory_create(datadir, 0700) == 0 &&
           platform_directory_create(blocksdir, 0700) == 0;
#else
    {
        char cmd[512];
        (void)blocksdir;
        (void)blocksdir_size;
        snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s/blocks",
                 datadir, datadir);
        return system(cmd) == 0;
    }
#endif
}

/* ── one real block on disk: a coinbase-shaped tx paying our key, plus
 * a Sapling tx carrying one shielded output. The second tx is what
 * makes the "wallet holds no Sapling key" condition observable — the
 * seed-only-restore state, which used to be skipped in total silence. */
static bool wrc_write_shared_body(const char *datadir,
                                  const struct script *pay_to_us,
                                  struct disk_block_pos *pos,
                                  struct uint256 *hash)
{
    bool wrote = false;
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000000u;
    blk.header.nBits = 0x2000ffffu;
    blk.num_vtx = 2;
    blk.vtx = calloc(2, sizeof(*blk.vtx)); /* raw-alloc-ok:test-fixture */
    if (blk.vtx) {
        /* tx0 — pays our key */
        struct transaction *t0 = &blk.vtx[0];
        transaction_init(t0);
        t0->version = 1;
        t0->vin = calloc(1, sizeof(*t0->vin)); /* raw-alloc-ok:test-fixture */
        t0->vout = calloc(1, sizeof(*t0->vout)); /* raw-alloc-ok:test-fixture */
        if (t0->vin && t0->vout) {
            t0->num_vin = 1;
            t0->num_vout = 1;
            outpoint_set_null(&t0->vin[0].prevout);
            script_init(&t0->vin[0].script_sig);
            t0->vin[0].sequence = 0xffffffffu;
            t0->vout[0].value = 1000000;
            /* struct script is a fixed-size value type — plain copy. */
            t0->vout[0].script_pub_key = *pay_to_us;
        }
        /* tx1 — Sapling v4 with one (all-zero) shielded output */
        struct transaction *t1 = &blk.vtx[1];
        transaction_init(t1);
        t1->overwintered = true;
        t1->version = 4;
        t1->version_group_id = 0x892F2085u;
        t1->v_shielded_output =
            calloc(1, sizeof(*t1->v_shielded_output)); /* raw-alloc-ok:test-fixture */
        if (t1->v_shielded_output)
            t1->num_shielded_output = 1;

        unsigned char msg_start[4] = { 0x24, 0xe9, 0x27, 0x64 };
        wrote = wrc_set_merkle(&blk) && write_block_to_disk(&blk, pos, datadir, msg_start);
        if (wrote)
            block_get_hash(&blk, hash);
    }
    block_free(&blk);
    return wrote;
}

/* Set or clear BLOCK_HAVE_DATA across the first n index entries. */
static void wrc_set_have_data(struct block_index *idx, int n, bool have)
{
    for (int i = 0; i < n; i++)
        if (have)
            idx[i].nStatus |= BLOCK_HAVE_DATA;
        else
            idx[i].nStatus &= ~BLOCK_HAVE_DATA;
}

static int wrc_deny_release(void *arg, int action, const char *a,
                            const char *b, const char *c, const char *d)
{
    (void)arg; (void)b; (void)c; (void)d;
    return action == SQLITE_SAVEPOINT && a && strcmp(a, "RELEASE") == 0
        ? SQLITE_DENY : SQLITE_OK;
}
static int wrc_cutover_corruption(sqlite3 *db, struct wallet_sqlite *ws,
                                  struct wallet *w, struct wallet_cutover_binding b)
{
    int failures = 0;
    struct wallet_cutover_binding out;
    WRC_CHECK("invalid marker setup", sqlite3_exec(db, "SAVEPOINT corrupt", NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_exec(db, "UPDATE node_state SET value='from=5 depth=10 since=0 blocker=- trailing' WHERE key='wallet_scan_incomplete'", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("invalid marker refused", wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_MALFORMED &&
        !wallet_sqlite_cutover_prepare(ws, w, &b));
    WRC_CHECK("invalid marker rollback", sqlite3_exec(db, "ROLLBACK TO corrupt; RELEASE corrupt", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("invalid version setup", sqlite3_exec(db, "SAVEPOINT corrupt; UPDATE node_state SET value=CAST(x'02'||substr(value,2) AS BLOB) WHERE key='wallet_cutover_binding'", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("invalid version refused", wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_MALFORMED);
    WRC_CHECK("invalid version rollback", sqlite3_exec(db, "ROLLBACK TO corrupt; RELEASE corrupt", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("invalid presence setup", sqlite3_exec(db, "SAVEPOINT corrupt; UPDATE node_state SET value=CAST(substr(value,1,1)||x'02'||substr(value,3) AS BLOB) WHERE key='wallet_cutover_binding'", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("invalid presence refused", wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_MALFORMED);
    WRC_CHECK("invalid presence rollback", sqlite3_exec(db, "ROLLBACK TO corrupt; RELEASE corrupt", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("invalid height refused", (b.target_height = -1, !wallet_sqlite_cutover_prepare(ws, w, &b)));
    b.target_height = 20;
    b.target_hash[0] = 9;
    WRC_CHECK("cutover mismatch refused", !wallet_sqlite_cutover_prepare(ws, w, &b) &&
        wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_PENDING && out.target_hash[0] == 2);
    WRC_CHECK("cutover missing marker refuses", sqlite3_exec(db,
        "DELETE FROM node_state WHERE key='wallet_scan_incomplete'", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_MALFORMED);
    WRC_CHECK("cutover malformed refuses", sqlite3_exec(db,
        "UPDATE node_state SET value=x'00' WHERE key='wallet_cutover_binding'", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_MALFORMED);
    return failures;
}

static bool wrc_schema_floor(sqlite3 *db, int32_t *out)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT value FROM node_state WHERE key='schema_compat_floor'", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = AR_STEP_ROW_READONLY(s) == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_BLOB &&
        sqlite3_column_bytes(s, 0) == (int)sizeof(*out) && sqlite3_column_blob(s, 0);
    if (ok) memcpy(out, sqlite3_column_blob(s, 0), sizeof(*out));
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool wrc_bound_resolve(void *ctx, const uint8_t hash[32], int *height)
{
    (void)ctx;
    if (hash[0] != 1) return false;
    *height = 10;
    return true;
}
static bool wrc_bound_reference(void *ctx, int height, const uint8_t hash[32])
{
    (void)ctx;
    return height == 10 && hash[0] == 1;
}

static int wrc_cutover_faults(sqlite3 *db, struct wallet_sqlite *ws,
                              struct wallet *w, const struct wallet_cutover_binding *b)
{
    int failures = 0;
    struct wallet_cutover_binding out;
    WRC_CHECK("cutover absent", wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_ABSENT);
    WRC_CHECK("absence never proves completion", wallet_sqlite_cutover_authority_read(ws, b, &out) == WALLET_CUTOVER_AUTH_ABSENT);
    WRC_CHECK("cutover inject partial failure", sqlite3_exec(db,
        "CREATE TRIGGER fail_binding BEFORE INSERT ON node_state WHEN NEW.key='wallet_cutover_binding' BEGIN SELECT RAISE(ABORT,'injected'); END", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("cutover atomic rollback", !wallet_sqlite_cutover_prepare(ws, w, b) &&
        wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_ABSENT &&
        !wallet_sqlite_read_scan_marker(ws, &(struct wallet_scan_marker){0}));
    int32_t before = -1, after = -1; struct wallet_cutover_binding bound = *b;
    bound.history_identity_present = true; bound.snapshot_whole_sha3[0] = 1; bound.history_manifest_root[0] = 2;
    WRC_CHECK("bound fence failure preserves floor", wrc_schema_floor(db, &before) &&
        !wallet_sqlite_cutover_prepare_bound(ws, w, &bound, 10, bound.old_hash, wrc_bound_resolve, wrc_bound_reference, NULL) &&
        wrc_schema_floor(db, &after) && before == after);
    WRC_CHECK("cutover remove trigger", sqlite3_exec(db, "DROP TRIGGER fail_binding", NULL, NULL, NULL) == SQLITE_OK);
    sqlite3 *empty = NULL;
    WRC_CHECK("empty schema open", sqlite3_open(":memory:", &empty) == SQLITE_OK);
    struct wallet_sqlite bad = {.db = empty, .open = true};
    WRC_CHECK("cutover schema failure is IO", wallet_sqlite_cutover_read(&bad, &out) == WALLET_CUTOVER_IO_ERROR);
    sqlite3_close(empty);
    WRC_CHECK("outer begin", sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("prepare inside outer transaction", wallet_sqlite_cutover_prepare(ws, w, b));
    WRC_CHECK("outer rollback", sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_ABSENT);
    WRC_CHECK("release fault installed", sqlite3_set_authorizer(db, wrc_deny_release, NULL) == SQLITE_OK);
    WRC_CHECK("release fault observable", !wallet_sqlite_cutover_prepare(ws, w, b));
    WRC_CHECK("release fault removed", sqlite3_set_authorizer(db, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("release fault rolled back", sqlite3_exec(db, "RELEASE wallet_cutover", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_cutover_read(ws, &out) == WALLET_CUTOVER_ABSENT);
    return failures;
}

static bool wrc_checkpoint_is_malformed(struct wallet_sqlite *ws)
{
    struct wallet_discover_checkpoint got, zero; memset(&zero, 0, sizeof(zero)); memset(&got, 0xa5, sizeof(got));
    return wallet_sqlite_discover_checkpoint_read(ws, &got) == WALLET_DISCOVER_MALFORMED &&
        !memcmp(&got, &zero, sizeof(got));
}
static bool wrc_checkpoint_mutate(sqlite3 *db, struct wallet_sqlite *ws,
    const uint8_t valid[304], size_t offset, uint8_t value)
{
    uint8_t bytes[304]; memcpy(bytes, valid, sizeof(bytes)); bytes[offset] = value;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "UPDATE node_state SET value=? WHERE key='wallet_discover_checkpoint'",
                           -1, &stmt, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(stmt, 1, bytes, sizeof(bytes), SQLITE_TRANSIENT) == SQLITE_OK &&
        AR_STEP_WRITE(stmt) == SQLITE_DONE;
    if (sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    struct wallet_discover_checkpoint got, zero; memset(&zero, 0, sizeof(zero)); memset(&got, 0xa5, sizeof(got));
    return ok && wallet_sqlite_discover_checkpoint_read(ws, &got) == WALLET_DISCOVER_MALFORMED &&
        !memcmp(&got, &zero, sizeof(got));
}
static int wrc_checkpoint_decode_mutations(sqlite3 *db, struct wallet_sqlite *ws)
{
    int failures = 0; uint8_t valid[304] = {0}; sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_prepare_v2(db, "SELECT value FROM node_state WHERE key='wallet_discover_checkpoint'",
                                -1, &stmt, NULL) == SQLITE_OK &&
              AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) == SQLITE_BLOB &&
              sqlite3_column_bytes(stmt, 0) == (int)sizeof(valid);
    if (ok) memcpy(valid, sqlite3_column_blob(stmt, 0), sizeof(valid));
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    WRC_CHECK("checkpoint valid mutation baseline", ok);
    if (!ok) return failures;
    WRC_CHECK("checkpoint bad version", wrc_checkpoint_mutate(db, ws, valid, 0, 2));
    WRC_CHECK("checkpoint invalid generation flag", wrc_checkpoint_mutate(db, ws, valid, 115, 2));
    WRC_CHECK("checkpoint absent nonzero generation", wrc_checkpoint_mutate(db, ws, valid, 115, 0));
    WRC_CHECK("checkpoint floor exceeds next", wrc_checkpoint_mutate(db, ws, valid, 124, 18));
    WRC_CHECK("checkpoint next exceeds endpoint", wrc_checkpoint_mutate(db, ws, valid, 128, 26));
    WRC_CHECK("checkpoint endpoint before target", wrc_checkpoint_mutate(db, ws, valid, 132, 19));
    stmt = NULL;
    bool restored = sqlite3_prepare_v2(db, "UPDATE node_state SET value=? WHERE key='wallet_discover_checkpoint'",
                                      -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(stmt, 1, valid, sizeof(valid), SQLITE_TRANSIENT) == SQLITE_OK &&
        AR_STEP_WRITE(stmt) == SQLITE_DONE;
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) restored = false;
    WRC_CHECK("checkpoint restore valid mutation baseline", restored);
    sqlite3 *other = NULL;
    bool opened = sqlite3_open(":memory:", &other) == SQLITE_OK;
    struct wallet_sqlite isolated = {.db = other, .open = true};
    struct wallet_discover_checkpoint got, zero; memset(&zero, 0, sizeof(zero)); memset(&got, 0xa5, sizeof(got));
    WRC_CHECK("checkpoint sqlite read error", opened &&
        wallet_sqlite_discover_checkpoint_read(&isolated, &got) == WALLET_DISCOVER_IO_ERROR &&
        !memcmp(&got, &zero, sizeof(got)));
    if (other) sqlite3_close(other);
    return failures;
}
static bool wrc_checkpoint_equal(const struct wallet_discover_checkpoint *got,
    const struct wallet_discover_checkpoint *c, const struct wallet_cutover_binding *binding)
{
    return wallet_cutover_binding_equal(&got->binding, binding) && got->generation_present && got->generation == 1 &&
        got->floor == 0 && got->next_height == 17 && got->endpoint_height == 25 &&
        !memcmp(got->endpoint_hash, c->endpoint_hash, 32) && !memcmp(got->endpoint_root, c->endpoint_root, 32) &&
        !memcmp(got->scan_identity, c->scan_identity, 32) && !memcmp(got->key_digest, c->key_digest, 32) &&
        got->event_end == c->event_end && !memcmp(got->event_digest, c->event_digest, 32);
}
static int wrc_checkpoint_persist(sqlite3 *db, struct wallet_sqlite *ws,
    struct wallet_discover_checkpoint *c, const struct wallet_cutover_binding *binding)
{
    int failures = 0; struct wallet_discover_checkpoint got;
    WRC_CHECK("checkpoint initially absent",
        wallet_sqlite_discover_checkpoint_read(ws, &got) == WALLET_DISCOVER_ABSENT);
    WRC_CHECK("checkpoint requires transaction", !wallet_sqlite_discover_checkpoint_save(ws, c));
    WRC_CHECK("checkpoint save starts transaction", sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("checkpoint saves", wallet_sqlite_discover_checkpoint_save(ws, c));
    WRC_CHECK("checkpoint roundtrip", wallet_sqlite_discover_checkpoint_read(ws, &got) == WALLET_DISCOVER_FOUND &&
        wrc_checkpoint_equal(&got, c, binding));
    WRC_CHECK("checkpoint rollback", sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_discover_checkpoint_read(ws, &got) == WALLET_DISCOVER_ABSENT);
    WRC_CHECK("checkpoint commit starts", sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("checkpoint commit succeeds", wallet_sqlite_discover_checkpoint_save(ws, c) &&
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("checkpoint unchanged after commit",
        wallet_sqlite_discover_checkpoint_read(ws, &got) == WALLET_DISCOVER_FOUND && got.next_height == 17);
    failures += wrc_checkpoint_decode_mutations(db, ws);
    return failures;
}
static int wrc_checkpoint_refusals(sqlite3 *db, struct wallet_sqlite *ws,
    struct wallet_discover_checkpoint *c, const struct wallet_cutover_binding *binding)
{
    int failures = 0;
    WRC_CHECK("checkpoint bad binding starts", sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK);
    c->binding.target_hash[0] ^= 1;
    WRC_CHECK("checkpoint changed binding refused", !wallet_sqlite_discover_checkpoint_save(ws, c));
    c->binding = *binding;
    c->generation_present = false; c->generation = 1;
    WRC_CHECK("checkpoint absent generation must be zero", !wallet_sqlite_discover_checkpoint_save(ws, c));
    c->generation_present = true; c->next_height = 26;
    WRC_CHECK("checkpoint out of range refused", !wallet_sqlite_discover_checkpoint_save(ws, c));
    WRC_CHECK("checkpoint refusal rollback", sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK);
    return failures;
}
static int wrc_checkpoint_integrity(sqlite3 *db, struct wallet_sqlite *ws, struct wallet *w,
    enum wallet_cutover_floor_status fs, int floor_before, struct wallet_readiness ready)
{
    int failures = 0, floor_after = -1;
    WRC_CHECK("checkpoint scan floor unchanged", wallet_sqlite_cutover_scan_floor(ws, &floor_after) == fs &&
        floor_after == floor_before);
    WRC_CHECK("checkpoint readiness unchanged", w->readiness.state == ready.state &&
        w->readiness.epoch == ready.epoch && w->readiness.generation_present == ready.generation_present &&
        w->readiness.generation == ready.generation);
    WRC_CHECK("checkpoint rejects overflow height on read", sqlite3_exec(db,
        "UPDATE node_state SET value=CAST(substr(value,1,128)||x'00000080'||substr(value,133) AS BLOB) "
        "WHERE key='wallet_discover_checkpoint'", NULL, NULL, NULL) == SQLITE_OK &&
        wrc_checkpoint_is_malformed(ws));
    WRC_CHECK("checkpoint wrong SQL type", sqlite3_exec(db,
        "UPDATE node_state SET value='text' WHERE key='wallet_discover_checkpoint'", NULL, NULL, NULL) == SQLITE_OK &&
        wrc_checkpoint_is_malformed(ws));
    WRC_CHECK("checkpoint wrong blob length", sqlite3_exec(db,
        "UPDATE node_state SET value=zeroblob(303) WHERE key='wallet_discover_checkpoint'", NULL, NULL, NULL) == SQLITE_OK &&
        wrc_checkpoint_is_malformed(ws));
    return failures;
}
static int wrc_discover_checkpoint(sqlite3 *db, struct wallet_sqlite *ws,
    struct wallet *w, const struct wallet_cutover_binding *binding)
{
    int failures = 0, floor_before = -1;
    struct wallet_discover_checkpoint c = {.binding = *binding,
        .generation_present = true, .generation = 1,
        .floor = 0, .next_height = 17, .endpoint_height = 25, .event_end = 12345};
    c.endpoint_hash[1] = 11; c.endpoint_root[2] = 12; c.scan_identity[3] = 13;
    c.key_digest[4] = 14; c.event_digest[5] = 15;
    struct wallet_readiness ready = w->readiness;
    enum wallet_cutover_floor_status fs = wallet_sqlite_cutover_scan_floor(ws, &floor_before);
    failures += wrc_checkpoint_persist(db, ws, &c, binding);
    failures += wrc_checkpoint_refusals(db, ws, &c, binding);
    failures += wrc_checkpoint_integrity(db, ws, w, fs, floor_before, ready);
    return failures;
}

static int wrc_bound_checkpoint(sqlite3 *db, struct wallet_sqlite *ws, struct wallet *w,
                                struct wallet_cutover_binding binding)
{
    int failures = 0;
    int32_t floor_before = -1, floor_now = -1;
    WRC_CHECK("bound initial compatibility floor", wrc_schema_floor(db, &floor_before));
    binding.history_identity_present = true;
    binding.snapshot_whole_sha3[0] = 0x51; binding.history_manifest_root[0] = 0x62;
    WRC_CHECK("bound checkpoint sandbox", sqlite3_exec(db,
        "SAVEPOINT bound; DELETE FROM node_state WHERE key IN ('wallet_cutover_binding','wallet_scan_incomplete','wallet_discover_checkpoint')",
        NULL, NULL, NULL) == SQLITE_OK);
    struct wallet_cutover_binding observed;
    WRC_CHECK("bound fence roundtrip", wallet_sqlite_cutover_prepare_bound(ws, w, &binding,
        10, binding.old_hash, wrc_bound_resolve, wrc_bound_reference, NULL) &&
        wallet_sqlite_cutover_read(ws, &observed) == WALLET_CUTOVER_PENDING &&
        wallet_cutover_binding_equal(&binding, &observed));
    WRC_CHECK("bound fence raises compatibility floor", wrc_schema_floor(db, &floor_now) &&
        floor_now >= WALLET_BOUND_CUTOVER_SCHEMA_VERSION);
    struct wallet_discover_checkpoint c = {.binding = binding, .generation_present = true,
        .generation = 1, .floor = 0, .next_height = 17, .endpoint_height = 25};
    struct wallet_discover_checkpoint got;
    WRC_CHECK("bound discover roundtrip", wallet_sqlite_discover_checkpoint_save(ws, &c) &&
        wallet_sqlite_discover_checkpoint_read(ws, &got) == WALLET_DISCOVER_FOUND &&
        wallet_cutover_binding_equal(&got.binding, &binding));
    c.binding.history_manifest_root[0] ^= 1;
    WRC_CHECK("bound checkpoint wrong root refuses", !wallet_sqlite_discover_checkpoint_save(ws, &c));
    WRC_CHECK("mixed bound checkpoint version", sqlite3_exec(db,
        "UPDATE node_state SET value=CAST(x'01'||substr(value,2) AS BLOB) WHERE key='wallet_discover_checkpoint'",
        NULL, NULL, NULL) == SQLITE_OK && wrc_checkpoint_is_malformed(ws));
    WRC_CHECK("bound checkpoint rollback", sqlite3_exec(db, "ROLLBACK TO bound; RELEASE bound", NULL, NULL, NULL) == SQLITE_OK);
    WRC_CHECK("bound rollback restores compatibility floor", wrc_schema_floor(db, &floor_now) && floor_now == floor_before);
    return failures;
}

static int wrc_cutover_binding(const char *datadir)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb = {0};
    char path[4096];
    snprintf(path, sizeof(path), "%s/cutover-test.sqlite", datadir);
    struct wallet_sqlite ws = {0};
    struct wallet *w = zcl_calloc(1, sizeof(*w), "cutover-test");
    struct wallet_cutover_binding b = {.old_generation_present = true,
        .old_generation = 0, .old_height = 10, .target_height = 20};
    struct wallet_cutover_binding out;
    b.old_hash[0] = 1; b.target_hash[0] = 2; b.artifact_digest[0] = 3;
    WRC_CHECK("cutover fixture open", w && node_db_open(&ndb, path) && wallet_sqlite_open_r(&ws, ndb.db).ok);
    if (!w || !ws.open) { free(w); if (ndb.open) node_db_close(&ndb); return failures + 1; }
    db = ndb.db; w->scan_retry.pending = true;
    w->scan_retry.from = 5; w->best_block_height = 10;
    failures += wrc_cutover_faults(db, &ws, w, &b);
    WRC_CHECK("cutover persists and reloads", wallet_sqlite_cutover_prepare(&ws, w, &b) &&
        wallet_sqlite_cutover_read(&ws, &out) == WALLET_CUTOVER_PENDING &&
        out.old_generation_present && out.old_generation == 0 && out.target_height == 20 && out.target_hash[0] == 2);
    failures += wrc_discover_checkpoint(db, &ws, w, &b);
    failures += wrc_bound_checkpoint(db, &ws, w, b);
    wallet_sqlite_close(&ws); node_db_close(&ndb); db = NULL;
    WRC_CHECK("cutover reopen", node_db_open(&ndb, path) && wallet_sqlite_open_r(&ws, ndb.db).ok);
    db = ndb.db;
    WRC_CHECK("cutover survives restart", wallet_sqlite_cutover_read(&ws, &out) == WALLET_CUTOVER_PENDING && out.target_hash[0] == 2);
    WRC_CHECK("cutover idempotent", wallet_sqlite_cutover_prepare(&ws, w, &b));
    failures += wrc_cutover_corruption(db, &ws, w, b);
    wallet_sqlite_close(&ws); node_db_close(&ndb); free(w); return failures;
}

/* Keep the indexed header exact while changing its transaction data. */
static bool wrc_write_invalid_body(const char *dir, const struct disk_block_pos *source,
    bool duplicate, struct disk_block_pos *pos, struct uint256 *header_hash)
{
    struct block block;
    block_init(&block);
    bool ok = read_block_from_disk(&block, source, dir) && block.num_vtx == 2;
    if (ok && duplicate) {
        transaction_free(&block.vtx[1]);
        transaction_init(&block.vtx[1]);
        ok = transaction_copy(&block.vtx[1], &block.vtx[0]) && wrc_set_merkle(&block);
    } else if (ok) {
        block.vtx[0].vout[0].value++;
    }
    const unsigned char magic[4] = {0x24, 0xe9, 0x27, 0x64};
    if (ok) {
        block_get_hash(&block, header_hash);
        disk_block_pos_init(pos);
        ok = write_block_to_disk(&block, pos, dir, magic);
    }
    block_free(&block);
    return ok;
}

static bool wrc_reject_invalid_body(struct wallet *wallet, const char *dir,
    const struct disk_block_pos *source, bool duplicate)
{
    struct disk_block_pos pos;
    struct uint256 hash;
    if (!wrc_write_invalid_body(dir, source, duplicate, &pos, &hash)) return false;
    struct block_index index;
    block_index_init(&index);
    index.nHeight = 0; index.nFile = pos.nFile; index.nDataPos = pos.nPos;
    index.nStatus = BLOCK_HAVE_DATA; index.phashBlock = &hash;
    struct block_index *slot = &index;
    struct active_chain chain = {.chain = &slot, .height = 0, .capacity = 1};
    size_t before = wallet->num_wallet_tx;
    struct wallet_rescan_report report;
    (void)wallet_rescan_report(wallet, &chain, 0, 0, dir, &report);
    return !report.coverage_ok && report.blocks_scanned == 0 &&
           report.blocks_read_failed == 1 && report.outputs_found == 0 &&
           wallet->num_wallet_tx == before;
}

/* ── R. The row-replacing scan against the coverage guard ───────────────
 * rescanwallet, replaywalletfromchain and the boot catch-up scan rebuild
 * wallet_utxos and wallet_transactions from the blocks. On a node started
 * from a state bundle the heights below the bundle hold no body; a scan over
 * them used to delete every row and write back only what the readable
 * blocks held, report success, and drop the balance.
 *
 * The wallet here holds one key that owns no output of the fixture: what
 * the readable blocks hold for it is nothing, so a scan that runs commits an
 * empty result and the seeded stale row shows whether it ran. `owner` holds
 * the key the fixture blocks pay: R8, R10-R12, R15-R17 use it for a scan that
 * finds a wallet transaction, whose row carries the hash of the block it was
 * read from (`body_hash`, the one body every height shares). */
struct wrc_r {
    struct node_db *ndb;
    struct rpc_table *tbl;
    const struct wallet *w;
    const struct wallet *owner;
    struct main_state *ms;
    const char *datadir;
    struct block_index *idx;
    const struct uint256 *body_hash;
};

#define WRC_R_STALE_VALUE 4242

static int64_t wrc_r_count(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* A wallet row pair no block of the fixture holds: a scan that replaced the
 * rows drops it, a scan that kept them leaves it. */
static bool wrc_r_seed_stale(struct node_db *ndb)
{
    static const uint8_t raw_tx[2] = {0x01, 0x02};
    static const uint8_t script[3] = {0x76, 0xa9, 0x14};
    struct db_wallet_tx tx;
    struct db_wallet_utxo u;
    memset(&tx, 0, sizeof(tx));
    memset(&u, 0, sizeof(u));
    memset(tx.txid, 0xee, sizeof(tx.txid));
    tx.raw_tx = (uint8_t *)raw_tx;
    tx.raw_tx_len = sizeof(raw_tx);
    tx.time_received = 1;
    memcpy(u.txid, tx.txid, sizeof(u.txid));
    memset(u.address_hash, 0xee, sizeof(u.address_hash));
    u.value = WRC_R_STALE_VALUE;
    u.script = (uint8_t *)script;
    u.script_len = sizeof(script);
    u.height = 3;
    return db_wallet_tx_save(ndb, &tx) && db_wallet_utxo_save(ndb, &u);
}

static bool wrc_r_has_stale(struct node_db *ndb)
{
    return wrc_r_count(ndb, "SELECT count(*) FROM wallet_utxos WHERE "
                            "value = 4242") == 1 &&
           wrc_r_count(ndb, "SELECT count(*) FROM wallet_transactions "
                            "WHERE hex(txid) GLOB 'EEEEEEEEEEEE*'") == 1;
}

struct wrc_r_rows {
    int64_t utxos, txs, balance;
    uint64_t utxo_fold, tx_fold;
    bool folded;
};

/* FNV-1a over the type and bytes of every column of every row, in key
 * order: equal folds mean the table is byte-for-byte unchanged. */
static bool wrc_r_fold(struct node_db *ndb, const char *sql, uint64_t *fold)
{
    sqlite3_stmt *st = NULL;
    *fold = 1469598103934665603ULL;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        for (int c = 0; c < sqlite3_column_count(st); c++) {
            const uint8_t *p = sqlite3_column_blob(st, c);
            int n = sqlite3_column_bytes(st, c);
            *fold = (*fold ^ (uint64_t)sqlite3_column_type(st, c)) *
                    1099511628211ULL;
            for (int i = 0; p && i < n; i++)
                *fold = (*fold ^ p[i]) * 1099511628211ULL;
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static struct wrc_r_rows wrc_r_rows_now(struct node_db *ndb)
{
    struct wrc_r_rows r = {
        .utxos = wrc_r_count(ndb, "SELECT count(*) FROM wallet_utxos"),
        .txs = wrc_r_count(ndb, "SELECT count(*) FROM wallet_transactions"),
        .balance = db_wallet_utxo_balance(ndb),
    };
    r.folded = wrc_r_fold(ndb, "SELECT * FROM wallet_utxos ORDER BY txid, vout",
                          &r.utxo_fold) &&
               wrc_r_fold(ndb, "SELECT * FROM wallet_transactions ORDER BY txid",
                          &r.tx_fold);
    return r;
}

static bool wrc_r_rows_equal(struct wrc_r_rows a, struct wrc_r_rows b)
{
    return a.folded && b.folded && a.utxos >= 0 && a.txs >= 0 &&
           a.utxos == b.utxos && a.txs == b.txs && a.balance == b.balance &&
           a.utxo_fold == b.utxo_fold && a.tx_fold == b.tx_fold;
}

/* Upper-case hex of 32 bytes in storage order, as SQLite's hex() prints a
 * blob. */
static void wrc_r_hex32(const uint8_t b[32], char out[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02X", b[i]);
}

/* Count, unspent value and fold of the rows matching one WHERE clause per
 * table: the rows a scan must leave alone, compared byte for byte while it
 * adds or marks others. */
static struct wrc_r_rows wrc_r_rows_where(struct node_db *ndb,
                                          const char *utxo_where,
                                          const char *tx_where)
{
    char sql[512];
    struct wrc_r_rows r = {.utxos = -1, .txs = -1};
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM wallet_utxos WHERE %s",
             utxo_where);
    r.utxos = wrc_r_count(ndb, sql);
    snprintf(sql, sizeof(sql),
             "SELECT count(*) FROM wallet_transactions WHERE %s", tx_where);
    r.txs = wrc_r_count(ndb, sql);
    snprintf(sql, sizeof(sql), "SELECT COALESCE(SUM(value),0) FROM "
             "wallet_utxos WHERE spent_txid IS NULL AND (%s)", utxo_where);
    r.balance = wrc_r_count(ndb, sql);
    snprintf(sql, sizeof(sql),
             "SELECT * FROM wallet_utxos WHERE %s ORDER BY txid, vout",
             utxo_where);
    bool utxos_folded = wrc_r_fold(ndb, sql, &r.utxo_fold);
    snprintf(sql, sizeof(sql),
             "SELECT * FROM wallet_transactions WHERE %s ORDER BY txid",
             tx_where);
    r.folded = utxos_folded && wrc_r_fold(ndb, sql, &r.tx_fold);
    return r;
}

/* Exactly one wallet_transactions row at or above `from`, carrying the
 * fixture body's hash, and exactly one unspent wallet_utxos row there: what
 * a scan of the paid key finds in heights that all share one body. */
static bool wrc_r_found_rows_hashed(const struct wrc_r *r, int from)
{
    char hex[65], sql[256];
    wrc_r_hex32(r->body_hash->data, hex);
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM wallet_transactions "
             "WHERE block_height >= %d AND hex(block_hash) = '%s'", from, hex);
    int64_t hashed = wrc_r_count(r->ndb, sql);
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM wallet_transactions "
             "WHERE block_height >= %d", from);
    int64_t txs = wrc_r_count(r->ndb, sql);
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM wallet_utxos WHERE "
             "height >= %d AND spent_txid IS NULL", from);
    int64_t utxos = wrc_r_count(r->ndb, sql);
    printf("[hashed=%lld txs=%lld utxos=%lld] ", (long long)hashed,
           (long long)txs, (long long)utxos);
    return hashed == 1 && txs == 1 && utxos == 1;
}

/* Run a wallet RPC; the reply text (or "") lands in out. */
static bool wrc_r_rpc(const struct wrc_r *r, const char *method, bool confirm,
                      char *out, size_t cap)
{
    struct json_value params, result, v;
    json_init(&params);
    json_set_array(&params);
    if (confirm) {
        json_init(&v);
        json_set_bool(&v, true);
        json_push_back(&params, &v);
        json_free(&v);
    }
    json_init(&result);
    bool ok = rpc_table_execute(r->tbl, method, &params, &result);
    const char *s = json_get_str(&result);
    snprintf(out, cap, "%s", s ? s : "");
    if (!ok)
        printf("[%s: %s] ", method, out);
    json_free(&params);
    json_free(&result);
    return ok;
}

/* R1, the positive control: every body present, the rescan replaces the
 * rows with what the blocks hold. */
static int wrc_r_full_range_replaces(const struct wrc_r *r)
{
    int failures = 0;
    wrc_set_have_data(r->idx, WRC_NBLOCKS, true);
    char reply[1024];
    WRC_CHECK("R1: seed a wallet row no block holds",
              wrc_r_seed_stale(r->ndb) && wrc_r_has_stale(r->ndb));
    WRC_CHECK("R1: rescanwallet over a fully bodied range succeeds",
              wrc_r_rpc(r, "rescanwallet", false, reply, sizeof(reply)));
    WRC_CHECK("R1: it replaced the rows: the stale row is gone",
              !wrc_r_has_stale(r->ndb));
    WRC_CHECK("R1: the rows now hold what the blocks hold for this key: none",
              wrc_r_count(r->ndb, "SELECT count(*) FROM wallet_utxos") == 0 &&
              wrc_r_count(r->ndb,
                          "SELECT count(*) FROM wallet_transactions") == 0);
    return failures;
}

/* R2/R3: heights 0..149 hold no body; every row-replacing RPC refuses and
 * the rows stay as they were. */
static int wrc_r_holed_range_refused(const struct wrc_r *r,
                                     const char *method, bool confirm)
{
    int failures = 0;
    char name[160], reply[1024];
    struct wrc_r_rows before = wrc_r_rows_now(r->ndb);
    bool ok = wrc_r_rpc(r, method, confirm, reply, sizeof(reply));
    struct wrc_r_rows after = wrc_r_rows_now(r->ndb);
    snprintf(name, sizeof(name), "R: %s over a range with 150 bodiless "
             "heights is refused", method);
    WRC_CHECK(name, !ok && strstr(reply, "refused") != NULL);
    snprintf(name, sizeof(name), "R: %s names the missing count, the first "
             "missing height and that the rows were kept", method);
    WRC_CHECK(name,
              strstr(reply, "no readable block data for 150 of the blocks at "
                            "heights 0..199") != NULL &&
              strstr(reply, "first missing height 0") != NULL &&
              strstr(reply, "were kept unchanged") != NULL);
    snprintf(name, sizeof(name), "R: %s left the wallet rows and the durable "
             "balance as they were", method);
    WRC_CHECK(name, wrc_r_rows_equal(before, after) &&
                    wrc_r_has_stale(r->ndb));
    return failures;
}

/* R6: the scan-time recheck. A body lost between the guard and Pass 2 (a
 * reorg into the range) stops Pass 2 before it writes. Called directly, as
 * the guard has already passed by the time Pass 2 runs. */
static int wrc_r_pass2_recheck(const struct wrc_r *r)
{
    int failures = 0;
    struct scan_addr_ht aht;
    scan_aht_init(&aht);
    const bool match[1] = {true};
    const struct timespec t = {.tv_sec = 1};
    struct wallet_scan_coverage cov = {.first_missing = -1};
    struct wrc_r_rows before = wrc_r_rows_now(r->ndb);
    int rc = wallet_scan_pass2_execute(r->ndb, &r->ms->chain_active,
                                       r->datadir, 0, WRC_NBLOCKS - 1,
                                       &aht, match, 1, 1, &t, &t, &cov);
    scan_aht_free(&aht);
    WRC_CHECK("R6: Pass 2 refuses at the first height with no body",
              rc == WALLET_SCAN_REFUSED_MISSING_DATA &&
              cov.first_missing == 0 && cov.blocks_missing >= 1);
    WRC_CHECK("R6: and leaves the wallet rows as they were",
              wrc_r_rows_equal(before, wrc_r_rows_now(r->ndb)) &&
              wrc_r_has_stale(r->ndb));
    return failures;
}

/* Point the boot cursor at `at` with the keyset fingerprint of `w`, so the
 * next boot scan covers only the delta above it. */
static bool wrc_r_stamp_cursor(struct node_db *ndb, const struct wallet *w,
                               int64_t at)
{
    return node_db_state_set_int(ndb, BOOT_CUR_WALLET, at) &&
           node_db_state_set_int(ndb, BOOT_CUR_WALLET_KS,
                                 (int64_t)wallet_scan_keyset_fp(w));
}

static bool wrc_r_cursor_is(struct node_db *ndb, int64_t want)
{
    int64_t cursor = -2;
    return node_db_state_get_int(ndb, BOOT_CUR_WALLET, &cursor) &&
           cursor == want;
}

/* Rows deleted from either wallet table, counted by temp triggers through a
 * C function: the count survives the rollback of the scan's transaction, so
 * it shows a delete that a failed write would otherwise hide. */
static int wrc_r_deletes;

static void wrc_r_count_delete(sqlite3_context *ctx, int argc,
                               sqlite3_value **argv)
{
    (void)argc;
    (void)argv;
    wrc_r_deletes++;
    sqlite3_result_null(ctx);
}

static bool wrc_r_watch_deletes(struct node_db *ndb, bool on)
{
    if (!on)
        return sqlite3_exec(ndb->db,
                            "DROP TRIGGER IF EXISTS temp.wrc_r_del_utxo;"
                            "DROP TRIGGER IF EXISTS temp.wrc_r_del_tx;",
                            NULL, NULL, NULL) == SQLITE_OK;
    wrc_r_deletes = 0;
    return sqlite3_create_function(ndb->db, "wrc_r_count_delete", 0,
                                   SQLITE_UTF8, NULL, wrc_r_count_delete,
                                   NULL, NULL) == SQLITE_OK &&
           sqlite3_exec(ndb->db,
                        "CREATE TEMP TRIGGER wrc_r_del_utxo AFTER DELETE ON "
                        "main.wallet_utxos BEGIN SELECT wrc_r_count_delete(); "
                        "END;"
                        "CREATE TEMP TRIGGER wrc_r_del_tx AFTER DELETE ON "
                        "main.wallet_transactions BEGIN SELECT "
                        "wrc_r_count_delete(); END;",
                        NULL, NULL, NULL) == SQLITE_OK;
}

/* A spent wallet_utxos row at height 10: the history a restart must keep. */
#define WRC_R_SPENT_VALUE 4343

static void wrc_r_spent_ids(uint8_t txid[32], uint8_t spender[32])
{
    memset(txid, 0xdd, 32);
    memset(spender, 0xcc, 32);
}

static bool wrc_r_seed_spent(struct node_db *ndb)
{
    static const uint8_t script[3] = {0x76, 0xa9, 0x14};
    uint8_t spender[32];
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    wrc_r_spent_ids(u.txid, spender);
    memset(u.address_hash, 0xdd, sizeof(u.address_hash));
    u.vout = 1;
    u.value = WRC_R_SPENT_VALUE;
    u.script = (uint8_t *)script;
    u.script_len = sizeof(script);
    u.height = 10;
    return db_wallet_utxo_save(ndb, &u) &&
           db_wallet_utxo_mark_spent(ndb, u.txid, u.vout, spender, 0);
}

static bool wrc_r_spent_mark_kept(struct node_db *ndb)
{
    uint8_t txid[32], spender[32];
    wrc_r_spent_ids(txid, spender);
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    if (!db_wallet_utxo_find(ndb, txid, 1, &u))
        return false;
    bool kept = u.is_spent && memcmp(u.spent_txid, spender, 32) == 0 &&
                u.spent_vin == 0 && u.value == WRC_R_SPENT_VALUE &&
                u.height == 10;
    db_wallet_utxo_free(&u);
    return kept;
}

/* Exactly the stale pair and the spent height-10 row, each case afresh. */
static bool wrc_r_reseed(struct node_db *ndb)
{
    return db_wallet_utxo_delete_all(ndb) && db_wallet_tx_delete_all(ndb) &&
           wrc_r_seed_stale(ndb) && wrc_r_seed_spent(ndb) &&
           wrc_r_spent_mark_kept(ndb) && wrc_r_has_stale(ndb);
}

/* One boot scan of the delta above cursor 149 for `w`, with deletes counted. */
static int wrc_r_delta_boot_scan(const struct wrc_r *r, const struct wallet *w,
                                 bool *armed, int *deletes)
{
    *armed = wrc_r_stamp_cursor(r->ndb, w, 149) &&
             wrc_r_watch_deletes(r->ndb, true);
    int found = boot_cursor_scan_wallet(r->ndb, &r->ms->chain_active, w,
                                        r->datadir, WRC_NBLOCKS - 1);
    *deletes = wrc_r_deletes;
    *armed = wrc_r_watch_deletes(r->ndb, false) && *armed;
    return found;
}

/* R7: a restart whose delta holds nothing for the wallet keeps every row
 * below the cursor, a spent mark included, and stamps the cursor. */
static int wrc_r_delta_keeps_rows(const struct wrc_r *r)
{
    int failures = 0;
    bool armed = false;
    int deletes = -1;
    bool seeded = wrc_r_reseed(r->ndb);
    struct wrc_r_rows before = wrc_r_rows_now(r->ndb);
    WRC_CHECK("R7: seed the stale pair and a spent row at height 10",
              seeded && before.utxos == 2 && before.txs == 1);
    int found = wrc_r_delta_boot_scan(r, r->w, &armed, &deletes);
    WRC_CHECK("R7: the restart delta 150..199 scans and deletes no row",
              armed && found == 0 && deletes == 0);
    WRC_CHECK("R7: every wallet_utxos and wallet_transactions row is "
              "byte-equal", wrc_r_rows_equal(before, wrc_r_rows_now(r->ndb)) &&
              wrc_r_has_stale(r->ndb));
    WRC_CHECK("R7: the height-10 row keeps its value and its spent mark",
              wrc_r_spent_mark_kept(r->ndb));
    WRC_CHECK("R7: the cursor is stamped at the tip",
              wrc_r_cursor_is(r->ndb, WRC_NBLOCKS - 1));
    return failures;
}

/* The rows stored below the delta: the stale pair and the spent height-10
 * row. */
#define WRC_R_OLD_UTXOS "height < 150"
#define WRC_R_OLD_TXS "block_height IS NULL OR block_height < 150"

/* R8: a delta that finds a wallet transaction with no stored row commits
 * it: the row carries the hash of the block it was read from, every row
 * stored before is byte-equal, nothing is deleted and the cursor stamps.
 * (The scan used to save has_block with a blank block_hash, which
 * db_wallet_tx_validate refuses, so the write rolled back and every boot
 * repeated the same failing delta.) */
static int wrc_r_delta_found_keeps_rows(const struct wrc_r *r)
{
    int failures = 0;
    bool armed = false;
    int deletes = -1;
    bool seeded = wrc_r_reseed(r->ndb);
    struct wrc_r_rows before =
        wrc_r_rows_where(r->ndb, WRC_R_OLD_UTXOS, WRC_R_OLD_TXS);
    int found = wrc_r_delta_boot_scan(r, r->owner, &armed, &deletes);
    struct wrc_r_rows after =
        wrc_r_rows_where(r->ndb, WRC_R_OLD_UTXOS, WRC_R_OLD_TXS);
    printf("[R8 found=%d deletes=%d] ", found, deletes);
    WRC_CHECK("R8: seed the stale pair and the spent row afresh",
              seeded && before.utxos == 2 && before.txs == 1);
    WRC_CHECK("R8: the delta 150..199 for the paid key commits what it "
              "found and deletes no row", armed && found > 0 &&
              deletes == 0);
    WRC_CHECK("R8: the found transaction's row carries the hash of the "
              "block at its height", wrc_r_found_rows_hashed(r, 150));
    WRC_CHECK("R8: every row stored before is byte-equal, the spent mark "
              "kept", wrc_r_rows_equal(before, after) &&
              wrc_r_has_stale(r->ndb) && wrc_r_spent_mark_kept(r->ndb));
    WRC_CHECK("R8: the cursor is stamped at the tip",
              wrc_r_cursor_is(r->ndb, WRC_NBLOCKS - 1));
    return failures;
}

/* R9: an empty range above height 0 (start > end) deletes nothing. */
static int wrc_r_empty_delta_range(const struct wrc_r *r)
{
    int failures = 0;
    bool seeded = wrc_r_reseed(r->ndb);
    struct wrc_r_rows before = wrc_r_rows_now(r->ndb);
    bool armed = seeded && wrc_r_watch_deletes(r->ndb, true);
    int rc = wallet_scan_blocks_checked(r->ndb, &r->ms->chain_active, r->w,
                                        r->datadir, WRC_NBLOCKS,
                                        WRC_NBLOCKS - 1, NULL);
    int deletes = wrc_r_deletes;
    armed = wrc_r_watch_deletes(r->ndb, false) && armed;
    WRC_CHECK("R9: the empty range 200..199 returns 0 and deletes no row",
              armed && rc == 0 && deletes == 0);
    WRC_CHECK("R9: every row is byte-equal, the spent mark kept",
              wrc_r_rows_equal(before, wrc_r_rows_now(r->ndb)) &&
              wrc_r_has_stale(r->ndb) && wrc_r_spent_mark_kept(r->ndb));
    return failures;
}

/* R10-R12: the owner's delta transaction as the live connect writer already
 * stored it, above the cursor: its wallet_transactions row (has_block, the
 * block hash set, so the validator accepts it) and its output as a
 * wallet_utxos row a later spend marked. */
#define WRC_R_FOUND_AT 150

static void wrc_r_found_spender(uint8_t spender[32])
{
    memset(spender, 0xcb, 32);
}

static bool wrc_r_save_found(struct node_db *ndb, const struct block *blk,
                             const struct byte_stream *raw, uint8_t txid[32])
{
    const struct transaction *t0 = &blk->vtx[0];
    const struct script *spk = &t0->vout[0].script_pub_key;
    struct uint256 bh;
    struct db_wallet_tx tx;
    struct db_wallet_utxo u;
    uint8_t spender[32];
    memset(&tx, 0, sizeof(tx));
    memset(&u, 0, sizeof(u));
    wrc_r_found_spender(spender);
    block_get_hash(blk, &bh);
    memcpy(txid, t0->hash.data, 32);
    memcpy(tx.txid, txid, 32);
    tx.raw_tx = raw->data;
    tx.raw_tx_len = raw->size;
    tx.has_block = true;
    memcpy(tx.block_hash, bh.data, 32);
    tx.block_height = WRC_R_FOUND_AT;
    tx.time_received = (int64_t)blk->header.nTime;
    memcpy(u.txid, txid, 32);
    u.value = t0->vout[0].value;
    memcpy(u.address_hash, spk->data + 3, 20); /* P2PKH: 76 a9 14 <20> */
    u.script = (uint8_t *)spk->data;
    u.script_len = spk->size;
    u.height = WRC_R_FOUND_AT;
    u.is_coinbase = true;
    return db_wallet_tx_save(ndb, &tx) && db_wallet_utxo_save(ndb, &u) &&
           db_wallet_utxo_mark_spent(ndb, u.txid, 0, spender, 0);
}

/* Read the shared body at WRC_R_FOUND_AT and store its owner rows. */
static bool wrc_r_seed_found(const struct wrc_r *r, uint8_t txid[32])
{
    const struct block_index *bi = &r->idx[WRC_R_FOUND_AT];
    struct disk_block_pos pos = {.nFile = bi->nFile, .nPos = bi->nDataPos};
    struct block blk;
    struct byte_stream raw;
    block_init(&blk);
    stream_init(&raw, 256);
    bool ok = read_block_from_disk(&blk, &pos, r->datadir) &&
              blk.num_vtx >= 1 && blk.vtx[0].num_vout == 1 &&
              blk.vtx[0].vout[0].script_pub_key.size == 25 &&
              transaction_serialize(&blk.vtx[0], &raw) && !raw.error &&
              wrc_r_save_found(r->ndb, &blk, &raw, txid);
    stream_free(&raw);
    block_free(&blk);
    return ok;
}

static bool wrc_r_found_mark_kept(struct node_db *ndb, const uint8_t txid[32])
{
    uint8_t spender[32];
    wrc_r_found_spender(spender);
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    if (!db_wallet_utxo_find(ndb, txid, 0, &u))
        return false;
    bool kept = u.is_spent && memcmp(u.spent_txid, spender, 32) == 0 &&
                u.spent_vin == 0 && u.height == WRC_R_FOUND_AT;
    db_wallet_utxo_free(&u);
    return kept;
}

/* The stale pair, the spent height-10 row and the owner's found rows. */
static bool wrc_r_reseed_found(const struct wrc_r *r, uint8_t txid[32])
{
    return wrc_r_reseed(r->ndb) && wrc_r_seed_found(r, txid) &&
           wrc_r_found_mark_kept(r->ndb, txid);
}

/* R10: a delta that finds the owner's transaction already stored commits
 * through the keep-existing branch: no row is saved over, so the output
 * keeps its spent mark, and the cursor stamps. */
static int wrc_r_delta_commit_keeps_rows(const struct wrc_r *r)
{
    int failures = 0;
    bool armed = false;
    int deletes = -1;
    uint8_t txid[32] = {0};
    bool seeded = wrc_r_reseed_found(r, txid);
    struct wrc_r_rows before = wrc_r_rows_now(r->ndb);
    WRC_CHECK("R10: seed the owner's delta transaction and its spent output",
              seeded && before.utxos == 3 && before.txs == 2);
    int found = wrc_r_delta_boot_scan(r, r->owner, &armed, &deletes);
    printf("[R10 found=%d deletes=%d] ", found, deletes);
    WRC_CHECK("R10: the delta 150..199 for the paid key commits and deletes "
              "no row", armed && found > 0 && deletes == 0);
    WRC_CHECK("R10: every row is byte-equal, both spent marks kept",
              wrc_r_rows_equal(before, wrc_r_rows_now(r->ndb)) &&
              wrc_r_has_stale(r->ndb) && wrc_r_spent_mark_kept(r->ndb) &&
              wrc_r_found_mark_kept(r->ndb, txid));
    WRC_CHECK("R10: the cursor is stamped at the tip",
              wrc_r_cursor_is(r->ndb, WRC_NBLOCKS - 1));
    return failures;
}

/* R11/R12/R14: a read of one wallet table fails during the delta. SQLite's
 * authorizer denies reads of that table for the scan only, so every read of
 * it fails to prepare; the scan must refuse, not save over or skip a spend.
 * Each case pins the end state only (a refusal, every row byte-equal, the
 * cursor unstamped), not which read refused first: a delta now reads the
 * stored unspent rows before its walk, so R11 refuses at that read, ahead of
 * the existing-row read inside the write (R17 covers that read and the
 * stored coin's recheck). R14 runs a wallet the delta blocks never pay,
 * whose delta read no wallet table before. */
static const char *wrc_r_denied_table;

static int wrc_r_deny_table_read(void *arg, int action, const char *a,
                                 const char *b, const char *c, const char *d)
{
    (void)arg; (void)b; (void)c; (void)d;
    return action == SQLITE_READ && a && wrc_r_denied_table &&
           strcmp(a, wrc_r_denied_table) == 0 ? SQLITE_DENY : SQLITE_OK;
}

static int wrc_r_delta_read_fails(const struct wrc_r *r,
                                  const struct wallet *w, const char *table,
                                  const char *label)
{
    int failures = 0;
    char name[200];
    uint8_t txid[32] = {0};
    bool seeded = wrc_r_reseed_found(r, txid) &&
                  wrc_r_stamp_cursor(r->ndb, w, 149);
    struct wrc_r_rows before = wrc_r_rows_now(r->ndb);
    wrc_r_denied_table = table;
    bool denied = sqlite3_set_authorizer(r->ndb->db, wrc_r_deny_table_read,
                                         NULL) == SQLITE_OK;
    int found = boot_cursor_scan_wallet(r->ndb, &r->ms->chain_active,
                                        w, r->datadir, WRC_NBLOCKS - 1);
    bool cleared = sqlite3_set_authorizer(r->ndb->db, NULL, NULL) == SQLITE_OK;
    wrc_r_denied_table = NULL;
    printf("[%s found=%d] ", label, found);
    snprintf(name, sizeof(name), "%s: a failed %s read refuses the delta",
             label, table);
    WRC_CHECK(name, seeded && denied && cleared && found < 0);
    snprintf(name, sizeof(name), "%s: every row is byte-equal, both spent "
             "marks kept", label);
    WRC_CHECK(name, wrc_r_rows_equal(before, wrc_r_rows_now(r->ndb)) &&
                    wrc_r_spent_mark_kept(r->ndb) &&
                    wrc_r_found_mark_kept(r->ndb, txid));
    snprintf(name, sizeof(name), "%s: the cursor is not stamped", label);
    WRC_CHECK(name, wrc_r_cursor_is(r->ndb, 149));
    return failures;
}

/* R13: a delta block spends a wallet coin stored below the cursor. The
 * spender block sits alone in blk00001.dat and pays no wallet key, and the
 * wallet scanned is one the delta blocks never pay, so Pass 1 matches no
 * file: only the delta's reread of the stored unspent rows can see the spend.
 * Its tx1 spends the stored coin (input 0) and the height-10 coin a
 * transaction already spent (input 1), whose mark must not change. */
#define WRC_R_SPEND_AT 160
#define WRC_R_SPENDME_VALUE 4545
#define WRC_R_SPEND_FEE 1000
#define WRC_R_OTHER_UTXOS "hex(txid) NOT GLOB '5A5A*'"
#define WRC_R_OTHER_TXS "block_height IS NULL OR block_height <> 160"

static bool wrc_u_write_file(const char *dir, int n, const uint8_t *data,
                             size_t len);
static uint8_t *wrc_u_read_file(const char *dir, int n, size_t *len);

static bool wrc_r_seed_spendme(struct node_db *ndb)
{
    static const uint8_t script[3] = {0x76, 0xa9, 0x14};
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    memset(u.txid, 0x5a, sizeof(u.txid));
    memset(u.address_hash, 0x5a, sizeof(u.address_hash));
    u.vout = 1;
    u.value = WRC_R_SPENDME_VALUE;
    u.script = (uint8_t *)script;
    u.script_len = sizeof(script);
    u.height = 12;
    return db_wallet_utxo_save(ndb, &u);
}

/* What a spender block's tx1 spends (up to two outpoints) and the one
 * output it pays to nobody. */
struct wrc_r_spend {
    uint8_t prev[2][32];
    uint32_t n[2];
    size_t nin;
    int64_t value;
    uint32_t time;
};

/* R13's spend: the stored coin (input 0) and the already spent height-10
 * coin (input 1), to nobody, less WRC_R_SPEND_FEE. */
static struct wrc_r_spend wrc_r_spendme_spend(void)
{
    struct wrc_r_spend sp = {.n = {1, 1}, .nin = 2,
                             .value = WRC_R_SPENDME_VALUE - WRC_R_SPEND_FEE,
                             .time = 1700000160u};
    memset(sp.prev[0], 0x5a, 32);
    memset(sp.prev[1], 0xdd, 32);
    return sp;
}

/* One input spending input i of sp. */
static void wrc_r_spend_input(struct tx_in *in, const struct wrc_r_spend *sp,
                              size_t i)
{
    memcpy(in->prevout.hash.data, sp->prev[i], 32);
    in->prevout.n = sp->n[i];
    script_init(&in->script_sig);
    in->sequence = 0xffffffffu;
}

/* A coinbase-shaped tx0 paying nobody, then tx1 spending what sp names to
 * nobody. */
static bool wrc_r_build_spender(struct block *blk, const struct wrc_r_spend *sp)
{
    blk->header.nVersion = 4;
    blk->header.nTime = sp->time;
    blk->header.nBits = 0x2000ffffu;
    blk->vtx = calloc(2, sizeof(*blk->vtx)); /* raw-alloc-ok:test-fixture */
    if (!blk->vtx)
        return false;
    blk->num_vtx = 2;
    struct transaction *t0 = &blk->vtx[0], *t1 = &blk->vtx[1];
    transaction_init(t0);
    transaction_init(t1);
    t0->version = t1->version = 1;
    t0->vin = calloc(1, sizeof(*t0->vin)); /* raw-alloc-ok:test-fixture */
    t0->vout = calloc(1, sizeof(*t0->vout)); /* raw-alloc-ok:test-fixture */
    t1->vin = calloc(sp->nin, sizeof(*t1->vin)); /* raw-alloc-ok:test-fixture */
    t1->vout = calloc(1, sizeof(*t1->vout)); /* raw-alloc-ok:test-fixture */
    if (!t0->vin || !t0->vout || !t1->vin || !t1->vout)
        return false;
    t0->num_vin = t0->num_vout = t1->num_vout = 1;
    t1->num_vin = sp->nin;
    outpoint_set_null(&t0->vin[0].prevout);
    script_init(&t0->vin[0].script_sig);
    t0->vin[0].sequence = 0xffffffffu;
    t0->vout[0].value = 1;
    script_init(&t0->vout[0].script_pub_key);
    for (size_t i = 0; i < sp->nin; i++)
        wrc_r_spend_input(&t1->vin[i], sp, i);
    t1->vout[0].value = sp->value;
    script_init(&t1->vout[0].script_pub_key);
    return wrc_set_merkle(blk);
}

/* Write the spender block in scratch `sdir` (write_block_to_disk numbers its
 * own files) and copy that file in as the fixture's blk00001.dat. */
static bool wrc_r_place_spender(const struct wrc_r *r, const char *sdir,
                                const struct wrc_r_spend *sp,
                                struct uint256 *hash, uint8_t spender[32],
                                struct disk_block_pos *pos)
{
    char blocksdir[360];
    unsigned char msg_start[4] = { 0x24, 0xe9, 0x27, 0x64 };
    struct block blk;
    block_init(&blk);
    bool ok = wrc_g_make_fixture_dirs(sdir, blocksdir, sizeof(blocksdir)) &&
              wrc_r_build_spender(&blk, sp) &&
              write_block_to_disk(&blk, pos, sdir, msg_start) &&
              pos->nFile == 0;
    if (ok) {
        block_get_hash(&blk, hash);
        memcpy(spender, blk.vtx[1].hash.data, 32);
    }
    block_free(&blk);
    size_t len = 0;
    uint8_t *buf = ok ? wrc_u_read_file(sdir, 0, &len) : NULL;
    ok = buf && wrc_u_write_file(r->datadir, 1, buf, len);
    free(buf);
    return ok;
}

/* The stored coin now carries exactly the spender's txid and input 0. */
static bool wrc_r_spendme_marked(struct node_db *ndb, const uint8_t spender[32])
{
    uint8_t txid[32];
    memset(txid, 0x5a, sizeof(txid));
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    if (!db_wallet_utxo_find(ndb, txid, 1, &u))
        return false;
    bool marked = u.is_spent && memcmp(u.spent_txid, spender, 32) == 0 &&
                  u.spent_vin == 0 && u.value == WRC_R_SPENDME_VALUE &&
                  u.height == 12;
    db_wallet_utxo_free(&u);
    return marked;
}

/* The spender's own row: the hash of its block at `height`, from_me, the
 * fee the spent coin's value implies. */
static bool wrc_r_spender_row(struct node_db *ndb, const uint8_t spender[32],
                              const struct uint256 *hash, int height)
{
    char txid_hex[65], hash_hex[65], sql[400];
    wrc_r_hex32(spender, txid_hex);
    wrc_r_hex32(hash->data, hash_hex);
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM wallet_transactions "
             "WHERE hex(txid) = '%s' AND block_height = %d AND "
             "hex(block_hash) = '%s' AND from_me = 1 AND fee = %d",
             txid_hex, height, hash_hex, WRC_R_SPEND_FEE);
    return wrc_r_count(ndb, sql) == 1;
}

/* Drop the spender file and the scratch directory. */
static void wrc_r_remove_spender(const struct wrc_r *r, const char *sdir)
{
    char path[400];
    snprintf(path, sizeof(path), "%s/blocks/blk00001.dat", r->datadir);
    (void)remove(path);
#if defined(_WIN32)
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", sdir);
    (void)remove(path);
    snprintf(path, sizeof(path), "%s/blocks", sdir);
    test_cleanup_tmpdir(path);
    test_cleanup_tmpdir(sdir);
#else
    snprintf(path, sizeof(path), "rm -rf %s", sdir);
    TEST_DISCARD(system(path));
#endif
}

/* A spender block placed as blk00001.dat at `height`: the index entry there
 * points at it until wrc_r_spender_uninstall restores the entry. */
struct wrc_r_placed {
    char sdir[300];
    struct uint256 hash;
    uint8_t spender[32];
    int height;
    struct block_index saved;
};

static bool wrc_r_spender_install(const struct wrc_r *r,
                                  struct wrc_r_placed *p, int height,
                                  const struct wrc_r_spend *sp)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->sdir, sizeof(p->sdir), "%s_s", r->datadir);
    p->height = height;
    struct block_index *at = &r->idx[height];
    p->saved = *at;
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    if (!wrc_r_place_spender(r, p->sdir, sp, &p->hash, p->spender, &pos))
        return false;
    at->nFile = 1;
    at->nDataPos = pos.nPos;
    at->phashBlock = &p->hash;
    return true;
}

static void wrc_r_spender_uninstall(const struct wrc_r *r,
                                    struct wrc_r_placed *p)
{
    r->idx[p->height] = p->saved;
    wrc_r_remove_spender(r, p->sdir);
}

static int wrc_r_delta_spends_stored_coin(const struct wrc_r *r)
{
    int failures = 0;
    struct wrc_r_placed p;
    const struct wrc_r_spend sp = wrc_r_spendme_spend();
    bool placed = wrc_r_spender_install(r, &p, WRC_R_SPEND_AT, &sp);
    const uint8_t *spender = p.spender;
    bool seeded = placed && wrc_r_reseed(r->ndb) &&
                  wrc_r_seed_spendme(r->ndb);
    struct wrc_r_rows before =
        wrc_r_rows_where(r->ndb, WRC_R_OTHER_UTXOS, WRC_R_OTHER_TXS);
    bool armed = false;
    int deletes = -1;
    int found = seeded ? wrc_r_delta_boot_scan(r, r->w, &armed, &deletes)
                       : -100;
    struct wrc_r_rows after =
        wrc_r_rows_where(r->ndb, WRC_R_OTHER_UTXOS, WRC_R_OTHER_TXS);
    printf("[R13 found=%d deletes=%d] ", found, deletes);
    WRC_CHECK("R13: the spender block lies alone in blk00001.dat; the coin "
              "it spends is stored unspent below the cursor", seeded);
    WRC_CHECK("R13: the delta finds the spend and deletes no row",
              armed && found == 1 && deletes == 0);
    WRC_CHECK("R13: the stored coin is marked spent by exactly that "
              "transaction and input", wrc_r_spendme_marked(r->ndb, spender));
    WRC_CHECK("R13: the height-10 coin, already spent, keeps its mark",
              wrc_r_spent_mark_kept(r->ndb));
    WRC_CHECK("R13: the spender's row carries block 160's hash, from_me and "
              "the fee from the stored coin's value",
              wrc_r_spender_row(r->ndb, spender, &p.hash, WRC_R_SPEND_AT));
    WRC_CHECK("R13: every other row is byte-equal",
              wrc_r_rows_equal(before, after) && wrc_r_has_stale(r->ndb));
    WRC_CHECK("R13: the cursor is stamped at the tip",
              wrc_r_cursor_is(r->ndb, WRC_NBLOCKS - 1));
    wrc_r_spender_uninstall(r, &p);
    return failures;
}

/* R16: a coin found inside the range and spent, with no change, by a block
 * in a file Pass 1 rules out (blk00001.dat pays no wallet key). The owner's
 * coin is the coinbase output every fixture body pays; the spender takes the
 * last height, so no later body pays the same outpoint again. Over empty
 * tables, both a full scan from 0 (a restored wallet's first boot) and a
 * delta with no stored unspent row must carry the spend: the walk parses
 * every height from the first coin on. Before, both skipped blk00001.dat and
 * committed the coin unspent. */
#define WRC_R16_AT (WRC_NBLOCKS - 1)

/* The owner's coin: output 0 of the fixture body's coinbase. */
static bool wrc_r16_spend(const struct wrc_r *r, struct wrc_r_spend *sp,
                          uint8_t coin[32])
{
    const struct block_index *bi = &r->idx[WRC_R_FOUND_AT];
    struct disk_block_pos pos = {.nFile = bi->nFile, .nPos = bi->nDataPos};
    struct block blk;
    block_init(&blk);
    bool ok = read_block_from_disk(&blk, &pos, r->datadir) &&
              blk.num_vtx >= 1 && blk.vtx[0].num_vout == 1 &&
              blk.vtx[0].vout[0].value > WRC_R_SPEND_FEE;
    if (ok) {
        memset(sp, 0, sizeof(*sp));
        memcpy(coin, blk.vtx[0].hash.data, 32);
        memcpy(sp->prev[0], coin, 32);
        sp->n[0] = 0;
        sp->nin = 1;
        sp->value = blk.vtx[0].vout[0].value - WRC_R_SPEND_FEE;
        sp->time = 1700000199u;
    }
    block_free(&blk);
    return ok;
}

/* The coin's one row carries exactly the spender's txid and input 0. */
static bool wrc_r16_coin_marked(struct node_db *ndb, const uint8_t coin[32],
                                const uint8_t spender[32])
{
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    if (!db_wallet_utxo_find(ndb, coin, 0, &u))
        return false;
    bool marked = u.is_spent && memcmp(u.spent_txid, spender, 32) == 0 &&
                  u.spent_vin == 0;
    printf("[spent=%d] ", u.is_spent ? 1 : 0);
    db_wallet_utxo_free(&u);
    return marked && wrc_r_count(ndb, "SELECT count(*) FROM wallet_utxos "
                                      "WHERE spent_txid IS NULL") == 0;
}

static bool wrc_r16_clear(struct node_db *ndb)
{
    return db_wallet_utxo_delete_all(ndb) && db_wallet_tx_delete_all(ndb);
}

static int wrc_r16_full(const struct wrc_r *r, const uint8_t coin[32],
                        const struct wrc_r_placed *p)
{
    int failures = 0;
    bool cleared = wrc_r16_clear(r->ndb);
    int found = wallet_scan_blocks_checked(r->ndb, &r->ms->chain_active,
                                           r->owner, r->datadir, 0,
                                           WRC_NBLOCKS - 1, NULL);
    printf("[R16 full found=%d] ", found);
    WRC_CHECK("R16: a full scan from 0 over empty tables commits",
              cleared && found > 0);
    WRC_CHECK("R16: the full scan marks the coin spent by the change-less "
              "spend in blk00001.dat", wrc_r16_coin_marked(r->ndb, coin,
                                                           p->spender));
    WRC_CHECK("R16: the full scan stores the spender's row with its block "
              "hash", wrc_r_spender_row(r->ndb, p->spender, &p->hash,
                                        WRC_R16_AT));
    return failures;
}

static int wrc_r16_delta(const struct wrc_r *r, const uint8_t coin[32],
                         const struct wrc_r_placed *p)
{
    int failures = 0;
    bool armed = false;
    int deletes = -1;
    bool cleared = wrc_r16_clear(r->ndb);
    int found = cleared ? wrc_r_delta_boot_scan(r, r->owner, &armed, &deletes)
                        : -100;
    printf("[R16 delta found=%d deletes=%d] ", found, deletes);
    WRC_CHECK("R16: a delta 150..199 with no stored unspent row commits and "
              "deletes no row", armed && found > 0 && deletes == 0);
    WRC_CHECK("R16: the delta marks the coin spent by the change-less spend "
              "in blk00001.dat", wrc_r16_coin_marked(r->ndb, coin,
                                                     p->spender));
    WRC_CHECK("R16: the delta stores the spender's row with its block hash",
              wrc_r_spender_row(r->ndb, p->spender, &p->hash, WRC_R16_AT));
    WRC_CHECK("R16: the cursor is stamped at the tip",
              wrc_r_cursor_is(r->ndb, WRC_NBLOCKS - 1));
    return failures;
}

static int wrc_r_found_spent_in_unmatched_file(const struct wrc_r *r)
{
    int failures = 0;
    struct wrc_r_spend sp;
    struct wrc_r_placed p;
    uint8_t coin[32] = {0};
    bool spend = wrc_r16_spend(r, &sp, coin);
    bool placed = spend && wrc_r_spender_install(r, &p, WRC_R16_AT, &sp);
    WRC_CHECK("R16: the change-less spender lies alone in blk00001.dat at "
              "the last height", placed);
    if (placed) {
        failures += wrc_r16_full(r, coin, &p);
        failures += wrc_r16_delta(r, coin, &p);
    }
    if (spend)
        wrc_r_spender_uninstall(r, &p);
    WRC_CHECK("R16: clear the rows it wrote", wrc_r16_clear(r->ndb));
    return failures;
}

/* R17: the stored unspent rows read before the walk succeeds, and a
 * wallet_utxos read inside the scan's write transaction fails. The
 * authorizer (given the connection) denies wallet_utxos reads only while a
 * transaction is open, so the pre-walk read, made outside one, passes and
 * the existing-row read of the write (R17a) or the stored coin's recheck
 * before its spend mark (R17b) fails. Either refuses: every row byte-equal,
 * the cursor unstamped. */
static int wrc_r17_reads_outside, wrc_r17_reads_denied;

static int wrc_r17_deny_utxo_read_in_tx(void *arg, int action, const char *a,
                                        const char *b, const char *c,
                                        const char *d)
{
    (void)b; (void)c; (void)d;
    if (action != SQLITE_READ || !a || strcmp(a, "wallet_utxos") != 0)
        return SQLITE_OK;
    if (sqlite3_get_autocommit((sqlite3 *)arg)) {
        wrc_r17_reads_outside++;
        return SQLITE_OK;
    }
    wrc_r17_reads_denied++;
    return SQLITE_DENY;
}

static int wrc_r17_run(const struct wrc_r *r, const struct wallet *w,
                       bool seeded, const char *label)
{
    int failures = 0;
    char name[200];
    seeded = seeded && wrc_r_stamp_cursor(r->ndb, w, 149);
    struct wrc_r_rows before = wrc_r_rows_now(r->ndb);
    wrc_r17_reads_outside = wrc_r17_reads_denied = 0;
    bool denied = sqlite3_set_authorizer(r->ndb->db,
                                         wrc_r17_deny_utxo_read_in_tx,
                                         r->ndb->db) == SQLITE_OK;
    int found = seeded ? boot_cursor_scan_wallet(r->ndb, &r->ms->chain_active,
                                                 w, r->datadir,
                                                 WRC_NBLOCKS - 1)
                       : -100;
    bool cleared = sqlite3_set_authorizer(r->ndb->db, NULL, NULL) == SQLITE_OK;
    printf("[%s found=%d read_before=%d denied_in_write=%d] ", label, found,
           wrc_r17_reads_outside, wrc_r17_reads_denied);
    snprintf(name, sizeof(name), "%s: the pre-walk read passes and a "
             "wallet_utxos read inside the write fails", label);
    WRC_CHECK(name, seeded && denied && cleared && wrc_r17_reads_outside > 0 &&
                    wrc_r17_reads_denied > 0);
    snprintf(name, sizeof(name), "%s: the delta refuses", label);
    WRC_CHECK(name, found < 0 && found != -100);
    snprintf(name, sizeof(name), "%s: every row is byte-equal", label);
    WRC_CHECK(name, wrc_r_rows_equal(before, wrc_r_rows_now(r->ndb)));
    snprintf(name, sizeof(name), "%s: the cursor is not stamped", label);
    WRC_CHECK(name, wrc_r_cursor_is(r->ndb, 149));
    return failures;
}

static int wrc_r_delta_write_read_fails(const struct wrc_r *r)
{
    int failures = 0;
    uint8_t txid[32] = {0};
    failures += wrc_r17_run(r, r->owner, wrc_r_reseed_found(r, txid),
                            "R17a existing-row read");
    struct wrc_r_placed p;
    const struct wrc_r_spend sp = wrc_r_spendme_spend();
    bool seeded = wrc_r_spender_install(r, &p, WRC_R_SPEND_AT, &sp) &&
                  wrc_r_reseed(r->ndb) && wrc_r_seed_spendme(r->ndb);
    failures += wrc_r17_run(r, r->w, seeded, "R17b stored-coin recheck");
    WRC_CHECK("R17b: the stored coin is still unspent",
              wrc_r_count(r->ndb, "SELECT count(*) FROM wallet_utxos WHERE "
                                  "hex(txid) GLOB '5A5A*' AND spent_txid IS "
                                  "NULL") == 1);
    wrc_r_spender_uninstall(r, &p);
    return failures;
}

/* R15: a full scan from height 0 that finds a wallet transaction. Over
 * empty tables it commits rows carrying the block hash (the repair a
 * rescanwallet used to be unable to make), and a second scan rediscovers
 * exactly those rows. With a stored row the scan cannot rediscover (rows a
 * block scan cannot derive exist: shielded-only, unconfirmed, watch-only),
 * the full replace refuses before it deletes anything. */
static int wrc_r_full_found(const struct wrc_r *r)
{
    int failures = 0;
    const struct active_chain *chain = &r->ms->chain_active;
    wrc_set_have_data(r->idx, WRC_NBLOCKS, true);
    bool cleared = db_wallet_utxo_delete_all(r->ndb) &&
                   db_wallet_tx_delete_all(r->ndb);
    int found = wallet_scan_blocks_checked(r->ndb, chain, r->owner,
                                           r->datadir, 0, WRC_NBLOCKS - 1,
                                           NULL);
    struct wrc_r_rows first = wrc_r_rows_now(r->ndb);
    printf("[R15 found=%d] ", found);
    WRC_CHECK("R15: a full scan from 0 over empty tables commits what it "
              "found", cleared && found > 0);
    WRC_CHECK("R15: its rows carry the hash of the block they were read "
              "from", wrc_r_found_rows_hashed(r, 0));
    int again = wallet_scan_blocks_checked(r->ndb, chain, r->owner,
                                           r->datadir, 0, WRC_NBLOCKS - 1,
                                           NULL);
    WRC_CHECK("R15: a second full scan rediscovers and rewrites the same "
              "rows", again == found &&
              wrc_r_rows_equal(first, wrc_r_rows_now(r->ndb)));
    bool armed = wrc_r_seed_stale(r->ndb) && wrc_r_has_stale(r->ndb);
    struct wrc_r_rows before = wrc_r_rows_now(r->ndb);
    armed = armed && wrc_r_watch_deletes(r->ndb, true);
    int refused = wallet_scan_blocks_checked(r->ndb, chain, r->owner,
                                             r->datadir, 0, WRC_NBLOCKS - 1,
                                             NULL);
    int deletes = wrc_r_deletes;
    armed = wrc_r_watch_deletes(r->ndb, false) && armed;
    printf("[R15 refused=%d deletes=%d] ", refused, deletes);
    WRC_CHECK("R15: with a stored row no block holds, the full replace "
              "refuses before any delete", armed && refused < 0 &&
              deletes == 0);
    WRC_CHECK("R15: and every row is byte-equal",
              wrc_r_rows_equal(before, wrc_r_rows_now(r->ndb)) &&
              wrc_r_has_stale(r->ndb));
    return failures;
}

/* R4/R5: the boot catch-up scan. A full range with holes keeps the rows and
 * the cursor. A delta range whose bodies are all present scans and keeps the
 * rows below the cursor: R4 used to pin the delete of every row, which a
 * routine restart turned into lost wallet history. */
static int wrc_r_boot_scan(const struct wrc_r *r)
{
    int failures = 0;
    const struct active_chain *chain = &r->ms->chain_active;
    const int64_t fp = (int64_t)wallet_scan_keyset_fp(r->w);
    int64_t cursor = 0;

    struct wrc_r_rows before = wrc_r_rows_now(r->ndb);
    bool reset = node_db_state_set_int(r->ndb, BOOT_CUR_WALLET, -1) &&
                 node_db_state_set_int(r->ndb, BOOT_CUR_WALLET_KS, fp);
    int refused = boot_cursor_scan_wallet(r->ndb, chain, r->w, r->datadir,
                                          WRC_NBLOCKS - 1);
    WRC_CHECK("R5: a boot scan from genesis over bodiless heights refuses",
              reset && refused < 0);
    WRC_CHECK("R5: it keeps the wallet rows and leaves the cursor unstamped",
              wrc_r_rows_equal(before, wrc_r_rows_now(r->ndb)) &&
              wrc_r_has_stale(r->ndb) &&
              node_db_state_get_int(r->ndb, BOOT_CUR_WALLET, &cursor) &&
              cursor == -1);

    bool delta = node_db_state_set_int(r->ndb, BOOT_CUR_WALLET, 149);
    before = wrc_r_rows_now(r->ndb);
    int found = boot_cursor_scan_wallet(r->ndb, chain, r->w, r->datadir,
                                        WRC_NBLOCKS - 1);
    WRC_CHECK("R4: the catch-up delta 150..199, every body present, scans",
              delta && found == 0);
    WRC_CHECK("R4: it keeps the rows below the cursor byte-equal and stamps "
              "the cursor", wrc_r_rows_equal(before, wrc_r_rows_now(r->ndb)) &&
              wrc_r_has_stale(r->ndb) &&
              wrc_r_cursor_is(r->ndb, WRC_NBLOCKS - 1));
    return failures;
}

static int wrc_r_coverage_guard(const struct wrc_r *r)
{
    int failures = 0;
    struct coins_view backing;
    struct coins_view_cache cache;
    memset(&backing, 0, sizeof(backing));
    coins_view_cache_init(&cache, &backing);
    rpc_wallet_set_coins_tip(&cache);
    /* Pin the scan's block directory to the fixture (mainnet params: the
     * network directory is the base), so no path reaches a real datadir. */
    bool pinned = chmod(r->datadir, 0700) == 0 && SetDataDir(r->datadir);
    WRC_CHECK("R: scan block directory pinned to the fixture", pinned);
    if (pinned) {
        failures += wrc_r_full_range_replaces(r);
        for (int i = 0; i < 150; i++)
            r->idx[i].nStatus &= ~BLOCK_HAVE_DATA;
        WRC_CHECK("R2: seed the stale row again",
                  wrc_r_seed_stale(r->ndb) && wrc_r_has_stale(r->ndb));
        failures += wrc_r_holed_range_refused(r, "rescanwallet", false);
        failures += wrc_r_holed_range_refused(r, "reindexdb", false);
        failures += wrc_r_holed_range_refused(r, "replaywalletfromchain",
                                              true);
        failures += wrc_r_pass2_recheck(r);
        failures += wrc_r_boot_scan(r);
        failures += wrc_r_delta_keeps_rows(r);
        failures += wrc_r_delta_found_keeps_rows(r);
        failures += wrc_r_empty_delta_range(r);
        failures += wrc_r_delta_commit_keeps_rows(r);
        failures += wrc_r_delta_read_fails(r, r->owner, "wallet_utxos",
                                           "R11");
        failures += wrc_r_delta_read_fails(r, r->owner,
                                           "wallet_transactions", "R12");
        failures += wrc_r_delta_spends_stored_coin(r);
        failures += wrc_r_delta_read_fails(r, r->w, "wallet_utxos", "R14");
        failures += wrc_r_full_found(r);
        failures += wrc_r_found_spent_in_unmatched_file(r);
        failures += wrc_r_delta_write_read_fails(r);
    }
    wrc_set_have_data(r->idx, WRC_NBLOCKS, true);
    WRC_CHECK("R: clear the rows this section wrote",
              db_wallet_utxo_delete_all(r->ndb) &&
              db_wallet_tx_delete_all(r->ndb));
    SetDataDir("");
    ClearDataDirCache();
    rpc_wallet_set_coins_tip(NULL);
    coins_view_cache_free(&cache);
    return failures;
}

/* ── U. Unreadable block data is a hole ──────────────────────────────────
 * Every height carries BLOCK_HAVE_DATA, yet the bytes behind it cannot be
 * read: its block file is absent, cut short before the block, or corrupted
 * so the block does not parse. The scan used to skip such a block silently
 * and replace the rows with what was left. Each case now refuses with the
 * rows byte-equal, through wallet_scan_blocks and straight into Pass 2.
 *
 * blk00000.dat holds block A (pays the wallet's key, so Pass 1 matches the
 * file) then block B (pays nobody); the one-height range points at B.
 * blk00001.dat is blk00000 cut at B's data position, blk00002.dat is
 * blk00000 with B's bytes after its version overwritten, blk00003.dat is
 * junk holding no wallet bytes, and blk00004.dat does not exist. */
#define WRC_U_FILES 5      /* direct Pass-2 calls map 0..4 */
#define WRC_U_NOT_RUN (-100)

struct wrc_u {
    const struct wallet *w;
    struct active_chain *chain;
    struct block_index *tip; /* the one height (0) of the scanned range */
    const char *dir;
};

struct wrc_u_out {
    int rc;
    bool kept;        /* rows byte-equal before and after, stale pair kept */
    bool replaced;    /* stale pair gone, both tables empty */
    struct wallet_scan_coverage cov;
};

static bool wrc_u_write_file(const char *dir, int n, const uint8_t *data,
                             size_t len)
{
    char path[400];
    snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", dir, n);
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(data, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static uint8_t *wrc_u_read_file(const char *dir, int n, size_t *len)
{
    char path[400];
    snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", dir, n);
    struct stat st;
    FILE *f = NULL;
    uint8_t *buf = NULL;
    if (stat(path, &st) == 0 && st.st_size > 0 && (f = fopen(path, "rb")))
        buf = malloc((size_t)st.st_size); /* raw-alloc-ok:test-fixture */
    if (buf && fread(buf, 1, (size_t)st.st_size, f) == (size_t)st.st_size) {
        *len = (size_t)st.st_size;
    } else {
        free(buf);
        buf = NULL;
    }
    if (f)
        fclose(f);
    return buf;
}

/* The hash of the block stored at `pos` under `dir`, read back from disk. */
static bool wrc_u_body_hash(const char *dir, const struct disk_block_pos *pos,
                            struct uint256 *hash)
{
    struct block blk;
    block_init(&blk);
    bool ok = read_block_from_disk(&blk, pos, dir);
    if (ok)
        block_get_hash(&blk, hash);
    block_free(&blk);
    return ok;
}

/* Write A and B, then the cut, corrupted and junk copies. `hash_b` is B's
 * hash, the hash an index entry for B names. */
static bool wrc_u_write_files(const char *dir, const struct key_id *kid,
                              unsigned *pos_b, struct uint256 *hash_b)
{
    struct script pay_to_us, pay_to_nobody;
    script_init(&pay_to_us);
    script_for_p2pkh(&pay_to_us, kid);
    script_init(&pay_to_nobody);
    struct disk_block_pos a, b;
    disk_block_pos_init(&a);
    disk_block_pos_init(&b);
    if (!wrc_g_write_body(&pay_to_us, &a, dir) ||
        !wrc_g_write_body(&pay_to_nobody, &b, dir) ||
        a.nFile != 0 || b.nFile != 0 || b.nPos <= a.nPos ||
        !wrc_u_body_hash(dir, &b, hash_b))
        return false;
    *pos_b = b.nPos;
    size_t len = 0;
    uint8_t *buf = wrc_u_read_file(dir, 0, &len);
    bool ok = buf && len > (size_t)b.nPos + 4 &&
              wrc_u_write_file(dir, 1, buf, b.nPos);
    if (ok) {
        memset(buf + b.nPos + 4, 0xff, len - b.nPos - 4);
        ok = wrc_u_write_file(dir, 2, buf, len);
    }
    uint8_t junk[64];
    memset(junk, 0xff, sizeof(junk));
    ok = ok && wrc_u_write_file(dir, 3, junk, sizeof(junk));
    free(buf);
    return ok;
}

/* Pass 2 alone, every file marked matched. */
static int wrc_u_pass2(const struct wrc_u *h, struct node_db *ndb,
                       struct wallet_scan_coverage *cov)
{
    struct scan_addr_ht aht;
    scan_aht_init(&aht);
    const bool match[WRC_U_FILES] = {true, true, true, true, true};
    const struct timespec t = {.tv_sec = 1};
    int rc = wallet_scan_pass2_execute(ndb, h->chain, h->dir, 0, 0, &aht,
                                       match, WRC_U_FILES, WRC_U_FILES,
                                       &t, &t, cov);
    scan_aht_free(&aht);
    return rc;
}

/* Point height 0 at (nfile, data_pos), seed the stale row pair in a fresh
 * node_db (no Pass-1 cache carries over) and run one scan. */
static struct wrc_u_out wrc_u_scan(const struct wrc_u *h, int nfile,
                                   unsigned data_pos, bool direct)
{
    struct wrc_u_out out = {.rc = WRC_U_NOT_RUN,
                            .cov = {.first_missing = -1}};
    h->tip->nFile = nfile;
    h->tip->nDataPos = data_pos;
    struct node_db ndb;
    if (!node_db_open(&ndb, ":memory:"))
        return out;
    if (wrc_r_seed_stale(&ndb) && wrc_r_has_stale(&ndb)) {
        struct wrc_r_rows before = wrc_r_rows_now(&ndb);
        out.rc = direct ? wrc_u_pass2(h, &ndb, &out.cov)
                        : wallet_scan_blocks_checked(&ndb, h->chain, h->w,
                                                     h->dir, 0, 0, &out.cov);
        out.kept = wrc_r_rows_equal(before, wrc_r_rows_now(&ndb)) &&
                   wrc_r_has_stale(&ndb);
        out.replaced = !wrc_r_has_stale(&ndb) &&
                       wrc_r_count(&ndb, "SELECT count(*) FROM wallet_utxos") == 0 &&
                       wrc_r_count(&ndb, "SELECT count(*) FROM "
                                         "wallet_transactions") == 0;
    }
    node_db_close(&ndb);
    printf("[%s rc=%d missing=%lld first=%d kept=%d] ",
           direct ? "pass2" : "scan", out.rc,
           (long long)out.cov.blocks_missing, out.cov.first_missing, out.kept);
    return out;
}

static int wrc_u_hole(const struct wrc_u *h, const char *what, int nfile,
                      unsigned data_pos)
{
    int failures = 0;
    char name[200];
    for (int direct = 0; direct < 2; direct++) {
        struct wrc_u_out o = wrc_u_scan(h, nfile, data_pos, direct != 0);
        snprintf(name, sizeof(name), "U: %s, %s: refused at height 0, rows "
                 "byte-equal", what, direct ? "Pass 2" : "wallet_scan_blocks");
        WRC_CHECK(name, o.rc == WALLET_SCAN_REFUSED_MISSING_DATA &&
                        o.cov.first_missing == 0 &&
                        o.cov.blocks_missing >= 1 && o.kept);
    }
    return failures;
}

static int wrc_u_cases(const struct wrc_u *h, unsigned pos_b)
{
    int failures = 0;
    for (int direct = 0; direct < 2; direct++) {
        struct wrc_u_out o = wrc_u_scan(h, 0, pos_b, direct != 0);
        WRC_CHECK(direct ? "U: positive control, Pass 2: the intact block "
                           "parses and the rows are replaced"
                         : "U: positive control, wallet_scan_blocks: the "
                           "intact chain replaces the rows",
                  o.rc == 0 && o.replaced && o.cov.blocks_missing == 0 &&
                  o.cov.first_missing == -1);
    }
    struct wrc_u_out skip = wrc_u_scan(h, 3, 8, false);
    WRC_CHECK("U: a block in a file Pass 1 read and ruled out is skipped "
              "unparsed, the rows are replaced",
              skip.rc == 0 && skip.replaced);
    /* The bytes at the entry's position parse, but as a block other than the
     * one the entry names: no row may carry either hash. */
    const struct uint256 *named = h->tip->phashBlock;
    struct uint256 other;
    memset(&other, 0x42, sizeof(other));
    h->tip->phashBlock = &other;
    failures += wrc_u_hole(h, "block does not hash to its index entry", 0,
                           pos_b);
    h->tip->phashBlock = named;
    failures += wrc_u_hole(h, "block file absent", 4, pos_b);
    failures += wrc_u_hole(h, "block file cut before the block", 1, pos_b);
    failures += wrc_u_hole(h, "block does not parse", 2, pos_b);
    return failures;
}

/* No block file at all over a non-empty range: refused, rows kept. */
static int wrc_u_no_files(struct wrc_u *h, const char *basedir,
                          unsigned pos_b)
{
    int failures = 0;
    char edir[300], blocksdir[360];
    snprintf(edir, sizeof(edir), "%s_h0", basedir);
    bool made = wrc_g_make_fixture_dirs(edir, blocksdir, sizeof(blocksdir)) &&
                chmod(edir, 0700) == 0 && SetDataDir(edir);
    WRC_CHECK("U: empty block directory pinned", made);
    if (made) {
        h->dir = edir;
        struct wrc_u_out o = wrc_u_scan(h, 0, pos_b, false);
        WRC_CHECK("U: no block file at all: refused at height 0, rows "
                  "byte-equal",
                  o.rc == WALLET_SCAN_REFUSED_MISSING_DATA &&
                  o.cov.first_missing == 0 && o.cov.blocks_missing == 1 &&
                  o.kept);
    }
#if defined(_WIN32)
    test_cleanup_tmpdir(blocksdir);
    test_cleanup_tmpdir(edir);
#else
    {
        char cmd[400];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", edir);
        TEST_DISCARD(system(cmd));
    }
#endif
    return failures;
}

static int wrc_u_unreadable_holes(const struct wallet *w,
                                  const struct key_id *kid,
                                  const char *basedir)
{
    int failures = 0;
    char hdir[300], blocksdir[360];
    snprintf(hdir, sizeof(hdir), "%s_h", basedir);
    unsigned pos_b = 0;
    struct uint256 hash_b;
    memset(&hash_b, 0, sizeof(hash_b));
    bool made = wrc_g_make_fixture_dirs(hdir, blocksdir, sizeof(blocksdir)) &&
                wrc_u_write_files(hdir, kid, &pos_b, &hash_b) &&
                chmod(hdir, 0700) == 0 && SetDataDir(hdir);
    WRC_CHECK("U: fixture block files written and pinned", made);
    struct active_chain chain;
    active_chain_init(&chain);
    struct block_index tip;
    block_index_init(&tip);
    tip.nHeight = 0;
    tip.nStatus = BLOCK_HAVE_DATA;
    tip.phashBlock = &hash_b;
    if (made && active_chain_install_tip_slot(&chain, &tip)) {
        struct wrc_u h = {.w = w, .chain = &chain, .tip = &tip, .dir = hdir};
        failures += wrc_u_cases(&h, pos_b);
        failures += wrc_u_no_files(&h, basedir, pos_b);
    } else {
        failures++;
    }
    active_chain_free(&chain);
    SetDataDir("");
    ClearDataDirCache();
#if defined(_WIN32)
    test_cleanup_tmpdir(blocksdir);
    test_cleanup_tmpdir(hdir);
#else
    {
        char cmd[400];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", hdir);
        TEST_DISCARD(system(cmd));
    }
#endif
    return failures;
}

int test_wallet_rescan_coverage(void);
int test_wallet_rescan_coverage(void)
{
    int failures = 0;

    char datadir[256];
    snprintf(datadir, sizeof(datadir),
             "test-tmp/wallet_rescan_coverage_%d", (int)getpid());
    char blocksdir[320];
    if (!wrc_create_fixture_dirs(datadir, blocksdir, sizeof(blocksdir))) {
        printf("wallet_rescan_coverage: could not create %s\n", datadir);
        return 1;
    }

    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", datadir);
    struct node_db ndb;
    if (!node_db_open(&ndb, dbpath)) {
        printf("wallet_rescan_coverage: node_db_open(%s) failed\n", dbpath);
        return 1;
    }

    /* ── wallet 1: owns the funding output ───────────────────────────── */
    struct wallet *w1 = zcl_calloc(1, sizeof(*w1), "test-wallet");
    /* ~40 MB wallet: heap, never stack */
    wallet_init(w1);
    struct pubkey pk;
    memset(&pk, 0, sizeof(pk));
    bool have_key = wallet_generate_new_key(w1, &pk);
    WRC_CHECK("wallet1 generates a key", have_key);
    struct key_id kid = pubkey_get_id(&pk);

    struct script pay_to_us;
    script_init(&pay_to_us);
    script_for_p2pkh(&pay_to_us, &kid);

    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    struct uint256 body_hash;
    memset(&body_hash, 0, sizeof(body_hash));
    bool wrote = wrc_write_shared_body(datadir, &pay_to_us, &pos, &body_hash);
    WRC_CHECK("write a block (1 transparent + 1 shielded tx) to disk", wrote);

    /* ── 200 index entries, every one pointing at that same on-disk block.
     * Sharing one body keeps the fixture cheap while giving a range large
     * enough to express the coverage floor. ── */
    struct block_index *idx =
        calloc(WRC_NBLOCKS, sizeof(*idx)); /* raw-alloc-ok:test-fixture */
    struct block_index **chain =
        calloc(WRC_NBLOCKS, sizeof(*chain)); /* raw-alloc-ok:test-fixture */
    WRC_CHECK("allocate synthetic chain", idx != NULL && chain != NULL);
    if (!idx || !chain) {
        free(idx); free(chain);
        node_db_close(&ndb);
        return failures + 1;
    }
    wrc_fill_chain(idx, chain, &pos, &body_hash, WRC_NBLOCKS);

    struct main_state ms;
    main_state_init(&ms);
    free(ms.chain_active.chain);
    ms.chain_active.chain = chain;
    ms.chain_active.height = WRC_NBLOCKS - 1;
    ms.chain_active.capacity = WRC_NBLOCKS;

    struct wallet_sqlite ws;
    WRC_CHECK("wallet_sqlite_open", wallet_sqlite_open(&ws, ndb.db));

    struct tx_mempool mempool;
    tx_mempool_init(&mempool, 0);

    struct rpc_table wtbl;
    rpc_table_init(&wtbl);
    register_wallet_rpc_commands(&wtbl);
    /* rpc_table_execute() refuses every method while warmup is armed
     * (code -28, "RPC server started"); this fixture never boots a node. */
    set_rpc_warmup_finished();

    rpc_wallet_set_state(w1, &ms, datadir, &ws, &mempool, NULL);
    rpc_wallet_set_node_db(&ndb);
    rpc_wallet_set_coins_tip(NULL);  /* skip the chainstate-lookup gate */

    const int last = WRC_NBLOCKS - 1;
    WRC_CHECK("mismatched transaction root cannot change wallet or coverage",
              wrc_reject_invalid_body(w1, datadir, &pos, false));
    WRC_CHECK("duplicate transaction tree cannot change wallet or coverage",
              wrc_reject_invalid_body(w1, datadir, &pos, true));

    /* ── A. Full coverage, wallet owns an output in every block ──────── */
    {
        struct json_value params, result;
        wrc_params(&params, 0, last);
        json_init(&result);
        bool ok = rpc_table_execute(&wtbl, "rescanblockchain", &params, &result);
        WRC_CHECK("A: rescan over a fully-bodied range succeeds", ok);
        WRC_CHECK("A: reports blocks_scanned == 200",
                  wrc_int(&result, "blocks_scanned") == WRC_NBLOCKS);
        WRC_CHECK("A: reports blocks_missing_data == 0",
                  wrc_int(&result, "blocks_missing_data") == 0);
        WRC_CHECK("A: reports outputs_found == 200 (one per block)",
                  wrc_int(&result, "outputs_found") == WRC_NBLOCKS);
        WRC_CHECK("A: coverage_ok is true", wrc_bool(&result, "coverage_ok", false));
        WRC_CHECK("A: no blocker is named",
                  wrc_str(&result, "blocker")[0] == '\0');
        /* D-item: the untried-shielded condition must be VISIBLE, not silent.
         * The wallet holds no Sapling key, so every shielded output in range
         * went untried — exactly the state after a seed-only restore. */
        WRC_CHECK("A: reports sapling_key_count == 0",
                  wrc_int(&result, "sapling_key_count") == 0);
        WRC_CHECK("A: reports 200 shielded txs left untried",
                  wrc_int(&result, "shielded_txs_unscanned") == WRC_NBLOCKS);
        WRC_CHECK("A: flags shielded_scan_skipped",
                  wrc_bool(&result, "shielded_scan_skipped", false));
        json_free(&params);
        json_free(&result);
    }

    /* ── B. THE AUDIT'S CASE: a snapshot-bootstrapped node. Every block is
     * indexed but no body is on disk. The pre-fix code reported success and
     * "0 wallet outputs found" here, and the user concluded the backup was
     * empty. It must now refuse. ── */
    wrc_set_have_data(idx, WRC_NBLOCKS, false);
    {
        struct json_value params, result;
        wrc_params(&params, 0, last);
        json_init(&result);
        (void)rpc_table_execute(&wtbl, "rescanblockchain", &params, &result);
        WRC_CHECK("B: reports blocks_scanned == 0 (nothing was read)",
                  wrc_int(&result, "blocks_scanned") == 0);
        WRC_CHECK("B: reports blocks_missing_data == 200",
                  wrc_int(&result, "blocks_missing_data") == WRC_NBLOCKS);
        WRC_CHECK("B: reports outputs_found == 0",
                  wrc_int(&result, "outputs_found") == 0);
        WRC_CHECK("B: coverage_ok is FALSE — a bodyless rescan is not success",
                  wrc_bool(&result, "coverage_ok", true) == false);
        WRC_CHECK("B: names blocker RESCAN_NO_BLOCK_DATA",
                  strcmp(wrc_str(&result, "blocker"),
                         "RESCAN_NO_BLOCK_DATA") == 0);
        json_free(&params);
        json_free(&result);
    }

    /* ── C. 150/200 bodies present = 75%, under the 99% floor ────────── */
    wrc_set_have_data(idx, WRC_NBLOCKS, true);
    for (int i = 0; i < 50; i++)
        idx[i].nStatus &= ~BLOCK_HAVE_DATA;
    {
        struct json_value params, result;
        wrc_params(&params, 0, last);
        json_init(&result);
        (void)rpc_table_execute(&wtbl, "rescanblockchain", &params, &result);
        WRC_CHECK("C: reports blocks_scanned == 150",
                  wrc_int(&result, "blocks_scanned") == 150);
        WRC_CHECK("C: reports blocks_missing_data == 50",
                  wrc_int(&result, "blocks_missing_data") == 50);
        WRC_CHECK("C: coverage_ok is FALSE at 75% coverage",
                  wrc_bool(&result, "coverage_ok", true) == false);
        WRC_CHECK("C: names blocker RESCAN_INCOMPLETE_COVERAGE",
                  strcmp(wrc_str(&result, "blocker"),
                         "RESCAN_INCOMPLETE_COVERAGE") == 0);
        /* Found outputs are still reported — a partial scan is not a void one. */
        WRC_CHECK("C: still reports the 150 outputs it did find",
                  wrc_int(&result, "outputs_found") == 150);
        json_free(&params);
        json_free(&result);
    }

    /* ── D. 199/200 = 99.5% coverage (clears the floor) but the wallet owns
     * nothing. We still cannot say "you have no funds" — the one block we
     * could not read is exactly where they might be. ── */
    struct wallet *w2 = zcl_calloc(1, sizeof(*w2), "test-wallet");
    /* ~40 MB wallet: heap, never stack */
    wallet_init(w2);
    wrc_set_have_data(idx, WRC_NBLOCKS, true);
    idx[7].nStatus &= ~BLOCK_HAVE_DATA;
    rpc_wallet_set_state(w2, &ms, datadir, &ws, &mempool, NULL);
    {
        struct json_value params, result;
        wrc_params(&params, 0, last);
        json_init(&result);
        (void)rpc_table_execute(&wtbl, "rescanblockchain", &params, &result);
        WRC_CHECK("D: reports blocks_scanned == 199",
                  wrc_int(&result, "blocks_scanned") == 199);
        WRC_CHECK("D: reports blocks_missing_data == 1",
                  wrc_int(&result, "blocks_missing_data") == 1);
        WRC_CHECK("D: reports outputs_found == 0 (this wallet owns nothing)",
                  wrc_int(&result, "outputs_found") == 0);
        WRC_CHECK("D: coverage_ok is FALSE — zero-found is inconclusive here",
                  wrc_bool(&result, "coverage_ok", true) == false);
        WRC_CHECK("D: names blocker RESCAN_INCONCLUSIVE_ZERO",
                  strcmp(wrc_str(&result, "blocker"),
                         "RESCAN_INCONCLUSIVE_ZERO") == 0);
        json_free(&params);
        json_free(&result);
    }

    /* ── R. rescanwallet, reindexdb, replaywalletfromchain and the boot
     * catch-up scan against the coverage guard ── */
    {
        struct pubkey pk2;
        memset(&pk2, 0, sizeof(pk2));
        WRC_CHECK("R: wallet2 generates a key that owns no fixture output",
                  wallet_generate_new_key(w2, &pk2));
        const struct wrc_r r = {
            .ndb = &ndb, .tbl = &wtbl, .w = w2, .owner = w1, .ms = &ms,
            .datadir = datadir, .idx = idx, .body_hash = &body_hash,
        };
        failures += wrc_r_coverage_guard(&r);
    }

    failures += wrc_u_unreadable_holes(w1, &kid, datadir);

    failures += wrc_boot_catch_up_body_root(w1, &ms, datadir, idx);
    {
        struct wrc_f f = {
            .owner = w1, .kid = &kid, .ms = &ms, .datadir = datadir,
            .idx = idx, .ws = &ws, .tbl = &wtbl, .mempool = &mempool,
        };
        failures += wrc_boot_catch_up_fail_closed(&f);
        failures += wrc_accounting_boundary(&f, w1);
        failures += wrc_accounting_history(&f, w1);
        failures += wrc_accounting_shielded_funded(&f, w1);
    }
    rpc_wallet_set_state(w1, &ms, datadir, &ws, &mempool, NULL);
    failures += wrc_k_cleared_marker_persists(w1, &ws, &wtbl, idx, last);

    /* ── G. Kill-restart depth re-basing (self-contained fixture) ─────── */
    failures += wrc_g_kill_restart_baseline(w1, &kid, datadir);
    failures += wrc_cutover_binding(datadir);

    /* ── teardown ────────────────────────────────────────────────────── */
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    rpc_wallet_set_node_db(NULL);
    tx_mempool_free(&mempool);
    wallet_sqlite_close(&ws);
    wallet_free(w2); free(w2);
    wallet_free(w1); free(w1);
    ms.chain_active.chain = NULL;
    ms.chain_active.capacity = 0;
    ms.chain_active.height = 0;
    free(chain);
    free(idx);
    node_db_close(&ndb);
#if defined(_WIN32)
    /* No rm -rf: the fixture is exactly two levels deep. */
    test_cleanup_tmpdir(blocksdir);
    test_cleanup_tmpdir(datadir);
#else
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", datadir);
         TEST_DISCARD(system(cmd));
    }
#endif

    if (failures == 0)
        printf("wallet_rescan_coverage: OK (a rescan can no longer "
               "silently find nothing)\n");
    else
        printf("=== wallet_rescan_coverage: %d failure(s) ===\n", failures);
    return failures;
}
