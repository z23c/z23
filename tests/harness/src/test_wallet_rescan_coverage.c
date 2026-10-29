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
 */

#include "test/test_core.h"
#include "platform/directory_compat.h"

#include "controllers/wallet_controller.h"
#include "config/boot_internal.h"
#include "chain/chainparams.h"
#include "util/util.h"

#include "models/database.h"

#include "wallet/wallet.h"
#include "util/safe_alloc.h"
#include "wallet/wallet_sqlite.h"

#include "storage/disk_block_io.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
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

/* A wallet as the next boot builds it: key, flushed txs, then scan state. */
static struct wallet *wrc_reboot_wallet(struct wrc_f *f)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "test-wallet");
    wallet_init(w);
    struct privkey key;
    if (wallet_dump_key(f->owner, f->kid, &key))
        (void)wallet_import_key(w, &key);
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
            wrote = write_block_to_disk(&blk, pos, dir, msg_start);
        }
    }
    block_free(&blk);
    return wrote;
}

/* Point n synthetic index entries at one shared on-disk body. */
static void wrc_fill_chain(struct block_index *idx, struct block_index **chain,
                           const struct disk_block_pos *pos, int n)
{
    for (int i = 0; i < n; i++) {
        block_index_init(&idx[i]);
        idx[i].nHeight = i;
        idx[i].nFile = pos->nFile;
        idx[i].nDataPos = pos->nPos;
        idx[i].nStatus = BLOCK_HAVE_DATA;
        idx[i].phashBlock = NULL;
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
    wrc_fill_chain(idx, chain, &pos_empty, WRC_G_BLOCKS);
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
                                  struct disk_block_pos *pos)
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
        wrote = write_block_to_disk(&blk, pos, datadir, msg_start);
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
    bool wrote = wrc_write_shared_body(datadir, &pay_to_us, &pos);
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
    wrc_fill_chain(idx, chain, &pos, WRC_NBLOCKS);

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

    failures += wrc_boot_catch_up_body_root(w1, &ms, datadir, idx);
    {
        struct wrc_f f = {
            .owner = w1, .kid = &kid, .ms = &ms, .datadir = datadir,
            .idx = idx, .ws = &ws, .tbl = &wtbl, .mempool = &mempool,
        };
        failures += wrc_boot_catch_up_fail_closed(&f);
    }

    /* ── G. Kill-restart depth re-basing (self-contained fixture) ─────── */
    failures += wrc_g_kill_restart_baseline(w1, &kid, datadir);

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
