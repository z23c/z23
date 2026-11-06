/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A WALLET THIS NODE MINTS FRESH AT BOOT RECORDS A BIRTHDAY; NO OTHER DOES.
 *
 * boot_wallet_create_new is the one boot site that makes a brand-new wallet
 * (reached only when boot_wallet_may_mint finds no key, no seed and no Sapling
 * key). Keys it draws now cannot have been paid in any earlier block, so it
 * stores the birthday at the height the datadir proves, and the first boot
 * catch-up starts at that floor instead of block 0 and the 1000-block deferral.
 * Without it a fresh node that syncs a long chain reads WALLET_CATCH_UP_DEFERRED
 * forever.
 *
 *   1. fresh boot wallet, connected tip at 1500: birthday 1500, the floor block
 *      is 1400, and a boot catch-up on that chain starts at 1400, not deferred.
 *   2. no known height (empty datadir): no birthday, scan from 0 as before.
 *   3. a wallet restored from a phrase gets no birthday, boot never mints over
 *      it, and its catch-up still defers from 0.
 *   4. a wallet that holds keys from elsewhere (imported, loaded) is never
 *      minted over, so it is never given a birthday.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "config/boot_internal.h"
#include "config/boot_wallet_phrase.h"
#include "models/database.h"
#include "models/wallet_key.h"
#include "services/wallet_recovery_service.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include "controllers/wallet_scan.h"
#include "wallet/wallet_sqlite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define WBB_CHECK(name, expr) do {                                     \
    printf("wallet_boot_birthday: %s... ", (name));                    \
    if (expr) { printf("OK\n"); }                                      \
    else { printf("FAIL\n"); failures++; }                             \
} while (0)

#define WBB_BLOCK_INSERT                                                    \
    "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"    \
    "bits,nonce,solution,chain_work,status) VALUES(X'%s',%d,zeroblob(32),4,"\
    "zeroblob(32),0,0,zeroblob(32),zeroblob(1),zeroblob(32),3)"

struct wbb_fixture {
    char dir[1024];
    struct node_db ndb;
    struct wallet_sqlite ws;
    bool open;
};

static bool wbb_block(struct node_db *ndb, uint8_t fill, int height)
{
    char hex[65], sql[512];
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", fill);
    snprintf(sql, sizeof(sql), WBB_BLOCK_INSERT, hex, height);
    return sqlite3_exec(ndb->db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool wbb_open(struct wbb_fixture *f, const char *tag, int tip)
{
    memset(f, 0, sizeof(*f));
    test_fmt_tmpdir(f->dir, sizeof(f->dir), "wallet_boot_birthday", tag);
    mkdir("./test-tmp", 0700);
    test_rm_rf(f->dir);
    if (mkdir(f->dir, 0700) != 0)
        return false;
    char p[1200];
    snprintf(p, sizeof(p), "%s/node.db", f->dir);
    if (!node_db_open(&f->ndb, p) || !f->ndb.open)
        return false;
    f->open = true;
    if (tip > 0 && !(wbb_block(&f->ndb, 0x09, tip - 100) &&
                     wbb_block(&f->ndb, 0x0a, tip)))
        return false;
    return wallet_sqlite_open_r(&f->ws, f->ndb.db).ok;
}

static void wbb_close(struct wbb_fixture *f)
{
    if (f->open) {
        wallet_sqlite_close(&f->ws);
        node_db_close(&f->ndb);
    }
    test_rm_rf(f->dir);
}

/* An in-memory active chain of heights 0..n-1; the block at `special` hashes
 * to 0x09 repeated, every other to 0x01 repeated. */
struct wbb_chain {
    struct active_chain chain;
    struct block_index *idx;
    struct block_index **ptr;
};

static bool wbb_chain_make(struct wbb_chain *k, int n, int special,
                           uint8_t fill)
{
    active_chain_init(&k->chain);
    k->idx = calloc((size_t)n, sizeof(*k->idx));
    k->ptr = calloc((size_t)n, sizeof(*k->ptr));
    if (!k->idx || !k->ptr)
        return false;
    for (int i = 0; i < n; i++) {
        block_index_init(&k->idx[i]);
        k->idx[i].nHeight = i;
        memset(k->idx[i].hashBlock.data, i == special ? fill : 1, 32);
        k->idx[i].phashBlock = &k->idx[i].hashBlock;
        k->ptr[i] = &k->idx[i];
    }
    free(k->chain.chain);
    k->chain.chain = k->ptr;
    k->chain.height = n - 1;
    k->chain.capacity = n;
    return true;
}

static void wbb_chain_free(struct wbb_chain *k)
{
    k->chain.chain = NULL;
    k->chain.capacity = 0;
    k->chain.height = 0;
    active_chain_free(&k->chain);
    free(k->idx);
    free(k->ptr);
}

static bool wbb_deferred(const struct wallet *w)
{
    return w->scan_retry.pending &&
           strcmp(w->scan_retry.blocker, "WALLET_CATCH_UP_DEFERRED") == 0;
}

/* Boot's first catch-up for a wallet that has scanned nothing. */
static struct wallet *wbb_catch_up(struct node_db *ndb, struct wbb_chain *k)
{
    struct wallet *w = calloc(1, sizeof(*w));
    if (!w)
        return NULL;
    wallet_init(w);
    w->initial_scan_floor = -1;
    (void)boot_wallet_boot_catch_up(w, &k->chain, "/nonexistent", ndb);
    return w;
}

static void wbb_wallet_release(struct wallet *w)
{
    if (w) {
        wallet_free(w);
        free(w);
    }
}

static bool wbb_mint(struct wbb_fixture *f, struct wallet *w)
{
    wallet_init(w);
    return boot_wallet_create_new(w, &f->ws, &f->ndb,
                                  WALLET_BOOT_CREATE_PLAINTEXT,
                                  ZCL_OPERATOR_LANE_DEV, f->dir);
}

static int t_fresh_wallet_records_birthday(void)
{
    int failures = 0;
    struct wbb_fixture f;
    bool open = wbb_open(&f, "fresh", 1500);
    struct wallet *w = calloc(1, sizeof(*w));
    bool minted = open && w && wbb_mint(&f, w);
    int64_t b = 0;
    uint8_t hash[32], want[32];
    memset(want, 0x09, sizeof(want));
    WBB_CHECK("a fresh boot wallet is created", minted);
    WBB_CHECK("it records the connected tip as its birthday",
              minted && db_wallet_birthday_get(&f.ndb, &b, hash) && b == 1500);
    WBB_CHECK("the floor block is the one 100 below",
              minted && memcmp(hash, want, sizeof(want)) == 0);

    struct wbb_chain k;
    bool made = minted && wbb_chain_make(&k, 1502, 1400, 0x09);
    struct wallet *boot = made ? wbb_catch_up(&f.ndb, &k) : NULL;
    WBB_CHECK("the first catch-up starts at the floor",
              boot && boot->initial_scan_floor == 1400);
    WBB_CHECK("and is not deferred", boot && !wbb_deferred(boot));
    wbb_wallet_release(boot);
    if (made)
        wbb_chain_free(&k);
    if (w) {
        if (minted)
            wallet_free(w);
        free(w);
    }
    wbb_close(&f);
    return failures;
}

static int t_unknown_height_records_none(void)
{
    int failures = 0;
    struct wbb_fixture f;
    bool open = wbb_open(&f, "zero", 0);
    struct wallet *w = calloc(1, sizeof(*w));
    bool minted = open && w && wbb_mint(&f, w);
    int64_t b = 0;
    uint8_t hash[32];
    WBB_CHECK("a fresh wallet is created with no known height", minted);
    WBB_CHECK("no birthday is recorded",
              minted && !db_wallet_birthday_get(&f.ndb, &b, hash));
    struct wbb_chain k;
    bool made = minted && wbb_chain_make(&k, 1502, -1, 0);
    struct wallet *boot = made ? wbb_catch_up(&f.ndb, &k) : NULL;
    WBB_CHECK("its catch-up keeps today's behaviour: from 0, deferred",
              boot && boot->initial_scan_floor == 0 && wbb_deferred(boot));
    wbb_wallet_release(boot);
    if (made)
        wbb_chain_free(&k);
    if (w) {
        if (minted)
            wallet_free(w);
        free(w);
    }
    wbb_close(&f);
    return failures;
}

/* Restore the fixed phrase into the fixture datadir through the recovery
 * service (no birthday asked) and reopen the fixture on the result, with two
 * connected rows seeded. Returns the restore verdict in *restored. */
static bool wbb_restore_and_reopen(struct wbb_fixture *f, bool *restored)
{
    wallet_lock_reset_for_test();
    setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);
    struct wallet_recovery_request rq = {
        .phrase = "abandon abandon abandon abandon abandon abandon abandon "
                  "abandon abandon abandon abandon about",
        .datadir = f->dir,
    };
    struct wallet_recovery_report rep;
    /* The recovery writes through its own handle; close ours first. */
    if (f->open) {
        wallet_sqlite_close(&f->ws);
        node_db_close(&f->ndb);
        f->open = false;
    }
    struct zcl_result r = wallet_recovery_run(&rq, &rep);
    unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
    *restored = r.ok;
    char p[1200];
    snprintf(p, sizeof(p), "%s/node.db", f->dir);
    f->open = r.ok && node_db_open(&f->ndb, p) && f->ndb.open;
    return f->open && wbb_block(&f->ndb, 0x09, 1400) &&
           wbb_block(&f->ndb, 0x0a, 1500) &&
           wallet_sqlite_open_r(&f->ws, f->ndb.db).ok;
}

static int t_restored_wallet_keeps_full_scan(void)
{
    int failures = 0;
    struct wbb_fixture f;
    bool restored = false;
    (void)wbb_open(&f, "restored", 0);
    bool ws_ok = wbb_restore_and_reopen(&f, &restored);
    WBB_CHECK("a phrase restore succeeds", restored);
    WBB_CHECK("boot never mints over a restored wallet",
              ws_ok && !boot_wallet_may_mint(&f.ws, 0));
    int64_t b = 0;
    uint8_t hash[32];
    WBB_CHECK("a restored wallet has no birthday",
              ws_ok && !db_wallet_birthday_get(&f.ndb, &b, hash));
    struct wbb_chain k;
    bool made = ws_ok && wbb_chain_make(&k, 1502, 1400, 0x09);
    struct wallet *boot = made ? wbb_catch_up(&f.ndb, &k) : NULL;
    WBB_CHECK("its first catch-up still scans from 0 and defers",
              boot && boot->initial_scan_floor == 0 && wbb_deferred(boot));
    wbb_wallet_release(boot);
    if (made)
        wbb_chain_free(&k);
    wbb_close(&f);
    return failures;
}

static int t_wallet_with_keys_is_not_minted_over(void)
{
    int failures = 0;
    struct wbb_fixture f;
    bool open = wbb_open(&f, "keys", 1500);
    struct wallet *w = calloc(1, sizeof(*w));
    bool minted = open && w && wbb_mint(&f, w);
    int64_t b = 0;
    uint8_t hash[32];
    bool had = minted && db_wallet_birthday_get(&f.ndb, &b, hash);
    /* The next boot loads these keys: nothing is minted, so nothing is
     * recorded again. An imported single key is the same: keys held. */
    WBB_CHECK("a wallet that holds keys is never minted over",
              minted && !boot_wallet_may_mint(&f.ws, w->keystore.num_keys));
    WBB_CHECK("one imported key is held keys too",
              open && !boot_wallet_may_mint(&f.ws, 1));
    WBB_CHECK("the birthday it already has is untouched",
              had && b == 1500);
    if (w) {
        if (minted)
            wallet_free(w);
        free(w);
    }
    wbb_close(&f);
    return failures;
}

/* The real fresh node: the compiled checkpoint bundle is its only known
 * height. The birthday is the shipped anchor and the first catch-up starts
 * there, so a chain well past it is not deferred. */
static int t_anchor_is_the_known_height(void)
{
    int failures = 0;
    static struct sha3_utxo_checkpoint anchor;
    memset(&anchor, 0, sizeof(anchor));
    anchor.height = 5000;
    memset(anchor.block_hash, 0x0b, sizeof(anchor.block_hash));
    checkpoints_set_sha3_override_for_test(&anchor);

    struct wbb_fixture f;
    bool open = wbb_open(&f, "anchor", 0);
    struct wallet *w = calloc(1, sizeof(*w));
    bool minted = open && w && wbb_mint(&f, w);
    int64_t b = 0;
    uint8_t hash[32], want[32];
    memset(want, 0x0b, sizeof(want));
    WBB_CHECK("a fresh wallet on a node with only the anchor is created",
              minted);
    WBB_CHECK("its birthday is the anchor plus the margin, floor block the anchor",
              minted && db_wallet_birthday_get(&f.ndb, &b, hash) &&
              b == 5100 && memcmp(hash, want, sizeof(want)) == 0);
    struct wbb_chain k;
    bool made = minted && wbb_chain_make(&k, 5200, 5000, 0x0b);
    struct wallet *boot = made ? wbb_catch_up(&f.ndb, &k) : NULL;
    WBB_CHECK("the first catch-up starts at the anchor and is not deferred",
              boot && boot->initial_scan_floor == 5000 && !wbb_deferred(boot));
    wbb_wallet_release(boot);
    if (made)
        wbb_chain_free(&k);
    if (w) {
        if (minted)
            wallet_free(w);
        free(w);
    }
    wbb_close(&f);
    memset(&anchor, 0, sizeof(anchor));
    checkpoints_set_sha3_override_for_test(&anchor);
    return failures;
}

int test_wallet_boot_birthday(void);
int test_wallet_boot_birthday(void)
{
    printf("\n=== a fresh boot wallet records a birthday ===\n");
    int failures = 0;
    static const struct sha3_utxo_checkpoint no_anchor = { .height = 0 };
    chain_params_select(CHAIN_MAIN);
    checkpoints_set_sha3_override_for_test(&no_anchor);
    failures += t_fresh_wallet_records_birthday();
    failures += t_unknown_height_records_none();
    failures += t_restored_wallet_keeps_full_scan();
    failures += t_wallet_with_keys_is_not_minted_over();
    failures += t_anchor_is_the_known_height();
    checkpoints_reset_sha3_override_for_test();
    return failures;
}
