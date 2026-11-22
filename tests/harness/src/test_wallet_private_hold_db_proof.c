/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: A pending private send is proven held by the database reservation
 * alone: after a restart the in-memory note cache is empty, and the hold proof
 * must still pass when the database names this send, and still refuse when it
 * names another send, names none, or a cached copy contradicts it. */
#include "test/test_core.h"
#include "controllers/wallet_private_broadcast.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/wallet_private_relay.h"
#include "util/safe_alloc.h"
#include "util/sync.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define WHP_NF 0x79

struct whp_fx {
    struct wallet *wallet;
    struct node_db ndb;
    struct wallet_sqlite wsql;
    struct wallet_tx tx;
    struct wpr_pending_guard guard;
    char dir[256];
    bool db_open, wsql_open, tx_built, guarded;
};

static void whp_report(const char *name, bool ok, int *failures)
{
    printf("wallet_private_hold_db_proof: %s... %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) (*failures)++;
}

static bool whp_build_tx(struct whp_fx *f)
{
    memset(&f->tx, 0, sizeof(f->tx));
    struct transaction *tx = &f->tx.tx;
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    f->tx_built = true;
    tx->version = SAPLING_TX_VERSION;
    tx->overwintered = true;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    memset(tx->vin[0].prevout.hash.data, 0x31, 32);
    tx->vin[0].sequence = 0xFFFFFFFF;
    uint8_t one[] = {0x51};
    script_set(&tx->vout[0].script_pub_key, one, 1);
    tx->vout[0].value = 1000;
    tx->v_shielded_spend = zcl_calloc(1, sizeof(*tx->v_shielded_spend), "whp_spend");
    if (!tx->v_shielded_spend) return false;
    tx->num_shielded_spend = 1;
    memset(tx->v_shielded_spend[0].nullifier.data, WHP_NF, 32);
    transaction_compute_hash(tx);
    return true;
}

static bool whp_save_note(struct node_db *ndb)
{
    struct db_sapling_note n;
    memset(&n, 0, sizeof(n));
    memset(n.txid, 0xAA, 32);
    memset(n.ivk, 0xBB, 32);
    memset(n.nullifier, WHP_NF, 32);
    memset(n.diversifier, 0xDD, 11);
    memset(n.pk_d, 0xEE, 32);
    memset(n.cm, 0xFF, 32);
    memset(n.rcm, 0x11, 32);
    n.value = 200000;
    n.block_height = 5;
    return db_sapling_note_save(ndb, &n);
}

/* A restarted node: the wallet holds the send, the database holds the note,
 * and the in-memory note cache is empty. */
static bool whp_open(struct whp_fx *f, bool with_note)
{
    memset(f, 0, sizeof(*f));
    f->wallet = zcl_calloc(1, sizeof(*f->wallet), "whp_wallet");
    if (!f->wallet || !test_mkdtemp(f->dir, sizeof(f->dir), "whp")) return false;
    wallet_init(f->wallet);
    wallet_lock_reset_for_test();
    wallet_lock_note_encrypted_at_rest();
    if (!node_db_open(&f->ndb, ":memory:")) return false;
    f->db_open = true;
    if (!wallet_sqlite_open_r(&f->wsql, f->ndb.db).ok) return false;
    f->wsql_open = true;
    if (!wallet_lock_unlock(NULL, NULL, "wallet-private-hold").ok) return false;
    if (!wallet_readiness_initialize(f->wallet, WALLET_READINESS_PENDING, true, 42)) return false;
    struct wpr *r = wpr_global();
    wpr_free(r);
    wpr_init(r);
    struct wpr_env env = { .wallet = f->wallet, .node_db = &f->ndb, .datadir = f->dir };
    wpr_configure(r, WPR_MODE_PRIVATE, &env);
    if (!whp_build_tx(f) || !wallet_add_to_wallet(f->wallet, &f->tx)) return false;
    if (with_note && !whp_save_note(&f->ndb)) return false;
    return wallet_sqlite_flush_transactions_r(&f->wsql, f->wallet).ok &&
           wpr_prepare(r, &f->tx.tx.hash).ok;
}

static bool whp_begin(struct whp_fx *f)
{
    struct wpr_pending_record rows[WPR_MAX_ENTRIES];
    size_t count = 0;
    if (!f->guarded) {
        if (wpr_pending_proof_begin(wpr_global(), &f->guard, rows, WPR_MAX_ENTRIES, &count) !=
                WPR_PENDING_OK || count != 1) return false;
        f->guarded = true;
    }
    return sqlite3_exec(f->ndb.db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
}

static void whp_rollback(struct whp_fx *f)
{
    if (!sqlite3_get_autocommit(f->ndb.db))
        (void)sqlite3_exec(f->ndb.db, "ROLLBACK", NULL, NULL, NULL);
}

static enum wallet_hold_proof_result whp_reserve(struct whp_fx *f)
{
    return whp_begin(f) ? wallet_private_broadcast_reserve_in_open_tx(&f->guard, &f->ndb, f->wallet)
                        : WALLET_HOLD_PROOF_ERROR;
}

static int whp_reserved_count(struct whp_fx *f)
{
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(f->ndb.db,
            "SELECT count(*) FROM wallet_sapling_notes WHERE spent_txid=?1",
            -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, f->tx.tx.hash.data, 32, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static bool whp_validate(struct whp_fx *f)
{
    zcl_mutex_lock(&f->wallet->cs);
    bool ok = wallet_private_broadcast_validate_holds_locked(&f->guard, f->wallet, f->ndb.db);
    zcl_mutex_unlock(&f->wallet->cs);
    return ok;
}

static void whp_close(struct whp_fx *f)
{
    if (f->guarded) wpr_pending_proof_end(&f->guard);
    if (f->db_open) whp_rollback(f);
    if (f->wsql_open) wallet_sqlite_close(&f->wsql);
    if (f->db_open) node_db_close(&f->ndb);
    wpr_free(wpr_global());
    wpr_init(wpr_global());
    if (f->tx_built) transaction_free(&f->tx.tx);
    if (f->wallet) { wallet_free(f->wallet); free(f->wallet); }
    if (f->dir[0]) test_rm_rf(f->dir);
}

static int whp_case_db_only(void)
{
    int failures = 0;
    struct whp_fx f;
    bool ok = whp_open(&f, true);
    bool first = ok && whp_reserve(&f) == WALLET_HOLD_PROOF_OK;
    bool valid = first && whp_validate(&f);
    int held = first ? whp_reserved_count(&f) : -1;
    whp_rollback(&f);
    /* the second boot: the rollback undid the reservation; it is made again */
    bool again = ok && whp_reserve(&f) == WALLET_HOLD_PROOF_OK;
    int held_again = again ? whp_reserved_count(&f) : -1;
    whp_report("a note known only to the database proves the hold",
               ok && first && f.wallet->num_sapling_notes == 0, &failures);
    whp_report("the final hold validation accepts it and the note is reserved once",
               valid && held == 1, &failures);
    whp_report("a second run reserves it once more, idempotently",
               again && held_again == 1, &failures);
    whp_close(&f);
    return failures;
}

static int whp_case_refused(void)
{
    int failures = 0;
    struct whp_fx f;
    bool ok = whp_open(&f, true) &&
        sqlite3_exec(f.ndb.db, "UPDATE wallet_sapling_notes SET spent_txid=zeroblob(32)",
                     NULL, NULL, NULL) == SQLITE_OK;
    bool conflict = ok && whp_reserve(&f) == WALLET_HOLD_PROOF_CONFLICT;
    whp_rollback(&f);
    whp_report("a note reserved by a different send is a conflict", conflict, &failures);
    whp_close(&f);
    ok = whp_open(&f, false);
    conflict = ok && whp_reserve(&f) == WALLET_HOLD_PROOF_CONFLICT;
    whp_report("a nullifier absent from the database is a conflict", conflict, &failures);
    whp_close(&f);
    return failures;
}

static int whp_case_cache_refutes(void)
{
    int failures = 0;
    struct whp_fx f;
    bool ok = whp_open(&f, true) && whp_reserve(&f) == WALLET_HOLD_PROOF_OK && whp_validate(&f);
    struct wallet *w = f.wallet;
    w->sapling_notes = ok ? zcl_calloc(1, sizeof(*w->sapling_notes), "whp_note") : NULL;
    if (w->sapling_notes) {
        w->num_sapling_notes = w->sapling_notes_cap = 1;
        w->sapling_notes[0].used = true;
        memset(w->sapling_notes[0].nf, WHP_NF, 32);
    }
    bool refuted = w->sapling_notes && !whp_validate(&f);
    if (w->sapling_notes) w->sapling_notes[0].spent = true;
    bool accepted = w->sapling_notes && whp_validate(&f);
    whp_report("a cached copy that is not spent contradicts the hold",
               refuted, &failures);
    whp_report("a cached copy that is spent agrees with it", accepted, &failures);
    whp_close(&f);
    return failures;
}

int test_wallet_private_hold_db_proof(void);
int test_wallet_private_hold_db_proof(void)
{
    int failures = 0;
    failures += whp_case_db_only();
    failures += whp_case_refused();
    failures += whp_case_cache_refutes();
    return failures;
}
