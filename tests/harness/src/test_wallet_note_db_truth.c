/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_wallet_note_db_truth -- the wallet database is the truth for shielded
 * notes; the in-memory note array holds only notes seen since the process
 * started. A restart is simulated by saving a note to node.db and leaving the
 * array empty. Each fixture is a private datadir that wallet recovery fills
 * from a fixed phrase; no live node, key or datadir is touched. */

#include "test/test_core.h"
#include "chain/chainparams.h"
#include "config/boot_wallet_phrase.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_helpers.h"
#include "json/json.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "rpc/server.h"
#include "sapling/sapling.h"
#include "sapling/zip32.h"
#include "services/store_buyer_internal.h"
#include "services/wallet_recovery_service.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "wallet/mnemonic.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WNT_UNIT ((int64_t)100000000)
#define WNT_NOTE_HEIGHT 100
#define WNT_TIP 200

struct wnt {
    char dir[256];
    struct node_db ndb;
    struct wallet_sqlite ws;
    struct wallet *w;
    struct rpc_table *tbl;
    bool db_open;
    bool ws_open;
};

static bool wnt_boot(struct wnt *f)
{
    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", f->dir);
    memset(&f->ndb, 0, sizeof(f->ndb));
    if (!node_db_open(&f->ndb, dbpath))
        return false;
    f->db_open = true;
    if (!wallet_sqlite_open_r(&f->ws, f->ndb.db).ok)
        return false;
    f->ws_open = true;
    f->w = zcl_calloc(1, sizeof(*f->w), "wnt_wallet");
    if (!f->w)
        return false;
    wallet_init(f->w);
    bool ok = wallet_sqlite_read_keys_r(&f->ws, f->w).ok;
    ok = wallet_sqlite_read_sapling_keys(&f->ws, f->w) && ok;
    rpc_wallet_set_state(f->w, NULL, f->dir, &f->ws, NULL, NULL);
    wallet_rpc_context_set_node_db(&f->ndb);
    return ok;
}

static void wnt_teardown(struct wnt *f)
{
    if (f->w) {
        wallet_free(f->w);
        free(f->w);
        f->w = NULL;
    }
    if (f->ws_open)
        wallet_sqlite_close(&f->ws);
    f->ws_open = false;
    wallet_rpc_context_set_node_db(NULL);
    if (f->db_open)
        node_db_close(&f->ndb);
    f->db_open = false;
    free(f->tbl);
    f->tbl = NULL;
    if (f->dir[0])
        (void)test_rm_rf_recursive(f->dir);
    f->dir[0] = '\0';
}

/* Restore a fixed phrase into a private datadir, boot it, and leave the
 * wallet READY at tip WNT_TIP with an empty note array: a fresh process. */
static bool wnt_restore(struct wnt *f)
{
    memset(f, 0, sizeof(*f));
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    int n = snprintf(f->dir, sizeof(f->dir), "%s/test-tmp/wnt_XXXXXX", cwd);
    if (n <= 0 || (size_t)n >= sizeof(f->dir) ||
        !test_mkdtemp(f->dir, sizeof(f->dir), "wnt"))
        return false;
    uint8_t entropy[16];
    memset(entropy, 0x2a, sizeof(entropy));
    char phrase[BOOT_WALLET_PHRASE_CAP];
    if (!mnemonic_from_entropy(entropy, sizeof(entropy), phrase,
                               sizeof(phrase)))
        return false;
    setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);
    struct wallet_recovery_request req = {
        .phrase = phrase, .datadir = f->dir, .dry_run = false };
    struct wallet_recovery_report rep;
    struct zcl_result r = wallet_recovery_run(&req, &rep);
    memory_cleanse(phrase, sizeof(phrase));
    unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
    if (!r.ok)
        return false;
    f->tbl = zcl_calloc(1, sizeof(*f->tbl), "wnt_rpc_table");
    if (!f->tbl)
        return false;
    rpc_table_init(f->tbl);
    register_wallet_rpc_commands(f->tbl);
    char status[32];
    if (rpc_is_in_warmup(status, sizeof(status)))
        set_rpc_warmup_finished();
    if (!wnt_boot(f))
        return false;
    f->w->best_block_height = WNT_TIP;
    return wallet_readiness_initialize(f->w, WALLET_READINESS_READY, false, 0);
}

/* A note the account key owns, as the database stores it. */
static bool wnt_note(struct wnt *f, uint8_t txid_byte, uint32_t index,
                     int64_t value, const char *memo, struct db_sapling_note *n)
{
    struct sapling_key_entry acct;
    memset(n, 0, sizeof(*n));
    if (!sapling_keystore_copy_receive_account(&f->w->sapling_keys, &acct))
        return false;
    memset(n->txid, txid_byte, sizeof(n->txid));
    n->output_index = index;
    n->value = value;
    n->rcm[0] = 5;
    memcpy(n->ivk, acct.ivk, sizeof(n->ivk));
    bool ok = zip32_xfvk_address(&acct.xfvk, n->diversifier, n->pk_d);
    memory_cleanse(&acct, sizeof(acct));
    memset(n->cm, txid_byte ^ 0x3c, sizeof(n->cm));
    memset(n->nullifier, txid_byte ^ 0xa5, sizeof(n->nullifier));
    n->block_height = WNT_NOTE_HEIGHT;
    snprintf((char *)n->memo, sizeof(n->memo), "%s", memo);
    n->memo_len = strlen(memo);
    snprintf(n->source, sizeof(n->source), "%s", DB_SAPLING_NOTE_SOURCE_LOCAL);
    return ok;
}

/* Save the note, with the transaction row the wallet keeps beside it. */
static bool wnt_save(struct wnt *f, const struct db_sapling_note *n)
{
    char sql[256], hex[65];
    for (int j = 0; j < 32; j++)
        snprintf(hex + j * 2, 3, "%02x", n->txid[j]);
    snprintf(sql, sizeof(sql),
             "INSERT INTO wallet_transactions(txid,raw_tx,time_received,"
             "from_me,fee) VALUES(x'%s',zeroblob(1),1,0,0);", hex);
    return sqlite3_exec(f->ndb.db, sql, NULL, NULL, NULL) == SQLITE_OK &&
           db_sapling_note_save(&f->ndb, n);
}

static bool wnt_address(const struct db_sapling_note *n, char *out,
                        size_t size)
{
    const struct chain_params *cp = chain_params_get();
    return sapling_encode_payment_address(
        n->diversifier, n->pk_d,
        cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], out, size);
}

static bool wnt_call(struct wnt *f, const char *method, const char *addr,
                     int minconf, struct json_value *result)
{
    struct json_value params = {0}, arg;
    json_init(&params);
    json_set_array(&params);
    if (addr) {
        json_init(&arg);
        json_set_str(&arg, addr);
        json_push_back(&params, &arg);
        json_free(&arg);
    }
    if (minconf >= 0) {
        json_init(&arg);
        json_set_int(&arg, minconf);
        json_push_back(&params, &arg);
        json_free(&arg);
    }
    json_init(result);
    bool ok = rpc_table_execute(f->tbl, method, &params, result);
    json_free(&params);
    return ok;
}

/* z_gettotalbalance "private" as text, or "" when it did not answer. */
static bool wnt_private_total(struct wnt *f, char *out, size_t size)
{
    struct json_value r;
    bool ok = wnt_call(f, "z_gettotalbalance", NULL, -1, &r);
    const struct json_value *v = ok ? json_get(&r, "private") : NULL;
    snprintf(out, size, "%s", v && json_get_str(v) ? json_get_str(v) : "");
    json_free(&r);
    return ok && v;
}

/* How many entries z_listreceivedbyaddress gives for `addr`, or -1 when it
 * refuses. */
static int wnt_listed(struct wnt *f, const char *addr, int minconf)
{
    struct json_value r;
    bool ok = wnt_call(f, "z_listreceivedbyaddress", addr, minconf, &r);
    int count = -1;
    if (ok && r.type == JSON_ARR)
        count = (int)json_size(&r);
    json_free(&r);
    return count;
}

/* A note in the database and not in the session array: z_listreceivedbyaddress
 * answers with the amount z_gettotalbalance reports, the confirmations, the
 * spent flag and the memo; a foreign address and a deeper minconf list nothing. */
static int wnt_list_from_database(void)
{
    struct wnt f = {0};
    int failures = 0;
    TEST("z_listreceivedbyaddress lists a database note missing from memory") {
        ASSERT(wnt_restore(&f));
        struct db_sapling_note note, spent;
        ASSERT(wnt_note(&f, 0x41, 3, 7 * WNT_UNIT, "hello", &note));
        ASSERT(wnt_save(&f, &note));
        ASSERT(wnt_note(&f, 0x42, 0, 2 * WNT_UNIT, "", &spent));
        ASSERT(wnt_save(&f, &spent));
        uint8_t by[32];
        memset(by, 0x77, sizeof(by));
        ASSERT_EQ(db_sapling_note_mark_spent(&f.ndb, spent.nullifier, by),
                  DB_MARK_SPENT_OK);
        ASSERT_EQ((int)f.w->num_sapling_notes, 0);

        char total[32], addr[128];
        ASSERT(wnt_private_total(&f, total, sizeof(total)));
        ASSERT_STR_EQ(total, "7.00000000");
        ASSERT(wnt_address(&note, addr, sizeof(addr)));

        ASSERT_EQ(wnt_listed(&f, addr, -1), 2);
        ASSERT_EQ(wnt_listed(&f, addr, 102), 0);
        ASSERT_EQ(wnt_listed(&f, addr, 101), 2);

        /* Both notes share the account address; read each by txid. */
        struct json_value r;
        ASSERT(wnt_call(&f, "z_listreceivedbyaddress", addr, 1, &r));
        double listed = 0;
        bool saw_memo = false, saw_spent = false;
        for (size_t i = 0; i < json_size(&r); i++) {
            const struct json_value *x = json_at(&r, i);
            const struct json_value *m = json_get(x, "memo");
            ASSERT(json_get(x, "txid") && json_get(x, "outindex"));
            ASSERT_EQ((int)json_get_int(json_get(x, "confirmations")),
                      WNT_TIP - WNT_NOTE_HEIGHT + 1);
            ASSERT(!json_get_bool(json_get(x, "change")));
            if (json_get_bool(json_get(x, "spent")))
                saw_spent = true;
            else
                listed += json_get_real(json_get(x, "amount"));
            if (m && json_get_str(m) && strcmp(json_get_str(m), "hello") == 0)
                saw_memo = true;
        }
        json_free(&r);
        ASSERT(saw_memo && saw_spent);
        printf("(unspent listed=%.8f total=%s) ", listed, total);
        ASSERT(listed > 6.99999999 && listed < 7.00000001);

        /* An address the wallet never received on lists nothing. */
        uint8_t fpk[32];
        memset(fpk, 0x66, sizeof(fpk));
        char foreign[128];
        struct db_sapling_note other = note;
        memcpy(other.pk_d, fpk, 32);
        ASSERT(wnt_address(&other, foreign, sizeof(foreign)));
        ASSERT_EQ(wnt_listed(&f, foreign, -1), 0);
        PASS();
    } _test_next:;
    wnt_teardown(&f);
    return failures;
}

/* The store buyer's shielded funding floor reads the same database total. */
static int wnt_store_floor(void)
{
    struct wnt f = {0};
    int failures = 0;
    TEST("store buyer funding floor sees a database note missing from memory") {
        ASSERT(wnt_restore(&f));
        struct db_sapling_note note;
        ASSERT(wnt_note(&f, 0x51, 1, 9 * WNT_UNIT, "", &note));
        ASSERT(wnt_save(&f, &note));
        ASSERT_EQ((int)f.w->num_sapling_notes, 0);
        char zaddr[128];
        ASSERT(wnt_address(&note, zaddr, sizeof(zaddr)));

        int64_t pool = 0;
        struct zcl_result r = sb_pay_pool_balance(f.dir, zaddr, f.w, &pool);
        printf("(pool=%lld) ", (long long)pool);
        ASSERT(r.ok);
        ASSERT_EQ(pool, 9 * WNT_UNIT);

        /* A database that cannot be opened is an error, not a smaller pool. */
        pool = 0;
        r = sb_pay_pool_balance("/nonexistent/wnt-no-such-datadir", zaddr,
                                f.w, &pool);
        ASSERT(!r.ok);
        PASS();
    } _test_next:;
    wnt_teardown(&f);
    return failures;
}

int test_wallet_note_db_truth(void)
{
    int failures = wnt_list_from_database();
    failures += wnt_store_floor();
    return failures;
}
