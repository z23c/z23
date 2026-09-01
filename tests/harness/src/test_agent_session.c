/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Agent session model tests (docs/work/agent-spend-policy-design.md,
 * "Model (migration v36)" lane). Proves:
 *  1. The v36 migration applies on node_db open (schema_migrations row +
 *     agent_sessions table present).
 *  2. save/find round-trip; upsert overwrites in place.
 *  3. list_for_account returns only that account's sessions.
 *  4. revoke persists across a db close/reopen.
 *  5. The CHECK constraint rejects a negative max_per_tx_zat at the SQL
 *     layer (constraint failure, no crash) and model validation rejects it
 *     before the SQL layer is ever reached.
 *  6. authorize accumulates within a window, rolls (reset anchor + zero
 *     spent) once window_seconds have elapsed, enforces both caps, and writes
 *     NOTHING when commit=false — so a plan-stage preview cannot burn budget.
 *  7. A debit can never un-revoke a grant (the targeted UPDATE is guarded by
 *     revoked=0), and a revoked grant's accounting is frozen.
 *  8. release credits back only inside the window the debit came from, clamps
 *     at zero, and is a no-op after the window rolls.
 *  9. window_seconds is bounded at every layer, and the largest accepted
 *     value still enforces the per-window cap (no overflowed comparison).
 * 10. The allowlist matches whole tokens only, and is enforced inside the same
 *     locked step as the caps.
 * 11. is_usable matrix: usable / revoked / expired / missing. */

#include "test/test_core.h"

#include "models/database.h"
#include "models/agent_session.h"
#include "models/principal.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static const char *const k_account = "t1AgentSessionTestAccount0000000000000";
static const char *const k_account_b = "t1AgentSessionTestAccountB000000000000";
static const char *const k_sid_a = "0123456789abcdef0123456789abcdef";
static const char *const k_sid_b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char *const k_sid_c = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const struct wallet_identity_row k_wallet = {
    .wallet_instance_id = "11111111111111111111111111111111",
    .network_genesis = { 0x42 },
    .operator_lane = "canonical",
    .created_at = 1,
};

/* Keep the pre-v52 accounting tests readable while driving the new binding
 * arguments on every authorization. */
#define agent_session_authorize(ndb_, sid_, amount_, recipient_, now_,       \
                                commit_, remaining_)                         \
    agent_session_authorize((ndb_), (sid_), (amount_), (recipient_), "prod", \
                            &k_wallet, (now_), (commit_), (remaining_))

/* node.db runs PRAGMA foreign_keys=ON, and agent_sessions.account REFERENCES
 * principals(address) — seed the principal rows first. */
static void seed_principal(struct node_db *ndb, const char *address)
{
    struct db_principal p;
    memset(&p, 0, sizeof(p));
    snprintf(p.address, sizeof(p.address), "%s", address);
    snprintf(p.pubkey_hex, sizeof(p.pubkey_hex), "02%064x", 0xabcdU);
    p.key_kind = PRINCIPAL_KEY_SECP256K1;
    p.role = PRINCIPAL_ROLE_OPERATOR;
    p.status = PRINCIPAL_STATUS_ACTIVE;
    p.sybil_proof_height = -1;
    (void)db_principal_save(ndb, &p);
}

static void mk_session(struct db_agent_session *s, const char *sid,
                       const char *account)
{
    memset(s, 0, sizeof(*s));
    snprintf(s->session_id, sizeof(s->session_id), "%s", sid);
    snprintf(s->account, sizeof(s->account), "%s", account);
    s->max_per_tx_zat = 1000000;        /* 0.01 ZCL */
    s->max_per_window_zat = 5000000;    /* 0.05 ZCL */
    s->reserve_floor_zat = AGENT_SESSION_DEV_RESERVE_DEFAULT_ZAT;
    s->window_seconds = 100;
    s->window_start_epoch = 1000;
    s->spent_in_window_zat = 0;
    s->created_at = 1000;
    s->expires_at = 0;                  /* never */
    s->revoked = 0;
    snprintf(s->wallet_scope, sizeof(s->wallet_scope), "prod");
    snprintf(s->wallet_instance_id, sizeof(s->wallet_instance_id), "%s",
             k_wallet.wallet_instance_id);
    wallet_identity_genesis_hex(&k_wallet, s->wallet_genesis);
}

static int open_db(struct node_db *ndb, char *dir, size_t dir_n,
                   char *dbpath, size_t dbpath_n, const char *tag)
{
    test_make_tmpdir(dir, dir_n, "agent_session", tag);
    snprintf(dbpath, dbpath_n, "%s/node.db", dir);
    memset(ndb, 0, sizeof(*ndb));
    if (!node_db_open(ndb, dbpath)) {
        printf("agent_session: node_db_open... FAIL\n");
        test_rm_rf(dir);
        return 0;
    }
    seed_principal(ndb, k_account);
    seed_principal(ndb, k_account_b);
    return 1;
}

static int test_migration_applies(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("v36 migration applies on node_db open") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "mig"));
        sqlite3_stmt *s = NULL;
        int found = 0;
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "SELECT COUNT(*) FROM schema_migrations WHERE version='036'",
            -1, &s, NULL) == SQLITE_OK);
        if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
            found = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        ASSERT_EQ(found, 1);
        s = NULL;
        found = 0;
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
            "AND name='agent_sessions'", -1, &s, NULL) == SQLITE_OK);
        if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
            found = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
        ASSERT_EQ(found, 1);
        ASSERT_EQ(agent_session_count(&ndb), 0);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_save_find_roundtrip(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("save/find round-trip; upsert overwrites in place") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "rt"));
        struct db_agent_session s;
        mk_session(&s, k_sid_a, k_account);
        snprintf(s.recipient_allowlist, sizeof(s.recipient_allowlist),
                 "t1aaa,zs1bbb");
        ASSERT(agent_session_save(&ndb, &s));

        struct db_agent_session got;
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_STR_EQ(got.session_id, k_sid_a);
        ASSERT_STR_EQ(got.account, k_account);
        ASSERT_EQ(got.max_per_tx_zat, 1000000);
        ASSERT_EQ(got.max_per_window_zat, 5000000);
        ASSERT_EQ(got.reserve_floor_zat,
                  AGENT_SESSION_DEV_RESERVE_DEFAULT_ZAT);
        ASSERT_EQ(got.window_seconds, 100);
        ASSERT_EQ(got.window_start_epoch, 1000);
        ASSERT_EQ(got.spent_in_window_zat, 0);
        ASSERT_STR_EQ(got.recipient_allowlist, "t1aaa,zs1bbb");
        ASSERT_EQ(got.expires_at, 0);
        ASSERT_EQ(got.revoked, 0);

        /* Upsert: same session_id, changed cap — still one row. */
        s.max_per_tx_zat = 2000000;
        ASSERT(agent_session_save(&ndb, &s));
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.max_per_tx_zat, 2000000);
        ASSERT_EQ(agent_session_count(&ndb), 1);

        /* Missing session id does not find. */
        ASSERT(!agent_session_find(&ndb, "ffffffffffffffffffffffffffffffff",
                                   &got));
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_list_for_account(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("list_for_account returns only that account's sessions") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "list"));
        struct db_agent_session s;
        mk_session(&s, k_sid_a, k_account);
        ASSERT(agent_session_save(&ndb, &s));
        mk_session(&s, k_sid_b, k_account);
        s.wallet_scope[0] = '\0';
        s.wallet_instance_id[0] = '\0';
        s.wallet_genesis[0] = '\0';
        ASSERT(agent_session_save(&ndb, &s));
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_b, 1, NULL, 1050,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_WALLET_UNBOUND);
        mk_session(&s, k_sid_b, k_account);
        ASSERT(agent_session_save(&ndb, &s));
        mk_session(&s, k_sid_c, k_account_b);
        ASSERT(agent_session_save(&ndb, &s));

        struct db_agent_session rows[8];
        int n = agent_session_list_for_account(&ndb, k_account, rows, 8);
        ASSERT_EQ(n, 2);
        ASSERT_STR_EQ(rows[0].account, k_account);
        ASSERT_STR_EQ(rows[1].account, k_account);
        n = agent_session_list_for_account(&ndb, k_account_b, rows, 8);
        ASSERT_EQ(n, 1);
        ASSERT_STR_EQ(rows[0].session_id, k_sid_c);
        n = agent_session_list_for_account(&ndb, k_account, rows, 1);
        ASSERT_EQ(n, 1); /* LIMIT respected */
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_revoke_persists(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("revoke persists across close/reopen; idempotent") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "rev"));
        struct db_agent_session s;
        mk_session(&s, k_sid_a, k_account);
        ASSERT(agent_session_save(&ndb, &s));
        ASSERT(agent_session_revoke(&ndb, k_sid_a));
        ASSERT(agent_session_revoke(&ndb, k_sid_a)); /* idempotent */
        ASSERT(!agent_session_revoke(&ndb, "ffffffffffffffffffffffffffffffff"));
        node_db_close(&ndb);

        memset(&ndb, 0, sizeof(ndb));
        ASSERT(node_db_open(&ndb, dbpath));
        struct db_agent_session got;
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.revoked, 1);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_check_rejects_negative(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("CHECK rejects negative max_per_tx_zat (SQL layer + validation)") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "chk"));
        /* Model validation rejects it before SQL. */
        struct db_agent_session s;
        mk_session(&s, k_sid_a, k_account);
        s.max_per_tx_zat = -1;
        ASSERT(!agent_session_save(&ndb, &s));
        ASSERT_EQ(agent_session_count(&ndb), 0);
        /* Over the 21M-ZCL cap is likewise rejected. */
        mk_session(&s, k_sid_a, k_account);
        s.max_per_tx_zat = AGENT_SESSION_MAX_ZAT + 1;
        ASSERT(!agent_session_save(&ndb, &s));
        ASSERT_EQ(agent_session_count(&ndb), 0);

        /* And the SQL CHECK itself holds (raw insert bypassing the model):
         * constraint failure, no crash. */
        sqlite3_stmt *st = NULL;
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "INSERT INTO agent_sessions "
            "(session_id,account,max_per_tx_zat,max_per_window_zat,"
            "window_seconds,window_start_epoch,created_at,expires_at) "
            "VALUES (?1,?2,-5,100,10,0,0,0)", -1, &st, NULL) == SQLITE_OK);
        sqlite3_bind_text(st, 1, k_sid_a, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, k_account, -1, SQLITE_STATIC);
        int rc = sqlite3_step(st);  // raw-sql-ok:test-check-constraint-probe
        sqlite3_finalize(st);
        ASSERT(rc == SQLITE_CONSTRAINT);
        ASSERT_EQ(agent_session_count(&ndb), 0);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_authorize_window(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("authorize accumulates in-window, rolls after window_seconds, and "
        "evaluates without writing when commit=false") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "win"));
        struct db_agent_session s;
        mk_session(&s, k_sid_a, k_account);
        ASSERT(agent_session_save(&ndb, &s));
        /* window_start=1000, window_seconds=100 → window covers [1000,1100) */

        struct db_agent_session got;
        int64_t remaining = -1;

        /* commit=false must leave the row untouched: a plan-stage preview may
         * enforce the caps but may never spend the window. */
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 500, NULL, 1050,
                                               false, &remaining),
                  (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT_EQ(remaining, 5000000 - 500);
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 0);

        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 500, NULL, 1050,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 500);
        ASSERT_EQ(got.window_start_epoch, 1000);

        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 300, NULL, 1099,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 800);
        ASSERT_EQ(got.window_start_epoch, 1000);

        /* At 1100 the window has elapsed: anchor resets, spent restarts. */
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 200, NULL, 1100,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 200);
        ASSERT_EQ(got.window_start_epoch, 1100);

        /* Caps: per-tx and per-window each refuse with their own verdict, and
         * a refusal writes nothing. */
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 1000001, NULL,
                                               1100, true, NULL),
                  (int)AGENT_SESSION_AUTHZ_TX_LIMIT);
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 200);
        /* window cap 5000000, already 200 spent: five more 1000000 spends fit
         * (5000200 > 5000000 on the fifth). */
        for (int i = 0; i < 4; i++)
            ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 1000000,
                                                   NULL, 1100, true, NULL),
                      (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 1000000, NULL,
                                               1100, true, NULL),
                  (int)AGENT_SESSION_AUTHZ_WINDOW_LIMIT);
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 4000200);

        /* Unknown session / bad amount refuse without writing. */
        ASSERT_EQ((int)agent_session_authorize(&ndb,
                      "ffffffffffffffffffffffffffffffff", 100, NULL, 1200,
                      true, NULL),
                  (int)AGENT_SESSION_AUTHZ_INVALID);
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, -1, NULL, 1200,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_STORE);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* The debit must not be able to resurrect a revoked grant. Before the targeted
 * UPDATE, the spend path loaded the whole row and rewrote every column, so a
 * revocation landing between that read and that write was overwritten with
 * revoked=0 — the operator's emergency lever lost to a routine spend. */
static int test_debit_never_unrevokes(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("a revoked grant refuses authorize and stays revoked; release cannot "
        "un-revoke it either") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "rev"));
        struct db_agent_session s;
        mk_session(&s, k_sid_a, k_account);
        ASSERT(agent_session_save(&ndb, &s));
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 500, NULL, 1050,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT(agent_session_revoke(&ndb, k_sid_a));

        struct db_agent_session got;
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ((int64_t)got.revoked, (int64_t)1);

        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 100, NULL, 1060,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_INVALID);
        (void)agent_session_release(&ndb, k_sid_a, 500, 1060);
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ((int64_t)got.revoked, (int64_t)1);
        /* Guarded by revoked=0, so the window was not credited back either —
         * the accounting of a revoked grant is frozen, which is what makes a
         * revocation auditable rather than an edit of history. */
        ASSERT_EQ(got.spent_in_window_zat, 500);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* A release credits the window back only inside the window the debit was
 * taken from, and never below zero. */
static int test_release_bounds(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("release credits back in-window, clamps at zero, and is a no-op once "
        "the window has rolled") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "rel"));
        struct db_agent_session s;
        mk_session(&s, k_sid_a, k_account);
        ASSERT(agent_session_save(&ndb, &s));
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 900, NULL, 1010,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_OK);
        struct db_agent_session got;

        ASSERT(agent_session_release(&ndb, k_sid_a, 400, 1020));
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 500);

        /* Over-release clamps at zero rather than manufacturing headroom. */
        ASSERT(agent_session_release(&ndb, k_sid_a, 999999, 1030));
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 0);

        /* Spend again, then release AFTER the window rolled: the debit belongs
         * to a window that no longer exists, so nothing is credited. */
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 700, NULL, 1040,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 600, NULL, 2000,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 600);
        ASSERT(agent_session_release(&ndb, k_sid_a, 700, 9000));
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 600);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* An unbounded window_seconds used to overflow `window_start + window_seconds`
 * so every roll check read "already elapsed" and the per-window cap silently
 * stopped existing. Three layers now refuse it; this pins the SQL one (the
 * last line of defence) and the arithmetic one. */
static int test_window_seconds_bounded(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("window_seconds is bounded, and the largest accepted value still "
        "enforces the per-window cap") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "wsec"));
        struct db_agent_session s;

        /* Model validation refuses an over-bound window. */
        mk_session(&s, k_sid_a, k_account);
        s.window_seconds = AGENT_SESSION_WINDOW_SECONDS_MAX + 1;
        ASSERT(!agent_session_save(&ndb, &s));
        ASSERT_EQ(agent_session_count(&ndb), 0);

        /* And so does the table CHECK, reached directly. */
        sqlite3_stmt *st = NULL;
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "INSERT INTO agent_sessions "
            "(session_id,account,max_per_tx_zat,max_per_window_zat,"
            "window_seconds,window_start_epoch,created_at,expires_at) "
            "VALUES (?1,?2,100,100,9223372036854775807,0,0,0)", -1, &st,
            NULL) == SQLITE_OK);
        sqlite3_bind_text(st, 1, k_sid_a, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, k_account, -1, SQLITE_STATIC);
        int rc = sqlite3_step(st);  // raw-sql-ok:test-check-constraint-probe
        sqlite3_finalize(st);
        ASSERT(rc == SQLITE_CONSTRAINT);

        /* The largest ACCEPTED window, anchored at 0, with `now` far in the
         * future: the roll must not fire, so the cap still binds. A summed
         * comparison would have overflowed to negative and let this through. */
        mk_session(&s, k_sid_a, k_account);
        s.window_seconds = AGENT_SESSION_WINDOW_SECONDS_MAX;
        s.window_start_epoch = 0;
        s.max_per_window_zat = 1000;
        s.max_per_tx_zat = 1000;
        ASSERT(agent_session_save(&ndb, &s));
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 1000, NULL,
                                               1000000, true, NULL),
                  (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 1, NULL,
                                               2000000, true, NULL),
                  (int)AGENT_SESSION_AUTHZ_WINDOW_LIMIT);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* The allowlist is exact-token, never substring: a prefix of a listed address
 * is a different address, and paying it would be paying the wrong person. */
static int test_allowlist_exact_token(void)
{
    int failures = 0;
    TEST("allowlist matches whole comma-separated tokens only") {
        ASSERT(agent_session_allowlisted("t1aaa,t1bbb,t1ccc", "t1bbb"));
        ASSERT(agent_session_allowlisted("t1aaa", "t1aaa"));
        ASSERT(!agent_session_allowlisted("t1aaa,t1bbb", "t1a"));
        ASSERT(!agent_session_allowlisted("t1aaaXX", "t1aaa"));
        ASSERT(!agent_session_allowlisted("t1aaa,t1bbb", "t1bbbb"));
        ASSERT(!agent_session_allowlisted("", "t1aaa"));
        ASSERT(!agent_session_allowlisted("t1aaa", NULL));
        ASSERT(!agent_session_allowlisted(NULL, "t1aaa"));
        PASS();
    } _test_next:;
    return failures;
}

/* Recipient enforcement lives in the model now (one place, inside the same
 * locked step as the cap check). */
static int test_authorize_recipient(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("authorize enforces a non-empty allowlist and refuses a missing "
        "recipient outright") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "rcpt"));
        struct db_agent_session s;
        mk_session(&s, k_sid_a, k_account);
        snprintf(s.recipient_allowlist, sizeof(s.recipient_allowlist),
                 "t1Allowed,t1AlsoAllowed");
        ASSERT(agent_session_save(&ndb, &s));

        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 100, "t1Allowed",
                                               1010, true, NULL),
                  (int)AGENT_SESSION_AUTHZ_OK);
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 100, "t1Other",
                                               1010, true, NULL),
                  (int)AGENT_SESSION_AUTHZ_RECIPIENT);
        /* No recipient at all is a refusal, not a pass: an allowlist that can
         * be skipped by omitting the field is not an allowlist. */
        ASSERT_EQ((int)agent_session_authorize(&ndb, k_sid_a, 100, NULL, 1010,
                                               true, NULL),
                  (int)AGENT_SESSION_AUTHZ_RECIPIENT);
        struct db_agent_session got;
        ASSERT(agent_session_find(&ndb, k_sid_a, &got));
        ASSERT_EQ(got.spent_in_window_zat, 100);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_is_usable_matrix(void)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], dbpath[320];
    TEST("is_usable: ok / revoked / expired / missing / never-expires") {
        ASSERT(open_db(&ndb, dir, sizeof(dir), dbpath, sizeof(dbpath), "use"));
        struct db_agent_session s;

        /* ok: expires_at=0 never expires. */
        mk_session(&s, k_sid_a, k_account);
        ASSERT(agent_session_save(&ndb, &s));
        ASSERT(agent_session_is_usable(&ndb, k_sid_a, 999999999));

        /* revoked. */
        mk_session(&s, k_sid_b, k_account);
        s.revoked = 1;
        ASSERT(agent_session_save(&ndb, &s));
        ASSERT(!agent_session_is_usable(&ndb, k_sid_b, 1000));

        /* expired at expiry boundary; usable just before. */
        mk_session(&s, k_sid_c, k_account);
        s.expires_at = 2000;
        ASSERT(agent_session_save(&ndb, &s));
        ASSERT(agent_session_is_usable(&ndb, k_sid_c, 1999));
        ASSERT(!agent_session_is_usable(&ndb, k_sid_c, 2000));
        ASSERT(!agent_session_is_usable(&ndb, k_sid_c, 3000));

        /* missing. */
        ASSERT(!agent_session_is_usable(&ndb,
            "ffffffffffffffffffffffffffffffff", 1000));
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

int test_agent_session(void)
{
    int failures = 0;
    failures += test_migration_applies();
    failures += test_save_find_roundtrip();
    failures += test_list_for_account();
    failures += test_revoke_persists();
    failures += test_check_rejects_negative();
    failures += test_authorize_window();
    failures += test_debit_never_unrevokes();
    failures += test_release_bounds();
    failures += test_window_seconds_bounded();
    failures += test_allowlist_exact_token();
    failures += test_authorize_recipient();
    failures += test_is_usable_matrix();
    printf("=== agent_session: %d failures ===\n", failures);
    return failures;
}
