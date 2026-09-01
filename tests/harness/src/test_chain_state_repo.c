/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the chain_state_repository — single writer for chain-tip
 * mutations. The repository must (a) keep the six sources of truth in
 * sync atomically, (b) refuse commits whose validation fails, and
 * (c) emit observable events on every outcome.
 *
 * Each test lives in its own static helper that returns a failure
 * count. The top-level test_chain_state_repo() aggregates them. */

#include "test/test_core.h"
#include "config/db_service.h"
#include "services/chain_state_service.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h"
#include "coins/coins_view.h"
#include "models/database.h"
#include "event/event.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

/* ── Tiny block_index fixture ─────────────────────────────────
 * Build a single-link chain of block_index records. Hashes are
 * stored in the fixture so the addresses are stable. */

#define MAX_FIXTURE_BLOCKS 16

struct csr_fixture {
    struct block_map        bm;
    struct active_chain     chain;
    struct block_index     *header_tip;
    struct coins_view_cache coins_tip;

    struct uint256       hashes[MAX_FIXTURE_BLOCKS];
    struct block_index   blocks[MAX_FIXTURE_BLOCKS];
    int                  count;
};

static void csr_fix_init(struct csr_fixture *f)
{
    memset(f, 0, sizeof(*f));
    block_map_init(&f->bm);
    active_chain_init(&f->chain);
    /* coins_view_cache_init dereferences its backing argument; pass a
     * zeroed view so it has something safe to copy from. */
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&f->coins_tip, &null_view);
    f->header_tip = NULL;
    f->count = 0;
}

static void csr_fix_free(struct csr_fixture *f)
{
    coins_view_cache_free(&f->coins_tip);
    active_chain_free(&f->chain);
    block_map_free(&f->bm);
}

static enum process_block_tip_publish_result
test_process_block_tip_result(enum csr_result rc)
{
    switch (rc) {
    case CSR_OK:
        return PROCESS_BLOCK_TIP_PUBLISH_OK;
    case CSR_REJECTED_NOT_INITIALIZED:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED_NOT_INITIALIZED;
    case CSR_REJECTED_DB_BUSY:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED_DB_BUSY;
    case CSR_REJECTED_PERSIST:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED_PERSIST;
    default:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED;
    }
}

static enum process_block_tip_publish_result test_process_block_commit_tip(
    void *ctx,
    struct main_state *ms,
    struct coins_view_cache *coins_tip,
    struct block_index *new_tip,
    const char *reason,
    bool update_header_tip,
    bool persist_coins_best,
    const struct process_block_tip_evidence *verified)
{
    (void)ctx;
    (void)coins_tip;
    (void)verified;
    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_TEST,
        .decision = POLICY_ALLOW,
        .from_height = ms ? active_chain_height(&ms->chain_active) : -1,
        .to_height = new_tip ? new_tip->nHeight : -1,
        .max_depth = INT64_MAX,
        .evidence_class = "test_process_block_tip_publication",
        .reason = reason ? reason : "test_process_block_commit_tip",
    };
    struct uint256 new_coins_best;
    memset(&new_coins_best, 0, sizeof(new_coins_best));
    if (new_tip && new_tip->phashBlock)
        new_coins_best = *new_tip->phashBlock;

    struct chain_state_commit commit = {
        .new_tip = new_tip,
        .new_coins_best = new_coins_best,
        .expected_utxo_count = 0,
        .update_header_tip = update_header_tip,
        .persist_coins_best = persist_coins_best,
        .rollback_auth = &rollback_auth,
        .wallet_scan_height = -1,
        .reason = reason,
    };

    return test_process_block_tip_result(csr_commit_tip(csr_instance(),
                                                        &commit));
}

/* Append one block at height = previous + 1. Each block hash is the
 * `seed` byte repeated 32 times so callers can give every block a
 * unique seed and reason about identity. */
static struct block_index *csr_fix_add(struct csr_fixture *f, uint8_t seed)
{
    if (f->count >= MAX_FIXTURE_BLOCKS) return NULL;
    int idx = f->count++;

    memset(&f->hashes[idx], seed, sizeof(struct uint256));
    block_index_init(&f->blocks[idx]);
    f->blocks[idx].phashBlock = &f->hashes[idx];
    f->blocks[idx].nHeight = idx;
    f->blocks[idx].pprev = (idx > 0) ? &f->blocks[idx - 1] : NULL;

    block_map_insert(&f->bm, &f->hashes[idx], &f->blocks[idx]);
    /* block_map_insert keeps the index pointer but a future grow
     * could relocate the bucket; re-point phashBlock so identity
     * stays stable across rehashes. */
    const struct block_index *canon = block_map_find(&f->bm, &f->hashes[idx]);
    if (canon) f->blocks[idx].phashBlock = canon->phashBlock;
    return &f->blocks[idx];
}

/* ── SQLite block-row helper ───────────────────────────────── */

static bool csr_sql_insert_block(struct node_db *ndb,
                                  const struct uint256 *hash,
                                  int height)
{
    if (!ndb || !ndb->db) return false;
    sqlite3_stmt *st = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO blocks"
        "(hash,height,prev_hash,version,merkle_root,time,bits,nonce,"
        " solution,chain_work,status,num_tx)"
        " VALUES(?,?,?,4,?,?,0,?,?,?,3,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    static const uint8_t zeros[32] = {0};
    static const uint8_t solution[1] = {0};
    sqlite3_bind_blob(st, 1, hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, height);
    sqlite3_bind_blob(st, 3, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, 1700000000 + height);
    sqlite3_bind_blob(st, 6, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 7, solution, sizeof(solution), SQLITE_STATIC);
    sqlite3_bind_blob(st, 8, zeros, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static bool csr_sql_insert_utxos(struct node_db *ndb, int n)
{
    if (!ndb || !ndb->db) return false;
    sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL);
    sqlite3_stmt *st = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO utxos"
        "(txid,vout,value,script,script_type,address_hash,"
        " height,is_coinbase)"
        " VALUES(?,?,?,?,0,?,0,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK) {
        sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL);
        return false;
    }
    static const uint8_t script[1] = {0x6a};
    static const uint8_t addr[20] = {0};
    bool ok = true;
    for (int i = 0; i < n && ok; i++) {
        uint8_t txid[32] = {0};
        memcpy(txid, &i, sizeof(i));
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, txid, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, 0);
        sqlite3_bind_int64(st, 3, 1000);
        sqlite3_bind_blob(st, 4, script, sizeof(script), SQLITE_STATIC);
        sqlite3_bind_blob(st, 5, addr, sizeof(addr), SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) ok = false;
    }
    sqlite3_finalize(st);
    sqlite3_exec(ndb->db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    return ok;
}

/* ── Event observer for assertions ────────────────────────── */

static _Atomic int g_commit_events;
static _Atomic int g_rejected_events;

static void csr_test_observer(enum event_type type, uint32_t peer_id,
                               const void *payload, uint32_t payload_len,
                               void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_CHAIN_TIP_COMMIT)
        atomic_fetch_add(&g_commit_events, 1);
    else if (type == EV_CHAIN_TIP_REJECTED)
        atomic_fetch_add(&g_rejected_events, 1);
}

static void csr_test_install_observer(void)
{
    event_log_init();
    event_clear_observers(EV_CHAIN_TIP_COMMIT);
    event_clear_observers(EV_CHAIN_TIP_REJECTED);
    atomic_store(&g_commit_events, 0);
    atomic_store(&g_rejected_events, 0);
    event_observe(EV_CHAIN_TIP_COMMIT, csr_test_observer, NULL);
    event_observe(EV_CHAIN_TIP_REJECTED, csr_test_observer, NULL);
}

/* ── Helper: build a commit pointing at one of the fixture blocks. */
static struct chain_state_commit csr_make_commit(struct block_index *bi,
                                                  const char *reason)
{
    struct chain_state_commit c;
    memset(&c, 0, sizeof(c));
    c.new_tip = bi;
    if (bi && bi->phashBlock) c.new_coins_best = *bi->phashBlock;
    c.reason = reason;
    c.wallet_scan_height = -1;
    return c;
}

/* Tiny pass/fail wrapper to keep tests visually consistent. */
#define CSR_RUN(name, expr) do { \
    printf("%s... ", (name));    \
    bool _ok = (expr);           \
    if (_ok) printf("OK\n");     \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Concurrency stress fixture ────────────────────────────── */

struct csr_concurrency_args {
    struct chain_state_repository *csr;
    struct block_index *tip;
    int iterations;
    _Atomic int oks;
};

static void *csr_thread_commit(void *p)
{
    struct csr_concurrency_args *a = p;
    for (int i = 0; i < a->iterations; i++) {
        struct chain_state_commit c = csr_make_commit(a->tip, "stress");
        if (csr_commit_tip(a->csr, &c) == CSR_OK)
            atomic_fetch_add(&a->oks, 1);
    }
    return NULL;
}

/* ── Tests ─────────────────────────────────────────────────── */

static int t_init_defaults(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    bool ok = csr.initialized
           && csr.block_map == &f.bm
           && csr.chain_active == &f.chain
           && csr.coins_tip == &f.coins_tip
           && csr.max_utxo_orphan_rows == 1000
           && csr.stale_index_height_gap == 100;
    CSR_RUN("csr: init populates fields and sets defaults", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_null_repo(void)
{
    int failures = 0;
    struct chain_state_commit c = {0};
    bool ok = csr_commit_tip(NULL, &c) == CSR_REJECTED_NULL_INPUT;
    CSR_RUN("csr: NULL repository returns NULL_INPUT", ok);
    struct zcl_result zr = csr_commit_tip_result(NULL, &c);
    ok = !zr.ok && zr.code == -(1000 + CSR_REJECTED_NULL_INPUT) &&
         strstr(zr.message, "null_input") != NULL;
    CSR_RUN("csr: result wrapper carries zcl_result failure", ok);
    return failures;
}

static int t_uninitialised(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    memset(&csr, 0, sizeof(csr));
    struct chain_state_commit c = {0};
    bool ok = csr_commit_tip(&csr, &c) == CSR_REJECTED_NOT_INITIALIZED;
    CSR_RUN("csr: uninitialised returns NOT_INITIALIZED", ok);
    return failures;
}

static int t_null_commit(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    bool ok = csr_commit_tip(&csr, NULL) == CSR_REJECTED_NULL_INPUT;
    CSR_RUN("csr: NULL commit returns NULL_INPUT", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_null_new_tip(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct chain_state_commit c = {0};
    c.reason = "test";
    bool ok = csr_commit_tip(&csr, &c) == CSR_REJECTED_NULL_INPUT;
    CSR_RUN("csr: NULL new_tip returns NULL_INPUT", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_null_reason(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *b = csr_fix_add(&f, 0xa1);
    struct chain_state_commit c = csr_make_commit(b, NULL);
    bool ok = csr_commit_tip(&csr, &c) == CSR_REJECTED_NULL_INPUT;
    CSR_RUN("csr: NULL reason returns NULL_INPUT", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_coins_mismatch(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *b = csr_fix_add(&f, 0xa2);
    struct chain_state_commit c = csr_make_commit(b, "test");
    c.new_coins_best.data[0] ^= 0xff;
    bool ok = csr_commit_tip(&csr, &c) == CSR_REJECTED_COINS_MISMATCH;
    CSR_RUN("csr: coins_best != tip hash returns COINS_MISMATCH", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_tip_not_in_index(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct uint256 h; memset(&h, 0xee, sizeof(h));
    struct block_index orphan; block_index_init(&orphan);
    orphan.phashBlock = &h;
    orphan.nHeight = 5;
    struct chain_state_commit c = csr_make_commit(&orphan, "test");
    bool ok = csr_commit_tip(&csr, &c) == CSR_REJECTED_TIP_NOT_IN_INDEX;
    CSR_RUN("csr: tip not in block_map returns TIP_NOT_IN_INDEX", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_stale_block_map_pointer(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *b = csr_fix_add(&f, 0xa3);
    struct block_index doppel; block_index_init(&doppel);
    doppel.phashBlock = b->phashBlock;
    doppel.nHeight = b->nHeight;
    struct chain_state_commit c = csr_make_commit(&doppel, "test");
    bool ok = csr_commit_tip(&csr, &c) == CSR_REJECTED_HASH_MISMATCH;
    CSR_RUN("csr: stale block_map pointer returns HASH_MISMATCH", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_missing_prev(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *b = csr_fix_add(&f, 0xa4);
    struct uint256 fake_hash; memset(&fake_hash, 0xcc, sizeof(fake_hash));
    struct block_index fake_prev; block_index_init(&fake_prev);
    fake_prev.phashBlock = &fake_hash;
    fake_prev.nHeight = 0;
    b->pprev = &fake_prev;
    struct chain_state_commit c = csr_make_commit(b, "test");
    bool ok = csr_commit_tip(&csr, &c) == CSR_REJECTED_MISSING_PREV;
    CSR_RUN("csr: pprev missing from block_map returns MISSING_PREV", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_happy_genesis(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g = csr_fix_add(&f, 0x01);
    struct chain_state_commit c = csr_make_commit(g, "genesis");
    bool ok = csr_commit_tip(&csr, &c) == CSR_OK;
    ok = ok && active_chain_height(&f.chain) == 0;
    ok = ok && active_chain_tip(&f.chain) == g;
    struct uint256 best;
    coins_view_cache_get_best_block(&f.coins_tip, &best);
    ok = ok && memcmp(best.data, g->phashBlock->data, 32) == 0;
    ok = ok && csr.commits_ok == 1u;
    CSR_RUN("csr: happy-path genesis commit updates active chain and coins", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_update_header(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g = csr_fix_add(&f, 0x10);
    struct chain_state_commit c = csr_make_commit(g, "boot");
    c.update_header_tip = true;
    bool ok = csr_commit_tip(&csr, &c) == CSR_OK && f.header_tip == g;
    CSR_RUN("csr: update_header_tip raises pindex_best_header", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_no_update_header(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g = csr_fix_add(&f, 0x11);
    f.header_tip = g; /* simulate prior knowledge */
    struct block_index *b1 = csr_fix_add(&f, 0x12);
    struct chain_state_commit c = csr_make_commit(b1, "extend");
    bool ok = csr_commit_tip(&csr, &c) == CSR_OK && f.header_tip == g;
    CSR_RUN("csr: without update_header_tip, header pointer is preserved", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_header_no_regress(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g  = csr_fix_add(&f, 0x20);
    struct block_index *b1 = csr_fix_add(&f, 0x21);
    struct block_index *b2 = csr_fix_add(&f, 0x22);
    (void)g;
    struct chain_state_commit c = csr_make_commit(b2, "boot");
    c.update_header_tip = true;
    bool ok = csr_commit_tip(&csr, &c) == CSR_OK && f.header_tip == b2;

    struct chain_state_commit c2 = csr_make_commit(b1, "rewind");
    c2.update_header_tip = true;
    ok = ok && csr_commit_tip(&csr, &c2) == CSR_OK && f.header_tip == b2;
    CSR_RUN("csr: header tip never regresses", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_header_regress_requires_typed_auth(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g  = csr_fix_add(&f, 0x23);
    struct block_index *b1 = csr_fix_add(&f, 0x24);
    struct block_index *b2 = csr_fix_add(&f, 0x25);
    (void)g;

    struct chain_state_commit c = csr_make_commit(b2, "boot");
    c.update_header_tip = true;
    bool ok = csr_commit_tip(&csr, &c) == CSR_OK && f.header_tip == b2;

    struct chain_state_commit c2 = csr_make_commit(b1, "rewind");
    c2.update_header_tip = true;
    ok = ok && csr_commit_tip(&csr, &c2) == CSR_OK && f.header_tip == b2;

    struct chain_state_rollback_authorization auth = {
        .source = CSR_ROLLBACK_SOURCE_TEST,
        .decision = POLICY_ALLOW,
        .from_height = 2,
        .to_height = 1,
        .max_depth = 10,
        .evidence_class = "unit_test",
        .reason = "authorized_header_rewind",
    };
    c2.reason = "authorized_rewind";
    c2.rollback_auth = &auth;
    ok = ok && csr_commit_tip(&csr, &c2) == CSR_OK && f.header_tip == b1;

    CSR_RUN("csr: typed rollback authorization gates header regression", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_header_commit_api_gates_regression(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g  = csr_fix_add(&f, 0x26);
    struct block_index *b1 = csr_fix_add(&f, 0x27);
    struct block_index *b2 = csr_fix_add(&f, 0x28);
    (void)g;

    struct chain_state_header_commit h2 = {
        .new_header_tip = b2,
        .rollback_auth = NULL,
        .reason = "unit.header_advance",
    };
    bool ok = csr_commit_header_tip(&csr, &h2) == CSR_OK &&
              f.header_tip == b2 &&
              active_chain_height(&f.chain) == -1;

    struct chain_state_header_commit h1 = {
        .new_header_tip = b1,
        .rollback_auth = NULL,
        .reason = "unit.header_regress",
    };
    ok = ok && csr_commit_header_tip(&csr, &h1) ==
         CSR_REJECTED_HEADER_REGRESSION &&
         f.header_tip == b2;

    struct chain_state_rollback_authorization auth = {
        .source = CSR_ROLLBACK_SOURCE_TEST,
        .decision = POLICY_ALLOW,
        .from_height = 2,
        .to_height = 1,
        .max_depth = 10,
        .evidence_class = "unit_test_header",
        .reason = "authorized_header_api_rewind",
    };
    h1.rollback_auth = &auth;
    h1.reason = "unit.header_regress_authorized";
    ok = ok && csr_commit_header_tip(&csr, &h1) == CSR_OK &&
         f.header_tip == b1;

    CSR_RUN("csr: header commit API gates regression with typed auth", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

/* Header tip is chainwork-ranked, not height-ranked. A taller-but-
 * lighter fork must NOT displace a heavier (more-work) header, and a
 * heavier candidate MUST advance the header tip even when it is no
 * taller. Mirrors Bitcoin Core's pindexBestHeader semantics. */
static int t_header_chainwork_ranked(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);

    /* heavy: the genuine most-work header (lower height, more work).
     * light_high: a competing fork that is HIGHER by raw height but
     * carries LESS cumulative work. heavier: a strictly-more-work
     * advance over `heavy` at the same height as `heavy`. */
    struct block_index *heavy      = csr_fix_add(&f, 0x40);
    struct block_index *light_high = csr_fix_add(&f, 0x41);
    struct block_index *heavier    = csr_fix_add(&f, 0x42);

    /* Stamp explicit chainwork so the gate's work comparison engages.
     * heavy has more work than the taller light_high fork. */
    arith_uint256_set_u64(&heavy->nChainWork, 1000);
    arith_uint256_set_u64(&light_high->nChainWork, 500);
    arith_uint256_set_u64(&heavier->nChainWork, 2000);
    /* light_high is taller by raw height than heavy. */
    light_high->nHeight = heavy->nHeight + 1;
    heavier->nHeight    = heavy->nHeight; /* not taller, just heavier */

    /* Promote the genuine most-work header. */
    struct chain_state_header_commit ch = {
        .new_header_tip = heavy,
        .rollback_auth = NULL,
        .reason = "unit.header_heavy",
    };
    bool ok = csr_commit_header_tip(&csr, &ch) == CSR_OK &&
              f.header_tip == heavy;

    /* Taller-but-lighter fork must be rejected as a regression and must
     * NOT displace the heavier header — even though it is higher. */
    struct chain_state_header_commit cl = {
        .new_header_tip = light_high,
        .rollback_auth = NULL,
        .reason = "unit.header_light_high",
    };
    ok = ok && csr_commit_header_tip(&csr, &cl) ==
         CSR_REJECTED_HEADER_REGRESSION &&
         f.header_tip == heavy;

    /* A strictly-heavier header advances the tip even at equal height. */
    struct chain_state_header_commit chh = {
        .new_header_tip = heavier,
        .rollback_auth = NULL,
        .reason = "unit.header_heavier",
    };
    ok = ok && csr_commit_header_tip(&csr, &chh) == CSR_OK &&
         f.header_tip == heavier;

    CSR_RUN("csr: header tip is chainwork-ranked, not height-ranked", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

/* Conservative fallback: when nChainWork has not yet been stamped
 * (still zero), the gate falls back to height ranking so a valid higher
 * header is never dropped just because work is not yet computed. */
static int t_header_zero_work_falls_back_to_height(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);

    /* Linear chain, all nChainWork == 0 (unstamped flat-index load). */
    struct block_index *b0 = csr_fix_add(&f, 0x50);
    struct block_index *b1 = csr_fix_add(&f, 0x51);
    (void)b0;

    struct chain_state_header_commit c0 = {
        .new_header_tip = b0, .rollback_auth = NULL,
        .reason = "unit.header_zero0",
    };
    bool ok = csr_commit_header_tip(&csr, &c0) == CSR_OK &&
              f.header_tip == b0;

    /* Higher height, both works zero -> advance (no regression). */
    struct chain_state_header_commit c1 = {
        .new_header_tip = b1, .rollback_auth = NULL,
        .reason = "unit.header_zero1",
    };
    ok = ok && csr_commit_header_tip(&csr, &c1) == CSR_OK &&
         f.header_tip == b1;

    /* Lower height, both works zero -> rejected (height fallback). */
    struct chain_state_header_commit c0b = {
        .new_header_tip = b0, .rollback_auth = NULL,
        .reason = "unit.header_zero0b",
    };
    ok = ok && csr_commit_header_tip(&csr, &c0b) ==
         CSR_REJECTED_HEADER_REGRESSION &&
         f.header_tip == b1;

    CSR_RUN("csr: zero-work header tip falls back to height ranking", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

/* Live regression (datadir ~/.zclassic-c23, pid 3591607): an inbound
 * msg_headers batch whose pindex_last lands BELOW the current best
 * header — but carries non-zero cumulative work that is NOT strictly
 * less than the incumbent's — was committing best_header DOWNWARD. That
 * dragged the active-chain window (which the header pipeline extends only
 * up to pindex_best_header) back below heights already in the index,
 * freezing header_admit/validate_headers at seed_h+1 while peers
 * advertised the real tip ~3,349 blocks higher. The guard must reject a
 * strictly-LOWER-height tip whenever its work does not strictly exceed
 * the incumbent (here: equal work), so best_header stays monotonic
 * non-decreasing on the network path. A legitimate authorized reorg
 * still rewinds via rollback_auth. */
static int t_header_equal_work_lower_height_rejected(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);

    /* low/high on the SAME most-work chain: equal cumulative work, high
     * is taller. (Stamping equal work models the real failure: the
     * inbound low-height pindex_last carried non-zero work that did not
     * trip the strict-less-work test.) */
    struct block_index *low  = csr_fix_add(&f, 0x60);
    struct block_index *high = csr_fix_add(&f, 0x61);
    arith_uint256_set_u64(&low->nChainWork, 1000);
    arith_uint256_set_u64(&high->nChainWork, 1000);
    high->nHeight = low->nHeight + 1;

    /* Promote the high (real) header tip. */
    struct chain_state_header_commit ch = {
        .new_header_tip = high, .rollback_auth = NULL,
        .reason = "unit.equalwork_high",
    };
    bool ok = csr_commit_header_tip(&csr, &ch) == CSR_OK &&
              f.header_tip == high;

    /* The lower-height, equal-work tip (the inbound low batch) MUST be
     * rejected — best_header must NOT regress. This is the exact bug:
     * before the fix it slipped through (work not strictly-less), pulling
     * best_header down and freezing the header pipeline. */
    struct chain_state_header_commit cl = {
        .new_header_tip = low, .rollback_auth = NULL,
        .reason = "unit.equalwork_low",
    };
    ok = ok && csr_commit_header_tip(&csr, &cl) ==
         CSR_REJECTED_HEADER_REGRESSION &&
         f.header_tip == high;

    /* A typed authorized reorg can still rewind to the lower header. */
    struct chain_state_rollback_authorization auth = {
        .source = CSR_ROLLBACK_SOURCE_TEST,
        .decision = POLICY_ALLOW,
        .from_height = high->nHeight,
        .to_height = low->nHeight,
        .max_depth = 10,
        .evidence_class = "unit_test_equalwork",
        .reason = "authorized_equalwork_rewind",
    };
    cl.rollback_auth = &auth;
    ok = ok && csr_commit_header_tip(&csr, &cl) == CSR_OK &&
         f.header_tip == low;

    CSR_RUN("csr: equal-work lower-height header tip rejected "
            "(no backward best_header)", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_clear_active_tip_requires_typed_auth(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *tip = csr_fix_add(&f, 0x29);

    struct chain_state_commit c = csr_make_commit(tip, "unit.set_tip");
    bool ok = csr_commit_tip(&csr, &c) == CSR_OK &&
              active_chain_height(&f.chain) == 0;

    struct chain_state_clear_commit no_auth = {
        .rollback_auth = NULL,
        .reason = "unit.clear_without_auth",
    };
    ok = ok && csr_clear_active_tip(&csr, &no_auth) ==
         CSR_REJECTED_ROLLBACK_AUTH &&
         active_chain_height(&f.chain) == 0;

    struct chain_state_rollback_authorization auth = {
        .source = CSR_ROLLBACK_SOURCE_TEST,
        .decision = POLICY_ALLOW,
        .from_height = 0,
        .to_height = -1,
        .max_depth = 10,
        .evidence_class = "unit_test_clear",
        .reason = "authorized_clear",
    };
    struct chain_state_clear_commit clear = {
        .rollback_auth = &auth,
        .reason = "unit.clear_authorized",
    };
    ok = ok && csr_clear_active_tip(&csr, &clear) == CSR_OK &&
         active_chain_height(&f.chain) == -1;

    CSR_RUN("csr: active-tip clear requires typed auth", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_extend_chain(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    bool ok = true;
    for (int i = 0; i < 5 && ok; i++) {
        struct block_index *b = csr_fix_add(&f, (uint8_t)(0x30 + i));
        struct chain_state_commit c = csr_make_commit(b, "extend");
        ok = csr_commit_tip(&csr, &c) == CSR_OK;
        ok = ok && active_chain_height(&f.chain) == i;
    }
    ok = ok && csr.commits_ok == 5u;
    CSR_RUN("csr: extending chain across many commits", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_sql_stale_index(void)
{
    int failures = 0;
    struct node_db ndb;
    bool dbok = node_db_open(&ndb, ":memory:");
    if (!dbok) {
        CSR_RUN("csr: SQLite stale-index gap returns STALE_INDEX (skipped: db open failed)", false);
        return failures;
    }
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, &ndb, NULL);

    struct block_index *g = csr_fix_add(&f, 0x40);
    struct uint256 high_hash; memset(&high_hash, 0x41, sizeof(high_hash));
    bool ok = csr_sql_insert_block(&ndb, g->phashBlock, 0)
           && csr_sql_insert_block(&ndb, &high_hash, 5000)
           && csr_sql_insert_utxos(&ndb, 2000);

    struct chain_state_commit c = csr_make_commit(g, "stale-index");
    ok = ok && csr_commit_tip(&csr, &c) == CSR_REJECTED_STALE_INDEX;
    ok = ok && active_chain_height(&f.chain) == -1;
    CSR_RUN("csr: SQLite stale-index gap returns STALE_INDEX", ok);

    csr_free(&csr);
    csr_fix_free(&f);
    node_db_close(&ndb);
    return failures;
}

/* Wave 9d regression: a forward step from the active tip into a
 * SQLite block_index range that has been pre-populated by body-pull
 * must NOT be rejected as stale_index. Before the carve-out, every
 * forward step from h=N → h=N+1 was rejected when sql_max was at
 * h=N+1000+ because body-pull writes block-index entries ahead of
 * the active chain advance. */
static int t_sql_stale_index_forward_step_bypass(void)
{
    int failures = 0;
    struct node_db ndb;
    bool dbok = node_db_open(&ndb, ":memory:");
    if (!dbok) {
        CSR_RUN("csr: forward step bypasses stale_index (skipped: db open failed)",
                false);
        return failures;
    }
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, &ndb, NULL);

    /* Build a 2-block fixture: g at h=0, b1 at h=1 with pprev=g. */
    struct block_index *g  = csr_fix_add(&f, 0x90);
    struct block_index *b1 = csr_fix_add(&f, 0x91);

    /* Seed SQLite with the active-chain ancestors plus a body-pull-
     * style pre-population of 5000+ heights ahead. UTXO row count
     * exceeds max_utxo_orphan_rows (default 1000). */
    struct uint256 far_hash; memset(&far_hash, 0x92, sizeof(far_hash));
    bool ok = csr_sql_insert_block(&ndb, g->phashBlock, 0)
           && csr_sql_insert_block(&ndb, b1->phashBlock, 1)
           && csr_sql_insert_block(&ndb, &far_hash, 5000)
           && csr_sql_insert_utxos(&ndb, 2000);

    /* Step 1: make g the active tip. With cur_h == -1 entering this
     * commit, sql_max=5000 - new_tip(0)=5000 > 100 fires the original
     * guard, but cur_utxos > orphan_rows requires the auth check —
     * we have no auth, so this should ALSO have failed before the
     * carve-out. Workaround for the seed: drop UTXOs to 0 first,
     * insert them after seeding g as active. */
    sqlite3_exec(ndb.db, "DELETE FROM utxos", NULL, NULL, NULL);
    struct chain_state_commit cg = csr_make_commit(g, "seed-active-tip");
    ok = ok && csr_commit_tip(&csr, &cg) == CSR_OK
            && active_chain_height(&f.chain) == 0;

    /* Re-insert the heavy UTXO set now that the active tip is seeded. */
    ok = ok && csr_sql_insert_utxos(&ndb, 2000);

    /* Step 2: forward step from active tip h=0 → h=1. sql_max is
     * still 5000 (body-pull style), gap=4999 > 100, UTXOs > 1000,
     * no rollback auth. Without the wave-9d carve-out this would
     * return CSR_REJECTED_STALE_INDEX; with it the commit succeeds. */
    struct chain_state_commit c1 = csr_make_commit(b1, "forward-step");
    ok = ok && csr_commit_tip(&csr, &c1) == CSR_OK
            && active_chain_height(&f.chain) == 1;

    CSR_RUN("csr: forward step bypasses stale_index (wave 9d)", ok);

    csr_free(&csr);
    csr_fix_free(&f);
    node_db_close(&ndb);
    return failures;
}

static int t_sql_hash_height_conflict(void)
{
    int failures = 0;
    struct node_db ndb;
    bool dbok = node_db_open(&ndb, ":memory:");
    if (!dbok) {
        CSR_RUN("csr: SQLite hash/height conflict returns HASH_MISMATCH (skipped)", false);
        return failures;
    }
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, &ndb, NULL);

    struct block_index *g = csr_fix_add(&f, 0x50);
    bool ok = csr_sql_insert_block(&ndb, g->phashBlock, 999);

    struct chain_state_commit c = csr_make_commit(g, "hash-mismatch");
    ok = ok && csr_commit_tip(&csr, &c) == CSR_REJECTED_HASH_MISMATCH;
    CSR_RUN("csr: SQLite hash/height conflict returns HASH_MISMATCH", ok);

    csr_free(&csr);
    csr_fix_free(&f);
    node_db_close(&ndb);
    return failures;
}

static int t_typed_rollback_authorization(void)
{
    int failures = 0;
    struct node_db ndb;
    bool dbok = node_db_open(&ndb, ":memory:");
    if (!dbok) {
        CSR_RUN("csr: typed rollback authorization bypasses orphan guard (skipped)", false);
        return failures;
    }
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, &ndb, NULL);

    struct block_index *g  = csr_fix_add(&f, 0x60);
    struct block_index *b1 = csr_fix_add(&f, 0x61);
    struct block_index *b2 = csr_fix_add(&f, 0x62);
    bool ok = csr_sql_insert_block(&ndb, g->phashBlock, 0)
           && csr_sql_insert_block(&ndb, b1->phashBlock, 1)
           && csr_sql_insert_block(&ndb, b2->phashBlock, 2)
           && csr_sql_insert_utxos(&ndb, 2000);

    struct chain_state_commit c2 = csr_make_commit(b2, "advance");
    ok = ok && csr_commit_tip(&csr, &c2) == CSR_OK;
    ok = ok && active_chain_height(&f.chain) == 2;

    struct chain_state_commit cback = csr_make_commit(g, "rollback");
    ok = ok && csr_commit_tip(&csr, &cback) == CSR_REJECTED_UTXO_DELTA_TOO_BIG;

    struct chain_state_rollback_authorization auth = {
        .source = CSR_ROLLBACK_SOURCE_TEST,
        .decision = POLICY_ALLOW,
        .from_height = 2,
        .to_height = 0,
        .max_depth = 10,
        .evidence_class = "unit_test",
        .reason = "rollback",
    };
    cback.rollback_auth = &auth;
    ok = ok && csr_commit_tip(&csr, &cback) == CSR_OK;
    ok = ok && active_chain_height(&f.chain) == 0;
    CSR_RUN("csr: typed rollback authorization bypasses orphan guard", ok);

    csr_free(&csr);
    csr_fix_free(&f);
    node_db_close(&ndb);
    return failures;
}

static int t_boot_repair_genesis_refuses_non_genesis_rollback(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);

    struct block_index *g  = csr_fix_add(&f, 0x63);
    struct block_index *b1 = csr_fix_add(&f, 0x64);
    struct block_index *b2 = csr_fix_add(&f, 0x65);
    (void)b1;

    bool ok = false;
    struct chain_state_commit c2 = csr_make_commit(b2, "advance");
    if (csr_commit_tip(&csr, &c2) == CSR_OK &&
        active_chain_height(&f.chain) == 2) {
        struct chain_state_rollback_authorization auth = {
            .source = CSR_ROLLBACK_SOURCE_BOOT_REPAIR,
            .decision = POLICY_ALLOW,
            .from_height = 2,
            .to_height = 0,
            .max_depth = INT64_MAX,
            .evidence_class = "boot_repair_verified",
            .reason = "genesis_init",
        };
        struct chain_state_commit cg = csr_make_commit(g, "genesis_init");
        cg.rollback_auth = &auth;
        ok = csr_commit_tip(&csr, &cg) == CSR_REJECTED_ROLLBACK_AUTH &&
             active_chain_height(&f.chain) == 2 &&
             active_chain_tip(&f.chain) == b2;
    }
    CSR_RUN("csr: boot genesis repair cannot roll back non-genesis tip", ok);

    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_expected_utxo_drift(void)
{
    int failures = 0;
    struct node_db ndb;
    bool dbok = node_db_open(&ndb, ":memory:");
    if (!dbok) {
        CSR_RUN("csr: expected_utxo_count drift returns UTXO_DELTA_TOO_BIG (skipped)", false);
        return failures;
    }
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, &ndb, NULL);

    struct block_index *g = csr_fix_add(&f, 0x70);
    bool ok = csr_sql_insert_block(&ndb, g->phashBlock, 0)
           && csr_sql_insert_utxos(&ndb, 100);

    struct chain_state_commit c = csr_make_commit(g, "drift");
    c.expected_utxo_count = 500; /* 80% drift */
    ok = ok && csr_commit_tip(&csr, &c) == CSR_REJECTED_UTXO_DELTA_TOO_BIG;
    CSR_RUN("csr: expected_utxo_count drift > 50% returns UTXO_DELTA_TOO_BIG", ok);

    csr_free(&csr);
    csr_fix_free(&f);
    node_db_close(&ndb);
    return failures;
}

static int t_expected_utxo_close(void)
{
    int failures = 0;
    struct node_db ndb;
    bool dbok = node_db_open(&ndb, ":memory:");
    if (!dbok) {
        CSR_RUN("csr: expected_utxo_count close to actual returns OK (skipped)", false);
        return failures;
    }
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, &ndb, NULL);

    struct block_index *g = csr_fix_add(&f, 0x80);
    bool ok = csr_sql_insert_block(&ndb, g->phashBlock, 0)
           && csr_sql_insert_utxos(&ndb, 100);

    struct chain_state_commit c = csr_make_commit(g, "close");
    c.expected_utxo_count = 90; /* drift 10% */
    ok = ok && csr_commit_tip(&csr, &c) == CSR_OK;
    CSR_RUN("csr: expected_utxo_count close to actual returns OK", ok);

    csr_free(&csr);
    csr_fix_free(&f);
    node_db_close(&ndb);
    return failures;
}

static int t_persist_coins_best_rejects_before_publish(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g = csr_fix_add(&f, 0x6d);
    struct chain_state_commit c = csr_make_commit(g, "persist.required");
    c.persist_coins_best = true;
    c.update_header_tip = true;

    bool ok = csr_commit_tip(&csr, &c) == CSR_REJECTED_PERSIST;
    ok = ok && active_chain_height(&f.chain) == -1;
    ok = ok && f.header_tip == NULL;
    ok = ok && uint256_is_null(&f.coins_tip.hash_block);
    CSR_RUN("csr: persist_coins_best rejects before publishing tip", ok);

    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_persist_coins_best_uses_db_writer(void)
{
    int failures = 0;
    struct node_db ndb;
    bool dbok = node_db_open(&ndb, ":memory:");
    if (!dbok) {
        CSR_RUN("csr: persist_coins_best uses serialized db writer (skipped)",
                false);
        return failures;
    }
    struct db_service dbsvc;
    db_service_init(&dbsvc);
    bool ok = db_service_attach(&dbsvc, &ndb) &&
              db_service_start(&dbsvc);

    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, &ndb, NULL);
    csr_set_db_service(&csr, &dbsvc);
    struct block_index *g = csr_fix_add(&f, 0x6e);
    ok = ok && csr_sql_insert_block(&ndb, g->phashBlock, 0);

    struct chain_state_commit c = csr_make_commit(g, "persist.writer");
    c.persist_coins_best = true;
    ok = ok && csr_commit_tip(&csr, &c) == CSR_OK;

    uint8_t persisted[32] = {0};
    size_t persisted_len = 0;
    ok = ok && node_db_state_get(&ndb, "coins_best_block",
                                 persisted, sizeof(persisted),
                                 &persisted_len);
    ok = ok && persisted_len == 32 &&
              memcmp(persisted, g->phashBlock->data, 32) == 0;
    ok = ok && active_chain_height(&f.chain) == 0;
    CSR_RUN("csr: persist_coins_best uses serialized db writer", ok);

    csr_free(&csr);
    csr_fix_free(&f);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);
    return failures;
}

static int t_snapshot_after_commit(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g = csr_fix_add(&f, 0x90);
    struct block_index *b = csr_fix_add(&f, 0x91);
    struct chain_state_commit c1 = csr_make_commit(g, "init");
    c1.update_header_tip = true;
    csr_commit_tip(&csr, &c1);
    struct chain_state_commit c2 = csr_make_commit(b, "extend");
    c2.update_header_tip = true;
    csr_commit_tip(&csr, &c2);

    struct chain_state_view v;
    csr_snapshot(&csr, &v);
    bool ok = v.tip_height == 1
           && v.header_height == 1
           && v.consistent
           && v.commits_ok == 2u
           && csr_header_tip_snapshot(&csr) == f.header_tip;
    CSR_RUN("csr: snapshot reflects committed state", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_snapshot_uninitialised(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    memset(&csr, 0, sizeof(csr));
    struct chain_state_view v;
    csr_snapshot(&csr, &v);
    bool ok = v.tip_height == -1
           && v.header_height == -1
           && v.utxo_count == -1;
    CSR_RUN("csr: snapshot of uninitialised repo is empty", ok);
    return failures;
}

/* csr_capture_frontiers — success + one failure envelope (E2 migration to
 * struct zcl_result; no prior direct coverage of this function). */
static int t_capture_frontiers_success(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g = csr_fix_add(&f, 0xA0);
    struct chain_state_commit c = csr_make_commit(g, "capture_frontiers init");
    c.update_header_tip = true;
    csr_commit_tip(&csr, &c);

    struct chain_state_frontier_view view;
    struct zcl_result r = csr_capture_frontiers(
        &csr, &f.chain, &f.header_tip, 0, &view);
    bool ok = r.ok && view.initialized && view.bound_to_expected_state &&
              view.window.height == 0 && view.header_tip == g;
    CSR_RUN("csr: capture_frontiers succeeds on bound, committed state", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_capture_frontiers_null_csr(void)
{
    int failures = 0;
    struct chain_state_frontier_view view;
    memset(&view, 0, sizeof(view));
    struct zcl_result r = csr_capture_frontiers(NULL, NULL, NULL, 0, &view);
    bool ok = !r.ok && r.message[0] != '\0';
    CSR_RUN("csr: capture_frontiers on NULL csr is a named failure", ok);
    return failures;
}

static int t_counters_increment(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g = csr_fix_add(&f, 0xb0);
    struct chain_state_commit c = csr_make_commit(g, "test");
    c.new_coins_best.data[0] ^= 0xff;
    csr_commit_tip(&csr, &c);
    csr_commit_tip(&csr, &c);
    bool ok = csr.commits_rejected[CSR_REJECTED_COINS_MISMATCH] == 2u
           && csr.commits_ok == 0u;
    CSR_RUN("csr: per-result counters increment on rejection", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_events_fire(void)
{
    int failures = 0;
    csr_test_install_observer();
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g = csr_fix_add(&f, 0xc0);
    struct chain_state_commit good = csr_make_commit(g, "ok");
    struct chain_state_commit bad = csr_make_commit(g, "bad");
    bad.new_coins_best.data[0] ^= 0xff;
    csr_commit_tip(&csr, &good);
    csr_commit_tip(&csr, &bad);
    bool ok = atomic_load(&g_commit_events) == 1
           && atomic_load(&g_rejected_events) == 1;
    CSR_RUN("csr: events fire on success and rejection", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_wallet_scan(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    int64_t scan = -1;
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, &scan);
    struct block_index *g = csr_fix_add(&f, 0xd0);
    struct chain_state_commit c = csr_make_commit(g, "wallet");
    c.wallet_scan_height = 42;
    bool ok = csr_commit_tip(&csr, &c) == CSR_OK && scan == 42;
    CSR_RUN("csr: wallet scan height applied", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_tunables(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    csr_set_max_utxo_orphan_rows(&csr, 999999);
    csr_set_stale_index_gap(&csr, 50);
    bool ok = csr.max_utxo_orphan_rows == 999999
           && csr.stale_index_height_gap == 50;
    CSR_RUN("csr: tunable thresholds update", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_concurrent(void)
{
    int failures = 0;
    struct chain_state_repository csr;
    struct csr_fixture f; csr_fix_init(&f);
    csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    struct block_index *g = csr_fix_add(&f, 0xe0);

    const int N_THREADS = 4;
    const int ITERS = 100;
    pthread_t th[4];
    struct csr_concurrency_args args;
    args.csr = &csr;
    args.tip = g;
    args.iterations = ITERS;
    atomic_store(&args.oks, 0);

    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&th[i], NULL, csr_thread_commit, &args);
    for (int i = 0; i < N_THREADS; i++)
        pthread_join(th[i], NULL);

    bool ok = atomic_load(&args.oks) == N_THREADS * ITERS
           && csr.commits_ok == (uint64_t)(N_THREADS * ITERS);
    CSR_RUN("csr: concurrent commits are serialised", ok);
    csr_free(&csr);
    csr_fix_free(&f);
    return failures;
}

static int t_result_names(void)
{
    int failures = 0;
    bool ok = true;
    for (int i = 0; i < CSR_NUM_RESULTS && ok; i++) {
        const char *n = csr_result_name((enum csr_result)i);
        if (!n || strcmp(n, "unknown") == 0) ok = false;
    }
    ok = ok && strcmp(csr_result_name(CSR_OK), "ok") == 0;
    CSR_RUN("csr: result_name covers every result code", ok);
    return failures;
}

/* ── Singleton tests ─────────────────────────────────────────
 * These exercise the process-lifetime singleton that call-site
 * migrations reach through csr_instance(). The tests intentionally
 * wire and unwire the singleton to keep the suite reentrant. */

static int t_singleton_identity(void)
{
    int failures = 0;
    struct chain_state_repository *a = csr_instance();
    struct chain_state_repository *b = csr_instance();
    bool ok = (a != NULL) && (a == b);
    CSR_RUN("csr: csr_instance returns stable singleton", ok);
    return failures;
}

static int t_singleton_uninitialized_rejects(void)
{
    /* The singleton starts its life before boot wires pointers.
     * Any commit attempt in that window must be rejected cleanly
     * with CSR_REJECTED_NOT_INITIALIZED and no side effects. */
    int failures = 0;
    struct chain_state_repository *csr = csr_instance();

    /* Guarantee a pristine state for this test even if an earlier
     * test already wired the singleton: flip initialized off so the
     * NOT_INITIALIZED path runs; we'll restore anything we changed. */
    bool was_initialized = csr->initialized;
    csr->initialized = false;

    struct chain_state_commit c = {0};
    /* new_tip is NULL; result must be NOT_INITIALIZED (not NULL_INPUT)
     * because the initialized gate runs before NULL validation. */
    enum csr_result rc = csr_commit_tip(csr, &c);
    bool ok = (rc == CSR_REJECTED_NOT_INITIALIZED);

    csr->initialized = was_initialized;
    CSR_RUN("csr: singleton rejects commits before csr_init", ok);
    return failures;
}

static int t_singleton_init_wires_fixture(void)
{
    /* Wire the singleton to a local fixture, commit a genesis tip,
     * and verify the event + counter fire. Afterwards restore the
     * singleton to uninitialized so the rest of the suite isn't
     * affected by our dangling pointers. */
    int failures = 0;
    csr_test_install_observer();
    struct csr_fixture f; csr_fix_init(&f);
    struct chain_state_repository *csr = csr_instance();
    csr_init(csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);

    uint64_t before_ok = csr->commits_ok;
    int before_events = atomic_load(&g_commit_events);

    struct block_index *g = csr_fix_add(&f, 0xf1);
    struct chain_state_commit c = csr_make_commit(g, "singleton.test");
    enum csr_result rc = csr_commit_tip(csr, &c);

    bool ok = (rc == CSR_OK)
           && (csr->commits_ok == before_ok + 1u)
           && (atomic_load(&g_commit_events) == before_events + 1);
    CSR_RUN("csr: singleton wired via csr_init commits cleanly", ok);

    /* Unwire: the test reset must clear every borrowed binding without
     * touching its pthread_once-owned mutex, remain idempotent, and permit a
     * later init to bind a fresh node lifetime. This is the behavior the
     * monolithic test reset relies on to avoid dangling fixture pointers. */
    struct node_db sentinel_ndb = {0};
    struct db_service sentinel_db_service = {0};
    int64_t sentinel_wallet_scan = 0;
    csr_init(csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip,
             &sentinel_ndb, &sentinel_wallet_scan);
    csr_set_db_service(csr, &sentinel_db_service);
    csr_test_reset_singleton();
    struct chain_state_view detached_view;
    csr_snapshot(csr, &detached_view);
    bool detached = !csr->initialized && !csr->block_map &&
                    !csr->chain_active && !csr->pindex_best_hdr &&
                    !csr->coins_tip && !csr->ndb && !csr->db_service &&
                    !csr->wallet_scan_h && detached_view.tip_height == -1 &&
                    detached_view.header_height == -1;
    CSR_RUN("csr: singleton test reset detaches every borrowed binding",
            detached);

    csr_test_reset_singleton();
    CSR_RUN("csr: singleton test reset is idempotent", !csr->initialized);

    csr_init(csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
    bool rebound = csr->initialized && csr->block_map == &f.bm &&
                   csr->chain_active == &f.chain &&
                   csr->pindex_best_hdr == &f.header_tip &&
                   csr->coins_tip == &f.coins_tip;
    CSR_RUN("csr: singleton can rebind after test detach", rebound);
    csr_test_reset_singleton();

    csr_fix_free(&f);
    return failures;
}

/* Regression guard: an update_tip declared `static
 * void` silently discards the bool return from
 * process_block_commit_tip. When the tip publisher refuses a commit (any of
 * CSR_REJECTED_COINS_MISMATCH / _TIP_NOT_IN_INDEX / _STALE_INDEX /
 * ...), connect_tip must not still return true with active_chain_tip
 * pointing at the old block — that shape re-emits
 * EV_BLOCK_CONNECTED for the same height dozens of times per second
 * until the download queue buffers the node to
 * GB-scale RSS and SIGABRT.
 *
 * The regression wires the csr singleton behind the test publisher,
 * hands update_tip a block_index NOT in the map (so the publisher will
 * respond CSR_REJECTED_TIP_NOT_IN_INDEX), and asserts the caller
 * observes false. Without the patch the wrapper would silently
 * return true. */
static int t_p71_update_tip_propagates_csr_rejection(void)
{
    int failures = 0;
    struct csr_fixture f; csr_fix_init(&f);
    struct chain_state_repository *csr = csr_instance();
    csr_init(csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip,
             NULL, NULL);

    int before_h = active_chain_height(&f.chain);
    uint64_t before_rej = 0;
    for (int i = 0; i < CSR_NUM_RESULTS; i++)
        before_rej += csr->commits_rejected[i];

    /* orphan block_index — not registered in f.bm, so csr must
     * reject with CSR_REJECTED_TIP_NOT_IN_INDEX. */
    struct uint256 h; memset(&h, 0xee, sizeof(h));
    struct block_index orphan;
    block_index_init(&orphan);
    orphan.phashBlock = &h;
    orphan.nHeight = 5;

    /* update_tip only dereferences ms->chain_active on the NULL-tip
     * disconnect branch (which we don't take); a zeroed main_state
     * is safe for the rejection path. */
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));

    process_block_set_tip_publication_hooks(test_process_block_commit_tip,
                                            NULL, NULL);
    bool returned = process_block_test_update_tip(&ms, &orphan);
    process_block_set_tip_publication_hooks(NULL, NULL, NULL);

    uint64_t after_rej = 0;
    for (int i = 0; i < CSR_NUM_RESULTS; i++)
        after_rej += csr->commits_rejected[i];

    bool ok = (returned == false);
    ok = ok && (active_chain_height(&f.chain) == before_h);
    ok = ok && (after_rej == before_rej + 1);
    CSR_RUN("csr/p7.1: update_tip propagates csr rejection (was silent)",
            ok);

    csr_test_reset_singleton();

    csr_fix_free(&f);
    return failures;
}

/* ── Test runner ─────────────────────────────────────────── */

int test_chain_state_repo(void)
{
    int failures = 0;

    failures += t_init_defaults();
    failures += t_null_repo();
    failures += t_uninitialised();
    failures += t_null_commit();
    failures += t_null_new_tip();
    failures += t_null_reason();
    failures += t_coins_mismatch();
    failures += t_tip_not_in_index();
    failures += t_stale_block_map_pointer();
    failures += t_missing_prev();
    failures += t_happy_genesis();
    failures += t_update_header();
    failures += t_no_update_header();
    failures += t_header_no_regress();
    failures += t_header_regress_requires_typed_auth();
    failures += t_header_commit_api_gates_regression();
    failures += t_header_chainwork_ranked();
    failures += t_header_zero_work_falls_back_to_height();
    failures += t_header_equal_work_lower_height_rejected();
    failures += t_clear_active_tip_requires_typed_auth();
    failures += t_extend_chain();
    failures += t_sql_stale_index();
    failures += t_sql_stale_index_forward_step_bypass();
    failures += t_sql_hash_height_conflict();
    failures += t_typed_rollback_authorization();
    failures += t_boot_repair_genesis_refuses_non_genesis_rollback();
    failures += t_expected_utxo_drift();
    failures += t_expected_utxo_close();
    failures += t_persist_coins_best_rejects_before_publish();
    failures += t_persist_coins_best_uses_db_writer();
    failures += t_snapshot_after_commit();
    failures += t_snapshot_uninitialised();
    failures += t_capture_frontiers_success();
    failures += t_capture_frontiers_null_csr();
    failures += t_counters_increment();
    failures += t_events_fire();
    failures += t_wallet_scan();
    failures += t_tunables();
    failures += t_concurrent();
    failures += t_result_names();
    failures += t_singleton_identity();
    failures += t_singleton_uninitialized_rejects();
    failures += t_singleton_init_wires_fixture();
    failures += t_p71_update_tip_propagates_csr_rejection();

    /* Negative height rejection */
    {
        printf("csr: negative height returns NULL_INPUT... ");
        struct chain_state_repository csr;
        struct csr_fixture f; csr_fix_init(&f);
        csr_init(&csr, &f.bm, &f.chain, &f.header_tip, &f.coins_tip, NULL, NULL);
        struct block_index *b = csr_fix_add(&f, 0xF1);
        b->nHeight = -1; /* force negative height */
        struct chain_state_commit c = csr_make_commit(b, "negative height test");
        bool ok = csr_commit_tip(&csr, &c) == CSR_REJECTED_NULL_INPUT;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        csr_free(&csr);
        csr_fix_free(&f);
    }

    /* Reset observers so we don't interfere with the rest of the suite. */
    event_clear_observers(EV_CHAIN_TIP_COMMIT);
    event_clear_observers(EV_CHAIN_TIP_REJECTED);

    return failures;
}
