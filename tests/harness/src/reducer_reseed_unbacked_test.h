/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Prove the runtime re-seed that reducer_ingest_block runs before
 * its drain never anchors the stage cursors of a seed-imported node (every
 * cursor 0, empty tip_finalize_log, header-only chain, no coins) at its
 * header-only tip, and that a folded node at its tip is left alone. Included
 * from test_reducer_ingest_e2e.c; uses its branch/env helpers and RIE_CHECK.
 */

#include "jobs/reducer_frontier.h"
#include "jobs/stage_helpers.h"
#include "models/database.h"
#include "services/seed_integrity_gate.h"

#define RRU_TIP 7 /* header-only tip height of the seed-imported fixture */

/* One node.db blocks row (hash, height, prev_hash): the rows the seed gate's
 * linkage walk reads (seed_integrity_gate.c gate_row_by_hash). */
static bool rru_blocks_row(struct node_db *ndb, const struct rie_branch *br,
                           int h)
{
    static const uint8_t zeros[32] = {0};
    static const uint8_t solution[1] = {0};
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO blocks"
            "(hash,height,prev_hash,version,merkle_root,time,bits,nonce,"
            " solution,chain_work,status,num_tx)"
            " VALUES(?,?,?,4,?,?,0,?,?,?,3,0)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, br->hashes[h].data, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, h);
    sqlite3_bind_blob(st, 3, h > 0 ? br->hashes[h - 1].data : zeros, 32,
                      SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, 1700000000 + h);
    sqlite3_bind_blob(st, 6, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 7, solution, sizeof(solution), SQLITE_STATIC);
    sqlite3_bind_blob(st, 8, zeros, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

/* Wire an in-memory node.db holding the branch's prev-hash-linked rows as the
 * seed gate's database, so the gate's linkage walk really runs. */
static bool rru_node_db_open(struct node_db *ndb, const struct rie_branch *br)
{
    memset(ndb, 0, sizeof(*ndb));
    seed_integrity_gate_reset_for_testing();
    if (!node_db_open(ndb, ":memory:"))
        return false;
    seed_integrity_gate_set_node_db_for_testing(ndb);
    for (int h = 0; h < br->n; h++)
        if (!rru_blocks_row(ndb, br, h))
            return false;
    return true;
}

static void rru_node_db_close(struct node_db *ndb)
{
    /* No blocker reset: the e2e teardown still reads the stage_spin_*
     * blockers the earlier scenarios may have raised. */
    seed_integrity_gate_reset_for_testing();
    node_db_close(ndb);
}

struct rru_state {
    uint64_t tf_cursor;
    uint64_t header_admit;
    uint64_t body_fetch;
    uint64_t utxo_apply;
    int64_t tf_rows;
    bool utxo_anchor_at_tip;
    bool trusted_found;
    int32_t trusted_h;
    uint64_t failures;
};

static bool rru_utxo_row_at(sqlite3 *db, int height)
{
    sqlite3_stmt *st = NULL;
    if (!db || sqlite3_prepare_v2(db,
            "SELECT 1 FROM utxo_apply_log WHERE height = ?", -1, &st,
            NULL) != SQLITE_OK)
        return false;  /* no table yet: no row */
    sqlite3_bind_int(st, 1, height);
    bool found = sqlite3_step(st) == SQLITE_ROW;  // raw-sql-ok:test-fixture-read
    sqlite3_finalize(st);
    return found;
}

static void rru_read_state(struct rru_state *s, int tip_h)
{
    sqlite3 *db = progress_store_db();
    memset(s, 0, sizeof(*s));
    s->tf_cursor = tip_finalize_stage_cursor();
    s->header_admit = stage_cursor_persisted(db, "header_admit", "rru");
    s->body_fetch = stage_cursor_persisted(db, "body_fetch", "rru");
    s->utxo_apply = stage_cursor_persisted(db, "utxo_apply", "rru");
    s->tf_rows = stage_log_row_count(db, "rru", "tip_finalize_log");
    s->utxo_anchor_at_tip = rru_utxo_row_at(db, tip_h);
    s->trusted_h = -1;
    if (!reducer_frontier_trusted_base_height_read(db, &s->trusted_h,
                                                   &s->trusted_found))
        s->trusted_found = true;  /* unreadable counts as written */
    s->failures = reducer_ingest_seed_anchor_reseed_failure_count();
}

static void rru_print(const char *what, const struct rru_state *s)
{
    printf("reducer_ingest_e2e: %s observed tf_cursor=%" PRIu64
           " header_admit=%" PRIu64 " body_fetch=%" PRIu64
           " utxo_apply=%" PRIu64 " tf_log_rows=%" PRId64
           " utxo_row_at_tip=%d trusted_base=%s%d failures=%" PRIu64 "\n",
           what, s->tf_cursor, s->header_admit, s->body_fetch, s->utxo_apply,
           s->tf_rows, s->utxo_anchor_at_tip ? 1 : 0,
           s->trusted_found ? "" : "absent:", s->trusted_h, s->failures);
}

/* Restart the tip_finalize stage over the installed chain, as boot does: init
 * publishes the tip authority at the cached tip (init_existing_tip), which is
 * the tip reducer_ingest_block's re-seed reads through active_chain_tip. */
static bool rru_reinit_tip_finalize(struct rie_env *e)
{
    tip_finalize_stage_shutdown();
    if (!tip_finalize_stage_init(&e->ms))
        return false;
    tip_finalize_stage_set_utxo_counter(rie_utxo_counter, &e->cc);
    return true;
}

static int rru_served_tip_height(struct rie_env *e)
{
    struct block_index *t = active_chain_tip(&e->ms.chain_active);
    return t ? t->nHeight : -1;
}

static void rru_run_seam(struct rie_env *e)
{
    struct chain_activation_controller ctl;
    memset(&ctl, 0, sizeof(ctl));
    ctl.ms = &e->ms;  /* params NULL: the regtest genesis branch stays off */
    reducer_ingest_seed_anchors_for_tip_for_testing(&ctl);
}

/* The post-run checks for the seed-imported shape: nothing moved, nothing
 * was written, the refusal was counted once per attempt. */
static int rru_check_unbacked(const char *label, const struct rru_state *b,
                              const struct rru_state *a, uint64_t attempts)
{
    int failures = 0;
    char name[192];
    snprintf(name, sizeof(name),
             "reseed-unbacked[%s]: tip_finalize cursor stays 0", label);
    RIE_CHECK(name, a->tf_cursor == 0);
    snprintf(name, sizeof(name),
             "reseed-unbacked[%s]: upstream cursors stay 0", label);
    RIE_CHECK(name, a->header_admit == 0 && a->body_fetch == 0 &&
                    a->utxo_apply == 0);
    snprintf(name, sizeof(name),
             "reseed-unbacked[%s]: no anchor row in either log", label);
    RIE_CHECK(name, a->tf_rows == 0 && !a->utxo_anchor_at_tip);
    snprintf(name, sizeof(name),
             "reseed-unbacked[%s]: trusted base not raised to the tip",
             label);
    RIE_CHECK(name, !a->trusted_found || a->trusted_h < RRU_TIP);
    snprintf(name, sizeof(name),
             "reseed-unbacked[%s]: each refusal counted", label);
    RIE_CHECK(name, a->failures == b->failures + attempts);
    return failures;
}

/* A header-only branch: genesis keeps its body, every later row is a
 * validated header without data, as the header seed leaves it. */
static bool rru_build_header_only(struct rie_branch *br)
{
    if (!branch_build(br, 0x5A, RRU_TIP + 1, -1, 0, NULL))
        return false;
    for (int h = 1; h < br->n; h++)
        br->blocks[h].nStatus = BLOCK_VALID_TREE;
    return true;
}

static int rru_run_unbacked_env(struct rie_env *e, struct rie_branch *C,
                                bool coins_key, const char *label)
{
    int failures = 0;
    struct node_db ndb;
    bool wired = rru_node_db_open(&ndb, C);
    bool coins_ok = !coins_key ||
        coins_kv_set_applied_height_in_tx(progress_store_db(), 1);
    char name[192];
    snprintf(name, sizeof(name),
             "reseed-unbacked[%s]: node.db linkage rows and coins key seeded",
             label);
    RIE_CHECK(name, wired && coins_ok);
    (void)install_branch(e, C);
    bool reinit = rru_reinit_tip_finalize(e);

    /* With no coins frontier the restarted stage publishes the header tip
     * ("authority publish fresh", the live seed-imported node's line) and the
     * re-seed is reached; a coins frontier below the tip withholds that
     * publish (fresh_tip_coin_frontier_allows), so nothing is re-seeded. */
    bool published = rru_served_tip_height(e) == RRU_TIP;
    struct rru_state before, after;
    rru_read_state(&before, RRU_TIP);
    rru_print("reseed-unbacked before", &before);
    snprintf(name, sizeof(name),
             "reseed-unbacked[%s]: seed-imported shape (%s, cursors 0, "
             "empty log)", label,
             coins_key ? "fresh publish withheld" : "served tip published");
    RIE_CHECK(name, reinit && published == !coins_key &&
                    before.tf_cursor == 0 && before.tf_rows == 0 &&
                    before.utxo_apply == 0 && before.header_admit == 0);

    /* Two ingests: the second must be refused the same way. */
    rru_run_seam(e);
    rru_run_seam(e);
    rru_read_state(&after, RRU_TIP);
    rru_print("reseed-unbacked after", &after);
    failures += rru_check_unbacked(label, &before, &after, published ? 2 : 0);
    rru_node_db_close(&ndb);
    return failures;
}

static int rru_run_unbacked(bool coins_key)
{
    int failures = 0;
    const char *label = coins_key ? "coins-key-1" : "coins-key-absent";
    struct rie_branch C;
    bool built = rru_build_header_only(&C);
    struct rie_env e;
    bool opened = built && rie_env_open(&e, label, &C, NULL, 0);
    char name[192];
    snprintf(name, sizeof(name), "reseed-unbacked[%s]: fixture opens", label);
    RIE_CHECK(name, opened);
    if (opened) {
        failures += rru_run_unbacked_env(&e, &C, coins_key, label);
        rie_env_close(&e);
    }
    branch_free(&C);
    tip_finalize_stage_test_reset();
    return failures;
}

/* A folded node at its tip (cursor == served tip, finalized rows behind it,
 * coins applied through the tip): the at-tip steady state the comment above
 * reducer_seed_anchors_for_ingest_tip describes. The ingest step must leave it
 * exactly as it is: no re-seed, no refusal, no row rewritten. */
static int rru_run_backed_env(struct rie_env *e, struct rie_branch *C)
{
    int failures = 0;
    int tip = C->n - 1;
    (void)install_branch(e, C);
    RIE_CHECK("reseed-backed: seed proof_validate through tip",
              seed_proof_validate(progress_store_db(), C, tip));
    (void)rie_drain_to_convergence();

    struct rru_state before, after;
    rru_read_state(&before, tip);
    rru_print("reseed-backed before", &before);
    RIE_CHECK("reseed-backed: folded to the served tip with finalized rows",
              rru_served_tip_height(e) == tip &&
              before.tf_cursor == (uint64_t)tip &&
              before.utxo_apply == (uint64_t)C->n && before.tf_rows == tip);

    rru_run_seam(e);
    rru_read_state(&after, tip);
    rru_print("reseed-backed after", &after);
    RIE_CHECK("reseed-backed: at-tip ingest leaves cursors and rows alone",
              after.tf_cursor == before.tf_cursor &&
              after.utxo_apply == before.utxo_apply &&
              after.tf_rows == before.tf_rows);
    RIE_CHECK("reseed-backed: no failure counted",
              after.failures == before.failures);
    return failures;
}

static int rru_run_backed(void)
{
    int failures = 0;
    struct rie_branch C;
    bool built = branch_build(&C, 0x5B, 6, -1, 0, NULL);
    struct rie_env e;
    bool opened = built && rie_env_open(&e, "reseed-backed", &C, NULL, 0);
    RIE_CHECK("reseed-backed: fixture opens", opened);
    if (opened) {
        failures += rru_run_backed_env(&e, &C);
        rie_env_close(&e);
    }
    branch_free(&C);
    tip_finalize_stage_test_reset();
    return failures;
}

static int rru_run_all(void)
{
    return rru_run_unbacked(false) + rru_run_unbacked(true) +
           rru_run_backed();
}
