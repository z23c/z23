/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Prove the runtime re-seed reducer_ingest_block runs before its
 * drain never anchors the node on the ORPHANED old tip after a reorg. A
 * reorg rewinds the tip_finalize cursor but the served tip stays on the old
 * block until the new branch finalizes past the old height (the publish gate
 * is height-monotonic, step_fin_publish_wanted), so every ingest in that
 * window sees cursor < served tip with the served tip off the best chain.
 * Also proves the legitimate re-seed (cursor clamped behind a served tip that
 * IS on the best chain) still fires. Included from test_reducer_ingest_e2e.c
 * after reducer_reseed_unbacked_test.h; uses its rru_* and rie_* helpers.
 */

#include "../../../engine/jobs/src/tip_finalize_anchor_internal.h"
#include "../../../engine/jobs/src/tip_finalize_log_store.h"

#define RRO_OLD_N 5    /* old chain L: h0..h4, served tip L4 */
#define RRO_NEW_N 7    /* heavier branch W: h0..h6 (headers all known) */
#define RRO_BODIES RRO_OLD_TIP /* W bodies present through the old height */
#define RRO_VALIDATED 2        /* upstream validation of W done through h2 */
#define RRO_OLD_TIP (RRO_OLD_N - 1)

struct rro_fixture {
    struct rie_branch L;
    struct rie_branch W;
};

struct rro_snap {
    uint64_t tf_cursor;
    int served_h;
    char served[8];
    char cursors[640];
    bool trusted_found;
    int32_t trusted_h;
    char trusted[8];
    bool tf_row;
    char tf_status[24];
    char tf_hash[8];
    bool ua_row;
    char ua_status[24];
    uint64_t failures;
};

/* "L3" / "W5" / "?" for a hash on either branch (genesis is shared: "L0"). */
static void rro_label(const struct rro_fixture *f, const uint8_t hash[32],
                      char *out, size_t n)
{
    snprintf(out, n, "?");
    for (int h = 0; h < f->L.n; h++)
        if (memcmp(f->L.hashes[h].data, hash, 32) == 0) {
            snprintf(out, n, "L%d", h);
            return;
        }
    for (int h = 0; h < f->W.n; h++)
        if (memcmp(f->W.hashes[h].data, hash, 32) == 0) {
            snprintf(out, n, "W%d", h);
            return;
        }
}

static void rro_read_cursors(sqlite3 *db, char *out, size_t n)
{
    out[0] = 0;
    sqlite3_stmt *st = NULL;
    if (!db || sqlite3_prepare_v2(db,
            "SELECT name, cursor FROM stage_cursor ORDER BY name", -1, &st,
            NULL) != SQLITE_OK) {
        snprintf(out, n, "unreadable");
        return;
    }
    size_t used = 0;
    while (sqlite3_step(st) == SQLITE_ROW && used + 1 < n) {  // raw-sql-ok:test-fixture-read
        const unsigned char *name = sqlite3_column_text(st, 0);
        int w = snprintf(out + used, n - used, "%s%s=%lld", used ? "," : "",
                         name ? (const char *)name : "",
                         (long long)sqlite3_column_int64(st, 1));
        if (w < 0)
            break;
        used += (size_t)w;
    }
    sqlite3_finalize(st);
}

static bool rro_ua_status_at(sqlite3 *db, int height, char *out, size_t n)
{
    out[0] = 0;
    sqlite3_stmt *st = NULL;
    if (!db || sqlite3_prepare_v2(db,
            "SELECT status FROM utxo_apply_log WHERE height = ?", -1, &st,
            NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool found = sqlite3_step(st) == SQLITE_ROW;  // raw-sql-ok:test-fixture-read
    if (found) {
        const unsigned char *s = sqlite3_column_text(st, 0);
        snprintf(out, n, "%s", s ? (const char *)s : "");
    }
    sqlite3_finalize(st);
    return found;
}

static void rro_read_served(struct rie_env *e, const struct rro_fixture *f,
                            struct rro_snap *s)
{
    struct block_index *t = active_chain_tip(&e->ms.chain_active);
    s->served_h = t ? t->nHeight : -1;
    snprintf(s->served, sizeof(s->served), "none");
    if (t && t->phashBlock)
        rro_label(f, t->phashBlock->data, s->served, sizeof(s->served));
}

static void rro_read_trusted(sqlite3 *db, const struct rro_fixture *f,
                             struct rro_snap *s)
{
    uint8_t hash[32] = {0};
    s->trusted_h = -1;
    snprintf(s->trusted, sizeof(s->trusted), "-");
    if (!reducer_frontier_trusted_base_read(db, &s->trusted_h, hash,
                                            &s->trusted_found)) {
        snprintf(s->trusted, sizeof(s->trusted), "bad");
        s->trusted_found = true;
        return;
    }
    if (s->trusted_found)
        rro_label(f, hash, s->trusted, sizeof(s->trusted));
}

static void rro_read_tf_row(sqlite3 *db, const struct rro_fixture *f,
                            struct rro_snap *s)
{
    struct finalized_tip_row row;
    memset(&row, 0, sizeof(row));
    snprintf(s->tf_hash, sizeof(s->tf_hash), "-");
    s->tf_row = finalized_tip_row_at(db, RRO_OLD_TIP, &row) && row.found;
    if (!tf_log_status_at(db, RRO_OLD_TIP, s->tf_status,
                          sizeof(s->tf_status)))
        snprintf(s->tf_status, sizeof(s->tf_status), "none");
    if (s->tf_row && row.has_tip_hash)
        rro_label(f, row.tip_hash.data, s->tf_hash, sizeof(s->tf_hash));
}

static void rro_snapshot(struct rie_env *e, const struct rro_fixture *f,
                         struct rro_snap *s)
{
    sqlite3 *db = progress_store_db();
    memset(s, 0, sizeof(*s));
    s->tf_cursor = tip_finalize_stage_cursor();
    rro_read_served(e, f, s);
    rro_read_cursors(db, s->cursors, sizeof(s->cursors));
    rro_read_trusted(db, f, s);
    rro_read_tf_row(db, f, s);
    s->ua_row = rro_ua_status_at(db, RRO_OLD_TIP, s->ua_status,
                                 sizeof(s->ua_status));
    if (!s->ua_row)
        snprintf(s->ua_status, sizeof(s->ua_status), "none");
    s->failures = reducer_ingest_seed_anchor_reseed_failure_count();
}

static void rro_print(const char *what, const struct rro_snap *s)
{
    printf("reducer_ingest_e2e: %s tf_cursor=%" PRIu64 " served=%d:%s "
           "trusted_base=%s%d:%s tf_log[%d]=%s:%s utxo_apply_log[%d]=%s "
           "failures=%" PRIu64 " cursors{%s}\n",
           what, s->tf_cursor, s->served_h, s->served,
           s->trusted_found ? "" : "absent:", s->trusted_h, s->trusted,
           RRO_OLD_TIP, s->tf_status, s->tf_hash, RRO_OLD_TIP, s->ua_status,
           s->failures, s->cursors);
}

/* ── shared fixture: L folded to its tip with node.db linkage rows ─────── */

static bool rro_build(struct rro_fixture *f)
{
    memset(f, 0, sizeof(*f));
    if (!branch_build(&f->L, 0x6A, RRO_OLD_N, -1, 0, NULL) ||
        !branch_build(&f->W, 0x6B, RRO_NEW_N, -1, 0, NULL))
        return false;
    for (int h = 0; h < f->W.n; h++)  /* W outweighs L at every height */
        arith_uint256_set_u64(&f->W.blocks[h].nChainWork,
                              (uint64_t)(h + 1) * 10u);
    return true;
}

static void rro_free(struct rro_fixture *f)
{
    branch_free(&f->L);
    branch_free(&f->W);
}

/* node.db holds both branches' headers: the seed gate's linkage walk reads
 * them (any header the node has accepted has such a row). */
static bool rro_node_db_open(struct node_db *ndb, const struct rro_fixture *f)
{
    if (!rru_node_db_open(ndb, &f->L))
        return false;
    for (int h = 1; h < f->W.n; h++)
        if (!rru_blocks_row(ndb, &f->W, h))
            return false;
    return true;
}

static int rro_fold_old_chain(struct rie_env *e, struct rro_fixture *f,
                              const char *label)
{
    int failures = 0;
    char name[192];
    (void)install_branch(e, &f->L);
    snprintf(name, sizeof(name), "%s: seed L proof_validate", label);
    RIE_CHECK(name, seed_proof_validate(progress_store_db(), &f->L,
                                        RRO_OLD_TIP));
    (void)rie_drain_to_convergence();
    struct rro_snap s;
    rro_snapshot(e, f, &s);
    snprintf(name, sizeof(name),
             "%s: L folded (cursor and served tip at L%d)", label,
             RRO_OLD_TIP);
    RIE_CHECK(name, s.tf_cursor == (uint64_t)RRO_OLD_TIP &&
                    s.served_h == RRO_OLD_TIP &&
                    strcmp(s.served, "L4") == 0);
    return failures;
}

/* ── the orphan scenario ──────────────────────────────────────────────── */

/* W's headers arrive (best header W6) with bodies through W4 but upstream
 * validation only through W2: the window moves to W4 (the rewind needs the
 * window to cover the old height), utxo_apply unwinds L and re-applies W1..W2,
 * tip_finalize rewinds and re-finalizes up to the validated frontier. */
static void rro_reorg_with_lagging_validation(struct rie_env *e,
                                             struct rro_fixture *f)
{
    e->ctx.active = &f->W;
    for (int h = RRO_BODIES + 1; h < f->W.n; h++)
        f->W.blocks[h].nStatus = BLOCK_VALID_TREE;  /* header only */
    for (int h = 1; h < f->W.n; h++)
        test_block_map_insert(&e->ms.map_block_index,
                              f->W.blocks[h].phashBlock, &f->W.blocks[h]);
    e->ms.pindex_best_header = &f->W.blocks[f->W.n - 1];
    active_chain_move_window_tip(&e->ms.chain_active,
                                 &f->W.blocks[RRO_BODIES]);
    (void)seed_proof_validate(progress_store_db(), &f->W, RRO_VALIDATED);
    (void)rie_drain_to_convergence();
}

/* The rest of W arrives and validates; the node drains to the end. */
static void rro_bodies_arrive(struct rie_env *e, struct rro_fixture *f)
{
    for (int h = RRO_BODIES + 1; h < f->W.n; h++)
        f->W.blocks[h].nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    active_chain_move_window_tip(&e->ms.chain_active,
                                 &f->W.blocks[f->W.n - 1]);
    (void)seed_proof_validate(progress_store_db(), &f->W, f->W.n - 1);
    (void)rie_drain_to_convergence();
}

/* The window the hazard lives in: the cursor rewound below the old height,
 * the served tip still on the orphaned L4. */
static int rro_check_rewound(const struct rro_snap *s)
{
    int failures = 0;
    RIE_CHECK("reseed-orphan: rewind leaves cursor below the served orphan L4",
              s->tf_cursor < (uint64_t)RRO_OLD_TIP &&
              s->served_h == RRO_OLD_TIP && strcmp(s->served, "L4") == 0);
    RIE_CHECK("reseed-orphan: unwind removed L4's utxo_apply row",
              !s->ua_row && !s->tf_row);
    return failures;
}

/* P1: two ingests in the window write nothing that names L4, move no cursor,
 * and each refusal is counted. */
static int rro_check_ingest_refused(const struct rro_snap *b,
                                    const struct rro_snap *a)
{
    int failures = 0;
    RIE_CHECK("reseed-orphan: ingest leaves the tip_finalize cursor alone",
              a->tf_cursor == b->tf_cursor);
    RIE_CHECK("reseed-orphan: ingest moves no upstream cursor",
              strcmp(a->cursors, b->cursors) == 0);
    RIE_CHECK("reseed-orphan: no trusted base names the orphan",
              a->trusted_found == b->trusted_found &&
              a->trusted_h == b->trusted_h &&
              strcmp(a->trusted, "L4") != 0);
    RIE_CHECK("reseed-orphan: no anchor row at the orphan height",
              !a->tf_row && !a->ua_row);
    RIE_CHECK("reseed-orphan: each refusal counted",
              a->failures == b->failures + 2);
    return failures;
}

/* P3/P6: the node still ends on W with every durable value naming W. */
static int rro_check_final(const struct rro_snap *s)
{
    int failures = 0;
    RIE_CHECK("reseed-orphan: node ends on the new branch tip W6",
              s->served_h == RRO_NEW_N - 1 && strcmp(s->served, "W6") == 0 &&
              s->tf_cursor == (uint64_t)(RRO_NEW_N - 1));
    RIE_CHECK("reseed-orphan: old-height rows name W (finalized->W5, verified)",
              strcmp(s->tf_status, "finalized") == 0 &&
              strcmp(s->tf_hash, "W5") == 0 &&
              strcmp(s->ua_status, "verified") == 0);
    RIE_CHECK("reseed-orphan: trusted base names no L block",
              !s->trusted_found || s->trusted[0] != 'L' ||
              strcmp(s->trusted, "L0") == 0);
    return failures;
}

static int rro_run_orphan_env(struct rie_env *e, struct rro_fixture *f)
{
    int failures = 0;
    struct node_db ndb;
    RIE_CHECK("reseed-orphan: node.db linkage rows for both branches",
              rro_node_db_open(&ndb, f));
    failures += rro_fold_old_chain(e, f, "reseed-orphan");

    struct rro_snap folded, rewound, reseeded, final;
    rro_snapshot(e, f, &folded);
    rro_print("reseed-orphan folded", &folded);

    rro_reorg_with_lagging_validation(e, f);
    rro_snapshot(e, f, &rewound);
    rro_print("reseed-orphan rewound", &rewound);
    failures += rro_check_rewound(&rewound);

    /* Two ingests before W re-finalizes past L4. */
    rru_run_seam(e);
    rru_run_seam(e);
    rro_snapshot(e, f, &reseeded);
    rro_print("reseed-orphan ingest", &reseeded);
    failures += rro_check_ingest_refused(&rewound, &reseeded);

    rro_bodies_arrive(e, f);
    rro_snapshot(e, f, &final);
    rro_print("reseed-orphan final", &final);
    failures += rro_check_final(&final);

    rru_node_db_close(&ndb);
    return failures;
}

static int rro_run_orphan(void)
{
    int failures = 0;
    struct rro_fixture f;
    bool built = rro_build(&f);
    struct rie_env e;
    bool opened = built && rie_env_open(&e, "reseed-orphan", &f.L, NULL, 0);
    RIE_CHECK("reseed-orphan: fixture opens", opened);
    if (opened) {
        failures += rro_run_orphan_env(&e, &f);
        rie_env_close(&e);
    }
    rro_free(&f);
    tip_finalize_stage_test_reset();
    return failures;
}

/* ── P2: the legitimate re-seed ───────────────────────────────────────── */

/* A folded node whose tip_finalize cursor is clamped behind a served tip that
 * IS on the best chain, its tip_finalize_log rows kept (the shape
 * stage_reconcile_clamp_tip_finalize_to_floor leaves): the ingest re-seed must
 * still anchor it back to the served tip. */
static int rro_check_backed_reseed(const struct rro_snap *b,
                                   const struct rro_snap *a)
{
    int failures = 0;
    RIE_CHECK("reseed-on-best-chain: clamped shape (cursor 2 < served L4)",
              b->tf_cursor == 2 && b->served_h == RRO_OLD_TIP &&
              strcmp(b->served, "L4") == 0 && !b->trusted_found);
    RIE_CHECK("reseed-on-best-chain: cursor re-seeded to the served tip",
              a->tf_cursor == (uint64_t)RRO_OLD_TIP &&
              strcmp(a->served, "L4") == 0);
    RIE_CHECK("reseed-on-best-chain: trusted base and anchor rows name L4",
              a->trusted_found && a->trusted_h == RRO_OLD_TIP &&
              strcmp(a->trusted, "L4") == 0 &&
              strcmp(a->tf_status, "anchor") == 0 &&
              strcmp(a->tf_hash, "L4") == 0);
    RIE_CHECK("reseed-on-best-chain: no failure counted",
              a->failures == b->failures);
    return failures;
}

static int rro_run_on_best_chain_env(struct rie_env *e, struct rro_fixture *f)
{
    int failures = 0;
    struct node_db ndb;
    RIE_CHECK("reseed-on-best-chain: node.db linkage rows",
              rro_node_db_open(&ndb, f));
    failures += rro_fold_old_chain(e, f, "reseed-on-best-chain");
    e->ms.pindex_best_header = &f->L.blocks[RRO_OLD_TIP];
    stage_t *tf = tip_finalize_stage_handle();
    RIE_CHECK("reseed-on-best-chain: clamp the tip_finalize cursor to 2",
              tf && stage_set_cursor(tf, progress_store_db(), 2));

    struct rro_snap before, after;
    rro_snapshot(e, f, &before);
    rro_print("reseed-on-best-chain before", &before);
    rru_run_seam(e);
    rro_snapshot(e, f, &after);
    rro_print("reseed-on-best-chain after", &after);
    failures += rro_check_backed_reseed(&before, &after);
    rru_node_db_close(&ndb);
    return failures;
}

static int rro_run_on_best_chain(void)
{
    int failures = 0;
    struct rro_fixture f;
    bool built = rro_build(&f);
    struct rie_env e;
    bool opened = built &&
                  rie_env_open(&e, "reseed-on-best-chain", &f.L, NULL, 0);
    RIE_CHECK("reseed-on-best-chain: fixture opens", opened);
    if (opened) {
        failures += rro_run_on_best_chain_env(&e, &f);
        rie_env_close(&e);
    }
    rro_free(&f);
    tip_finalize_stage_test_reset();
    return failures;
}

static int rro_run_all(void)
{
    return rro_run_orphan() + rro_run_on_best_chain();
}
