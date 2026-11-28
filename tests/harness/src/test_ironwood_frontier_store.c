/* purpose: Exercise Ironwood checkpoint audit, replay and transactional reorg. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/test_core.h"
#include "storage/anchor_kv.h"
#include "storage/ironwood_frontier_store.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

struct test_state {
    sqlite3 *db;
    struct ironwood_checkpoint_session session;
    struct ironwood_checkpoint out;
    uint8_t parent[32], h0[32], h1[32], h2[32], h3[32];
    uint8_t empty[32], root[32], one[41], two[41];
};
static int check(const char *label, bool passed)
{
    printf("ironwood_frontier_store: %s... %s\n", label, passed ? "OK" : "FAIL");
    return passed ? 0 : 1;
}
static bool sql(sqlite3 *db, const char *text)
{ return sqlite3_exec(db, text, NULL, NULL, NULL) == SQLITE_OK; }
static int scalar(sqlite3 *db, const char *text)
{
    sqlite3_stmt *s = NULL; int out = -1;
    if (sqlite3_prepare_v2(db, text, -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW) out = sqlite3_column_int(s, 0); // raw-sql-ok:test-fixture
    sqlite3_finalize(s); return out;
}
static bool legacy_delete(void)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    bool ok = sql(db, "CREATE TABLE sprout_anchors(anchor BLOB,height INTEGER,tree BLOB);"
        "CREATE TABLE sapling_anchors(anchor BLOB,height INTEGER,tree BLOB);"
        "INSERT INTO sprout_anchors VALUES(1,2,2);") &&
        anchor_kv_delete_range(db, 2, 2) &&
        scalar(db, "SELECT COUNT(*) FROM sprout_anchors") == 0;
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}
static bool initial_progress(struct test_state *t)
{
    int64_t tip = 77, generation = 88;
    if (!ironwood_checkpoint_progress(&t->session, &tip, &generation) || tip != -1 || generation != 0) return false;
    tip = 77; generation = 88;
    return !ironwood_checkpoint_progress(&t->session, NULL, &generation) &&
        !ironwood_checkpoint_progress(&t->session, &tip, NULL) &&
        !ironwood_checkpoint_progress(&t->session, &tip, &tip) && tip == 77 && generation == 88;
}
static bool init_history(struct test_state *t)
{
    return anchor_kv_ensure_schema(t->db) && sql(t->db, "BEGIN") && ironwood_checkpoint_ensure_schema(t->db) &&
        !ironwood_checkpoint_audit(t->db, &t->session) &&
        ironwood_checkpoint_probe(t->db) == IRONWOOD_CHECKPOINT_UNINITIALIZED &&
        ironwood_checkpoint_begin_replay(t->db, t->parent, t->empty) &&
        ironwood_checkpoint_probe(t->db) == IRONWOOD_CHECKPOINT_PRESENT &&
        ironwood_checkpoint_refresh(t->db, &t->session) &&
        ironwood_checkpoint_refresh(t->db, &t->session) && initial_progress(t) &&
        ironwood_checkpoint_find_root(&t->session, 0, t->empty, &t->out) == IRONWOOD_CHECKPOINT_MISSING && t->out.height == 99;
}
static bool add_history(struct test_state *t)
{
    return ironwood_checkpoint_append(&t->session, 0, t->h0, t->parent, t->empty, 0, NULL, 0) &&
        ironwood_checkpoint_append(&t->session, 1, t->h1, t->h0, t->root, 1, t->one, sizeof(t->one)) &&
        ironwood_checkpoint_append(&t->session, 2, t->h2, t->h1, t->root, 2, t->two, sizeof(t->two)) &&
        ironwood_checkpoint_find_root(&t->session, 2, t->root, &t->out) == IRONWOOD_CHECKPOINT_FOUND && t->out.height == 1 && t->out.count == 1 &&
        ironwood_checkpoint_find_root(&t->session, 3, t->root, &t->out) == IRONWOOD_CHECKPOINT_FOUND && t->out.height == 2 && t->out.count == 2 &&
        !ironwood_checkpoint_append(&t->session, 3, t->h3, t->h2, t->empty, 2, t->two, sizeof(t->two)) &&
        !ironwood_checkpoint_append(&t->session, 4, t->h3, t->h2, t->root, 2, NULL, 0) && sql(t->db, "COMMIT");
}
static bool legacy_after_init(struct test_state *t)
{
    return !anchor_kv_delete_range(t->db, 2, 2) &&
        scalar(t->db, "SELECT COUNT(*) FROM ironwood_checkpoints") == 4 &&
        sql(t->db, "INSERT INTO sapling_anchors(anchor,height,tree) VALUES(1,2,2)");
}
static bool rolled_back_progress(struct test_state *t)
{
    int64_t tip = 77, generation = 88;
    return !ironwood_checkpoint_progress(&t->session, &tip, &generation) &&
        tip == 77 && generation == 88 &&
        ironwood_checkpoint_latest_before(&t->session, 3, &t->out) == IRONWOOD_CHECKPOINT_INCOMPLETE &&
        ironwood_checkpoint_refresh(t->db, &t->session) &&
        ironwood_checkpoint_progress(&t->session, &tip, &generation) && tip == 2 && generation == 3;
}
static bool rollback_append(struct test_state *t)
{
    int64_t tip = 77, generation = 88;
    if (ironwood_checkpoint_progress(&t->session, &tip, &generation) || tip != 77 || generation != 88) return false;
    if (!sql(t->db, "BEGIN") || !ironwood_checkpoint_progress(&t->session, &tip, &generation) || tip != 2 || generation != 3 ||
        !ironwood_checkpoint_append(&t->session, 3, t->h3, t->h2, t->root, 2, NULL, 0) ||
        !ironwood_checkpoint_progress(&t->session, &tip, &generation) || tip != 3 || generation != 4 ||
        !sql(t->db, "ROLLBACK") || !sql(t->db, "BEGIN")) return false;
    return rolled_back_progress(t);
}
static bool rollback_reorg(struct test_state *t)
{
    return anchor_kv_delete_range(t->db, 2, 2) &&
        ironwood_checkpoint_latest_before(&t->session, 3, &t->out) == IRONWOOD_CHECKPOINT_INCOMPLETE &&
        sql(t->db, "ROLLBACK") && scalar(t->db, "SELECT COUNT(*) FROM sapling_anchors") == 1 &&
        scalar(t->db, "SELECT COUNT(*) FROM ironwood_checkpoints") == 4;
}
static bool commit_reorg(struct test_state *t)
{
    return sql(t->db, "BEGIN") && ironwood_checkpoint_audit(t->db, &t->session) &&
        anchor_kv_delete_range(t->db, 2, 2) && sql(t->db, "COMMIT") &&
        scalar(t->db, "SELECT COUNT(*) FROM ironwood_checkpoints") == 3 &&
        scalar(t->db, "SELECT COUNT(*) FROM sapling_anchors") == 0;
}
static bool reopen_check(struct test_state *t, const char *path)
{
    return sqlite3_close(t->db) == SQLITE_OK && sqlite3_open(path, &t->db) == SQLITE_OK &&
        sql(t->db, "BEGIN") && ironwood_checkpoint_audit(t->db, &t->session) &&
        ironwood_checkpoint_latest_before(&t->session, 2, &t->out) == IRONWOOD_CHECKPOINT_FOUND &&
        t->out.height == 1 && t->out.count == 1 &&
        ironwood_checkpoint_latest_before(&t->session, 3, &t->out) == IRONWOOD_CHECKPOINT_INCOMPLETE && sql(t->db, "COMMIT");
}
static bool wrong_type_schema(void)
{
    static const char *names[] = {"ironwood_checkpoints", "ironwood_checkpoint_state",
        "ironwood_checkpoints_root", "ironwood_checkpoints_payload"};
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(names) / sizeof(names[0]); i++) {
        char create[128];
        int n = snprintf(create, sizeof create, "CREATE VIEW %s AS SELECT 1", names[i]);
        ok = n > 0 && (size_t)n < sizeof create && sql(db, "BEGIN") &&
            sql(db, create) && !ironwood_checkpoint_ensure_schema(db) &&
            scalar(db, "SELECT count(*) FROM sqlite_master") == 1 && sql(db, "ROLLBACK");
    }
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static bool partial_schema(struct test_state *t)
{
    return sql(t->db, "BEGIN") &&
        sql(t->db, "DROP TABLE ironwood_checkpoint_state") &&
        !ironwood_checkpoint_ensure_schema(t->db) &&
        scalar(t->db, "SELECT count(*) FROM ironwood_checkpoints") == 3 &&
        scalar(t->db, "SELECT count(*) FROM sqlite_master WHERE name='ironwood_checkpoint_state'") == 0 &&
        sql(t->db, "ROLLBACK");
}
static bool missing_index(struct test_state *t)
{
    return sql(t->db, "BEGIN") &&
        sql(t->db, "DROP INDEX ironwood_checkpoints_payload") &&
        !ironwood_checkpoint_ensure_schema(t->db) &&
        !ironwood_checkpoint_audit(t->db, &t->session) &&
        scalar(t->db, "SELECT count(*) FROM sqlite_master WHERE name='ironwood_checkpoints_payload'") == 0 &&
        sql(t->db, "ROLLBACK");
}

static bool partial_history(struct test_state *t)
{
    return sql(t->db, "BEGIN") && sql(t->db, "DELETE FROM ironwood_checkpoint_state") &&
        ironwood_checkpoint_probe(t->db) == IRONWOOD_CHECKPOINT_PROBE_ERROR &&
        !ironwood_checkpoint_begin_replay(t->db, t->parent, t->empty) && sql(t->db, "ROLLBACK");
}
static bool missing_parent(struct test_state *t)
{
    return sql(t->db, "BEGIN") && sql(t->db, "DELETE FROM ironwood_checkpoints WHERE height=1") &&
        ironwood_checkpoint_latest_before(&t->session, 2, &t->out) == IRONWOOD_CHECKPOINT_ERROR && sql(t->db, "ROLLBACK");
}
static bool rejected_audit(struct test_state *t, const char *mutation)
{
    return sql(t->db, "BEGIN") && sql(t->db, mutation) &&
        !ironwood_checkpoint_audit(t->db, &t->session) && sql(t->db, "ROLLBACK");
}
int test_ironwood_frontier_store(void)
{
    int failures = 0; char dir[512], path[600]; struct test_state t = {0};
    test_make_tmpdir(dir, sizeof(dir), "ironwood_frontier_store", "db");
    if (snprintf(path, sizeof(path), "%s/checkpoints.db", dir) < 0 || sqlite3_open(path, &t.db) != SQLITE_OK) return 1;
    t.parent[0]=1; t.h0[0]=2; t.h1[0]=3; t.h2[0]=4; t.h3[0]=5;
    t.empty[0]=9; t.root[0]=8; t.one[0]=1; t.one[1]=1; t.one[9]=1;
    t.two[0]=1; t.two[1]=2; t.two[9]=2; t.out.height=99;
    failures += check("legacy autocommit", legacy_delete());
    failures += check("explicit replay required", init_history(&t));
    failures += check("ordered duplicate roots and counts", add_history(&t));
    failures += check("initialized history requires transaction", legacy_after_init(&t));
    failures += check("rolled-back append invalidates session", rollback_append(&t));
    failures += check("transactional reorg rollback", rollback_reorg(&t));
    failures += check("transactional reorg commit", commit_reorg(&t));
    failures += check("reopen audited history", reopen_check(&t, path));
    failures += check("reserved wrong-type schema is not repaired", wrong_type_schema());
    failures += check("partial populated schema is not repaired", partial_schema(&t));
    failures += check("missing index is not repaired", missing_index(&t));
    failures += check("partial history cannot initialize", partial_history(&t));
    failures += check("missing immediate parent rejected", missing_parent(&t));
    failures += check("gap refuses audit", rejected_audit(&t, "DELETE FROM ironwood_checkpoints WHERE height=0"));
    failures += check("text blob refuses audit", rejected_audit(&t, "UPDATE ironwood_checkpoints SET block=CAST(block AS TEXT) WHERE height=0"));
    failures += check("corrupt row refuses audit", rejected_audit(&t, "UPDATE ironwood_checkpoints SET root=zeroblob(32) WHERE height=0"));
    if (t.db) sqlite3_close(t.db);
    return failures;
}
