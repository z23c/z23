/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_shielded_bind_guard — the two fail-closed guards against a
 * HEIGHT-MISMATCHED shielded-history bind.
 *
 * Root cause (the manufacture these guards outlaw): -import-complete-shielded
 * binds the Sapling/Sprout frontier at the SOURCE chainstate's persisted best
 * block. A zclassicd whose on-disk chainstate lags its live tip (it had
 * stopped flushing its block DB) produced a datadir whose shielded frontier
 * sat tens of thousands of blocks BELOW the coins island root, with both
 * activation cursors flipped to 0. The fold then hard-wedged at the first
 * Sapling-commitment block above the island (fold_sapling appends to the
 * stale tree and mismatches the header-committed hashFinalSaplingRoot;
 * utxo_apply.apply_failed, H* pinned) — a silent-cause consensus-time
 * livelock. The guards turn that into a loud build-time refusal:
 *
 *   IMPORT-TIME — shielded_history_import_from_chainstate (and the verb's
 *   terminal probe) REFUSE any bind where tip_height != the fold-resume
 *   anchor (coins island root from reducer_frontier_derive_coins_best):
 *   nothing is committed, both cursors stay POSITIVE, the wedge is intact.
 *   A fresh datadir with no coins authority passes (shielded-first ordering
 *   is legal), and a bind that equals the island root imports normally.
 *
 *   BOOT-TIME — utxo_apply_anchor_bind_mismatch detects an ALREADY
 *   manufactured mismatch (cursors 0 + latest Sapling frontier row below the
 *   island root + the header-committed root at the island root MOVED) and
 *   utxo_apply_anchor_gap_blocker_refresh_with_ndb raises the NAMED
 *   permanent blocker utxo_apply.anchor_backfill_gap with both heights and
 *   the remedy, instead of clearing it into the mismatch livelock. Pure
 *   detection, no auto-repair.
 *
 * Hermetic: temp LevelDB fixture chainstates (exact zclassicd key/value
 * shapes), temp progress.kv, temp node.db — no live datadir, no chain, no
 * params. Small synthetic heights throughout. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "models/block.h"
#include "models/database.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/shielded_history_import_service.h"
#include "storage/anchor_kv.h"
#include "storage/dbwrapper.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SBG_BOUNDARY 3176326   /* the wedge height + 1 (positive cursor) */
#define SBG_TIP_H    3176325   /* the chainstate tip height == the island root
                                  in the CONSISTENT case */
#define SBG_LAG_H    (SBG_TIP_H - 100)  /* a source chainstate lagging the
                                           island by 100 blocks */

#define SBG_CHECK(name, expr) do {                          \
    printf("  shielded_bind_guard: %s... ", (name));        \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

/* ── fixture builders (same shapes as test_shielded_history_import.c) ── */

static void sbg_fill(struct uint256 *h, uint8_t seed, size_t idx)
{
    for (size_t i = 0; i < 32; i++)
        h->data[i] = (uint8_t)(seed ^ (idx * 7 + i));
}

/* A non-empty Sapling frontier of `n` synthetic commitments -> its root. */
static void sbg_sapling_tree(size_t n, struct incremental_merkle_tree *out,
                             struct uint256 *root_out)
{
    sapling_tree_init(out);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm;
        sbg_fill(&cm, 0x5A, i + 1);
        incremental_tree_append(out, &cm);
    }
    incremental_tree_root(out, root_out);
}

static void sbg_sprout_tree(size_t n, struct incremental_merkle_tree *out,
                            struct uint256 *root_out)
{
    sprout_tree_init(out);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm;
        sbg_fill(&cm, 0xA5, i + 1);
        incremental_tree_append(out, &cm);
    }
    incremental_tree_root(out, root_out);
}

/* Write one (key -> value) row into the LevelDB at `dir`. Opens/closes per
 * call: LevelDB is single-writer, so no write may overlap the reader's LOCK. */
static bool sbg_put(const char *dir, const char *key, size_t klen,
                    const void *val, size_t vlen)
{
    struct db_wrapper db;
    memset(&db, 0, sizeof(db));
    if (!db_wrapper_open(&db, dir, 1u << 20, false, false))
        return false;
    bool ok = db_write(&db, key, klen, (const char *)val, vlen, true);
    db_wrapper_close(&db);
    return ok;
}

static bool sbg_put_anchor(const char *dir, char prefix,
                           const struct incremental_merkle_tree *tree,
                           const struct uint256 *root)
{
    struct byte_stream s;
    stream_init(&s, 256);
    bool ok = incremental_tree_serialize(tree, &s) && !s.error;
    char key[33];
    key[0] = prefix;
    memcpy(key + 1, root->data, 32);
    ok = ok && sbg_put(dir, key, sizeof(key), s.data, s.size);
    stream_free(&s);
    return ok;
}

static bool sbg_put_nullifier(const char *dir, char prefix,
                              const struct uint256 *nf)
{
    char key[33];
    key[0] = prefix;
    memcpy(key + 1, nf->data, 32);
    const uint8_t present = 0x01;   /* serialized C++ `bool true` */
    return sbg_put(dir, key, sizeof(key), &present, 1);
}

static bool sbg_put_pointer(const char *dir, char key_byte,
                            const struct uint256 *root)
{
    return sbg_put(dir, &key_byte, 1, root->data, 32);
}

/* A small COMPLETE zclassicd-shaped chainstate: 3 Sapling + 2 Sprout anchor
 * frontiers (the last Sapling one designated the tip), 3+2 nullifiers, and
 * the 'z'/'a'/'B' best pointers. Fills the tip Sapling root for the caller. */
static bool sbg_build_chainstate(const char *cs_dir,
                                 struct uint256 *tip_sapling_root_out)
{
    struct incremental_merkle_tree sap_a, sap_b, sap_tip;
    struct uint256 sr_a, sr_b, sr_tip;
    sbg_sapling_tree(3, &sap_a, &sr_a);
    sbg_sapling_tree(7, &sap_b, &sr_b);
    sbg_sapling_tree(11, &sap_tip, &sr_tip);   /* designated tip frontier */
    *tip_sapling_root_out = sr_tip;

    struct incremental_merkle_tree spr_a, spr_best;
    struct uint256 pr_a, pr_best;
    sbg_sprout_tree(2, &spr_a, &pr_a);
    sbg_sprout_tree(5, &spr_best, &pr_best);

    if (!sbg_put_anchor(cs_dir, 'Z', &sap_a, &sr_a) ||
        !sbg_put_anchor(cs_dir, 'Z', &sap_b, &sr_b) ||
        !sbg_put_anchor(cs_dir, 'Z', &sap_tip, &sr_tip) ||
        !sbg_put_anchor(cs_dir, 'A', &spr_a, &pr_a) ||
        !sbg_put_anchor(cs_dir, 'A', &spr_best, &pr_best))
        return false;

    struct uint256 nf;
    for (int i = 0; i < 3; i++) {
        sbg_fill(&nf, 0x51, (size_t)i + 100);
        if (!sbg_put_nullifier(cs_dir, 'S', &nf))
            return false;
    }
    for (int i = 0; i < 2; i++) {
        sbg_fill(&nf, 0x53, (size_t)i + 200);
        if (!sbg_put_nullifier(cs_dir, 's', &nf))
            return false;
    }

    struct uint256 best_block;
    sbg_fill(&best_block, 0xBB, 999);
    return sbg_put_pointer(cs_dir, 'z', &sr_tip) &&
           sbg_put_pointer(cs_dir, 'a', &pr_best) &&
           sbg_put_pointer(cs_dir, 'B', &best_block);
}

static void sbg_best_block(struct uint256 *out)
{
    sbg_fill(out, 0xBB, 999);
}

static bool sbg_import_fixture(sqlite3 *db, const char *cs_dir,
                               int64_t tip_height,
                               const struct uint256 *tip_root,
                               struct shielded_import_report *out)
{
    struct uint256 best_block;
    sbg_best_block(&best_block);
    return shielded_history_import_from_chainstate(
        db, cs_dir, tip_height, &best_block, tip_root, out);
}

/* Seed a wedged progress.kv: both anchor pools + the nullifier marker at a
 * POSITIVE boundary, with both permanent gap blockers raised. */
static bool sbg_seed_wedge(sqlite3 *db)
{
    blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
    blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
    if (!anchor_kv_initialize_history(db, SBG_BOUNDARY) ||
        !nullifier_kv_initialize_history(db, SBG_BOUNDARY))
        return false;
    utxo_apply_anchor_gap_blocker_refresh(db);
    utxo_apply_nullifier_gap_blocker_refresh(db);
    return true;
}

/* progress.kv coins-best derivation prerequisites (mirrors the production
 * proven-authority triple + the validate_headers_log own-hash witness, same
 * shape as test_shielded_import_cured_tip_anchor.c's cta_seed_coins_best):
 *   - progress_meta.coins_applied_height  = H + 1 (LE int64 blob)
 *   - progress_meta.coins_kv_migration_complete = 1
 *   - a non-empty `coins` table
 *   - validate_headers_log row at H carrying `hash`
 * So reducer_frontier_derive_coins_best returns (H, hash). */
static bool sbg_seed_coins_best(sqlite3 *db, int32_t h,
                                const struct uint256 *hash)
{
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');"
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "  fail_reason TEXT, validated_at INTEGER);",
            NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[sbg] schema: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }

    uint8_t applied_le[8];
    int64_t applied = (int64_t)h + 1;
    for (int i = 0; i < 8; i++)
        applied_le[i] = (uint8_t)((uint64_t)applied >> (8 * i));

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, applied_le, 8, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;

    uint8_t one = 1;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log(height,hash,ok) "
            "VALUES(?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Write one connected header row into node.db at `height` with
 * blocks.sapling_root set to `sapling_root` — the column the fixed
 * --importblockindex persists from the header's hashFinalSaplingRoot, and the
 * bind guard's header evidence. */
static bool sbg_write_header_row(struct node_db *ndb, int height,
                                 const struct uint256 *sapling_root)
{
    static uint8_t sol[1] = {0};
    struct db_block b;
    memset(&b, 0, sizeof(b));
    sbg_fill((struct uint256 *)b.hash, 0xBC, (size_t)height);
    b.height = height;
    memset(b.prev_hash, 0x10, 32);
    b.version = 4;
    memset(b.merkle_root, 0x11, 32);
    b.time = 1700000000u;
    b.bits = 0x2000ffffu;
    memset(b.nonce, 0x22, 32);
    b.solution = sol;
    b.solution_len = sizeof(sol);
    b.status = BLOCK_VALID_SCRIPTS;
    b.num_tx = 1;
    memcpy(b.sapling_root, sapling_root->data, 32);
    return db_block_save(ndb, &b);
}

static int64_t sbg_count(sqlite3 *db, const char *table)
{
    char sql[96];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK)
        return -1;
    int64_t n = -1;
    if (sqlite3_step(s) == SQLITE_ROW)
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

static bool sbg_cursor_is(sqlite3 *db, int pool, int64_t want)
{
    int64_t c = -1;
    bool found = false;
    return anchor_kv_activation_cursor(db, pool, &c, &found) && found &&
           c == want;
}

/* Fetch the anchor gap blocker's reason into `out` (NULL-terminated). Returns
 * false when the blocker is absent. */
static bool sbg_gap_blocker_reason(char *out, size_t cap)
{
    struct blocker_snapshot snaps[8];
    int n = blocker_snapshot_all(snaps, 8);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID) == 0) {
            snprintf(out, cap, "%s", snaps[i].reason);
            return true;
        }
    }
    return false;
}

int test_shielded_bind_guard(void);
int test_shielded_bind_guard(void)
{
    int failures = 0;

    /* ── Scenario A: IMPORT-TIME guard — a bind BELOW the island root is
     * REFUSED with nothing committed; a fresh datadir passes the probe ── */
    {
        char cs_dir[256], pg_dir[256];
        test_make_tmpdir(cs_dir, sizeof(cs_dir), "sbg_refuse", "cs");
        test_make_tmpdir(pg_dir, sizeof(pg_dir), "sbg_refuse", "pg");

        struct uint256 tip_root;
        SBG_CHECK("build complete fixture chainstate",
                  sbg_build_chainstate(cs_dir, &tip_root));

        SBG_CHECK("progress.kv opens", progress_store_open(pg_dir));
        sqlite3 *db = progress_store_db();
        SBG_CHECK("wedge seeded (cursors positive + blockers raised)",
                  db && sbg_seed_wedge(db));

        /* Fresh datadir, no coins authority: the probe passes silently
         * (shielded-first ordering is legal). */
        int32_t cb = -1;
        SBG_CHECK("probe passes with no coins authority (fresh datadir)",
                  shielded_history_import_bind_guard_probe(db, SBG_LAG_H,
                                                           &cb));

        /* Manufacture the coins island 100 blocks ABOVE the chainstate tip
         * (the real case: source chainstate lags the island root). */
        struct uint256 island_hash;
        sbg_fill(&island_hash, 0x1C, 1);
        SBG_CHECK("coins island seeded above the chainstate tip",
                  sbg_seed_coins_best(db, SBG_TIP_H + 100, &island_hash));

        cb = -1;
        SBG_CHECK("probe REFUSES a bind below the island root",
                  !shielded_history_import_bind_guard_probe(db, SBG_TIP_H,
                                                            &cb));
        SBG_CHECK("probe reports the island root height",
                  cb == SBG_TIP_H + 100);

        struct shielded_import_report rep;
        bool ok = sbg_import_fixture(
            db, cs_dir, SBG_TIP_H, &tip_root, &rep);
        SBG_CHECK("import REFUSES the height-mismatched bind", !ok);
        SBG_CHECK("import did NOT commit", !rep.committed);

        /* nothing committed: every table empty (the tx never began) */
        SBG_CHECK("sapling_anchors empty after refusal",
                  sbg_count(db, "sapling_anchors") == 0);
        SBG_CHECK("sprout_anchors empty after refusal",
                  sbg_count(db, "sprout_anchors") == 0);
        SBG_CHECK("nullifiers empty after refusal",
                  sbg_count(db, "nullifiers") == 0);

        /* the safe wedge held: cursors still POSITIVE, blockers still up */
        SBG_CHECK("Sprout anchor cursor still positive",
                  sbg_cursor_is(db, ANCHOR_POOL_SPROUT, SBG_BOUNDARY));
        SBG_CHECK("Sapling anchor cursor still positive",
                  sbg_cursor_is(db, ANCHOR_POOL_SAPLING, SBG_BOUNDARY));
        SBG_CHECK("anchor gap blocker still raised",
                  blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID));
        SBG_CHECK("nullifier gap blocker still raised",
                  blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

        progress_store_close();
        test_rm_rf_recursive(cs_dir);
        test_rm_rf_recursive(pg_dir);
    }

    /* ── Scenario B: IMPORT-TIME guard — a bind == the island root imports ── */
    {
        char cs_dir[256], pg_dir[256];
        test_make_tmpdir(cs_dir, sizeof(cs_dir), "sbg_accept", "cs");
        test_make_tmpdir(pg_dir, sizeof(pg_dir), "sbg_accept", "pg");

        struct uint256 tip_root;
        SBG_CHECK("build complete fixture (accept scenario)",
                  sbg_build_chainstate(cs_dir, &tip_root));

        SBG_CHECK("progress.kv opens (accept)", progress_store_open(pg_dir));
        sqlite3 *db = progress_store_db();
        SBG_CHECK("wedge seeded (accept)", db && sbg_seed_wedge(db));

        /* The consistent source: chainstate best block == the island root. */
        struct uint256 island_hash;
        sbg_best_block(&island_hash);
        SBG_CHECK("coins island seeded AT the chainstate tip",
                  sbg_seed_coins_best(db, SBG_TIP_H, &island_hash));

        int32_t cb = -1;
        SBG_CHECK("probe accepts a bind == the island root",
                  shielded_history_import_bind_guard_probe(db, SBG_TIP_H,
                                                           &cb) &&
                  cb == SBG_TIP_H);

        struct uint256 foreign_best;
        sbg_fill(&foreign_best, 0xBC, 1000);
        struct shielded_import_report rep;
        bool ok = shielded_history_import_from_chainstate(
            db, cs_dir, SBG_TIP_H, &foreign_best, &tip_root, &rep);
        SBG_CHECK("import REFUSES source best block above/below target", !ok);
        SBG_CHECK("source mismatch did NOT commit", !rep.committed);
        SBG_CHECK("source mismatch left nullifiers empty",
                  sbg_count(db, "nullifiers") == 0);

        ok = sbg_import_fixture(
            db, cs_dir, SBG_TIP_H, &tip_root, &rep);
        SBG_CHECK("matching bind imports + commits",
                  ok && rep.committed && rep.tip_anchor_bound);
        SBG_CHECK("imported exactly 3 Sapling anchors",
                  rep.sapling_anchors == 3);
        SBG_CHECK("Sapling anchor cursor flipped to 0",
                  sbg_cursor_is(db, ANCHOR_POOL_SAPLING, 0));
        SBG_CHECK("anchor gap blocker cleared after consistent import",
                  !blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID));

        /* the bound frontier is selectable for the forward fold */
        {
            struct incremental_merkle_tree latest;
            struct uint256 latest_root;
            SBG_CHECK("latest Sapling frontier == tip anchor",
                      anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &latest,
                                            &latest_root, NULL) ==
                          ANCHOR_KV_FOUND &&
                      uint256_eq(&latest_root, &tip_root));
        }

        progress_store_close();
        test_rm_rf_recursive(cs_dir);
        test_rm_rf_recursive(pg_dir);
    }

    /* ── Scenario C: BOOT-TIME guard — a manufactured mismatch (cursors 0,
     * frontier keyed BELOW the island root, header root MOVED) is detected and
     * raises the NAMED permanent blocker; detection only, no auto-repair ── */
    {
        char pg_dir[256], nd_dir[256];
        test_make_tmpdir(pg_dir, sizeof(pg_dir), "sbg_boot", "pg");
        test_make_tmpdir(nd_dir, sizeof(nd_dir), "sbg_boot", "nd");

        SBG_CHECK("progress.kv opens (boot)", progress_store_open(pg_dir));
        sqlite3 *db = progress_store_db();

        /* The post-buggy-import state: both cursors 0 (complete-history
         * claim) and ONE imported frontier row keyed at the lagging bind
         * height SBG_LAG_H. */
        SBG_CHECK("cursors stamped complete (0)",
                  db && anchor_kv_ensure_schema(db) &&
                  anchor_kv_reset_mark_complete_in_tx(db));
        struct incremental_merkle_tree frontier;
        struct uint256 frontier_root;
        sbg_sapling_tree(9, &frontier, &frontier_root);
        SBG_CHECK("imported frontier row keyed at the lag height",
                  anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &frontier,
                                     SBG_LAG_H));

        /* The coins island root sits 100 blocks higher. */
        struct uint256 island_hash;
        sbg_fill(&island_hash, 0x1C, 3);
        SBG_CHECK("coins island seeded (boot)",
                  sbg_seed_coins_best(db, SBG_TIP_H, &island_hash));

        /* The header chain at the island root commits a DIFFERENT Sapling
         * root — the live chain moved over blocks the imported frontier
         * never saw. */
        char ndb_path[320];
        snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", nd_dir);
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        SBG_CHECK("node.db opens (boot)", node_db_open(&ndb, ndb_path));
        struct uint256 moved_root;
        sbg_sapling_tree(23, &frontier, &moved_root);   /* reuse tree buffer */
        SBG_CHECK("header root at the island root moved",
                  !uint256_eq(&moved_root, &frontier_root) &&
                  sbg_write_header_row(&ndb, SBG_TIP_H, &moved_root));

        /* Pure detection. */
        int64_t fh = -1;
        int32_t ch = -1;
        SBG_CHECK("bind mismatch detected on the manufactured state",
                  utxo_apply_anchor_bind_mismatch(db, &ndb, &fh, &ch));
        SBG_CHECK("detection reports the lagging frontier height",
                  fh == SBG_LAG_H);
        SBG_CHECK("detection reports the island root height",
                  ch == SBG_TIP_H);

        /* The refresh converts it into the NAMED permanent blocker. */
        blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        utxo_apply_anchor_gap_blocker_refresh_with_ndb(db, &ndb);
        SBG_CHECK("named blocker utxo_apply.anchor_backfill_gap raised",
                  blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID));
        char reason[BLOCKER_REASON_MAX];
        SBG_CHECK("blocker reason names the mismatch + both heights",
                  sbg_gap_blocker_reason(reason, sizeof(reason)) &&
                  strstr(reason, "shielded anchor height mismatch") &&
                  strstr(reason, "3176225") &&   /* SBG_LAG_H */
                  strstr(reason, "3176325"));    /* SBG_TIP_H */

        /* No auto-repair: the stored state is untouched (cursors stay 0,
         * the frontier row stays, the fold's own fail-closed root check
         * remains the backstop). */
        SBG_CHECK("no auto-repair: Sapling cursor still 0",
                  sbg_cursor_is(db, ANCHOR_POOL_SAPLING, 0));
        SBG_CHECK("no auto-repair: frontier row untouched",
                  sbg_count(db, "sapling_anchors") == 1);

        /* The global progress_store is single-directory: close the mismatch
         * fixture before the controls open their own stores. */
        node_db_close(&ndb);
        progress_store_close();

        /* CONTROL 1 — consistent datadir (frontier at the island root,
         * header root equal): no detection, blocker clears. */
        {
            char pg2[256], nd2[256];
            test_make_tmpdir(pg2, sizeof(pg2), "sbg_bootok", "pg");
            test_make_tmpdir(nd2, sizeof(nd2), "sbg_bootok", "nd");
            SBG_CHECK("progress.kv opens (control)", progress_store_open(pg2));
            sqlite3 *db2 = progress_store_db();
            struct uint256 island2_hash;
            sbg_fill(&island2_hash, 0x1C, 4);
            SBG_CHECK("control: cursors complete + island + header seeded",
                      db2 && anchor_kv_ensure_schema(db2) &&
                      anchor_kv_reset_mark_complete_in_tx(db2) &&
                      sbg_seed_coins_best(db2, SBG_TIP_H, &island2_hash));
            struct incremental_merkle_tree ctree;
            struct uint256 croot;
            sbg_sapling_tree(9, &ctree, &croot);
            SBG_CHECK("control: frontier keyed AT the island root",
                      anchor_kv_add_tree(db2, ANCHOR_POOL_SAPLING, &ctree,
                                         SBG_TIP_H));
            char ndb2_path[320];
            snprintf(ndb2_path, sizeof(ndb2_path), "%s/node.db", nd2);
            struct node_db ndb2;
            memset(&ndb2, 0, sizeof(ndb2));
            SBG_CHECK("control: node.db opens + header root matches",
                      node_db_open(&ndb2, ndb2_path) &&
                      sbg_write_header_row(&ndb2, SBG_TIP_H, &croot));
            SBG_CHECK("control: NO mismatch on a consistent datadir",
                      !utxo_apply_anchor_bind_mismatch(db2, &ndb2, NULL,
                                                       NULL));
            blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
            utxo_apply_anchor_gap_blocker_refresh_with_ndb(db2, &ndb2);
            SBG_CHECK("control: blocker stays cleared",
                      !blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID));
            node_db_close(&ndb2);
            progress_store_close();
            test_rm_rf_recursive(pg2);
            test_rm_rf_recursive(nd2);
        }

        /* CONTROL 2 — commitment-free tail: frontier BELOW the island root
         * but the header root did NOT move (no Sapling-output blocks in
         * between). This is the healthy steady state of a folded node; the
         * guard must stay silent. */
        {
            char pg3[256], nd3[256];
            test_make_tmpdir(pg3, sizeof(pg3), "sbg_boottail", "pg");
            test_make_tmpdir(nd3, sizeof(nd3), "sbg_boottail", "nd");
            SBG_CHECK("progress.kv opens (tail)", progress_store_open(pg3));
            sqlite3 *db3 = progress_store_db();
            struct uint256 island3_hash;
            sbg_fill(&island3_hash, 0x1C, 5);
            SBG_CHECK("tail: cursors complete + island seeded",
                      db3 && anchor_kv_ensure_schema(db3) &&
                      anchor_kv_reset_mark_complete_in_tx(db3) &&
                      sbg_seed_coins_best(db3, SBG_TIP_H, &island3_hash));
            struct incremental_merkle_tree ttree;
            struct uint256 troot;
            sbg_sapling_tree(9, &ttree, &troot);
            SBG_CHECK("tail: frontier keyed below the island root",
                      anchor_kv_add_tree(db3, ANCHOR_POOL_SAPLING, &ttree,
                                         SBG_LAG_H));
            char ndb3_path[320];
            snprintf(ndb3_path, sizeof(ndb3_path), "%s/node.db", nd3);
            struct node_db ndb3;
            memset(&ndb3, 0, sizeof(ndb3));
            SBG_CHECK("tail: node.db opens + header root UNMOVED",
                      node_db_open(&ndb3, ndb3_path) &&
                      sbg_write_header_row(&ndb3, SBG_TIP_H, &troot));
            SBG_CHECK("tail: NO mismatch on a commitment-free tail",
                      !utxo_apply_anchor_bind_mismatch(db3, &ndb3, NULL,
                                                       NULL));
            blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
            utxo_apply_anchor_gap_blocker_refresh_with_ndb(db3, &ndb3);
            SBG_CHECK("tail: blocker stays cleared",
                      !blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID));
            node_db_close(&ndb3);
            progress_store_close();
            test_rm_rf_recursive(pg3);
            test_rm_rf_recursive(nd3);
        }

        /* CONTROL 3 — positive cursors (the ordinary safe wedge): the bind
         * guard does not fire; the refresh raises the STANDARD backfill
         * blocker, not the mismatch one. */
        {
            char pg4[256], nd4[256];
            test_make_tmpdir(pg4, sizeof(pg4), "sbg_bootwedge", "pg");
            test_make_tmpdir(nd4, sizeof(nd4), "sbg_bootwedge", "nd");
            SBG_CHECK("progress.kv opens (wedge control)",
                      progress_store_open(pg4));
            sqlite3 *db4 = progress_store_db();
            SBG_CHECK("wedge control seeded", db4 && sbg_seed_wedge(db4));
            char ndb4_path[320];
            snprintf(ndb4_path, sizeof(ndb4_path), "%s/node.db", nd4);
            struct node_db ndb4;
            memset(&ndb4, 0, sizeof(ndb4));
            SBG_CHECK("wedge control: node.db opens",
                      node_db_open(&ndb4, ndb4_path));
            SBG_CHECK("wedge control: bind mismatch does NOT fire",
                      !utxo_apply_anchor_bind_mismatch(db4, &ndb4, NULL,
                                                       NULL));
            utxo_apply_anchor_gap_blocker_refresh_with_ndb(db4, &ndb4);
            char reason4[BLOCKER_REASON_MAX];
            SBG_CHECK("wedge control: standard backfill blocker raised",
                      sbg_gap_blocker_reason(reason4, sizeof(reason4)) &&
                      strstr(reason4, "incomplete below cursor") &&
                      !strstr(reason4, "shielded anchor height mismatch"));
            node_db_close(&ndb4);
            progress_store_close();
            test_rm_rf_recursive(pg4);
            test_rm_rf_recursive(nd4);
        }

        test_rm_rf_recursive(pg_dir);
        test_rm_rf_recursive(nd_dir);
    }

    return failures;
}
