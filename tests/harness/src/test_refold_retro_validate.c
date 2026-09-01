/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_refold_retro_validate — the ONE end-to-end fixture proving the sovereign
 * cure on a small chain: MINT a SHA3-verified anchor snapshot at height M, run
 * the production -refold-from-anchor reset to re-seed coins_kv from that anchor,
 * fold forward M->N over synthetic on-disk stage logs, and assert H* (the
 * provable tip, reducer_frontier_compute_hstar) CLIMBS from M to N with no halt.
 * Then RETROACTIVELY VALIDATE: independently re-seed a second coins_kv from the
 * SAME verified anchor, fold ONLY M->K, and assert its coins_kv_commitment at K
 * equals (a) the boundary root the M->N fold recorded at K and (b) an
 * independent snapshot commitment captured at K.
 *
 * This closes the gap the task names: existing tests prove the pieces in
 * isolation (test_refold_from_anchor_fatal: refold->authority@anchor+1, no climb;
 * test_refold_progress_floor: H* climb on synthetic logs, no verified anchor;
 * test_keystone_utxo_binding: boundary-root round-trip, no real fold) but NO
 * single test chains MINT -> refold-climb -> retro-commitment-equality.
 *
 * The fixture lowers the compiled anchor (reducer_frontier_test_set_compiled_anchor)
 * and installs a test checkpoint (checkpoints_set_sha3_override_for_test) whose
 * sha3_hash IS the real commitment of a hand-built coins_kv set, so the IDENTICAL
 * production logic runs at a handful of rows instead of 3 million. The gate is
 * H* CLIMB + commitment equality — never "booted without FATAL".
 */

#define _GNU_SOURCE
#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "chain/mmr.h"
#include "chain/utxo_snapshot_loader.h"
#include "config/boot.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* src-private test seam (witness pattern — not in a public header). */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

#define RV_CHECK(name, expr) do {                                  \
    printf("refold_retro_validate: %s... ", (name));               \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* M = the lowered anchor, N = the fold tip, K = a real MMR boundary in (M,N]. */
#define RV_ANCHOR_M ((int32_t)200)
#define RV_TIP_N    ((int32_t)400)
#define RV_RETRO_K  ((int32_t)300)   /* M < K <= N, K % 100 == 0 (a boundary) */

/* ── synthetic stage-log fold harness (the same shape boot_refold_from_anchor_reset
 *    leaves behind: 8 stage cursors at the anchor + empty *_log tables that the
 *    pipeline then fills anchor+1..tip). We fill the *_log tables + cursors by
 *    hand so reducer_frontier_compute_hstar reads an identical durable image. ── */

static void rv_synth_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
}

static bool rv_meta_is(sqlite3 *db, const char *key, const char *want)
{
    char buf[24] = {0};
    size_t len = 0;
    bool found = false;
    size_t want_len = strlen(want);
    return progress_meta_get(db, key, buf, sizeof(buf), &len, &found) &&
           found && len == want_len && memcmp(buf, want, want_len) == 0;
}

static bool rv_put_row(sqlite3 *db, const char *table, const char *hash_col,
                       int32_t height, const uint8_t hash[32], const char *status)
{
    char sql[256];
    bool profile_bound = strcmp(table, "script_validate_log") == 0 ||
                         strcmp(table, "proof_validate_log") == 0 ||
                         strcmp(table, "utxo_apply_log") == 0;
    const char *row_status = profile_bound ? "verified" : status;
    if (hash_col && row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok,%s) VALUES(?,?,1,?)",
                 table, hash_col);
    else if (hash_col)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok,%s) VALUES(?,1,?)", table, hash_col);
    else if (row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok) VALUES(?,?,1)", table);
    else
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok) VALUES(?,1)", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int col = 1;
    sqlite3_bind_int64(st, col++, height);
    if (row_status)
        sqlite3_bind_text(st, col++, row_status, -1, SQLITE_STATIC);
    if (hash_col) {
        if (hash) sqlite3_bind_blob(st, col++, hash, 32, SQLITE_STATIC);
        else      sqlite3_bind_null(st, col++);
    }
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

static bool rv_put_chain_binding(sqlite3 *db, int32_t height,
                                 const uint8_t hash[32])
{
    uint8_t parent[32];
    rv_synth_hash(parent, height - 1);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, height);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, parent, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok)
        return false;

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) VALUES(?,?,x'',x'')",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, height);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* One fully-consistent ok=1 row across every success-checked stage log at h. */
static bool rv_put_consistent(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    rv_synth_hash(hh, h);
    return rv_put_chain_binding(db, h, hh)
        && rv_put_row(db, "validate_headers_log", "hash", h, hh, NULL)
        && rv_put_row(db, "script_validate_log", "block_hash", h, hh, "ok")
        && rv_put_row(db, "body_persist_log", NULL, h, NULL, NULL)
        && rv_put_row(db, "proof_validate_log", "block_hash", h, hh, NULL)
        && rv_put_row(db, "utxo_apply_log", NULL, h, NULL, NULL)
        && rv_put_row(db, "tip_finalize_log", NULL, h, NULL, "ok");
}

static bool rv_set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    /* The production stage_cursor schema (platform/modules/util/src/stage.c) carries a
     * NOT NULL updated_at column — boot_refold_from_anchor_reset materializes
     * it, so write all three columns. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,0)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool rv_set_applied_height(sqlite3 *db, int32_t next)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
              SQLITE_OK;
    if (ok && !coins_kv_set_applied_height_in_tx(db, next))
        ok = false;
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err)
        sqlite3_free(err);
    return ok;
}

/* Force all 8 stage cursors to the upstream "next height" frame value `next`
 * (tip_finalize's served-tip cursor is normalized to next-1 = served tip). */
static bool rv_set_all_cursors(sqlite3 *db, int64_t next)
{
    return rv_set_cursor(db, "validate_headers", next)
        && rv_set_cursor(db, "body_fetch", next)
        && rv_set_cursor(db, "body_persist", next)
        && rv_set_cursor(db, "proof_validate", next)
        && rv_set_cursor(db, "script_validate", next)
        && rv_set_cursor(db, "utxo_apply", next)
        && rv_set_cursor(db, "tip_finalize", next - 1);  /* served-tip convention */
}

/* H* under progress_store_tx_lock (compute_hstar requires the caller holds it). */
static bool rv_hstar(sqlite3 *db, int32_t *out)
{
    int32_t hs = -1, sf = -1;
    progress_store_tx_lock();
    bool ok = reducer_frontier_compute_hstar(db, &hs, &sf);
    progress_store_tx_unlock();
    if (ok) *out = hs;
    return ok;
}

/* Deterministic coin: txid derived from index, one output. The set we build at M
 * is the "anchor UTXO set"; each folded block ADDS one coin (no spends keeps the
 * canonical-order commitment trivially deterministic + monotone). */
static bool rv_add_coin(sqlite3 *db, int32_t idx, int32_t height)
{
    uint8_t txid[32];
    for (int j = 0; j < 32; j++) txid[j] = (uint8_t)((0x30 + idx * 13 + j) & 0xff);
    txid[0] = (uint8_t)(idx & 0xff);
    txid[1] = (uint8_t)((idx >> 8) & 0xff);
    uint8_t script[5] = { 0x76, 0xa9, 0x14, (uint8_t)(idx & 0xff), 0x88 };
    return coins_kv_add(db, txid, /*vout=*/0, /*value=*/100000 + idx,
                        height, /*is_coinbase=*/idx == 0, script, sizeof(script));
}

/* Seed the deterministic ANCHOR coin set (the UTXO set as it stands at M). */
static bool rv_seed_anchor_set(sqlite3 *db)
{
    for (int32_t i = 0; i < 8; i++)
        if (!rv_add_coin(db, i, /*height=*/i + 1))
            return false;
    return true;
}

/* uss_iter callback: insert one snapshot record into the target coins_kv. */
struct rv_load_ctx { sqlite3 *db; bool failed; };
static bool rv_load_cb(const struct uss_record *r, void *vctx)
{
    struct rv_load_ctx *c = vctx;
    if (!coins_kv_add(c->db, r->txid, r->vout, r->value, (int32_t)r->height,
                      r->is_coinbase != 0, r->script, (size_t)r->script_len)) {
        c->failed = true;
        return false;
    }
    return true;
}

int test_refold_retro_validate(void);
int test_refold_retro_validate(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "refold_retro", "main");

    /* ── PHASE 0: lowered anchor + the ANCHOR coin set + the override checkpoint
     *    whose sha3_hash IS that set's real commitment at height M. ── */
    reducer_frontier_test_set_compiled_anchor(RV_ANCHOR_M);

    RV_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    RV_CHECK("pdb handle", pdb != NULL);
    RV_CHECK("coins_kv schema", coins_kv_ensure_schema(pdb));
    /* the *_log + stage_cursor tables the staged pipeline + compute_hstar read. */
    RV_CHECK("progress_meta ensure", progress_meta_table_ensure(pdb));
    {
        static const char *const ddl =
            "CREATE TABLE IF NOT EXISTS stage_cursor (name TEXT PRIMARY KEY,"
            "  cursor INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS header_admit_log ("
            "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
            "  parent_hash BLOB, admitted_at INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "  fail_reason TEXT, validated_at INTEGER);"
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL, block_hash BLOB);"
            "CREATE TABLE IF NOT EXISTS body_persist_log ("
            "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS proof_validate_log ("
            "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "  block_hash BLOB);"
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "  spent_count INTEGER, added_count INTEGER);"
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "  height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
            "  spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL, tip_hash BLOB);";
        char *err = NULL;
        RV_CHECK("stage-log schema",
                 sqlite3_exec(pdb, ddl, NULL, NULL, &err) == SQLITE_OK);
        if (err) sqlite3_free(err);
    }

    RV_CHECK("seed anchor coin set", rv_seed_anchor_set(pdb));
    uint8_t stale_nf[32] = {0x7a};
    RV_CHECK("seed stale explicit-complete nullifier state",
             nullifier_kv_ensure_schema(pdb) &&
             progress_meta_set(pdb, "nullifier_kv.activation_cursor",
                               "0", 1) &&
             nullifier_kv_add(pdb, stale_nf, NULLIFIER_POOL_SAPLING, 1));

    uint8_t anchor_root[32] = {0};
    RV_CHECK("anchor commitment computed", coins_kv_commitment(pdb, anchor_root) == 0);
    int64_t num_txs = 0, real_count = 0, supply = 0;
    RV_CHECK("anchor setinfo", coins_kv_setinfo(pdb, &num_txs, &real_count, &supply));

    struct sha3_utxo_checkpoint cp;
    memset(&cp, 0, sizeof(cp));
    cp.height = RV_ANCHOR_M;
    memcpy(cp.sha3_hash, anchor_root, 32);
    cp.utxo_count = (uint64_t)real_count;
    cp.total_supply = supply;
    /* a deterministic anchor block hash for the snapshot header bind check. */
    for (int i = 0; i < 32; i++) cp.block_hash[i] = (uint8_t)(0xAB ^ i);
    checkpoints_set_sha3_override_for_test(&cp);

    /* ── PHASE 1: MINT the verified anchor snapshot at M (production writer). The
     *    body SHA3 == coins_kv_commitment == cp.sha3_hash by construction, so the
     *    artifact is SHA3-verified vs the compiled checkpoint. ── */
    char snap_path[400];
    snprintf(snap_path, sizeof(snap_path), "%s/utxo-anchor.snapshot", dir);
    setenv("ZCL_MINT_ANCHOR_OUT", snap_path, 1);
    unlink(snap_path);
    {
        uint8_t out_sha3[32] = {0};
        uint64_t out_count = 0;
        int64_t out_supply = 0;
        RV_CHECK("mint snapshot written",
                 coins_kv_snapshot_write(pdb, snap_path, RV_ANCHOR_M, cp.block_hash,
                                         /*shielded=*/NULL,
                                         out_sha3, &out_count, &out_supply));
        RV_CHECK("mint body SHA3 == checkpoint root",
                 memcmp(out_sha3, cp.sha3_hash, 32) == 0);
        RV_CHECK("mint count == checkpoint count", out_count == cp.utxo_count);

        /* the snapshot is VERIFIED-REACHABLE: uss_open binds it to the checkpoint. */
        char err[128] = {0};
        struct uss_header hdr;
        struct uss_handle *h = uss_open(snap_path, /*verify_full_sha3=*/true,
                                        cp.sha3_hash, &hdr, err, sizeof(err));
        RV_CHECK("snapshot uss_open verifies vs checkpoint", h != NULL);
        if (h) {
            RV_CHECK("snapshot count == checkpoint", hdr.count == cp.utxo_count);
            RV_CHECK("snapshot height == anchor", (int32_t)hdr.height == cp.height);
            uss_close(h);
        }
    }

    /* ── PHASE 2: run the PRODUCTION -refold-from-anchor reset. It re-seeds
     *    coins_kv from the verified snapshot, HARD-ASSERTS it reproduces the
     *    checkpoint, and forces the 8 cursors to M. Assert coins_kv becomes the
     *    proven authority at M+1 (the positive-control invariant). ── */
    char ndbpath[460];
    snprintf(ndbpath, sizeof(ndbpath), "%s/node.db", dir);
    struct node_db ndb;
    RV_CHECK("node_db opens", node_db_open(&ndb, ndbpath));

    boot_refold_from_anchor_reset(&ndb);

    int32_t applied = -1;
    RV_CHECK("refold: coins_kv is proven authority",
             coins_kv_is_proven_authority(pdb, &applied));
    RV_CHECK("refold: applied frontier == anchor+1", applied == RV_ANCHOR_M + 1);
    bool stale_found = true;
    RV_CHECK("refold: nullifiers cleared with incomplete boundary",
             nullifier_kv_get(pdb, stale_nf, NULLIFIER_POOL_SAPLING,
                              &stale_found, NULL) &&
             !stale_found &&
             rv_meta_is(pdb, "nullifier_kv.activation_cursor", "200"));

    /* re-seeded set reproduces the anchor exactly (commitment + count). */
    {
        uint8_t got[32] = {0};
        RV_CHECK("refold: re-seeded commitment == anchor root",
                 coins_kv_commitment(pdb, got) == 0 &&
                 memcmp(got, anchor_root, 32) == 0);
        RV_CHECK("refold: re-seeded count == anchor count",
                 coins_kv_count(pdb) == (int64_t)cp.utxo_count);
    }

    /* Mark the from-anchor refold active so reducer_frontier_floor() holds the
     * floor AT the anchor (M) — the same flag the boot path sets after the reset.
     * (boot_refold_from_anchor_reset itself does not set it; the caller does.) */
    RV_CHECK("mark refold-from-anchor active (resume target N)",
             refold_progress_mark_started_from_anchor(pdb, RV_TIP_N));
    RV_CHECK("refold_from_anchor_active() true", refold_from_anchor_active());

    /* ── PHASE 3: PROVE H* CLIMBS M -> N. Before any fold the cursors sit at M and
     *    the *_log tables are empty above M, so H* == M (the floor). Fold forward
     *    one block at a time, filling every stage log + advancing the cursors, and
     *    recording the boundary root at each MMR boundary exactly as the live path
     *    does (tip_finalize_post_step.c:216-220). ── */
    int32_t hstar_start = -1;
    RV_CHECK("compute H* at anchor", rv_hstar(pdb, &hstar_start));
    RV_CHECK("H* starts AT the anchor (M)", hstar_start == RV_ANCHOR_M);

    bool climbed_monotone = true;
    int32_t prev = hstar_start;
    uint8_t boundary_root_at_K[32] = {0};
    bool captured_K = false;

    for (int32_t h = RV_ANCHOR_M + 1; h <= RV_TIP_N; h++) {
        /* apply block h: add one coin, then fill the stage logs + cursors. */
        bool step_ok = rv_add_coin(pdb, h, h)
                    && rv_put_consistent(pdb, h)
                    && rv_set_applied_height(pdb, h + 1)
                    && rv_set_all_cursors(pdb, h + 1);
        if (!step_ok) { climbed_monotone = false; break; }

        /* at an MMR boundary, RECORD the per-height UTXO root over the live set
         * AS IT STANDS AFTER this block — the retro-validation target. */
        if (h % MMR_COMMITMENT_INTERVAL == 0) {
            uint8_t root[32] = {0};
            if (coins_kv_commitment(pdb, root) != 0 ||
                !coins_kv_boundary_root_set(pdb, h, root)) {
                climbed_monotone = false; break;
            }
            if (h == RV_RETRO_K) {
                memcpy(boundary_root_at_K, root, 32);
                captured_K = true;
            }
        }

        int32_t hs = -1;
        if (!rv_hstar(pdb, &hs)) { climbed_monotone = false; break; }
        /* H* must track the folded tip exactly + never regress. */
        if (hs != h || hs < prev) { climbed_monotone = false; break; }
        prev = hs;
    }
    RV_CHECK("H* climbs monotonically M->N tracking the folded tip", climbed_monotone);

    int32_t hstar_end = -1;
    RV_CHECK("compute H* at tip", rv_hstar(pdb, &hstar_end));
    RV_CHECK("H* ends AT the tip (N)", hstar_end == RV_TIP_N);
    bool refold_climbs = climbed_monotone &&
                         hstar_start == RV_ANCHOR_M && hstar_end == RV_TIP_N;
    RV_CHECK("refold climbed M->N with no halt", refold_climbs);
    RV_CHECK("refold: self-folded provenance marker set",
             coins_kv_contains_refold_marker(pdb));
    {
        char reason[96] = {0};
        RV_CHECK("refold: G-SOV parts 2+3 hold at climbed tip",
                 coins_kv_tip_is_self_derived(pdb, hstar_end, reason,
                                               sizeof(reason)));
    }
    RV_CHECK("captured boundary root at K", captured_K);

    /* publish the served provable tip the cutover serve points read, then confirm
     * the lock-free cache reflects the tip — the value getblockcount would serve. */
    reducer_frontier_provable_tip_set(hstar_end);
    RV_CHECK("served provable-tip cache == tip (cutover value)",
             reducer_frontier_provable_tip_cached() == RV_TIP_N);

    /* capture the boundary root the M->N fold recorded at K from the durable
     * table (the readback the catch-up / rebuild side uses — no refold). */
    uint8_t recorded_root_at_K[32] = {0};
    {
        bool found = false;
        RV_CHECK("boundary root readback at K",
                 coins_kv_boundary_root_get(pdb, RV_RETRO_K, recorded_root_at_K,
                                            &found) && found);
    }

    /* ── PHASE 4: RETROACTIVE VALIDATION. Independently re-seed a SECOND coins_kv
     *    from the SAME verified anchor snapshot, fold ONLY M->K, and assert its
     *    commitment at K == (a) the recorded boundary root, (b) the live boundary
     *    root captured during the M->N fold. Equality proves the verified-anchor
     *    fold reproduces the stopgap state at K EXACTLY. ── */
    char dir2[256];
    test_make_tmpdir(dir2, sizeof(dir2), "refold_retro2", "main");

    progress_store_close();           /* one process-wide handle: re-point it. */
    RV_CHECK("second progress_store opens", progress_store_open(dir2));
    sqlite3 *pdb2 = progress_store_db();
    RV_CHECK("pdb2 handle", pdb2 != NULL);
    RV_CHECK("pdb2 coins_kv schema", coins_kv_ensure_schema(pdb2));

    /* Re-seed pdb2 from the SAME minted, SHA3-verified snapshot (uss_open binds it
     * to the checkpoint root before a single coin lands). */
    {
        char err[128] = {0};
        struct uss_header hdr;
        struct uss_handle *h = uss_open(snap_path, /*verify_full_sha3=*/true,
                                        cp.sha3_hash, &hdr, err, sizeof(err));
        RV_CHECK("retro: snapshot re-open verifies", h != NULL);
        bool loaded = (h != NULL);
        if (h) {
            struct rv_load_ctx lc = { .db = pdb2 };
            int64_t emitted = uss_iter(h, rv_load_cb, &lc);
            loaded = !lc.failed && emitted == (int64_t)hdr.count;
            uss_close(h);
        }
        RV_CHECK("retro: re-seeded from verified anchor", loaded);
    }
    /* the independent re-seed reproduces the anchor commitment exactly. */
    {
        uint8_t got[32] = {0};
        RV_CHECK("retro: independent seed commitment == anchor root",
                 coins_kv_commitment(pdb2, got) == 0 &&
                 memcmp(got, anchor_root, 32) == 0);
    }

    /* Fold ONLY M->K on pdb2, applying the IDENTICAL per-block coin the M->N fold
     * applied (rv_add_coin(h,h)) — the canonical UTXO set at K must be identical. */
    bool fold2_ok = true;
    for (int32_t h = RV_ANCHOR_M + 1; h <= RV_RETRO_K; h++)
        if (!rv_add_coin(pdb2, h, h)) { fold2_ok = false; break; }
    RV_CHECK("retro: independent fold M->K", fold2_ok);

    uint8_t refold_root_at_K[32] = {0};
    RV_CHECK("retro: commitment at K computed",
             coins_kv_commitment(pdb2, refold_root_at_K) == 0);

    bool match_recorded =
        memcmp(refold_root_at_K, recorded_root_at_K, 32) == 0;
    bool match_live =
        captured_K && memcmp(refold_root_at_K, boundary_root_at_K, 32) == 0;
    RV_CHECK("retro: independent commitment == recorded boundary root at K",
             match_recorded);
    RV_CHECK("retro: independent commitment == live boundary root at K",
             match_live);

    bool retro_matches = match_recorded && match_live;

    /* NEGATIVE control: a state-wrong coin at K must CHANGE the commitment, so the
     * retro-validation could NOT spuriously pass on a corrupted set. */
    {
        const int32_t idx = 5;  /* same derivation as rv_add_coin(idx, ...) */
        uint8_t txid[32];
        for (int j = 0; j < 32; j++) txid[j] = (uint8_t)((0x30 + idx * 13 + j) & 0xff);
        txid[0] = (uint8_t)(idx & 0xff);
        txid[1] = (uint8_t)((idx >> 8) & 0xff);
        (void)coins_kv_spend(pdb2, txid, 0);
        uint8_t mutated[32] = {0};
        bool ok = coins_kv_commitment(pdb2, mutated) == 0;
        RV_CHECK("retro neg-control: mutating a coin changes the commitment",
                 ok && memcmp(mutated, refold_root_at_K, 32) != 0);
    }

    bool full_flow = refold_climbs && retro_matches;
    RV_CHECK("FULL FLOW: mint -> refold-climb -> retro-validate", full_flow);

    /* ── teardown ── */
    checkpoints_set_sha3_override_for_test(NULL);
    reducer_frontier_test_set_compiled_anchor(-1);
    refold_progress_test_set_cached(false);
    reducer_frontier_provable_tip_reset();
    unsetenv("ZCL_MINT_ANCHOR_OUT");
    node_db_close(&ndb);
    progress_store_close();
    test_cleanup_tmpdir(dir2);
    test_cleanup_tmpdir(dir);

    if (failures == 0)
        printf("test_refold_retro_validate: ALL PASSED "
               "(H* %d->%d, retro match=%d)\n",
               hstar_start, hstar_end, retro_matches);
    else
        printf("test_refold_retro_validate: %d FAILURE(S)\n", failures);
    return failures;
}
