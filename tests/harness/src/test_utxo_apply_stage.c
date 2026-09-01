/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Unit tests for Wave S S-8 utxo_apply stage. */

#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "controllers/agent_security_posture.h"
#include "core/uint256.h"
#include "json/json.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/incremental_merkle_tree.h"
#include "jobs/created_outputs_index.h"
#include "jobs/reducer_frontier.h"
#include "jobs/utxo_apply_batch_commit.h"
#include "jobs/utxo_apply_history_hold.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

/* src-private: the select-idle reason enum + note fn under test (Task A #1). */
#include "../../../engine/jobs/src/utxo_apply_stage_internal.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define UV_CHECK(name, expr) do { \
    printf("utxo_apply: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Rewind primitives under test in the nullifier rewind case (f). Mirrors
 * engine/jobs/src/utxo_apply_delta_internal.h (a src-private header). */
bool utxo_apply_emit_inverse_delta(sqlite3 *db, int height);
bool utxo_apply_delete_rows_above(sqlite3 *db, int first_h, int last_h);
bool utxo_apply_unwind_write_cursor(sqlite3 *db, uint64_t value);

enum uv_fail_kind {
    UV_FAIL_NONE = 0,
    UV_FAIL_UNKNOWN,
    UV_FAIL_COLLISION,
    UV_FAIL_OVERFLOW,
};

struct external_utxo {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
};

struct synth_chain_uv {
    struct block_index *blocks;
    struct uint256     *hashes;
    struct block       *bodies;
    struct external_utxo *ext;
    int                 n;
    int                 upstream_fail_height;
    int                 read_calls;
    int                 read_fail_height;  /* fake_reader() fails here */
    enum uv_fail_kind   fail_kind;
};

static int mkdir_p_uv(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void synthetic_txid(struct uint256 *out, int h, int salt)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0x80 + h);
    out->data[1] = (uint8_t)salt;
}

static bool make_tx(struct transaction *tx, int h, bool coinbase,
                    const struct uint256 *prev, int64_t in_value,
                    int64_t out_value)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1)) return false;
    if (coinbase) {
        outpoint_set_null(&tx->vin[0].prevout);
    } else {
        tx->vin[0].prevout.hash = *prev;
        tx->vin[0].prevout.n = 0;
        (void)in_value;
    }
    tx->vout[0].value = out_value;
    tx->vout[0].script_pub_key.size = 0;
    synthetic_txid(&tx->hash, h, coinbase ? 1 : 2);
    return true;
}

static bool uv_security_posture_nullifier_gap(bool expect_gap,
                                              int64_t expect_cursor)
{
    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    agent_push_security_posture_json(&root, "security_posture", NULL);
    const struct json_value *posture = json_get(&root, "security_posture");
    bool ok = posture && posture->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(posture, "schema")),
                      "zcl.security_posture.v1") == 0;
    ok = ok && json_get_bool(json_get(posture, "nullifier_backfill_gap")) ==
        expect_gap;
    ok = ok && json_get_int(json_get(posture,
                                     "nullifier_activation_cursor")) ==
        expect_cursor;
    ok = ok && json_get_bool(json_get(posture,
                                      "nullifier_history_complete")) ==
        !expect_gap;
    if (expect_gap) {
        ok = ok && strcmp(json_get_str(json_get(posture, "status")),
                          "review_required_nullifier_backfill_gap") == 0;
        ok = ok && strcmp(json_get_str(json_get(posture, "next_action")),
                          "run_shielded_history_backfill_or_from_genesis_refold")
            == 0;
    }
    json_free(&root);
    return ok;
}

static bool uv_security_posture_anchor_gap(bool expect_gap,
                                           int64_t expect_sapling_cursor)
{
    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    agent_push_security_posture_json(&root, "security_posture", NULL);
    const struct json_value *posture = json_get(&root, "security_posture");
    bool ok = posture && posture->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(posture, "anchor_backfill_gap")) ==
        expect_gap;
    ok = ok && json_get_int(json_get(
        posture, "sapling_anchor_activation_cursor")) ==
        expect_sapling_cursor;
    ok = ok && json_get_bool(json_get(posture,
                                      "anchor_history_complete")) ==
        !expect_gap;
    if (expect_gap)
        ok = ok && strcmp(json_get_str(json_get(posture, "status")),
                          "review_required_anchor_backfill_gap") == 0;
    json_free(&root);
    return ok;
}

static bool make_body(struct synth_chain_uv *sc, int h)
{
    struct block *b = &sc->bodies[h];
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700002000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 2;
    b->vtx = zcl_calloc(2, sizeof(struct transaction), "uv_tx");
    if (!b->vtx) return false;

    struct uint256 prev;
    synthetic_txid(&prev, h, 9);
    sc->ext[h].txid = prev;
    sc->ext[h].vout = 0;
    sc->ext[h].value = 1000 + h;

    if (!make_tx(&b->vtx[0], h, true, NULL, 0, 50 + h)) return false;
    int64_t out_value = (sc->fail_kind == UV_FAIL_OVERFLOW && h == 1)
        ? 5000 : 900 + h;
    if (!make_tx(&b->vtx[1], h, false, &prev, sc->ext[h].value, out_value))
        return false;
    struct uint256 txids[2] = { b->vtx[0].hash, b->vtx[1].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    return true;
}

/* Turn one not-yet-applied synthetic block into the production incident's
 * exact safe-repair shape: coinbase plus no transparent-input transaction.
 * The caller uses a two-block chain, so changing the final block hash cannot
 * invalidate a successor link. */
static bool uv_make_block_coinbase_only(struct synth_chain_uv *sc, int h)
{
    if (!sc || h < 0 || h >= sc->n || sc->bodies[h].num_vtx != 2)
        return false;
    struct block *blk = &sc->bodies[h];
    transaction_free(&blk->vtx[1]);
    blk->num_vtx = 1;
    blk->header.hashMerkleRoot = blk->vtx[0].hash;
    block_header_get_hash(&blk->header, &sc->hashes[h]);
    sc->blocks[h].hashMerkleRoot = blk->header.hashMerkleRoot;
    return true;
}

static bool synth_chain_uv_build(struct synth_chain_uv *sc, int n)
{
    sc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index),
                            "uv_blocks");
    sc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256),
                            "uv_hashes");
    sc->bodies = zcl_calloc((size_t)n, sizeof(struct block),
                            "uv_bodies");
    sc->ext = zcl_calloc((size_t)n, sizeof(struct external_utxo),
                         "uv_ext");
    if (!sc->blocks || !sc->hashes || !sc->bodies || !sc->ext)
        return false;
    sc->read_fail_height = -1;
    for (int i = 0; i < n; i++) {
        if (!make_body(sc, i)) return false;
        if (i > 0)
            sc->bodies[i].header.hashPrevBlock = sc->hashes[i - 1];
        block_header_get_hash(&sc->bodies[i].header, &sc->hashes[i]);
        block_index_init(&sc->blocks[i]);
        sc->blocks[i].phashBlock = &sc->hashes[i];
        sc->blocks[i].hashMerkleRoot = sc->bodies[i].header.hashMerkleRoot;
        sc->blocks[i].nHeight = i;
        sc->blocks[i].nVersion = sc->bodies[i].header.nVersion;
        sc->blocks[i].nTime = sc->bodies[i].header.nTime;
        sc->blocks[i].nBits = sc->bodies[i].header.nBits;
        sc->blocks[i].nStatus = BLOCK_HAVE_DATA;
        if (i > 0) sc->blocks[i].pprev = &sc->blocks[i - 1];
    }
    sc->n = n;
    return true;
}

static void synth_chain_uv_free(struct synth_chain_uv *sc)
{
    if (sc->bodies) {
        for (int i = 0; i < sc->n; i++)
            block_free(&sc->bodies[i]);
    }
    free(sc->blocks);
    free(sc->hashes);
    free(sc->bodies);
    free(sc->ext);
    memset(sc, 0, sizeof(*sc));
}

static bool fake_reader(struct block *out, const struct block_index *bi,
                        const char *datadir, void *user)
{
    (void)datadir;
    struct synth_chain_uv *sc = user;
    if (!out || !bi || !sc || bi->nHeight < 0 || bi->nHeight >= sc->n)
        return false;
    if (bi->nHeight == sc->read_fail_height)
        return false;  /* simulate on-disk bytes vanished/corrupted */
    sc->read_calls++;
    return test_block_copy(out, &sc->bodies[bi->nHeight], "uv_tx_copy");
}

static bool fake_lookup(const struct uint256 *txid, uint32_t vout,
                        struct utxo_apply_lookup *out, void *user)
{
    struct synth_chain_uv *sc = user;
    memset(out, 0, sizeof(*out));
    if (!sc) return true;
    if (sc->fail_kind == UV_FAIL_COLLISION &&
        uint256_eq(txid, &sc->bodies[1].vtx[1].hash) && vout == 0) {
        out->found = true;
        out->value = 1;
        return true;
    }
    if (sc->fail_kind == UV_FAIL_UNKNOWN &&
        uint256_eq(txid, &sc->ext[1].txid) && vout == sc->ext[1].vout)
        return true;
    for (int i = 0; i < sc->n; i++) {
        if (sc->ext[i].vout == vout && uint256_eq(&sc->ext[i].txid, txid)) {
            out->found = true;
            out->value = sc->ext[i].value;
            return true;
        }
    }
    return true;
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

/* Count created_outputs rows at `height` (lane-A1 prune subtest). */
static int co_rows_at(sqlite3 *db, int height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM created_outputs WHERE height=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, height);
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static bool seed_proof_validate(sqlite3 *db, const struct synth_chain_uv *sc,
                                int n, int upstream_fail_height)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height                  INTEGER PRIMARY KEY,"
        "  status                  TEXT    NOT NULL,"
        "  ok                      INTEGER NOT NULL,"
        "  sapling_spends_total    INTEGER NOT NULL,"
        "  sapling_outputs_total   INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL,"
        "  block_hash              BLOB,"
        "  first_failure_txid      BLOB,"
        "  first_failure_proof_type TEXT,"
        "  validated_at            INTEGER NOT NULL"
        ")"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO proof_validate_log "
        "(height, status, ok, sapling_spends_total, sapling_outputs_total, "
        " sprout_joinsplits_total, block_hash, validated_at) "
        "VALUES (?, ?, ?, 0, 0, 0, ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < n; h++) {
        int ok = (h == upstream_fail_height) ? 0 : 1;
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_text(st, 2, ok ? "verified" : "proof_invalid",
                          -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 3, ok);
        sqlite3_bind_blob(st, 4, sc->hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);

    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES('proof_validate', ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, n);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool set_proof_validate_hash(sqlite3 *db, int height,
                                    const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE proof_validate_log SET block_hash=? WHERE height=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    int bind_rc = hash ? sqlite3_bind_blob(st, 1, hash->data, 32,
                                           SQLITE_STATIC)
                       : sqlite3_bind_null(st, 1);
    bool ok = bind_rc == SQLITE_OK &&
              sqlite3_bind_int(st, 2, height) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

/* Seed a script_validate_log verdict row hash-bound to `hash` (the table is
 * ensured by utxo_apply_stage_init, so seeding after uv_setup is valid). */
static bool seed_script_validate_row(sqlite3 *db, int height, int ok,
                                     const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO script_validate_log "
        "(height, status, ok, tx_count, input_count, validated_at, "
        " block_hash) VALUES (?, 'verified', ?, 1, 1, 1, ?)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

static bool seed_tip_finalize_anchor_row(sqlite3 *db, int height,
                                         const struct uint256 *hash)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height           INTEGER PRIMARY KEY,"
        "  status           TEXT    NOT NULL,"
        "  ok               INTEGER NOT NULL,"
        "  work_delta_high  INTEGER NOT NULL,"
        "  work_delta_low   INTEGER NOT NULL,"
        "  utxo_size_after  INTEGER NOT NULL,"
        "  reorg_depth      INTEGER NOT NULL,"
        "  finalized_at     INTEGER NOT NULL,"
        "  tip_hash         BLOB"
        ")"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO tip_finalize_log "
        "(height, status, ok, work_delta_high, work_delta_low, "
        " utxo_size_after, reorg_depth, finalized_at, tip_hash) "
        "VALUES (?, 'anchor', 1, 0, 0, -1, 0, 1, ?)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

static bool uv_write_body_to_disk(struct synth_chain_uv *sc, int height)
{
    if (!sc || height < 0 || height >= sc->n)
        return false;
    char datadir[512];
    GetDataDir(true, datadir, sizeof(datadir));
    if (mkdir_p_uv(datadir) != 0)
        return false;
    char blocks_dir[640];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", datadir);
    if (mkdir_p_uv(blocks_dir) != 0)
        return false;

    const unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    if (!write_block_to_disk(&sc->bodies[height], &pos, datadir, msg_start))
        return false;
    sc->blocks[height].nFile = pos.nFile;
    sc->blocks[height].nDataPos = pos.nPos;
    return true;
}

static bool log_row_at(sqlite3 *db, int height, int *out_ok,
                       char *out_status, size_t status_size,
                       char *out_kind, size_t kind_size)
{
    *out_ok = -1;
    if (out_status && status_size) out_status[0] = 0;
    if (out_kind && kind_size) out_kind[0] = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status, first_failure_kind "
        "FROM utxo_apply_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out_ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt && out_status && status_size)
            snprintf(out_status, status_size, "%s", (const char *)txt);
        const unsigned char *kind = sqlite3_column_text(st, 2);
        if (kind && out_kind && kind_size)
            snprintf(out_kind, kind_size, "%s", (const char *)kind);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

static int uv_setup(const char *tag, int n, enum uv_fail_kind fail_kind,
                    int upstream_fail_height, char *dir_out,
                    size_t dir_out_size, struct main_state *ms,
                    struct synth_chain_uv *sc)
{
    test_fmt_tmpdir(dir_out, dir_out_size, "utxo_apply", tag);
    mkdir_p_uv("./test-tmp");
    mkdir_p_uv(dir_out);
    SetDataDir(dir_out);
    if (!progress_store_open(dir_out)) return 1;
    /* address_index / txindex projection co-writers use the projection handle;
     * open it too so any projection tick in the harness has a store. The
     * created_outputs prune itself now runs on the kernel handle (A3 flip —
     * created_outputs lives in consensus.db). */
    if (!projection_store_open(dir_out)) return 1;

    memset(sc, 0, sizeof(*sc));
    sc->fail_kind = fail_kind;
    sc->upstream_fail_height = upstream_fail_height;
    memset(ms, 0, sizeof(*ms));
    active_chain_init(&ms->chain_active);
    block_map_init(&ms->map_block_index);
    if (!synth_chain_uv_build(sc, n)) return 2;
    active_chain_move_window_tip(&ms->chain_active, &sc->blocks[n - 1]);

    if (!seed_proof_validate(progress_store_db(), sc, n,
                             upstream_fail_height))
        return 3;
    if (!utxo_apply_stage_init(ms)) return 4;
    for (int h = 0; h < n; h++) {
        if (!seed_script_validate_row(progress_store_db(), h, 1,
                                      &sc->hashes[h]))
            return 5;
    }
    utxo_apply_stage_set_reader(fake_reader, sc);
    utxo_apply_stage_set_lookup(fake_lookup, sc);
    return 0;
}

static void uv_teardown(const char *dir, struct main_state *ms,
                        struct synth_chain_uv *sc)
{
    utxo_apply_stage_shutdown();
    active_chain_free(&ms->chain_active);
    block_map_free(&ms->map_block_index);
    synth_chain_uv_free(sc);
    projection_store_close();
    progress_store_close();
    SetDataDir("");
    ClearDataDirCache();
    test_cleanup_tmpdir(dir);
}

/* ── Shielded-nullifier (C-3) helpers ──────────────────────────────────
 * Bodies are mutated AFTER uv_setup (the fake reader deep-copies them at
 * drain time, and the synthetic tx hashes / merkle wiring do not cover
 * shielded data, so post-build mutation is safe). */

static void uv_nf_bytes(uint8_t out[32], uint8_t a, uint8_t b)
{
    memset(out, 0, 32);
    out[0] = a;
    out[1] = b;
}

/* Attach `n` Sapling spends whose nullifiers are (tags[i], mark). */
static bool uv_add_sapling_spends(struct transaction *tx,
                                  const uint8_t *tags, size_t n,
                                  uint8_t mark)
{
    tx->v_shielded_spend =
        zcl_calloc(n, sizeof(struct spend_description), "uv_sap");
    if (!tx->v_shielded_spend) return false;
    tx->num_shielded_spend = n;
    struct incremental_merkle_tree empty;
    struct uint256 empty_root;
    sapling_tree_init(&empty);
    incremental_tree_root(&empty, &empty_root);
    for (size_t i = 0; i < n; i++) {
        /* Keep the synthetic proof fixture anchored to a protocol-defined
         * active root so this nullifier test reaches the predicate it owns. */
        tx->v_shielded_spend[i].anchor = empty_root;
        tx->v_shielded_spend[i].nullifier.data[0] = tags[i];
        tx->v_shielded_spend[i].nullifier.data[1] = mark;
    }
    return true;
}

/* Attach ONE JoinSplit (vpub_old = vpub_new = 0, money-neutral) whose two
 * Sprout nullifiers are (tag0, mark) and (tag1, mark). */
static bool uv_add_joinsplit_nfs(struct transaction *tx, uint8_t tag0,
                                 uint8_t tag1, uint8_t mark)
{
    tx->v_joinsplit =
        zcl_calloc(1, sizeof(struct js_description), "uv_js");
    if (!tx->v_joinsplit) return false;
    tx->num_joinsplit = 1;
    struct incremental_merkle_tree empty;
    sprout_tree_init(&empty);
    incremental_tree_root(&empty, &tx->v_joinsplit[0].anchor);
    tx->v_joinsplit[0].nullifiers[0].data[0] = tag0;
    tx->v_joinsplit[0].nullifiers[0].data[1] = mark;
    tx->v_joinsplit[0].nullifiers[1].data[0] = tag1;
    tx->v_joinsplit[0].nullifiers[1].data[1] = mark;
    return true;
}

/* Append a bare tx (no vin/vout — money-neutral shielded-data carrier) to a
 * built body, for the intra-block cross-tx duplicate case. The existing vtx
 * array is shallow-moved: inner pointers transfer; the old array is released
 * with plain free (no per-tx free), so nothing double-frees at block_free. */
static bool uv_append_bare_tx(struct block *b, int h)
{
    struct transaction *nv =
        zcl_calloc(b->num_vtx + 1, sizeof(*nv), "uv_tx3");
    if (!nv) return false;
    memcpy(nv, b->vtx, b->num_vtx * sizeof(*nv));
    free(b->vtx);
    b->vtx = nv;
    struct transaction *tx = &b->vtx[b->num_vtx];
    transaction_init(tx);
    synthetic_txid(&tx->hash, h, 3);
    b->num_vtx++;
    return true;
}

/* COUNT(*) of nullifier rows revealed at `height`. -1 on error. */
static int64_t uv_nf_rows_at(sqlite3 *db, int height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM nullifiers WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, height);
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int64_t uv_table_rows_at(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM %s WHERE height = ?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, height);
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* COUNT(*) of canonical coin rows created at `height`. -1 on error. */
static int64_t uv_coin_rows_at(sqlite3 *db, int height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM coins WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, height);
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* True iff the utxo_apply.apply_failed blocker reason contains `needle`
 * (block_apply_failure embeds "status=... kind=..." in the reason). */
static bool uv_blocker_reason_has(const char *needle)
{
    struct blocker_snapshot snaps[16];
    int n = blocker_snapshot_all(snaps, 16);
    for (int i = 0; i < n; i++)
        if (strcmp(snaps[i].id, "utxo_apply.apply_failed") == 0 &&
            strstr(snaps[i].reason, needle) != NULL)
            return true;
    return false;
}

static bool uv_blocker_fire_count(const char *id, uint32_t *count_out)
{
    struct blocker_snapshot snaps[16];
    int n = blocker_snapshot_all(snaps, 16);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, id) == 0) {
            if (count_out) *count_out = snaps[i].fire_count;
            return true;
        }
    }
    return false;
}

static bool uv_meta_is(sqlite3 *db, const char *key, const char *want)
{
    char buf[24] = {0};
    size_t len = 0;
    bool found = false;
    size_t want_len = strlen(want);
    return progress_meta_get(db, key, buf, sizeof(buf), &len, &found) &&
           found && len == want_len && memcmp(buf, want, want_len) == 0;
}

/* True iff the utxo_apply dump_state JSON contains `needle` — the counter
 * surface for statuses without a public accessor (mirrors native dumpstate). */
static bool uv_dump_has(const char *needle)
{
    struct json_value v;
    json_init(&v);
    bool ok = utxo_apply_dump_state_json(&v, NULL);
    char buf[2048];
    size_t n = json_write(&v, buf, sizeof(buf));
    json_free(&v);
    return ok && n > 0 && n < sizeof(buf) && strstr(buf, needle) != NULL;
}

static void run_fail_case(int *failures_out, enum uv_fail_kind kind,
                          const char *expected_status,
                          uint64_t (*counter)(void))
{
    int failures = 0;
    char dir[256]; struct main_state ms; struct synth_chain_uv sc;
    blocker_clear("utxo_apply.apply_failed");
    UV_CHECK("failure: setup",
             uv_setup(expected_status, 3, kind, -1, dir, sizeof(dir),
                      &ms, &sc) == 0);
    UV_CHECK("failure: drains until failed height", utxo_apply_stage_drain(100) == 1);
    UV_CHECK("failure: counter == 1", counter() == 1);
    int ok = -1; char status[32]; char kindbuf[32];
    bool found = log_row_at(progress_store_db(), 1, &ok, status, sizeof(status),
                            kindbuf, sizeof(kindbuf));
    UV_CHECK("failure: h=1 row rolled back", !found && ok == -1);
    UV_CHECK("failure: cursor held at h=1", utxo_apply_stage_cursor() == 1);
    UV_CHECK("failure: typed blocker recorded",
             blocker_exists("utxo_apply.apply_failed"));
    /* A block that FAILED utxo_apply must never report success: this is what
     * keeps reducer_pending_body_is_accepted from accepting a stateful-invalid
     * block. The failed verdict blocks and rolls back its scratch row, so no
     * ok=0 row can masquerade as an applied height. */
    UV_CHECK("failure: succeeded_at(1) false (no committed row)",
             !utxo_apply_stage_succeeded_at(1));
    /* CS-F4: the blocked height recomputes every tick (retry semantics), but
     * the per-status total counts BLOCKS — a retry tick of the unchanged
     * (height,status) pair must not inflate it. */
    UV_CHECK("failure: retry tick stays BLOCKED",
             utxo_apply_stage_step_once() == JOB_BLOCKED);
    UV_CHECK("failure: counter still 1 after retry tick", counter() == 1);
    blocker_clear("utxo_apply.apply_failed");
    uv_teardown(dir, &ms, &sc);
    *failures_out += failures;
}

int test_utxo_apply_stage(void);
int test_utxo_apply_stage(void)
{
    printf("\n=== utxo_apply_stage tests ===\n");
    int failures = 0;

    blocker_module_init();

    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("happy: setup",
                 uv_setup("happy", 3, UV_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        UV_CHECK("happy: drains 3", utxo_apply_stage_drain(100) == 3);
        UV_CHECK("happy: one reorg audit per batch",
                 utxo_apply_stage_reorg_audit_total() == 1);
        UV_CHECK("happy: cursor at 3", utxo_apply_stage_cursor() == 3);
        UV_CHECK("happy: verified_total == 3",
                 utxo_apply_stage_verified_total() == 3);
        UV_CHECK("happy: added_total == 6",
                 utxo_apply_stage_outputs_added_total() == 6);
        UV_CHECK("happy: spent_total == 3",
                 utxo_apply_stage_outputs_spent_total() == 3);
        for (int h = 0; h < 3; h++) {
            int ok = -1; char status[32]; char kind[32];
            log_row_at(progress_store_db(), h, &ok, status, sizeof(status),
                       kind, sizeof(kind));
            UV_CHECK("happy: row ok=1", ok == 1);
            UV_CHECK("happy: row status verified",
                     strcmp(status, "verified") == 0);
            UV_CHECK("happy: failure kind null", kind[0] == 0);
        }
        /* The reducer front door (reducer_pending_body_is_accepted) gates
         * acceptance of an un-finalizable tip on this accessor: an applied
         * (ok=1) height reports success; an un-applied height and a negative
         * height report failure. This is the consensus gate added to close the
         * accept-on-HAVE_DATA hole. */
        UV_CHECK("happy: succeeded_at(2) true",
                 utxo_apply_stage_succeeded_at(2));
        UV_CHECK("happy: succeeded_at(99) false (no row)",
                 !utxo_apply_stage_succeeded_at(99));
        UV_CHECK("happy: succeeded_at(-1) false",
                 !utxo_apply_stage_succeeded_at(-1));
        UV_CHECK("happy: next step IDLE",
                 utxo_apply_stage_step_once() == JOB_IDLE);
        uv_teardown(dir, &ms, &sc);
    }

    /* lane/stall-taxonomy audit: stage_body_read_hold. proof_validate /
     * script_validate already verified this body's hash+merkle root (they
     * co-sign height+hash before utxo_apply ever reads it), so a
     * stage_read_block() failure here is on-disk damage, not a normal
     * wait — it must name a typed TRANSIENT blocker
     * "utxo_apply.body_read_failed" immediately, exactly like the sibling
     * script_validate / proof_validate stages, instead of holding on only
     * the WARN-throttled utxo_apply_select_idle_note diagnostic. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("body_read_failed: setup",
                 uv_setup("body_read_failed", 3, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        sc.read_fail_height = 1;
        UV_CHECK("body_read_failed: drains only up to the hole",
                 utxo_apply_stage_drain(100) == 1);
        UV_CHECK("body_read_failed: cursor held at the hole (1)",
                 utxo_apply_stage_cursor() == 1);
        UV_CHECK("body_read_failed: next step stays JOB_IDLE",
                 utxo_apply_stage_step_once() == JOB_IDLE);

        struct blocker_snapshot rf_snaps[16];
        int rf_n = blocker_snapshot_all(rf_snaps, 16);
        bool rf_found = false, rf_fields_ok = false;
        for (int k = 0; k < rf_n; k++) {
            if (strcmp(rf_snaps[k].id, "utxo_apply.body_read_failed") == 0) {
                rf_found = true;
                rf_fields_ok = strstr(rf_snaps[k].reason, "height=1") &&
                               rf_snaps[k].class == BLOCKER_TRANSIENT;
                break;
            }
        }
        UV_CHECK("body_read_failed: typed blocker raised", rf_found);
        UV_CHECK("body_read_failed: blocker names height + class TRANSIENT",
                 rf_fields_ok);

        int ok2 = -1; char status2[32]; char kind2[32];
        UV_CHECK("body_read_failed: no terminal row written at the hole",
                 !log_row_at(progress_store_db(), 1, &ok2, status2,
                             sizeof(status2), kind2, sizeof(kind2)));

        sc.read_fail_height = -1;
        UV_CHECK("body_read_failed: resumes once the read succeeds again",
                 utxo_apply_stage_drain(100) == 2);
        UV_CHECK("body_read_failed: cursor advanced to tip (3)",
                 utxo_apply_stage_cursor() == 3);
        UV_CHECK("body_read_failed: blocker cleared on resolve",
                 !blocker_exists("utxo_apply.body_read_failed"));
        uv_teardown(dir, &ms, &sc);
    }

    {
        /* HASH-BOUND VERDICT GATE (height-splice class): a
         * script_validate_log row at the apply height that is provably bound
         * to a DIFFERENT block hash (a stale verdict surviving a header
         * relabel/reorg) must REFUSE the apply with the typed transient
         * blocker utxo_apply.label_splice — never re-use the height-keyed
         * verdict for the wrong block (the coin-hole mechanism, detected 28
         * labels later as bad-cb-height). Re-binding the row to the block
         * actually applied clears the refusal. */
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.label_splice");
        UV_CHECK("label_splice: setup",
                 uv_setup("label_splice", 3, UV_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        struct uint256 wrong;
        uint256_set_null(&wrong);
        wrong.data[0] = 0x5a;
        UV_CHECK("label_splice: foreign failed proof fixture",
                 set_proof_validate_hash(progress_store_db(), 1, &wrong) &&
                     exec_sql(progress_store_db(),
                         "UPDATE proof_validate_log SET ok=0 WHERE height=1"));
        UV_CHECK("label_splice: seed mismatched-hash verdict at h=1",
                 seed_script_validate_row(progress_store_db(), 1, 1, &wrong));
        UV_CHECK("label_splice: drains only h0, refuses h1",
                 utxo_apply_stage_drain(100) == 1);
        UV_CHECK("label_splice: cursor held at 1",
                 utxo_apply_stage_cursor() == 1);
        UV_CHECK("label_splice: typed blocker recorded",
                 blocker_exists("utxo_apply.label_splice") &&
                     !blocker_exists("utxo_apply.apply_failed"));
        UV_CHECK("label_splice: counter counts the height",
                 uv_dump_has("\"label_splice_total\":1"));
        int ok = -1; char status[32]; char kindbuf[32];
        UV_CHECK("label_splice: no log row committed at h=1",
                 !log_row_at(progress_store_db(), 1, &ok, status,
                             sizeof(status), kindbuf, sizeof(kindbuf)));
        UV_CHECK("label_splice: retry tick stays BLOCKED",
                 utxo_apply_stage_step_once() == JOB_BLOCKED);
        UV_CHECK("label_splice: retry tick does not inflate the counter",
                 uv_dump_has("\"label_splice_total\":1"));
        /* Heal: re-bind the verdict to the block actually being applied. */
        UV_CHECK("label_splice: re-bind verdict to the true block",
                 seed_script_validate_row(progress_store_db(), 1, 1,
                                          sc.blocks[1].phashBlock));
        UV_CHECK("label_splice: text-typed proof hash refuses",
                 exec_sql(progress_store_db(),
                     "UPDATE proof_validate_log SET block_hash="
                     "'12345678901234567890123456789012' WHERE height=1") &&
                     utxo_apply_stage_step_once() == JOB_BLOCKED &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("label_splice: hashless proof refuses",
                 set_proof_validate_hash(progress_store_db(), 1, NULL) &&
                     utxo_apply_stage_step_once() == JOB_BLOCKED &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("label_splice: stale proof also refuses",
                 set_proof_validate_hash(progress_store_db(), 1, &wrong) &&
                     utxo_apply_stage_step_once() == JOB_BLOCKED &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("label_splice: proof receipt re-bound",
                 exec_sql(progress_store_db(),
                     "UPDATE proof_validate_log SET ok=1 WHERE height=1") &&
                     set_proof_validate_hash(progress_store_db(), 1,
                                             sc.blocks[1].phashBlock));
        UV_CHECK("label_splice: malformed script verdict refuses apply",
                 seed_script_validate_row(progress_store_db(), 1, 2,
                                          sc.blocks[1].phashBlock) &&
                     utxo_apply_stage_step_once() == JOB_BLOCKED &&
                     utxo_apply_stage_cursor() == 1 &&
                     blocker_exists("utxo_apply.apply_failed"));
        UV_CHECK("label_splice: current script failure refuses apply",
                 seed_script_validate_row(progress_store_db(), 1, 0,
                                          sc.blocks[1].phashBlock) &&
                     utxo_apply_stage_step_once() == JOB_BLOCKED &&
                     utxo_apply_stage_cursor() == 1 &&
                     blocker_exists("utxo_apply.apply_failed"));
        UV_CHECK("label_splice: current script receipt recovers",
                 seed_script_validate_row(progress_store_db(), 1, 1,
                                          sc.blocks[1].phashBlock));
        UV_CHECK("label_splice: healed drain applies the rest",
                 utxo_apply_stage_drain(100) == 2);
        UV_CHECK("label_splice: cursor at 3 after heal",
                 utxo_apply_stage_cursor() == 3);
        UV_CHECK("label_splice: typed blocker clears after heal",
                 !blocker_exists("utxo_apply.label_splice") &&
                     !blocker_exists("utxo_apply.apply_failed"));
        uv_teardown(dir, &ms, &sc);
    }

    {
        /* Hash-bound apply fallback: the self-mint anchor producer can have
         * proof/script/body logs proving the next height while the active-chain
         * window does not expose that height. If the script verdict is ok,
         * hash-bound to a block in the map, and that block extends the visible
         * parent, utxo_apply must use that exact block instead of idling. */
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("hash_fallback: setup",
                 uv_setup("hash_fallback", 3, UV_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("hash_fallback: retract visible window to h0",
                 active_chain_move_window_tip(&ms.chain_active,
                                              &sc.blocks[0]));
        UV_CHECK("hash_fallback: block_map has h1 by hash",
                 block_map_insert(&ms.map_block_index, sc.blocks[1].phashBlock,
                                  &sc.blocks[1]));
        UV_CHECK("hash_fallback: seed h1 script hash verdict",
                 seed_script_validate_row(progress_store_db(), 1, 1,
                                          sc.blocks[1].phashBlock));
        UV_CHECK("hash_fallback: h0 applies through active window",
                 utxo_apply_stage_step_once() == JOB_ADVANCED);
        sc.blocks[1].nStatus |= BLOCK_FAILED_VALID;
        UV_CHECK("hash_fallback: failed h1 verdict cannot be reapplied",
                 utxo_apply_stage_step_once() == JOB_IDLE &&
                     utxo_apply_stage_cursor() == 1 &&
                     uv_dump_has("\"select_idle_reason\":\"block_failed\"") &&
                     uv_dump_has("\"hash_bound_fallback_total\":0"));
        sc.blocks[1].nStatus &= ~(unsigned)BLOCK_FAILED_ANY_MASK;
        UV_CHECK("hash_fallback: reconsidered h1 applies through hash-bound fallback",
                 utxo_apply_stage_step_once() == JOB_ADVANCED);
        UV_CHECK("hash_fallback: cursor at 2",
                 utxo_apply_stage_cursor() == 2);
        UV_CHECK("hash_fallback: fallback counter recorded",
                 uv_dump_has("\"hash_bound_fallback_total\":1"));
        UV_CHECK("hash_fallback: fallback height recorded",
                 uv_dump_has("\"hash_bound_fallback_height\":1"));
        uv_teardown(dir, &ms, &sc);
    }

    {
        /* Anchor-resume stale-data-bit fallback: a resumed offline mint can
         * have durable proof/script rows for h1 and a correct disk position in
         * the block index, while the in-memory BLOCK_HAVE_DATA bit was lost
         * during boot/window repair. The hash-bound fallback may refresh that
         * bit only after the indexed body re-reads and hashes to the scripted
         * block, then the production reader must apply h1. */
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("hash_fallback_stale_data_bit: setup",
                 uv_setup("hash_fallback_stale_data_bit", 3, UV_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("hash_fallback_stale_data_bit: visible h0 only",
                 active_chain_move_window_tip(&ms.chain_active,
                                              &sc.blocks[0]));
        UV_CHECK("hash_fallback_stale_data_bit: seed h1 script hash verdict",
                 seed_script_validate_row(progress_store_db(), 1, 1,
                                          sc.blocks[1].phashBlock));
        UV_CHECK("hash_fallback_stale_data_bit: block_map has h1 by hash",
                 block_map_insert(&ms.map_block_index, sc.blocks[1].phashBlock,
                                  &sc.blocks[1]));
        UV_CHECK("hash_fallback_stale_data_bit: h1 body on disk",
                 uv_write_body_to_disk(&sc, 1));
        sc.blocks[1].nStatus &= ~(unsigned)BLOCK_HAVE_DATA;
        UV_CHECK("hash_fallback_stale_data_bit: h1 data bit cleared",
                 (sc.blocks[1].nStatus & BLOCK_HAVE_DATA) == 0);
        UV_CHECK("hash_fallback_stale_data_bit: h0 applies",
                 utxo_apply_stage_step_once() == JOB_ADVANCED);
        utxo_apply_stage_set_reader(NULL, NULL);
        UV_CHECK("hash_fallback_stale_data_bit: h1 applies with refreshed bit",
                 utxo_apply_stage_step_once() == JOB_ADVANCED);
        UV_CHECK("hash_fallback_stale_data_bit: cursor at 2",
                 utxo_apply_stage_cursor() == 2);
        UV_CHECK("hash_fallback_stale_data_bit: data bit restored",
                 (sc.blocks[1].nStatus & BLOCK_HAVE_DATA) != 0);
        UV_CHECK("hash_fallback_stale_data_bit: fallback counter recorded",
                 uv_dump_has("\"hash_bound_fallback_total\":1"));
        uv_teardown(dir, &ms, &sc);
    }

    {
        /* Anchor-resume fallback: after a long offline mint resumes, the
         * visible active-chain window can lose the already-applied parent.
         * The next block is still safe to apply when script_validate_log binds
         * the current height and tip_finalize_log durably witnesses the
         * parent hash. */
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("hash_fallback_durable_parent: setup",
                 uv_setup("hash_fallback_durable_parent", 3, UV_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("hash_fallback_durable_parent: visible h0 only",
                 active_chain_move_window_tip(&ms.chain_active,
                                              &sc.blocks[0]));
        UV_CHECK("hash_fallback_durable_parent: seed h1 script hash verdict",
                 seed_script_validate_row(progress_store_db(), 1, 1,
                                          sc.blocks[1].phashBlock));
        UV_CHECK("hash_fallback_durable_parent: block_map has h1 by hash",
                 block_map_insert(&ms.map_block_index, sc.blocks[1].phashBlock,
                                  &sc.blocks[1]));
        UV_CHECK("hash_fallback_durable_parent: h0 applies",
                 utxo_apply_stage_step_once() == JOB_ADVANCED);
        UV_CHECK("hash_fallback_durable_parent: durable h0 witness",
                 seed_tip_finalize_anchor_row(progress_store_db(), 0,
                                              sc.blocks[0].phashBlock));
        uint8_t durable_parent_hash[32] = {0};
        UV_CHECK("hash_fallback_durable_parent: h0 witness resolves",
                 tip_finalize_stage_block_hash_at(progress_store_db(), 0,
                                                  durable_parent_hash) &&
                 memcmp(durable_parent_hash, sc.blocks[0].phashBlock->data,
                        sizeof(durable_parent_hash)) == 0);
        active_chain_free(&ms.chain_active);
        active_chain_init(&ms.chain_active);
        UV_CHECK("hash_fallback_durable_parent: h1 applies without visible parent",
                 utxo_apply_stage_step_once() == JOB_ADVANCED);
        UV_CHECK("hash_fallback_durable_parent: cursor at 2",
                 utxo_apply_stage_cursor() == 2);
        UV_CHECK("hash_fallback_durable_parent: fallback counter recorded",
                 uv_dump_has("\"hash_bound_fallback_total\":1"));
        UV_CHECK("hash_fallback_durable_parent: fallback height recorded",
                 uv_dump_has("\"hash_bound_fallback_height\":1"));
        uv_teardown(dir, &ms, &sc);
    }

    {
        /* Checkpoint first-transition fallback: once tip_finalize replaces the
         * seed anchor row, the exact trusted-base metadata remains the only
         * durable hash(H) witness until the next transition. */
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("hash_fallback_trusted_base: setup",
                 uv_setup("hash_fallback_trusted_base", 3, UV_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("hash_fallback_trusted_base: visible h0 only",
                 active_chain_move_window_tip(&ms.chain_active,
                                              &sc.blocks[0]));
        UV_CHECK("hash_fallback_trusted_base: seed h1 script hash verdict",
                 seed_script_validate_row(progress_store_db(), 1, 1,
                                          sc.blocks[1].phashBlock));
        UV_CHECK("hash_fallback_trusted_base: block_map has h1 by hash",
                 block_map_insert(&ms.map_block_index, sc.blocks[1].phashBlock,
                                  &sc.blocks[1]));
        UV_CHECK("hash_fallback_trusted_base: h0 applies",
                 utxo_apply_stage_step_once() == JOB_ADVANCED);
        uint8_t trusted_height[8] = {0};
        UV_CHECK("hash_fallback_trusted_base: exact authority pair stored",
                 progress_meta_set(progress_store_db(),
                                   REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                                   trusted_height, sizeof(trusted_height)) &&
                 progress_meta_set(progress_store_db(),
                                   REDUCER_TRUSTED_BASE_HASH_KEY,
                                   sc.blocks[0].phashBlock->data, 32));
        UV_CHECK("hash_fallback_trusted_base: h1 body on disk",
                 uv_write_body_to_disk(&sc, 1));
        /* A block-file scan can create a same-hash body owner whose derived
         * pprev link is absent even though the body header itself carries the
         * exact durable parent hash. The apply gate must bind to the validated
         * body bytes, not that rebuildable pointer. */
        sc.blocks[1].pprev = NULL;
        active_chain_free(&ms.chain_active);
        active_chain_init(&ms.chain_active);
        UV_CHECK("hash_fallback_trusted_base: h1 applies without anchor row",
                 utxo_apply_stage_step_once() == JOB_ADVANCED);
        UV_CHECK("hash_fallback_trusted_base: fallback counter recorded",
                 uv_dump_has("\"hash_bound_fallback_total\":1"));
        uv_teardown(dir, &ms, &sc);
    }

    run_fail_case(&failures, UV_FAIL_UNKNOWN, "spend_unknown_utxo",
                  utxo_apply_stage_spend_unknown_total);
    run_fail_case(&failures, UV_FAIL_COLLISION, "utxo_collision",
                  utxo_apply_stage_utxo_collision_total);
    run_fail_case(&failures, UV_FAIL_OVERFLOW, "value_overflow",
                  utxo_apply_stage_value_overflow_total);

    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("upstream_failed: setup",
                 uv_setup("upstream", 3, UV_FAIL_NONE, 2, dir, sizeof(dir),
                          &ms, &sc) == 0);
        blocker_clear("utxo_apply.apply_failed");
        UV_CHECK("upstream_failed: drains until failed height",
                 utxo_apply_stage_drain(100) == 2);
        UV_CHECK("upstream_failed: counter == 1",
                 utxo_apply_stage_upstream_failed_total() == 1);
        int ok = -1; char status[32]; char kind[32];
        bool found = log_row_at(progress_store_db(), 2, &ok, status,
                                sizeof(status), kind, sizeof(kind));
        UV_CHECK("upstream_failed: h=2 row rolled back", !found && ok == -1);
        UV_CHECK("upstream_failed: cursor held at h=2",
                 utxo_apply_stage_cursor() == 2);
        UV_CHECK("upstream_failed: typed blocker recorded",
                 blocker_exists("utxo_apply.apply_failed"));
        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }

    /* CS-F4 memo lifecycle: a held reject ticks without inflating its
     * counter; once the cause heals, the SAME height applies and the stage
     * resumes (JOB_ADVANCED clears the memo, so the dedup never wedges
     * recovery and a later reject counts as a new block). */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        UV_CHECK("dedup: setup",
                 uv_setup("dedup", 3, UV_FAIL_UNKNOWN, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        UV_CHECK("dedup: drains until failed height",
                 utxo_apply_stage_drain(100) == 1);
        UV_CHECK("dedup: counter == 1 after first reject",
                 utxo_apply_stage_spend_unknown_total() == 1);
        UV_CHECK("dedup: retry tick 1 stays BLOCKED",
                 utxo_apply_stage_step_once() == JOB_BLOCKED);
        UV_CHECK("dedup: retry tick 2 stays BLOCKED",
                 utxo_apply_stage_step_once() == JOB_BLOCKED);
        UV_CHECK("dedup: counter still 1 (counts blocks, not ticks)",
                 utxo_apply_stage_spend_unknown_total() == 1);
        sc.fail_kind = UV_FAIL_NONE;   /* heal: prevout resolvable again */
        UV_CHECK("dedup: healed drain applies the rest",
                 utxo_apply_stage_drain(100) == 2);
        UV_CHECK("dedup: cursor at 3", utxo_apply_stage_cursor() == 3);
        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("idle: setup",
                 uv_setup("idle", 3, UV_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        sqlite3_exec(progress_store_db(),
            "UPDATE stage_cursor SET cursor=1 WHERE name='proof_validate'",
            NULL, NULL, NULL);
        UV_CHECK("idle: advances one", utxo_apply_stage_drain(100) == 1);
        UV_CHECK("idle: next step IDLE",
                 utxo_apply_stage_step_once() == JOB_IDLE);
        UV_CHECK("idle: cursor stays 1", utxo_apply_stage_cursor() == 1);
        uv_teardown(dir, &ms, &sc);
    }

    {
        UV_CHECK("guard: step_once with no init returns IDLE",
                 utxo_apply_stage_step_once() == JOB_IDLE);
        UV_CHECK("guard: init(NULL) rejected",
                 !utxo_apply_stage_init(NULL));
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("dump: setup",
                 uv_setup("dump", 2, UV_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        utxo_apply_stage_drain(100);
        struct json_value v;
        json_init(&v);
        UV_CHECK("dump: returns true", utxo_apply_dump_state_json(&v, NULL));
        char buf[2048];   /* headroom: the dump grew two C-2/C-3 counters */
        size_t n = json_write(&v, buf, sizeof(buf));
        UV_CHECK("dump: serializes", n > 0 && n < sizeof(buf));
        UV_CHECK("dump: stage_name",
                 strstr(buf, "\"stage_name\":\"utxo_apply\"") != NULL);
        UV_CHECK("dump: cursor=2", strstr(buf, "\"cursor\":2") != NULL);
        UV_CHECK("dump: verified_total=2",
                 strstr(buf, "\"verified_total\":2") != NULL);
        /* Lane 1.1 (per-stage step latency/rate metrics): the shared
         * stage_dump_counters() helper adds these keys to every one of the
         * eight stage dumpstates for free (see engine/jobs/include/jobs/
         * stage_helpers.h). Two blocks were driven above via drain(100),
         * which stops at the first non-ADVANCED step_once() — so the drain
         * issues one extra IDLE probe after the two ADVANCED steps
         * (STAGE_DRAIN_IMPL breaks on the first result != JOB_ADVANCED).
         * steps_total must equal the sum of the four verdict counters
         * rather than a hardcoded 2, so this doesn't hardcode that drain
         * internal. */
        int64_t adv = json_get_int(json_get(&v, "advanced_count"));
        int64_t blk = json_get_int(json_get(&v, "blocked_count"));
        int64_t idl = json_get_int(json_get(&v, "idle_count"));
        int64_t err = json_get_int(json_get(&v, "error_count"));
        UV_CHECK("dump: advanced_count=2", adv == 2);
        UV_CHECK("dump: steps_total == sum of verdict counters",
                 json_get_int(json_get(&v, "steps_total")) ==
                     adv + blk + idl + err);
        UV_CHECK("dump: last_step_us key present",
                 strstr(buf, "\"last_step_us\":") != NULL);
        UV_CHECK("dump: step_us_ewma key present",
                 strstr(buf, "\"step_us_ewma\":") != NULL);
        UV_CHECK("dump: steps_per_sec_ewma key present",
                 strstr(buf, "\"steps_per_sec_ewma\":") != NULL);
        UV_CHECK("dump: last_step_us > 0",
                 json_get_int(json_get(&v, "last_step_us")) > 0);
        UV_CHECK("dump: step_us_ewma > 0",
                 json_get_int(json_get(&v, "step_us_ewma")) > 0);
        json_free(&v);
        uv_teardown(dir, &ms, &sc);
    }

    /* ── Shielded-nullifier double-spend gate (C-3) ─────────────────────
     * zclassicd rejects a tx revealing an already-seen nullifier
     * (bad-txns-joinsplit-requirements-not-met, main.cpp:2627). The stage
     * enforces it via nullifier_kv check-then-insert inside the apply txn. */

    /* (a)+(e) Sapling cross-block double-spend: h=1 reveals N, h=2 reveals
     * a FRESH nullifier X then N again -> h=2 rejected, cursor held, and
     * ZERO rows inserted for h=2 (two-pass: X must not leak). */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        UV_CHECK("nf sapling: setup",
                 uv_setup("nf_sapling", 3, UV_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        const uint8_t h1_tags[1] = { 0xA1 };
        const uint8_t h2_tags[2] = { 0xAE, 0xA1 };   /* fresh X, then dup N */
        UV_CHECK("nf sapling: h=1 spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], h1_tags, 1, 0x5A));
        UV_CHECK("nf sapling: h=2 spends attach",
                 uv_add_sapling_spends(&sc.bodies[2].vtx[1], h2_tags, 2, 0x5A));
        UV_CHECK("nf sapling: drains until dup height",
                 utxo_apply_stage_drain(100) == 2);
        UV_CHECK("nf sapling: counter == 1",
                 uv_dump_has("\"shielded_double_spend_total\":1"));
        UV_CHECK("nf sapling: blocker status",
                 uv_blocker_reason_has("status=shielded_double_spend"));
        UV_CHECK("nf sapling: blocker kind is zclassicd's exact string",
                 uv_blocker_reason_has(
                     "kind=bad-txns-joinsplit-requirements-not-met"));
        UV_CHECK("nf sapling: retry stays JOB_BLOCKED",
                 utxo_apply_stage_step_once() == JOB_BLOCKED);
        UV_CHECK("nf sapling: counter still 1 after retry (CS-F4 dedup)",
                 uv_dump_has("\"shielded_double_spend_total\":1"));
        UV_CHECK("nf sapling: cursor held at h=2",
                 utxo_apply_stage_cursor() == 2);
        UV_CHECK("nf sapling: h=1 row revealed",
                 uv_nf_rows_at(progress_store_db(), 1) == 1);
        UV_CHECK("nf sapling: rejected h=2 left ZERO rows (no partial insert)",
                 uv_nf_rows_at(progress_store_db(), 2) == 0);
        {
            uint8_t x[32]; bool found = true;
            uv_nf_bytes(x, 0xAE, 0x5A);
            UV_CHECK("nf sapling: fresh X of the rejected block absent",
                     nullifier_kv_get(progress_store_db(), x,
                                      NULLIFIER_POOL_SAPLING, &found, NULL) &&
                     !found);
        }
        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }

    /* (b) Sprout variant: a JoinSplit at h=2 re-reveals one of h=1's two
     * Sprout nullifiers (its other nullifier is fresh) -> rejected. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        UV_CHECK("nf sprout: setup",
                 uv_setup("nf_sprout", 3, UV_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        UV_CHECK("nf sprout: h=1 joinsplit attaches",
                 uv_add_joinsplit_nfs(&sc.bodies[1].vtx[1], 0xB1, 0xB2, 0x5B));
        UV_CHECK("nf sprout: h=2 joinsplit attaches",
                 uv_add_joinsplit_nfs(&sc.bodies[2].vtx[1], 0xB1, 0xB3, 0x5B));
        UV_CHECK("nf sprout: drains until dup height",
                 utxo_apply_stage_drain(100) == 2);
        UV_CHECK("nf sprout: counter == 1",
                 uv_dump_has("\"shielded_double_spend_total\":1"));
        UV_CHECK("nf sprout: blocker status",
                 uv_blocker_reason_has("status=shielded_double_spend"));
        UV_CHECK("nf sprout: cursor held at h=2",
                 utxo_apply_stage_cursor() == 2);
        UV_CHECK("nf sprout: h=1 revealed both sprout rows",
                 uv_nf_rows_at(progress_store_db(), 1) == 2);
        UV_CHECK("nf sprout: rejected h=2 left zero rows",
                 uv_nf_rows_at(progress_store_db(), 2) == 0);
        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }

    /* (c) INTRA-BLOCK cross-tx duplicate: two txs of the SAME block reveal
     * the same Sapling nullifier -> the block is rejected (zclassicd's
     * per-tx check-then-set order catches the second tx). Regression lock:
     * the durable set alone cannot see this case. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        UV_CHECK("nf intra: setup",
                 uv_setup("nf_intra", 2, UV_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        const uint8_t tag[1] = { 0xC1 };
        UV_CHECK("nf intra: vtx[1] spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tag, 1, 0x5C));
        UV_CHECK("nf intra: bare tx appends",
                 uv_append_bare_tx(&sc.bodies[1], 1));
        UV_CHECK("nf intra: vtx[2] dup spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[2], tag, 1, 0x5C));
        UV_CHECK("nf intra: drains until dup block",
                 utxo_apply_stage_drain(100) == 1);
        UV_CHECK("nf intra: counter == 1",
                 uv_dump_has("\"shielded_double_spend_total\":1"));
        UV_CHECK("nf intra: cursor held at h=1",
                 utxo_apply_stage_cursor() == 1);
        UV_CHECK("nf intra: rejected block left zero rows",
                 uv_nf_rows_at(progress_store_db(), 1) == 0);
        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }

    /* (c2) Same rule with a larger earlier-tx accumulator. This catches
     * regressions where the fast lookup table is built at the wrong boundary
     * or misses entries beyond the tiny one-nullifier case above. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        UV_CHECK("nf intra many: setup",
                 uv_setup("nf_intra_many", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        uint8_t tags[64];
        for (size_t i = 0; i < 64; i++)
            tags[i] = (uint8_t)(0x20u + i);
        UV_CHECK("nf intra many: vtx[1] spends attach",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tags, 64, 0x71));
        UV_CHECK("nf intra many: bare tx appends",
                 uv_append_bare_tx(&sc.bodies[1], 1));
        const uint8_t dup[1] = { tags[37] };
        UV_CHECK("nf intra many: vtx[2] dup spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[2], dup, 1, 0x71));
        UV_CHECK("nf intra many: drains until dup block",
                 utxo_apply_stage_drain(100) == 1);
        UV_CHECK("nf intra many: counter == 1",
                 uv_dump_has("\"shielded_double_spend_total\":1"));
        UV_CHECK("nf intra many: cursor held at h=1",
                 utxo_apply_stage_cursor() == 1);
        UV_CHECK("nf intra many: rejected block left zero rows",
                 uv_nf_rows_at(progress_store_db(), 1) == 0);
        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }

    /* (d) CROSS-POOL byte-reuse is LEGAL: the same 32 bytes revealed as a
     * Sapling nullifier at h=1 and a Sprout nullifier at h=2 must BOTH apply
     * (zclassicd keeps separate per-pool maps, coins.cpp:166-180 — a single
     * shared namespace would fork the other way). */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("nf xpool: setup",
                 uv_setup("nf_xpool", 3, UV_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        const uint8_t tag[1] = { 0xD1 };
        UV_CHECK("nf xpool: sapling spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tag, 1, 0x5D));
        UV_CHECK("nf xpool: sprout joinsplit attaches (same bytes)",
                 uv_add_joinsplit_nfs(&sc.bodies[2].vtx[1], 0xD1, 0xD2, 0x5D));
        UV_CHECK("nf xpool: ALL heights apply", utxo_apply_stage_drain(100) == 3);
        UV_CHECK("nf xpool: cursor at 3", utxo_apply_stage_cursor() == 3);
        {
            uint8_t nf[32]; bool fs = false, fz = false;
            int64_t hs = -1, hz = -1;
            uv_nf_bytes(nf, 0xD1, 0x5D);
            UV_CHECK("nf xpool: sapling row at h=1",
                     nullifier_kv_get(progress_store_db(), nf,
                                      NULLIFIER_POOL_SAPLING, &fz, &hz) &&
                     fz && hz == 1);
            UV_CHECK("nf xpool: sprout row (same bytes) at h=2",
                     nullifier_kv_get(progress_store_db(), nf,
                                      NULLIFIER_POOL_SPROUT, &fs, &hs) &&
                     fs && hs == 2);
        }
        uv_teardown(dir, &ms, &sc);
    }

    /* (d2) TG-F6 INTRA-BLOCK cross-pool byte-reuse is LEGAL: the same 32
     * bytes revealed as a Sapling nullifier (tx1) and a Sprout nullifier
     * (tx2) in ONE block must apply — nf_seen's accumulator keys on
     * (pool, bytes); dropping the pool term would false-reject this block
     * (an opposite-direction fork). Neither (c) (same-pool intra-block) nor
     * (d) (cross-pool but cross-block) covers it. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("nf xpool intra: setup",
                 uv_setup("nf_xpool_intra", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        const uint8_t tag[1] = { 0xE1 };
        UV_CHECK("nf xpool intra: vtx[1] sapling spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tag, 1, 0x6A));
        UV_CHECK("nf xpool intra: bare tx appends",
                 uv_append_bare_tx(&sc.bodies[1], 1));
        UV_CHECK("nf xpool intra: vtx[2] sprout joinsplit (same bytes)",
                 uv_add_joinsplit_nfs(&sc.bodies[1].vtx[2], 0xE1, 0xE2, 0x6A));
        UV_CHECK("nf xpool intra: block APPLIES",
                 utxo_apply_stage_drain(100) == 2);
        UV_CHECK("nf xpool intra: cursor at 2",
                 utxo_apply_stage_cursor() == 2);
        UV_CHECK("nf xpool intra: no blocker recorded",
                 !blocker_exists("utxo_apply.apply_failed"));
        {
            uint8_t nf[32]; bool fz = false, fs = false;
            int64_t hz = -1, hs = -1;
            uv_nf_bytes(nf, 0xE1, 0x6A);
            UV_CHECK("nf xpool intra: sapling row at h=1",
                     nullifier_kv_get(progress_store_db(), nf,
                                      NULLIFIER_POOL_SAPLING, &fz, &hz) &&
                     fz && hz == 1);
            UV_CHECK("nf xpool intra: sprout row (same bytes) at h=1",
                     nullifier_kv_get(progress_store_db(), nf,
                                      NULLIFIER_POOL_SPROUT, &fs, &hs) &&
                     fs && hs == 1);
        }
        uv_teardown(dir, &ms, &sc);
    }

    /* (d3) TG-F6 mirror reject: two Sprout txs of the SAME block revealing
     * the same Sprout nullifier must be rejected — the (c) regression lock
     * for the Sprout side of the accumulator. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        UV_CHECK("nf sprout intra: setup",
                 uv_setup("nf_sprout_intra", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("nf sprout intra: vtx[1] joinsplit attaches",
                 uv_add_joinsplit_nfs(&sc.bodies[1].vtx[1], 0xE5, 0xE6, 0x6B));
        UV_CHECK("nf sprout intra: bare tx appends",
                 uv_append_bare_tx(&sc.bodies[1], 1));
        UV_CHECK("nf sprout intra: vtx[2] dup joinsplit attaches",
                 uv_add_joinsplit_nfs(&sc.bodies[1].vtx[2], 0xE5, 0xE7, 0x6B));
        UV_CHECK("nf sprout intra: drains until dup block",
                 utxo_apply_stage_drain(100) == 1);
        UV_CHECK("nf sprout intra: counter == 1",
                 uv_dump_has("\"shielded_double_spend_total\":1"));
        UV_CHECK("nf sprout intra: cursor held at h=1",
                 utxo_apply_stage_cursor() == 1);
        UV_CHECK("nf sprout intra: rejected block left zero rows",
                 uv_nf_rows_at(progress_store_db(), 1) == 0);
        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }

    /* (f) REWIND INVARIANT: after a 3-pass utxo_apply_delete_rows_above
     * rewind (inverse deltas + log/delta/NULLIFIER deletes + cursor), the
     * SAME blocks re-apply with no false shielded_double_spend. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("nf rewind: setup",
                 uv_setup("nf_rewind", 3, UV_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        const uint8_t f1[1] = { 0xF1 };
        const uint8_t f2[1] = { 0xF2 };
        UV_CHECK("nf rewind: h=1 spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], f1, 1, 0x5F));
        UV_CHECK("nf rewind: h=2 spend attaches",
                 uv_add_sapling_spends(&sc.bodies[2].vtx[1], f2, 1, 0x5F));
        UV_CHECK("nf rewind: first apply drains 3",
                 utxo_apply_stage_drain(100) == 3);
        sqlite3 *db = progress_store_db();
        UV_CHECK("nf rewind: rows revealed",
                 uv_nf_rows_at(db, 1) == 1 && uv_nf_rows_at(db, 2) == 1);
        /* Rewind [1..2] exactly like the unwind/repair paths do. */
        bool rewound =
            exec_sql(db, "BEGIN IMMEDIATE") &&
            utxo_apply_emit_inverse_delta(db, 2) &&
            utxo_apply_emit_inverse_delta(db, 1) &&
            utxo_apply_delete_rows_above(db, 1, 2) &&
            utxo_apply_unwind_write_cursor(db, 1) &&
            coins_kv_set_applied_height_in_tx(db, 1) &&
            exec_sql(db, "COMMIT");
        UV_CHECK("nf rewind: rewind txn commits", rewound);
        UV_CHECK("nf rewind: rewound nullifier rows deleted",
                 uv_nf_rows_at(db, 1) == 0 && uv_nf_rows_at(db, 2) == 0);
        UV_CHECK("nf rewind: re-apply drains 2 (NO false reject)",
                 utxo_apply_stage_drain(100) == 2);
        UV_CHECK("nf rewind: cursor back at 3",
                 utxo_apply_stage_cursor() == 3);
        UV_CHECK("nf rewind: rows re-revealed",
                 uv_nf_rows_at(db, 1) == 1 && uv_nf_rows_at(db, 2) == 1);
        UV_CHECK("nf rewind: no blocker recorded",
                 !blocker_exists("utxo_apply.apply_failed"));
        uv_teardown(dir, &ms, &sc);
    }

    /* A past cursor-only repair could leave shielded kernel rows at future
     * heights. Restart must remove that suffix before the next block fold,
     * while preserving rows below the exact cursor/coin frontier. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("suffix reconcile: setup",
                 uv_setup("suffix_reconcile", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("suffix reconcile: establish cursor one",
                 utxo_apply_stage_drain(1) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        sqlite3 *db = progress_store_db();
        utxo_apply_stage_shutdown();
        UV_CHECK("suffix reconcile: seed kept and future shielded rows",
                 exec_sql(db,
                     "INSERT OR REPLACE INTO sapling_anchors"
                     "(anchor,height,tree) VALUES(zeroblob(32),0,x'');"
                     "INSERT OR REPLACE INTO sapling_anchors"
                     "(anchor,height,tree) VALUES(x'01',1,x'');"
                     "INSERT OR REPLACE INTO nullifiers"
                     "(nf,pool,height) VALUES(zeroblob(32),1,1)"));
        UV_CHECK("suffix reconcile: restart succeeds",
                 utxo_apply_stage_init(&ms));
        UV_CHECK("suffix reconcile: future kernel rows removed",
                 uv_table_rows_at(db, "sapling_anchors", 1) == 0 &&
                     uv_nf_rows_at(db, 1) == 0);
        UV_CHECK("suffix reconcile: below-frontier row preserved",
                 uv_table_rows_at(db, "sapling_anchors", 0) == 1 &&
                     stage_cursor_persisted(db, "utxo_apply",
                                            "suffix_reconcile_test") == 1);
        uv_teardown(dir, &ms, &sc);
    }

    /* A cursor-only repair can also leave the actual transparent coin rows
     * from an unapplied suffix.  Remove them only after canonical body bytes
     * prove that every spendable output matches one future-height coin
     * exactly. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("coin suffix reconcile: setup",
                 uv_setup("coin_suffix_reconcile", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("coin suffix reconcile: establish cursor one",
                 utxo_apply_stage_drain(1) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        sqlite3 *db = progress_store_db();
        utxo_apply_stage_shutdown();
        UV_CHECK("coin suffix reconcile: make zero-spend suffix",
                 uv_make_block_coinbase_only(&sc, 1));
        const struct transaction *cb = &sc.bodies[1].vtx[0];
        UV_CHECK("coin suffix reconcile: seed exact future coin",
                 coins_kv_add(db, cb->hash.data, 0, cb->vout[0].value, 1,
                              true, cb->vout[0].script_pub_key.data,
                              cb->vout[0].script_pub_key.size) &&
                     uv_coin_rows_at(db, 1) == 1);
        utxo_apply_stage_set_reader(fake_reader, &sc);
        UV_CHECK("coin suffix reconcile: restart proves and repairs",
                 utxo_apply_stage_init(&ms));
        UV_CHECK("coin suffix reconcile: future coin removed",
                 uv_coin_rows_at(db, 1) == 0 &&
                     stage_cursor_persisted(db, "utxo_apply",
                                            "coin_suffix_test") == 1);
        uv_teardown(dir, &ms, &sc);
    }

    /* A proved suffix may contain transparent spends.  Reconstruct each
     * missing pre-suffix coin from created_outputs plus its canonical creator
     * block, in the same transaction that removes the future outputs. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("coin suffix spend restore: setup",
                 uv_setup("coin_suffix_spend_restore", 2, UV_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("coin suffix spend restore: establish cursor one",
                 utxo_apply_stage_drain(1) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        sqlite3 *db = progress_store_db();
        utxo_apply_stage_shutdown();
        struct transaction *spend = &sc.bodies[1].vtx[1];
        const struct transaction *creator = &sc.bodies[0].vtx[0];
        spend->vin[0].prevout.hash = creator->hash;
        spend->vin[0].prevout.n = 0;
        UV_CHECK("coin suffix spend restore: creator indexed",
                 created_outputs_index_put_block(db, &sc.bodies[0], 0));
        UV_CHECK("coin suffix spend restore: simulate applied spend",
                 coins_kv_spend(db, creator->hash.data, 0) &&
                     uv_coin_rows_at(db, 0) == 1);
        bool seeded = true;
        for (size_t ti = 0; ti < sc.bodies[1].num_vtx && seeded; ti++) {
            const struct transaction *tx = &sc.bodies[1].vtx[ti];
            seeded = coins_kv_add(
                db, tx->hash.data, 0, tx->vout[0].value, 1,
                transaction_is_coinbase(tx),
                tx->vout[0].script_pub_key.data,
                tx->vout[0].script_pub_key.size);
        }
        UV_CHECK("coin suffix spend restore: future outputs seeded",
                 seeded && uv_coin_rows_at(db, 1) == 2);
        utxo_apply_stage_set_reader(fake_reader, &sc);
        UV_CHECK("coin suffix spend restore: restart proves and repairs",
                 utxo_apply_stage_init(&ms));
        UV_CHECK("coin suffix spend restore: pre-suffix set reconstructed",
                 uv_coin_rows_at(db, 1) == 0 &&
                     uv_coin_rows_at(db, 0) == 2 &&
                     coins_kv_exists(db, creator->hash.data, 0));
        uv_teardown(dir, &ms, &sc);
    }

    /* A crash may persist suffix outputs before spending every input.  An
     * already-live pre-suffix input is the desired rolled-back state, but its
     * complete coin record must still match the canonical creator exactly. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("partial coin suffix: setup",
                 uv_setup("partial_coin_suffix", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("partial coin suffix: establish cursor one",
                 utxo_apply_stage_drain(1) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        sqlite3 *db = progress_store_db();
        utxo_apply_stage_shutdown();
        struct transaction *spend = &sc.bodies[1].vtx[1];
        const struct transaction *creator = &sc.bodies[0].vtx[0];
        spend->vin[0].prevout.hash = creator->hash;
        spend->vin[0].prevout.n = 0;
        UV_CHECK("partial coin suffix: creator indexed and still live",
                 created_outputs_index_put_block(db, &sc.bodies[0], 0) &&
                     coins_kv_exists(db, creator->hash.data, 0));
        bool seeded = true;
        for (size_t ti = 0; ti < sc.bodies[1].num_vtx && seeded; ti++) {
            const struct transaction *tx = &sc.bodies[1].vtx[ti];
            seeded = coins_kv_add(
                db, tx->hash.data, 0, tx->vout[0].value, 1,
                transaction_is_coinbase(tx),
                tx->vout[0].script_pub_key.data,
                tx->vout[0].script_pub_key.size);
        }
        UV_CHECK("partial coin suffix: future outputs seeded",
                 seeded && uv_coin_rows_at(db, 1) == 2);
        utxo_apply_stage_set_reader(fake_reader, &sc);
        UV_CHECK("partial coin suffix: restart proves and repairs",
                 utxo_apply_stage_init(&ms));
        UV_CHECK("partial coin suffix: live input retained exactly once",
                 uv_coin_rows_at(db, 1) == 0 &&
                     coins_kv_exists(db, creator->hash.data, 0));
        uv_teardown(dir, &ms, &sc);
    }

    /* The authoritative frontier may precede the first contradictory coin
     * row.  Prove that gapped creator from its canonical body, but do not
     * restore it before the reducer has applied the intervening block. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("gapped coin suffix: setup",
                 uv_setup("gapped_coin_suffix", 3, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("gapped coin suffix: establish cursor one",
                 utxo_apply_stage_drain(1) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        sqlite3 *db = progress_store_db();
        utxo_apply_stage_shutdown();
        struct transaction *spend = &sc.bodies[2].vtx[1];
        const struct transaction *gap_creator = &sc.bodies[1].vtx[0];
        spend->vin[0].prevout.hash = gap_creator->hash;
        spend->vin[0].prevout.n = 0;
        UV_CHECK("gapped coin suffix: creator indexed",
                 created_outputs_index_put_block(db, &sc.bodies[1], 1));
        bool seeded = true;
        for (size_t ti = 0; ti < sc.bodies[2].num_vtx && seeded; ti++) {
            const struct transaction *tx = &sc.bodies[2].vtx[ti];
            seeded = coins_kv_add(
                db, tx->hash.data, 0, tx->vout[0].value, 2,
                transaction_is_coinbase(tx),
                tx->vout[0].script_pub_key.data,
                tx->vout[0].script_pub_key.size);
        }
        UV_CHECK("gapped coin suffix: future outputs seeded",
                 seeded && uv_coin_rows_at(db, 1) == 0 &&
                     uv_coin_rows_at(db, 2) == 2);
        utxo_apply_stage_set_reader(fake_reader, &sc);
        UV_CHECK("gapped coin suffix: restart proves and repairs",
                 utxo_apply_stage_init(&ms));
        UV_CHECK("gapped coin suffix: creator remains unapplied",
                 uv_coin_rows_at(db, 1) == 0 &&
                     uv_coin_rows_at(db, 2) == 0 &&
                     !coins_kv_exists(db, gap_creator->hash.data, 0));
        uv_teardown(dir, &ms, &sc);
    }

    /* The same repair must fail closed when the canonical suffix contains a
     * transparent input whose creator proof is unavailable.  The failed
     * restart leaves both rows intact. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("coin suffix spend refusal: setup",
                 uv_setup("coin_suffix_spend_refusal", 2, UV_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("coin suffix spend refusal: establish cursor one",
                 utxo_apply_stage_drain(1) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        sqlite3 *db = progress_store_db();
        utxo_apply_stage_shutdown();
        const struct block *blk = &sc.bodies[1];
        bool seeded = true;
        for (size_t ti = 0; ti < blk->num_vtx && seeded; ti++) {
            const struct transaction *tx = &blk->vtx[ti];
            seeded = coins_kv_add(
                db, tx->hash.data, 0, tx->vout[0].value, 1,
                transaction_is_coinbase(tx),
                tx->vout[0].script_pub_key.data,
                tx->vout[0].script_pub_key.size);
        }
        UV_CHECK("coin suffix spend refusal: seed future outputs",
                 seeded && uv_coin_rows_at(db, 1) == 2);
        utxo_apply_stage_set_reader(fake_reader, &sc);
        UV_CHECK("coin suffix spend refusal: restart fails closed",
                 !utxo_apply_stage_init(&ms));
        UV_CHECK("coin suffix spend refusal: rows preserved",
                 uv_coin_rows_at(db, 1) == 2 &&
                     stage_cursor_persisted(db, "utxo_apply",
                                            "coin_suffix_refusal_test") == 1);
        uv_teardown(dir, &ms, &sc);
    }

    /* (g) C-3 ACTIVATION GAP blocker: a marker > 0 (table first created on
     * a datadir with already-applied history) must surface the PERMANENT
     * utxo_apply.nullifier_backfill_gap blocker; only explicit 0 (a
     * from-genesis or fully backfilled store) may clear it. Drives the refresh
     * directly against the live registry. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("nf gap: setup",
                 uv_setup("nf_gap", 2, UV_FAIL_NONE, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        sqlite3 *db = progress_store_db();
        /* Fresh store: table first created at cursor 0 → marker "0", so
         * init's refresh must NOT have registered the gap blocker. */
        UV_CHECK("nf gap: fresh store has no gap blocker",
                 !blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));
        UV_CHECK("nf gap: marker write",
                 progress_meta_set(db, "nullifier_kv.activation_cursor",
                                   "3134000", 7));
        utxo_apply_nullifier_gap_blocker_refresh(db);
        int64_t nf_cursor = -1;
        bool nf_gap = false;
        UV_CHECK("nf gap: runtime snapshot caches marker without SQL",
                 utxo_apply_nullifier_gap_snapshot(&nf_cursor, &nf_gap) &&
                     nf_cursor == 3134000 && nf_gap);
        UV_CHECK("nf gap: blocker registered for marker > 0",
                 blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));
        UV_CHECK("nf gap: blocker is PERMANENT (operator-clear only)",
                 blocker_class_for(UTXO_APPLY_NF_GAP_BLOCKER_ID) ==
                     BLOCKER_PERMANENT);
        UV_CHECK("nf gap: security posture exposes review-required gap",
                 uv_security_posture_nullifier_gap(true, 3134000));
        UV_CHECK("nf gap: transparent-only blocks still advance",
                 utxo_apply_stage_drain(100) == 2 &&
                     utxo_apply_stage_cursor() == 2);
        UV_CHECK("nf gap: transparent h=1 coins were committed",
                 uv_coin_rows_at(db, 1) > 0);
        UV_CHECK("nf gap: absent marker simulated",
                 progress_meta_delete(db,
                                      "nullifier_kv.activation_cursor"));
        utxo_apply_nullifier_gap_blocker_refresh(db);
        UV_CHECK("nf gap: absent marker is unknown, not complete",
                 utxo_apply_nullifier_gap_snapshot(&nf_cursor, &nf_gap) &&
                     nf_cursor == -1 && nf_gap &&
                     blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));
        UV_CHECK("nf gap: marker reset",
                 progress_meta_set(db, "nullifier_kv.activation_cursor",
                                   "0", 1));
        utxo_apply_nullifier_gap_blocker_refresh(db);
        UV_CHECK("nf gap: runtime snapshot observes cleared marker",
                 utxo_apply_nullifier_gap_snapshot(&nf_cursor, &nf_gap) &&
                     nf_cursor == 0 && !nf_gap);
        UV_CHECK("nf gap: blocker cleared for marker == 0",
                 !blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));
        UV_CHECK("nf gap: security posture clears nullifier gap",
                 uv_security_posture_nullifier_gap(false, 0));
        uv_teardown(dir, &ms, &sc);
    }

    /* (h) OLD-NULLIFIER PARITY CONTROL.  These paired fixtures model the same
     * candidate spend against (1) zclassicd/full history, where its below-seed
     * nullifier N is present, and (2) a truncated snapshot store, where N is
     * absent but the positive activation marker truthfully records that gap.
     * The full view must produce zclassicd's exact duplicate verdict; the
     * truncated view must HOLD rather than falsely accept. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        UV_CHECK("nf old full: setup",
                 uv_setup("nf_old_full", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        const uint8_t tag[1] = { 0x91 };
        uint8_t old_nf[32];
        uv_nf_bytes(old_nf, tag[0], 0x73);
        UV_CHECK("nf old full: candidate spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tag, 1, 0x73));
        UV_CHECK("nf old full: complete state contains N below seed",
                 nullifier_kv_add(progress_store_db(), old_nf,
                                  NULLIFIER_POOL_SAPLING, 0));
        UV_CHECK("nf old full: zclassicd-parity duplicate is rejected",
                 utxo_apply_stage_drain(100) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("nf old full: exact zclassicd status",
                 uv_blocker_reason_has("status=shielded_double_spend"));
        UV_CHECK("nf old full: exact zclassicd reject kind",
                 uv_blocker_reason_has(
                     "kind=bad-txns-joinsplit-requirements-not-met"));
        UV_CHECK("nf old full: rejected h=1 authored no coins/nullifiers",
                 uv_coin_rows_at(progress_store_db(), 1) == 0 &&
                     uv_nf_rows_at(progress_store_db(), 1) == 0 &&
                     uv_nf_rows_at(progress_store_db(), 0) == 1);
        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        UV_CHECK("nf old truncated: setup",
                 uv_setup("nf_old_truncated", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        const uint8_t tag[1] = { 0x91 };
        uint8_t old_nf[32]; bool found = true;
        uv_nf_bytes(old_nf, tag[0], 0x73);
        UV_CHECK("nf old truncated: candidate spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tag, 1, 0x73));
        UV_CHECK("nf old truncated: positive history-gap marker",
                 progress_meta_set(progress_store_db(),
                                   "nullifier_kv.activation_cursor", "1", 1));
        UV_CHECK("nf old truncated: N is absent from partial state",
                 nullifier_kv_get(progress_store_db(), old_nf,
                                  NULLIFIER_POOL_SAPLING, &found, NULL) &&
                     !found);
        UV_CHECK("nf old truncated: candidate is held fail-closed",
                 utxo_apply_stage_drain(100) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("nf old truncated: causal permanent blocker remains visible",
                 blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID) &&
                     blocker_class_for(UTXO_APPLY_NF_GAP_BLOCKER_ID) ==
                         BLOCKER_PERMANENT);
        UV_CHECK("nf old truncated: no transient peer-invalid blocker",
                 !blocker_exists("utxo_apply.apply_failed"));
        UV_CHECK("nf old truncated: no peer-invalid reject was counted",
                 uv_dump_has("\"shielded_double_spend_total\":0") &&
                     uv_dump_has("\"shielded_anchor_reject_total\":0"));
        uint32_t nf_fires_before = 0, nf_fires_after = 0;
        UV_CHECK("nf old truncated: causal blocker fire count readable",
                 uv_blocker_fire_count(UTXO_APPLY_NF_GAP_BLOCKER_ID,
                                       &nf_fires_before));
        int reads_before_retry = sc.read_calls;
        UV_CHECK("nf old truncated: retry parks JOB_IDLE",
                 utxo_apply_stage_step_once() == JOB_IDLE &&
                     sc.read_calls == reads_before_retry);
        UV_CHECK("nf old truncated: retry creates no blocker churn",
                 uv_blocker_fire_count(UTXO_APPLY_NF_GAP_BLOCKER_ID,
                                       &nf_fires_after) &&
                     nf_fires_after == nf_fires_before &&
                     !blocker_exists("utxo_apply.apply_failed"));
        UV_CHECK("nf old truncated: held h=1 authored no coins/nullifiers",
                 uv_coin_rows_at(progress_store_db(), 1) == 0 &&
                     uv_nf_rows_at(progress_store_db(), 1) == 0);
        {
            int row_ok = -1; char status[32]; char kind[32];
            UV_CHECK("nf old truncated: scratch log row rolled back",
                     !log_row_at(progress_store_db(), 1, &row_ok, status,
                                 sizeof(status), kind, sizeof(kind)) &&
                         row_ok == -1);
        }
        int reads_before_marker_change = sc.read_calls;
        UV_CHECK("nf old truncated: dependency marker generation changes",
                 progress_meta_set(progress_store_db(),
                                   "nullifier_kv.activation_cursor", "2", 1));
        UV_CHECK("nf old truncated: changed marker invalidates park",
                 utxo_apply_stage_step_once() == JOB_IDLE &&
                     sc.read_calls == reads_before_marker_change + 1 &&
                     utxo_apply_stage_cursor() == 1);
        /* Same-height replacement waits for proof+script receipts bound to the
         * replacement hash. While the causal history blocker exists it parks
         * quietly; without that cause, a stale upstream hash is named. */
        sc.bodies[1].header.nTime++;
        sc.blocks[1].nTime = sc.bodies[1].header.nTime;
        block_header_get_hash(&sc.bodies[1].header, &sc.hashes[1]);
        int reads_before_stale_verdicts = sc.read_calls;
        UV_CHECK("nf old truncated: changed hash waits for bound verdicts",
                 utxo_apply_stage_step_once() == JOB_IDLE &&
                     sc.read_calls == reads_before_stale_verdicts &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("nf old truncated: causal blocker suppresses symptoms",
                 !blocker_exists("utxo_apply.label_splice") &&
                     !blocker_exists(
                         UTXO_APPLY_STALE_UPSTREAM_HASH_BLOCKER_ID));
        blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
        UV_CHECK("nf old truncated: stale proof is named without cause",
                 utxo_apply_stage_step_once() == JOB_BLOCKED &&
                     sc.read_calls == reads_before_stale_verdicts &&
                     blocker_exists("utxo_apply.label_splice"));
        UV_CHECK("nf old truncated: replacement script is hash-bound",
                 seed_script_validate_row(progress_store_db(), 1, 1,
                                          &sc.hashes[1]));
        UV_CHECK("nf old truncated: fresh script cannot authorize stale proof",
                 utxo_apply_stage_step_once() == JOB_BLOCKED &&
                     sc.read_calls == reads_before_stale_verdicts &&
                     blocker_exists("utxo_apply.label_splice"));
        UV_CHECK("nf old truncated: hashless proof is an explicit dependency",
                 set_proof_validate_hash(progress_store_db(), 1, NULL) &&
                     utxo_apply_stage_step_once() == JOB_IDLE &&
                     sc.read_calls == reads_before_stale_verdicts &&
                     blocker_exists(
                         UTXO_APPLY_STALE_UPSTREAM_HASH_BLOCKER_ID));
        UV_CHECK("nf old truncated: replacement proof is hash-bound",
                 seed_proof_validate(progress_store_db(), &sc, 2, -1));
        int reads_before_reorg = sc.read_calls;
        UV_CHECK("nf old truncated: same-height new hash rereads and re-gates",
                 utxo_apply_stage_step_once() == JOB_IDLE &&
                     sc.read_calls == reads_before_reorg + 1 &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("nf old truncated: replacement remains fail-closed",
                 uv_coin_rows_at(progress_store_db(), 1) == 0 &&
                     uv_nf_rows_at(progress_store_db(), 1) == 0);
        UV_CHECK("nf old truncated: stale receipt blocker heals",
                 !blocker_exists("utxo_apply.label_splice") &&
                     !blocker_exists(
                         UTXO_APPLY_STALE_UPSTREAM_HASH_BLOCKER_ID));
        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }

    /* (h2) Old crash-window regression: a precreated empty nullifier table
     * with no marker at a nonzero reducer cursor must be adopted as incomplete.
     * Stage restart atomically stamps the cursor and holds the first spend. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
        UV_CHECK("nf absent marker: setup",
                 uv_setup("nf_absent_marker", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        sqlite3 *db = progress_store_db();
        utxo_apply_stage_shutdown();
        UV_CHECK("nf absent marker: table remains precreated",
                 nullifier_kv_table_exists(db));
        UV_CHECK("nf absent marker: simulate nonzero cursor",
                 exec_sql(db,
                     "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
                     "VALUES('utxo_apply',1,1)"));
        UV_CHECK("nf absent marker: simulate old missing marker",
                 progress_meta_delete(db,
                                      "nullifier_kv.activation_cursor"));
        UV_CHECK("nf absent marker: restart initializes safely",
                 utxo_apply_stage_init(&ms));
        utxo_apply_stage_set_reader(fake_reader, &sc);
        utxo_apply_stage_set_lookup(fake_lookup, &sc);
        UV_CHECK("nf absent marker: cursor stamped positive",
                 uv_meta_is(db, "nullifier_kv.activation_cursor", "1"));
        const uint8_t tag[1] = { 0x96 };
        UV_CHECK("nf absent marker: spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tag, 1, 0x77));
        UV_CHECK("nf absent marker: first spend is held",
                 utxo_apply_stage_step_once() == JOB_IDLE &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("nf absent marker: causal blocker visible",
                 blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));
        UV_CHECK("nf absent marker: no h=1 state authored",
                 uv_coin_rows_at(db, 1) == 0 && uv_nf_rows_at(db, 1) == 0);
        uv_teardown(dir, &ms, &sc);
    }

    {
        /* A storage/schema failure while reading the adoption cursor must not
         * be reinterpreted as complete genesis history. */
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("history cursor read error: setup",
                 uv_setup("history_cursor_error", 2, UV_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        sqlite3 *db = progress_store_db();
        utxo_apply_stage_shutdown();
        UV_CHECK("history cursor read error: clear old markers",
                 exec_sql(db, "DELETE FROM anchor_state") &&
                     progress_meta_delete(
                         db, "nullifier_kv.activation_cursor"));
        UV_CHECK("history cursor read error: break cursor store",
                 exec_sql(db, "DROP TABLE stage_cursor"));
        UV_CHECK("history cursor read error: init fails closed",
                 !utxo_apply_stage_init(&ms));
        int64_t cursor = -1; bool found = true;
        UV_CHECK("history cursor read error: no anchor completeness stamped",
                 anchor_kv_activation_cursor(
                     db, ANCHOR_POOL_SAPLING, &cursor, &found) && !found);
        UV_CHECK("history cursor read error: no nullifier completeness stamped",
                 nullifier_kv_activation_cursor(db, &cursor, &found) && !found);
        uv_teardown(dir, &ms, &sc);
    }

    {
        /* Missing stage_cursor on a nonempty authority is not a virgin store:
         * derive a positive incomplete boundary from coins_applied_height. */
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("history cursor lost: setup",
                 uv_setup("history_cursor_lost", 2, UV_FAIL_NONE, -1,
                          dir, sizeof(dir), &ms, &sc) == 0);
        sqlite3 *db = progress_store_db();
        UV_CHECK("history cursor lost: establish nonempty authority",
                 utxo_apply_stage_drain(1) == 1 && coins_kv_count(db) > 0);
        utxo_apply_stage_shutdown();
        UV_CHECK("history cursor lost: remove cursor and markers",
                 exec_sql(db,
                     "DELETE FROM stage_cursor WHERE name='utxo_apply'") &&
                     exec_sql(db, "DELETE FROM anchor_state") &&
                     progress_meta_delete(
                         db, "nullifier_kv.activation_cursor"));
        UV_CHECK("history cursor lost: init adopts conservative boundary",
                 utxo_apply_stage_init(&ms));
        int64_t anchor_cursor = -1; bool anchor_found = false;
        UV_CHECK("history cursor lost: anchor history remains incomplete",
                 anchor_kv_activation_cursor(
                     db, ANCHOR_POOL_SAPLING, &anchor_cursor,
                     &anchor_found) && anchor_found && anchor_cursor == 1);
        UV_CHECK("history cursor lost: nullifier history remains incomplete",
                 uv_meta_is(db, "nullifier_kv.activation_cursor", "1") &&
                     blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));
        uv_teardown(dir, &ms, &sc);
    }

    /* (i) Relevant anchor adoption gaps are also unconditional spend holds.
     * Empty roots would otherwise resolve as protocol-defined FOUND, so these
     * cases prove the preflight checks completeness, not only point lookup. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        UV_CHECK("anchor gap sapling: setup",
                 uv_setup("anchor_gap_sapling", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        const uint8_t tag[1] = { 0x92 };
        UV_CHECK("anchor gap sapling: spend attaches with empty root",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tag, 1, 0x74));
        UV_CHECK("anchor gap sapling: mark membership prefix incomplete",
                 exec_sql(progress_store_db(),
                          "UPDATE anchor_state SET activation_cursor=1 "
                          "WHERE pool=1"));
        UV_CHECK("anchor gap sapling: spend held",
                 utxo_apply_stage_drain(100) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("anchor gap sapling: causal blocker only",
                 blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID) &&
                     blocker_class_for(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID) ==
                         BLOCKER_PERMANENT &&
                     !blocker_exists("utxo_apply.apply_failed"));
        UV_CHECK("anchor gap sapling: security posture exposes gap",
                 uv_security_posture_anchor_gap(true, 1));
        UV_CHECK("anchor gap sapling: no peer-invalid reject was counted",
                 uv_dump_has("\"shielded_anchor_reject_total\":0"));
        UV_CHECK("anchor gap sapling: authored no h=1 state",
                 uv_coin_rows_at(progress_store_db(), 1) == 0 &&
                     uv_nf_rows_at(progress_store_db(), 1) == 0);
        blocker_clear("utxo_apply.apply_failed");
        blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        uv_teardown(dir, &ms, &sc);
    }
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        UV_CHECK("anchor gap sprout: setup",
                 uv_setup("anchor_gap_sprout", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("anchor gap sprout: JoinSplit attaches with empty root",
                 uv_add_joinsplit_nfs(&sc.bodies[1].vtx[1],
                                      0x93, 0x94, 0x75));
        UV_CHECK("anchor gap sprout: mark membership prefix incomplete",
                 exec_sql(progress_store_db(),
                          "UPDATE anchor_state SET activation_cursor=1 "
                          "WHERE pool=0"));
        UV_CHECK("anchor gap sprout: JoinSplit held",
                 utxo_apply_stage_drain(100) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("anchor gap sprout: causal blocker only",
                 blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID) &&
                     blocker_class_for(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID) ==
                         BLOCKER_PERMANENT &&
                     !blocker_exists("utxo_apply.apply_failed"));
        UV_CHECK("anchor gap sprout: no peer-invalid reject was counted",
                 uv_dump_has("\"shielded_anchor_reject_total\":0"));
        UV_CHECK("anchor gap sprout: authored no h=1 state",
                 uv_coin_rows_at(progress_store_db(), 1) == 0 &&
                     uv_nf_rows_at(progress_store_db(), 1) == 0);
        blocker_clear("utxo_apply.apply_failed");
        blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        uv_teardown(dir, &ms, &sc);
    }

    /* (i2) IMPORT-COMMIT CONTINUITY: after shielded_history_import_service.c's
     * exact commit sequence (anchor_kv_publish_full_replay_complete_in_tx +
     * nullifier_kv_publish_full_replay_complete_in_tx +
     * shielded_history_cancel_full_replay_in_tx, one BEGIN IMMEDIATE/COMMIT)
     * flips both anchor pools + the nullifier marker from a positive wedge
     * boundary to durably 0, the blocker refresh must RE-DERIVE from the live
     * cursor (not a stale cached verdict) and the reducer must RESUME folding
     * the SAME held block at the SAME height — no skip, no duplicate write,
     * no re-wedge on the following heights. This is the live H*=wedge shape
     * (docs/HANDOFF.md: utxo_apply.anchor_backfill_gap + the nullifier
     * history dependency raised together) taken all the way through cursor
     * flip -> blocker clear -> forward fold. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.apply_failed");
        blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
        UV_CHECK("import continuity: setup",
                 uv_setup("import_continuity", 4, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        sqlite3 *db = progress_store_db();
        const uint8_t tag[1] = { 0x97 };
        UV_CHECK("import continuity: h=1 spend attaches (empty-root anchor)",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tag, 1, 0x78));

        /* Seed the WEDGE: both anchor pools + the nullifier marker at the
         * SAME positive boundary (the importer requires a uniform boundary —
         * shielded_history_import_service.c:shi_read_boundaries refuses a
         * mixed one). */
        const int64_t boundary = 1;
        UV_CHECK("import continuity: wedge both anchor pools positive",
                 exec_sql(db, "UPDATE anchor_state SET activation_cursor=1"));
        UV_CHECK("import continuity: wedge nullifier marker positive",
                 progress_meta_set(db, "nullifier_kv.activation_cursor",
                                   "1", 1));
        utxo_apply_anchor_gap_blocker_refresh(db);
        utxo_apply_nullifier_gap_blocker_refresh(db);
        UV_CHECK("import continuity: anchor gap blocker raised",
                 blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID));
        UV_CHECK("import continuity: nullifier gap blocker raised",
                 blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

        /* h=0 (transparent) applies; h=1's spend HOLDs on the wedge — exactly
         * the live stall (JOB_IDLE, cursor pinned at the unresolved height). */
        UV_CHECK("import continuity: h=0 applies, h=1 wedges",
                 utxo_apply_stage_drain(100) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        int32_t applied_before = -1; bool applied_before_found = false;
        UV_CHECK("import continuity: coins_applied_height pinned at wedge",
                 coins_kv_get_applied_height(db, &applied_before,
                                             &applied_before_found) &&
                     applied_before_found && applied_before == 1);
        UV_CHECK("import continuity: h=1 authored nothing while wedged",
                 uv_coin_rows_at(db, 1) == 0 && uv_nf_rows_at(db, 1) == 0);

        /* Flip BOTH activation cursors to 0 via the importer's EXACT commit
         * primitives in its EXACT one-transaction sequence, WITHOUT calling
         * the refresh functions yet: proves the still-raised blocker is a
         * stale, live-recheckable cache, not something the commit itself
         * must clear. */
        progress_store_tx_lock();
        UV_CHECK("import continuity: BEGIN IMMEDIATE",
                 exec_sql(db, "BEGIN IMMEDIATE"));
        UV_CHECK("import continuity: anchor cursors published complete",
                 anchor_kv_publish_full_replay_complete_in_tx(db, boundary));
        UV_CHECK("import continuity: nullifier cursor published complete",
                 nullifier_kv_publish_full_replay_complete_in_tx(db,
                                                                 boundary));
        UV_CHECK("import continuity: replay markers cancelled",
                 shielded_history_cancel_full_replay_in_tx(db));
        UV_CHECK("import continuity: COMMIT", exec_sql(db, "COMMIT"));
        progress_store_tx_unlock();

        int64_t spr_c = -1, sap_c = -1; bool spr_f = false, sap_f = false;
        UV_CHECK("import continuity: both anchor cursors now durably 0",
                 anchor_kv_activation_cursor(db, ANCHOR_POOL_SPROUT, &spr_c,
                                             &spr_f) &&
                     anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING,
                                                 &sap_c, &sap_f) &&
                     spr_f && sap_f && spr_c == 0 && sap_c == 0);
        UV_CHECK("import continuity: nullifier cursor now durably 0",
                 uv_meta_is(db, "nullifier_kv.activation_cursor", "0"));
        UV_CHECK("import continuity: blockers still raised pre-refresh "
                 "(stale cache, not auto-cleared by the commit)",
                 blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID) &&
                     blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

        /* The next reducer tick's refresh re-derives from the LIVE cursor
         * (not a cached snapshot) and clears both. */
        utxo_apply_anchor_gap_blocker_refresh(db);
        utxo_apply_nullifier_gap_blocker_refresh(db);
        UV_CHECK("import continuity: anchor gap blocker refresh clears it",
                 !blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID));
        UV_CHECK("import continuity: nullifier gap blocker refresh clears it",
                 !blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

        /* Resume: the SAME held block at h=1 applies (no skip), then h=2,3
         * apply cleanly (no re-wedge) — the cursor reaches the full tip. */
        UV_CHECK("import continuity: fold RESUMES at h=1 (no skip) and "
                 "drains the rest (no re-wedge over h=2,3)",
                 utxo_apply_stage_drain(100) == 3 &&
                     utxo_apply_stage_cursor() == 4);
        UV_CHECK("import continuity: h=1 spend authored exactly once "
                 "(no duplicate)",
                 uv_coin_rows_at(db, 1) > 0 && uv_nf_rows_at(db, 1) == 1);
        int32_t applied_after = -1; bool applied_after_found = false;
        UV_CHECK("import continuity: coins_applied_height advances to "
                 "hstar+1 (continuity, not skipping)",
                 coins_kv_get_applied_height(db, &applied_after,
                                             &applied_after_found) &&
                     applied_after_found && applied_after == 4);
        UV_CHECK("import continuity: no residual gap blocker after resume",
                 !blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID) &&
                     !blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

        blocker_clear("utxo_apply.apply_failed");
        uv_teardown(dir, &ms, &sc);
    }

    /* (j) Malformed durable completeness evidence is a store-fatal hold, not a
     * value that strtoll silently converts to the complete marker 0. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.fatal_store");
        UV_CHECK("nf malformed: setup",
                 uv_setup("nf_malformed", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        const uint8_t tag[1] = { 0x95 };
        UV_CHECK("nf malformed: spend attaches",
                 uv_add_sapling_spends(&sc.bodies[1].vtx[1], tag, 1, 0x76));
        UV_CHECK("nf malformed: corrupt marker written",
                 progress_meta_set(progress_store_db(),
                                   "nullifier_kv.activation_cursor",
                                   "12x", 3));
        UV_CHECK("nf malformed: transparent h=0 advances then spend is fatal",
                 utxo_apply_stage_drain(100) == 1 &&
                     utxo_apply_stage_cursor() == 1);
        UV_CHECK("nf malformed: named permanent store blocker",
                 blocker_exists("utxo_apply.fatal_store") &&
                     blocker_class_for("utxo_apply.fatal_store") ==
                         BLOCKER_PERMANENT);
        UV_CHECK("nf malformed: h=1 authored no coins/nullifiers",
                 uv_coin_rows_at(progress_store_db(), 1) == 0 &&
                     uv_nf_rows_at(progress_store_db(), 1) == 0);
        uv_teardown(dir, &ms, &sc);
        blocker_clear("utxo_apply.fatal_store");
    }

    /* FIX C regression pin (job-fatal-blocker, utxo_apply_stage.c step_apply
     * ua_fatal_permanent_blocker): a genuine permanent store-corruption /
     * unrecoverable-read site inside step_apply must surface a NAMED PERMANENT
     * typed blocker (utxo_apply.fatal_store) AND return JOB_FATAL, never
     * crash-loop with an anonymous halt. Without the blocker,
     * wd_deterministic_stall_cause() finds no PERMANENT blocker on a torn
     * store and the chain_tip_watchdog burns its restart budget power-cycling
     * the same wedge; the blocker is re-derived on the first tick of every
     * boot so the stall is immediately classified "permanent_blocker_active"
     * and the node stays up degraded with a halt an operator can see via
     * `zclassic23 blockers`.
     *
     * The site exercised is the script_validate_log verdict read
     * (script_validate_log_verdict_at < 0 → ua_fatal_permanent_blocker): a
     * small positive utxo_apply cursor (1) below the proof_validate cursor (2,
     * seeded by uv_setup) with a proof_validate_log row at h=1 reaches the
     * verdict read; dropping the script_validate_log table makes its prepare
     * fail (SQLite error), so step_apply routes through the permanent blocker
     * before the JOB_FATAL return. (The ~L350 negative-persisted-cursor site
     * is defense-in-depth inside step_apply but is currently shadowed by
     * utxo_apply_reorg_unwind_if_needed's own `cursor > INT32_MAX` guard,
     * which intercepts a huge cursor earlier in utxo_apply_stage_step_once and
     * returns JOB_FATAL without the blocker — a separate gap; this test pins
     * the step_apply permanent-blocker mechanism at a site that IS reachable
     * through the public entry point.) */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        blocker_clear("utxo_apply.fatal_store");
        UV_CHECK("fatal_store: setup",
                 uv_setup("fatal_store", 2, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        /* Hold the utxo_apply cursor at h=1 (next height to apply), with
         * proof_validate already at 2 so step_apply's pv_cursor guard passes
         * next_h=1 through to the verdict read. proof_validate_log already
         * holds an ok row at h=1 (seeded by uv_setup), so the L400 read does
         * not fatal first. */
        UV_CHECK("fatal_store: hold utxo_apply cursor at h=1",
                 exec_sql(progress_store_db(),
                          "INSERT OR REPLACE INTO stage_cursor(name,cursor,"
                          "updated_at) VALUES('utxo_apply',1,1)"));
        /* Corrupt the store: drop script_validate_log so the verdict-read
         * prepare fails (returns < 0), routing step_apply through
         * ua_fatal_permanent_blocker. */
        UV_CHECK("fatal_store: drop script_validate_log (torn store)",
                 exec_sql(progress_store_db(),
                          "DROP TABLE script_validate_log"));
        job_result_t r = utxo_apply_stage_step_once();
        UV_CHECK("fatal_store: step returns JOB_FATAL", r == JOB_FATAL);
        UV_CHECK("fatal_store: permanent blocker registered",
                 blocker_exists("utxo_apply.fatal_store"));
        UV_CHECK("fatal_store: blocker class is PERMANENT",
                 blocker_class_for("utxo_apply.fatal_store") ==
                     BLOCKER_PERMANENT);
        blocker_clear("utxo_apply.fatal_store");
        uv_teardown(dir, &ms, &sc);
    }

    /* ── Lane A1: created_outputs prune DECOUPLED from the kernel co-commit ──
     * The prune now runs post-commit in its OWN tx from utxo_apply_stage_drain,
     * computed from the final committed cursor. Proves: (1) a crash between the
     * kernel commit and the prune leaves extra created_outputs rows that are
     * harmless and get pruned on the NEXT advancing drain; (2) the coins
     * commitment is invariant to the prune (no consensus value in it). Uses the
     * test-only retention override so the prune fires over a 6-block chain. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        const int N = 6;
        UV_CHECK("prune_decouple: setup",
                 uv_setup("prune_decouple", N, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        sqlite3 *db = progress_store_db();
        /* retention=2 → after applying to cursor C, prune floor = C-2. */
        utxo_apply_created_outputs_retain_set_for_test(2);
        /* Populate created_outputs for every height exactly as body_persist
         * (the upstream stage) would; 2 outputs per block (coinbase + tx). */
        UV_CHECK("prune_decouple: created_outputs schema",
                 created_outputs_index_ensure_schema(db));
        bool seeded_co = true;
        for (int h = 0; h < N; h++)
            seeded_co = seeded_co &&
                created_outputs_index_put_block(db, &sc.bodies[h], h);
        UV_CHECK("prune_decouple: created_outputs seeded 0..5", seeded_co);

        uint64_t runs0 = 0; int64_t floor0 = 0;
        utxo_apply_post_prune_stats(&runs0, &floor0);

        /* Drain the first three heights → cursor=3 → post-commit prune floor=1
         * → created_outputs h<1 pruned (h=0 gone), h>=1 retained. */
        UV_CHECK("prune_decouple: drain 3", utxo_apply_stage_drain(3) == 3);
        UV_CHECK("prune_decouple: cursor at 3", utxo_apply_stage_cursor() == 3);
        uint64_t runs1 = 0; int64_t floor1 = 0;
        utxo_apply_post_prune_stats(&runs1, &floor1);
        UV_CHECK("prune_decouple: post-commit prune ran (own tx)",
                 runs1 == runs0 + 1 && floor1 == 1);
        UV_CHECK("prune_decouple: h=0 pruned below floor", co_rows_at(db, 0) == 0);
        UV_CHECK("prune_decouple: h=1,2 retained at/above floor",
                 co_rows_at(db, 1) == 2 && co_rows_at(db, 2) == 2);

        /* Simulate a crash that left EXTRA stale rows a completed prune would
         * have removed: re-insert h=0's created_outputs (below the future
         * floor). The next advancing drain's post-commit prune must remove it. */
        UV_CHECK("prune_decouple: re-seed stale h=0 (crash residue)",
                 created_outputs_index_put_block(db, &sc.bodies[0], 0) &&
                 co_rows_at(db, 0) == 2);

        /* Drain the remaining three heights → cursor=6 → prune floor=4 →
         * created_outputs h<4 pruned (the re-seeded h=0 residue + 1,2,3 gone),
         * h>=4 retained. Extra rows pruned on the NEXT drain — convergence. */
        UV_CHECK("prune_decouple: drain rest", utxo_apply_stage_drain(100) == 3);
        UV_CHECK("prune_decouple: cursor at 6", utxo_apply_stage_cursor() == 6);
        uint64_t runs2 = 0; int64_t floor2 = 0;
        utxo_apply_post_prune_stats(&runs2, &floor2);
        UV_CHECK("prune_decouple: second post-commit prune ran",
                 runs2 == runs1 + 1 && floor2 == 4);
        UV_CHECK("prune_decouple: crash-residue h=0 pruned on next drain",
                 co_rows_at(db, 0) == 0);
        UV_CHECK("prune_decouple: h=1,2,3 pruned below floor",
                 co_rows_at(db, 1) == 0 && co_rows_at(db, 2) == 0 &&
                 co_rows_at(db, 3) == 0);
        UV_CHECK("prune_decouple: h=4,5 retained at/above floor",
                 co_rows_at(db, 4) == 2 && co_rows_at(db, 5) == 2);

        /* Coins commitment is INVARIANT to the prune: all 6 heights applied,
         * every coinbase (50+h) and tx output (900+h) live, exactly 2*N coins.
         * The prune touched only the created_outputs projection. */
        bool coins_ok = coins_kv_count(db) == 2 * N;
        for (int h = 0; h < N && coins_ok; h++) {
            struct uint256 id; int64_t v = -1;
            synthetic_txid(&id, h, 1);
            coins_ok = coins_ok &&
                coins_kv_get(db, id.data, 0, &v, NULL, 0, NULL) && v == 50 + h;
            synthetic_txid(&id, h, 2);
            v = -1;
            coins_ok = coins_ok &&
                coins_kv_get(db, id.data, 0, &v, NULL, 0, NULL) && v == 900 + h;
        }
        UV_CHECK("prune_decouple: coins commitment unchanged by prune", coins_ok);

        utxo_apply_created_outputs_retain_set_for_test(-1);
        uv_teardown(dir, &ms, &sc);
    }

    /* ── H2: batch-commit telemetry (ring/EWMA math + a commit records it) ── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        const int N = 5;
        UV_CHECK("batch_commit: setup",
                 uv_setup("batch_commit", N, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);

        /* Deterministic starting point: zero every rolling-stats field so
         * this block's assertions are exact, not "increased by at least". */
        utxo_apply_batch_commit_reset_for_test();

        struct json_value idle;
        json_init(&idle);
        UV_CHECK("batch_commit: idle dump before any commit",
                 utxo_apply_batch_commit_dump_state_json(&idle, NULL));
        UV_CHECK("batch_commit: idle total_commits == 0",
                 json_get_int(json_get(&idle, "total_commits")) == 0);
        UV_CHECK("batch_commit: idle ring_samples == 0",
                 json_get_int(json_get(&idle, "ring_samples")) == 0);
        json_free(&idle);

        /* Drain all N heights in one call -> exactly one outer-batch COMMIT,
         * so this is the simplest possible "a commit records a sample"
         * proof: the drive itself calls utxo_apply_batch_commit_record()
         * from inside utxo_apply_stage_drain() on the committed path. */
        UV_CHECK("batch_commit: drain all N heights in one batch",
                 utxo_apply_stage_drain(100) == N);

        struct json_value after1;
        json_init(&after1);
        UV_CHECK("batch_commit: dump after first drain",
                 utxo_apply_batch_commit_dump_state_json(&after1, NULL));
        UV_CHECK("batch_commit: total_commits == 1 after one drain",
                 json_get_int(json_get(&after1, "total_commits")) == 1);
        UV_CHECK("batch_commit: ring_samples == 1 after one drain",
                 json_get_int(json_get(&after1, "ring_samples")) == 1);
        /* Heights are 0-indexed (h=0..N-1) and g_ua_last_advance_height
         * starts at -1 (fresh init), so a first-ever batch that folds all N
         * heights reports the range 0..N-1. */
        UV_CHECK("batch_commit: last_height_lo == 0, last_height_hi == N-1",
                 json_get_int(json_get(&after1, "last_height_lo")) == 0 &&
                 json_get_int(json_get(&after1, "last_height_hi")) == N - 1);
        UV_CHECK("batch_commit: last_rows == N",
                 json_get_int(json_get(&after1, "last_rows")) == N);
        int64_t first_us = json_get_int(json_get(&after1, "last_commit_us"));
        UV_CHECK("batch_commit: last_commit_us >= 1 (floored, never 0)",
                 first_us >= 1);
        UV_CHECK("batch_commit: commit_us_ewma == first sample "
                 "(EWMA seeds from the first sample)",
                 json_get_int(json_get(&after1, "commit_us_ewma")) == first_us);
        UV_CHECK("batch_commit: commit_us_max == first sample",
                 json_get_int(json_get(&after1, "commit_us_max")) == first_us);
        UV_CHECK("batch_commit: ring_avg_us == first sample",
                 json_get_int(json_get(&after1, "ring_avg_us")) == first_us);
        json_free(&after1);
        UV_CHECK("batch_commit: drain returns 0 at tip (no further commit)",
                 utxo_apply_stage_drain(100) == 0);

        /* No further heights to fold, so no second outer-batch COMMIT is
         * issued (a drain with advanced==0 and no dirty non-advancing work
         * never opens/COMMITs a batch) -> total_commits stays 1. Exercise
         * the ring/EWMA math directly instead, over a synthetic sequence
         * with a known closed form, decoupled from real fold timing. */
        utxo_apply_batch_commit_reset_for_test();
        int64_t samples[] = { 100, 200, 300, 400 };
        int64_t ewma = 0;
        for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
            /* height_before_batch = i*10, rows=1 -> folded height i*10+1. */
            utxo_apply_batch_commit_record((int64_t)(i * 10), 1, samples[i]);
            ewma = (i == 0) ? samples[i] : ewma + (samples[i] - ewma) / 16;
        }
        struct json_value synth;
        json_init(&synth);
        UV_CHECK("batch_commit: synthetic dump",
                 utxo_apply_batch_commit_dump_state_json(&synth, NULL));
        UV_CHECK("batch_commit: synthetic total_commits == 4",
                 json_get_int(json_get(&synth, "total_commits")) == 4);
        UV_CHECK("batch_commit: synthetic ring_samples == 4",
                 json_get_int(json_get(&synth, "ring_samples")) == 4);
        UV_CHECK("batch_commit: synthetic commit_us_ewma matches closed form",
                 json_get_int(json_get(&synth, "commit_us_ewma")) == ewma);
        UV_CHECK("batch_commit: synthetic commit_us_max == 400 (running max)",
                 json_get_int(json_get(&synth, "commit_us_max")) == 400);
        UV_CHECK("batch_commit: synthetic ring_avg_us == mean(100,200,300,400)",
                 json_get_int(json_get(&synth, "ring_avg_us")) == 250);
        UV_CHECK("batch_commit: synthetic last_height_lo/hi == last record's "
                 "folded height (30+1)",
                 json_get_int(json_get(&synth, "last_height_lo")) == 31 &&
                 json_get_int(json_get(&synth, "last_height_hi")) == 31);
        json_free(&synth);

        utxo_apply_batch_commit_reset_for_test();
        uv_teardown(dir, &ms, &sc);
    }

    /* A resumed stage must seed its observer from the durable cursor before
     * the first drain. Otherwise the first real post-checkpoint commit is
     * falsely logged as heights 0..N even though state advances at C+1. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_uv sc;
        UV_CHECK("batch_commit resume: setup",
                 uv_setup("batch_commit_resume", 5, UV_FAIL_NONE, -1, dir,
                          sizeof(dir), &ms, &sc) == 0);
        UV_CHECK("batch_commit resume: establish durable prefix",
                 utxo_apply_stage_drain(3) == 3 &&
                 utxo_apply_stage_cursor() == 3);
        utxo_apply_stage_shutdown();
        UV_CHECK("batch_commit resume: reinitialize stage",
                 utxo_apply_stage_init(&ms));
        utxo_apply_stage_set_reader(fake_reader, &sc);
        utxo_apply_stage_set_lookup(fake_lookup, &sc);
        utxo_apply_batch_commit_reset_for_test();
        UV_CHECK("batch_commit resume: fold remaining suffix",
                 utxo_apply_stage_drain(100) == 2);
        struct json_value resumed;
        json_init(&resumed);
        UV_CHECK("batch_commit resume: dump",
                 utxo_apply_batch_commit_dump_state_json(&resumed, NULL));
        UV_CHECK("batch_commit resume: absolute range is 3..4",
                 json_get_int(json_get(&resumed, "last_height_lo")) == 3 &&
                 json_get_int(json_get(&resumed, "last_height_hi")) == 4);
        json_free(&resumed);
        uv_teardown(dir, &ms, &sc);
    }

    /* Task A #1 — apply-candidate anomaly is split from legitimate window lag.
     * utxo_apply_select_apply_block returning NULL used to fold BOTH classes
     * into one silent JOB_IDLE with no typed blocker. Now a REAL anomaly
     * (block map / durable-or-visible parent / on-disk body disagreeing with
     * the ok-bound verdict) names "utxo_apply.apply_candidate_anomaly"
     * (TRANSIENT, height in reason) so the safety net keyed off the blocker
     * registry sees it; a legitimate wait clears the blocker. Exercised
     * directly against utxo_apply_select_idle_note (the classification), which
     * is what every NULL-return in select_apply_block routes through. */
    {
        blocker_clear("utxo_apply.apply_candidate_anomaly");

        /* Each anomaly reason must raise the typed blocker. */
        enum utxo_apply_select_idle_reason anomalies[] = {
            UA_SELECT_IDLE_INDEXED_BODY_READ_FAILED,
            UA_SELECT_IDLE_INDEXED_BODY_HASH_MISMATCH,
            UA_SELECT_IDLE_BLOCK_MAP_MISS,
            UA_SELECT_IDLE_HEIGHT_MISMATCH,
            UA_SELECT_IDLE_PARENT_MISMATCH,
        };
        bool all_anom_raise = true;
        for (size_t i = 0; i < sizeof(anomalies) / sizeof(anomalies[0]); i++) {
            blocker_clear("utxo_apply.apply_candidate_anomaly");
            utxo_apply_select_idle_note(4242 + (int)i, anomalies[i], NULL);
            struct blocker_snapshot sn[32];
            int nn = blocker_snapshot_all(sn, 32);
            bool found = false;
            for (int k = 0; k < nn; k++) {
                if (strcmp(sn[k].id, "utxo_apply.apply_candidate_anomaly") == 0) {
                    char needle[32];
                    snprintf(needle, sizeof(needle), "height=%d", 4242 + (int)i);
                    found = sn[k].class == BLOCKER_TRANSIENT &&
                            strstr(sn[k].reason, needle) != NULL &&
                            strstr(sn[k].reason,
                                   utxo_apply_select_idle_reason_name(
                                       anomalies[i])) != NULL;
                    break;
                }
            }
            if (!found) all_anom_raise = false;
        }
        UV_CHECK("candidate_anomaly: every anomaly reason names the typed "
                 "TRANSIENT blocker with height + reason", all_anom_raise);

        /* A legitimate wait-reason clears it (a just-resolved anomaly must not
         * leave a stale claim behind). */
        utxo_apply_select_idle_note(4242, UA_SELECT_IDLE_ACTIVE_CHAIN_MISSING,
                                    NULL);
        UV_CHECK("candidate_anomaly: window-lag wait clears the blocker",
                 !blocker_exists("utxo_apply.apply_candidate_anomaly"));

        /* The explicit clear helper (called on the success paths in
         * utxo_apply_select_apply_block) is a no-op-safe clear. */
        utxo_apply_select_idle_note(4242, UA_SELECT_IDLE_BLOCK_MAP_MISS, NULL);
        UV_CHECK("candidate_anomaly: re-raised before clear helper",
                 blocker_exists("utxo_apply.apply_candidate_anomaly"));
        utxo_apply_select_idle_blocker_clear();
        UV_CHECK("candidate_anomaly: clear helper removes it",
                 !blocker_exists("utxo_apply.apply_candidate_anomaly"));

        /* The LIVE hold accessor recovery Conditions read (tip_fork_stale's
         * corroborated fast path). It must report the held height only while the
         * hold is live, and -1 the instant it ends — the last-observed
         * select_idle_height, which survives the hold, is not good enough. */
        UV_CHECK("anomaly_hold: -1 once the hold is cleared",
                 utxo_apply_stage_candidate_anomaly_hold_height() == -1);
        utxo_apply_select_idle_note(3195364, UA_SELECT_IDLE_PARENT_MISMATCH,
                                    NULL);
        UV_CHECK("anomaly_hold: reports the held height while live "
                 "(incident shape: parent_mismatch at tip+1)",
                 utxo_apply_stage_candidate_anomaly_hold_height() == 3195364);
        /* A legitimate wait-reason ends the hold; the stale last-observed height
         * must not keep the accessor reporting a wedge. */
        utxo_apply_select_idle_note(3195364, UA_SELECT_IDLE_NO_SCRIPT_HASH,
                                    NULL);
        UV_CHECK("anomaly_hold: -1 when the hold resolves to a plain wait, "
                 "even at the same height",
                 utxo_apply_stage_candidate_anomaly_hold_height() == -1 &&
                 utxo_apply_stage_select_idle_height() == 3195364);
    }

    printf("utxo_apply_stage tests: %s\n", failures ? "FAILED" : "PASSED");
    return failures;
}
