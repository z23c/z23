/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_pv_lookahead — the differential parity oracle for the offline-mint
 * cross-height proof pre-verification pool (engine/jobs/src/pv_lookahead.c).
 *
 * Each scenario folds the SAME synthetic chain through the real
 * proof_validate stage twice — once with the pool off (the serial reference)
 * and once with the pool started and fully warmed (every consume is a cache
 * HIT) — and asserts byte-identical per-height proof_validate_log rows
 * (status, ok, proof totals, failure txid + type) and identical stage counter
 * totals. Poisoned-proof, wrong-hash cache-miss, all-miss fallback, and the
 * internal-error-never-cached TL-2 hold are each pinned the same way. One leg
 * runs the REAL verifier (sapling params + ed25519 joinsplit check) instead of
 * the injected one. */

#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "jobs/catchup_cadence.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/pv_lookahead.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/params_init.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PVLA_CHECK(name, expr) do { \
    printf("pv_lookahead: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── fixture: synthetic chain of shielded (or plain) blocks ──────────────── */

struct la_chain {
    struct block_index *blocks;
    struct uint256     *hashes;
    struct block       *bodies;
    int                 n;
    int                 fail_height;         /* injected-verifier controls */
    bool                fail_internal;
    bool                plain_first;         /* h=0 carries no shielded proofs */
};

static bool la_make_shielded_tx(struct transaction *tx, int h)
{
    transaction_init(tx);
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->num_shielded_spend = 1;
    tx->v_shielded_spend = zcl_calloc(1, sizeof(struct spend_description),
                                      "la_spend");
    tx->num_shielded_output = 1;
    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "la_output");
    tx->num_joinsplit = 2;
    tx->v_joinsplit = zcl_calloc(2, sizeof(struct js_description),
                                 "la_joinsplit");
    if (!tx->v_shielded_spend || !tx->v_shielded_output || !tx->v_joinsplit)
        return false;
    tx->v_joinsplit[0].use_groth = true;
    tx->v_joinsplit[1].use_groth = false;
    memset(tx->joinsplit_pubkey.data, h & 0xff, 32);
    memset(tx->binding_sig, 0x42, 64);
    transaction_compute_hash(tx);
    return true;
}

static bool la_make_plain_tx(struct transaction *tx, int h)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    outpoint_set_null(&tx->vin[0].prevout);
    script_init(&tx->vin[0].script_sig);
    tx->vout[0].value = 1000 + h;
    script_init(&tx->vout[0].script_pub_key);
    transaction_compute_hash(tx);
    return true;
}

static bool la_make_body(struct la_chain *sc, int h)
{
    struct block *b = &sc->bodies[h];
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700002000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 1;
    b->vtx = zcl_calloc(1, sizeof(struct transaction), "la_tx");
    if (!b->vtx) return false;
    bool built = (sc->plain_first && h == 0)
        ? la_make_plain_tx(&b->vtx[0], h)
        : la_make_shielded_tx(&b->vtx[0], h);
    if (!built) return false;
    struct uint256 txids[1] = { b->vtx[0].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 1);
    return true;
}

static bool la_chain_build(struct la_chain *sc, int n, bool plain_first)
{
    memset(sc, 0, sizeof(*sc));
    sc->fail_height = -1;
    sc->plain_first = plain_first;
    sc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index), "la_blocks");
    sc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "la_hashes");
    sc->bodies = zcl_calloc((size_t)n, sizeof(struct block), "la_bodies");
    if (!sc->blocks || !sc->hashes || !sc->bodies)
        return false;
    for (int i = 0; i < n; i++) {
        if (!la_make_body(sc, i)) return false;
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

static void la_chain_free(struct la_chain *sc)
{
    if (sc->bodies) {
        for (int i = 0; i < sc->n; i++)
            block_free(&sc->bodies[i]);
    }
    free(sc->blocks);
    free(sc->hashes);
    free(sc->bodies);
    memset(sc, 0, sizeof(*sc));
}

static bool la_reader(struct block *out, const struct block_index *bi,
                      const char *datadir, void *user)
{
    (void)datadir;
    struct la_chain *sc = user;
    if (!out || !bi || !sc || bi->nHeight < 0 || bi->nHeight >= sc->n)
        return false;
    return test_block_copy(out, &sc->bodies[bi->nHeight], "la_tx_copy");
}

static bool la_reader_never(struct block *out, const struct block_index *bi,
                            const char *datadir, void *user)
{
    (void)out; (void)bi; (void)datadir; (void)user;
    return false;
}

/* Injected verifier: fixed per-tx proof totals; sc->fail_height selects one
 * failing height (proof_invalid, or internal_error when sc->fail_internal). */
static bool la_verifier(const struct transaction *tx, int height,
                        struct proof_validate_tx_report *out, void *user)
{
    struct la_chain *sc = user;
    memset(out, 0, sizeof(*out));
    out->ok = true;
    out->sapling_spends_total = tx ? tx->num_shielded_spend : 0;
    out->sapling_outputs_total = tx ? tx->num_shielded_output : 0;
    out->sprout_joinsplits_total = tx ? tx->num_joinsplit : 0;
    if (!sc || height != sc->fail_height)
        return true;
    out->ok = false;
    out->internal_error = sc->fail_internal;
    out->first_failure_proof_type =
        sc->fail_internal ? "sapling_ctx" : "sapling_spend";
    return true;
}

/* ── seeding + row/counter snapshots ─────────────────────────────────────── */

static bool la_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool la_seed_script_validate(sqlite3 *db, const struct la_chain *sc)
{
    if (!la_exec(db,
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height             INTEGER PRIMARY KEY,"
        "  status             TEXT    NOT NULL,"
        "  ok                 INTEGER NOT NULL,"
        "  tx_count           INTEGER NOT NULL,"
        "  input_count        INTEGER NOT NULL,"
        "  first_failure_txid BLOB,"
        "  first_failure_vin  INTEGER,"
        "  block_hash         BLOB,"
        "  validated_at       INTEGER NOT NULL"
        ")"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO script_validate_log "
        "(height, status, ok, tx_count, input_count, block_hash, validated_at) "
        "VALUES (?, 'verified', 1, 1, 1, ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < sc->n; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {  // raw-sql-ok:test-fixture-seeding
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES('script_validate', ?, 1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, sc->n);
    bool ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

struct la_row {
    bool   present;
    int    ok;
    char   status[32];
    char   type[32];
    char   txid_hex[65];
    int64_t spends, outputs, joinsplits;
};

static bool la_row_at(sqlite3 *db, int height, struct la_row *r)
{
    memset(r, 0, sizeof(*r));
    r->ok = -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status, first_failure_proof_type, first_failure_txid, "
        "sapling_spends_total, sapling_outputs_total, sprout_joinsplits_total "
        "FROM proof_validate_log WHERE height = ?", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:test-fixture-assertion
        r->present = true;
        r->ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt) snprintf(r->status, sizeof(r->status), "%s", (const char *)txt);
        const unsigned char *typ = sqlite3_column_text(st, 2);
        if (typ) snprintf(r->type, sizeof(r->type), "%s", (const char *)typ);
        if (sqlite3_column_type(st, 3) == SQLITE_BLOB &&
            sqlite3_column_bytes(st, 3) == 32) {
            const unsigned char *b = sqlite3_column_blob(st, 3);
            for (int i = 0; i < 32; i++)
                snprintf(r->txid_hex + 2 * i, 3, "%02x", b[i]);
        }
        r->spends = sqlite3_column_int64(st, 4);
        r->outputs = sqlite3_column_int64(st, 5);
        r->joinsplits = sqlite3_column_int64(st, 6);
    }
    sqlite3_finalize(st);
    return true;
}

static bool la_rows_eq(const struct la_row *a, const struct la_row *b)
{
    return a->present == b->present && a->ok == b->ok &&
           strcmp(a->status, b->status) == 0 &&
           strcmp(a->type, b->type) == 0 &&
           strcmp(a->txid_hex, b->txid_hex) == 0 &&
           a->spends == b->spends && a->outputs == b->outputs &&
           a->joinsplits == b->joinsplits;
}

struct la_counters {
    uint64_t verified, proof_invalid, internal_error, upstream_failed;
    uint64_t sp_ok, sp_bad, out_ok, out_bad;
    uint64_t g16_ok, g16_bad, phgr_ok, phgr_bad, bind_ok, bind_bad;
};

static void la_counters_capture(struct la_counters *c)
{
    c->verified = proof_validate_stage_verified_total();
    c->proof_invalid = proof_validate_stage_proof_invalid_total();
    c->internal_error = proof_validate_stage_internal_error_total();
    c->upstream_failed = proof_validate_stage_upstream_failed_total();
    c->sp_ok = proof_validate_stage_sapling_spends_verified_total();
    c->sp_bad = proof_validate_stage_sapling_spends_failed_total();
    c->out_ok = proof_validate_stage_sapling_outputs_verified_total();
    c->out_bad = proof_validate_stage_sapling_outputs_failed_total();
    c->g16_ok = proof_validate_stage_sprout_groth16_verified_total();
    c->g16_bad = proof_validate_stage_sprout_groth16_failed_total();
    c->phgr_ok = proof_validate_stage_sprout_phgr13_verified_total();
    c->phgr_bad = proof_validate_stage_sprout_phgr13_failed_total();
    c->bind_ok = proof_validate_stage_binding_sig_verified_total();
    c->bind_bad = proof_validate_stage_binding_sig_failed_total();
}

static bool la_counters_eq(const struct la_counters *a,
                           const struct la_counters *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

/* ── the fold runner ─────────────────────────────────────────────────────── */

enum la_pool_mode {
    LA_POOL_OFF,        /* serial reference */
    LA_POOL_WARM,       /* start pool via the stage wrapper; wait for warm-up */
    LA_POOL_DEAD_READER, /* pool started with a never-succeeding reader */
    LA_POOL_HEIGHT_GAP  /* one body missing; later exact hashes still warm */
};

struct la_result {
    bool setup_ok;
    bool warm_ok;
    int  drained;
    uint64_t cursor;
    uint64_t hits, misses;
    bool wrong_hash_missed;
    struct la_counters counters;
    struct la_row rows[64];
    int n_rows;
};

static bool la_wait_populated(uint64_t target, int timeout_ms)
{
    for (int i = 0; i < timeout_ms / 2 + 1; i++) {
        if (pv_lookahead_populated() >= target)
            return true;
        platform_sleep_ms(2);
    }
    return pv_lookahead_populated() >= target;
}

/* Fold the fixture once through the real stage. `use_real_verifier` selects
 * the built-in (params + ed25519) verifier instead of la_verifier. `expect`
 * is the number of heights expected to populate in WARM mode (fail_internal
 * heights are never cached). */
static bool la_seed_stage_cursor(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (!db || !name || cursor < 0 || sqlite3_prepare_v2(
            db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static void la_fold_from(struct la_result *out, const char *tag, int n,
                         bool plain_first, int fail_height,
                         bool fail_internal, bool use_real_verifier,
                         enum la_pool_mode mode, uint64_t warm_expect,
                         int start_cursor, int body_gap)
{
    memset(out, 0, sizeof(*out));
    if (n > 64 || start_cursor < 0 || start_cursor > n ||
        (body_gap >= 0 && (body_gap < start_cursor || body_gap >= n)))
        return;

    char dir[256];
    struct main_state ms;
    struct la_chain sc;
    test_make_tmpdir(dir, sizeof(dir), "pv_lookahead", tag);
    if (!progress_store_open(dir))
        return;
    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    if (!la_chain_build(&sc, n, plain_first)) {
        progress_store_close();
        return;
    }
    sc.fail_height = fail_height;
    sc.fail_internal = fail_internal;
    if (mode == LA_POOL_HEIGHT_GAP) {
        if (body_gap < 0) {
            la_chain_free(&sc);
            active_chain_free(&ms.chain_active);
            progress_store_close();
            return;
        }
        block_index_status_clear_bits(&sc.blocks[body_gap], BLOCK_HAVE_DATA);
    }
    active_chain_move_window_tip(&ms.chain_active, &sc.blocks[n - 1]);
    if (!la_seed_script_validate(progress_store_db(), &sc) ||
        !la_seed_stage_cursor(progress_store_db(), "proof_validate",
                              start_cursor) ||
        !proof_validate_stage_init(&ms)) {
        la_chain_free(&sc);
        active_chain_free(&ms.chain_active);
        progress_store_close();
        return;
    }
    proof_validate_stage_set_reader(la_reader, &sc);
    if (!use_real_verifier)
        proof_validate_stage_set_tx_verifier(la_verifier, &sc);
    out->setup_ok = true;

    out->warm_ok = true;
    if (mode == LA_POOL_WARM || mode == LA_POOL_HEIGHT_GAP) {
        out->warm_ok = proof_validate_lookahead_start() &&
                       la_wait_populated(warm_expect, 10000);
    } else if (mode == LA_POOL_DEAD_READER) {
        /* Direct start with a reader that never yields a block: every consume
         * must MISS and the stage must fold inline, verdict-identical. */
        out->warm_ok = pv_lookahead_start(
            &ms, dir, la_reader_never, &sc,
            use_real_verifier ? NULL : la_verifier,
            use_real_verifier ? NULL : (void *)&sc);
    }

    if (mode == LA_POOL_HEIGHT_GAP) {
        /* A wrong hash at the first readable height beyond the gap must miss
         * without consuming the exact-hash slot.  The serial drive below then
         * consumes that same slot through the selected block hash. */
        int probe_h = body_gap + 1;
        if (out->warm_ok && probe_h < n) {
            struct uint256 wrong = sc.hashes[probe_h];
            wrong.data[0] ^= 0xff;
            struct pv_lookahead_verdict ignored;
            out->wrong_hash_missed = !pv_lookahead_take(
                probe_h, &wrong,
                use_real_verifier ? NULL : la_verifier,
                use_real_verifier ? NULL : (void *)&sc, &ignored);
        }
        /* Make the held serial height readable.  The pool deliberately does
         * not backtrack over a per-height gap, so this height verifies inline;
         * the already-warmed later heights remain exact-hash cache hits. */
        block_index_status_fetch_or(&sc.blocks[body_gap], BLOCK_HAVE_DATA);
    }

    out->drained = proof_validate_stage_drain(1000);
    out->cursor = proof_validate_stage_cursor();
    out->hits = pv_lookahead_hit_total();
    out->misses = pv_lookahead_miss_total();
    la_counters_capture(&out->counters);
    out->n_rows = n;
    for (int h = 0; h < n; h++)
        (void)la_row_at(progress_store_db(), h, &out->rows[h]);

    proof_validate_stage_shutdown();   /* stops the pool first (idempotent) */
    la_chain_free(&sc);
    active_chain_free(&ms.chain_active);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

static void la_fold(struct la_result *out, const char *tag, int n,
                    bool plain_first, int fail_height, bool fail_internal,
                    bool use_real_verifier, enum la_pool_mode mode,
                    uint64_t warm_expect)
{
    la_fold_from(out, tag, n, plain_first, fail_height, fail_internal,
                 use_real_verifier, mode, warm_expect,
                 /*start_cursor=*/0, /*body_gap=*/-1);
}

static bool la_results_identical(const struct la_result *a,
                                 const struct la_result *b)
{
    if (!a->setup_ok || !b->setup_ok || a->drained != b->drained ||
        a->cursor != b->cursor || a->n_rows != b->n_rows ||
        !la_counters_eq(&a->counters, &b->counters))
        return false;
    for (int h = 0; h < a->n_rows; h++)
        if (!la_rows_eq(&a->rows[h], &b->rows[h]))
            return false;
    return true;
}

/* ── the tests ───────────────────────────────────────────────────────────── */

static bool la_params_available(void)
{
    if (sapling_params_loaded())
        return true;
    const char *home = getenv("HOME");
    char params_dir[512];
    snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
             home ? home : ".");
    return sapling_init_params(params_dir);
}

int test_pv_lookahead(void);
int test_pv_lookahead(void)
{
    printf("\n=== pv_lookahead differential parity tests ===\n");
    int failures = 0;
    blocker_module_init();
    chain_params_select(CHAIN_MAIN);

    PVLA_CHECK("capacity: one default catch-up drain fits in the exact-key ring",
               PV_LOOKAHEAD_WINDOW >= CATCHUP_CADENCE_DEFAULT_DRAIN_BATCH);

    /* 1) Full-window differential: 64 heights, one poisoned proof at h=40 —
     * every consume is a HIT, all rows + counters identical to serial. */
    {
        struct la_result serial, pooled;
        la_fold(&serial, "d_ser", 64, false, 40, false, false,
                LA_POOL_OFF, 0);
        la_fold(&pooled, "d_pool", 64, false, 40, false, false,
                LA_POOL_WARM, 64);
        PVLA_CHECK("diff: serial setup + full drain",
                   serial.setup_ok && serial.drained == 64);
        PVLA_CHECK("diff: pool warmed all 64 heights", pooled.warm_ok);
        PVLA_CHECK("diff: pooled fold consumed 64 hits, 0 misses",
                   pooled.hits == 64 && pooled.misses == 0);
        PVLA_CHECK("diff: rows + counters + cursor identical",
                   la_results_identical(&serial, &pooled));
        PVLA_CHECK("diff: poisoned row is proof_invalid/sapling_spend both ways",
                   serial.rows[40].present && serial.rows[40].ok == 0 &&
                   strcmp(serial.rows[40].status, "proof_invalid") == 0 &&
                   strcmp(serial.rows[40].type, "sapling_spend") == 0 &&
                   pooled.rows[40].present && pooled.rows[40].ok == 0);
    }

    /* 2) REAL verifier (sapling params + ed25519): h0 proof-free (real ok),
     * h1 garbage joinsplit sig (real proof_invalid/joinsplit_sig). */
    if (!la_params_available()) {
        /* Honest, LOUD self-skip (counted by test_parallel's "SKIP (" sentinel
         * scan) — this scenario needs the real Sapling prover/verifier to
         * drive a genuine joinsplit-signature-invalid verdict; the ~770MB
         * param files are not in the repo and are not fetched by hosted CI.
         * Every other differential scenario in this file uses the injected
         * la_verifier and needs no params at all. */
        printf("  SKIP (real verifier differential) — ~/.zcash-params "
               "absent; this leg needs the real Sapling prover to drive a "
               "genuine joinsplit-signature-invalid verdict, not the "
               "injected la_verifier test hook. The other differential "
               "scenarios in this file still run.\n");
    } else {
        struct la_result serial, pooled;
        la_fold(&serial, "r_ser", 2, true, -1, false, true, LA_POOL_OFF, 0);
        la_fold(&pooled, "r_pool", 2, true, -1, false, true, LA_POOL_WARM, 2);
        PVLA_CHECK("real: serial folds 2", serial.setup_ok &&
                   serial.drained == 2);
        PVLA_CHECK("real: pool warmed + all hits",
                   pooled.warm_ok && pooled.hits == 2 && pooled.misses == 0);
        PVLA_CHECK("real: rows + counters identical",
                   la_results_identical(&serial, &pooled));
        PVLA_CHECK("real: h0 verified, h1 joinsplit_sig both ways",
                   serial.rows[0].ok == 1 &&
                   strcmp(serial.rows[0].status, "verified") == 0 &&
                   serial.rows[1].ok == 0 &&
                   strcmp(serial.rows[1].type, "joinsplit_sig") == 0);
    }

    /* 3) Wrong-hash / wrong-verifier keying: a populated slot never matches a
     * different block hash or verifier pair, and a hit consumes the slot. */
    {
        char dir[256];
        struct main_state ms;
        struct la_chain sc;
        test_make_tmpdir(dir, sizeof(dir), "pv_lookahead", "keying");
        bool setup = progress_store_open(dir);
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        setup = setup && la_chain_build(&sc, 4, false);
        if (setup) {
            active_chain_move_window_tip(&ms.chain_active, &sc.blocks[3]);
            setup = la_seed_script_validate(progress_store_db(), &sc) &&
                    proof_validate_stage_init(&ms);
        }
        if (setup) {
            proof_validate_stage_set_reader(la_reader, &sc);
            proof_validate_stage_set_tx_verifier(la_verifier, &sc);
        }
        PVLA_CHECK("keying: setup", setup);
        PVLA_CHECK("keying: pool warms 4",
                   setup && proof_validate_lookahead_start() &&
                   la_wait_populated(4, 10000));
        struct pv_lookahead_verdict v;
        struct uint256 flipped = sc.hashes[2];
        flipped.data[0] ^= 0xff;
        PVLA_CHECK("keying: flipped hash misses",
                   !pv_lookahead_take(2, &flipped, la_verifier, &sc, &v));
        PVLA_CHECK("keying: wrong verifier pair misses",
                   !pv_lookahead_take(2, &sc.hashes[2], NULL, NULL, &v));
        PVLA_CHECK("keying: exact key hits with ok verdict",
                   pv_lookahead_take(2, &sc.hashes[2], la_verifier, &sc, &v) &&
                   v.ok == 1 && v.sapling_spends_total == 1);
        PVLA_CHECK("keying: consumed slot misses on re-take",
                   !pv_lookahead_take(2, &sc.hashes[2], la_verifier, &sc, &v));
        proof_validate_stage_shutdown();
        la_chain_free(&sc);
        active_chain_free(&ms.chain_active);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* 4) Per-height body gap: begin at h3 with its HAVE_DATA bit absent while
     * h4..h7 are readable.  The pool must retain exact-hash h4/h5 work instead
     * of parking behind h3, and h4..h7 must consume the warmed verdicts;
     * rows/counters remain serial-identical.
     *
     * h3 itself is a RACE by design and the count is asserted as a range.  The
     * worker loop re-sweeps from the lowest gapped height once the claim window
     * is exhausted (pv_lookahead.c), because on the live/replay path a gap means
     * "body has not landed yet", not "body is missing".  So once this fixture
     * makes h3 readable, either the drive reaches it first (inline miss, 4 hits)
     * or a re-sweeping worker verifies it first (5 hits).  Both are correct and
     * indistinguishable in the verdict: the serial-identical check below is the
     * guarantee, and it stays exact.  Only WHO computed h3 varies. */
    {
        struct la_result serial, pooled;
        la_fold_from(&serial, "g_ser", 8, false, -1, false, false,
                     LA_POOL_OFF, 0, /*start_cursor=*/3, /*body_gap=*/-1);
        la_fold_from(&pooled, "g_pool", 8, false, -1, false, false,
                     LA_POOL_HEIGHT_GAP, /*h4..h7=*/4,
                     /*start_cursor=*/3, /*body_gap=*/3);
        PVLA_CHECK("gap: serial folds h3..h7",
                   serial.setup_ok && serial.drained == 5 &&
                   serial.cursor == 8);
        PVLA_CHECK("gap: h4..h7 warm while h3 body is absent",
                   pooled.warm_ok);
        PVLA_CHECK("gap: wrong h4 hash misses without consuming exact slot",
                   pooled.wrong_hash_missed);
        /* Six takes either way: h3..h7 plus the wrong-hash probe above. h4..h7
         * are always hits; h3 is the raced height, so hits is 4 or 5 and the
         * remainder are misses. drained/cursor stay exact. */
        PVLA_CHECK("gap: h4..h7 are hits, h3 raced, six takes total",
                   pooled.hits >= 4 && pooled.hits <= 5 &&
                   pooled.hits + pooled.misses == 6 &&
                   pooled.drained == 5 && pooled.cursor == 8);
        PVLA_CHECK("gap: rows + counters + cursor remain serial-identical",
                   la_results_identical(&serial, &pooled));
        PVLA_CHECK("gap: exact h4/h5 verdicts reached selected rows",
                   pooled.rows[4].present && pooled.rows[4].ok == 1 &&
                   pooled.rows[5].present && pooled.rows[5].ok == 1);
    }

    /* 5) All-miss fallback: pool running but its reader never yields a block —
     * zero hits, the stage folds inline, rows identical to serial. */
    {
        struct la_result serial, dead;
        la_fold(&serial, "m_ser", 8, false, 5, false, false, LA_POOL_OFF, 0);
        la_fold(&dead, "m_dead", 8, false, 5, false, false,
                LA_POOL_DEAD_READER, 0);
        PVLA_CHECK("miss: pool started with dead reader", dead.warm_ok);
        PVLA_CHECK("miss: zero hits, every consume missed",
                   dead.hits == 0 && dead.misses == 8);
        PVLA_CHECK("miss: inline fallback rows identical",
                   la_results_identical(&serial, &dead));
    }

    /* 6) internal_error is NEVER cached: the drive resolves it inline and the
     * TL-2 HOLD semantics are unchanged (no row, cursor held, counter == 1). */
    {
        struct la_result serial, pooled;
        la_fold(&serial, "i_ser", 3, false, 1, true, false, LA_POOL_OFF, 0);
        /* h=1 never populates: expect only h0 + h2 cached. */
        la_fold(&pooled, "i_pool", 3, false, 1, true, false, LA_POOL_WARM, 2);
        PVLA_CHECK("internal: serial holds at the hole",
                   serial.setup_ok && serial.drained == 1 &&
                   serial.cursor == 1 && !serial.rows[1].present &&
                   serial.counters.internal_error == 1);
        PVLA_CHECK("internal: pooled warm_ok (h0+h2 cached, h1 skipped)",
                   pooled.warm_ok);
        PVLA_CHECK("internal: pooled fold identical (hold, no row at h1)",
                   la_results_identical(&serial, &pooled));
        PVLA_CHECK("internal: h0 was a hit, h1 was an inline miss",
                   pooled.hits >= 1 && pooled.misses >= 1);
    }

    printf("pv_lookahead tests: %s\n", failures ? "FAILED" : "PASSED");
    return failures;
}
