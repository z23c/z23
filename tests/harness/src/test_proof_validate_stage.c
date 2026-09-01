/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Unit tests for Wave S S-7 proof_validate stage. */

#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/proof_validate_null_hash_rearm.h"
#include "services/recovery_policy.h"
#include "sapling/params_init.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PV_CHECK(name, expr) do { \
    printf("proof_validate: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

enum pv_fail_kind {
    PV_FAIL_NONE = 0,
    PV_FAIL_SAPLING_SPEND,
    PV_FAIL_SAPLING_OUTPUT,
    PV_FAIL_SPROUT_GROTH16,
    PV_FAIL_SPROUT_PHGR13,
    PV_FAIL_BINDING_SIG,
    PV_FAIL_INTERNAL,
};

struct synth_chain_pv {
    struct block_index *blocks;
    struct uint256     *hashes;
    struct block       *bodies;
    int                 n;
    int                 fail_height;
    enum pv_fail_kind   fail_kind;
};

static int mkdir_p_pv(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static bool make_shielded_tx(struct transaction *tx, int h)
{
    transaction_init(tx);
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->num_shielded_spend = 1;
    tx->v_shielded_spend = zcl_calloc(1, sizeof(struct spend_description),
                                      "pv_spend");
    tx->num_shielded_output = 1;
    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "pv_output");
    tx->num_joinsplit = 2;
    tx->v_joinsplit = zcl_calloc(2, sizeof(struct js_description),
                                 "pv_joinsplit");
    if (!tx->v_shielded_spend || !tx->v_shielded_output || !tx->v_joinsplit)
        return false;

    tx->v_joinsplit[0].use_groth = true;
    tx->v_joinsplit[1].use_groth = false;
    memset(tx->joinsplit_pubkey.data, h, 32);
    memset(tx->binding_sig, 0x42, 64);
    transaction_compute_hash(tx);
    return true;
}

static bool make_body(struct synth_chain_pv *sc, int h)
{
    struct block *b = &sc->bodies[h];
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700001000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 1;
    b->vtx = zcl_calloc(1, sizeof(struct transaction), "pv_tx");
    if (!b->vtx) return false;
    if (!make_shielded_tx(&b->vtx[0], h)) return false;
    struct uint256 txids[1] = { b->vtx[0].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 1);
    return true;
}

static bool synth_chain_pv_build(struct synth_chain_pv *sc, int n)
{
    memset(sc, 0, sizeof(*sc));
    sc->fail_height = -1;
    sc->fail_kind = PV_FAIL_NONE;
    sc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index),
                            "pv_blocks");
    sc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256),
                            "pv_hashes");
    sc->bodies = zcl_calloc((size_t)n, sizeof(struct block),
                            "pv_bodies");
    if (!sc->blocks || !sc->hashes || !sc->bodies)
        return false;
    for (int i = 0; i < n; i++) {
        if (!make_body(sc, i)) return false;
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

static void synth_chain_pv_free(struct synth_chain_pv *sc)
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

static bool fake_reader(struct block *out, const struct block_index *bi,
                        const char *datadir, void *user)
{
    (void)datadir;
    struct synth_chain_pv *sc = user;
    if (!out || !bi || !sc || bi->nHeight < 0 || bi->nHeight >= sc->n)
        return false;
    return test_block_copy(out, &sc->bodies[bi->nHeight], "pv_tx_copy");
}

static const char *fail_kind_name(enum pv_fail_kind k)
{
    switch (k) {
    case PV_FAIL_SAPLING_SPEND:   return "sapling_spend";
    case PV_FAIL_SAPLING_OUTPUT:  return "sapling_output";
    case PV_FAIL_SPROUT_GROTH16:  return "sprout_groth16";
    case PV_FAIL_SPROUT_PHGR13:   return "sprout_phgr13";
    case PV_FAIL_BINDING_SIG:     return "binding_sig";
    case PV_FAIL_INTERNAL:        return "sapling_ctx";
    case PV_FAIL_NONE:
    default:                      return NULL;
    }
}

static bool fake_tx_verifier(const struct transaction *tx, int height,
                             struct proof_validate_tx_report *out,
                             void *user)
{
    struct synth_chain_pv *sc = user;
    memset(out, 0, sizeof(*out));
    out->ok = true;
    out->sapling_spends_total = tx ? tx->num_shielded_spend : 0;
    out->sapling_outputs_total = tx ? tx->num_shielded_output : 0;
    out->sprout_joinsplits_total = tx ? tx->num_joinsplit : 0;
    if (!sc || height != sc->fail_height || sc->fail_kind == PV_FAIL_NONE)
        return true;
    out->ok = false;
    out->internal_error = (sc->fail_kind == PV_FAIL_INTERNAL);
    out->first_failure_proof_type = fail_kind_name(sc->fail_kind);
    return true;
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool ensure_params_loaded_pv(void)
{
    if (sapling_params_loaded())
        return true;
    const char *home = getenv("HOME");
    char params_dir[512];
    snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
             home ? home : ".");
    return sapling_init_params(params_dir);
}

static bool seed_script_validate(sqlite3 *db,
                                 const struct synth_chain_pv *sc,
                                 int upstream_fail_height)
{
    if (!exec_sql(db,
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
        "VALUES (?, ?, ?, 1, 1, ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < sc->n; h++) {
        int ok = (h == upstream_fail_height) ? 0 : 1;
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_text(st, 2, ok ? "verified" : "script_invalid",
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
        "VALUES('script_validate', ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, sc->n);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool set_script_validate_hash(sqlite3 *db, int height,
                                     const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE script_validate_log SET block_hash=? WHERE height=?",
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

static bool log_row_at(sqlite3 *db, int height, int *out_ok,
                       char *out_status, size_t status_size,
                       char *out_type, size_t type_size)
{
    *out_ok = -1;
    if (out_status && status_size) out_status[0] = 0;
    if (out_type && type_size) out_type[0] = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status, first_failure_proof_type "
        "FROM proof_validate_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out_ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt && out_status && status_size)
            snprintf(out_status, status_size, "%s", (const char *)txt);
        const unsigned char *typ = sqlite3_column_text(st, 2);
        if (typ && out_type && type_size)
            snprintf(out_type, type_size, "%s", (const char *)typ);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

/* Read a proof_validate_log row's ok flag + whether its block_hash is NULL.
 * Returns true if a row exists at `height`. */
static bool pv_row_hash_state(sqlite3 *db, int height, int *out_ok,
                              bool *out_hash_null)
{
    if (out_ok) *out_ok = -1;
    if (out_hash_null) *out_hash_null = true;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ok, block_hash IS NULL FROM proof_validate_log "
            "WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (out_ok) *out_ok = sqlite3_column_int(st, 0);
        if (out_hash_null) *out_hash_null = sqlite3_column_int(st, 1) != 0;
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

/* Read a stage's DURABLY persisted cursor straight from the stage_cursor
 * table (the in-memory stage_t accessor does not reflect a direct
 * stage_set_named_cursor rewind until the stage reloads). -1 if absent. */
static int64_t read_stage_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = ?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int64_t cur = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        cur = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return cur;
}

static int pv_setup(const char *tag, int n, int upstream_fail_height,
                    char *dir_out, size_t dir_out_size,
                    struct main_state *ms, struct synth_chain_pv *sc)
{
    test_fmt_tmpdir(dir_out, dir_out_size, "proof_validate", tag);
    mkdir_p_pv("./test-tmp");
    mkdir_p_pv(dir_out);
    if (!progress_store_open(dir_out)) return 1;

    memset(ms, 0, sizeof(*ms));
    active_chain_init(&ms->chain_active);
    if (!synth_chain_pv_build(sc, n)) return 2;
    active_chain_move_window_tip(&ms->chain_active, &sc->blocks[n - 1]);

    if (!seed_script_validate(progress_store_db(), sc, upstream_fail_height))
        return 3;
    if (!proof_validate_stage_init(ms)) return 4;
    proof_validate_stage_set_reader(fake_reader, sc);
    proof_validate_stage_set_tx_verifier(fake_tx_verifier, sc);
    return 0;
}

static void pv_teardown(const char *dir, struct main_state *ms,
                        struct synth_chain_pv *sc)
{
    proof_validate_stage_shutdown();
    active_chain_free(&ms->chain_active);
    synth_chain_pv_free(sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

static void run_invalid_case(int *failures_out, enum pv_fail_kind kind,
                             const char *expected_type,
                             uint64_t (*counter)(void))
{
    int failures = 0;
    char dir[256]; struct main_state ms; struct synth_chain_pv sc;
    PV_CHECK("invalid: setup",
             pv_setup(expected_type, 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
    sc.fail_height = 1;
    sc.fail_kind = kind;
    PV_CHECK("invalid: drains 3", proof_validate_stage_drain(100) == 3);
    PV_CHECK("invalid: proof_invalid_total == 1",
             proof_validate_stage_proof_invalid_total() == 1);
    PV_CHECK("invalid: type counter == 1", counter() == 1);
    int ok = -1; char status[32]; char type[32];
    log_row_at(progress_store_db(), 1, &ok, status, sizeof(status),
               type, sizeof(type));
    PV_CHECK("invalid: h=1 ok=0", ok == 0);
    PV_CHECK("invalid: h=1 status", strcmp(status, "proof_invalid") == 0);
    PV_CHECK("invalid: failure type", strcmp(type, expected_type) == 0);
    pv_teardown(dir, &ms, &sc);
    *failures_out += failures;
}

int test_proof_validate_stage(void);
int test_proof_validate_stage(void)
{
    printf("\n=== proof_validate_stage tests ===\n");
    int failures = 0;

    blocker_module_init();

    {
        char dir[256]; struct main_state ms; struct synth_chain_pv sc;
        PV_CHECK("params_missing: setup",
                 pv_setup("params_missing", 1, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        sapling_free_params();
        proof_validate_stage_set_tx_verifier(NULL, NULL);
        /* CS-PROOF-TRANSIENT: during the NORMAL background param-load window the
         * LOADER has not named the permanent blocker, so proof_validate must HOLD
         * (JOB_IDLE) and re-derive next tick — it must NOT name a permanent
         * blocker of its own (that would wedge a transient load window). */
        blocker_clear("params_missing");
        PV_CHECK("params_missing: transient load window holds (JOB_IDLE)",
                 proof_validate_stage_step_once() == JOB_IDLE);
        PV_CHECK("params_missing: cursor stays 0 (idle)",
                 proof_validate_stage_cursor() == 0);
        int ok = -1; char status[32]; char type[32];
        PV_CHECK("params_missing: no poisoned row (idle)",
                 !log_row_at(progress_store_db(), 0, &ok, status,
                             sizeof(status), type, sizeof(type)));
        /* The LOADER is the authority: once it declares the PERMANENT
         * params_missing blocker (a genuine corrupt/parse failure),
         * proof_validate RE-SURFACES it as JOB_BLOCKED — still no poisoned row. */
        struct blocker_record rec;
        PV_CHECK("params_missing: loader names blocker",
                 blocker_init(&rec, "params_missing", "crypto.params",
                              BLOCKER_PERMANENT, "test: params corrupt") &&
                 blocker_set(&rec) == 0);
        PV_CHECK("params_missing: shielded block blocks (named blocker)",
                 proof_validate_stage_step_once() == JOB_BLOCKED);
        PV_CHECK("params_missing: cursor stays 0 (blocked)",
                 proof_validate_stage_cursor() == 0);
        PV_CHECK("params_missing: still no poisoned row",
                 !log_row_at(progress_store_db(), 0, &ok, status,
                             sizeof(status), type, sizeof(type)));
        blocker_clear("params_missing");
        pv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_pv sc;
        blocker_clear(PROOF_VALIDATE_STALE_UPSTREAM_HASH_BLOCKER_ID);
        PV_CHECK("stale_hash: setup",
                 pv_setup("stale_hash", 2, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        PV_CHECK("stale_hash: malformed verdict fails closed and named",
                 exec_sql(progress_store_db(),
                     "UPDATE script_validate_log SET ok=2 WHERE height=0") &&
                     proof_validate_stage_step_once() == JOB_BLOCKED &&
                     proof_validate_stage_cursor() == 0 &&
                     blocker_exists(
                         PROOF_VALIDATE_INVALID_UPSTREAM_BLOCKER_ID));
        PV_CHECK("stale_hash: restore canonical verdict",
                 exec_sql(progress_store_db(),
                     "UPDATE script_validate_log SET ok=1 WHERE height=0"));
        PV_CHECK("stale_hash: text-typed hash fails closed",
                 exec_sql(progress_store_db(),
                     "UPDATE script_validate_log SET block_hash="
                     "'12345678901234567890123456789012' WHERE height=0") &&
                     proof_validate_stage_step_once() == JOB_IDLE &&
                     proof_validate_stage_cursor() == 0 &&
                     blocker_exists(
                         PROOF_VALIDATE_STALE_UPSTREAM_HASH_BLOCKER_ID));
        PV_CHECK("stale_hash: hashless receipt fails closed",
                 set_script_validate_hash(progress_store_db(), 0, NULL) &&
                     proof_validate_stage_step_once() == JOB_IDLE &&
                     proof_validate_stage_cursor() == 0 &&
                     blocker_exists(
                         PROOF_VALIDATE_STALE_UPSTREAM_HASH_BLOCKER_ID));
        struct uint256 foreign = sc.hashes[0];
        foreign.data[0] ^= 0xff;
        PV_CHECK("stale_hash: seed foreign script receipt",
                 set_script_validate_hash(progress_store_db(), 0, &foreign));
        PV_CHECK("stale_hash: proof stage parks without reading branch",
                 proof_validate_stage_step_once() == JOB_IDLE &&
                     proof_validate_stage_cursor() == 0);
        PV_CHECK("stale_hash: dependency is named",
                 blocker_exists(
                     PROOF_VALIDATE_STALE_UPSTREAM_HASH_BLOCKER_ID) &&
                 blocker_class_for(
                     PROOF_VALIDATE_STALE_UPSTREAM_HASH_BLOCKER_ID) ==
                     BLOCKER_DEPENDENCY);
        PV_CHECK("stale_hash: bind script receipt to selected branch",
                 set_script_validate_hash(progress_store_db(), 0,
                                          &sc.hashes[0]));
        PV_CHECK("stale_hash: rebound receipt advances",
                 proof_validate_stage_step_once() == JOB_ADVANCED &&
                     proof_validate_stage_cursor() == 1);
        PV_CHECK("stale_hash: dependency clears on rebind",
                 !blocker_exists(
                     PROOF_VALIDATE_STALE_UPSTREAM_HASH_BLOCKER_ID));
        pv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_pv sc;
        PV_CHECK("happy: setup",
                 pv_setup("happy", 2, -1, dir, sizeof(dir), &ms, &sc) == 0);
        PV_CHECK("happy: drains 2", proof_validate_stage_drain(100) == 2);
        PV_CHECK("happy: cursor at 2", proof_validate_stage_cursor() == 2);
        PV_CHECK("happy: verified_total == 2",
                 proof_validate_stage_verified_total() == 2);
        PV_CHECK("happy: sapling spends verified == 2",
                 proof_validate_stage_sapling_spends_verified_total() == 2);
        PV_CHECK("happy: sapling outputs verified == 2",
                 proof_validate_stage_sapling_outputs_verified_total() == 2);
        PV_CHECK("happy: sprout groth16 verified == 2",
                 proof_validate_stage_sprout_groth16_verified_total() == 2);
        PV_CHECK("happy: sprout phgr13 verified == 2",
                 proof_validate_stage_sprout_phgr13_verified_total() == 2);
        PV_CHECK("happy: binding sig verified == 2",
                 proof_validate_stage_binding_sig_verified_total() == 2);
        for (int h = 0; h < 2; h++) {
            int ok = -1; char status[32]; char type[32];
            log_row_at(progress_store_db(), h, &ok, status, sizeof(status),
                       type, sizeof(type));
            PV_CHECK("happy: row ok=1", ok == 1);
            PV_CHECK("happy: row status verified",
                     strcmp(status, "verified") == 0);
            PV_CHECK("happy: failure type null", type[0] == 0);
        }
        PV_CHECK("happy: next step IDLE",
                 proof_validate_stage_step_once() == JOB_IDLE);
        pv_teardown(dir, &ms, &sc);
    }

    run_invalid_case(&failures, PV_FAIL_SAPLING_SPEND, "sapling_spend",
                     proof_validate_stage_sapling_spends_failed_total);
    run_invalid_case(&failures, PV_FAIL_SAPLING_OUTPUT, "sapling_output",
                     proof_validate_stage_sapling_outputs_failed_total);
    run_invalid_case(&failures, PV_FAIL_SPROUT_GROTH16, "sprout_groth16",
                     proof_validate_stage_sprout_groth16_failed_total);
    run_invalid_case(&failures, PV_FAIL_SPROUT_PHGR13, "sprout_phgr13",
                     proof_validate_stage_sprout_phgr13_failed_total);
    run_invalid_case(&failures, PV_FAIL_BINDING_SIG, "binding_sig",
                     proof_validate_stage_binding_sig_failed_total);

    {
        char dir[256]; struct main_state ms; struct synth_chain_pv sc;
        PV_CHECK("joinsplit_sig: setup",
                 pv_setup("joinsplit_sig", 1, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        proof_validate_stage_set_tx_verifier(NULL, NULL);
        if (!ensure_params_loaded_pv()) {
            /* Honest, LOUD self-skip (counted by test_parallel's "SKIP ("
             * sentinel scan) — this leg needs the real Sapling prover/
             * verifier to drive a genuine joinsplit-signature-invalid
             * verdict; the ~770MB param files are not in the repo and are
             * not fetched by hosted CI. Every other case in this file
             * (including the params_missing case just above) exercises the
             * REAL absent-params path through the injected fake_tx_verifier
             * and needs no params at all — only this one leg requires them. */
            printf("  SKIP (joinsplit_sig) — ~/.zcash-params absent; this "
                   "leg needs the real Sapling prover to drive a genuine "
                   "joinsplit-signature-invalid verdict through the real "
                   "verifier, not the fake_tx_verifier test hook. Setup "
                   "above still ran.\n");
            pv_teardown(dir, &ms, &sc);
        } else {
            PV_CHECK("joinsplit_sig: drains 1",
                     proof_validate_stage_drain(100) == 1);
            PV_CHECK("joinsplit_sig: proof_invalid_total == 1",
                     proof_validate_stage_proof_invalid_total() == 1);
            int ok = -1; char status[32]; char type[32];
            log_row_at(progress_store_db(), 0, &ok, status, sizeof(status),
                       type, sizeof(type));
            PV_CHECK("joinsplit_sig: h=0 ok=0", ok == 0);
            PV_CHECK("joinsplit_sig: h=0 status",
                     strcmp(status, "proof_invalid") == 0);
            PV_CHECK("joinsplit_sig: failure type",
                     strcmp(type, "joinsplit_sig") == 0);
            pv_teardown(dir, &ms, &sc);
        }
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_pv sc;
        PV_CHECK("upstream_failed: setup",
                 pv_setup("upstream", 3, 2, dir, sizeof(dir), &ms, &sc) == 0);
        PV_CHECK("upstream_failed: drains 3",
                 proof_validate_stage_drain(100) == 3);
        PV_CHECK("upstream_failed: counter == 1",
                 proof_validate_stage_upstream_failed_total() == 1);
        int ok = -1; char status[32]; char type[32];
        log_row_at(progress_store_db(), 2, &ok, status, sizeof(status),
                   type, sizeof(type));
        PV_CHECK("upstream_failed: h=2 ok=0", ok == 0);
        PV_CHECK("upstream_failed: h=2 status",
                 strcmp(status, "upstream_failed") == 0);
        pv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_pv sc;
        PV_CHECK("internal_error: setup",
                 pv_setup("internal", 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sc.fail_height = 1;
        sc.fail_kind = PV_FAIL_INTERNAL;
        /* TL-2: a transient internal_error (e.g. a sapling_ctx allocation failure
         * under memory pressure) is NOT a permanent reject. The stage HOLDS the
         * cursor at the hole — no terminal ok=0 row, no advance — and re-derives
         * next tick. So the drain stops at the hole (only h=0 advances) and NO row
         * is written at h=1. */
        PV_CHECK("internal_error: drains only up to the hole",
                 proof_validate_stage_drain(100) == 1);
        PV_CHECK("internal_error: cursor held at the hole (1)",
                 proof_validate_stage_cursor() == 1);
        PV_CHECK("internal_error: counter == 1 (one held height)",
                 proof_validate_stage_internal_error_total() == 1);
        int ok = -1; char status[32]; char type[32];
        bool row = log_row_at(progress_store_db(), 1, &ok, status,
                              sizeof(status), type, sizeof(type));
        PV_CHECK("internal_error: no terminal row written at the hole",
                 !row && ok == -1);
        /* Re-tick within budget: still HOLDS (JOB_IDLE), never advances, never
         * writes a row, counter stays 1 (paged once per held height). */
        PV_CHECK("internal_error: re-tick still holds (JOB_IDLE)",
                 proof_validate_stage_step_once() == JOB_IDLE);
        PV_CHECK("internal_error: counter still 1 (same held height)",
                 proof_validate_stage_internal_error_total() == 1);
        pv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_pv sc;
        PV_CHECK("idle: setup",
                 pv_setup("idle", 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sqlite3_exec(progress_store_db(),
            "UPDATE stage_cursor SET cursor=1 WHERE name='script_validate'",
            NULL, NULL, NULL);
        PV_CHECK("idle: advances one", proof_validate_stage_drain(100) == 1);
        PV_CHECK("idle: next step IDLE",
                 proof_validate_stage_step_once() == JOB_IDLE);
        PV_CHECK("idle: cursor stays 1",
                 proof_validate_stage_cursor() == 1);
        pv_teardown(dir, &ms, &sc);
    }

    {
        PV_CHECK("guard: step_once with no init returns IDLE",
                 proof_validate_stage_step_once() == JOB_IDLE);
        PV_CHECK("guard: init(NULL) rejected",
                 !proof_validate_stage_init(NULL));
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_pv sc;
        PV_CHECK("dump: setup",
                 pv_setup("dump", 2, -1, dir, sizeof(dir), &ms, &sc) == 0);
        proof_validate_stage_drain(100);
        struct json_value v;
        json_init(&v);
        PV_CHECK("dump: returns true",
                 proof_validate_dump_state_json(&v, NULL));
        char buf[1024];
        size_t n = json_write(&v, buf, sizeof(buf));
        PV_CHECK("dump: serializes", n > 0 && n < sizeof(buf));
        PV_CHECK("dump: stage_name",
                 strstr(buf, "\"stage_name\":\"proof_validate\"") != NULL);
        PV_CHECK("dump: cursor=2", strstr(buf, "\"cursor\":2") != NULL);
        PV_CHECK("dump: verified_total=2",
                 strstr(buf, "\"verified_total\":2") != NULL);
        json_free(&v);
        pv_teardown(dir, &ms, &sc);
    }

    /* null_hash_rearm: the pre-stamping NULL-block_hash artifact + its
     * CONTAINED, recovery-gated re-derive-in-place re-arm. Models the live
     * wedge — proof_validate_log rows written before block_hash stamping
     * (commit 7fb9f5650) are ok=1/NULL-block_hash; utxo_apply's guard refuses
     * them, and proof_validate's cursor has already passed them. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_pv sc;
        sqlite3 *db = NULL;
        PV_CHECK("rearm: setup",
                 pv_setup("rearm", 5, -1, dir, sizeof(dir), &ms, &sc) == 0);
        db = progress_store_db();

        /* Fold all five heights with the CURRENT writer — every row gets a
         * stamped block_hash and the pv cursor lands at 5. */
        PV_CHECK("rearm: initial drain 5",
                 proof_validate_stage_drain(100) == 5);
        PV_CHECK("rearm: pv cursor at 5",
                 proof_validate_stage_cursor() == 5);

        /* Both downstream proof-receipt consumers are wedged at height 2:
         * utxo_apply (label_splice guard) and tip_finalize (validation_evidence).
         * The re-arm floors at min(utxo_apply, tip_finalize); seed BOTH cursors
         * so the LCC floor reflects the deepest consumer. Heights below 2 are
         * already applied by both and must NOT be rewound (LCC floor). */
        PV_CHECK("rearm: seed utxo_apply cursor = 2",
                 exec_sql(db,
                     "INSERT OR REPLACE INTO stage_cursor(name, cursor, "
                     "updated_at) VALUES('utxo_apply', 2, 1)"));
        PV_CHECK("rearm: seed tip_finalize cursor = 2",
                 exec_sql(db,
                     "INSERT OR REPLACE INTO stage_cursor(name, cursor, "
                     "updated_at) VALUES('tip_finalize', 2, 1)"));

        /* Recreate the pre-stamping artifact: null the block_hash of the
         * ok=1 rows at/above the utxo_apply cursor (heights 2,3,4). */
        PV_CHECK("rearm: null block_hash of suffix >= 2",
                 exec_sql(db,
                     "UPDATE proof_validate_log SET block_hash=NULL "
                     "WHERE height >= 2"));
        {
            int okv; bool hn;
            PV_CHECK("rearm: h=1 still hashed (below floor)",
                     pv_row_hash_state(db, 1, &okv, &hn) && okv == 1 && !hn);
            PV_CHECK("rearm: h=2 now NULL-hash",
                     pv_row_hash_state(db, 2, &okv, &hn) && okv == 1 && hn);
        }

        /* Containment: a refusing policy (dry_run) must NOT mutate. */
        {
            struct recovery_policy refuse;
            policy_set_defaults(&refuse);
            refuse.dry_run = true;
            struct proof_validate_rearm_report rep;
            enum proof_validate_rearm_outcome oc =
                proof_validate_null_hash_rearm(db, &refuse, &rep);
            PV_CHECK("rearm: refusing policy -> REFUSED",
                     oc == PV_REARM_REFUSED);
            PV_CHECK("rearm: refused detected lowest_null=2",
                     rep.lowest_null_height == 2 && rep.null_row_count == 3);
            PV_CHECK("rearm: refused did NOT rewind (cursor still 5)",
                     read_stage_cursor(db, "proof_validate") == 5);
            int okv; bool hn;
            PV_CHECK("rearm: refused left suffix NULL",
                     pv_row_hash_state(db, 2, &okv, &hn) && hn);
        }

        /* Allow: default caps permit a 3-height rewind. */
        {
            struct recovery_policy allow;
            policy_set_defaults(&allow);
            struct proof_validate_rearm_report rep;
            enum proof_validate_rearm_outcome oc =
                proof_validate_null_hash_rearm(db, &allow, &rep);
            PV_CHECK("rearm: allow policy -> REARMED",
                     oc == PV_REARM_REARMED);
            PV_CHECK("rearm: rewound_to == 2 && floor == 2",
                     rep.rewound_to == 2 && rep.ua_cursor_floor == 2);
            PV_CHECK("rearm: deleted 3 NULL rows",
                     rep.deleted_rows == 3);
            PV_CHECK("rearm: pv cursor rewound to 2",
                     read_stage_cursor(db, "proof_validate") == 2);
            /* Below-floor valid rows are untouched. */
            int okv; bool hn;
            PV_CHECK("rearm: h=1 untouched (still hashed)",
                     pv_row_hash_state(db, 1, &okv, &hn) && okv == 1 && !hn);
            PV_CHECK("rearm: NULL suffix rows deleted (h=2 gone)",
                     !pv_row_hash_state(db, 2, &okv, &hn));
        }

        /* Re-fold: the CURRENT binary re-derives + re-stamps block_hash so the
         * suffix is hash-complete and utxo_apply can advance. */
        PV_CHECK("rearm: re-drain re-stamps suffix",
                 proof_validate_stage_drain(100) == 3);
        PV_CHECK("rearm: pv cursor back at 5",
                 proof_validate_stage_cursor() == 5);
        {
            int okv; bool hn;
            for (int h = 2; h < 5; h++) {
                PV_CHECK("rearm: re-stamped row hashed",
                         pv_row_hash_state(db, h, &okv, &hn) &&
                             okv == 1 && !hn);
            }
        }

        /* Idempotent: a clean log now re-arms to NOT_NEEDED without mutating. */
        {
            struct recovery_policy allow;
            policy_set_defaults(&allow);
            struct proof_validate_rearm_report rep;
            enum proof_validate_rearm_outcome oc =
                proof_validate_null_hash_rearm(db, &allow, &rep);
            PV_CHECK("rearm: clean log -> NOT_NEEDED", oc == PV_REARM_NOT_NEEDED);
            PV_CHECK("rearm: NOT_NEEDED left cursor at 5",
                     read_stage_cursor(db, "proof_validate") == 5);
        }

        pv_teardown(dir, &ms, &sc);
    }

    printf("proof_validate_stage tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
