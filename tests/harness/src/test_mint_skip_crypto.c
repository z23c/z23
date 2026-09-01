/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_mint_skip_crypto — proves the OFFLINE FAST-MINT state-only fold yields
 * the IDENTICAL coins_kv set (same SHA3 commitment + count) as the
 * full-validated fold, on a small synthetic chain.
 *
 * It runs the SAME three-stage tail of the staged pipeline — script_validate ->
 * proof_validate -> utxo_apply — TWICE on one synthetic chain, in two isolated
 * datadirs:
 *
 *   Run A (full validation): mint_skip_crypto OFF (the default). script_validate
 *     runs the REAL per-input verify_script (the OP_TRUE prevouts pass);
 *     proof_validate runs the REAL proof verifier (the blocks carry no shielded
 *     proofs, so it verifies vacuously). utxo_apply folds the bodies.
 *   Run B (state-only): mint_skip_crypto ON. Both crypto stages skip their
 *     verifier and write checkpoint_fold, never verified. utxo_apply folds the
 *     SAME bodies — UNCHANGED.
 *
 * EXPECT: coins_kv_commitment(A) == coins_kv_commitment(B) AND count(A) ==
 * count(B). This is the load-bearing fact: state-only == validated for the UTXO
 * set, so the mint's SHA3==checkpoint hard-assert is satisfied by the exact same
 * set either way.
 *
 * EQUIVALENCE FLOOR (the toggle is the only difference): Run A actually ran
 * crypto (inputs_verified_total > 0); Run B skipped it (inputs_verified_total
 * == 0). This proves the OFF path runs real verify_script and the ON path does
 * not — so a normal boot (toggle unset) runs full crypto. */

#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "jobs/mint_skip_crypto.h"
#include "jobs/refold_progress.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "chain/checkpoints.h"
#include "config/boot.h"
#include "config/mint_anchor_progress.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

#if defined(_WIN32)
#include "platform/time_compat.h"
#endif

/* Source-private reducer-log helpers under direct authority-type test. */
bool script_validate_log_ensure_schema(sqlite3 *db);
bool script_validate_log_insert(sqlite3 *db, int height,
                                const char *status, bool ok,
                                size_t tx_count, size_t input_count,
                                const struct uint256 *first_failure_txid,
                                int first_failure_vin,
                                ScriptError first_failure_serror,
                                const struct uint256 *block_hash);
bool proof_validate_log_ensure_schema(sqlite3 *db);
bool proof_validate_log_insert(sqlite3 *db, int height,
                               const char *status, bool ok,
                               size_t sapling_spends_total,
                               size_t sapling_outputs_total,
                               size_t sprout_joinsplits_total,
                               const struct uint256 *block_hash,
                               const struct uint256 *first_failure_txid,
                               const char *first_failure_proof_type);
bool boot_mint_anchor_genesis_reset(struct node_db *ndb);

#define MSC_CHECK(name, expr) do { \
    printf("mint_skip_crypto: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* One synthetic chain shared by both runs, modeled on test_utxo_apply_stage so
 * the utxo_apply STATE fold ACCEPTS every block (no coinbase-protect, no
 * subsidy-ceiling reject) — otherwise both runs would reject identically and
 * the equivalence would be vacuous. Each block has:
 *   vtx[0] coinbase paying a tiny OP_TRUE output (50+h, well under subsidy);
 *   vtx[1] spends an EXTERNAL OP_TRUE prevout (ext[h], value 1000+h) with an
 *          empty scriptSig (valid against OP_TRUE) into a 900+h OP_TRUE output.
 * The external prevout is resolved by BOTH the script_validate prevout resolver
 * (so verify_script passes in the full run) AND the utxo_apply lookup (so the
 * state fold resolves the spent value), exactly as test_utxo_apply_stage does. */
struct external_utxo {
    struct uint256 txid;
    uint32_t       vout;
    int64_t        value;
};
struct synth_chain {
    struct block_index   *blocks;
    struct uint256       *hashes;
    struct block         *bodies;
    struct external_utxo *ext;       /* the external prevout spent at each h */
    int                   n;
};

static void synthetic_ext_txid(struct uint256 *out, int h)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0x80 + h);
    out->data[1] = 0x09;
}

static int mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static bool make_body(struct synth_chain *sc, int h)
{
    struct block *b = &sc->bodies[h];
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700000000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 2;
    b->vtx = zcl_calloc(2, sizeof(struct transaction), "msc_tx");
    if (!b->vtx) return false;

    /* The external prevout this block's spend consumes (OP_TRUE, 1000+h). */
    synthetic_ext_txid(&sc->ext[h].txid, h);
    sc->ext[h].vout  = 0;
    sc->ext[h].value = 1000 + h;

    /* vtx[0]: coinbase, one OP_TRUE output worth 50+h (well under subsidy). */
    transaction_init(&b->vtx[0]);
    if (!transaction_alloc(&b->vtx[0], 1, 1)) return false;
    outpoint_set_null(&b->vtx[0].vin[0].prevout);
    script_push_data(&b->vtx[0].vin[0].script_sig, (const unsigned char *)&h,
                     sizeof(h));
    b->vtx[0].vout[0].value = 50 + h;
    script_init(&b->vtx[0].vout[0].script_pub_key);
    script_push_op(&b->vtx[0].vout[0].script_pub_key, OP_TRUE);
    transaction_compute_hash(&b->vtx[0]);

    /* vtx[1]: spend the EXTERNAL OP_TRUE prevout with empty scriptSig (passes
     * OP_TRUE) into a 900+h OP_TRUE output (input 1000+h leaves a fee). */
    transaction_init(&b->vtx[1]);
    if (!transaction_alloc(&b->vtx[1], 1, 1)) return false;
    b->vtx[1].vin[0].prevout.hash = sc->ext[h].txid;
    b->vtx[1].vin[0].prevout.n = sc->ext[h].vout;
    script_init(&b->vtx[1].vin[0].script_sig);
    b->vtx[1].vout[0].value = 900 + h;
    script_init(&b->vtx[1].vout[0].script_pub_key);
    script_push_op(&b->vtx[1].vout[0].script_pub_key, OP_TRUE);
    transaction_compute_hash(&b->vtx[1]);

    struct uint256 txids[2] = { b->vtx[0].hash, b->vtx[1].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    return true;
}

static bool synth_chain_build(struct synth_chain *sc, int n)
{
    memset(sc, 0, sizeof(*sc));
    sc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index), "msc_bi");
    sc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "msc_h");
    sc->bodies = zcl_calloc((size_t)n, sizeof(struct block), "msc_b");
    sc->ext    = zcl_calloc((size_t)n, sizeof(struct external_utxo), "msc_ext");
    if (!sc->blocks || !sc->hashes || !sc->bodies || !sc->ext)
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

static void synth_chain_free(struct synth_chain *sc)
{
    if (sc->bodies)
        for (int i = 0; i < sc->n; i++)
            block_free(&sc->bodies[i]);
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
    struct synth_chain *sc = user;
    if (!out || !bi || !sc || bi->nHeight < 0 || bi->nHeight >= sc->n)
        return false;
    return test_block_copy(out, &sc->bodies[bi->nHeight], "msc_copy");
}

/* script_validate prevout resolver: the spend's prevout is the EXTERNAL
 * OP_TRUE coin ext[h] (so verify_script passes against an empty scriptSig). */
static bool fake_prevout(const struct outpoint *prevout, struct tx_out *out,
                         void *user)
{
    struct synth_chain *sc = user;
    if (!prevout || !out || !sc) return false;
    for (int h = 0; h < sc->n; h++) {
        if (uint256_eq(&prevout->hash, &sc->ext[h].txid) &&
            prevout->n == sc->ext[h].vout) {
            tx_out_set_null(out);
            out->value = sc->ext[h].value;
            script_init(&out->script_pub_key);
            script_push_op(&out->script_pub_key, OP_TRUE);
            return true;
        }
    }
    return false;
}

/* utxo_apply lookup: resolve the EXTERNAL spent prevout's value/script so the
 * state fold accepts the spend (the coin's pre-image for the inverse delta). */
static bool fake_lookup(const struct uint256 *txid, uint32_t vout,
                        struct utxo_apply_lookup *out, void *user)
{
    struct synth_chain *sc = user;
    memset(out, 0, sizeof(*out));
    if (!sc) return true;
    for (int h = 0; h < sc->n; h++) {
        if (uint256_eq(&sc->ext[h].txid, txid) && sc->ext[h].vout == vout) {
            out->found = true;
            out->value = sc->ext[h].value;
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

static bool msc_identity_same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mode == b->st_mode &&
#if defined(_WIN32)
        /* UCRT struct stat carries second-resolution timestamps only; the
         * identity assertion (same unmodified file) is unaffected. */
        a->st_mtime == b->st_mtime &&
        a->st_ctime == b->st_ctime;
#else
        a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

#if defined(_WIN32)

/* Child body for the Windows arm of msc_make_killed_wal: re-executed suite
 * process, dispatched via ZCL_TEST_FORK_ROLE (see test_core.h). Reads the
 * target dir and lane from env, commits the row, drops a ready-token FILE
 * (Windows has no pipe(2) across re-exec), then sleeps forever until the
 * parent TerminateProcess()es it — the kill -9 analogue. */
static int msc_wal_writer_child(void)
{
    const char *dir = getenv("ZCL_MSC_WAL_DIR");
    const char *prod = getenv("ZCL_MSC_PRODUCER");
    if (!dir || !dir[0] || !prod) return 2;
    bool producer = strcmp(prod, "1") == 0;

    char path[512];
    int n = snprintf(path, sizeof(path), "%s/consensus.db", dir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return 2;

    sqlite3 *db = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL) ==
            SQLITE_OK &&
        sqlite3_exec(db, "PRAGMA synchronous=FULL", NULL, NULL, NULL) ==
            SQLITE_OK &&
        sqlite3_exec(db, "PRAGMA wal_autocheckpoint=0", NULL, NULL, NULL) ==
            SQLITE_OK &&
        sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS progress_meta("
            "key TEXT PRIMARY KEY,value BLOB NOT NULL)",
            NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)",
                     NULL, NULL, NULL) == SQLITE_OK;
    const char *insert = producer
        ? "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('"
          MINT_ANCHOR_PRODUCER_LANE_KEY "',X'02')"
        : "INSERT OR REPLACE INTO progress_meta(key,value) "
          "VALUES('ordinary_serving_marker',X'01')";
    if (ok)
        ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) ==
                SQLITE_OK &&
             sqlite3_exec(db, insert, NULL, NULL, NULL) == SQLITE_OK &&
             sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;

    char ready_path[560];
    if (snprintf(ready_path, sizeof(ready_path), "%s/wal_ready.token", dir) <= 0)
        ok = false;
    if (ok) {
        FILE *fp = fopen(ready_path, "wb");
        if (fp) {
            fputc('R', fp);
            fclose(fp);
        } else {
            ok = false;
        }
    }
    if (!ok) return 2;
    for (;;)
        platform_sleep_ms(1000);
    return 0; /* unreachable */
}

/* Returns 0 when the role was handled (group entry short-circuits), -1 when
 * the role names nothing here (harness error surfaces as a failure). */
int msc_fork_role_dispatch(const char *role)
{
    if (strcmp(role, "wal_writer") == 0)
        return msc_wal_writer_child() == 0 ? 0 : 1;
    fprintf(stderr, "mint_skip_crypto: unknown ZCL_TEST_FORK_ROLE '%s'\n",
            role);
    return 1;
}

#endif /* _WIN32 */

/* Leave a committed row only in a kill-9-surviving WAL.  The child keeps the
 * SQLite connection open until the parent kills it, so no graceful close can
 * checkpoint the row into the kernel store.  A4: the kernel store the preflight
 * inspects is consensus.db after the flip. */
static bool msc_make_killed_wal(const char *dir, bool producer)
{
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/consensus.db", dir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;

#if defined(_WIN32)
    (void)path; /* the child recomputes it from ZCL_MSC_WAL_DIR */
    char ready_path[560];
    char log_path[576];
    if (snprintf(ready_path, sizeof(ready_path), "%s/wal_ready.token", dir)
                <= 0 ||
        snprintf(log_path, sizeof(log_path), "%s/wal_child.log", dir) <= 0)
        return false;
    (void)unlink(ready_path);
    if (_putenv_s("ZCL_MSC_WAL_DIR", dir) != 0 ||
        _putenv_s("ZCL_MSC_PRODUCER", producer ? "1" : "0") != 0)
        return false;
    void *child = test_spawn_self_with_role("test_mint_skip_crypto",
                                            "wal_writer", log_path);
    if (!child)
        return false;
    bool ready = false;
    for (int i = 0; i < 1200 && !ready; i++) {
        struct stat st;
        ready = stat(ready_path, &st) == 0;
        if (!ready) platform_sleep_ms(50);
    }
    if (ready)
        test_self_child_kill(child);
    int code = test_self_child_wait(child);
    (void)unlink(ready_path);
    return ready && code == 137;
#else
    int ready[2];
    if (pipe(ready) != 0)
        return false;
    pid_t child = fork();
    if (child < 0) {
        close(ready[0]);
        close(ready[1]);
        return false;
    }
    if (child == 0) {
        close(ready[0]);
        sqlite3 *db = NULL;
        bool ok = sqlite3_open(path, &db) == SQLITE_OK &&
            sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL) ==
                SQLITE_OK &&
            sqlite3_exec(db, "PRAGMA synchronous=FULL", NULL, NULL, NULL) ==
                SQLITE_OK &&
            sqlite3_exec(db, "PRAGMA wal_autocheckpoint=0", NULL, NULL, NULL) ==
                SQLITE_OK &&
            sqlite3_exec(db,
                "CREATE TABLE IF NOT EXISTS progress_meta("
                "key TEXT PRIMARY KEY,value BLOB NOT NULL)",
                NULL, NULL, NULL) == SQLITE_OK &&
            sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)",
                         NULL, NULL, NULL) == SQLITE_OK;
        const char *insert = producer
            ? "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('"
              MINT_ANCHOR_PRODUCER_LANE_KEY "',X'02')"
            : "INSERT OR REPLACE INTO progress_meta(key,value) "
              "VALUES('ordinary_serving_marker',X'01')";
        if (ok)
            ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) ==
                    SQLITE_OK &&
                 sqlite3_exec(db, insert, NULL, NULL, NULL) == SQLITE_OK &&
                 sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
        const char token = ok ? 'R' : 'E';
        (void)write(ready[1], &token, 1);
        if (!ok)
            _exit(2);
        for (;;)
            pause();
    }

    close(ready[1]);
    char token = 0;
    ssize_t got;
    do {
        got = read(ready[0], &token, 1);
    } while (got < 0 && errno == EINTR);
    close(ready[0]);
    if (got == 1 && token == 'R')
        (void)kill(child, SIGKILL);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return got == 1 && token == 'R' && waited == child &&
        WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
#endif
}

/* Seed body_persist_log + its cursor so script_validate sees an ok=1 upstream
 * for every height (the stages it feeds are the ones under test). */
static bool seed_body_persist(sqlite3 *db, int n)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT NOT NULL, "
        "  ok INTEGER NOT NULL, persisted_at INTEGER NOT NULL)"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO body_persist_log "
        "(height, source, ok, persisted_at) VALUES (?, 'verified', 1, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < n; h++) {
        sqlite3_bind_int(st, 1, h);
        if (sqlite3_step(st) != SQLITE_DONE) { sqlite3_finalize(st); return false; }
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES('body_persist', ?, 1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, n);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Run the script_validate -> proof_validate -> utxo_apply tail over `n` heights
 * in a fresh datadir. `skip` selects full-validation (false) vs state-only
 * (true). On success writes the resulting commitment + count + whether real
 * script crypto ran into the out params. Returns the count of script_validate
 * heights drained (== n on a clean fold). */
static bool stage_rows_match(sqlite3 *db, const char *table, int rows,
                             const char *status, const uint8_t epoch[32])
{
    bool script = strcmp(table, "script_validate_log") == 0;
    bool proof = strcmp(table, "proof_validate_log") == 0;
    bool utxo = strcmp(table, "utxo_apply_log") == 0;
    if (!script && !proof && !utxo)
        return false;
    bool epoch_bound = !utxo;
    char sql[160];
    int size = snprintf(sql, sizeof(sql),
        "SELECT height,status%s FROM %s ORDER BY height",
        epoch_bound ? ",source_epoch_digest" : "", table);
    if (size <= 0 || (size_t)size >= sizeof(sql))
        return false;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return false;
    int expected = 0;
    int rc;
    size_t status_size = strlen(status);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int status_type = sqlite3_column_type(stmt, 1);
        int epoch_type = epoch_bound ? sqlite3_column_type(stmt, 2)
                                     : SQLITE_BLOB;
        const void *text = status_type == SQLITE_TEXT
            ? sqlite3_column_text(stmt, 1) : NULL;
        const void *row_epoch = epoch_bound
            ? (epoch_type == SQLITE_BLOB ? sqlite3_column_blob(stmt, 2) : NULL)
            : epoch;
        if (sqlite3_column_type(stmt, 0) != SQLITE_INTEGER ||
            sqlite3_column_int(stmt, 0) != expected ||
            status_type != SQLITE_TEXT || !text ||
            !row_epoch ||
            sqlite3_column_bytes(stmt, 1) != (int)status_size ||
            memcmp(text, status, status_size) != 0 ||
            (epoch_bound && (epoch_type != SQLITE_BLOB ||
             sqlite3_column_bytes(stmt, 2) != 32 ||
             memcmp(row_epoch, epoch, 32) != 0))) {
            sqlite3_finalize(stmt);
            return false;
        }
        expected++;
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && expected == rows;
}

struct fold_observation {
    uint8_t commitment[32];
    int64_t count;
    uint64_t inputs_verified;
    uint64_t script_verified;
    uint64_t proof_verified;
    uint64_t utxo_verified;
    bool profile_rows;
    bool all_script_valid;
};

static int run_fold(const char *tag, struct synth_chain *sc, bool skip,
                    struct fold_observation *out)
{
    char dir[256];
    struct main_state ms;
    test_fmt_tmpdir(dir, sizeof(dir), "mint_skip_crypto", tag);
    mkdir_p("./test-tmp");
    mkdir_p(dir);
    int drained = -1;
    if (!progress_store_open(dir)) return -1;
    memset(out, 0, sizeof(*out));
    out->count = -1;

    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    for (int h = 0; h < sc->n; h++)
        sc->blocks[h].nStatus = BLOCK_HAVE_DATA;
    active_chain_move_window_tip(&ms.chain_active, &sc->blocks[sc->n - 1]);

    /* The toggle is process-global; set it BEFORE init/drive and clear after. */
    mint_skip_crypto_set(skip);

    uint8_t epoch[32];
    for (size_t i = 0; i < sizeof(epoch); i++)
        epoch[i] = (uint8_t)(0x80u + i);
    if (!progress_meta_set(progress_store_db(),
                           CONSENSUS_STATE_SOURCE_EPOCH_META_KEY,
                           epoch, sizeof(epoch)))
        goto done;

    if (!seed_body_persist(progress_store_db(), sc->n)) goto done;

    if (!script_validate_stage_init(&ms)) goto done;
    script_validate_stage_set_reader(fake_reader, sc);
    script_validate_stage_set_prevout_resolver(fake_prevout, sc);
    if (!proof_validate_stage_init(&ms)) goto done;
    proof_validate_stage_set_reader(fake_reader, sc);
    if (!utxo_apply_stage_init(&ms)) goto done;
    utxo_apply_stage_set_reader(fake_reader, sc);
    utxo_apply_stage_set_lookup(fake_lookup, sc);

    drained = script_validate_stage_drain(1000);
    (void)proof_validate_stage_drain(1000);
    (void)utxo_apply_stage_drain(1000);

    const char *expected_status = skip ? "checkpoint_fold" : "verified";
    out->profile_rows =
        stage_rows_match(progress_store_db(), "script_validate_log",
                         sc->n, expected_status, epoch) &&
        stage_rows_match(progress_store_db(), "proof_validate_log",
                         sc->n, expected_status, epoch) &&
        stage_rows_match(progress_store_db(), "utxo_apply_log",
                         sc->n, expected_status, epoch);
    out->inputs_verified = script_validate_stage_inputs_verified_total();
    out->script_verified = script_validate_stage_verified_total();
    out->proof_verified = proof_validate_stage_verified_total();
    out->utxo_verified = utxo_apply_stage_verified_total();
    out->count = coins_kv_count(progress_store_db());
    (void)coins_kv_commitment(progress_store_db(), out->commitment);
    out->all_script_valid = true;
    for (int h = 0; h < sc->n; h++)
        if ((sc->blocks[h].nStatus & BLOCK_VALID_MASK) != BLOCK_VALID_SCRIPTS)
            out->all_script_valid = false;

done:
    utxo_apply_stage_shutdown();
    proof_validate_stage_shutdown();
    script_validate_stage_shutdown();
    mint_skip_crypto_set(false);        /* never leak the toggle to other tests */
    active_chain_free(&ms.chain_active);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return drained;
}

static char *read_source_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    char *buf = zcl_malloc((size_t)len + 1, "msc_source");
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)len, f);
    fclose(f);
    if (got != (size_t)len) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

static bool msc_set_applied_height(sqlite3 *db, int32_t h)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK;
    if (ok)
        ok = coins_kv_set_applied_height_in_tx(db, h);
    if (ok)
        ok = sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err)
        sqlite3_free(err);
    return ok;
}

static struct sha3_utxo_checkpoint msc_checkpoint(int32_t height,
                                                  uint64_t count,
                                                  uint8_t salt)
{
    struct sha3_utxo_checkpoint cp;
    memset(&cp, 0, sizeof(cp));
    cp.height = height;
    cp.utxo_count = count;
    cp.total_supply = 123456;
    for (int i = 0; i < 32; i++) {
        cp.sha3_hash[i] = (uint8_t)(salt + i);
        cp.block_hash[i] = (uint8_t)(0x80 + salt + i);
    }
    return cp;
}

static void msc_clear_refold_progress(sqlite3 *db)
{
    if (db) {
        (void)progress_meta_delete(db, REFOLD_IN_PROGRESS_KEY);
        (void)progress_meta_delete(db, REFOLD_FROM_ANCHOR_KEY);
        (void)progress_meta_delete(db, REFOLD_FROM_ANCHOR_TARGET_KEY);
        (void)refold_progress_refresh(db);
    }
    refold_progress_test_set_cached(false);
}

static int test_mint_anchor_progress_resume(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_skip_crypto", "resume_marker");
    mkdir_p("./test-tmp");
    mkdir_p(dir);

    struct sha3_utxo_checkpoint cp = msc_checkpoint(200, 9, 0x11);
    struct sha3_utxo_checkpoint other = msc_checkpoint(200, 9, 0x22);

    bool opened = progress_store_open(dir);
    sqlite3 *db = opened ? progress_store_db() : NULL;
    MSC_CHECK("mint progress: progress store opens", opened && db);
    if (!opened || !db)
        return failures + 1;

    MSC_CHECK("mint progress: clean full producer lane binds",
              mint_anchor_producer_lane_bind(db, false));
    int32_t through = -99;
    bool legacy = true;
    MSC_CHECK("mint progress: no marker does not resume",
              !mint_anchor_progress_can_resume(db, &cp, &through, &legacy));

    MSC_CHECK("mint progress: seed applied frontier",
              msc_set_applied_height(db, 43));
    MSC_CHECK("mint progress: mark in progress",
              mint_anchor_progress_mark(db, &cp));
    through = -99;
    legacy = true;
    MSC_CHECK("mint progress: matching marker resumes",
              mint_anchor_progress_can_resume(db, &cp, &through, &legacy) &&
              through == 42 && !legacy);
    MSC_CHECK("mint progress: checkpoint mismatch refuses resume",
              !mint_anchor_progress_can_resume(db, &other, NULL, NULL));

    MSC_CHECK("mint progress: clear marker",
              mint_anchor_progress_clear(db));
    (void)progress_meta_delete(db, REFOLD_IN_PROGRESS_KEY);
    (void)refold_progress_refresh(db);
    MSC_CHECK("mint progress: cleared marker no longer resumes",
              !mint_anchor_progress_can_resume(db, &cp, NULL, NULL));

    MSC_CHECK("mint progress: legacy refold signal armed",
              refold_progress_mark_started(db));
    through = -99;
    legacy = false;
    MSC_CHECK("mint progress: legacy interrupted fold adopted",
              mint_anchor_progress_can_resume(db, &cp, &through, &legacy) &&
              through == 42 && legacy);
    through = -99;
    legacy = true;
    MSC_CHECK("mint progress: adopted marker resumes normally",
              mint_anchor_progress_can_resume(db, &cp, &through, &legacy) &&
              through == 42 && !legacy);

    MSC_CHECK("mint progress: frontier past anchor recorded",
              msc_set_applied_height(db, cp.height + 2));
    MSC_CHECK("mint progress: marker refuses past-anchor frontier",
              !mint_anchor_progress_can_resume(db, &cp, NULL, NULL));

    msc_clear_refold_progress(db);
    progress_store_close();
    refold_progress_test_set_cached(false);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Nanosecond identity of two stat results, platform-split at file scope —
 * preprocessing directives may not sit inside a macro argument list, so the
 * MSC_CHECK call above goes through this helper. UCRT struct stat carries
 * second-resolution times only. */
#if defined(_WIN32)
static bool msc_stat_times_equal(const struct stat *a, const struct stat *b)
{
    return a->st_mtime==b->st_mtime&&a->st_ctime==b->st_ctime;
}
#else
static bool msc_stat_times_equal(const struct stat *a, const struct stat *b)
{
    return a->st_mtim.tv_sec==b->st_mtim.tv_sec&&
           a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
           a->st_ctim.tv_sec==b->st_ctim.tv_sec&&
           a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
#endif

static int test_mint_anchor_lane_containment(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_skip_crypto", "producer_lane");
    mkdir_p("./test-tmp");
    mkdir_p(dir);
    bool opened = progress_store_open(dir);
    sqlite3 *db = opened ? progress_store_db() : NULL;
    MSC_CHECK("producer lane: progress store opens", opened && db);
    if (!opened || !db)
        return failures + 1;

    char reason[256];
    MSC_CHECK("producer lane: clean serving datadir is allowed",
              mint_anchor_normal_boot_allowed(db, reason, sizeof(reason)));
    MSC_CHECK("producer lane: legitimate seed anchor row remains allowed",
              exec_sql(db,
                  "CREATE TABLE utxo_apply_log("
                  "height INTEGER PRIMARY KEY,status TEXT,ok INTEGER);"
                  "INSERT INTO utxo_apply_log VALUES(7,'anchor',1)") &&
              mint_anchor_normal_boot_allowed(db, reason, sizeof(reason)));
    MSC_CHECK("producer lane: embedded-NUL evidence is contained",
              exec_sql(db,
                  "INSERT INTO utxo_apply_log VALUES(8,"
                  "CAST(X'7665726966696564006a756e6b' AS TEXT),1)") &&
              !mint_anchor_normal_boot_allowed(db, reason, sizeof(reason)) &&
              reason[0] != '\0');
    MSC_CHECK("producer lane: remove hostile fixture row",
              exec_sql(db, "DELETE FROM utxo_apply_log WHERE height=8"));
    MSC_CHECK("producer lane: exact checkpoint evidence is contained",
              exec_sql(db,
                  "INSERT INTO utxo_apply_log VALUES(8,'checkpoint_fold',1)") &&
              !mint_anchor_normal_boot_allowed(db, reason, sizeof(reason)) &&
              reason[0] != '\0');
    MSC_CHECK("producer lane: remove checkpoint fixture row",
              exec_sql(db, "DELETE FROM utxo_apply_log WHERE height=8"));
    MSC_CHECK("producer lane: malformed ok storage is not success",
              exec_sql(db,
                  "INSERT INTO utxo_apply_log VALUES(9,'verified',"
                  "CAST('1x' AS TEXT))") &&
              !utxo_apply_stage_succeeded_at(9));
    MSC_CHECK("producer lane: remove malformed ok fixture row",
              exec_sql(db, "DELETE FROM utxo_apply_log WHERE height=9"));

    /* Pre-lane state is deliberately ambiguous: old full and old fast
     * producers wrote the same durable rows. It may only be conservatively
     * adopted as checkpoint_fold, never promoted to full. */
    MSC_CHECK("producer lane: legacy applied frontier fixture",
              msc_set_applied_height(db, 43));
    MSC_CHECK("producer lane: legacy refold fixture",
              refold_progress_mark_started(db));
    MSC_CHECK("producer lane: unknown legacy mode cannot bind full",
              !mint_anchor_producer_lane_bind(db, false));
    {
        uint8_t lane = 0;
        size_t lane_n = 0;
        bool lane_found = false;
        MSC_CHECK("producer lane: refused full adoption writes no lane",
                  progress_meta_get_blob_exact(
                      db, MINT_ANCHOR_PRODUCER_LANE_KEY, &lane, sizeof(lane),
                      &lane_n, &lane_found) && !lane_found);
    }
    MSC_CHECK("producer lane: unknown legacy mode downgrades to checkpoint",
              mint_anchor_producer_lane_bind(db, true));
    MSC_CHECK("producer lane: downgraded legacy can never become full",
              !mint_anchor_producer_lane_bind(db, false));
    msc_clear_refold_progress(db);

    MSC_CHECK("producer lane: TEXT marker fixture writes",
              exec_sql(db,
                  "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('"
                  MINT_ANCHOR_IN_PROGRESS_KEY
                  "',CAST('ZAM1-1x' AS TEXT))"));
    MSC_CHECK("producer lane: TEXT marker cannot authorize resume",
              !mint_anchor_progress_can_resume(db, &(struct sha3_utxo_checkpoint){0},
                                               NULL, NULL));
    MSC_CHECK("producer lane: TEXT marker contains normal boot",
              !mint_anchor_normal_boot_allowed(db, reason, sizeof(reason)));
    MSC_CHECK("producer lane: remove TEXT marker fixture",
              progress_meta_delete(db, MINT_ANCHOR_IN_PROGRESS_KEY));
    MSC_CHECK("producer lane: REAL marker fixture writes",
              exec_sql(db,
                  "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('"
                  MINT_ANCHOR_IN_PROGRESS_KEY "',1.25)"));
    MSC_CHECK("producer lane: REAL marker contains normal boot",
              !mint_anchor_normal_boot_allowed(db, reason, sizeof(reason)));
    MSC_CHECK("producer lane: remove REAL marker fixture",
              progress_meta_delete(db, MINT_ANCHOR_IN_PROGRESS_KEY));

    uint8_t legacy_marker[48] = {0};
    memcpy(legacy_marker, "ZAM1", 4);
    MSC_CHECK("producer lane: legacy in-progress marker is written",
              progress_meta_set(db, MINT_ANCHOR_IN_PROGRESS_KEY,
                                legacy_marker, sizeof(legacy_marker)));
    MSC_CHECK("producer lane: legacy producer cannot normal boot",
              !mint_anchor_normal_boot_allowed(db, reason, sizeof(reason)) &&
              strstr(reason, "in-progress marker") != NULL);
    MSC_CHECK("producer lane: remove legacy marker fixture",
              progress_meta_delete(db, MINT_ANCHOR_IN_PROGRESS_KEY));

    MSC_CHECK("producer lane: numeric-prefix TEXT lane fixture writes",
              exec_sql(db,
                  "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('"
                  MINT_ANCHOR_PRODUCER_LANE_KEY "',CAST('2x' AS TEXT))"));
    MSC_CHECK("producer lane: TEXT lane cannot authorize resume",
              !mint_anchor_producer_lane_bind(db, true));
    MSC_CHECK("producer lane: remove TEXT lane fixture",
              progress_meta_delete(db, MINT_ANCHOR_PRODUCER_LANE_KEY));
    MSC_CHECK("producer lane: REAL lane fixture writes",
              exec_sql(db,
                  "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('"
                  MINT_ANCHOR_PRODUCER_LANE_KEY "',2.0)"));
    MSC_CHECK("producer lane: REAL lane cannot authorize resume",
              !mint_anchor_producer_lane_bind(db, true));
    MSC_CHECK("producer lane: REAL lane contains normal boot",
              !mint_anchor_normal_boot_allowed(db, reason, sizeof(reason)));
    MSC_CHECK("producer lane: remove REAL lane fixture",
              progress_meta_delete(db, MINT_ANCHOR_PRODUCER_LANE_KEY));

    MSC_CHECK("producer lane: checkpoint profile binds durably",
              mint_anchor_producer_lane_bind(db, true));
    MSC_CHECK("producer lane: same profile may resume",
              mint_anchor_producer_lane_bind(db, true));
    MSC_CHECK("producer lane: cross-profile resume is refused",
              !mint_anchor_producer_lane_bind(db, false));
    MSC_CHECK("producer lane: producer cannot become serving node",
              !mint_anchor_normal_boot_allowed(db, reason, sizeof(reason)) &&
              strstr(reason, "producer lane") != NULL);

    progress_store_close();
    opened = progress_store_open(dir);
    db = opened ? progress_store_db() : NULL;
    MSC_CHECK("producer lane: progress store reopens", opened && db);
    MSC_CHECK("producer lane: restart cannot erase containment",
              db && !mint_anchor_normal_boot_allowed(
                  db, reason, sizeof(reason)) && reason[0] != '\0');
    if (opened)
        progress_store_close();

    char progress_path[512],node_path[512],wallet_path[512];
    snprintf(progress_path,sizeof(progress_path),"%s/consensus.db",dir);
    snprintf(node_path,sizeof(node_path),"%s/node.db",dir);
    snprintf(wallet_path,sizeof(wallet_path),"%s/wallet.dat",dir);
    struct stat before,after;
    bool stat_before=lstat(progress_path,&before)==0;
    MSC_CHECK("producer lane: earliest preflight refuses producer datadir",
              stat_before&&!boot_mint_anchor_normal_boot_preflight(dir));
    MSC_CHECK("producer lane: preflight is read-only and precedes node/wallet",
              lstat(progress_path,&after)==0&&
              before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&
              before.st_size==after.st_size&&before.st_mode==after.st_mode&&
              msc_stat_times_equal(&before,&after)&&
              access(node_path,F_OK)!=0&&access(wallet_path,F_OK)!=0);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int test_normal_boot_preflight_killed_wal(void)
{
    int failures = 0;
    for (int producer = 0; producer <= 1; producer++) {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "mint_skip_crypto",
                        producer ? "killed_wal_producer" :
                                   "killed_wal_benign");
        mkdir_p("./test-tmp");
        mkdir_p(dir);

        bool made = msc_make_killed_wal(dir, producer != 0);
        MSC_CHECK(producer ? "WAL preflight: producer kill-9 fixture"
                           : "WAL preflight: benign kill-9 fixture",
                  made);

        char main_path[512], wal_path[512], shm_path[512];
        int n1 = snprintf(main_path, sizeof(main_path), "%s/consensus.db", dir);
        int n2 = snprintf(wal_path, sizeof(wal_path), "%s/consensus.db-wal", dir);
        int n3 = snprintf(shm_path, sizeof(shm_path), "%s/consensus.db-shm", dir);
        bool paths_ok = n1 > 0 && (size_t)n1 < sizeof(main_path) &&
            n2 > 0 && (size_t)n2 < sizeof(wal_path) &&
            n3 > 0 && (size_t)n3 < sizeof(shm_path);
        bool shm_removed = paths_ok &&
            (unlink(shm_path) == 0 || errno == ENOENT);
        struct stat main_before, wal_before;
        bool identity_ready = made && shm_removed &&
            lstat(main_path, &main_before) == 0 &&
            lstat(wal_path, &wal_before) == 0 && wal_before.st_size > 0 &&
            access(shm_path, F_OK) != 0 && errno == ENOENT;
        MSC_CHECK("WAL preflight: source is main plus non-empty WAL only",
                  identity_ready);

        bool allowed = identity_ready &&
            boot_mint_anchor_normal_boot_preflight(dir);
        MSC_CHECK(producer
                      ? "WAL preflight: WAL-only producer marker is refused"
                      : "WAL preflight: benign WAL-only row is allowed",
                  producer ? identity_ready && !allowed : allowed);

        struct stat main_after, wal_after;
        bool unchanged = identity_ready &&
            lstat(main_path, &main_after) == 0 &&
            lstat(wal_path, &wal_after) == 0 &&
            msc_identity_same(&main_before, &main_after) &&
            msc_identity_same(&wal_before, &wal_after) &&
            access(shm_path, F_OK) != 0 && errno == ENOENT;
        MSC_CHECK("WAL preflight: source family remains exactly unchanged",
                  unchanged);
        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int deny_delete_authorizer(void *opaque, int action, const char *a,
                                  const char *b, const char *c, const char *d)
{
    (void)opaque;
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    return action == SQLITE_DELETE ? SQLITE_DENY : SQLITE_OK;
}

/* A brand-new producer datadir has no legacy node.db header_admit_log
 * mirror; the genesis reset must treat that as already-reset, not refuse
 * (regression: fresh -mint-anchor datadir FATALed on the missing table). */
static int test_mint_anchor_reset_fresh_datadir(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_skip_crypto", "reset_fresh");
    mkdir_p("./test-tmp");
    mkdir_p(dir);
    bool opened = progress_store_open(dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool node_open = node_db_open(&ndb, ":memory:");
    MSC_CHECK("fresh reset: stores open", opened && node_open);
    bool no_mirror = node_open &&
        !node_db_exec(&ndb, "SELECT 1 FROM header_admit_log LIMIT 1");
    MSC_CHECK("fresh reset: legacy header_admit_log mirror absent", no_mirror);
    MSC_CHECK("fresh reset: genesis reset completes on a fresh datadir",
              opened && node_open && boot_mint_anchor_genesis_reset(&ndb));
    if (node_open)
        node_db_close(&ndb);
    if (opened)
        progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int test_mint_anchor_reset_fail_closed(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_skip_crypto", "reset_fail_closed");
    mkdir_p("./test-tmp");
    mkdir_p(dir);
    bool opened = progress_store_open(dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool node_open = node_db_open(&ndb, ":memory:");
    MSC_CHECK("reset failure: stores open", opened && node_open);
    bool authorizer = node_open && sqlite3_set_authorizer(
        ndb.db, deny_delete_authorizer, NULL) == SQLITE_OK;
    MSC_CHECK("reset failure: DELETE fault arms", authorizer);
    MSC_CHECK("reset failure: genesis reset refuses partial authority",
              authorizer && !boot_mint_anchor_genesis_reset(&ndb));
    uint8_t marker[64];
    size_t marker_n = 0;
    bool marker_found = false;
    MSC_CHECK("reset failure: no resumable producer marker is minted",
              progress_meta_get(progress_store_db(),
                  MINT_ANCHOR_IN_PROGRESS_KEY, marker, sizeof(marker),
                  &marker_n, &marker_found) && !marker_found);
    if (node_open) {
        (void)sqlite3_set_authorizer(ndb.db, NULL, NULL);
        node_db_close(&ndb);
    }
    if (opened)
        progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static bool msc_epoch_cell(sqlite3 *db, const char *table, int height,
                           int *type_out, int *bytes_out, bool *found_out)
{
    *type_out = SQLITE_NULL;
    *bytes_out = 0;
    *found_out = false;
    char sql[192];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT source_epoch_digest FROM %s WHERE height=?",
                     table);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return false;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(stmt, 1, height);
    int rc = sqlite3_step(stmt); // raw-sql-ok:test-fixture-verify
    if (rc == SQLITE_ROW) {
        *found_out = true;
        *type_out = sqlite3_column_type(stmt, 0);
        *bytes_out = sqlite3_column_bytes(stmt, 0);
        rc = sqlite3_step(stmt); // raw-sql-ok:test-fixture-verify
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

static int test_source_epoch_authority_types(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "mint_skip_crypto", "source_epoch_type");
    mkdir_p("./test-tmp");
    mkdir_p(dir);
    bool opened = progress_store_open(dir);
    sqlite3 *db = opened ? progress_store_db() : NULL;
    MSC_CHECK("source epoch: progress store opens", opened && db);
    if (!opened || !db)
        return failures + 1;
    MSC_CHECK("source epoch: log schemas initialize",
              script_validate_log_ensure_schema(db) &&
              proof_validate_log_ensure_schema(db));

    struct uint256 hash;
    uint256_set_null(&hash);
    hash.data[0] = 0x42;
    MSC_CHECK("source epoch: numeric-prefix TEXT fixture writes",
              exec_sql(db,
                  "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('"
                  CONSENSUS_STATE_SOURCE_EPOCH_META_KEY
                  "',CAST('123x' AS TEXT))"));
    MSC_CHECK("source epoch: TEXT refuses script receipt publication",
              !script_validate_log_insert(db, 1, "verified", true, 0, 0,
                                          NULL, -1, SCRIPT_ERR_OK, &hash));
    MSC_CHECK("source epoch: TEXT refuses proof receipt publication",
              !proof_validate_log_insert(db, 1, "verified", true, 0, 0, 0,
                                         &hash, NULL, NULL));

    MSC_CHECK("source epoch: REAL fixture writes",
              exec_sql(db,
                  "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('"
                  CONSENSUS_STATE_SOURCE_EPOCH_META_KEY "',1.25)"));
    MSC_CHECK("source epoch: REAL refuses script receipt publication",
              !script_validate_log_insert(db, 2, "verified", true, 0, 0,
                                          NULL, -1, SCRIPT_ERR_OK, &hash));
    MSC_CHECK("source epoch: REAL refuses proof receipt publication",
              !proof_validate_log_insert(db, 2, "verified", true, 0, 0, 0,
                                         &hash, NULL, NULL));

    MSC_CHECK("source epoch: optional legacy absence fixture",
              progress_meta_delete(db, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY));
    MSC_CHECK("source epoch: absent epoch keeps legacy script receipt",
              script_validate_log_insert(db, 3, "verified", true, 0, 0,
                                         NULL, -1, SCRIPT_ERR_OK, &hash));
    MSC_CHECK("source epoch: absent epoch keeps legacy proof receipt",
              proof_validate_log_insert(db, 3, "verified", true, 0, 0, 0,
                                        &hash, NULL, NULL));
    int type = -1, bytes = -1;
    bool found = false;
    MSC_CHECK("source epoch: legacy script receipt is explicitly unbound",
              msc_epoch_cell(db, "script_validate_log", 3, &type, &bytes,
                             &found) && found && type == SQLITE_NULL);
    MSC_CHECK("source epoch: legacy proof receipt is explicitly unbound",
              msc_epoch_cell(db, "proof_validate_log", 3, &type, &bytes,
                             &found) && found && type == SQLITE_NULL);

    uint8_t epoch[32];
    memset(epoch, 0xa5, sizeof(epoch));
    MSC_CHECK("source epoch: exact BLOB authority writes",
              progress_meta_set(db, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY,
                                epoch, sizeof(epoch)));
    MSC_CHECK("source epoch: exact BLOB binds script receipt",
              script_validate_log_insert(db, 4, "verified", true, 0, 0,
                                         NULL, -1, SCRIPT_ERR_OK, &hash));
    MSC_CHECK("source epoch: exact BLOB binds proof receipt",
              proof_validate_log_insert(db, 4, "verified", true, 0, 0, 0,
                                        &hash, NULL, NULL));
    MSC_CHECK("source epoch: script receipt stores exact BLOB32",
              msc_epoch_cell(db, "script_validate_log", 4, &type, &bytes,
                             &found) && found && type == SQLITE_BLOB &&
              bytes == 32);
    MSC_CHECK("source epoch: proof receipt stores exact BLOB32",
              msc_epoch_cell(db, "proof_validate_log", 4, &type, &bytes,
                             &found) && found && type == SQLITE_BLOB &&
              bytes == 32);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_mint_skip_crypto(void);
int test_mint_skip_crypto(void)
{
    int failures = 0;
#if defined(_WIN32)
    /* Re-executed child-process arm (test_spawn_self_with_role): run only
     * the fork-role body, never the full group. */
    {
        const char *role = getenv("ZCL_TEST_FORK_ROLE");
        if (role && role[0])
            return msc_fork_role_dispatch(role);
    }
#endif
#if defined(_WIN32)
    /* progress_store is fail-closed on Windows ("native Windows consensus
     * store disabled: retained-directory SQLite VFS is not qualified"; that
     * refusal is the acceptance in
     * progress_store_windows_refusal_acceptance.c), so neither fold can open
     * its store and the equivalence claim is unobservable here. */
    printf("mint_skip_crypto: SKIP (Windows): progress_store refuses on "
           "Windows by design (see the refusal acceptance)\n");
    return 0;
#endif
    printf("\n=== test_mint_skip_crypto: state-only fold == validated fold ===\n");

    blocker_module_init();

    const int N = 5;
    struct synth_chain sc;
    if (!synth_chain_build(&sc, N)) {
        printf("mint_skip_crypto: FAILED to build synthetic chain\n");
        return 1;
    }

    struct fold_observation full, skip;
    int drained_full = run_fold("full", &sc, /*skip=*/false, &full);
    int drained_skip = run_fold("skip", &sc, /*skip=*/true, &skip);

    /* Both folds walked every height. */
    MSC_CHECK("full validation drains all heights", drained_full == N);
    MSC_CHECK("state-only fold drains all heights", drained_skip == N);

    /* The load-bearing equivalence: the UTXO set is identical. */
    MSC_CHECK("count(full) == count(state-only)",
              full.count == skip.count && full.count > 0);
    MSC_CHECK("coins_kv commitment identical",
              memcmp(full.commitment, skip.commitment, 32) == 0);

    /* Equivalence floor — the toggle is the ONLY difference: full validation
     * actually ran verify_script (inputs verified > 0); the state-only fold
     * skipped it (0). Proves the OFF path (a normal boot) runs real crypto. */
    MSC_CHECK("full validation ran verify_script (inputs_verified > 0)",
              full.inputs_verified > 0);
    MSC_CHECK("state-only fold SKIPPED verify_script (inputs_verified == 0)",
              skip.inputs_verified == 0);
    MSC_CHECK("full crypto rows bind prepared epoch as verified",
              full.profile_rows);
    MSC_CHECK("fast crypto rows bind prepared epoch as checkpoint_fold",
              skip.profile_rows);
    MSC_CHECK("full fold counts all three verified stages",
              full.script_verified == (uint64_t)N &&
              full.proof_verified == (uint64_t)N &&
              full.utxo_verified == (uint64_t)N);
    MSC_CHECK("checkpoint fold never increments verified stage counters",
              skip.script_verified == 0 && skip.proof_verified == 0 &&
              skip.utxo_verified == 0);
    MSC_CHECK("full fold raises BLOCK_VALID_SCRIPTS", full.all_script_valid);
    MSC_CHECK("checkpoint fold cannot raise BLOCK_VALID_SCRIPTS",
              !skip.all_script_valid);

    /* Sanity: a non-empty set actually folded. Each block creates 2 outputs
     * (coinbase + spend) and spends an EXTERNAL coin (not in this set), so 2
     * coins survive per block → 2*N coins. A non-trivial, non-empty fold makes
     * the commitment-equality above load-bearing (not a vacuous empty==empty). */
    MSC_CHECK("folded a non-trivial UTXO set",
              full.count == (int64_t)(2 * N));

    char *boot_src = read_source_file("engine/composition/src/boot.c");
    char *main_src = read_source_file("engine/entry/main.c");
    const char *offline_marker = boot_src
        ? strstr(boot_src, "-mint-anchor: offline reducer stages initialized")
        : NULL;
    const char *services_start = boot_src
        ? strstr(boot_src, "app_init_services(ctx, params, &g_svc)")
        : NULL;
    MSC_CHECK("mint-anchor app_init exits before app_init_services",
              offline_marker && services_start && offline_marker < services_start);

    const char *mint_branch = main_src
        ? strstr(main_src, "if (ctx.mint_anchor) {")
        : NULL;
    const char *offline_shutdown = mint_branch
        ? strstr(mint_branch, "app_shutdown_offline();")
        : NULL;
    const char *mint_return = mint_branch
        ? strstr(mint_branch, "return minted ? 0 : 1;")
        : NULL;
    const char *full_shutdown = mint_branch
        ? strstr(mint_branch, "app_shutdown();")
        : NULL;
    MSC_CHECK("mint-anchor uses offline shutdown",
              offline_shutdown && mint_return && offline_shutdown < mint_return);
    MSC_CHECK("mint-anchor does not call full app_shutdown",
              mint_return && (!full_shutdown || full_shutdown > mint_return));

    const char *offline_shutdown_fn = boot_src
        ? strstr(boot_src, "void app_shutdown_offline(void)")
        : NULL;
    const char *wallet_flush = offline_shutdown_fn
        ? strstr(offline_shutdown_fn, "wallet_sqlite_flush_r(&g_wallet_sqlite")
        : NULL;
    const char *wallet_close = offline_shutdown_fn
        ? strstr(offline_shutdown_fn, "wallet_sqlite_close(&g_wallet_sqlite)")
        : NULL;
    const char *wallet_free_call = offline_shutdown_fn
        ? strstr(offline_shutdown_fn, "wallet_free(&g_wallet)")
        : NULL;
    MSC_CHECK("offline shutdown flushes wallet sqlite before wallet_free",
              wallet_flush && wallet_free_call && wallet_flush < wallet_free_call);
    MSC_CHECK("offline shutdown closes wallet sqlite before wallet_free",
              wallet_close && wallet_free_call && wallet_close < wallet_free_call);

    MSC_CHECK("mint-anchor emits 10k progress heartbeats",
              !boot_mint_anchor_should_log_progress(9999, 3056758) &&
              boot_mint_anchor_should_log_progress(10000, 3056758) &&
              !boot_mint_anchor_should_log_progress(10001, 3056758) &&
              boot_mint_anchor_should_log_progress(20000, 3056758));
    MSC_CHECK("mint-anchor emits final-anchor tail heartbeats",
              !boot_mint_anchor_should_log_progress(3056741, 3056758) &&
              boot_mint_anchor_should_log_progress(3056742, 3056758) &&
              boot_mint_anchor_should_log_progress(3056758, 3056758));
    failures += test_mint_anchor_progress_resume();
    failures += test_mint_anchor_lane_containment();
    failures += test_normal_boot_preflight_killed_wal();
    failures += test_mint_anchor_reset_fresh_datadir();
    failures += test_mint_anchor_reset_fail_closed();
    failures += test_source_epoch_authority_types();
    free(boot_src);
    free(main_src);

    synth_chain_free(&sc);

    printf("=== test_mint_skip_crypto complete: %d failure(s) ===\n", failures);
    return failures;
}
