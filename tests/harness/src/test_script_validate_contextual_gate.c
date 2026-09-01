/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * #26 — at-tip contextual gate in script_validate (contextual_check_block
 * wiring). Pins the load-bearing properties of the gate:
 *   - unseeded finalized tip (tip_h == -1) keeps the gate CLOSED, so
 *     early/cold replay never re-rejects history (the always-true-window
 *     defeat the spec's verification round caught);
 *   - tip-proximity: next_h far below the finalized tip keeps it closed;
 *   - at tip, BIP34 (bad-cb-height) and per-tx finality
 *     (bad-txns-nonfinal) reject via the fail-closed ok=0 row, the
 *     contextual counter increments, and BLOCK_VALID_SCRIPTS is NOT set;
 *   - the finality cutoff is the block's OWN header time, not MTP
 *     (nLockTime in [MTP, header_time) is ACCEPTED);
 *   - snapshot-tail: a sparse pow/MTP window below the gate height makes
 *     process_block_should_skip_contextual_header bypass the gate;
 *   - cascade: a contextual ok=0 row flows downstream as a plain
 *     upstream_failed (proof_validate advances past it, no JOB_FATAL);
 *   - IBD granularity (rule level): is_ibd=true skips ONLY the per-tx
 *     contextual_check_transaction rules; finality + BIP34 still fire.
 *
 * Stage harness adapted from test_script_validate_stage.c. The synthetic
 * main_state is always in IBD (zero chainwork), which is exactly the
 * production shape the gate must enforce finality + BIP34 under; the
 * is_ibd=false branch is pinned at rule level via direct
 * contextual_check_block calls. */

#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "json/json.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CG_CHECK(name, expr) do { \
    printf("contextual_gate: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Chain long enough that process_block_should_skip_contextual_header's
 * pow-window walk (nPowAveragingWindow=17 + MEDIAN_TIME_SPAN=11 from
 * pprev) completes: the gate is reachable at heights >= 28. */
#define CG_CHAIN_LEN 33
#define CG_GATE_H    30   /* gate-eligible height the cases mutate */
#define CG_BASE_TIME 1700000000u

struct cg_chain {
    struct block_index *blocks;
    struct uint256     *hashes;
    struct block       *bodies;
    struct uint256     *prev_hashes;
    struct tx_out      *prevouts;
    int                 n;
};

static int cg_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* Minimal CScriptNum height encoding (the exact bytes BIP34 expects).
 * Heights here are <= 127, so no sign byte is ever needed, but keep the
 * general encoder so the fixture matches bip34_check_coinbase_height. */
static size_t cg_bip34_sig(uint8_t *out, int height)
{
    if (height == 0) { out[0] = 0x00; return 1; }
    uint8_t num[4];
    size_t n = 0;
    int h = height;
    while (h > 0) { num[n++] = (uint8_t)(h & 0xff); h >>= 8; }
    if (num[n - 1] & 0x80) num[n++] = 0x00;
    out[0] = (uint8_t)n;
    memcpy(out + 1, num, n);
    return 1 + n;
}

static void cg_make_prevout(struct tx_out *out)
{
    tx_out_set_null(out);
    out->value = 100000000;
    script_init(&out->script_pub_key);
    script_push_op(&out->script_pub_key, OP_TRUE);
}

static bool cg_make_body(struct cg_chain *sc, int h)
{
    struct block *b = &sc->bodies[h];
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = CG_BASE_TIME + (uint32_t)h;
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 2;
    b->vtx = zcl_calloc(2, sizeof(struct transaction), "cg_tx");
    if (!b->vtx) return false;

    transaction_init(&b->vtx[0]);
    if (!transaction_alloc(&b->vtx[0], 1, 1)) return false;
    outpoint_set_null(&b->vtx[0].vin[0].prevout);
    uint8_t cb_sig[8];
    size_t cb_len = cg_bip34_sig(cb_sig, h);
    script_set(&b->vtx[0].vin[0].script_sig, cb_sig, cb_len);
    b->vtx[0].vin[0].sequence = 0xFFFFFFFF;
    b->vtx[0].vout[0] = sc->prevouts[h];
    transaction_compute_hash(&b->vtx[0]);
    sc->prev_hashes[h] = b->vtx[0].hash;

    transaction_init(&b->vtx[1]);
    if (!transaction_alloc(&b->vtx[1], 1, 1)) return false;
    b->vtx[1].vin[0].prevout.hash = sc->prev_hashes[h];
    b->vtx[1].vin[0].prevout.n = 0;
    script_init(&b->vtx[1].vin[0].script_sig);
    /* transaction_alloc defaults sequence to UINT32_MAX (final-by-sequence,
     * which would defeat the lock_time fixtures); force the non-final
     * sequence so finality is decided by lock_time. */
    b->vtx[1].vin[0].sequence = 0;
    b->vtx[1].vout[0].value = 99900000;
    script_init(&b->vtx[1].vout[0].script_pub_key);
    script_push_op(&b->vtx[1].vout[0].script_pub_key, OP_TRUE);
    transaction_compute_hash(&b->vtx[1]);

    struct uint256 txids[2] = { b->vtx[0].hash, b->vtx[1].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    return true;
}

static bool cg_chain_build(struct cg_chain *sc, int n)
{
    memset(sc, 0, sizeof(*sc));
    sc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index),
                            "cg_blocks");
    sc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "cg_hashes");
    sc->bodies = zcl_calloc((size_t)n, sizeof(struct block), "cg_bodies");
    sc->prev_hashes = zcl_calloc((size_t)n, sizeof(struct uint256),
                                 "cg_prev_hashes");
    sc->prevouts = zcl_calloc((size_t)n, sizeof(struct tx_out),
                              "cg_prevouts");
    if (!sc->blocks || !sc->hashes || !sc->bodies ||
        !sc->prev_hashes || !sc->prevouts)
        return false;
    for (int i = 0; i < n; i++) {
        cg_make_prevout(&sc->prevouts[i]);
        if (!cg_make_body(sc, i)) return false;
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

static void cg_chain_free(struct cg_chain *sc)
{
    if (sc->bodies) {
        for (int i = 0; i < sc->n; i++)
            block_free(&sc->bodies[i]);
    }
    free(sc->blocks);
    free(sc->hashes);
    free(sc->bodies);
    free(sc->prev_hashes);
    free(sc->prevouts);
    memset(sc, 0, sizeof(*sc));
}

/* Recompute hashes after a body mutation at height h: tx0 hash feeds
 * tx1's intra-block prevout (so the script path still resolves when the
 * gate is closed), then merkle root + block hash. hashes[h] is updated
 * in place, so blocks[h].phashBlock stays valid. */
static bool cg_rebuild(struct cg_chain *sc, int h)
{
    struct block *b = &sc->bodies[h];
    transaction_compute_hash(&b->vtx[0]);
    sc->prev_hashes[h] = b->vtx[0].hash;
    b->vtx[1].vin[0].prevout.hash = sc->prev_hashes[h];
    transaction_compute_hash(&b->vtx[1]);
    struct uint256 txids[2] = { b->vtx[0].hash, b->vtx[1].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    block_header_get_hash(&b->header, &sc->hashes[h]);
    sc->blocks[h].hashMerkleRoot = b->header.hashMerkleRoot;
    return true;
}

/* BIP34 violation: corrupt the height byte of the minimal push. */
static bool cg_corrupt_cb_height(struct cg_chain *sc, int h)
{
    struct block *b = &sc->bodies[h];
    if (b->vtx[0].vin[0].script_sig.size < 2) return false;
    b->vtx[0].vin[0].script_sig.data[1] ^= 0x55;
    return cg_rebuild(sc, h);
}

static bool cg_set_locktime(struct cg_chain *sc, int h, uint32_t lock_time)
{
    sc->bodies[h].vtx[1].lock_time = lock_time;
    return cg_rebuild(sc, h);
}

static bool cg_fake_reader(struct block *out, const struct block_index *bi,
                           const char *datadir, void *user)
{
    (void)datadir;
    struct cg_chain *sc = user;
    if (!out || !bi || !sc || bi->nHeight < 0 || bi->nHeight >= sc->n)
        return false;
    return test_block_copy(out, &sc->bodies[bi->nHeight], "cg_tx_copy");
}

static bool cg_fake_prevout(const struct outpoint *prevout,
                            struct tx_out *out, void *user)
{
    struct cg_chain *sc = user;
    if (!prevout || !out || !sc) return false;
    for (int h = 0; h < sc->n; h++) {
        if (uint256_eq(&prevout->hash, &sc->prev_hashes[h]) &&
            prevout->n == 0) {
            *out = sc->prevouts[h];
            return true;
        }
    }
    return false;
}

static bool cg_exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool cg_seed_body_persist(sqlite3 *db, int n)
{
    if (!cg_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height       INTEGER PRIMARY KEY,"
        "  source       TEXT    NOT NULL,"
        "  ok           INTEGER NOT NULL,"
        "  persisted_at INTEGER NOT NULL"
        ")"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO body_persist_log "
        "(height, source, ok, persisted_at) VALUES (?, 'verified', 1, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < n; h++) {
        sqlite3_bind_int(st, 1, h);
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
        "VALUES('body_persist', ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, n);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool cg_log_row_at(sqlite3 *db, int height, int *out_ok,
                          char *out_status, size_t status_size)
{
    *out_ok = -1;
    if (out_status && status_size) out_status[0] = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status FROM script_validate_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out_ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt && out_status && status_size)
            snprintf(out_status, status_size, "%s", (const char *)txt);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

/* Same shape as cg_log_row_at against proof_validate_log (the downstream
 * stage's verdict table) for the cascade case. */
static bool cg_pv_row_at(sqlite3 *db, int height, int *out_ok,
                         char *out_status, size_t status_size)
{
    *out_ok = -1;
    if (out_status && status_size) out_status[0] = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status FROM proof_validate_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out_ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt && out_status && status_size)
            snprintf(out_status, status_size, "%s", (const char *)txt);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

/* Serialize the stage dump and look for an exact "key":value token —
 * the only exported surface for g_contextual_reject_total. */
static bool cg_dump_has(const char *needle)
{
    struct json_value v;
    json_init(&v);
    if (!script_validate_dump_state_json(&v, NULL)) {
        json_free(&v);
        return false;
    }
    char buf[2048];
    size_t n = json_write(&v, buf, sizeof(buf));
    json_free(&v);
    if (n == 0 || n >= sizeof(buf)) return false;
    return strstr(buf, needle) != NULL;
}

/* Seed/clear the reducer's authoritative finalized tip. tip_finalize's
 * stage is never initialised here, so only the in-memory last-advance
 * marker (what tip_finalize_stage_last_height() reads) changes. */
static void cg_seed_tip(int height, const struct uint256 *hash)
{
    uint8_t zero[32] = {0};
    tip_finalize_stage_set_authoritative_tip(
        height, hash ? hash->data : zero);
}

static int cg_setup(const char *tag, char *dir_out, size_t dir_out_size,
                    struct main_state *ms, struct cg_chain *sc)
{
    test_fmt_tmpdir(dir_out, dir_out_size, "contextual_gate", tag);
    cg_mkdir_p("./test-tmp");
    cg_mkdir_p(dir_out);
    if (!progress_store_open(dir_out)) return 1;

    memset(ms, 0, sizeof(*ms));
    active_chain_init(&ms->chain_active);
    if (!cg_chain_build(sc, CG_CHAIN_LEN)) return 2;
    return 0;
}

/* Wire the chain + stage AFTER the per-case body mutations, so the
 * block_index hashes the stage stamps match the mutated bodies. */
static int cg_arm(struct main_state *ms, struct cg_chain *sc)
{
    active_chain_move_window_tip(&ms->chain_active,
                                 &sc->blocks[sc->n - 1]);
    if (!cg_seed_body_persist(progress_store_db(), sc->n)) return 1;
    if (!script_validate_stage_init(ms)) return 2;
    script_validate_stage_set_reader(cg_fake_reader, sc);
    script_validate_stage_set_prevout_resolver(cg_fake_prevout, sc);
    return 0;
}

static void cg_teardown(const char *dir, struct main_state *ms,
                        struct cg_chain *sc)
{
    script_validate_stage_shutdown();
    cg_seed_tip(-1, NULL);  /* never leak a finalized tip to later tests */
    active_chain_free(&ms->chain_active);
    cg_chain_free(sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

/* ── rule-level fixture (direct contextual_check_block calls) ────── */

static bool cg_make_rule_block(struct block *b, int height,
                               uint32_t header_time, bool overwintered_tx,
                               bool wrong_cb, uint32_t lock_time)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = header_time;
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 2;
    b->vtx = zcl_calloc(2, sizeof(struct transaction), "cg_rule_tx");
    if (!b->vtx) return false;

    transaction_init(&b->vtx[0]);
    if (!transaction_alloc(&b->vtx[0], 1, 1)) return false;
    outpoint_set_null(&b->vtx[0].vin[0].prevout);
    uint8_t cb_sig[8];
    size_t cb_len = cg_bip34_sig(cb_sig, height);
    if (wrong_cb) cb_sig[1] ^= 0x55;
    script_set(&b->vtx[0].vin[0].script_sig, cb_sig, cb_len);
    b->vtx[0].vin[0].sequence = 0xFFFFFFFF;
    b->vtx[0].vout[0].value = 1000000;
    script_push_op(&b->vtx[0].vout[0].script_pub_key, OP_TRUE);
    transaction_compute_hash(&b->vtx[0]);

    transaction_init(&b->vtx[1]);
    if (!transaction_alloc(&b->vtx[1], 1, 1)) return false;
    memset(b->vtx[1].vin[0].prevout.hash.data, 0xBB, 32);
    b->vtx[1].vin[0].prevout.n = 0;
    b->vtx[1].vin[0].sequence = 0;  /* non-final: finality rides lock_time */
    b->vtx[1].lock_time = lock_time;
    if (overwintered_tx) {
        /* Overwinter-v3 shape at a pre-Overwinter mainnet height —
         * contextual_check_transaction must reject tx-overwinter-not-active
         * when is_ibd=false and skip it entirely when is_ibd=true. */
        b->vtx[1].overwintered = true;
        b->vtx[1].version = 3;
        b->vtx[1].version_group_id = OVERWINTER_VERSION_GROUP_ID;
    }
    b->vtx[1].vout[0].value = 500000;
    script_push_op(&b->vtx[1].vout[0].script_pub_key, OP_TRUE);
    transaction_compute_hash(&b->vtx[1]);
    return true;
}

int test_script_validate_contextual_gate(void);
int test_script_validate_contextual_gate(void)
{
    printf("\n=== script_validate contextual gate (#26) tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* (1) CORRECTION-1 pin: unseeded finalized tip (tip_h == -1) keeps
     * the gate CLOSED — a BIP34-violating block at a gate-eligible
     * height must still come out "verified". */
    {
        char dir[256]; struct main_state ms; struct cg_chain sc;
        CG_CHECK("unseeded: setup",
                 cg_setup("unseeded", dir, sizeof(dir), &ms, &sc) == 0);
        CG_CHECK("unseeded: corrupt cb height",
                 cg_corrupt_cb_height(&sc, CG_GATE_H));
        CG_CHECK("unseeded: arm", cg_arm(&ms, &sc) == 0);
        cg_seed_tip(-1, NULL);
        CG_CHECK("unseeded: drains all",
                 script_validate_stage_drain(100) == CG_CHAIN_LEN);
        int ok = -1; char status[64];
        CG_CHECK("unseeded: row exists",
                 cg_log_row_at(progress_store_db(), CG_GATE_H, &ok, status,
                               sizeof(status)));
        CG_CHECK("unseeded: gate closed -> verified",
                 ok == 1 && strcmp(status, "verified") == 0);
        CG_CHECK("unseeded: counter 0",
                 cg_dump_has("\"contextual_reject_total\":0"));
        cg_teardown(dir, &ms, &sc);
    }

    /* (2) tip-proximity negative: finalized tip FAR above next_h (the
     * restored-datadir historical-replay shape) keeps the gate closed. */
    {
        char dir[256]; struct main_state ms; struct cg_chain sc;
        CG_CHECK("far_tip: setup",
                 cg_setup("far_tip", dir, sizeof(dir), &ms, &sc) == 0);
        CG_CHECK("far_tip: corrupt cb height",
                 cg_corrupt_cb_height(&sc, CG_GATE_H));
        CG_CHECK("far_tip: arm", cg_arm(&ms, &sc) == 0);
        cg_seed_tip(2000, NULL);  /* next_h=30 << 2000 - 16 */
        CG_CHECK("far_tip: drains all",
                 script_validate_stage_drain(100) == CG_CHAIN_LEN);
        int ok = -1; char status[64];
        cg_log_row_at(progress_store_db(), CG_GATE_H, &ok, status,
                      sizeof(status));
        CG_CHECK("far_tip: gate closed -> verified",
                 ok == 1 && strcmp(status, "verified") == 0);
        CG_CHECK("far_tip: counter 0",
                 cg_dump_has("\"contextual_reject_total\":0"));
        cg_teardown(dir, &ms, &sc);
    }

    /* (3) BIP34 at tip: bad-cb-height rejects fail-closed (ok=0 row,
     * counter++, BLOCK_VALID_SCRIPTS not raised), neighbours verify. */
    {
        char dir[256]; struct main_state ms; struct cg_chain sc;
        CG_CHECK("bip34: setup",
                 cg_setup("bip34", dir, sizeof(dir), &ms, &sc) == 0);
        CG_CHECK("bip34: corrupt cb height",
                 cg_corrupt_cb_height(&sc, CG_GATE_H));
        CG_CHECK("bip34: arm", cg_arm(&ms, &sc) == 0);
        cg_seed_tip(CG_CHAIN_LEN - 1, &sc.hashes[CG_CHAIN_LEN - 1]);
        CG_CHECK("bip34: drains all",
                 script_validate_stage_drain(100) == CG_CHAIN_LEN);
        int ok = -1; char status[64];
        cg_log_row_at(progress_store_db(), CG_GATE_H, &ok, status,
                      sizeof(status));
        CG_CHECK("bip34: reject row ok=0", ok == 0);
        CG_CHECK("bip34: reason bad-cb-height",
                 strcmp(status, "bad-cb-height") == 0);
        CG_CHECK("bip34: counter 1",
                 cg_dump_has("\"contextual_reject_total\":1"));
        CG_CHECK("bip34: VALID_SCRIPTS not set on rejected block",
                 (sc.blocks[CG_GATE_H].nStatus & BLOCK_VALID_MASK)
                     < (unsigned)BLOCK_VALID_SCRIPTS);
        cg_log_row_at(progress_store_db(), CG_GATE_H + 1, &ok, status,
                      sizeof(status));
        CG_CHECK("bip34: gate-eligible neighbour verified",
                 ok == 1 && strcmp(status, "verified") == 0);
        CG_CHECK("bip34: VALID_SCRIPTS set on neighbour",
                 (sc.blocks[CG_GATE_H + 1].nStatus & BLOCK_VALID_MASK)
                     == (unsigned)BLOCK_VALID_SCRIPTS);
        cg_teardown(dir, &ms, &sc);
    }

    /* (4) per-tx finality at tip: lock_time above header time with a
     * non-final sequence -> bad-txns-nonfinal (fires even under the
     * harness's IBD latch — finality is NOT IBD-gated). */
    {
        char dir[256]; struct main_state ms; struct cg_chain sc;
        CG_CHECK("nonfinal: setup",
                 cg_setup("nonfinal", dir, sizeof(dir), &ms, &sc) == 0);
        CG_CHECK("nonfinal: set lock_time above header time",
                 cg_set_locktime(&sc, CG_GATE_H,
                                 CG_BASE_TIME + CG_GATE_H + 1000));
        CG_CHECK("nonfinal: arm", cg_arm(&ms, &sc) == 0);
        cg_seed_tip(CG_CHAIN_LEN - 1, &sc.hashes[CG_CHAIN_LEN - 1]);
        CG_CHECK("nonfinal: drains all",
                 script_validate_stage_drain(100) == CG_CHAIN_LEN);
        int ok = -1; char status[64];
        cg_log_row_at(progress_store_db(), CG_GATE_H, &ok, status,
                      sizeof(status));
        CG_CHECK("nonfinal: reject row ok=0", ok == 0);
        CG_CHECK("nonfinal: reason bad-txns-nonfinal",
                 strcmp(status, "bad-txns-nonfinal") == 0);
        CG_CHECK("nonfinal: counter 1",
                 cg_dump_has("\"contextual_reject_total\":1"));
        cg_teardown(dir, &ms, &sc);
    }

    /* (5) header-time-cutoff pin: lock_time in [MTP, header_time) must
     * be ACCEPTED. MTP of blocks 19..29 is BASE+24; header time of block
     * 30 is BASE+30; lock_time BASE+29 sits between them — an MTP cutoff
     * (the pre-parity-fix c23 behavior) would wrongly reject it. */
    {
        char dir[256]; struct main_state ms; struct cg_chain sc;
        CG_CHECK("header_time: setup",
                 cg_setup("header_time", dir, sizeof(dir), &ms, &sc) == 0);
        CG_CHECK("header_time: lock_time in [MTP, header_time)",
                 cg_set_locktime(&sc, CG_GATE_H,
                                 CG_BASE_TIME + CG_GATE_H - 1));
        CG_CHECK("header_time: arm", cg_arm(&ms, &sc) == 0);
        cg_seed_tip(CG_CHAIN_LEN - 1, &sc.hashes[CG_CHAIN_LEN - 1]);
        CG_CHECK("header_time: drains all",
                 script_validate_stage_drain(100) == CG_CHAIN_LEN);
        int ok = -1; char status[64];
        cg_log_row_at(progress_store_db(), CG_GATE_H, &ok, status,
                      sizeof(status));
        CG_CHECK("header_time: accepted (verified)",
                 ok == 1 && strcmp(status, "verified") == 0);
        CG_CHECK("header_time: counter 0",
                 cg_dump_has("\"contextual_reject_total\":0"));
        cg_teardown(dir, &ms, &sc);
    }

    /* (6) clean chain at tip: gate open, nothing rejected, every
     * gate-eligible block verified with VALID_SCRIPTS raised. */
    {
        char dir[256]; struct main_state ms; struct cg_chain sc;
        CG_CHECK("clean: setup",
                 cg_setup("clean", dir, sizeof(dir), &ms, &sc) == 0);
        CG_CHECK("clean: arm", cg_arm(&ms, &sc) == 0);
        cg_seed_tip(CG_CHAIN_LEN - 1, &sc.hashes[CG_CHAIN_LEN - 1]);
        CG_CHECK("clean: drains all",
                 script_validate_stage_drain(100) == CG_CHAIN_LEN);
        CG_CHECK("clean: counter 0",
                 cg_dump_has("\"contextual_reject_total\":0"));
        bool all_verified = true;
        for (int h = 1; h < CG_CHAIN_LEN; h++) {
            int ok = -1; char status[64];
            if (!cg_log_row_at(progress_store_db(), h, &ok, status,
                               sizeof(status)) ||
                ok != 1 || strcmp(status, "verified") != 0)
                all_verified = false;
        }
        CG_CHECK("clean: all rows verified", all_verified);
        CG_CHECK("clean: VALID_SCRIPTS set at gate height",
                 (sc.blocks[CG_GATE_H].nStatus & BLOCK_VALID_MASK)
                     == (unsigned)BLOCK_VALID_SCRIPTS);
        cg_teardown(dir, &ms, &sc);
    }

    /* (7) snapshot-tail: a sparse pow/MTP window below the gate height
     * (the metadata-only import-anchor shape, nTime==0) makes
     * process_block_should_skip_contextual_header return true, so even a
     * BIP34-violating block at an in-window height is NOT gated. */
    {
        char dir[256]; struct main_state ms; struct cg_chain sc;
        CG_CHECK("sparse_tail: setup",
                 cg_setup("sparse_tail", dir, sizeof(dir), &ms, &sc) == 0);
        CG_CHECK("sparse_tail: corrupt cb height",
                 cg_corrupt_cb_height(&sc, CG_GATE_H));
        /* Sparse anchor inside the MTP span of CG_GATE_H's pow window —
         * exactly the post-FlyClient-snapshot-tail signal the skip
         * predicate checks (process_block_contextual_header.c). Only
         * block_index metadata changes; body hashes are untouched. */
        sc.blocks[5].nTime = 0;
        CG_CHECK("sparse_tail: arm", cg_arm(&ms, &sc) == 0);
        cg_seed_tip(CG_CHAIN_LEN - 1, &sc.hashes[CG_CHAIN_LEN - 1]);
        CG_CHECK("sparse_tail: drains all",
                 script_validate_stage_drain(100) == CG_CHAIN_LEN);
        int ok = -1; char status[64];
        cg_log_row_at(progress_store_db(), CG_GATE_H, &ok, status,
                      sizeof(status));
        CG_CHECK("sparse_tail: gate skipped -> verified",
                 ok == 1 && strcmp(status, "verified") == 0);
        CG_CHECK("sparse_tail: counter 0",
                 cg_dump_has("\"contextual_reject_total\":0"));
        cg_teardown(dir, &ms, &sc);
    }

    /* (8) cursor cascade (first hop): a contextual ok=0 row must flow
     * downstream as a status-agnostic upstream_failed — proof_validate
     * advances PAST the rejected height (no JOB_FATAL, no stall).
     * utxo_apply's JOB_BLOCKED-on-ok=0 behavior is pinned separately by
     * test_utxo_apply_stage. */
    {
        char dir[256]; struct main_state ms; struct cg_chain sc;
        CG_CHECK("cascade: setup",
                 cg_setup("cascade", dir, sizeof(dir), &ms, &sc) == 0);
        CG_CHECK("cascade: corrupt cb height",
                 cg_corrupt_cb_height(&sc, CG_GATE_H));
        CG_CHECK("cascade: arm", cg_arm(&ms, &sc) == 0);
        cg_seed_tip(CG_CHAIN_LEN - 1, &sc.hashes[CG_CHAIN_LEN - 1]);
        CG_CHECK("cascade: script drains all",
                 script_validate_stage_drain(100) == CG_CHAIN_LEN);
        int ok = -1; char status[64];
        cg_log_row_at(progress_store_db(), CG_GATE_H, &ok, status,
                      sizeof(status));
        CG_CHECK("cascade: contextual reject row ok=0",
                 ok == 0 && strcmp(status, "bad-cb-height") == 0);
        CG_CHECK("cascade: proof stage init", proof_validate_stage_init(&ms));
        proof_validate_stage_set_reader(cg_fake_reader, &sc);
        CG_CHECK("cascade: proof drains all (no FATAL, no stall)",
                 proof_validate_stage_drain(100) == CG_CHAIN_LEN);
        CG_CHECK("cascade: proof cursor past reject",
                 proof_validate_stage_cursor() == (uint64_t)CG_CHAIN_LEN);
        CG_CHECK("cascade: upstream_failed total 1",
                 proof_validate_stage_upstream_failed_total() == 1);
        cg_pv_row_at(progress_store_db(), CG_GATE_H, &ok, status,
                     sizeof(status));
        CG_CHECK("cascade: proof row upstream_failed ok=0",
                 ok == 0 && strcmp(status, "upstream_failed") == 0);
        proof_validate_stage_shutdown();
        cg_teardown(dir, &ms, &sc);
    }

    /* ── rule level: IBD granularity of contextual_check_block ─────── */

    /* (9) per-tx rules: rejected when is_ibd=false, SKIPPED when
     * is_ibd=true (zclassicd's ContextualCheckTransaction short-circuit,
     * main.cpp:941). Height 100 is pre-Overwinter on mainnet, so an
     * overwintered tx is structurally invalid there. */
    {
        const struct chain_params *p = chain_params_get();
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 99;
        prev.nTime = CG_BASE_TIME - 100;

        struct block b;
        CG_CHECK("ibd: build overwinter-shaped block",
                 cg_make_rule_block(&b, 100, CG_BASE_TIME, true, false, 0));

        struct validation_state st;
        validation_state_init(&st);
        bool ok = contextual_check_block(&b, &st, p, &prev, false);
        CG_CHECK("ibd: is_ibd=false rejects tx-overwinter-not-active",
                 !ok && strcmp(st.reject_reason,
                               "tx-overwinter-not-active") == 0);

        validation_state_init(&st);
        ok = contextual_check_block(&b, &st, p, &prev, true);
        CG_CHECK("ibd: is_ibd=true skips per-tx rules (accepts)", ok);
        block_free(&b);
    }

    /* (10) BIP34 is NOT IBD-gated: wrong coinbase height rejects even
     * with is_ibd=true. */
    {
        const struct chain_params *p = chain_params_get();
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 99;
        prev.nTime = CG_BASE_TIME - 100;

        struct block b;
        CG_CHECK("ibd_bip34: build wrong-cb block",
                 cg_make_rule_block(&b, 100, CG_BASE_TIME, false, true, 0));

        struct validation_state st;
        validation_state_init(&st);
        bool ok = contextual_check_block(&b, &st, p, &prev, true);
        CG_CHECK("ibd_bip34: rejects bad-cb-height under IBD",
                 !ok && strcmp(st.reject_reason, "bad-cb-height") == 0);
        block_free(&b);
    }

    /* (11) finality is NOT IBD-gated: non-final tx rejects even with
     * is_ibd=true. */
    {
        const struct chain_params *p = chain_params_get();
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 99;
        prev.nTime = CG_BASE_TIME - 100;

        struct block b;
        CG_CHECK("ibd_final: build non-final block",
                 cg_make_rule_block(&b, 100, CG_BASE_TIME, false, false,
                                    CG_BASE_TIME + 100));

        struct validation_state st;
        validation_state_init(&st);
        bool ok = contextual_check_block(&b, &st, p, &prev, true);
        CG_CHECK("ibd_final: rejects bad-txns-nonfinal under IBD",
                 !ok && strcmp(st.reject_reason, "bad-txns-nonfinal") == 0);
        block_free(&b);
    }

    printf("script_validate contextual gate tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
