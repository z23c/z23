/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reducer_stage_fuzz — adversarial fuzz / invariant coverage for the
 * eight Wave-S reducer stages (the heart of the system).
 *
 *   engine/jobs/src/{header_admit,validate_headers,body_fetch,body_persist,
 *                 script_validate,proof_validate,utxo_apply,tip_finalize}_stage.c
 *
 * The promise this test defends
 * -----------------------------
 * A reducer stage is a Job: a cursor-stamped step that consumes the next
 * durable unit and returns exactly one of four typed outcomes
 * (JOB_ADVANCED / JOB_BLOCKED / JOB_IDLE / JOB_FATAL — see jobs/job.h).
 * The "no silent halt" architecture mandate means a stage must NEVER:
 *   - crash, read OOB, or hang on malformed input;
 *   - return a value outside the four-state enum;
 *   - silently ADVANCE its cursor on garbage;
 *   - move its cursor forward on a rejected step.
 *
 * These are exactly the runtime complement of the E8 "no silent ready"
 * static gate: that gate proves the code can't *compile* a silent-success
 * path; this proves the stages don't silently succeed at *runtime* on a
 * battery of adversarial inputs.
 *
 * What "adversarial input" means for a reducer stage
 * --------------------------------------------------
 * Every stage reads from two surfaces:
 *   (a) the in-memory active chain (block_index entries: hashes, heights,
 *       version, bits, status flags, pprev links); and
 *   (b) progress.kv (its own persisted cursor + the upstream stage's
 *       cursor and *_log rows).
 * The fuzz mutates BOTH surfaces:
 *   - cursors: ahead of tip, behind genesis, the int32 boundary, the
 *     uint64 wraparound region (huge values that a stage casts to int);
 *   - log rows: missing, duplicated, out-of-order, ok=garbage, wrong hash;
 *   - block_index: NULL phashBlock, NULL pprev mid-chain, BLOCK_HAVE_DATA
 *     cleared, version/bits zeroed, height scrambled;
 *   - injected readers (for the downstream stages that expose a reader
 *     seam): return truncated/oversized/zero-tx/garbage-merkle bodies.
 *
 * Determinism / seed-replay
 * -------------------------
 * Every fuzz iteration's adversarial choices come from a splitmix64 RNG
 * seeded from a single base seed. The base seed is printed once at the
 * top; on ANY assertion failure the per-iteration sub-seed is printed so
 * the exact case can be replayed by re-running with that seed. (Bugs
 * become 64-bit seeds — the project's core principle.)
 *
 * Stages driven in isolation
 * ---------------------------
 * All eight stages are driven through their public *_stage_step_once /
 * _drain entry points against synthetic fixtures, the same way the
 * per-stage unit tests do. header_admit reads the live active chain;
 * validate_headers..tip_finalize read upstream cursor + log rows that we
 * stamp directly. The downstream stages that expose a reader/validator
 * seam get an adversarial injector. tip_finalize's "live chain advanced"
 * precondition genuinely needs the in-memory chain to be wired the way a
 * booted pipeline wires it; we drive what we can in isolation and document
 * the boot-boundary parts inline (see TIP_FINALIZE section).
 *
 * Teeth
 * -----
 * The invariant checker `expect_typed_no_silent_advance()` is mutation-
 * tested at the bottom (the `self_check` block): we feed it a fabricated
 * "stage advanced but cursor didn't move" observation and confirm the
 * checker flags it. If the checker had no teeth, that block would fail.
 */

#include "test/test_core.h"
#include "bloom/merkle.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "jobs/job.h"
#include "jobs/header_admit_stage.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── harness scaffolding ───────────────────────────────────────────── */

static int g_failures;
static uint64_t g_iter_seed;  /* sub-seed of the iteration in flight */

#define RF_CHECK(name, expr) do {                                       \
    if ((expr)) {                                                       \
        /* quiet on success to keep the suite log readable */           \
    } else {                                                            \
        printf("reducer_fuzz: %s... FAIL  (replay seed=0x%016llx)\n",   \
               (name), (unsigned long long)g_iter_seed);                \
        g_failures++;                                                   \
    }                                                                   \
} while (0)

/* splitmix64 — tiny, deterministic, well-distributed. Self-contained so
 * the test has no dependency on global RNG state (and so the seed is the
 * single source of truth for replay). */
static uint64_t sm_next(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint32_t sm_u32(uint64_t *s) { return (uint32_t)(sm_next(s) >> 32); }
static int sm_range(uint64_t *s, int lo, int hi)  /* inclusive */
{
    if (hi <= lo) return lo;
    return lo + (int)(sm_u32(s) % (uint32_t)(hi - lo + 1));
}

/* rf_tmpdir folds the per-iteration suffix into a single tag, then
 * delegates path-build + stale-cleanup + mkdir to the shared helper. */
static void rf_tmpdir(char *buf, size_t n, const char *tag, int i)
{
    char t[64];
    snprintf(t, sizeof(t), "%s_%d", tag, i);
    test_make_tmpdir(buf, n, "reducer_fuzz", t);
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

/* ── the central invariant checker (mutation-tested below) ─────────────
 *
 * Given an observation of one step (its result, and the cursor before
 * and after), decide whether the stage upheld the Job contract.
 *
 * Returns true iff the observation is contract-conformant:
 *   - result is one of the four enum values (never out-of-band);
 *   - on JOB_ADVANCED the cursor moved STRICTLY forward;
 *   - on JOB_BLOCKED / JOB_IDLE / JOB_FATAL the cursor did NOT move.
 *
 * The "non-empty typed reason" half of the invariant for BLOCKED/FATAL is
 * enforced structurally by the stage primitive itself (stage_run_once
 * coerces a BLOCKED-with-empty-id to JOB_FATAL, and a claimed-ADVANCE that
 * fails to move the cursor to JOB_FATAL — see platform/modules/util/src/stage.c). So an
 * observed JOB_BLOCKED here is guaranteed to have carried a non-empty
 * blocker id; we assert the cursor-stillness that the contract layers on
 * top. */
static bool obs_conformant(job_result_t r,
                           uint64_t cursor_before,
                           uint64_t cursor_after)
{
    switch (r) {
    case JOB_ADVANCED:
        return cursor_after > cursor_before;       /* moved forward */
    case JOB_BLOCKED:
    case JOB_IDLE:
    case JOB_FATAL:
        return cursor_after == cursor_before;      /* did not move */
    default:
        return false;                              /* out-of-band enum */
    }
}

/* Read the DURABLY persisted cursor for `name` straight from
 * stage_cursor. We measure the invariant against the persisted value, not
 * the stage's in-memory accessor: the in-memory mirror lags the persisted
 * value until the first stage_run_once syncs it, so an accessor-based
 * before/after would spuriously look like "the cursor moved" on the very
 * first step after we stamp an adversarial cursor directly into the
 * table. The durable cursor is the one the saga contract is about — it is
 * what survives a crash and what the next boot replays from. */
static uint64_t persisted_cursor(const char *name)
{
    sqlite3 *db = progress_store_db();
    if (!db) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT cursor FROM stage_cursor WHERE name = ?",
        -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    uint64_t out = 0;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-direct
        out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return out;
}

/* Run one step of an arbitrary stage and assert the invariant. The
 * function pointers let us treat all eight stages uniformly; `name` is the
 * stage's stage_cursor key so we can read its durable cursor. */
static void expect_typed_no_silent_advance(
        const char *label,
        const char *name,
        job_result_t (*step)(void))
{
    uint64_t before = persisted_cursor(name);
    job_result_t r = step();           /* must not crash / hang / UB */
    uint64_t after  = persisted_cursor(name);

    /* result is within the enum */
    RF_CHECK(label, r == JOB_ADVANCED || r == JOB_BLOCKED ||
                    r == JOB_IDLE || r == JOB_FATAL);
    /* typed outcome respects the cursor contract */
    RF_CHECK(label, obs_conformant(r, before, after));
}

/* ── synthetic chain (shared shape with the per-stage unit tests) ─────── */

struct synth {
    struct block_index *blocks;
    struct uint256     *hashes;
    struct block       *bodies;   /* only built for body-reading stages */
    int                 n;
};

static bool make_body(struct block *b, int h)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700000000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 1;
    b->vtx = zcl_calloc(1, sizeof(struct transaction), "rf_tx");
    if (!b->vtx) return false;
    transaction_init(&b->vtx[0]);
    b->vtx[0].hash.data[0] = (uint8_t)h;
    b->vtx[0].hash.data[1] = 0x5b;
    b->header.hashMerkleRoot = compute_merkle_root(&b->vtx[0].hash, 1);
    return true;
}

static bool synth_build(struct synth *sc, int n, bool with_bodies)
{
    memset(sc, 0, sizeof(*sc));
    if (n <= 0) n = 1;
    sc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index), "rf_blk");
    sc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "rf_hash");
    if (with_bodies)
        sc->bodies = zcl_calloc((size_t)n, sizeof(struct block), "rf_body");
    if (!sc->blocks || !sc->hashes || (with_bodies && !sc->bodies)) {
        free(sc->blocks); free(sc->hashes); free(sc->bodies);
        memset(sc, 0, sizeof(*sc));
        return false;
    }
    for (int i = 0; i < n; i++) {
        block_index_init(&sc->blocks[i]);
        if (with_bodies) {
            if (!make_body(&sc->bodies[i], i)) return false;
            block_header_get_hash(&sc->bodies[i].header, &sc->hashes[i]);
            sc->blocks[i].hashMerkleRoot = sc->bodies[i].header.hashMerkleRoot;
            sc->blocks[i].nVersion = sc->bodies[i].header.nVersion;
            sc->blocks[i].nTime    = sc->bodies[i].header.nTime;
            sc->blocks[i].nBits    = sc->bodies[i].header.nBits;
        } else {
            sc->hashes[i].data[0] = (uint8_t)(i & 0xFF);
            sc->hashes[i].data[1] = (uint8_t)((i >> 8) & 0xFF);
            sc->hashes[i].data[2] = 0xAB;
        }
        sc->blocks[i].phashBlock = &sc->hashes[i];
        sc->blocks[i].nHeight = i;
        sc->blocks[i].nStatus = BLOCK_HAVE_DATA;
        if (i > 0) sc->blocks[i].pprev = &sc->blocks[i - 1];
    }
    sc->n = n;
    return true;
}

static void synth_free(struct synth *sc)
{
    if (sc->bodies) {
        for (int i = 0; i < sc->n; i++) block_free(&sc->bodies[i]);
    }
    free(sc->blocks); free(sc->hashes); free(sc->bodies);
    memset(sc, 0, sizeof(*sc));
}

/* Apply a random structural corruption to the chain. Returns a label of
 * what was done (for diagnostics). Never frees anything — the corruptions
 * stay within the allocated arrays so the stage must defend, not the
 * fixture. */
static const char *corrupt_chain(struct synth *sc, uint64_t *rng)
{
    if (sc->n <= 0) return "empty";
    int which = sm_range(rng, 0, 6);
    int h = sm_range(rng, 0, sc->n - 1);
    switch (which) {
    case 0:
        sc->blocks[h].phashBlock = NULL;            /* NULL hash ptr */
        return "null_phashBlock";
    case 1:
        if (h > 0) sc->blocks[h].pprev = NULL;      /* broken prev link */
        return "null_pprev_midchain";
    case 2:
        sc->blocks[h].nStatus &= ~(uint32_t)BLOCK_HAVE_DATA; /* no body */
        return "no_have_data";
    case 3:
        sc->blocks[h].nVersion = 0;                 /* bad version */
        sc->blocks[h].nBits = 0;
        return "zero_version_bits";
    case 4:
        sc->blocks[h].nHeight = sm_range(rng, -5, 1 << 28); /* scrambled */
        return "scrambled_height";
    case 5:
        if (sc->hashes) sc->hashes[h].data[31] ^= 0xFF; /* hash mutation */
        return "hash_bitflip";
    default:
        return "none";
    }
}

/* ── upstream-state stamping (garbage cursors + log rows) ─────────────── */

/* Pick an adversarial cursor value covering the dangerous regions:
 *   ahead of tip, exactly tip, behind genesis (0), int32 max, and the
 *   uint64 wraparound region that a stage truncates to a negative int. */
static uint64_t adversarial_cursor(uint64_t *rng, int chain_n)
{
    switch (sm_range(rng, 0, 6)) {
    case 0: return 0;                                   /* genesis floor */
    case 1: return (uint64_t)chain_n;                   /* exactly at tip */
    case 2: return (uint64_t)chain_n + (uint64_t)sm_range(rng, 1, 1000);
    case 3: return (uint64_t)INT32_MAX;                 /* int32 boundary */
    case 4: return (uint64_t)INT32_MAX + 1;             /* int32 overflow */
    case 5: return UINT64_MAX - (uint64_t)sm_range(rng, 0, 8); /* wrap */
    default: return (uint64_t)sm_range(rng, 0, chain_n + 4);
    }
}

static void stamp_cursor(sqlite3 *db, const char *name, uint64_t v)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at)"
        " VALUES(?,?,0)", -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)v);
    sqlite3_step(st);  // raw-sql-ok:test-direct
    sqlite3_finalize(st);
}

/* Stamp an upstream log table with adversarial rows: garbage `ok`,
 * missing heights, out-of-order, duplicate-then-replace. The exact column
 * set differs per table; the caller passes the CREATE + a parametrised
 * INSERT that binds (height, ok). */
static void stamp_upstream_log(sqlite3 *db, uint64_t *rng,
                               const char *create_sql,
                               const char *insert_sql,
                               int n)
{
    exec_sql(db, create_sql);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, insert_sql, -1, &st, NULL) != SQLITE_OK)
        return;
    for (int h = 0; h < n; h++) {
        /* Randomly drop some rows entirely (missing-row adversary). */
        if (sm_range(rng, 0, 4) == 0) continue;
        /* Garbage ok: not just 0/1 but negative + large values. */
        int ok;
        switch (sm_range(rng, 0, 3)) {
        case 0:  ok = 1; break;
        case 1:  ok = 0; break;
        case 2:  ok = -7; break;
        default: ok = 999; break;
        }
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_int(st, 2, ok);
        sqlite3_step(st);  // raw-sql-ok:test-direct
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);
}

/* ── adversarial injected readers/validators for downstream stages ────── */

static bool adv_vh_validator(const struct block_index *bi, const char *datadir,
                             char *out_reason, size_t out_reason_size,
                             void *user)
{
    (void)bi; (void)datadir;
    uint64_t *rng = user;
    /* Randomly pass / fail-with-reason / fail-empty-reason. A failing
     * validator MUST write a reason per its contract; we sometimes leave
     * it empty to confirm the stage still produces a typed outcome. */
    int pick = rng ? sm_range(rng, 0, 2) : 0;
    if (pick == 0) {
        if (out_reason && out_reason_size) out_reason[0] = 0;
        return true;
    }
    if (pick == 1 && out_reason && out_reason_size)
        snprintf(out_reason, out_reason_size, "adv-injected-fail");
    else if (out_reason && out_reason_size)
        out_reason[0] = 0;  /* empty reason on a failure (adversarial) */
    return false;
}

/* Body reader that returns a grab-bag of malformed bodies. Shared shape
 * across body_persist / script_validate / proof_validate / utxo_apply. */
static bool adv_body_reader(struct block *out, const struct block_index *bi,
                            const char *datadir, void *user)
{
    (void)datadir;
    uint64_t *rng = user;
    if (!out || !bi) return false;
    int pick = rng ? sm_range(rng, 0, 4) : 0;
    switch (pick) {
    case 0:
        return false;                       /* read failure */
    case 1:
        block_init(out);                    /* zero-tx body */
        out->num_vtx = 0;
        return true;
    case 2: {
        block_init(out);                    /* body with garbage merkle */
        out->header.nVersion = 4;
        out->header.nBits = 0x1f07ffff;
        out->num_vtx = 1;
        out->vtx = zcl_calloc(1, sizeof(struct transaction), "rf_advtx");
        if (!out->vtx) return false;
        transaction_init(&out->vtx[0]);
        out->vtx[0].hash.data[0] = 0xEE;
        memset(&out->header.hashMerkleRoot, 0xAB,
               sizeof(out->header.hashMerkleRoot));
        return true;
    }
    case 3: {
        block_init(out);                    /* oversized vtx claim */
        out->header.nVersion = 4;
        out->num_vtx = 1;
        out->vtx = zcl_calloc(1, sizeof(struct transaction), "rf_advtx2");
        if (!out->vtx) return false;
        transaction_init(&out->vtx[0]);
        return true;
    }
    default:
        block_init(out);                    /* header-only, no version */
        out->num_vtx = 0;
        return true;
    }
}

static bool adv_prevout(const struct outpoint *prevout, struct tx_out *out,
                        void *user)
{
    (void)prevout;
    uint64_t *rng = user;
    if (!out) return false;
    if (rng && sm_range(rng, 0, 1) == 0) return false; /* unknown prevout */
    out->value = (int64_t)sm_next(rng);                /* garbage value */
    return true;
}

static bool adv_tx_verify(const struct transaction *tx, int height,
                          struct proof_validate_tx_report *out, void *user)
{
    (void)tx; (void)height;
    uint64_t *rng = user;
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    int pick = rng ? sm_range(rng, 0, 2) : 0;
    if (pick == 0) { out->ok = true; return true; }
    if (pick == 1) { out->ok = false;
                     out->first_failure_proof_type = "adv"; return false; }
    out->internal_error = true; out->ok = false; return false;
}

static bool adv_utxo_lookup(const struct uint256 *txid, uint32_t vout,
                            struct utxo_apply_lookup *out, void *user)
{
    (void)txid; (void)vout;
    uint64_t *rng = user;
    if (!out) return false;
    if (rng && sm_range(rng, 0, 1) == 0) { out->found = false; out->value = 0;
                                           return true; }
    out->found = true;
    out->value = (int64_t)sm_next(rng);     /* arbitrary, may overflow sums */
    return true;
}

static bool adv_utxo_count(int height_after, int64_t *out_count, void *user)
{
    (void)height_after;
    uint64_t *rng = user;
    if (!out_count) return false;
    *out_count = (int64_t)sm_next(rng);
    return true;
}

/* ── per-stage fuzz drivers ───────────────────────────────────────────── */

/* HEADER_ADMIT — reads the live active chain only. Adversary: corrupt the
 * chain structure and stamp a garbage own-cursor, then step. */
static void fuzz_header_admit(uint64_t *rng, int iter)
{
    char dir[256];
    rf_tmpdir(dir, sizeof(dir), "ha", iter);
    if (!progress_store_open(dir)) { test_cleanup_tmpdir(dir); return; }

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    int n = sm_range(rng, 1, 12);
    struct synth sc;
    if (!synth_build(&sc, n, false)) {
        active_chain_free(&ms.chain_active);
        progress_store_close(); test_cleanup_tmpdir(dir); return;
    }
    active_chain_move_window_tip(&ms.chain_active, &sc.blocks[n - 1]);

    if (header_admit_stage_init(&ms)) {
        /* Stamp an adversarial own-cursor BEFORE corrupting, so the stage
         * loads it on the next run. */
        stamp_cursor(progress_store_db(), "header_admit",
                     adversarial_cursor(rng, n));
        corrupt_chain(&sc, rng);
        for (int s = 0; s < 6; s++)
            expect_typed_no_silent_advance("header_admit.step",
                "header_admit", header_admit_stage_step_once);
        header_admit_stage_shutdown();
    }

    active_chain_free(&ms.chain_active);
    synth_free(&sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

/* VALIDATE_HEADERS — reads header_admit cursor + header_admit_log, runs an
 * injected validator. Adversary: garbage header_admit cursor + log rows +
 * a validator that randomly fails (with and without a reason). */
static void fuzz_validate_headers(uint64_t *rng, int iter)
{
    char dir[256];
    rf_tmpdir(dir, sizeof(dir), "vh", iter);
    if (!progress_store_open(dir)) { test_cleanup_tmpdir(dir); return; }

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    int n = sm_range(rng, 1, 12);
    struct synth sc;
    if (!synth_build(&sc, n, false)) {
        active_chain_free(&ms.chain_active);
        progress_store_close(); test_cleanup_tmpdir(dir); return;
    }
    active_chain_move_window_tip(&ms.chain_active, &sc.blocks[n - 1]);

    /* header_admit must be inited first (validate_headers reads its cursor
     * + log). Then stamp garbage. */
    bool ha_ok = header_admit_stage_init(&ms);
    if (ha_ok && validate_headers_stage_init(&ms)) {
        sqlite3 *db = progress_store_db();
        /* Stamp an adversarial header_admit cursor + log of garbage rows. */
        stamp_cursor(db, "header_admit", adversarial_cursor(rng, n));
        stamp_upstream_log(db, rng,
            "CREATE TABLE IF NOT EXISTS header_admit_log ("
            " height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
            " parent_hash BLOB, admitted_at INTEGER NOT NULL)",
            "INSERT OR REPLACE INTO header_admit_log"
            " (height,hash,parent_hash,admitted_at)"
            " VALUES(?, zeroblob(32), NULL, ?)",  /* 2nd bind = ok-slot reuse */
            n);
        validate_headers_stage_set_validator(adv_vh_validator, rng);
        corrupt_chain(&sc, rng);
        for (int s = 0; s < 6; s++)
            expect_typed_no_silent_advance("validate_headers.step",
                "validate_headers", validate_headers_stage_step_once);
    }
    validate_headers_stage_shutdown();
    if (ha_ok) header_admit_stage_shutdown();

    active_chain_free(&ms.chain_active);
    synth_free(&sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

/* BODY_FETCH — reads validate_headers cursor + validate_headers_log, plus
 * the live chain's BLOCK_HAVE_DATA flag. No injectable seam; adversary is
 * the garbage upstream + corrupt chain. */
static void fuzz_body_fetch(uint64_t *rng, int iter)
{
    char dir[256];
    rf_tmpdir(dir, sizeof(dir), "bf", iter);
    if (!progress_store_open(dir)) { test_cleanup_tmpdir(dir); return; }

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    int n = sm_range(rng, 1, 12);
    struct synth sc;
    if (!synth_build(&sc, n, false)) {
        active_chain_free(&ms.chain_active);
        progress_store_close(); test_cleanup_tmpdir(dir); return;
    }
    active_chain_move_window_tip(&ms.chain_active, &sc.blocks[n - 1]);

    if (body_fetch_stage_init(&ms)) {
        sqlite3 *db = progress_store_db();
        stamp_cursor(db, "validate_headers", adversarial_cursor(rng, n));
        stamp_cursor(db, "body_fetch", adversarial_cursor(rng, n));
        stamp_upstream_log(db, rng,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            " height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
            " ok INTEGER NOT NULL, fail_reason TEXT,"
            " validated_at INTEGER NOT NULL)",
            "INSERT OR REPLACE INTO validate_headers_log"
            " (height,hash,ok,validated_at) VALUES(?, zeroblob(32), ?, 1)",
            n);
        corrupt_chain(&sc, rng);
        for (int s = 0; s < 6; s++)
            expect_typed_no_silent_advance("body_fetch.step",
                "body_fetch", body_fetch_stage_step_once);
        body_fetch_stage_shutdown();
    }

    active_chain_free(&ms.chain_active);
    synth_free(&sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

/* Shared driver for the four body-reading downstream stages. The struct
 * captures the per-stage upstream table + insert + init/step/cursor and
 * the injector wiring closure. */
struct down_spec {
    const char *label;
    const char *up_cursor_name;
    const char *create_sql;
    const char *insert_sql;     /* binds (height, ok) */
    bool (*init)(struct main_state *);
    job_result_t (*step)(void);
    uint64_t (*cursor)(void);
    void (*shutdown)(void);
    void (*wire)(uint64_t *rng); /* installs adversarial injectors */
};

static void wire_body_persist(uint64_t *rng)
{ body_persist_stage_set_reader(adv_body_reader, rng); }

static void wire_script_validate(uint64_t *rng)
{
    script_validate_stage_set_reader(adv_body_reader, rng);
    script_validate_stage_set_prevout_resolver(adv_prevout, rng);
}

static void wire_proof_validate(uint64_t *rng)
{
    proof_validate_stage_set_reader(adv_body_reader, rng);
    proof_validate_stage_set_tx_verifier(adv_tx_verify, rng);
}

static void wire_utxo_apply(uint64_t *rng)
{
    utxo_apply_stage_set_reader(adv_body_reader, rng);
    utxo_apply_stage_set_lookup(adv_utxo_lookup, rng);
}

static void fuzz_downstream(uint64_t *rng, int iter, const struct down_spec *sp)
{
    char dir[256];
    rf_tmpdir(dir, sizeof(dir), sp->label, iter);
    if (!progress_store_open(dir)) { test_cleanup_tmpdir(dir); return; }

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    int n = sm_range(rng, 1, 12);
    struct synth sc;
    if (!synth_build(&sc, n, true)) {     /* bodies: stages read them */
        active_chain_free(&ms.chain_active);
        progress_store_close(); test_cleanup_tmpdir(dir); return;
    }
    active_chain_move_window_tip(&ms.chain_active, &sc.blocks[n - 1]);

    if (sp->init(&ms)) {
        sqlite3 *db = progress_store_db();
        stamp_cursor(db, sp->up_cursor_name, adversarial_cursor(rng, n));
        stamp_cursor(db, sp->label, adversarial_cursor(rng, n));
        stamp_upstream_log(db, rng, sp->create_sql, sp->insert_sql, n);
        if (sp->wire) sp->wire(rng);
        corrupt_chain(&sc, rng);
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "%s.step", sp->label);
        for (int s = 0; s < 6; s++)
            expect_typed_no_silent_advance(lbl, sp->label, sp->step);
        sp->shutdown();
    } else {
        sp->shutdown();   /* idempotent; clears any partial wiring */
    }

    active_chain_free(&ms.chain_active);
    synth_free(&sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

/* TIP_FINALIZE — reads utxo_apply cursor + utxo_apply_log, AND has a
 * genuine "live chain advanced to the next active tip" precondition that
 * a fully booted pipeline satisfies by wiring the in-memory active chain
 * + block work. We CAN drive it in isolation against a garbage upstream
 * with an injected utxo-counter; what we DON'T reproduce in isolation is
 * the cross-subsystem chain-work / active-tip handoff that only exists
 * once boot_services has wired the coordinator. In isolation the stage
 * legitimately reports IDLE/BLOCKED on the missing precondition — which
 * is itself a typed, non-silent outcome, so the invariant still holds.
 * (Boot-boundary part documented; not faked.) */
static void fuzz_tip_finalize(uint64_t *rng, int iter)
{
    char dir[256];
    rf_tmpdir(dir, sizeof(dir), "tf", iter);
    if (!progress_store_open(dir)) { test_cleanup_tmpdir(dir); return; }

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    int n = sm_range(rng, 1, 12);
    struct synth sc;
    if (!synth_build(&sc, n, false)) {
        active_chain_free(&ms.chain_active);
        progress_store_close(); test_cleanup_tmpdir(dir); return;
    }
    active_chain_move_window_tip(&ms.chain_active, &sc.blocks[n - 1]);

    if (tip_finalize_stage_init(&ms)) {
        sqlite3 *db = progress_store_db();
        stamp_cursor(db, "utxo_apply", adversarial_cursor(rng, n));
        stamp_cursor(db, "tip_finalize", adversarial_cursor(rng, n));
        stamp_upstream_log(db, rng,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
            " ok INTEGER NOT NULL, spent_count INTEGER NOT NULL,"
            " added_count INTEGER NOT NULL, total_value_delta INTEGER NOT NULL,"
            " first_failure_kind TEXT, first_failure_detail BLOB,"
            " applied_at INTEGER NOT NULL)",
            "INSERT OR REPLACE INTO utxo_apply_log"
            " (height,status,ok,spent_count,added_count,total_value_delta,"
            "  applied_at) VALUES(?, 'verified', ?, 1, 2, 1, 1)",
            n);
        tip_finalize_stage_set_utxo_counter(adv_utxo_count, rng);
        corrupt_chain(&sc, rng);
        for (int s = 0; s < 6; s++)
            expect_typed_no_silent_advance("tip_finalize.step",
                "tip_finalize", tip_finalize_stage_step_once);
        tip_finalize_stage_shutdown();
    }

    active_chain_free(&ms.chain_active);
    synth_free(&sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

/* ── entry point ──────────────────────────────────────────────────────── */

int test_reducer_stage_fuzz(void)
{
    printf("\n=== reducer_stage_fuzz tests (8 Wave-S stages) ===\n");
    g_failures = 0;

    blocker_module_init();

    /* Base seed: env override for replay, else a fixed default so the
     * suite run is deterministic. Print it so any CI failure is replayable
     * by exporting REDUCER_FUZZ_SEED to the value shown. */
    uint64_t base_seed = 0xC0FFEE123456789ULL;
    const char *env = getenv("REDUCER_FUZZ_SEED");
    if (env && *env) base_seed = strtoull(env, NULL, 0);
    printf("reducer_fuzz: base_seed=0x%016llx (set REDUCER_FUZZ_SEED to replay)\n",
           (unsigned long long)base_seed);

    /* ── teeth: mutation-test the invariant checker itself ──────────────
     * If obs_conformant had no teeth this block fails the suite. */
    {
        /* A claimed advance that did NOT move the cursor must be flagged. */
        RF_CHECK("self_check: ADVANCED-without-move is flagged",
                 obs_conformant(JOB_ADVANCED, 5, 5) == false);
        /* A claimed advance that moved BACKWARD must be flagged. */
        RF_CHECK("self_check: ADVANCED-backward is flagged",
                 obs_conformant(JOB_ADVANCED, 5, 4) == false);
        /* An IDLE/BLOCKED/FATAL that moved the cursor must be flagged. */
        RF_CHECK("self_check: IDLE-that-moved is flagged",
                 obs_conformant(JOB_IDLE, 5, 6) == false);
        RF_CHECK("self_check: BLOCKED-that-moved is flagged",
                 obs_conformant(JOB_BLOCKED, 5, 6) == false);
        RF_CHECK("self_check: FATAL-that-moved is flagged",
                 obs_conformant(JOB_FATAL, 5, 6) == false);
        /* An out-of-band enum value must be flagged. */
        RF_CHECK("self_check: out-of-band result is flagged",
                 obs_conformant((job_result_t)42, 5, 5) == false);
        /* Conformant cases must pass. */
        RF_CHECK("self_check: legit advance passes",
                 obs_conformant(JOB_ADVANCED, 5, 6) == true);
        RF_CHECK("self_check: legit idle passes",
                 obs_conformant(JOB_IDLE, 5, 5) == true);
    }

    /* Bounded iteration count — kept small so the whole battery runs in a
     * fraction of a second. Each iteration touches all eight stages with
     * fresh per-stage sub-seeds derived from the base. */
    const int ITERS = 24;

    const struct down_spec body_persist_spec = {
        .label = "body_persist", .up_cursor_name = "body_fetch",
        .create_sql =
            "CREATE TABLE IF NOT EXISTS body_fetch_log ("
            " height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
            " source TEXT NOT NULL, bytes INTEGER NOT NULL DEFAULT 0,"
            " fetched_at INTEGER NOT NULL, ok INTEGER NOT NULL,"
            " fail_reason TEXT)",
        .insert_sql =
            "INSERT OR REPLACE INTO body_fetch_log"
            " (height,hash,source,bytes,fetched_at,ok,fail_reason)"
            " VALUES(?, zeroblob(32), 'disk', 0, 1, ?, NULL)",
        .init = body_persist_stage_init,
        .step = body_persist_stage_step_once,
        .cursor = body_persist_stage_cursor,
        .shutdown = body_persist_stage_shutdown,
        .wire = wire_body_persist,
    };
    const struct down_spec script_validate_spec = {
        .label = "script_validate", .up_cursor_name = "body_persist",
        .create_sql =
            "CREATE TABLE IF NOT EXISTS body_persist_log ("
            " height INTEGER PRIMARY KEY, source TEXT NOT NULL,"
            " ok INTEGER NOT NULL, persisted_at INTEGER NOT NULL)",
        .insert_sql =
            "INSERT OR REPLACE INTO body_persist_log"
            " (height,source,ok,persisted_at) VALUES(?, 'verified', ?, 1)",
        .init = script_validate_stage_init,
        .step = script_validate_stage_step_once,
        .cursor = script_validate_stage_cursor,
        .shutdown = script_validate_stage_shutdown,
        .wire = wire_script_validate,
    };
    const struct down_spec proof_validate_spec = {
        .label = "proof_validate", .up_cursor_name = "script_validate",
        .create_sql =
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
            " ok INTEGER NOT NULL, tx_count INTEGER NOT NULL,"
            " input_count INTEGER NOT NULL, first_failure_txid BLOB,"
            " first_failure_vin INTEGER, validated_at INTEGER NOT NULL)",
        .insert_sql =
            "INSERT OR REPLACE INTO script_validate_log"
            " (height,status,ok,tx_count,input_count,validated_at)"
            " VALUES(?, 'verified', ?, 1, 1, 1)",
        .init = proof_validate_stage_init,
        .step = proof_validate_stage_step_once,
        .cursor = proof_validate_stage_cursor,
        .shutdown = proof_validate_stage_shutdown,
        .wire = wire_proof_validate,
    };
    const struct down_spec utxo_apply_spec = {
        .label = "utxo_apply", .up_cursor_name = "proof_validate",
        .create_sql =
            "CREATE TABLE IF NOT EXISTS proof_validate_log ("
            " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
            " ok INTEGER NOT NULL, sapling_spends_total INTEGER NOT NULL,"
            " sapling_outputs_total INTEGER NOT NULL,"
            " sprout_joinsplits_total INTEGER NOT NULL,"
            " first_failure_txid BLOB, first_failure_proof_type TEXT,"
            " validated_at INTEGER NOT NULL)",
        .insert_sql =
            "INSERT OR REPLACE INTO proof_validate_log"
            " (height,status,ok,sapling_spends_total,sapling_outputs_total,"
            "  sprout_joinsplits_total,validated_at)"
            " VALUES(?, 'verified', ?, 0, 0, 0, 1)",
        .init = utxo_apply_stage_init,
        .step = utxo_apply_stage_step_once,
        .cursor = utxo_apply_stage_cursor,
        .shutdown = utxo_apply_stage_shutdown,
        .wire = wire_utxo_apply,
    };

    for (int i = 0; i < ITERS; i++) {
        /* Each stage gets its own sub-seed derived deterministically from
         * the base + iteration + stage index, so a failure prints the
         * exact sub-seed needed to reproduce that one case. */
        uint64_t mix = base_seed ^ ((uint64_t)i * 0x100000001B3ULL);

        g_iter_seed = mix ^ 0x01; uint64_t r0 = g_iter_seed;
        fuzz_header_admit(&r0, i);

        g_iter_seed = mix ^ 0x02; uint64_t r1 = g_iter_seed;
        fuzz_validate_headers(&r1, i);

        g_iter_seed = mix ^ 0x03; uint64_t r2 = g_iter_seed;
        fuzz_body_fetch(&r2, i);

        g_iter_seed = mix ^ 0x04; uint64_t r3 = g_iter_seed;
        fuzz_downstream(&r3, i, &body_persist_spec);

        g_iter_seed = mix ^ 0x05; uint64_t r4 = g_iter_seed;
        fuzz_downstream(&r4, i, &script_validate_spec);

        g_iter_seed = mix ^ 0x06; uint64_t r5 = g_iter_seed;
        fuzz_downstream(&r5, i, &proof_validate_spec);

        g_iter_seed = mix ^ 0x07; uint64_t r6 = g_iter_seed;
        fuzz_downstream(&r6, i, &utxo_apply_spec);

        g_iter_seed = mix ^ 0x08; uint64_t r7 = g_iter_seed;
        fuzz_tip_finalize(&r7, i);
    }

    printf("reducer_stage_fuzz: %d failures (%d iterations x 8 stages)\n",
           g_failures, ITERS);
    return g_failures;
}
