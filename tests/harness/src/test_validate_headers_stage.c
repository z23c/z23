/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the Wave S S-3 validate_headers stage
 * (engine/services/src/validate_headers_stage.c).
 *
 * Coverage:
 *   - init / shutdown round-trip; pool spins up + joins clean
 *   - happy: synthetic chain, header_admit drains fully, validate
 *     drains, log has N pass rows
 *   - batched: > VH_BATCH_SIZE; multi-step advance
 *   - header_admit floor: validate cursor never overruns admit cursor
 *   - injected failure: stub returns false for one height → ok=0 + reason
 *   - replay across progress_store reopen: cursor + log persist
 *   - pre-init guards */

#include "test/test_core.h"
#include "json/json.h"

#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "core/uint256.h"
#include "domain/consensus/verify.h"
#include "models/block.h"
#include "models/database.h"
#include "primitives/block.h"
#include "jobs/header_admit_stage.h"
#include "jobs/stage_repair.h"
#include "jobs/validate_headers_stage.h"
#include "storage/block_index_db.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "storage/txdb.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_logic.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Mirror of validate_headers_stage.c's private VH_MARK_FAIL_BLOCKER_ID (the
 * mark-failure typed blocker id) for the storm/repair assertions below. */
#define VH_MARK_FAIL_BLOCKER_ID_T "validate_headers.mark_failed"

#define VH_CHECK(name, expr) do { \
    printf("validate_headers: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

extern struct block_tree_db *g_active_block_tree;

/* Item 2 seam: inject the node.db handle used by the default validator's
 * SQLite solution fallback (declared in validate_headers_internal.h, a
 * sibling-private header). */
void validate_headers_validator_set_node_db(struct node_db *ndb);

/* Gap C seam (ZCL_TESTING-only, validate_headers_validator.c): override the
 * validator that validate_headers_stage_ensure_pass_record runs, so the focused
 * test can drive its pass/fail branches without a mined Equihash header.
 * Production always uses the real default validator. NULL restores the default. */
void validate_headers_ensure_set_validator_for_test(vh_validator_fn fn,
                                                    void *user);

/* W1 seam: the default header validator (PoW + Equihash from the ordered
 * source resolver) — declared in the sibling-private internal header. The
 * W1 resolver tests call it DIRECTLY to exercise the repair-table source
 * (the new first branch) without going through the stage. */
bool validate_headers_default_validator(const struct block_index *bi,
                                        const char *datadir,
                                        char *out_reason,
                                        size_t out_reason_size,
                                        void *user);

/* Insert one connected (status>=3) block row at `height` carrying
 * `sol`/`sol_len` as its Equihash solution. A NULL/0 solution exercises
 * the empty-column residual path. Returns true on save. */
static bool vh_db_put_block(struct node_db *ndb, int height,
                            const unsigned char *sol, size_t sol_len)
{
    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    memset(blk.hash, (uint8_t)(0x40 + (height & 0x3F)), 32);
    blk.hash[31] = (uint8_t)height;          /* keep hashes distinct */
    memset(blk.prev_hash, 0xBB, 32);
    memset(blk.merkle_root, 0xCC, 32);
    blk.height = height;
    blk.time = 1700000000;
    blk.bits = 0x1d00ffff;
    blk.status = 3;                          /* connected floor */
    blk.solution = (uint8_t *)sol;           /* may be NULL → empty col */
    blk.solution_len = sol_len;
    return db_block_save(ndb, &blk);
}

static bool vh_header_from_bi_solution(const struct block_index *bi,
                                       const unsigned char *sol,
                                       size_t sol_len,
                                       struct block_header *out)
{
    if (!bi || !out || (!sol && sol_len > 0) ||
        sol_len > MAX_SOLUTION_SIZE)
        return false;
    if (bi->nHeight > 0 && (!bi->pprev || !bi->pprev->phashBlock))
        return false;

    block_header_init(out);
    out->nVersion = bi->nVersion;
    if (bi->pprev && bi->pprev->phashBlock)
        out->hashPrevBlock = *bi->pprev->phashBlock;
    out->hashMerkleRoot = bi->hashMerkleRoot;
    out->hashFinalSaplingRoot = bi->hashFinalSaplingRoot;
    out->nTime = bi->nTime;
    out->nBits = bi->nBits;
    out->nNonce = bi->nNonce;
    if (sol_len > 0) {
        memcpy(out->nSolution, sol, sol_len);
        out->nSolutionSize = sol_len;
    }
    return true;
}

static bool vh_set_bi_hash_for_solution(struct block_index *bi,
                                        struct uint256 *hash_slot,
                                        const unsigned char *sol,
                                        size_t sol_len)
{
    struct block_header h;
    if (!vh_header_from_bi_solution(bi, sol, sol_len, &h))
        return false;
    block_header_get_hash(&h, hash_slot);
    bi->phashBlock = hash_slot;
    return true;
}

static bool vh_grind_pow(struct block_header *h, struct uint256 *hash_out,
                         uint32_t max_trials)
{
    const struct chain_params *cp = chain_params_get();
    if (!h || !hash_out || !cp)
        return false;
    for (uint32_t i = 0; i < max_trials; i++) {
        memcpy(h->nNonce.data, &i, sizeof(i));
        block_header_get_hash(h, hash_out);
        if (domain_consensus_verify_pow_solution(hash_out, h->nBits,
                                                 &cp->consensus).ok)
            return true;
    }
    return false;
}

static bool vh_db_put_header(struct node_db *ndb, int height,
                             const struct block_header *h,
                             const struct uint256 *hash)
{
    if (!ndb || !h || !hash)
        return false;
    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    memcpy(blk.hash, hash->data, 32);
    blk.height = height;
    memcpy(blk.prev_hash, h->hashPrevBlock.data, 32);
    blk.version = h->nVersion;
    memcpy(blk.merkle_root, h->hashMerkleRoot.data, 32);
    blk.time = h->nTime;
    blk.bits = h->nBits;
    memcpy(blk.nonce, h->nNonce.data, 32);
    blk.solution = (uint8_t *)h->nSolution;
    blk.solution_len = h->nSolutionSize;
    memset(blk.chain_work, 0x44, 32);
    blk.status = 3;
    blk.num_tx = 1;
    memcpy(blk.sapling_root, h->hashFinalSaplingRoot.data, 32);
    return db_block_save(ndb, &blk);
}

static bool vh_write_disk_block_for_index(const char *datadir,
                                          const struct block_header *h,
                                          struct block_index *bi,
                                          struct uint256 *hash_slot)
{
    const struct chain_params *cp = chain_params_get();
    if (!datadir || !h || !bi || !hash_slot || !cp)
        return false;

    struct block b;
    block_init(&b);
    b.header = *h;

    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    if (!write_block_to_disk(&b, &pos, datadir, cp->pchMessageStart))
        return false;

    block_header_get_hash(h, hash_slot);
    bi->phashBlock = hash_slot;
    bi->nStatus |= BLOCK_HAVE_DATA;
    bi->nFile = pos.nFile;
    bi->nDataPos = pos.nPos;
    return true;
}

static int mkdir_p_vh(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

struct synth_chain_vh {
    struct block_index *blocks;
    struct uint256     *hashes;
    int                 n;
};

static bool synth_chain_vh_build(struct synth_chain_vh *sc, int n)
{
    memset(sc, 0, sizeof(*sc));
    sc->blocks = zcl_malloc(
        (size_t)n * sizeof(struct block_index), "vh_blocks");
    if (!sc->blocks) return false;
    sc->hashes = zcl_malloc(
        (size_t)n * sizeof(struct uint256), "vh_hashes");
    if (!sc->hashes) { free(sc->blocks); return false; }
    for (int i = 0; i < n; i++) {
        block_index_init(&sc->blocks[i]);
        memset(&sc->hashes[i], 0, sizeof(struct uint256));
        sc->hashes[i].data[0] = (uint8_t)(i & 0xFF);
        sc->hashes[i].data[1] = (uint8_t)((i >> 8) & 0xFF);
        sc->hashes[i].data[2] = 0xC3;
        sc->blocks[i].phashBlock = &sc->hashes[i];
        sc->blocks[i].nHeight = i;
        sc->blocks[i].nVersion = 4;          /* MIN_BLOCK_VERSION */
        sc->blocks[i].nBits = 0x1f07ffff;    /* unused under stub */
        if (i > 0) sc->blocks[i].pprev = &sc->blocks[i - 1];
    }
    sc->n = n;
    return true;
}

static void synth_chain_vh_free(struct synth_chain_vh *sc)
{
    if (sc->blocks) {
        for (int i = 0; i < sc->n; i++) {
            free(sc->blocks[i].nSolution);
            sc->blocks[i].nSolution = NULL;
            sc->blocks[i].nSolutionSize = 0;
        }
    }
    free(sc->blocks);
    free(sc->hashes);
    memset(sc, 0, sizeof(*sc));
}

/* Stub validator that always passes. */
static bool stub_pass(const struct block_index *bi, const char *datadir,
                      char *out_reason, size_t out_reason_size,
                      void *user)
{
    (void)bi; (void)datadir; (void)user;
    if (out_reason && out_reason_size) out_reason[0] = 0;
    return true;
}

/* Stub validator that fails at a configurable height. */
struct fail_at_ctx {
    int fail_height;
    const char *reason;
    _Atomic int call_count;
};

static bool stub_fail_at(const struct block_index *bi, const char *datadir,
                          char *out_reason, size_t out_reason_size,
                          void *user)
{
    (void)datadir;
    struct fail_at_ctx *c = (struct fail_at_ctx *)user;
    atomic_fetch_add(&c->call_count, 1);
    if (bi && bi->nHeight == c->fail_height) {
        snprintf(out_reason, out_reason_size, "%s",
                 c->reason ? c->reason : "stub-injected-failure");
        return false;
    }
    if (out_reason && out_reason_size) out_reason[0] = 0;
    return true;
}

static int log_row_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM validate_headers_log",
        -1, &st, NULL) != SQLITE_OK) return -1;
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static bool log_row_at(sqlite3 *db, int height,
                       int *out_ok, char *out_reason, size_t reason_size)
{
    *out_ok = -1;
    if (out_reason && reason_size) out_reason[0] = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, fail_reason FROM validate_headers_log WHERE height=?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out_ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt && out_reason && reason_size)
            snprintf(out_reason, reason_size, "%s", (const char *)txt);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

/* True when `reason` is one of the "no real verified solution available"
 * markers — i.e. a verdict that did NOT reach the actual PoW/Equihash
 * verification. Asserting a reason is NOT in this set proves the resolved
 * bytes flowed into the identical validate_header_fields. */
static bool reason_is_pre_pow(const char *reason)
{
    return strcmp(reason, "no-header-solution") == 0 ||
           strcmp(reason, "no-header-solution-backfill-required") == 0 ||
           strcmp(reason, "disk-read-failed") == 0 ||
           strcmp(reason, "no-repair-store") == 0 ||
           strcmp(reason, "no-repair-header") == 0 ||
           strcmp(reason, "no-node-db-header") == 0 ||
           strcmp(reason, "header-source-hash-mismatch") == 0 ||
           strstr(reason, "-hash-mismatch") != NULL;
}

/* Insert a failed (ok=0) validate_headers_log row at `height` carrying
 * `hash` — used by the W1 T4 frontier-reach test to stage a failed
 * frontier row that the recheck path must rebind. */
static bool seed_failed_vh_row(sqlite3 *db, int height,
                               const struct uint256 *hash,
                               const char *reason)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log"
            "(height,hash,ok,fail_reason,validated_at) "
            "VALUES(?,?,0,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, reason, -1, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Force a stage_cursor row to `value` (test-only). Mirrors the stage's
 * own cursor table layout. */
static bool set_stage_cursor(sqlite3 *db, const char *name, int value)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, value);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool seed_repair_header_for_block(sqlite3 *db, struct block_index *bi,
                                         struct uint256 *hash_slot)
{
    if (!db || !bi || !bi->phashBlock || !hash_slot)
        return false;

    struct block_header h;
    block_header_init(&h);
    h.nVersion = 4;
    if (bi->pprev && bi->pprev->phashBlock)
        h.hashPrevBlock = *bi->pprev->phashBlock;
    h.hashMerkleRoot.data[0] = (uint8_t)bi->nHeight;
    h.hashMerkleRoot.data[1] = 0x55;
    h.hashFinalSaplingRoot.data[0] = (uint8_t)bi->nHeight;
    h.hashFinalSaplingRoot.data[1] = 0x66;
    h.nTime = 1700000000u + (uint32_t)bi->nHeight;
    h.nBits = 0x1f07ffff;
    h.nNonce.data[0] = (uint8_t)bi->nHeight;
    h.nNonce.data[1] = 0x77;
    h.nSolutionSize = 32;
    for (size_t i = 0; i < h.nSolutionSize; i++)
        h.nSolution[i] = (uint8_t)(0x80 + i + (size_t)bi->nHeight);

    struct uint256 hash;
    block_header_get_hash(&h, &hash);
    *hash_slot = hash;
    return stage_repair_header_solution_save(db, bi->nHeight, &hash, &h);
}

/* Build {progress_store + ms + synth_chain + S-2 init + S-3 init w/
 * injected validator}. The caller does the work and then runs the
 * teardown. Returns 0 on success, nonzero on partial failure (still
 * tear down whatever was set up). */
static int vh_setup(const char *tag, int n, vh_validator_fn fn, void *user,
                     char *dir_out, size_t dir_out_size,
                     struct main_state *ms,
                     struct synth_chain_vh *sc)
{
    test_fmt_tmpdir(dir_out, dir_out_size, "validate_headers", tag);
    mkdir_p_vh(dir_out);
    if (!progress_store_open(dir_out)) return 1;

    memset(ms, 0, sizeof(*ms));
    active_chain_init(&ms->chain_active);
    if (!synth_chain_vh_build(sc, n)) return 2;
    active_chain_move_window_tip(&ms->chain_active, &sc->blocks[n - 1]);

    if (!header_admit_stage_init(ms))  return 3;
    if (!validate_headers_stage_init(ms)) return 4;
    if (fn) validate_headers_stage_set_validator(fn, user);
    return 0;
}

static void vh_teardown(const char *dir, struct main_state *ms,
                         struct synth_chain_vh *sc)
{
    validate_headers_stage_shutdown();
    header_admit_stage_shutdown();
    active_chain_free(&ms->chain_active);
    synth_chain_vh_free(sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

int test_validate_headers_stage(void);
int test_validate_headers_stage(void)
{
    printf("\n=== validate_headers_stage tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* ── happy: 5 blocks, all pass under stub ──────────────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("happy: setup",
                 vh_setup("happy", 5, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);

        /* Drain S-2 fully so validate can advance. */
        VH_CHECK("happy: header_admit drains 5",
                 header_admit_stage_drain(100) == 5);

        int adv = validate_headers_stage_drain(100);
        VH_CHECK("happy: validate drains 5 (single batched step)",
                 adv == 1);  /* batch=8 covers 5 in one step */
        VH_CHECK("happy: cursor reaches 5",
                 validate_headers_stage_cursor() == 5);
        VH_CHECK("happy: passed_total == 5",
                 validate_headers_stage_passed_total() == 5);
        VH_CHECK("happy: failed_total == 0",
                 validate_headers_stage_failed_total() == 0);

        sqlite3 *db = progress_store_db();
        VH_CHECK("happy: log has 5 rows", log_row_count(db) == 5);
        for (int h = 0; h < 5; h++) {
            int ok = -1;
            log_row_at(db, h, &ok, NULL, 0);
            VH_CHECK("happy: row marks ok=1", ok == 1);
        }
        struct validate_headers_window_report rep;
        VH_CHECK("happy: window report available",
                 validate_headers_stage_window_report(0, 4, &rep));
        VH_CHECK("happy: window report complete",
                 rep.available && rep.complete &&
                 rep.expected_count == 5 && rep.checked_count == 5);
        VH_CHECK("happy: window report has no failures",
                 rep.failed_count == 0 && rep.first_failed_height == -1);

        /* Next step is IDLE — nothing to validate. */
        job_result_t r = validate_headers_stage_step_once();
        VH_CHECK("happy: next step IDLE", r == JOB_IDLE);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── batched: two full batches plus one partial ────────────────── */
    {
        const int batch_total = 2 * VH_BATCH_SIZE + 4;
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("batched: setup",
                 vh_setup("batched", batch_total, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        VH_CHECK("batched: header_admit drains all",
                 header_admit_stage_drain(batch_total + 1) == batch_total);

        VH_CHECK("batched: step 1 ADVANCED",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("batched: cursor at one batch after step 1",
                 validate_headers_stage_cursor() == VH_BATCH_SIZE);
        VH_CHECK("batched: step 2 ADVANCED",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("batched: cursor at two batches after step 2",
                 validate_headers_stage_cursor() == 2 * VH_BATCH_SIZE);
        VH_CHECK("batched: step 3 ADVANCED (final partial)",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("batched: cursor reaches final partial",
                 validate_headers_stage_cursor() == (uint64_t)batch_total);
        VH_CHECK("batched: passed_total reaches all",
                 validate_headers_stage_passed_total() == (uint64_t)batch_total);

        sqlite3 *db = progress_store_db();
        VH_CHECK("batched: log has every row",
                 log_row_count(db) == batch_total);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── header_admit floor: validate stays at or below S-2 cursor ── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("floor: setup",
                 vh_setup("floor", 10, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);

        /* Admit only 3 of 10 → validate can do 3. */
        for (int i = 0; i < 3; i++) {
            job_result_t r = header_admit_stage_step_once();
            VH_CHECK("floor: admit step advances", r == JOB_ADVANCED);
        }
        VH_CHECK("floor: admit cursor at 3",
                 header_admit_stage_cursor() == 3);

        VH_CHECK("floor: validate step ADVANCED (partial batch of 3)",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("floor: validate cursor at 3",
                 validate_headers_stage_cursor() == 3);

        /* Next validate step has nothing to do → IDLE. */
        VH_CHECK("floor: next validate step IDLE",
                 validate_headers_stage_step_once() == JOB_IDLE);

        /* Admit 3 more, validate advances 3 more. */
        for (int i = 0; i < 3; i++)
            header_admit_stage_step_once();
        VH_CHECK("floor: admit cursor now at 6",
                 header_admit_stage_cursor() == 6);
        VH_CHECK("floor: validate ADVANCED again",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("floor: validate cursor at 6",
                 validate_headers_stage_cursor() == 6);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── injected failure: stub returns false at height=3 ──────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct fail_at_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.fail_height = 3;
        VH_CHECK("fail: setup",
                 vh_setup("fail", 5, stub_fail_at, &ctx,
                          dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);

        VH_CHECK("fail: validate drains 1 (batched step)",
                 validate_headers_stage_drain(10) == 1);
        VH_CHECK("fail: cursor at 5 (failure does not block advance)",
                 validate_headers_stage_cursor() == 5);
        VH_CHECK("fail: passed_total == 4",
                 validate_headers_stage_passed_total() == 4);
        VH_CHECK("fail: failed_total == 1",
                 validate_headers_stage_failed_total() == 1);
        VH_CHECK("fail: every height was checked",
                 atomic_load(&ctx.call_count) == 5);

        sqlite3 *db = progress_store_db();
        int ok = -1;
        char reason[64] = {0};
        VH_CHECK("fail: row at h=3 exists",
                 log_row_at(db, 3, &ok, reason, sizeof(reason)));
        VH_CHECK("fail: row at h=3 has ok=0", ok == 0);
        VH_CHECK("fail: row at h=3 reason matches",
                 strcmp(reason, "stub-injected-failure") == 0);

        int ok0 = -1;
        log_row_at(db, 0, &ok0, NULL, 0);
        VH_CHECK("fail: row at h=0 has ok=1", ok0 == 1);
        struct validate_headers_window_report rep;
        VH_CHECK("fail: window report available",
                 validate_headers_stage_window_report(0, 4, &rep));
        VH_CHECK("fail: window report counts failure",
                 rep.complete && rep.failed_count == 1 &&
                 rep.first_failed_height == 3);
        VH_CHECK("fail: window report carries reason",
                 strcmp(rep.first_fail_reason,
                        "stub-injected-failure") == 0);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── stale failures never starve the live frontier ─────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct fail_at_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.fail_height = 0;
        VH_CHECK("frontier: setup",
                 vh_setup("frontier_priority", 4, stub_fail_at, &ctx,
                          dir, sizeof(dir), &ms, &sc) == 0);

        VH_CHECK("frontier: admit first header",
                 header_admit_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("frontier: validate first header fails/advances",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("frontier: cursor at 1 after failed first header",
                 validate_headers_stage_cursor() == 1);

        validate_headers_stage_set_validator(stub_pass, NULL);
        for (int i = 0; i < 3; i++)
            header_admit_stage_step_once();
        VH_CHECK("frontier: admit cursor reaches 4",
                 header_admit_stage_cursor() == 4);

        VH_CHECK("frontier: forward validation wins over recheck",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("frontier: cursor reaches live frontier",
                 validate_headers_stage_cursor() == 4);

        int ok = -1;
        VH_CHECK("frontier: h=1 row exists",
                 log_row_at(progress_store_db(), 1, &ok, NULL, 0));
        VH_CHECK("frontier: h=1 passed before h=0 recheck",
                 ok == 1);

        ok = -1;
        char reason[64] = {0};
        VH_CHECK("frontier: old failed h=0 still pending",
                 log_row_at(progress_store_db(), 0, &ok,
                            reason, sizeof(reason)) &&
                 ok == 0 &&
                 strcmp(reason, "stub-injected-failure") == 0);

        VH_CHECK("frontier: idle step leaves same-run failure alone",
                 validate_headers_stage_step_once() == JOB_IDLE);
        ok = -1;
        reason[0] = 0;
        VH_CHECK("frontier: old same-run failure remains failed",
                 log_row_at(progress_store_db(), 0, &ok,
                            reason, sizeof(reason)) &&
                 ok == 0 &&
                 strcmp(reason, "stub-injected-failure") == 0);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── default validator must not require a body file ────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("index-header: setup default validator",
                 vh_setup("index_header", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        sc.blocks[0].nSolutionSize = 36;
        sc.blocks[0].nSolution = zcl_malloc(sc.blocks[0].nSolutionSize,
                                            "vh_test_solution");
        VH_CHECK("index-header: alloc solution",
                 sc.blocks[0].nSolution != NULL);
        if (sc.blocks[0].nSolution)
            memset(sc.blocks[0].nSolution, 0, sc.blocks[0].nSolutionSize);
        VH_CHECK("index-header: bind phashBlock to index header",
                 vh_set_bi_hash_for_solution(&sc.blocks[0], &sc.hashes[0],
                                             sc.blocks[0].nSolution,
                                             sc.blocks[0].nSolutionSize));

        header_admit_stage_drain(10);
        VH_CHECK("index-header: validate one row",
                 validate_headers_stage_drain(10) == 1);
        int ok = -1;
        char reason[64];
        VH_CHECK("index-header: row exists",
                 log_row_at(progress_store_db(), 0, &ok,
                            reason, sizeof(reason)));
        VH_CHECK("index-header: failure is header-derived",
                 ok == 0 && strcmp(reason, "disk-read-failed") != 0);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── default validator loads persisted solution, not block body ── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct block_tree_db btdb;
        bool btdb_open = false;
        struct block_tree_db *old_tree = g_active_block_tree;

        VH_CHECK("persisted-solution: setup default validator",
                 vh_setup("persisted_solution", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);

        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        dbi.nHeight = 0;
        dbi.nStatus = BLOCK_VALID_HEADER;
        dbi.nVersion = sc.blocks[0].nVersion;
        dbi.hashMerkleRoot = sc.blocks[0].hashMerkleRoot;
        dbi.hashFinalSaplingRoot = sc.blocks[0].hashFinalSaplingRoot;
        dbi.nTime = sc.blocks[0].nTime;
        dbi.nBits = sc.blocks[0].nBits;
        dbi.nNonce = sc.blocks[0].nNonce;
        dbi.nSolutionSize = 36;
        memset(dbi.nSolution, 0, dbi.nSolutionSize);
        disk_block_index_get_hash(&dbi, &sc.hashes[0]);

        char btdb_path[512];
        snprintf(btdb_path, sizeof(btdb_path), "%s/blocktree", dir);
        btdb_open = block_tree_db_open(&btdb, btdb_path,
                                       1 << 20, false, true);
        VH_CHECK("persisted-solution: blocktree opens", btdb_open);
        if (btdb_open) {
            VH_CHECK("persisted-solution: writes disk index",
                     block_tree_db_write_block_index(&btdb, &dbi));
            g_active_block_tree = &btdb;
        }

        header_admit_stage_drain(10);
        VH_CHECK("persisted-solution: validate one row",
                 validate_headers_stage_drain(10) == 1);
        int ok = -1;
        char reason[64];
        VH_CHECK("persisted-solution: row exists",
                 log_row_at(progress_store_db(), 0, &ok,
                            reason, sizeof(reason)));
        VH_CHECK("persisted-solution: failure is header-derived",
                 ok == 0 &&
                 strcmp(reason, "disk-read-failed") != 0 &&
                 strcmp(reason, "no-header-solution") != 0);

        g_active_block_tree = old_tree;
        if (btdb_open)
            block_tree_db_close(&btdb);
        vh_teardown(dir, &ms, &sc);
    }

    /* ── Item 2: node.db solution loader bounds (case c) ───────────── */
    {
        struct node_db ndb;
        VH_CHECK("loader: db opens",
                 node_db_open(&ndb, ":memory:"));

        unsigned char sol[64];
        memset(sol, 0xA5, sizeof(sol));
        VH_CHECK("loader: insert connected block w/ 64B solution",
                 vh_db_put_block(&ndb, 100, sol, sizeof(sol)));

        /* Present + fits → loads exactly, sets out_len. */
        unsigned char out[MAX_SOLUTION_SIZE];
        size_t out_len = 999;
        VH_CHECK("loader: loads present solution",
                 db_block_load_solution_by_height(&ndb, 100, out,
                                                  &out_len, sizeof(out)));
        VH_CHECK("loader: out_len == 64 + bytes match",
                 out_len == sizeof(sol) &&
                 memcmp(out, sol, sizeof(sol)) == 0);

        /* Oversize: max smaller than the stored blob → false, out_len 0. */
        out_len = 999;
        VH_CHECK("loader: oversize (max<len) → false",
                 !db_block_load_solution_by_height(&ndb, 100, out,
                                                   &out_len, 32) &&
                 out_len == 0);

        /* Missing height → false. */
        out_len = 999;
        VH_CHECK("loader: missing row → false",
                 !db_block_load_solution_by_height(&ndb, 4242, out,
                                                   &out_len, sizeof(out)) &&
                 out_len == 0);

        /* Wrong status (below the >=3 connected floor) → invisible. */
        {
            sqlite3_stmt *st = NULL;
            unsigned char z32[32]; memset(z32, 0x11, 32);
            int rc = sqlite3_prepare_v2(ndb.db,
                "INSERT INTO blocks(hash,height,prev_hash,version,"
                "merkle_root,time,bits,nonce,solution,chain_work,status,"
                "num_tx) VALUES(?,?,?,4,?,1,1,?,?,?,1,0)",
                -1, &st, NULL);
            VH_CHECK("loader: prepare status-2 insert", rc == SQLITE_OK);
            if (rc == SQLITE_OK) {
                unsigned char h[32]; memset(h, 0x77, 32);
                sqlite3_bind_blob(st, 1, h, 32, SQLITE_STATIC);
                sqlite3_bind_int(st, 2, 101);
                sqlite3_bind_blob(st, 3, z32, 32, SQLITE_STATIC);
                sqlite3_bind_blob(st, 4, z32, 32, SQLITE_STATIC);
                sqlite3_bind_blob(st, 5, z32, 32, SQLITE_STATIC);
                sqlite3_bind_blob(st, 6, sol, (int)sizeof(sol), SQLITE_STATIC);
                sqlite3_bind_blob(st, 7, z32, 32, SQLITE_STATIC);
                (void)sqlite3_step(st);  // raw-sql-ok:test-direct
                sqlite3_finalize(st);
            }
            out_len = 999;
            VH_CHECK("loader: status<3 row not returned",
                     !db_block_load_solution_by_height(&ndb, 101, out,
                                                       &out_len, sizeof(out)));
        }

        /* Empty solution column at status>=3 → false (backfill residual). */
        {
            sqlite3_stmt *st = NULL;
            unsigned char z32[32]; memset(z32, 0x22, 32);
            int rc = sqlite3_prepare_v2(ndb.db,
                "INSERT INTO blocks(hash,height,prev_hash,version,"
                "merkle_root,time,bits,nonce,solution,chain_work,status,"
                "num_tx) VALUES(?,?,?,4,?,1,1,?,?,?,3,0)",
                -1, &st, NULL);
            VH_CHECK("loader: prepare empty-solution insert", rc == SQLITE_OK);
            if (rc == SQLITE_OK) {
                unsigned char h[32]; memset(h, 0x88, 32);
                sqlite3_bind_blob(st, 1, h, 32, SQLITE_STATIC);
                sqlite3_bind_int(st, 2, 102);
                sqlite3_bind_blob(st, 3, z32, 32, SQLITE_STATIC);
                sqlite3_bind_blob(st, 4, z32, 32, SQLITE_STATIC);
                /* zero-length, non-NULL blob → satisfies NOT NULL but empty */
                sqlite3_bind_blob(st, 5, z32, 32, SQLITE_STATIC);
                sqlite3_bind_blob(st, 6, "", 0, SQLITE_STATIC);
                sqlite3_bind_blob(st, 7, z32, 32, SQLITE_STATIC);
                (void)sqlite3_step(st);  // raw-sql-ok:test-direct
                sqlite3_finalize(st);
            }
            out_len = 999;
            VH_CHECK("loader: empty solution col → false (no false data)",
                     !db_block_load_solution_by_height(&ndb, 102, out,
                                                       &out_len, sizeof(out)) &&
                     out_len == 0);
        }

        /* NULL-arg / out_len-only guards. */
        VH_CHECK("loader: NULL ndb → false",
                 !db_block_load_solution_by_height(NULL, 100, out,
                                                   &out_len, sizeof(out)));
        VH_CHECK("loader: max==0 → false",
                 !db_block_load_solution_by_height(&ndb, 100, out,
                                                   &out_len, 0));

        node_db_close(&ndb);
    }

    /* ── Item 2: validator fallback loads from node.db (case a) ────── *
     * block_index solution empty, persisted index absent, BUT node.db
     * carries a solution at this height. The fallback must LOAD it and
     * push it through the IDENTICAL validate_header_fields path — so the
     * verdict is a real PoW/Equihash result, never the backfill reason
     * and never "no-header-solution". (A synthetic 1344B zero blob will
     * fail Equihash, which is exactly correct: no false pass.) */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct node_db ndb;
        VH_CHECK("fallback: node.db opens",
                 node_db_open(&ndb, ":memory:"));

        unsigned char sol[MAX_SOLUTION_SIZE];
        memset(sol, 0x00, sizeof(sol));
        VH_CHECK("fallback: seed node.db solution at h=0",
                 vh_db_put_block(&ndb, 0, sol, sizeof(sol)));

        VH_CHECK("fallback: setup default validator",
                 vh_setup("fallback_loads", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        /* Leave sc.blocks[0].nSolution NULL (index empty) and inject the
         * fixture node.db so the fallback resolves it. */
        VH_CHECK("fallback: bind phashBlock to solution fallback header",
                 vh_set_bi_hash_for_solution(&sc.blocks[0], &sc.hashes[0],
                                             sol, sizeof(sol)));
        validate_headers_validator_set_node_db(&ndb);

        header_admit_stage_drain(10);
        VH_CHECK("fallback: validate one row",
                 validate_headers_stage_drain(10) == 1);
        int ok = -1;
        char reason[64] = {0};
        VH_CHECK("fallback: row exists",
                 log_row_at(progress_store_db(), 0, &ok,
                            reason, sizeof(reason)));
        /* Loader was reached: verdict is a real validation failure, NOT
         * the residual backfill reason and NOT the pre-loader empty
         * reason. This proves the node.db bytes flowed into identical
         * Equihash verification. */
        VH_CHECK("fallback: node.db solution reached identical validation",
                 ok == 0 &&
                 strcmp(reason, "no-header-solution") != 0 &&
                 strcmp(reason,
                        "no-header-solution-backfill-required") != 0);

        validate_headers_validator_set_node_db(NULL);
        vh_teardown(dir, &ms, &sc);
        node_db_close(&ndb);
    }

    /* ── full node.db header source wins over stale block_index fields ─ */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct node_db ndb;
        VH_CHECK("node-db-header: node.db opens",
                 node_db_open(&ndb, ":memory:"));

        chain_params_select(CHAIN_REGTEST);
        VH_CHECK("node-db-header: setup default validator",
                 vh_setup("node_db_header", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);

        struct block_header h;
        block_header_init(&h);
        h.nVersion = 4;
        h.hashMerkleRoot.data[0] = 0x31;
        h.hashFinalSaplingRoot.data[0] = 0x32;
        h.nTime = 1700000300u;
        h.nBits = 0x200f0f0f; /* regtest powLimit compact */
        /* 36 bytes = regtest Equihash(48,5) size: passes the epoch
         * solution-size pin so the Equihash VERIFY renders the verdict */
        h.nSolutionSize = 36;
        memset(h.nSolution, 0x42, h.nSolutionSize);
        struct uint256 hash;
        VH_CHECK("node-db-header: grind PoW-valid synthetic header",
                 vh_grind_pow(&h, &hash, 100000));
        VH_CHECK("node-db-header: save full node.db header",
                 vh_db_put_header(&ndb, 0, &h, &hash));

        sc.hashes[0] = hash;
        sc.blocks[0].phashBlock = &sc.hashes[0];
        sc.blocks[0].nBits = 0x1f07ffff;
        sc.blocks[0].nNonce.data[0] ^= 0x7f;
        sc.blocks[0].nSolutionSize = 36;
        sc.blocks[0].nSolution = zcl_malloc(sc.blocks[0].nSolutionSize,
                                            "vh_stale_index_solution");
        VH_CHECK("node-db-header: alloc stale index solution",
                 sc.blocks[0].nSolution != NULL);
        if (sc.blocks[0].nSolution)
            memset(sc.blocks[0].nSolution, 0xEE,
                   sc.blocks[0].nSolutionSize);

        validate_headers_validator_set_node_db(&ndb);
        char reason[VH_MAX_REASON] = {0};
        bool ok = validate_headers_default_validator(
            &sc.blocks[0], dir, reason, sizeof(reason), NULL);
        VH_CHECK("node-db-header: full header reaches Equihash verdict",
                 !ok && strcmp(reason, "invalid-solution") == 0);

        validate_headers_validator_set_node_db(NULL);
        vh_teardown(dir, &ms, &sc);
        node_db_close(&ndb);
        chain_params_select(CHAIN_MAIN);
    }

    /* ── wrong-epoch solution size must be PINNED, not self-verified ──
     * The Equihash verify derives (n,k) FROM the solution size, so an
     * internally-consistent wrong-epoch solution (here 1344 bytes =
     * Equihash(200,9) at a height whose epoch pins 48,5 → 36) would
     * self-verify under the wrong parameters and could ride the staged
     * path even though every peer-facing accept path rejects it — the
     * exact asymmetry the epoch pin closes. Asserts the pin's distinct
     * reject reason fires BEFORE the Equihash verdict. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct node_db ndb;
        VH_CHECK("epoch-pin: node.db opens",
                 node_db_open(&ndb, ":memory:"));

        chain_params_select(CHAIN_REGTEST);
        VH_CHECK("epoch-pin: setup default validator",
                 vh_setup("epoch_pin_reject", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);

        struct block_header h;
        block_header_init(&h);
        h.nVersion = 4;
        h.hashMerkleRoot.data[0] = 0x61;
        h.hashFinalSaplingRoot.data[0] = 0x62;
        h.nTime = 1700000500u;
        h.nBits = 0x200f0f0f; /* regtest powLimit compact */
        /* 1344 bytes = Equihash(200,9): plausible for another epoch,
         * never for regtest's pinned 48,5 (expected 36). */
        h.nSolutionSize = 1344;
        memset(h.nSolution, 0x42, h.nSolutionSize);
        struct uint256 hash;
        VH_CHECK("epoch-pin: grind PoW-valid synthetic header",
                 vh_grind_pow(&h, &hash, 100000));
        VH_CHECK("epoch-pin: save full node.db header",
                 vh_db_put_header(&ndb, 0, &h, &hash));

        /* Index source carries no solution (rejected as solutionless);
         * the hash-bound node.db row is the only usable source. */
        sc.hashes[0] = hash;
        sc.blocks[0].phashBlock = &sc.hashes[0];
        sc.blocks[0].nBits = 0x1f07ffff;
        sc.blocks[0].nNonce.data[0] ^= 0x7f;

        validate_headers_validator_set_node_db(&ndb);
        char reason[VH_MAX_REASON] = {0};
        bool ok = validate_headers_default_validator(
            &sc.blocks[0], dir, reason, sizeof(reason), NULL);
        VH_CHECK("epoch-pin: wrong-epoch solution size pinned",
                 !ok && strcmp(reason, "bad-equihash-solution-size") == 0);

        validate_headers_validator_set_node_db(NULL);
        vh_teardown(dir, &ms, &sc);
        node_db_close(&ndb);
        chain_params_select(CHAIN_MAIN);
    }

    /* ── disk block source covers stale / empty SQL header sources ───── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct node_db ndb;
        VH_CHECK("disk-block: node.db opens",
                 node_db_open(&ndb, ":memory:"));

        chain_params_select(CHAIN_REGTEST);
        VH_CHECK("disk-block: setup default validator",
                 vh_setup("disk_block_source", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);

        struct block_header h;
        block_header_init(&h);
        h.nVersion = 4;
        h.hashMerkleRoot.data[0] = 0x51;
        h.hashFinalSaplingRoot.data[0] = 0x52;
        h.nTime = 1700000400u;
        h.nBits = 0x200f0f0f; /* regtest powLimit compact */
        /* 36 bytes = regtest Equihash(48,5) size (see node-db-header) */
        h.nSolutionSize = 36;
        memset(h.nSolution, 0x5A, h.nSolutionSize);
        struct uint256 hash;
        VH_CHECK("disk-block: grind PoW-valid synthetic header",
                 vh_grind_pow(&h, &hash, 100000));
        VH_CHECK("disk-block: write full block to disk",
                 vh_write_disk_block_for_index(dir, &h, &sc.blocks[0],
                                               &sc.hashes[0]));

        /* Force earlier index/SQL sources to be unusable; the disk block is
         * the only source carrying bytes that hash-bind to phashBlock. */
        sc.blocks[0].nBits = 0x1f07ffff;
        sc.blocks[0].nNonce.data[0] ^= 0x9b;
        free(sc.blocks[0].nSolution);
        sc.blocks[0].nSolution = NULL;
        sc.blocks[0].nSolutionSize = 0;
        validate_headers_validator_set_node_db(&ndb);

        char reason[VH_MAX_REASON] = {0};
        bool ok = validate_headers_default_validator(
            &sc.blocks[0], dir, reason, sizeof(reason), NULL);
        VH_CHECK("disk-block: full block header reaches validation",
                 !ok && strcmp(reason, "invalid-solution") == 0);

        validate_headers_validator_set_node_db(NULL);
        vh_teardown(dir, &ms, &sc);
        node_db_close(&ndb);
        chain_params_select(CHAIN_MAIN);
    }

    /* ── Item 2: node.db ALSO empty → fail with backfill reason (b) ── *
     * The 675K residual rows. block_index empty, persisted index empty,
     * node.db has no solution at this height → the validator MUST fail
     * with the distinct backfill reason. Proves there is NO false-pass on
     * a header lacking a real, verified solution. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct node_db ndb;
        VH_CHECK("residual: node.db opens",
                 node_db_open(&ndb, ":memory:"));
        /* node.db is empty — no row at h=0 at all. */

        VH_CHECK("residual: setup default validator",
                 vh_setup("residual_backfill", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        validate_headers_validator_set_node_db(&ndb);

        header_admit_stage_drain(10);
        VH_CHECK("residual: validate one row",
                 validate_headers_stage_drain(10) == 1);
        int ok = -1;
        char reason[64] = {0};
        VH_CHECK("residual: row exists",
                 log_row_at(progress_store_db(), 0, &ok,
                            reason, sizeof(reason)));
        VH_CHECK("residual: fails with distinct backfill reason (no false pass)",
                 ok == 0 &&
                 strcmp(reason,
                        "no-header-solution-backfill-required") == 0);

        validate_headers_validator_set_node_db(NULL);
        vh_teardown(dir, &ms, &sc);
        node_db_close(&ndb);
    }

    /* ── repair-header row feeds validation before node.db fallback ───── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct node_db ndb;
        VH_CHECK("repair-header: node.db opens",
                 node_db_open(&ndb, ":memory:"));

        VH_CHECK("repair-header: setup default validator",
                 vh_setup("repair_header_loads", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        validate_headers_validator_set_node_db(&ndb);
        VH_CHECK("repair-header: seed repair header",
                 seed_repair_header_for_block(progress_store_db(),
                                              &sc.blocks[0],
                                              &sc.hashes[0]));

        header_admit_stage_drain(10);
        VH_CHECK("repair-header: validate one row",
                 validate_headers_stage_drain(10) == 1);
        int ok = -1;
        char reason[64] = {0};
        VH_CHECK("repair-header: row exists",
                 log_row_at(progress_store_db(), 0, &ok,
                            reason, sizeof(reason)));
        VH_CHECK("repair-header: supplied bytes reached validation",
                 ok == 0 &&
                 strcmp(reason, "no-header-solution") != 0 &&
                 strcmp(reason,
                        "no-header-solution-backfill-required") != 0);

        validate_headers_validator_set_node_db(NULL);
        vh_teardown(dir, &ms, &sc);
        node_db_close(&ndb);
    }

    /* ── W1 T1: resolver covers the frontier from header_solution_repair
     *           with an EMPTY node.db, via a DIRECT validator call ──────
     * The repair table is the new FIRST source. With node.db empty and the
     * block index solution-less, only the repair row can supply bytes. We
     * call validate_headers_default_validator() DIRECTLY (the W1 surface)
     * and assert the verdict is a real PoW/Equihash result (reason NOT a
     * pre-PoW marker) — proving the repair bytes reached identical
     * verification. The synthetic 32B solution is non-PoW so it correctly
     * fails check_equihash_solution: a real verdict, never a false pass. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct node_db ndb;
        VH_CHECK("resolver-direct: node.db opens (empty)",
                 node_db_open(&ndb, ":memory:"));
        VH_CHECK("resolver-direct: setup",
                 vh_setup("resolver_direct", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        validate_headers_validator_set_node_db(&ndb);

        VH_CHECK("resolver-direct: seed repair header",
                 seed_repair_header_for_block(progress_store_db(),
                                              &sc.blocks[0],
                                              &sc.hashes[0]));

        /* Direct validator call — NOT through the stage. */
        char reason[VH_MAX_REASON] = {0};
        bool ok = validate_headers_default_validator(
            &sc.blocks[0], dir, reason, sizeof(reason), NULL);
        VH_CHECK("resolver-direct: repair bytes reached identical PoW path",
                 !ok && !reason_is_pre_pow(reason));

        validate_headers_validator_set_node_db(NULL);
        vh_teardown(dir, &ms, &sc);
        node_db_close(&ndb);
    }

    /* ── W1 T2: no-false-pass — empty node.db AND empty repair table ────
     * Direct validator call. With no source holding a solution, every
     * branch (repair / index / persisted / node.db) returns false and the
     * verdict is the distinct backfill reason — never a false pass. This
     * pins that the new first branch falls through cleanly on a missing
     * repair row. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct node_db ndb;
        VH_CHECK("resolver-nofalsepass: node.db opens (empty)",
                 node_db_open(&ndb, ":memory:"));
        VH_CHECK("resolver-nofalsepass: setup",
                 vh_setup("resolver_nofalsepass", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        validate_headers_validator_set_node_db(&ndb);
        /* No repair row seeded; index solution-less; node.db empty. */

        char reason[VH_MAX_REASON] = {0};
        bool ok = validate_headers_default_validator(
            &sc.blocks[0], dir, reason, sizeof(reason), NULL);
        VH_CHECK("resolver-nofalsepass: fails distinct backfill reason",
                 !ok && strcmp(reason,
                               "no-header-solution-backfill-required") == 0);

        validate_headers_validator_set_node_db(NULL);
        vh_teardown(dir, &ms, &sc);
        node_db_close(&ndb);
    }

    /* ── W1 T3: precedence — repair row consulted FIRST, still PoW-verified
     * Seed BOTH a header_solution_repair row AND a node.db solution at the
     * same height. The repair branch is first; whatever bytes it returns
     * still funnel through validate_header_fields, so the verdict is a real
     * PoW/Equihash result (reason NOT a pre-PoW marker). Both sources
     * hash-bind to bi->phashBlock, so the verdict is source-independent. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct node_db ndb;
        VH_CHECK("resolver-precedence: node.db opens",
                 node_db_open(&ndb, ":memory:"));

        unsigned char sol[MAX_SOLUTION_SIZE];
        memset(sol, 0x00, sizeof(sol));
        VH_CHECK("resolver-precedence: seed node.db solution at h=0",
                 vh_db_put_block(&ndb, 0, sol, sizeof(sol)));

        VH_CHECK("resolver-precedence: setup",
                 vh_setup("resolver_precedence", 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        validate_headers_validator_set_node_db(&ndb);
        VH_CHECK("resolver-precedence: seed repair header",
                 seed_repair_header_for_block(progress_store_db(),
                                              &sc.blocks[0],
                                              &sc.hashes[0]));

        char reason[VH_MAX_REASON] = {0};
        bool ok = validate_headers_default_validator(
            &sc.blocks[0], dir, reason, sizeof(reason), NULL);
        VH_CHECK("resolver-precedence: real PoW verdict (repair first)",
                 !ok && !reason_is_pre_pow(reason));

        validate_headers_validator_set_node_db(NULL);
        vh_teardown(dir, &ms, &sc);
        node_db_close(&ndb);
    }

    /* ── W1 T4: the recheck path REACHES + VALIDATES the frontier whose
     *           height is ABOVE the finalized active-chain window tip ─────
     * The live wedge: a failed validate_headers_log row sits at the frontier
     * height N — ONE above the finalized window tip (N-1) — and the recheck
     * path's height resolve must reach it. Pre-fix, the recheck used
     * active_chain_at, which returns NULL for any height above the window
     * tip, so the recheck bailed JOB_IDLE and never reached the frontier.
     * Post-fix, vh_resolve_bi falls back to block_index_get_ancestor over
     * ms->pindex_best_header to reach it.
     *
     * We build heights 0..N, set the window tip to N-1 while best_header
     * points at the frontier block N, seed an ok=0 frontier row + a real
     * header_solution_repair row at N, advance the persisted validate cursor
     * past N so the recheck query selects it, then drive step_once. The
     * assertion is that the frontier row is REBOUND: the recheck returns
     * JOB_ADVANCED and the row's reason flips from the seeded backfill marker
     * to a real PoW/Equihash verdict (the synthetic 32B repair solution is
     * non-PoW, so it correctly fails Equihash — a real verdict, never a
     * false pass). The load-bearing point is that the frontier was REACHED
     * at all (no longer JOB_IDLE / no longer the backfill marker). */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        const int N = 4;   /* frontier height; window tip will be N-1 */

        /* Build heights 0..N (N+1 blocks). vh_setup moves the window tip to
         * the top (N); we then collapse it back to N-1 to model the
         * finalized window sitting one below the frontier. */
        VH_CHECK("frontier-reach: setup",
                 vh_setup("frontier_reach", N + 1, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);

        sqlite3 *db = progress_store_db();

        /* Window tip -> N-1; the frontier block N stays best_header. */
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[N - 1]);
        ms.pindex_best_header = &sc.blocks[N];
        VH_CHECK("frontier-reach: active_chain_at(N) is NULL (above window)",
                 active_chain_at(&ms.chain_active, N) == NULL);
        VH_CHECK("frontier-reach: ancestor reaches the frontier above window",
                 block_index_get_ancestor(ms.pindex_best_header, N) ==
                     &sc.blocks[N]);

        /* Seed a failed frontier row + a real repair header at N, and push
         * the validate cursor past N so the recheck selects [.., N+1). */
        VH_CHECK("frontier-reach: seed failed frontier row",
                 seed_failed_vh_row(db, N, &sc.hashes[N],
                                    "no-header-solution-backfill-required"));
        VH_CHECK("frontier-reach: seed repair header at frontier",
                 seed_repair_header_for_block(db, &sc.blocks[N],
                                              &sc.hashes[N]));
        VH_CHECK("frontier-reach: advance validate cursor past frontier",
                 set_stage_cursor(db, "validate_headers", N + 1));

        /* Pre-state: frontier row is ok=0 with the backfill marker. */
        int ok = -1;
        char reason[VH_MAX_REASON] = {0};
        VH_CHECK("frontier-reach: pre row ok=0 backfill marker",
                 log_row_at(db, N, &ok, reason, sizeof(reason)) && ok == 0 &&
                 strcmp(reason,
                        "no-header-solution-backfill-required") == 0);

        /* Drive the recheck. step_once runs the forward step (IDLE — header
         * admit floor) then the recheck, which must reach the frontier. */
        job_result_t r = validate_headers_stage_step_once();
        VH_CHECK("frontier-reach: recheck ADVANCED (frontier reached)",
                 r == JOB_ADVANCED);

        /* Frontier row REBOUND: reason flips off the backfill marker to a
         * real PoW/Equihash verdict (repair bytes flowed into validation). */
        ok = -1;
        reason[0] = 0;
        VH_CHECK("frontier-reach: frontier row rebound to real verdict",
                 log_row_at(db, N, &ok, reason, sizeof(reason)) &&
                 !reason_is_pre_pow(reason));

        vh_teardown(dir, &ms, &sc);
    }

    /* ── persisted failures are rechecked after restart ────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct fail_at_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.fail_height = 1;
        ctx.reason = "no-header-solution-backfill-required";
        VH_CHECK("recheck: setup with failing validator",
                 vh_setup("recheck", 3, stub_fail_at, &ctx,
                          dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);
        VH_CHECK("recheck: initial validate advances",
                 validate_headers_stage_drain(10) >= 1);
        int ok = -1;
        char reason[64] = {0};
        VH_CHECK("recheck: failed row exists",
                 log_row_at(progress_store_db(), 1, &ok,
                            reason, sizeof(reason)));
        VH_CHECK("recheck: initial row failed",
                 ok == 0 &&
                 strcmp(reason,
                        "no-header-solution-backfill-required") == 0);

        validate_headers_stage_shutdown();
        header_admit_stage_shutdown();
        progress_store_close();

        VH_CHECK("recheck: reopen store", progress_store_open(dir));
        VH_CHECK("recheck: re-init admit", header_admit_stage_init(&ms));
        VH_CHECK("recheck: re-init validate",
                 validate_headers_stage_init(&ms));
        VH_CHECK("recheck: repaired solution is now hash-bound",
                 seed_repair_header_for_block(progress_store_db(),
                                              &sc.blocks[1], &sc.hashes[1]));
        validate_headers_stage_set_validator(stub_pass, NULL);

        VH_CHECK("recheck: failed row is retried",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        ok = -1;
        reason[0] = 0;
        VH_CHECK("recheck: retried row exists",
                 log_row_at(progress_store_db(), 1, &ok,
                            reason, sizeof(reason)));
        VH_CHECK("recheck: retried row now passes", ok == 1);
        VH_CHECK("recheck: cursor remains advanced",
                 validate_headers_stage_cursor() == 3);
        VH_CHECK("recheck: next step idle",
                 validate_headers_stage_step_once() == JOB_IDLE);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── unresolved solutionless rows back off without fake advances ─────
     * C3 measured the validate cursor already at peer tip while the failed-row
     * recheck repeatedly selected the same 64 solutionless rows.  With no
     * solution bytes available, each pass was guaranteed to reproduce the
     * same failure, yet the stage reported JOB_ADVANCED and consumed 128.9s.
     * Readiness is the hash-bound repair row (or canonical in-index solution):
     * before it exists, repeated polls are IDLE and do not call the validator;
     * after it lands, exactly one unchanged validation advances the row. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct fail_at_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.fail_height = 1;
        ctx.reason = "no-header-solution-backfill-required";
        VH_CHECK("recheck-readiness: setup with solutionless failure",
                 vh_setup("recheck_readiness", 3, stub_fail_at, &ctx,
                          dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);
        VH_CHECK("recheck-readiness: forward validation records failure",
                 validate_headers_stage_drain(10) >= 1);

        int calls_before = atomic_load(&ctx.call_count);
        ctx.fail_height = -1; /* unchanged stub now passes when invoked */
        VH_CHECK("recheck-readiness: unresolved poll is IDLE",
                 validate_headers_stage_step_once() == JOB_IDLE);
        VH_CHECK("recheck-readiness: repeated unresolved poll is IDLE",
                 validate_headers_stage_step_once() == JOB_IDLE);
        VH_CHECK("recheck-readiness: unresolved polls never invoke validator",
                 atomic_load(&ctx.call_count) == calls_before);

        VH_CHECK("recheck-readiness: repair solution becomes hash-bound",
                 seed_repair_header_for_block(progress_store_db(),
                                              &sc.blocks[1], &sc.hashes[1]));
        VH_CHECK("recheck-readiness: ready row advances exactly once",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("recheck-readiness: ready row invoked validator once",
                 atomic_load(&ctx.call_count) == calls_before + 1);
        VH_CHECK("recheck-readiness: resolved row stays idle",
                 validate_headers_stage_step_once() == JOB_IDLE);
        VH_CHECK("recheck-readiness: resolved row is not revalidated",
                 atomic_load(&ctx.call_count) == calls_before + 1);

        int ok = -1;
        VH_CHECK("recheck-readiness: repaired row is now passing",
                 log_row_at(progress_store_db(), 1, &ok, NULL, 0) && ok == 1);
        vh_teardown(dir, &ms, &sc);
    }

    /* ── terminal persisted failures are not retried after restart ───── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct fail_at_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.fail_height = 1;
        ctx.reason = "stub-injected-failure";
        VH_CHECK("terminal-recheck: setup with terminal failure",
                 vh_setup("terminal_recheck", 3, stub_fail_at, &ctx,
                          dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);
        VH_CHECK("terminal-recheck: initial validate advances",
                 validate_headers_stage_drain(10) == 1);

        validate_headers_stage_shutdown();
        header_admit_stage_shutdown();
        progress_store_close();

        VH_CHECK("terminal-recheck: reopen store", progress_store_open(dir));
        VH_CHECK("terminal-recheck: re-init admit",
                 header_admit_stage_init(&ms));
        VH_CHECK("terminal-recheck: re-init validate",
                 validate_headers_stage_init(&ms));
        validate_headers_stage_set_validator(stub_pass, NULL);

        VH_CHECK("terminal-recheck: terminal row is not retried",
                 validate_headers_stage_step_once() == JOB_IDLE);
        int ok = -1;
        char reason[64] = {0};
        VH_CHECK("terminal-recheck: terminal row remains failed",
                 log_row_at(progress_store_db(), 1, &ok,
                            reason, sizeof(reason)) &&
                 ok == 0 && strcmp(reason, "stub-injected-failure") == 0);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── replay across reopen: cursor + log persist ────────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("replay: setup",
                 vh_setup("replay", 7, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);
        VH_CHECK("replay: validate cursor at 7",
                 validate_headers_stage_drain(10) >= 1 &&
                 validate_headers_stage_cursor() == 7);

        /* Tear down both stages, close store. */
        validate_headers_stage_shutdown();
        header_admit_stage_shutdown();
        progress_store_close();

        /* Reopen everything. */
        VH_CHECK("replay: reopen store", progress_store_open(dir));
        VH_CHECK("replay: re-init admit", header_admit_stage_init(&ms));
        VH_CHECK("replay: re-init validate",
                 validate_headers_stage_init(&ms));
        validate_headers_stage_set_validator(stub_pass, NULL);

        job_result_t r = validate_headers_stage_step_once();
        VH_CHECK("replay: first step after reopen is IDLE (cursor=7)",
                 r == JOB_IDLE);
        VH_CHECK("replay: cursor restored to 7",
                 validate_headers_stage_cursor() == 7);

        sqlite3 *db = progress_store_db();
        VH_CHECK("replay: log still has 7 rows",
                 log_row_count(db) == 7);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── authoritative path marks successful headers valid ─────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("auth: setup",
                 vh_setup("auth", 2, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);
        sc.blocks[0].nStatus = BLOCK_VALID_UNKNOWN;

        VH_CHECK("auth: validate advances",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("auth: h=0 marked valid header",
                 (sc.blocks[0].nStatus & BLOCK_VALID_MASK) >=
                     BLOCK_VALID_HEADER);
        VH_CHECK("auth: pass record lookup succeeds",
                 validate_headers_stage_has_pass_record(0, &sc.hashes[0]));

        vh_teardown(dir, &ms, &sc);
    }

    /* ── mark-failure → typed blocker, no storm (deliverable a) ──────────
     * The live 18,440-WARN/5min storm: the validator PASSES a header but the
     * block_index entry is BLOCK_FAILED-masked (set by the getheaders serve
     * path), so mark_valid_header refuses it forever and the old code returned
     * JOB_FATAL hot. With no repairable evidence (no header_solution_repair row)
     * the mask must NOT be cleared; instead the stage raises ONE typed blocker,
     * emits exactly ONE WARN per streak, and backs off JOB_IDLE — the cursor
     * holds, never a hot loop. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("mark-storm: setup",
                 vh_setup("mark_storm", 2, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        VH_CHECK("mark-storm: header_admit drains 2",
                 header_admit_stage_drain(100) == 2);

        /* Stale serve-path poison: BLOCK_FAILED_VALID on the frontier block,
         * with NO header_solution_repair row (so it is not the clearable
         * repairable class). The validator (stub_pass) still passes. */
        sc.blocks[0].nStatus |= BLOCK_FAILED_VALID;

        blocker_clear(VH_MARK_FAIL_BLOCKER_ID_T);
        int64_t warn0 = validate_headers_stage_mark_fail_warn_count();

        /* Drive several steps: every one must be JOB_IDLE (backoff), never
         * JOB_FATAL/JOB_ADVANCED, and the cursor must not move. */
        bool all_idle = true;
        for (int s = 0; s < 6; s++) {
            job_result_t r = validate_headers_stage_step_once();
            if (r != JOB_IDLE) all_idle = false;
        }
        VH_CHECK("mark-storm: every step backs off JOB_IDLE (no hot loop)",
                 all_idle);
        VH_CHECK("mark-storm: cursor held at 0 (never advanced past poison)",
                 validate_headers_stage_cursor() == 0);
        VH_CHECK("mark-storm: exactly ONE WARN per streak (no storm)",
                 validate_headers_stage_mark_fail_warn_count() - warn0 == 1);
        VH_CHECK("mark-storm: typed blocker raised",
                 blocker_exists(VH_MARK_FAIL_BLOCKER_ID_T));

        vh_teardown(dir, &ms, &sc);
    }

    /* ── repairable stale FAILED mask clears on recheck (deliverable b) ──
     * A header fails solutionless (ok=0, the repairable class), THEN its
     * block_index entry gets a stale BLOCK_FAILED mask (serve-path poison) AND
     * its solution is repaired (validator now passes). The recheck path must:
     * re-run the UNCHANGED validator (now passing), clear the stale FAILED bits,
     * mark the header valid, and flip the log row to ok=1 — cursor/floor
     * advances. The mask leaves FAILED ONLY because the unchanged validator
     * passed (E13-neutral). */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct fail_at_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.fail_height = 1;
        ctx.reason = "no-header-solution-backfill-required";
        VH_CHECK("mark-repair: setup with solutionless failing validator",
                 vh_setup("mark_repair", 3, stub_fail_at, &ctx,
                          dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);
        VH_CHECK("mark-repair: initial validate advances",
                 validate_headers_stage_drain(10) >= 1);

        sqlite3 *db = progress_store_db();
        int ok = -1; char reason[64] = {0};
        VH_CHECK("mark-repair: h=1 row failed solutionless",
                 log_row_at(db, 1, &ok, reason, sizeof(reason)) && ok == 0 &&
                 strcmp(reason,
                        "no-header-solution-backfill-required") == 0);

        /* Serve-path poison: stale BLOCK_FAILED mask on the failed frontier
         * block; and the solution is now repaired (validator passes). */
        sc.blocks[1].nStatus |= BLOCK_FAILED_VALID;
        VH_CHECK("mark-repair: precondition — block is FAILED-masked",
                 (sc.blocks[1].nStatus & BLOCK_FAILED_MASK) != 0);
        VH_CHECK("mark-repair: seed repaired solution",
                 seed_repair_header_for_block(db, &sc.blocks[1],
                                              &sc.hashes[1]));
        validate_headers_stage_set_validator(stub_pass, NULL);

        VH_CHECK("mark-repair: recheck re-validates + advances",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        VH_CHECK("mark-repair: stale FAILED mask cleared (unchanged validator "
                 "passed)",
                 (sc.blocks[1].nStatus & BLOCK_FAILED_MASK) == 0);
        VH_CHECK("mark-repair: block marked BLOCK_VALID_HEADER",
                 (sc.blocks[1].nStatus & BLOCK_VALID_MASK) >=
                     BLOCK_VALID_HEADER);
        ok = -1;
        VH_CHECK("mark-repair: h=1 row flipped to ok=1",
                 log_row_at(db, 1, &ok, NULL, 0) && ok == 1);
        VH_CHECK("mark-repair: no mark-failure blocker raised (repair path)",
                 !blocker_exists(VH_MARK_FAIL_BLOCKER_ID_T));

        vh_teardown(dir, &ms, &sc);
    }

    /* ── pre-init guards ───────────────────────────────────────────── */
    {
        VH_CHECK("guard: step_once with no init returns IDLE",
                 validate_headers_stage_step_once() == JOB_IDLE);
        VH_CHECK("guard: init(NULL) rejected",
                 !validate_headers_stage_init(NULL));
    }

    /* ── dump_state_json shape ─────────────────────────────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("dump: setup",
                 vh_setup("dump", 2, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);
        validate_headers_stage_drain(10);

        struct json_value v;
        json_init(&v);
        VH_CHECK("dump: returns true",
                 validate_headers_stage_dump_state_json(&v, NULL));
        char buf[2048];
        size_t n = json_write(&v, buf, sizeof(buf));
        VH_CHECK("dump: serializes", n > 0 && n < sizeof(buf));
        VH_CHECK("dump: initialised=true",
                 strstr(buf, "\"initialised\":true") != NULL);
        VH_CHECK("dump: cursor=2",
                 strstr(buf, "\"cursor\":2") != NULL);
        VH_CHECK("dump: passed_total=2",
                 strstr(buf, "\"passed_total\":2") != NULL);
        VH_CHECK("dump: pool_size present",
                 strstr(buf, "\"pool_size\":4") != NULL);
        VH_CHECK("dump: failure_log_count present",
                 strstr(buf, "\"failure_log_count\":0") != NULL);
        VH_CHECK("dump: first_failed_height present",
                 strstr(buf, "\"first_failed_height\":-1") != NULL);
        VH_CHECK("dump: last_failed_height present",
                 strstr(buf, "\"last_failed_height\":-1") != NULL);
        VH_CHECK("dump: recheck cursor present",
                 strstr(buf, "\"failure_recheck_cursor\":") != NULL);
        json_free(&v);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── stale-floor clamp: ancient solutionless rows never starve the
     *    cursor-frontier recheck ─────────────────────────────────────────
     * Regression for the second live tip-wedge: after validate_headers drains
     * forward over a cold-imported chain it leaves many ancient ok=0
     * "no-header-solution-backfill-required" rows (empty-solution headers).
     * Those are REPAIRABLE-looking, so the in-process recheck floor used to pin
     * on the lowest of them and the bounded batch (LIMIT VH_BATCH_SIZE) never
     * reached the real frontier whose solution had since landed — tip frozen.
     * The fix clamps the recheck scan floor up to the live pipeline frontier
     * = min(tip_finalize_cursor, body_fetch_cursor), excluding the ancient rows
     * so the recheck reaches and flips the frontier. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        /* Validator passes everything it is ASKED to re-validate, so the only
         * thing that can keep a row ok=0 is the recheck scan never reaching it
         * — making "ancient row still ok=0" a clean proof of exclusion. */
        VH_CHECK("clamp: setup",
                 vh_setup("clamp_frontier", 6, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        sqlite3 *db = progress_store_db();

        /* An ANCIENT repairable ok=0 row far below the frontier (height 1, a
         * cold-import artifact) and one AT the frontier (height 4). Both carry
         * the exact solutionless reason so both look repairable to the floor. */
        VH_CHECK("clamp: seed ancient ok=0",
                 seed_failed_vh_row(db, 1, sc.blocks[1].phashBlock,
                                    "no-header-solution-backfill-required"));
        VH_CHECK("clamp: seed frontier ok=0",
                 seed_failed_vh_row(db, 4, sc.blocks[4].phashBlock,
                                    "no-header-solution-backfill-required"));
        VH_CHECK("clamp: seed frontier hash-mismatch ok=0",
                 seed_failed_vh_row(db, 5, sc.blocks[5].phashBlock,
                                    "header-source-hash-mismatch"));

        /* Forward drain caught up (validate==header_admit==6 ⇒ step_once runs
         * the recheck), and the pipeline is durably BLOCKED at height 4
         * (tip_finalize and body_fetch cursors both 4). */
        VH_CHECK("clamp: set validate cursor",
                 set_stage_cursor(db, "validate_headers", 6));
        VH_CHECK("clamp: set header_admit cursor",
                 set_stage_cursor(db, "header_admit", 6));
        VH_CHECK("clamp: set tip_finalize frontier",
                 set_stage_cursor(db, "tip_finalize", 4));
        VH_CHECK("clamp: set body_fetch frontier",
                 set_stage_cursor(db, "body_fetch", 4));
        VH_CHECK("clamp: seed frontier repair header",
                 seed_repair_header_for_block(db, &sc.blocks[4],
                                              &sc.hashes[4]));

        /* Reopen so the never-persisted in-process recheck floor starts at 0 —
         * the exact fresh-boot condition under which the ancient row used to
         * pin it. Cursors reload from the table (validate/header_admit = 6). */
        validate_headers_stage_shutdown();
        header_admit_stage_shutdown();
        progress_store_close();
        VH_CHECK("clamp: reopen", progress_store_open(dir));
        VH_CHECK("clamp: re-init admit", header_admit_stage_init(&ms));
        VH_CHECK("clamp: re-init validate", validate_headers_stage_init(&ms));
        validate_headers_stage_set_validator(stub_pass, NULL);
        db = progress_store_db();

        /* One step: recheck clamps the scan to [4,6), reaches + flips the
         * frontier row. */
        VH_CHECK("clamp: step reaches + flips frontier",
                 validate_headers_stage_step_once() == JOB_ADVANCED);

        int ok = -1;
        VH_CHECK("clamp: frontier h=4 now ok=1",
                 log_row_at(db, 4, &ok, NULL, 0) && ok == 1);
        ok = -1;
        VH_CHECK("clamp: hash-mismatch h=5 waits for repair header",
                 log_row_at(db, 5, &ok, NULL, 0) && ok == 0);

        VH_CHECK("clamp: seed hash-mismatch repair header",
                 seed_repair_header_for_block(db, &sc.blocks[5],
                                              &sc.hashes[5]));
        VH_CHECK("clamp: hash-mismatch recheck fires after repair header",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        ok = -1;
        VH_CHECK("clamp: hash-mismatch frontier h=5 now ok=1",
                 log_row_at(db, 5, &ok, NULL, 0) && ok == 1);

        /* Load-bearing assertion: the ancient h=1 row was clamped OUT of the
         * scan window, so it is untouched — still ok=0. Without the clamp the
         * same batch would have scanned [0,6) and flipped h=1 under stub_pass
         * (and with >VH_BATCH_SIZE ancient rows would have starved h=4). */
        ok = -1;
        VH_CHECK("clamp: ancient h=1 excluded — still ok=0",
                 log_row_at(db, 1, &ok, NULL, 0) && ok == 0);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── stale high recheck floor: live frontier wins downward too ───────
     * Regression for the soak-lane wedge at 3169601: the in-process
     * failure_recheck_cursor had advanced to the validate_headers cursor while
     * body_fetch/tip_finalize were still pinned at the live frontier. Once a
     * repairable ok=0 row appeared at that frontier, the recheck used to keep
     * start=validated_cursor and never looked back. The durable executable
     * frontier must lower that stale in-memory floor as well as raise ancient
     * floors. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("stale-high-floor: setup",
                 vh_setup("stale_high_floor", 6, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        sqlite3 *db = progress_store_db();

        VH_CHECK("stale-high-floor: set validate cursor",
                 set_stage_cursor(db, "validate_headers", 6));
        VH_CHECK("stale-high-floor: set header_admit cursor",
                 set_stage_cursor(db, "header_admit", 6));
        VH_CHECK("stale-high-floor: set tip_finalize frontier",
                 set_stage_cursor(db, "tip_finalize", 4));
        VH_CHECK("stale-high-floor: set body_fetch frontier",
                 set_stage_cursor(db, "body_fetch", 4));

        validate_headers_stage_shutdown();
        header_admit_stage_shutdown();
        progress_store_close();
        VH_CHECK("stale-high-floor: reopen", progress_store_open(dir));
        VH_CHECK("stale-high-floor: re-init admit",
                 header_admit_stage_init(&ms));
        VH_CHECK("stale-high-floor: re-init validate",
                 validate_headers_stage_init(&ms));
        validate_headers_stage_set_validator(stub_pass, NULL);
        db = progress_store_db();

        VH_CHECK("stale-high-floor: empty recheck advances memory floor",
                 validate_headers_stage_step_once() == JOB_IDLE);
        VH_CHECK("stale-high-floor: seed stranded frontier row",
                 seed_failed_vh_row(db, 4, sc.blocks[4].phashBlock,
                                    "no-header-solution-backfill-required"));
        VH_CHECK("stale-high-floor: seed stranded repair header",
                 seed_repair_header_for_block(db, &sc.blocks[4],
                                              &sc.hashes[4]));

        VH_CHECK("stale-high-floor: lowered floor reaches stranded row",
                 validate_headers_stage_step_once() == JOB_ADVANCED);
        int ok = -1;
        VH_CHECK("stale-high-floor: frontier h=4 now ok=1",
                 log_row_at(db, 4, &ok, NULL, 0) && ok == 1);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── Task A #12: hash-mismatch recheck row with no repair pins the floor ──
     * A "header-source-hash-mismatch" failed row whose repair table entry is
     * NOT yet present is a recheck candidate but not recheck-ready. Before the
     * fix its `continue` left first_unresolved unset, so when it was the ONLY
     * selected recheck row the n==0 idle_floor jumped to validated_cursor —
     * skipping the recheck PAST a height whose failed-row mask is still
     * unrepaired. The floor must instead pin AT that unresolved height.
     * Constructed with tip_finalize/body_fetch cursors at 0 so the durable-
     * frontier anchor does not mask the in-process floor (frontier<=0 path). */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("recheck-floor-pin: setup",
                 vh_setup("recheck_floor_pin", 5, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        sqlite3 *db = progress_store_db();

        /* One unrepaired hash-mismatch row at h=2, no repair header seeded so
         * vh_hash_mismatch_recheck_ready() stays false. validate cursor at 5
         * makes it the only selectable recheck candidate; tip_finalize and
         * body_fetch cursors left at 0 so frontier<=0 and start = the in-process
         * floor (g_failure_recheck_cursor, reset to 0 on init). */
        VH_CHECK("recheck-floor-pin: seed unrepaired hash-mismatch row at h=2",
                 seed_failed_vh_row(db, 2, sc.blocks[2].phashBlock,
                                    "header-source-hash-mismatch"));
        VH_CHECK("recheck-floor-pin: set validate cursor to 5",
                 set_stage_cursor(db, "validate_headers", 5));
        VH_CHECK("recheck-floor-pin: floor starts at 0",
                 validate_headers_stage_recheck_floor_for_test() == 0);

        /* Forward step is IDLE (header_admit floor), so the recheck runs; the
         * lone candidate is skipped (not repair-ready) → n==0 idle_floor. */
        VH_CHECK("recheck-floor-pin: recheck holds (row not repair-ready)",
                 validate_headers_stage_step_once() == JOB_IDLE);

        /* THE FIX: the floor is pinned at the still-unresolved height (2), NOT
         * skipped forward to validated_cursor (5). Pre-fix this read 5, and the
         * next pass would never revisit h=2 after its repair landed. */
        VH_CHECK("recheck-floor-pin: floor pinned at unresolved height (2)",
                 validate_headers_stage_recheck_floor_for_test() == 2);
        VH_CHECK("recheck-floor-pin: floor did NOT skip to validated_cursor (5)",
                 validate_headers_stage_recheck_floor_for_test() != 5);

        vh_teardown(dir, &ms, &sc);
    }

    /* ── Gap C: on-demand single-header pass-record (the instant-on seam) ───
     * validate_headers_stage_ensure_pass_record resolves the header at a height,
     * runs the configured validator (the stage's g_validator, else the default),
     * and durably records a PASS row on success — the mechanism that gives a
     * headers-first (--importblockindex) substrate the checkpoint-header pass
     * record the -4 header-bootstrap bind needs, without running the whole
     * forward stage. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("ensure-pass: setup",
                 vh_setup("ensure_pass_record", 8, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        /* Drive ensure_pass_record's validator branch with the passing stub. */
        validate_headers_ensure_set_validator_for_test(stub_pass, NULL);
        sqlite3 *db = progress_store_db();

        VH_CHECK("ensure-pass: h=5 has no pass record initially",
                 !validate_headers_stage_has_pass_record(5, &sc.hashes[5]));
        VH_CHECK("ensure-pass: ensure_pass_record(h=5) -> true",
                 validate_headers_stage_ensure_pass_record(&ms, 5));
        VH_CHECK("ensure-pass: h=5 pass record now present",
                 validate_headers_stage_has_pass_record(5, &sc.hashes[5]));
        int rows_after = log_row_count(db);
        VH_CHECK("ensure-pass: exactly one row written",
                 rows_after == 1);

        /* Idempotent: a second call returns true and writes no extra row. */
        VH_CHECK("ensure-pass: idempotent second call -> true",
                 validate_headers_stage_ensure_pass_record(&ms, 5));
        VH_CHECK("ensure-pass: idempotent -> no extra log row",
                 log_row_count(db) == rows_after);

        /* Absent height (above the header tip, no header index) -> false. */
        VH_CHECK("ensure-pass: absent height -> false",
                 !validate_headers_stage_ensure_pass_record(&ms, 999));
        /* Null ms / negative height fail closed. */
        VH_CHECK("ensure-pass: null ms -> false",
                 !validate_headers_stage_ensure_pass_record(NULL, 5));
        VH_CHECK("ensure-pass: negative height -> false",
                 !validate_headers_stage_ensure_pass_record(&ms, -1));

        validate_headers_ensure_set_validator_for_test(NULL, NULL);
        vh_teardown(dir, &ms, &sc);
    }

    /* A FAILING validator (wrong-block / PoW-invalid header) writes NO pass
     * record and returns false — the header-bootstrap bind then still refuses. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        struct fail_at_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.fail_height = 4;
        ctx.reason = "stub-injected-failure";
        VH_CHECK("ensure-fail: setup",
                 vh_setup("ensure_pass_fail", 8, NULL, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        validate_headers_ensure_set_validator_for_test(stub_fail_at, &ctx);
        VH_CHECK("ensure-fail: failing validator -> false",
                 !validate_headers_stage_ensure_pass_record(&ms, 4));
        VH_CHECK("ensure-fail: failing validator wrote no pass record",
                 !validate_headers_stage_has_pass_record(4, &sc.hashes[4]));
        VH_CHECK("ensure-fail: no rows written at all",
                 log_row_count(progress_store_db()) == 0);
        validate_headers_ensure_set_validator_for_test(NULL, NULL);
        vh_teardown(dir, &ms, &sc);
    }

    /* A fresh-genesis reset can lower pindex_best_header while the imported
     * checkpoint header remains in the map. The baked height+hash may recover
     * that header, but no arbitrary height may use the fallback. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_vh sc;
        VH_CHECK("ensure-map-fallback: setup",
                 vh_setup("ensure_pass_mapfb", 4, stub_pass, NULL,
                          dir, sizeof(dir), &ms, &sc) == 0);
        validate_headers_ensure_set_validator_for_test(stub_pass, NULL);

        const int32_t cp_height = 9000;
        struct uint256 cp_hash;
        memset(&cp_hash, 0, sizeof(cp_hash));
        cp_hash.data[0] = 0xAB;
        cp_hash.data[31] = 0x09;
        struct block_index *cp = chainstate_insert_block_index(
            (struct chainstate *)&ms, &cp_hash);
        VH_CHECK("ensure-map-fallback: checkpoint in map", cp != NULL);
        cp->nHeight = cp_height;
        cp->nVersion = 4;
        ms.pindex_best_header = NULL;

        struct sha3_utxo_checkpoint override;
        memset(&override, 0, sizeof(override));
        override.height = cp_height;
        memcpy(override.block_hash, cp_hash.data, 32);
        checkpoints_set_sha3_override_for_test(&override);
        VH_CHECK("ensure-map-fallback: baked checkpoint validates from map",
                 validate_headers_stage_ensure_pass_record(&ms, cp_height));
        VH_CHECK("ensure-map-fallback: pass fact is durable",
                 validate_headers_stage_has_pass_record(cp_height, &cp_hash));
        VH_CHECK("ensure-map-fallback: arbitrary height remains unresolved",
                 !validate_headers_stage_ensure_pass_record(&ms,
                                                            cp_height + 1));

        checkpoints_reset_sha3_override_for_test();
        validate_headers_ensure_set_validator_for_test(NULL, NULL);
        vh_teardown(dir, &ms, &sc);
    }

    /* Genesis exemption: the loader's synthetic genesis entry (inserted on
     * an empty index with nVersion=0 and no solution — block_index_loader.c)
     * must PASS the validator by construction — its hash IS the consensus
     * pin — while a non-genesis block in the exact same state must still
     * fail version-too-low. Regression for the 2026-07-27 wipe-to-tip
     * reducer wedge (validate_headers terminal-failed h=0, proof_validate
     * dead-waited, H*=0 forever). */
    {
        const struct chain_params *cp = chain_params_get();
        VH_CHECK("genesis-exempt: chain params available", cp != NULL);
        struct block_index gen;
        memset(&gen, 0, sizeof(gen));
        gen.hashBlock = cp->consensus.hashGenesisBlock;
        gen.phashBlock = &gen.hashBlock;
        gen.nHeight = 0;
        gen.nVersion = 0;                 /* the synthetic stub's poison */
        char reason[VH_MAX_REASON] = {0};
        VH_CHECK("genesis-exempt: v0 synthetic genesis validates",
                 validate_headers_default_validator(&gen, NULL, reason,
                                                  sizeof(reason), NULL));

        struct block_index nongen = gen;
        nongen.hashBlock.data[0] ^= 0xff; /* same state, no longer genesis */
        nongen.phashBlock = &nongen.hashBlock; /* repoint: the copy inherited
                                                * gen's self-pointer */
        memset(reason, 0, sizeof(reason));
        VH_CHECK("genesis-exempt: v0 non-genesis still fails version-too-low",
                 !validate_headers_default_validator(&nongen, NULL, reason,
                                                     sizeof(reason), NULL) &&
                     strcmp(reason, "version-too-low") == 0);
    }

    printf("validate_headers_stage: %d failures\n", failures);
    return failures;
}
