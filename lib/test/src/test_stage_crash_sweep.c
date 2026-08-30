/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_stage_crash_sweep — DETERMINISTIC kill -9 sweep across EVERY
 * stage-batch commit boundary of the real eight-stage reducer pipeline.
 *
 * Why this is a distinct proof from test_kill9_recovery.c /
 * test_fold_inram_crash_proof.c
 * -----------------------------------------------------------------------
 * Those two harnesses SIGKILL a forked child after a randomised wall-clock
 * delay (test_kill9_recovery), or at a small, hand-picked set of points
 * inside ONE stage (test_fold_inram_crash_proof's three fixed utxo_apply
 * heights). Both are real and valuable, but neither systematically proves
 * "a kill -9 at ANY commit boundary, in ANY of the eight stages, always
 * resumes without losing or repeating work" — a timing race only SAMPLES
 * the boundary space, and a hand-picked set only covers one stage.
 *
 * This harness instead uses the in-process, test-only crash-point hook
 * `stage_set_test_commit_boundary_hook()` (lib/util/src/stage.c /
 * util/stage.h) that `stage_run_once()` — the single seam every one of
 * the eight reducer stages funnels through — consults immediately BEFORE
 * its per-step commit. The hook is called with a monotonically
 * increasing, purely ORDINAL sequence number (not a timestamp), so a test
 * can request "crash exactly at the Nth commit boundary" and get it
 * deterministically, every run, regardless of machine speed. Sweeping N
 * across [0, G) where G is the total boundary count of an uninterrupted
 * "golden" run therefore covers EVERY commit boundary the pipeline
 * produces for the fixture — header_admit, validate_headers, body_fetch,
 * body_persist, script_validate, proof_validate, utxo_apply, and
 * tip_finalize alike — not a sample of them.
 *
 * Fixture + drive pattern
 * ------------------------
 * A tiny (SCS_N_BLOCKS) regtest chain built the same way
 * test_fold_inram_crash_proof.c's `fip_*` helpers do — real mine_block_pow,
 * real header_admit/validate_headers/body_fetch/body_persist/
 * script_validate/proof_validate/utxo_apply/tip_finalize stages, real
 * reducer_kick_unbudgeted drive — duplicated here (not shared) for the
 * same reason test_kill9_recovery.c's header documents: independent test
 * files stay independent. The crash hook is armed BEFORE fixture setup so
 * header_admit's own commits are swept too, not just the later stages'.
 *
 * One cycle for crash point N:
 *   1. GOLDEN (N == -1, done once): fold to completion uninterrupted;
 *      record the terminal digest (all eight stage cursors + coins_kv
 *      row count) and the total boundary count G the hook observed.
 *   2. CRASHER: fork a child, arm the hook with crash_at = N, fold the
 *      SAME fixture from a fresh datadir. The hook calls raise(SIGKILL)
 *      the instant boundary N is reached — the step's cursor write and
 *      output are staged but UNCOMMITTED, so this is indistinguishable
 *      from a real kill -9 landing there (SQLite's WAL recovery discards
 *      the uncommitted transaction on next open).
 *   3. RESUMER: fork a FRESH process pointed at the same (crash-truncated)
 *      datadir. It rebuilds the deterministic fixture (headers/bodies are
 *      reproducible bit-for-bit from height) and drives to completion,
 *      recording its OWN terminal digest and how many boundaries ITS OWN
 *      run consulted the hook for (R).
 *   4. Assert:
 *      (a) resumer digest == golden digest — final tip height and stage
 *          cursors match the uninterrupted run exactly.
 *      (b) resumer coins_kv row count == golden row count — no duplicate
 *          side effects (folded in (a)'s digest).
 *      (c) R == G - N EXACTLY — the resumer redid precisely the boundaries
 *          that were never committed (boundary N itself, plus everything
 *          after) and NOT ONE MORE: if a bug re-folded any already-durable
 *          height, that height's stage would go JOB_ADVANCED again and R
 *          would exceed G-N; if a bug skipped required work, R would fall
 *          short of G-N or the digest in (a) would diverge.
 *
 * Determinism: N sweeps every integer in [0, G) in order — no RNG, no
 * wall-clock. SCS_N_BLOCKS is kept tiny so G stays in the "dozens" range
 * (measured, not tuned to a hardcoded expectation).
 *
 * Why there is no wall-clock budget
 * ---------------------------------
 * This harness used to abort the sweep and count a FAILURE when its elapsed
 * time passed a 30-second ceiling. That was a performance assertion wearing a
 * correctness assertion's clothes, and it behaved like one: 29/29 crash points
 * in 9s on an idle box, a hard FAIL at n=18/29 under load average 42 on the
 * same 32-core machine — on branches that do not touch any code this harness
 * exercises. It also silently WEAKENED the proof exactly when it fired, since
 * aborting at n=18 leaves boundaries 18..28 unswept.
 *
 * What the budget was really guarding is bounded work, and work here is
 * countable without consulting a clock:
 *
 *   - G itself is bounded by SCS_MAX_BOUNDARIES (see below) — the pipeline
 *     may not commit more than once per (stage, height).
 *   - The sweep's total work is then FORCED: cycle n's resumer redoes exactly
 *     G-n boundaries (assertion (c)), so summed over the sweep the resumer
 *     side performs exactly G*(G+1)/2 boundary commits. That total is
 *     asserted directly. A regression that made any cycle redo more work
 *     inflates it; one that skipped work deflates it. Neither can hide behind
 *     a fast machine, and neither can be manufactured by a slow one.
 *
 * Hangs are still caught: the suite runner (lib/test/src/test_parallel.c)
 * SIGKILLs any group exceeding its per-group timeout (300s by default), so an
 * in-test stopwatch was never what stood between a wedged fold and a wedged
 * suite. If you want a genuine performance guard, set ZCL_TEST_PERF_BUDGET_SEC
 * to a positive integer — it is opt-in, off in the default suite, and it fails
 * loudly rather than truncating the sweep.
 *
 * Batch-vs-boundary invariant
 * ----------------------------
 * Driving the fixture through
 * reducer_kick_unbudgeted at its PRODUCTION batch cadence
 * (ZCL_REFOLD_DRAIN_BATCH, default 2000; the steady-state supervisor path
 * defaults to 100) fails assertion (c) at every N that lands inside
 * an open batch: the resumer correctly redoes a WHOLE uncommitted batch
 * (never less, never more than that), which is MORE than G-N when N isn't
 * itself a batch-end boundary. Assertions (a) and (b) — final digest and
 * no duplicate side effects — hold regardless;
 * only the "redid exactly G-N" optimality check
 * fails at a mid-batch crash point. Root cause: `stage_run_once`'s per-step commit is a real SQL
 * COMMIT only when unbatched; inside a drain driver's open
 * stage_batch_begin/end window (see util/stage.h + stage.c's "Batched
 * drain" doc comment) each step is a SAVEPOINT, and only the outer batch's
 * end is a real COMMIT — so a hook-observed "boundary" mid-batch is not
 * itself durable. This is a deliberate, pre-existing fsync-amortization
 * design (also documented in MEMORY.md "Drain batch commits"), not a
 * defect: a kill -9 during accelerated bulk-fold redoes at most one
 * batch's worth of CPU-bound re-verification, never loses or duplicates
 * any COMMITted row. test_stage_crash_sweep now pins
 * ZCL_REFOLD_DRAIN_BATCH=1 (see test_stage_crash_sweep()) so every
 * hook-observed boundary IS a real COMMIT, proving the strongest, most
 * literal form of the guarantee — every SQL COMMIT the fold performs, not
 * just every batch — while leaving the production default (and the
 * batching optimization itself) untouched.
 *
 * make t ONLY=stage_crash_sweep
 */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "config/boot.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "domain/consensus/coinbase.h"
#include "json/json.h"
#include "mining/miner.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/chain_activation_service.h"
#include "services/header_admit_inbox.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/event_log.h"
#include "storage/progress_store.h"
#include "storage/snapshot_shielded.h"
#include "jobs/header_admit_stage.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/stage_helpers.h"
#include "jobs/mint_fold_ceiling.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "util/util.h"
#include "validation/accept_block_header.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/main_constants.h"
#include "validation/main_state.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SCS_N_BLOCKS   4

/* Structural ceiling on G, the golden run's total commit-boundary count.
 *
 * This replaces an elapsed-seconds budget that used to abort the sweep (see
 * "Why there is no wall-clock budget" in the file header). The thing that can
 * actually blow this harness up is the BOUNDARY COUNT, not the clock: the
 * sweep runs one crasher + one resumer fork per boundary, so its total work is
 * quadratic in G. With ZCL_REFOLD_DRAIN_BATCH=1 every hook-observed boundary
 * is one real COMMIT, and the pipeline's contract is at most one commit per
 * (stage, height) — eight stages over SCS_N_BLOCKS heights, plus a margin of
 * one height's worth for seed/init commits. Exceeding that means a stage
 * started committing per-row, or re-folding heights, or the cadence knob
 * stopped being honoured. Every one of those is a real defect, and every one
 * of them trips this bound identically on an idle box and a saturated one. */
#define SCS_MAX_BOUNDARIES (8 * (SCS_N_BLOCKS + 1))

#define SCS_CHECK(name, expr) do {                        \
    printf("  stage_crash_sweep: %s... ", (name));          \
    if ((expr)) printf("OK\n");                              \
    else { printf("FAIL\n"); failures++; }                   \
} while (0)

static bool scs_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return true;
    return errno == EEXIST;
}

/* One-coinbase regtest block, real merkle root, regtest powLimit nBits —
 * identical shape to test_fold_inram_crash_proof.c's fip_build_regtest_block
 * (duplicated per the project's own "independent test files stay
 * independent" convention; see test_kill9_recovery.c's header). */
static bool scs_build_regtest_block(struct block *blk, int height,
                                    const struct uint256 *prev_hash,
                                    const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "scs_vtx");
    if (!blk->vtx)
        return false;
    blk->num_vtx = 1;

    struct transaction *coinbase = &blk->vtx[0];
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1))
        return false;

    struct script miner_script;
    script_init(&miner_script);
    miner_script.data[0] = 0x76; /* OP_DUP        */
    miner_script.data[1] = 0xa9; /* OP_HASH160    */
    miner_script.data[2] = 0x14; /* push 20       */
    for (int i = 0; i < 20; i++)
        miner_script.data[3 + i] = (unsigned char)(0x50 + i);
    miner_script.data[23] = 0x88; /* OP_EQUALVERIFY */
    miner_script.data[24] = 0xac; /* OP_CHECKSIG    */
    miner_script.size = 25;

    int64_t subsidy = get_block_subsidy(height, &cp->consensus);
    struct domain_consensus_coinbase_inputs cb_in = {
        .n_height     = height,
        .subsidy      = subsidy,
        .total_fees   = 0,
        .miner_script = &miner_script,
        .params       = &cp->consensus,
    };
    struct zcl_result r = domain_consensus_coinbase_build(&cb_in, coinbase);
    if (!r.ok)
        return false;

    struct uint256 txid = blk->vtx[0].hash;
    blk->header.hashMerkleRoot = compute_merkle_root(&txid, 1);
    blk->header.hashPrevBlock = *prev_hash;
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1700100000u + (uint32_t)height;

    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);
    return true;
}

static bool scs_seed_genesis_utxo_apply_row(sqlite3 *db)
{
    if (!db) return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO utxo_apply_log "
        "(height,status,ok,spent_count,added_count,total_value_delta,applied_at) "
        "VALUES(0,'verified',1,0,0,0,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = (sqlite3_step(st) == SQLITE_DONE);  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

struct scs_fixture {
    struct main_state ms;
    struct chain_activation_controller ctl;
    const struct chain_params *cp;
    char netdir[512];
};

/* Build the fixture: genesis + SCS_N_BLOCKS regtest blocks, all eight
 * reducer stages initialised, headers admitted (durably, via the real
 * mailbox + header_admit_stage_drain — so its commits participate in the
 * boundary sweep exactly like the other seven stages), bodies persisted,
 * fold ceiling set. Safe to call again on an already-populated (or
 * crash-truncated) datadir: block_index is rebuilt in-memory from
 * scratch every call (deterministic from height + prev-hash), and every
 * durable write here (header_admit's stage cursor, body files) is either
 * naturally idempotent (header_admit's own cursor gate no-ops on an
 * already-admitted height) or unconditionally deterministic (body bytes
 * are pure functions of height) — the same resume contract
 * test_fold_inram_crash_proof.c's fip_setup documents. */
static bool scs_setup(const char *dir, int n_blocks, struct scs_fixture *fx)
{
    memset(fx, 0, sizeof(*fx));

    scs_mkdir_p("./test-tmp");
    if (!scs_mkdir_p(dir)) return false;
    SetDataDir(dir);
    GetDataDir(true, fx->netdir, sizeof(fx->netdir));
    if (!scs_mkdir_p(fx->netdir)) return false;
    char blocksdir[700];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", fx->netdir);
    if (!scs_mkdir_p(blocksdir)) return false;

    if (!progress_store_open(dir)) return false;

    chain_params_select(CHAIN_REGTEST);
    fx->cp = chain_params_get();
    main_state_init(&fx->ms);

    struct uint256 genesis_hash = fx->cp->consensus.hashGenesisBlock;
    struct block_index *genesis = chainstate_insert_block_index(
        (struct chainstate *)&fx->ms, &genesis_hash);
    if (!genesis) return false;
    genesis->nHeight = 0;
    genesis->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    genesis->nTx = 1;
    genesis->nChainTx = 1;
    genesis->nChainWork = GetBlockProof(genesis);
    active_chain_move_window_tip(&fx->ms.chain_active, genesis);
    fx->ms.pindex_best_header = genesis;

    bool stages_ok =
        header_admit_stage_init(&fx->ms) &&
        validate_headers_stage_init(&fx->ms) &&
        body_fetch_stage_init(&fx->ms) &&
        body_persist_stage_init(&fx->ms) &&
        script_validate_stage_init(&fx->ms) &&
        proof_validate_stage_init(&fx->ms) &&
        utxo_apply_stage_init(&fx->ms) &&
        tip_finalize_stage_init(&fx->ms);
    if (!stages_ok) return false;

    if (!scs_seed_genesis_utxo_apply_row(progress_store_db())) return false;
    if (!tip_finalize_stage_seed_anchor(0, genesis_hash.data, false)) return false;

    mint_fold_ceiling_set(n_blocks);

    struct uint256 prev_hash = genesis_hash;
    for (int h = 1; h <= n_blocks; h++) {
        struct block blk;
        if (!scs_build_regtest_block(&blk, h, &prev_hash, fx->cp)) return false;
        if (!mine_block_pow(&blk, h, fx->cp, 0)) { block_free(&blk); return false; }

        struct uint256 hh;
        block_get_hash(&blk, &hh);

        struct block_index *bi = add_to_block_index(&fx->ms, &blk.header);
        if (!bi || !bi->phashBlock) { block_free(&blk); return false; }
        if ((bi->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE)
            bi->nStatus = (bi->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_TREE;
        fx->ms.pindex_best_header = bi;

        struct header_admit_msg m;
        memset(&m, 0, sizeof(m));
        m.hash = hh;
        m.has_header = true;
        m.header = blk.header;
        m.height = -1;
        if (!mailbox_header_admit_push(&m)) { block_free(&blk); return false; }
        (void)header_admit_stage_drain(50);

        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        bool persisted = write_block_to_disk(&blk, &pos, fx->netdir,
                                             fx->cp->pchMessageStart) &&
                         block_index_set_have_data_verified(bi, &pos, fx->netdir);
        block_free(&blk);
        if (!persisted) return false;

        prev_hash = hh;
    }

    activation_controller_init(&fx->ctl, &fx->ms, NULL, fx->cp, fx->netdir);
    return true;
}

/* ── Test-only commit-boundary hook wiring ─────────────────────────────
 *
 * `g_crash_at` and `g_seen` are per-PROCESS (each cycle forks a fresh
 * process, so there is exactly one meaningful value of each per run — no
 * cross-cycle state to reset). `g_crash_at < 0` means "never crash"
 * (golden + resumer runs); the hook then just counts. */
static int64_t g_crash_at = -1;
static uint64_t g_seen = 0;

static void scs_boundary_hook(const char *stage_name, uint64_t seq)
{
    (void)stage_name;
    g_seen = seq + 1;
    if (g_crash_at >= 0 && seq == (uint64_t)g_crash_at) {
        fflush(NULL);
        raise(SIGKILL);
        /* Should never return — if the signal is somehow held off, fall
         * through and let the caller's WIFSIGNALED check fail loudly
         * rather than silently continuing past the intended crash point. */
        struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
        nanosleep(&ts, NULL);
    }
}

/* Fold the fixture at `dir` to completion (all eight stage cursors reach
 * n_blocks+1) or exhaust max_rounds. `crash_at < 0` disarms the crash;
 * otherwise the hook self-SIGKILLs exactly at that boundary ordinal.
 * `*out_seen` (if non-NULL) receives the number of boundaries THIS
 * process's hook observed before returning (or before being killed, in
 * which case the process never reaches the return). */
static bool scs_run_to_completion(const char *dir, int n_blocks,
                                  int64_t crash_at, uint64_t *out_seen)
{
    g_crash_at = crash_at;
    g_seen = 0;
    stage_set_test_commit_boundary_hook(scs_boundary_hook);

    struct scs_fixture fx;
    if (!scs_setup(dir, n_blocks, &fx)) {
        stage_set_test_commit_boundary_hook(NULL);
        return false;
    }

    /* Completion signal: utxo_apply's cursor, not tip_finalize's. tip_finalize
     * uses a one-block LOOKAHEAD (finalize H by observing H+1 exists — see
     * jobs/stage_helpers.h's reducer_extend_window_to_candidate doc), so on a
     * finite, closed fixture chain with no successor to the last block it can
     * never finalize that last height — it is permanently (and correctly)
     * one behind. utxo_apply_stage_cursor() reaching n_blocks+1 is the same
     * completion signal test_fold_inram_crash_proof.c's fip_drive_to_completion
     * uses for exactly this reason. tip_finalize's cursor is still captured in
     * the terminal digest below (golden vs resumer must still agree on
     * whatever value it settles at — n_blocks, one behind — not on it
     * reaching n_blocks+1). */
    bool done = false;
    for (int i = 0; i < 20000; i++) {
        if (utxo_apply_stage_cursor() >= (uint64_t)(n_blocks + 1)) {
            done = true;
            break;
        }
        (void)reducer_kick_unbudgeted(&fx.ctl);
    }

    stage_set_test_commit_boundary_hook(NULL);
    if (out_seen) *out_seen = g_seen;
    return done;
}

/* Terminal digest: the eight stage cursors + the coins_kv row count — the
 * exact facts assertion (a)/(b) in the file header compare. */
struct scs_digest {
    uint64_t cursor[8];
    int64_t  coins_count;
};

static void scs_capture_digest(struct scs_digest *d)
{
    d->cursor[0] = header_admit_stage_cursor();
    d->cursor[1] = validate_headers_stage_cursor();
    d->cursor[2] = body_fetch_stage_cursor();
    d->cursor[3] = body_persist_stage_cursor();
    d->cursor[4] = script_validate_stage_cursor();
    d->cursor[5] = proof_validate_stage_cursor();
    d->cursor[6] = utxo_apply_stage_cursor();
    d->cursor[7] = tip_finalize_stage_cursor();
    d->coins_count = coins_kv_count(progress_store_db());
}

static bool scs_digest_equal(const struct scs_digest *a, const struct scs_digest *b)
{
    for (int i = 0; i < 8; i++)
        if (a->cursor[i] != b->cursor[i]) return false;
    return a->coins_count == b->coins_count;
}

static bool scs_write_result(const char *path, const struct scs_digest *d,
                             uint64_t seen, bool done)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fprintf(f, "%d %llu", done ? 1 : 0, (unsigned long long)seen);
    for (int i = 0; i < 8; i++)
        fprintf(f, " %llu", (unsigned long long)d->cursor[i]);
    fprintf(f, " %lld\n", (long long)d->coins_count);
    fclose(f);
    return true;
}

static bool scs_read_result(const char *path, struct scs_digest *d,
                            uint64_t *seen, bool *done)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    int done_i = 0;
    unsigned long long seen_u = 0;
    unsigned long long c[8];
    long long coins = 0;
    int n = fscanf(f, "%d %llu %llu %llu %llu %llu %llu %llu %llu %llu %lld",
                  &done_i, &seen_u,
                  &c[0], &c[1], &c[2], &c[3], &c[4], &c[5], &c[6], &c[7],
                  &coins);
    fclose(f);
    if (n != 11) return false;
    *done = done_i != 0;
    *seen = (uint64_t)seen_u;
    for (int i = 0; i < 8; i++)
        d->cursor[i] = (uint64_t)c[i];
    d->coins_count = (int64_t)coins;
    return true;
}

/* ── Golden run: uninterrupted fold, records the terminal digest every
 * crash cycle below must reproduce, and G (the total boundary count). ── */
static bool scs_golden_run(const char *dir, struct scs_digest *out_digest,
                           uint64_t *out_g)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return false; }
    if (pid == 0) {
        uint64_t seen = 0;
        bool done = scs_run_to_completion(dir, SCS_N_BLOCKS, -1, &seen);
        struct scs_digest d;
        scs_capture_digest(&d);
        char res[320];
        snprintf(res, sizeof(res), "%s.result", dir);
        bool wrote = scs_write_result(res, &d, seen, done);
        _exit((done && wrote) ? 0 : 1);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0))
        return false;

    char res[320];
    snprintf(res, sizeof(res), "%s.result", dir);
    bool done = false;
    bool ok = scs_read_result(res, out_digest, out_g, &done);
    unlink(res);
    return ok && done;
}

/* One crash-at-N cycle: fork a crasher (self-SIGKILLs at boundary N), then
 * a resumer (fresh process, same datadir). Returns true iff every
 * assertion for this N held (failures already printed on mismatch).
 * `out_rseen` receives the number of commit boundaries THIS cycle's resumer
 * performed (0 when the cycle could not produce one) so the caller can total
 * the sweep's work and check it against the forced analytic value. */
static bool scs_cycle(const char *base_dir, int64_t n, uint64_t g,
                      const struct scs_digest *golden, uint64_t *out_rseen)
{
    if (out_rseen) *out_rseen = 0;
    char dir[300];
    snprintf(dir, sizeof(dir), "%s_n%" PRId64, base_dir, n);
    test_rm_rf_recursive(dir);

    pid_t pidC = fork();
    if (pidC < 0) { perror("fork"); return false; }
    if (pidC == 0) {
        scs_run_to_completion(dir, SCS_N_BLOCKS, n, NULL);
        /* Only reached if the hook failed to kill us — surface as a
         * distinguishable non-zero exit, never a silent pass. */
        _exit(42);
    }
    int stC = 0;
    if (waitpid(pidC, &stC, 0) != pidC) {
        printf("FAIL (n=%" PRId64 ": waitpid crasher failed)\n", n);
        test_rm_rf_recursive(dir);
        return false;
    }
    bool killed = WIFSIGNALED(stC) && WTERMSIG(stC) == SIGKILL;
    if (!killed) {
        printf("FAIL (n=%" PRId64 ": crasher not terminated by SIGKILL; "
               "WIFSIGNALED=%d WIFEXITED=%d status=%d — the hook never "
               "fired at this boundary)\n",
               n, WIFSIGNALED(stC), WIFEXITED(stC), stC);
        test_rm_rf_recursive(dir);
        return false;
    }

    pid_t pidR = fork();
    if (pidR < 0) { perror("fork"); test_rm_rf_recursive(dir); return false; }
    if (pidR == 0) {
        uint64_t seen = 0;
        bool done = scs_run_to_completion(dir, SCS_N_BLOCKS, -1, &seen);
        struct scs_digest d;
        scs_capture_digest(&d);
        char res[340];
        snprintf(res, sizeof(res), "%s.result", dir);
        bool wrote = scs_write_result(res, &d, seen, done);
        _exit((done && wrote) ? 0 : 1);
    }
    int stR = 0;
    waitpid(pidR, &stR, 0);
    bool resumer_ok = WIFEXITED(stR) && WEXITSTATUS(stR) == 0;
    if (!resumer_ok) {
        printf("FAIL (n=%" PRId64 ": resumer did not reach completion; "
               "WIFEXITED=%d status=%d)\n", n, WIFEXITED(stR), stR);
        test_rm_rf_recursive(dir);
        return false;
    }

    struct scs_digest rd;
    uint64_t rseen = 0;
    bool rdone = false;
    char res[340];
    snprintf(res, sizeof(res), "%s.result", dir);
    bool read_ok = scs_read_result(res, &rd, &rseen, &rdone);
    unlink(res);
    test_rm_rf_recursive(dir);
    if (read_ok && out_rseen) *out_rseen = rseen;

    bool pass = true;
    if (!read_ok) {
        printf("FAIL (n=%" PRId64 ": resumer result unreadable)\n", n);
        pass = false;
    }
    if (read_ok && !scs_digest_equal(&rd, golden)) {
        printf("FAIL (n=%" PRId64 ": terminal digest diverged from golden — "
               "cursors resumed=[%llu %llu %llu %llu %llu %llu %llu %llu] "
               "coins=%lld vs golden=[%llu %llu %llu %llu %llu %llu %llu "
               "%llu] coins=%lld)\n",
               n,
               (unsigned long long)rd.cursor[0], (unsigned long long)rd.cursor[1],
               (unsigned long long)rd.cursor[2], (unsigned long long)rd.cursor[3],
               (unsigned long long)rd.cursor[4], (unsigned long long)rd.cursor[5],
               (unsigned long long)rd.cursor[6], (unsigned long long)rd.cursor[7],
               (long long)rd.coins_count,
               (unsigned long long)golden->cursor[0], (unsigned long long)golden->cursor[1],
               (unsigned long long)golden->cursor[2], (unsigned long long)golden->cursor[3],
               (unsigned long long)golden->cursor[4], (unsigned long long)golden->cursor[5],
               (unsigned long long)golden->cursor[6], (unsigned long long)golden->cursor[7],
               (long long)golden->coins_count);
        pass = false;
    }
    uint64_t expect_seen = g - (uint64_t)n;
    if (read_ok && rseen != expect_seen) {
        printf("FAIL (n=%" PRId64 ": resumer redid %llu boundar%s but "
               "exactly %llu were expected (G=%llu - N=%" PRId64 ") — the "
               "resumer either re-folded already-durable work (redid more) "
               "or failed to fully resume (redid fewer))\n",
               n, (unsigned long long)rseen, rseen == 1 ? "y" : "ies",
               (unsigned long long)expect_seen, (unsigned long long)g, n);
        pass = false;
    }
    return pass;
}

static int test_stage_crash_sweep_platform_arm(void);
static int test_stage_crash_sweep_platform_arm(void)
{
    int failures = 0;
    printf("\n=== test_stage_crash_sweep: deterministic kill -9 sweep "
           "across every reducer stage-batch commit boundary ===\n");

    /* FINDING (see file header "Batch-vs-boundary finding" below): the drive
     * path this harness uses (reducer_kick_unbudgeted, armed by
     * mint_fold_ceiling_set) opens ONE stage_batch_begin/end txn per
     * *_stage_drain() call spanning up to ZCL_REFOLD_DRAIN_BATCH steps
     * (default 2000; the steady-state supervisor path uses 100) — every
     * step in that window is a SAVEPOINT, not a real COMMIT, so the hook's
     * per-step "boundary" is only durable at the OUTER batch's commit, not
     * at each individual seq the hook observes. That is a deliberate,
     * documented fsync-amortization tradeoff (stage.c's own "Batched
     * drain" doc comment; MEMORY.md "Drain batch commits"), not a defect:
     * assertions (a) final-digest and (b) no-duplicate-side-effects hold
     * at EVERY crash point regardless of batch size (verified — see
     * summary). Only assertion (c)'s EXACT "redid == G-N" check requires
     * per-step durability, which requires per-step commits. Force that
     * here via the same production cadence knob refold_cadence.c already
     * exposes for exactly this purpose (inert on a normal live node — see
     * jobs/refold_cadence.h) so this sweep proves the strongest, most
     * literal reading of "kill -9 at ANY commit boundary": every SQL
     * COMMIT this fixture's fold performs, not just every batch. Inherited
     * by every fork()ed golden/crasher/resumer child below (setenv before
     * any fork in this function). */
    setenv("ZCL_REFOLD_DRAIN_BATCH", "1", 1);

    /* Informational only — reported, never asserted on. The one exception is
     * the opt-in ZCL_TEST_PERF_BUDGET_SEC guard at the end, which is unset in
     * the default suite. See "Why there is no wall-clock budget" in the file
     * header. */
    time_t t0 = time(NULL);  // platform-ok:stage-crash-sweep-elapsed-report-only

    char golden_dir[256];
    test_fmt_tmpdir(golden_dir, sizeof(golden_dir), "stage_crash_sweep", "golden");
    test_rm_rf_recursive(golden_dir);

    struct scs_digest golden;
    uint64_t g = 0;
    bool golden_ok = scs_golden_run(golden_dir, &golden, &g);
    test_rm_rf_recursive(golden_dir);
    SCS_CHECK("golden uninterrupted fold completed", golden_ok);
    if (!golden_ok) {
        unsetenv("ZCL_REFOLD_DRAIN_BATCH");
        printf("=== test_stage_crash_sweep complete: %d failure(s), sweep "
               "aborted (no golden reference) ===\n", ++failures);
        return failures;
    }
    printf("  stage_crash_sweep: golden run observed G=%llu commit "
           "boundaries across %d blocks x 8 stages; final cursors="
           "[ha=%llu vh=%llu bf=%llu bp=%llu sv=%llu pv=%llu ua=%llu "
           "tf=%llu] coins=%lld\n",
           (unsigned long long)g, SCS_N_BLOCKS,
           (unsigned long long)golden.cursor[0], (unsigned long long)golden.cursor[1],
           (unsigned long long)golden.cursor[2], (unsigned long long)golden.cursor[3],
           (unsigned long long)golden.cursor[4], (unsigned long long)golden.cursor[5],
           (unsigned long long)golden.cursor[6], (unsigned long long)golden.cursor[7],
           (long long)golden.coins_count);

    SCS_CHECK("golden boundary count is nonzero (the sweep has something "
              "to cover)", g > 0);

    /* THE work bound — deterministic, machine-independent, and the reason no
     * stopwatch is needed. See SCS_MAX_BOUNDARIES. */
    if (g > SCS_MAX_BOUNDARIES)
        printf("  stage_crash_sweep: G=%llu exceeds the structural ceiling "
               "%d = 8 stages x (%d blocks + 1) — some stage is committing "
               "more than once per height, or the per-step commit cadence "
               "(ZCL_REFOLD_DRAIN_BATCH=1) stopped being honoured\n",
               (unsigned long long)g, SCS_MAX_BOUNDARIES, SCS_N_BLOCKS);
    SCS_CHECK("golden boundary count is within the structural ceiling "
              "(at most one commit per stage per height)",
              g <= SCS_MAX_BOUNDARIES);

    char base_dir[256];
    test_fmt_tmpdir(base_dir, sizeof(base_dir), "stage_crash_sweep", "n");

    /* Every crash point is swept, always. Nothing shortens this loop — a
     * truncated sweep is a weaker proof, and "the box was busy" is not a
     * reason to prove less. */
    int n_pass = 0;
    uint64_t resumer_boundaries_total = 0;
    for (int64_t n = 0; n < (int64_t)g; n++) {
        uint64_t rseen = 0;
        bool ok = scs_cycle(base_dir, n, g, &golden, &rseen);
        resumer_boundaries_total += rseen;
        if (ok) n_pass++;
        else failures++;
    }

    /* The sweep's total work, stated as one number. Cycle n's resumer redoes
     * exactly G-n boundaries, so the sum over n in [0,G) is G*(G+1)/2 — forced
     * by the pipeline's resume contract, identical on every machine. This is
     * the operation count the deleted 30-second budget was a proxy for. */
    uint64_t expect_total = g * (g + 1) / 2;
    if (resumer_boundaries_total != expect_total)
        printf("  stage_crash_sweep: resumer work total %llu != forced "
               "G*(G+1)/2 = %llu (G=%llu) — some cycle re-folded durable work "
               "or failed to resume fully\n",
               (unsigned long long)resumer_boundaries_total,
               (unsigned long long)expect_total, (unsigned long long)g);
    SCS_CHECK("sweep resumer work totals exactly G*(G+1)/2 commit boundaries",
              resumer_boundaries_total == expect_total);

    time_t elapsed = time(NULL) - t0;  // platform-ok:stage-crash-sweep-elapsed-report-only
    printf("  stage_crash_sweep: %d/%llu crash points passed, %llu resumer "
           "commit boundaries total, in %llds (elapsed is reported, not "
           "asserted)\n", n_pass, (unsigned long long)g,
           (unsigned long long)resumer_boundaries_total, (long long)elapsed);

    /* Opt-in performance guard. Unset in the default suite, so a loaded box
     * never turns this correctness harness red; set it when you actually want
     * to measure. */
    {
        const char *perf = getenv("ZCL_TEST_PERF_BUDGET_SEC");
        long budget = perf ? strtol(perf, NULL, 10) : 0;
        if (budget > 0) {
            if (elapsed > budget)
                printf("  stage_crash_sweep: PERF sweep took %llds > "
                       "ZCL_TEST_PERF_BUDGET_SEC=%ld\n",
                       (long long)elapsed, budget);
            SCS_CHECK("PERF (opt-in): sweep inside ZCL_TEST_PERF_BUDGET_SEC",
                      elapsed <= budget);
        }
    }

    unsetenv("ZCL_REFOLD_DRAIN_BATCH");

    printf("=== test_stage_crash_sweep complete: %d failure(s) ===\n",
           failures);
    return failures;
}
#else  /* _WIN32 */
/* A kill -9 sweep across reducer stage-batch commit boundaries, driven by
 * fork()+SIGKILL+waitpid children. The Windows kill9 analogue lives in
 * test_kill9_recovery.c (TerminateProcess re-exec lanes); this sweep's
 * per-stage fork machinery is POSIX-only. */
static int test_stage_crash_sweep_platform_arm(void)
{
    printf("stage_crash_sweep: SKIP (Windows): fork+SIGKILL stage sweep "
           "lane; kill9_recovery covers the TerminateProcess analogue\n");
    return 0;
}
#endif

int test_stage_crash_sweep(void)
{
    return test_stage_crash_sweep_platform_arm();
}
