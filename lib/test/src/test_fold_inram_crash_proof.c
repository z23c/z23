/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_fold_inram_crash_proof — the two proof items the fold-IO
 * design (coins_ram in-RAM overlay during -mint-anchor, WAL autocheckpoint
 * held, flush at high-water boundaries — lib/storage/src/coins_ram.c,
 * lib/storage/src/coins_kv.c:coins_kv_overlay_safe,
 * config/src/boot_mint_anchor.c) requires:
 *
 *   (1) DURABLE-vs-INRAM A/B EQUIVALENCE: fold the SAME small regtest fixture
 *       chain genesis..N twice through the REAL 8-stage reducer pipeline —
 *       once with ZCL_FOLD_INRAM=0 (durable coins_kv path) and once with
 *       ZCL_FOLD_INRAM=1 (coins_ram overlay path) — and assert the terminal
 *       states are byte-identical: same coins-set content, same shielded
 *       anchors/nullifier frontier, same total supply, same applied-height.
 *       The comparison is the SAME single SHA3 commitment boot_mint_anchor.c
 *       itself hard-asserts against the compiled checkpoint (coins_kv_
 *       snapshot_write / coins_ram_snapshot_write over the coins set PLUS the
 *       collected shielded frontier), so any divergence between the two
 *       storage paths fails loudly here exactly as it would at a real mint.
 *
 *   (2) CRASH-INJECTION RESUME: with ZCL_FOLD_INRAM=1, fork a child that
 *       folds the same fixture and SIGKILL it at three progress points (right
 *       after the first coins_ram flush boundary, and twice more mid-batch
 *       between flush boundaries), then resume the fold in a FRESH process
 *       pointed at the same (crash-truncated) datadir and prove the terminal
 *       digest equals an uninterrupted run's. This is the WAL/flush-boundary
 *       crash-ordering invariant coins_ram.h documents: an INRAM crash loses
 *       at most the un-flushed overlay tail, never corrupts durable state.
 *
 * FIXTURE: N_BLOCKS (6) tiny regtest (Equihash 48,5) blocks, built the same
 * way test_mint_anchor_fresh_datadir.c's scenario (c) does — real
 * mine_block_pow, real header_admit/validate_headers/body_fetch/body_persist/
 * script_validate/proof_validate/utxo_apply/tip_finalize stages, real
 * reducer_kick_unbudgeted drive. ZCL_FOLD_INRAM_FLUSH_EVERY=2 so the tiny
 * fixture still crosses multiple real flush boundaries.
 *
 * PROCESS MODEL: ZCL_FOLD_INRAM is cached ONCE per process
 * (coins_ram_enabled(), coins_ram.c) — so every leg that needs a SPECIFIC
 * value (the durable leg needs it OFF; every overlay leg needs it ON) runs in
 * its own fork()ed child that has never called coins_ram_enabled() before
 * setting its env. Each child independently rebuilds the (small, fast,
 * deterministic) fixture from scratch — genesis and block content are
 * reproducible bit-for-bit from height + prev-hash + chain params, so a
 * resumer child rebuilding the same headers/bodies on top of a crash-
 * truncated datadir reconstructs the identical in-memory block_index while
 * the durable coins/cursor/flush-watermark state is read back from disk
 * exactly as a real restart would. What this does NOT prove: recovery of the
 * in-memory block_index itself from durable LevelDB storage after a crash —
 * that is a distinct, already-covered concern (test_kill9_recovery.c's
 * MID-IMPORTBLOCKINDEX phase).
 *
 * make t ONLY=fold_inram_crash_proof
 */

#include "test/test_core.h"
#include "coins/undo.h"

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
#include "storage/coins_ram.h"
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
#include "util/util.h"
#include "validation/accept_block_header.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/main_constants.h"
#include "validation/main_state.h"

#include <errno.h>
#include <fcntl.h>
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

#define FIP_N_BLOCKS 6

#define FIP_CHECK(name, expr) do {                              \
    printf("  fold_inram_crash_proof: %s... ", (name));          \
    if ((expr)) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                       \
} while (0)

static bool fip_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0 == 0;
    if (errno == EEXIST) return true;
    return false;
}

/* One-coinbase regtest block, real merkle root, regtest powLimit nBits.
 * Deterministic in every field but nSolution/nNonce (found by mine_block_pow)
 * so an independent process rebuilding the same (height, prev_hash) block
 * reproduces the identical block hash. Mirrors
 * test_mint_anchor_fresh_datadir.c's mfd_build_regtest_block. */
static bool fip_build_regtest_block(struct block *blk, int height,
                                    const struct uint256 *prev_hash,
                                    const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "fip_vtx");
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
        miner_script.data[3 + i] = (unsigned char)(0x30 + i);
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
    blk->header.nTime = 1700000000u + (uint32_t)height;

    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);
    return true;
}

static bool fip_seed_genesis_utxo_apply_row(sqlite3 *db)
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

/* One built fixture: genesis + FIP_N_BLOCKS regtest blocks, all eight
 * reducer stages initialised, headers admitted, bodies persisted, ceiling
 * set at FIP_N_BLOCKS. Ready for the caller to drive utxo_apply/tip_finalize
 * (via reducer_kick_unbudgeted) to fold the chain. */
struct fip_fixture {
    struct main_state ms;
    struct chain_activation_controller ctl;
    const struct chain_params *cp;
    char dir[300];
    char netdir[512];
    uint8_t tip_hash[32];
};

static bool fip_setup(const char *dir, int n_blocks, struct fip_fixture *fx)
{
    memset(fx, 0, sizeof(*fx));
    snprintf(fx->dir, sizeof(fx->dir), "%s", dir);

    fip_mkdir_p("./test-tmp");
    if (!fip_mkdir_p(dir)) return false;
    SetDataDir(dir);
    GetDataDir(true, fx->netdir, sizeof(fx->netdir));
    if (!fip_mkdir_p(fx->netdir)) return false;
    char blocksdir[700];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", fx->netdir);
    if (!fip_mkdir_p(blocksdir)) return false;

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

    if (!fip_seed_genesis_utxo_apply_row(progress_store_db())) return false;
    if (!tip_finalize_stage_seed_anchor(0, genesis_hash.data, false)) return false;

    mint_fold_ceiling_set(n_blocks);

    struct uint256 prev_hash = genesis_hash;
    for (int h = 1; h <= n_blocks; h++) {
        struct block blk;
        if (!fip_build_regtest_block(&blk, h, &prev_hash, fx->cp)) return false;
        if (!mine_block_pow(&blk, h, fx->cp, 0)) { block_free(&blk); return false; }

        struct uint256 hh;
        block_get_hash(&blk, &hh);

        /* Build the block_index entry DIRECTLY via the same primitive
         * header_admit_stage's reducer-producer path uses internally
         * (add_to_block_index), independent of header_admit's OWN durable
         * stage cursor. A resumer child re-running this same loop on a
         * crash-truncated datadir opens a process where header_admit's
         * persisted cursor is already advanced past every height in this
         * fixture (the crasher fully admitted headers before crashing
         * mid-utxo_apply) — so header_admit_stage's step function, gated
         * strictly on cursor_in, would never look at height h again and
         * this fresh process's (empty) map_block_index would stay empty.
         * add_to_block_index is idempotent on an already-mapped hash (it
         * returns the existing entry without re-deriving pprev/nHeight/
         * nChainWork), so calling it here is safe alongside the mailbox
         * push below, which still separately advances header_admit's own
         * cursor/log for downstream upstream-cursor gates in the
         * fresh-datadir (golden/crasher) legs. */
        struct block_index *bi = add_to_block_index(&fx->ms, &blk.header);
        if (!bi || !bi->phashBlock) { block_free(&blk); return false; }
        if ((bi->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE)
            bi->nStatus = (bi->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_TREE;
        /* header_admit_stage's own step (gated on ITS cursor, see the
         * comment above) is what normally advances pindex_best_header —
         * skipped here in the resumer, so advance it directly. Heights
         * are strictly increasing in this loop, so this is always the new
         * best header; reducer_extend_window_to_candidate (called by
         * every downstream stage step) walks the have-data window out to
         * pindex_best_header, which is what makes active_chain_at(height)
         * resolve for utxo_apply's block selection. */
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
        memcpy(fx->tip_hash, hh.data, 32);
    }

    activation_controller_init(&fx->ctl, &fx->ms, NULL, fx->cp, fx->netdir);
    return true;
}

/* No teardown helper: every fip_setup caller here is a fork()ed worker that
 * _exit()s immediately after writing its result — the OS reclaims the
 * process, so there is nothing to tear down (mirrors test_kill9_recovery.c's
 * child-worker convention). */

/* Drive reducer_kick_unbudgeted until utxo_apply has applied through
 * n_blocks (cursor == n_blocks+1) or max_kicks is exhausted. */
static bool fip_drive_to_completion(struct fip_fixture *fx, int n_blocks,
                                    int max_kicks)
{
    for (int i = 0; i < max_kicks; i++) {
        if (utxo_apply_stage_cursor() >= (uint64_t)(n_blocks + 1))
            return true;
        (void)reducer_kick_unbudgeted(&fx->ctl);
    }
    return utxo_apply_stage_cursor() >= (uint64_t)(n_blocks + 1);
}

/* reducer_kick_unbudgeted drains EVERY stage back-to-back to full
 * convergence inside ONE call (boot_mint_anchor.c's own doc comment) — for
 * the crash-injection proof below we need CONTROL over exactly how many
 * heights utxo_apply has folded when the SIGKILL lands, so these two
 * helpers drive the pipeline in two separate, individually-steppable
 * phases instead: upstream (header_admit is already driven per-block by
 * fip_setup; this drains validate_headers..proof_validate to convergence,
 * none of which touch coins_ram/coins_kv) then utxo_apply ONE HEIGHT per
 * utxo_apply_stage_step_once() call — the exact call reducer_kick's own
 * inner loop makes, so coins_ram_note_applied/coins_ram_flush fire with
 * the same real per-height cadence, just under this loop's control. */
static bool fip_drain_upstream_to_convergence(int max_rounds)
{
    for (int i = 0; i < max_rounds; i++) {
        int adv = validate_headers_stage_drain(64) +
                  body_fetch_stage_drain(64) +
                  body_persist_stage_drain(64) +
                  script_validate_stage_drain(64) +
                  proof_validate_stage_drain(64);
        if (adv == 0)
            return true;
    }
    return false;
}

/* Drive utxo_apply one height at a time up to n_blocks. If stop_after_height
 * >= 0, stop the INSTANT the cursor shows that height applied, touch
 * marker_path (best-effort, existence is the only signal), then sleep so a
 * racing parent has ample time to SIGKILL before this loop would otherwise
 * resume. */
static bool fip_drive_utxo_apply(int n_blocks, int32_t stop_after_height,
                                 const char *marker_path)
{
    for (int i = 0; i < 100000; i++) {
        uint64_t cur = utxo_apply_stage_cursor();
        if (stop_after_height >= 0 && cur >= (uint64_t)(stop_after_height + 1)) {
            if (marker_path) {
                int fd = open(marker_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
                if (fd >= 0) close(fd);
                struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
                nanosleep(&ts, NULL);
            }
            return true;
        }
        if (cur >= (uint64_t)(n_blocks + 1))
            return true;
        (void)utxo_apply_stage_step_once();
    }
    return utxo_apply_stage_cursor() >= (uint64_t)(n_blocks + 1);
}

/* Terminal-state digest: the SAME snapshot writer + shielded-frontier
 * collector boot_mint_anchor.c hard-asserts against the compiled checkpoint
 * with, routed the same way (coins_ram_active() picks the overlay writer).
 * Writes "<sha3-hex> <count> <supply> <applied_through>\n" to result_path. */
static bool fip_write_result(struct fip_fixture *fx, int n_blocks,
                             const char *result_path)
{
    sqlite3 *pdb = progress_store_db();
    struct snapshot_shielded shielded;
    if (!snapshot_shielded_collect_from_db(pdb, n_blocks, &shielded))
        return false;

    char snap_path[700];
    snprintf(snap_path, sizeof(snap_path), "%s/utxo-anchor.snapshot", fx->dir);
    uint8_t sha3[32] = {0};
    uint64_t count = 0;
    int64_t supply = 0;
    bool ok = coins_ram_active()
        ? coins_ram_snapshot_write(snap_path, n_blocks, fx->tip_hash, &shielded,
                                   sha3, &count, &supply)
        : coins_kv_snapshot_write(pdb, snap_path, n_blocks, fx->tip_hash,
                                  &shielded, sha3, &count, &supply);
    snapshot_shielded_free_collected(&shielded);
    if (!ok) return false;

    int32_t applied_through = (int32_t)utxo_apply_stage_cursor() - 1;
    FILE *f = fopen(result_path, "w");
    if (!f) return false;
    for (int i = 0; i < 32; i++)
        fprintf(f, "%02x", sha3[i]);
    fprintf(f, " %llu %lld %d\n", (unsigned long long)count,
            (long long)supply, applied_through);
    fclose(f);
    return true;
}

static bool fip_read_result(const char *path, char sha3_hex[65],
                            uint64_t *count, int64_t *supply, int32_t *applied)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    unsigned long long c = 0;
    long long s = 0;
    int a = 0;
    int n = fscanf(f, "%64s %llu %lld %d", sha3_hex, &c, &s, &a);
    fclose(f);
    if (n != 4) return false;
    *count = (uint64_t)c;
    *supply = (int64_t)s;
    *applied = a;
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (1) DURABLE-vs-INRAM A/B EQUIVALENCE
 * ══════════════════════════════════════════════════════════════════════ */

static int fip_proof1_ab_equivalence(void)
{
    int failures = 0;
    printf("\n=== fold_inram_crash_proof: (1) durable-vs-INRAM A/B "
           "equivalence over a real %d-block regtest fold ===\n", FIP_N_BLOCKS);

    char dirA[256], dirB[256];
    test_fmt_tmpdir(dirA, sizeof(dirA), "fold_inram_ab", "durable");
    test_fmt_tmpdir(dirB, sizeof(dirB), "fold_inram_ab", "inram");
    char resA[320], resB[320];
    snprintf(resA, sizeof(resA), "%s.result", dirA);
    snprintf(resB, sizeof(resB), "%s.result", dirB);
    unlink(resA);
    unlink(resB);

    pid_t pidA = fork();
    if (pidA < 0) { perror("fork"); return ++failures; }
    if (pidA == 0) {
        setenv("ZCL_FOLD_INRAM", "0", 1);
        struct fip_fixture fx;
        bool ok = fip_setup(dirA, FIP_N_BLOCKS, &fx) &&
                  fip_drive_to_completion(&fx, FIP_N_BLOCKS, 8192) &&
                  fip_write_result(&fx, FIP_N_BLOCKS, resA);
        _exit(ok ? 0 : 1);
    }

    pid_t pidB = fork();
    if (pidB < 0) {
        perror("fork");
        waitpid(pidA, NULL, 0);
        return ++failures;
    }
    if (pidB == 0) {
        setenv("ZCL_FOLD_INRAM", "1", 1);
        setenv("ZCL_FOLD_INRAM_FLUSH_EVERY", "2", 1);
        struct fip_fixture fx;
        bool ok = fip_setup(dirB, FIP_N_BLOCKS, &fx) &&
                  fip_drive_to_completion(&fx, FIP_N_BLOCKS, 8192) &&
                  fip_write_result(&fx, FIP_N_BLOCKS, resB);
        _exit(ok ? 0 : 1);
    }

    int stA = 0, stB = 0;
    waitpid(pidA, &stA, 0);
    waitpid(pidB, &stB, 0);
    FIP_CHECK("leg A (ZCL_FOLD_INRAM=0, durable) fold completed",
              WIFEXITED(stA) && WEXITSTATUS(stA) == 0);
    FIP_CHECK("leg B (ZCL_FOLD_INRAM=1, overlay) fold completed",
              WIFEXITED(stB) && WEXITSTATUS(stB) == 0);

    char sha3A[65] = {0}, sha3B[65] = {0};
    uint64_t cntA = 0, cntB = 0;
    int64_t supA = 0, supB = 0;
    int32_t appA = -1, appB = -1;
    bool rA = fip_read_result(resA, sha3A, &cntA, &supA, &appA);
    bool rB = fip_read_result(resB, sha3B, &cntB, &supB, &appB);
    FIP_CHECK("leg A result readable", rA);
    FIP_CHECK("leg B result readable", rB);
    FIP_CHECK("A/B: applied-height identical (both reached the anchor)",
              rA && rB && appA == appB && appA == FIP_N_BLOCKS);
    FIP_CHECK("A/B: coins count identical", rA && rB && cntA == cntB);
    FIP_CHECK("A/B: total supply identical", rA && rB && supA == supB);
    FIP_CHECK("A/B: terminal snapshot SHA3 (coins + shielded anchors + "
              "nullifiers) byte-identical",
              rA && rB && strcmp(sha3A, sha3B) == 0);
    if (rA && rB && strcmp(sha3A, sha3B) != 0)
        printf("  >> durable=%s inram=%s\n", sha3A, sha3B);

    test_rm_rf_recursive(dirA);
    test_rm_rf_recursive(dirB);
    unlink(resA);
    unlink(resB);
    return failures;
}

/* ══════════════════════════════════════════════════════════════════════
 * (2) CRASH-INJECTION RESUME
 * ══════════════════════════════════════════════════════════════════════ */

/* Fold the fixture at dir, then drive utxo_apply one height at a time,
 * touching `marker_path` the instant utxo_apply has just applied
 * `kill_after_height`, then sleeping so the parent has ample time to
 * SIGKILL before this process would otherwise continue. If the parent
 * somehow fails to kill it, it exits cleanly (surfacing as a test FAILURE
 * via the "terminated by SIGKILL" assertion, not a hang). */
static bool fip_crasher_child(const char *dir, int n_blocks,
                              int32_t kill_after_height,
                              const char *marker_path)
{
    setenv("ZCL_FOLD_INRAM", "1", 1);
    setenv("ZCL_FOLD_INRAM_FLUSH_EVERY", "2", 1);

    struct fip_fixture fx;
    if (!fip_setup(dir, n_blocks, &fx))
        return false;
    if (!fip_drain_upstream_to_convergence(64))
        return false;

    fip_drive_utxo_apply(n_blocks, kill_after_height, marker_path);
    _exit(0); /* only reached if the parent failed to kill us in time */
}

/* Reopen the (possibly crash-truncated) datadir in a fresh process, rebuild
 * the deterministic headers/bodies, and drive the fold to completion —
 * proving coins_ram_reconcile_boot's crash-replay resumes cleanly. */
static bool fip_resumer_child(const char *dir, int n_blocks,
                              const char *result_path)
{
    setenv("ZCL_FOLD_INRAM", "1", 1);
    setenv("ZCL_FOLD_INRAM_FLUSH_EVERY", "2", 1);

    struct fip_fixture fx;
    if (!fip_setup(dir, n_blocks, &fx))
        return false;
    if (!fip_drain_upstream_to_convergence(64))
        return false;
    if (!fip_drive_utxo_apply(n_blocks, -1, NULL))
        return false;
    return fip_write_result(&fx, n_blocks, result_path);
}

static int fip_proof2_crash_resume(void)
{
    int failures = 0;
    printf("\n=== fold_inram_crash_proof: (2) ZCL_FOLD_INRAM=1 crash-"
           "injection resume over a real %d-block regtest fold ===\n",
           FIP_N_BLOCKS);

    /* Golden: one uninterrupted INRAM fold — the terminal every crash cycle
     * below must reproduce exactly. */
    char dirG[256];
    test_fmt_tmpdir(dirG, sizeof(dirG), "fold_inram_crash", "golden");
    char resG[320];
    snprintf(resG, sizeof(resG), "%s.result", dirG);
    unlink(resG);

    pid_t pidG = fork();
    if (pidG < 0) { perror("fork"); return ++failures; }
    if (pidG == 0) {
        setenv("ZCL_FOLD_INRAM", "1", 1);
        setenv("ZCL_FOLD_INRAM_FLUSH_EVERY", "2", 1);
        struct fip_fixture fx;
        bool ok = fip_setup(dirG, FIP_N_BLOCKS, &fx) &&
                  fip_drain_upstream_to_convergence(64) &&
                  fip_drive_utxo_apply(FIP_N_BLOCKS, -1, NULL) &&
                  fip_write_result(&fx, FIP_N_BLOCKS, resG);
        _exit(ok ? 0 : 1);
    }
    int stG = 0;
    waitpid(pidG, &stG, 0);
    FIP_CHECK("golden uninterrupted INRAM fold completed",
              WIFEXITED(stG) && WEXITSTATUS(stG) == 0);

    char sha3G[65] = {0};
    uint64_t cntG = 0;
    int64_t supG = 0;
    int32_t appG = -1;
    bool rG = fip_read_result(resG, sha3G, &cntG, &supG, &appG);
    FIP_CHECK("golden result readable", rG);

    /* ZCL_FOLD_INRAM_FLUSH_EVERY=2 -> flush boundaries at applied-height
     * 2, 4, 6. Three crash points: right after the first flush boundary,
     * and two mid-batch points strictly between flush boundaries. */
    static const int32_t kill_points[3] = { 2, 3, 5 };
    static const char *const kill_labels[3] = {
        "right after the first flush boundary (h=2)",
        "mid-batch between flushes (h=3, before the h=4 flush)",
        "mid-batch near the un-flushed tail (h=5, before the h=6 flush)",
    };

    for (int c = 0; c < 3 && rG; c++) {
        char dirC[256], tag[32];
        snprintf(tag, sizeof(tag), "crash%d", c);
        test_fmt_tmpdir(dirC, sizeof(dirC), "fold_inram_crash", tag);
        char marker[320], resC[320];
        snprintf(marker, sizeof(marker), "%s.marker", dirC);
        snprintf(resC, sizeof(resC), "%s.result", dirC);
        unlink(marker);
        unlink(resC);

        printf("  fold_inram_crash_proof: cycle %d: SIGKILL %s\n",
               c, kill_labels[c]);

        pid_t pidC = fork();
        if (pidC < 0) { perror("fork"); failures++; continue; }
        if (pidC == 0) {
            bool ok = fip_crasher_child(dirC, FIP_N_BLOCKS, kill_points[c],
                                        marker);
            _exit(ok ? 0 : 1);
        }

        bool saw_marker = false;
        for (int p = 0; p < 5000; p++) {
            struct stat st;
            if (stat(marker, &st) == 0) { saw_marker = true; break; }
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 2 * 1000 * 1000L };
            nanosleep(&ts, NULL);
        }
        if (!saw_marker) {
            printf("FAIL (cycle %d: progress marker never appeared within "
                   "budget)\n", c);
            failures++;
            kill(pidC, SIGKILL);
            waitpid(pidC, NULL, 0);
            test_rm_rf_recursive(dirC);
            continue;
        }

        if (kill(pidC, SIGKILL) != 0 && errno != ESRCH) {
            perror("kill");
            failures++;
        }
        int stC = 0;
        if (waitpid(pidC, &stC, 0) != pidC) {
            printf("FAIL (cycle %d: waitpid failed)\n", c);
            failures++;
            test_rm_rf_recursive(dirC);
            continue;
        }
        bool killed = WIFSIGNALED(stC) && WTERMSIG(stC) == SIGKILL;
        FIP_CHECK("crasher terminated by SIGKILL (not a graceful exit)",
                  killed);

        pid_t pidR = fork();
        if (pidR < 0) {
            perror("fork");
            failures++;
            test_rm_rf_recursive(dirC);
            continue;
        }
        if (pidR == 0) {
            bool ok = fip_resumer_child(dirC, FIP_N_BLOCKS, resC);
            _exit(ok ? 0 : 1);
        }
        int stR = 0;
        waitpid(pidR, &stR, 0);
        FIP_CHECK("resumer (fresh process) drove the fold to completion",
                  WIFEXITED(stR) && WEXITSTATUS(stR) == 0);

        char sha3C[65] = {0};
        uint64_t cntC = 0;
        int64_t supC = 0;
        int32_t appC = -1;
        bool rC = fip_read_result(resC, sha3C, &cntC, &supC, &appC);
        FIP_CHECK("resume result readable", rC);
        FIP_CHECK("resume: applied-height == golden",
                  rC && appC == appG);
        FIP_CHECK("resume: coins count == golden", rC && cntC == cntG);
        FIP_CHECK("resume: total supply == golden", rC && supC == supG);
        FIP_CHECK("resume: terminal snapshot SHA3 == golden (the "
                  "crash-ordering proof)",
                  rC && strcmp(sha3C, sha3G) == 0);
        if (rC && strcmp(sha3C, sha3G) != 0)
            printf("  >> golden=%s resumed=%s\n", sha3G, sha3C);

        test_rm_rf_recursive(dirC);
        unlink(marker);
        unlink(resC);
    }

    test_rm_rf_recursive(dirG);
    unlink(resG);
    return failures;
}

static int test_fold_inram_crash_proof_platform_arm(void);
static int test_fold_inram_crash_proof_platform_arm(void)
{
    int failures = 0;
    printf("\n=== test_fold_inram_crash_proof: the coins_ram fold-IO cure's "
           "two open proof items (durable-vs-INRAM A/B equivalence, crash-"
           "injection resume) ===\n");

    failures += fip_proof1_ab_equivalence();
    failures += fip_proof2_crash_resume();

    printf("=== test_fold_inram_crash_proof complete: %d failure(s) ===\n",
           failures);
    return failures;
}
#else  /* _WIN32 */
/* Both proof items drive crash injection through fork()+SIGKILL children;
 * the Windows TerminateProcess analogue of the fold-recovery invariant is
 * carried by test_kill9_recovery.c's mint-fold phase. */
static int test_fold_inram_crash_proof_platform_arm(void)
{
    printf("fold_inram_crash_proof: SKIP (Windows): fork+SIGKILL "
           "crash-injection lane; kill9_recovery mint-fold covers the "
           "TerminateProcess analogue\n");
    return 0;
}
#endif

int test_fold_inram_crash_proof(void)
{
    return test_fold_inram_crash_proof_platform_arm();
}
