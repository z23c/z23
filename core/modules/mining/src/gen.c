/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "mining/gen.h"
#include "metrics/metrics.h"
#include "chain/equihash.h"
#include "chain/pow.h"
#include "core/random.h"
#include "core/serialize.h"
#include "crypto/equihash.h"
#include "crypto/equihash_solver.h"
#include "validation/chainstate.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "util/log_macros.h"
#include "util/util.h"
#include "util/safe_alloc.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"
#include <stdatomic.h>

static pthread_t *g_miner_threads = NULL;
static int g_num_miner_threads = 0;

/* Supervisor liveness (root child — core/modules/mining cannot include the app-side
 * supervisors/domains.h, see util/thread_liveness.h). gen_start() can spawn
 * ctx->num_threads miner threads that all share the name "zcl_miner"; ONE
 * shared contract answers the honest question "is at least one miner loop
 * alive" — thread_liveness_register is idempotent, so every thread's
 * registration call after the first is a no-op. CPU-bound tight solve loop
 * has no natural idle boundary, so no deadline and no progress-quiet gate
 * (liveness-only); the progress marker is still published per outer-loop
 * (per solve-attempt-batch) pass as telemetry, same as the disabled-gate
 * pattern in engine/modules/health/src/heartbeat.c's sweeper. */
static struct thread_liveness_child g_miner_liveness = { .id = SUPERVISOR_INVALID_ID };
static _Atomic uint64_t g_miner_batch_count = 0;

static bool mining_cancelled(void *arg)
{
    const _Atomic bool *running = arg;
    return !atomic_load_explicit(running, memory_order_relaxed);
}

static bool try_solve_equihash(struct block *blk,
                                const struct chain_params *params,
                                int height, _Atomic bool *running)
{
    /* Regtest (fMineBlocksOnDemand) delegates to the ONE real solver,
     * mine_block_pow(), which calls equihash_basic_solve() and actually SETS
     * header.nSolution before testing the hash against the target. The
     * brute-force nonce loop further down never set a solution at all, so
     * every block this thread "found" on regtest was rejected
     * `invalid-solution` by check_block() at intake and the tip never moved.
     *
     * Gated on fMineBlocksOnDemand — true ONLY for regtest — so mainnet and
     * testnet block production takes exactly the path it took before. */
    if (params->fMineBlocksOnDemand)
        return mine_block_pow(blk, height, params, 0);

    unsigned int n = chain_params_equihash_n(params, height);
    unsigned int k = chain_params_equihash_k(params, height);

    /* Same refusal as mine_block_pow: an (N,K) outside the bit-packers'
     * width assumptions must never reach them (their asserts are live in
     * release builds). */
    if (!equihash_params_supported(n, k))
        LOG_FAIL("mining", "try_solve_equihash: unsupported equihash "
                 "parameters N=%u K=%u at height %d", n, k, height);

    struct equihash_params ep;
    equihash_params_init(&ep, n, k);

    struct blake2b_ctx base_state;
    equihash_initialise_state(&ep, &base_state);

    /* Hash block header fields before nonce */
    struct byte_stream s;
    stream_init(&s, 256);
    stream_write_i32_le(&s, blk->header.nVersion);
    stream_write_bytes(&s, blk->header.hashPrevBlock.data, 32);
    stream_write_bytes(&s, blk->header.hashMerkleRoot.data, 32);
    stream_write_bytes(&s, blk->header.hashFinalSaplingRoot.data, 32);
    stream_write_u32_le(&s, blk->header.nTime);
    stream_write_u32_le(&s, blk->header.nBits);
    blake2b_update(&base_state, s.data, s.size);
    stream_free(&s);

    /* Tromp solver path is for post-Bubbles mainnet (192,7). */
    if (n == 192 && k == 7) {
        struct eh_solver *solver = eh_solver_new();
        if (!solver)
            return false;

        /* Try nonces until a solution is found */
        for (int nonce_try = 0; nonce_try < 256; nonce_try++) {
            for (int b = 0; b < 32; b++)
                blk->header.nNonce.data[b] = (unsigned char)(GetRand(256));

            struct blake2b_ctx curr = base_state;
            blake2b_update(&curr, blk->header.nNonce.data, 32);

            eh_solver_set_state(solver, &curr);
            uint32_t nsols = eh_solver_run_cancelable(
                solver, mining_cancelled, running);
            metrics_increment_eh_solver_runs();
            if (solver->cancelled)
                break;

            for (uint32_t i = 0; i < nsols; i++) {
                /* Convert indices to minimal/compressed solution */
                unsigned char sol_bytes[EH_SOL_BYTES];
                size_t sol_len = eh_get_minimal_from_indices(
                    solver->sols[i], EH_PROOFSIZE,
                    ep.collision_bit_length,
                    sol_bytes, sizeof(sol_bytes));

                if (sol_len != EH_SOL_BYTES)
                    continue;

                /* Set solution on block */
                memcpy(blk->header.nSolution, sol_bytes, sol_len);
                blk->header.nSolutionSize = sol_len;

                /* Verify: hash must meet target */
                struct uint256 hash;
                block_header_get_hash(&blk->header, &hash);
                if (CheckProofOfWork(hash, blk->header.nBits,
                                      &params->consensus)) {
                    /* Double-check equihash validity */
                    if (check_equihash_solution(&blk->header, params)) {
                        eh_solver_free(solver);
                        return true;
                    }
                }
            }
        }
        eh_solver_free(solver);
    } else {
        /* Mainnet/testnet (200,9) fallback, unchanged and unreached by
         * regtest (handled by the fMineBlocksOnDemand delegate above). It
         * searches nonces WITHOUT producing an Equihash witness, so a hit
         * here still carries an empty nSolution — kept byte-for-byte as it
         * was rather than altering mainnet block production. In-process
         * (200,9) mining is not a supported path; real miners use
         * getblocktemplate + submitblock. */
        for (unsigned int attempt = 0; attempt < 1000000; attempt++) {
            for (int b = 0; b < 32; b++)
                blk->header.nNonce.data[b] = (unsigned char)(GetRand(256));

            struct uint256 hash;
            block_header_get_hash(&blk->header, &hash);

            if (CheckProofOfWork(hash, blk->header.nBits,
                                  &params->consensus)) {
                return true;
            }
        }
    }

    return false;
}

static void *miner_thread(void *arg)
{
    struct gen_context *ctx = (struct gen_context *)arg;
    LogPrintf("Miner thread started.\n");

    while (ctx->running) {
        struct block_index *tip = active_chain_tip(&ctx->ms->chain_active);
        if (!tip) {
            sleep(1);
            continue;
        }

        struct block_template *tmpl = create_new_block(
            &ctx->coinbase_script, ctx->ms, ctx->coins_tip,
            ctx->mempool, ctx->params);
        if (!tmpl) {
            sleep(1);
            continue;
        }

        unsigned int extra_nonce = 0;
        increment_extra_nonce(&tmpl->block, tip, &extra_nonce);

        if (try_solve_equihash(&tmpl->block, ctx->params,
                               tip->nHeight + 1, &ctx->running)) {
            LogPrintf("Found block!\n");
            if (ctx->block_found &&
                ctx->block_found(&tmpl->block, ctx->block_found_ctx)) {
                struct block_index *new_tip =
                    active_chain_tip(&ctx->ms->chain_active);
                if (new_tip && new_tip->phashBlock) {
                    char hex[65];
                    uint256_get_hex(new_tip->phashBlock, hex);
                    LogPrintf("New block: height=%d hash=%s\n",
                              new_tip->nHeight, hex);
                }
            }
        }

        block_template_free(tmpl);
        free(tmpl);

        /* Per solve-attempt batch, not per inner hash — that would be
         * far too hot a path. */
        thread_liveness_beat(&g_miner_liveness,
                             (int64_t)atomic_fetch_add(&g_miner_batch_count, 1) + 1);
    }

    LogPrintf("Miner thread stopped.\n");
    return NULL;
}

void gen_start(struct gen_context *ctx)
{
    int started = 0;

    if (!ctx)
        return;
    if (ctx->num_threads <= 0)
        ctx->num_threads = 1;

    if (atomic_load(&ctx->running))
        return;
    g_num_miner_threads = ctx->num_threads;
    g_miner_threads = zcl_calloc((size_t)g_num_miner_threads, sizeof(pthread_t), "miner_threads");
    if (!g_miner_threads) {
        LOG_WARN("mining", "gen_start: calloc failed for %d threads", g_num_miner_threads);
        return;
    }

    atomic_store(&ctx->running, true);

    for (int i = 0; i < g_num_miner_threads; i++) {
        if (thread_registry_spawn("zcl_miner", miner_thread, ctx,
                                      &g_miner_threads[i]) != 0) {
            LOG_WARN("mining", "gen_start: failed to start miner thread %d", i);
            atomic_store(&ctx->running, false);
            for (int j = 0; j < started; j++)
                pthread_join(g_miner_threads[j], NULL);
            free(g_miner_threads);
            g_miner_threads = NULL;
            g_num_miner_threads = 0;
            return;
        }
        started++;
        thread_liveness_register(&g_miner_liveness, "zcl_miner", 0, 0);
    }

    LogPrintf("Mining started with %d thread(s).\n", g_num_miner_threads);
}

void gen_stop(struct gen_context *ctx)
{
    if (!ctx || !g_miner_threads)
        return;
    atomic_store(&ctx->running, false);
    for (int i = 0; i < g_num_miner_threads; i++)
        pthread_join(g_miner_threads[i], NULL);
    thread_liveness_retire(&g_miner_liveness);
    free(g_miner_threads);
    g_miner_threads = NULL;
    g_num_miner_threads = 0;
    LogPrintf("Mining stopped.\n");
}
