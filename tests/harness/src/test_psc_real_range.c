/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_psc_real_range — the P1 DIFFERENTIAL PARITY ORACLE for the Parallel
 * State Compiler over a REAL on-disk datadir (engine/jobs/src/psc_block_source.c,
 * psc_audit.c).
 *
 * The P0 oracle (test_parallel_range_fold.c) proved the parallel fold
 * bit-identical to a serial replay of utxo_apply_compute_block_delta over an
 * IN-RAM fixture. This P1 oracle raises the bar to the PRODUCTION paths:
 *
 *   (1) MERGE BAR — fold a small regtest chain genesis..N through the REAL
 *       eight-stage reducer pipeline (the SAME machinery
 *       test_fold_inram_crash_proof.c drives: real mine_block_pow,
 *       header_admit/validate_headers/body_fetch/body_persist/script_validate/
 *       proof_validate/utxo_apply/tip_finalize, blocks written to a real
 *       blocks/ dir), then recompute the terminal transparent set with the
 *       PARALLEL compiler reading those SAME on-disk bodies through the
 *       PRODUCTION provider (psc_prod_block_provider = active_chain_at + the
 *       lock-free read_block_from_disk_index_pread), and assert the parallel
 *       terminal SHA3 (coins_kv_commitment's encoder), coin count, and supply
 *       are BIT-IDENTICAL to the durable coins_kv the serial utxo_apply wrote.
 *
 *   (2) AUDIT + dumpstate psc — psc_audit_run over the full range reports a
 *       MATCH and dumpstate psc reflects it; an audit over a deliberately short
 *       range reports a MISMATCH (fewer coins) — proving the opt-in audit
 *       surfaces both verdicts without touching the serial fold.
 *
 *   (3) MEASUREMENT — serial utxo_apply us/block vs parallel compile us/block
 *       over the on-disk fixture (small N; the scaled compute-parallelism
 *       number is measured by the P0 group at N=4000).
 *
 * Shielded/nullifier state stays serial in P1: this fixture carries none, and
 * the audit compares the TRANSPARENT coins set only (coins_kv_commitment), so a
 * pass asserts the shielded path is untouched by construction.
 *
 * make t ONLY=psc_real_range
 */
#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "domain/consensus/coinbase.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/header_admit_stage.h"
#include "jobs/mint_fold_ceiling.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/psc_audit.h"
#include "jobs/psc_block_source.h"
#include "jobs/psc_range_fold.h"
#include "jobs/script_validate_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/validate_headers_stage.h"
#include "json/json.h"
#include "mining/miner.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/header_admit_inbox.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/accept_block_header.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PRR_N_BLOCKS 24

#define PRR_CHECK(name, expr) do {                          \
    printf("  psc_real_range: %s... ", (name));             \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

static bool prr_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return true;
    return errno == EEXIST;
}

/* One-coinbase regtest block — a slim copy of
 * test_fold_inram_crash_proof.c:fip_build_regtest_block. Deterministic in every
 * field but nSolution/nNonce (found by mine_block_pow). */
static bool prr_build_regtest_block(struct block *blk, int height,
                                    const struct uint256 *prev_hash,
                                    const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "prr_vtx");
    if (!blk->vtx) return false;
    blk->num_vtx = 1;

    struct transaction *coinbase = &blk->vtx[0];
    transaction_init(coinbase);
    if (!transaction_alloc(coinbase, 1, 1)) return false;

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
    if (!r.ok) return false;

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

static bool prr_seed_genesis_utxo_apply_row(sqlite3 *db)
{
    if (!db) return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO utxo_apply_log "
        "(height,status,ok,spent_count,added_count,total_value_delta,applied_at) "
        "VALUES(0,'verified',1,0,0,0,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = (sqlite3_step(st) == SQLITE_DONE);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

struct prr_fixture {
    struct main_state    ms;
    const struct chain_params *cp;
    char dir[300];
    char netdir[512];
    struct block_index  *tip_bi;
    uint8_t tip_hash[32];
    int n_blocks;
};

/* Build genesis + n_blocks regtest blocks on a REAL datadir, initialise all
 * eight reducer stages, admit headers, persist bodies. Slim copy of
 * test_fold_inram_crash_proof.c:fip_setup (no activation controller — this test
 * drives utxo_apply directly). */
static bool prr_setup(const char *dir, int n_blocks, struct prr_fixture *fx)
{
    memset(fx, 0, sizeof(*fx));
    fx->n_blocks = n_blocks;
    snprintf(fx->dir, sizeof(fx->dir), "%s", dir);

    prr_mkdir_p("./test-tmp");
    if (!prr_mkdir_p(dir)) return false;
    SetDataDir(dir);
    GetDataDir(true, fx->netdir, sizeof(fx->netdir));
    if (!prr_mkdir_p(fx->netdir)) return false;
    char blocksdir[700];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", fx->netdir);
    if (!prr_mkdir_p(blocksdir)) return false;

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

    if (!prr_seed_genesis_utxo_apply_row(progress_store_db())) return false;
    if (!tip_finalize_stage_seed_anchor(0, genesis_hash.data, false)) return false;

    mint_fold_ceiling_set(n_blocks);

    struct uint256 prev_hash = genesis_hash;
    for (int h = 1; h <= n_blocks; h++) {
        struct block blk;
        if (!prr_build_regtest_block(&blk, h, &prev_hash, fx->cp)) return false;
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
        fx->tip_bi = bi;
        memcpy(fx->tip_hash, hh.data, 32);
    }
    return true;
}

static void prr_teardown(struct prr_fixture *fx)
{
    active_chain_free(&fx->ms.chain_active);
    progress_store_close();
    test_rm_rf_recursive(fx->dir);
}

/* Drive validate_headers..proof_validate to convergence (none touch coins_kv),
 * then utxo_apply one height at a time up to n_blocks — timing ONLY the
 * utxo_apply loop so the serial number is a clean per-block apply cost. */
static bool prr_serial_fold(struct prr_fixture *fx, double *out_utxo_us)
{
    for (int round = 0; round < 128; round++) {
        int adv = validate_headers_stage_drain(64) +
                  body_fetch_stage_drain(64) +
                  body_persist_stage_drain(64) +
                  script_validate_stage_drain(64) +
                  proof_validate_stage_drain(64);
        if (adv == 0) break;
    }
    int64_t t0 = platform_time_monotonic_us();
    for (int i = 0; i < 1000000; i++) {
        if (utxo_apply_stage_cursor() >= (uint64_t)(fx->n_blocks + 1)) break;
        (void)utxo_apply_stage_step_once();
    }
    *out_utxo_us = (double)(platform_time_monotonic_us() - t0);
    return utxo_apply_stage_cursor() >= (uint64_t)(fx->n_blocks + 1);
}

/* Durable transparent supply: SUM(value) over the coins table coins_kv writes
 * (coins_kv_commitment reads "FROM coins" in the same canonical order). */
static bool prr_durable_supply(sqlite3 *db, int64_t *out)
{
    *out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COALESCE(SUM(value),0) FROM coins",
                           -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = false;
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:test-fixture-assertion
        *out = sqlite3_column_int64(st, 0);
        ok = true;
    }
    sqlite3_finalize(st);
    return ok;
}

static void prr_hex(const uint8_t d[32], char out[65])
{
    static const char *hx = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2*i] = hx[d[i]>>4]; out[2*i+1] = hx[d[i]&15]; }
    out[64] = '\0';
}

int test_psc_real_range(void);
int test_psc_real_range(void)
{
    int failures = 0;
    printf("\n=== test_psc_real_range: Parallel State Compiler P1 — real-datadir "
           "differential parity oracle + audit ===\n");

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "psc_real_range", "fold");

    struct prr_fixture fx;
    bool setup_ok = prr_setup(dir, PRR_N_BLOCKS, &fx);
    PRR_CHECK("real regtest datadir + 8-stage pipeline built", setup_ok);
    if (!setup_ok) {
        if (fx.dir[0]) prr_teardown(&fx);
        chain_params_select(CHAIN_MAIN);
        printf("=== test_psc_real_range complete: %d failure(s) ===\n",
               ++failures);
        return failures;
    }

    /* ── serial reference: the durable coins_kv the real utxo_apply wrote ── */
    double serial_utxo_us = 0;
    bool serial_ok = prr_serial_fold(&fx, &serial_utxo_us);
    PRR_CHECK("serial fold applied every block (utxo_apply cursor == N+1)",
              serial_ok && utxo_apply_stage_cursor() == (uint64_t)(PRR_N_BLOCKS + 1));

    sqlite3 *db = progress_store_db();
    uint8_t serial_sha3[32] = {0};
    int serial_commit_rc = coins_kv_commitment(db, serial_sha3);
    int64_t serial_count = coins_kv_count(db);
    int64_t serial_supply = 0;
    bool supply_ok = prr_durable_supply(db, &serial_supply);
    PRR_CHECK("durable coins_kv commitment + count + supply computed",
              serial_commit_rc == 0 && serial_count == PRR_N_BLOCKS && supply_ok);
    char serial_hex[65]; prr_hex(serial_sha3, serial_hex);

    /* Ensure the active-chain window spans [1,N] for the production provider's
     * active_chain_at height→block_index resolution (ancestor walk from tip). */
    active_chain_move_window_tip(&fx.ms.chain_active, fx.tip_bi);

    /* ── parallel: recompute the terminal set from the SAME on-disk bodies via
     * the PRODUCTION provider (active_chain_at + read_block_from_disk_index_pread),
     * invariant under (K,S). ── */
    static const int Ks[] = { 1, 4, 8 };
    static const int Ss[] = { 2, 8, 16 };
    double best_parallel_us_per_blk = 0;
    printf("\n  %-4s %-4s %-12s %-12s %-12s %-10s\n",
           "K", "S", "events", "extract_us", "join_us", "us/blk");
    for (size_t i = 0; i < sizeof(Ks)/sizeof(Ks[0]); i++) {
        struct psc_prod_source src = { .ms = &fx.ms, .datadir = fx.netdir };
        struct psc_range_result r;
        bool ran = psc_compile_range(1, PRR_N_BLOCKS, Ks[i], Ss[i],
                                     psc_prod_block_provider, &src, &r);
        char name[96];
        snprintf(name, sizeof(name), "PSC prod-provider compile clean (K=%d,S=%d)",
                 Ks[i], Ss[i]);
        PRR_CHECK(name, ran && r.ok);
        if (!ran || !r.ok) continue;

        printf("  %-4d %-4d %-12llu %-12.0f %-12.0f %-10.3f\n",
               Ks[i], Ss[i], (unsigned long long)r.events_total,
               r.extract_us, r.join_us, r.total_us / (double)PRR_N_BLOCKS);
        if (i == sizeof(Ks)/sizeof(Ks[0]) - 1)
            best_parallel_us_per_blk = r.total_us / (double)PRR_N_BLOCKS;

        char phex[65]; prr_hex(r.terminal_sha3, phex);
        snprintf(name, sizeof(name), "terminal SHA3 == durable coins_kv (K=%d,S=%d)",
                 Ks[i], Ss[i]);
        PRR_CHECK(name, strcmp(phex, serial_hex) == 0);
        if (strcmp(phex, serial_hex) != 0)
            printf("    >> durable=%s parallel=%s\n", serial_hex, phex);
        snprintf(name, sizeof(name), "coin count == durable (K=%d,S=%d)", Ks[i], Ss[i]);
        PRR_CHECK(name, (int64_t)r.terminal_count == serial_count);
        snprintf(name, sizeof(name), "supply == durable (K=%d,S=%d)", Ks[i], Ss[i]);
        PRR_CHECK(name, r.terminal_supply == serial_supply);
    }

    printf("\n  MEASUREMENT (real on-disk %d-block regtest fold):\n", PRR_N_BLOCKS);
    printf("    serial utxo_apply : %.3f us/blk\n",
           serial_utxo_us / (double)PRR_N_BLOCKS);
    printf("    parallel compile  : %.3f us/blk (K=8; scaled compute-parallelism "
           "is measured at N=4000 by the parallel_range_fold group)\n",
           best_parallel_us_per_blk);

    /* ── audit + dumpstate psc: MATCH over the full range ── */
    struct psc_audit_result ar;
    bool match = psc_audit_run(&fx.ms, fx.netdir, 1, PRR_N_BLOCKS, 0, 0, &ar);
    PRR_CHECK("psc_audit_run full range reports MATCH",
              match && ar.ran && ar.match &&
              ar.parallel_count == (uint64_t)PRR_N_BLOCKS &&
              ar.durable_count == serial_count);
    {
        struct json_value js; memset(&js, 0, sizeof(js));
        bool dumped = psc_dump_state_json(&js, NULL);
        const struct json_value *has_run = json_get(&js, "has_run");
        const struct json_value *jm = json_get(&js, "match");
        const struct json_value *jc = json_get(&js, "parallel_count");
        PRR_CHECK("dumpstate psc reflects the MATCH audit",
                  dumped && has_run && json_get_bool(has_run) &&
                  jm && json_get_bool(jm) &&
                  jc && json_get_int(jc) == PRR_N_BLOCKS);
        json_free(&js);
    }

    /* ── audit MISMATCH over a deliberately short range (fewer coins) ── */
    struct psc_audit_result ar2;
    bool match2 = psc_audit_run(&fx.ms, fx.netdir, 1, PRR_N_BLOCKS - 1, 0, 0, &ar2);
    PRR_CHECK("psc_audit_run short range reports MISMATCH",
              !match2 && ar2.ran && !ar2.match &&
              ar2.parallel_count == (uint64_t)(PRR_N_BLOCKS - 1) &&
              ar2.durable_count == serial_count);
    {
        struct json_value js; memset(&js, 0, sizeof(js));
        bool dumped = psc_dump_state_json(&js, NULL);
        const struct json_value *jm = json_get(&js, "match");
        PRR_CHECK("dumpstate psc reflects the MISMATCH audit",
                  dumped && jm && !json_get_bool(jm));
        json_free(&js);
    }

    prr_teardown(&fx);
    chain_params_select(CHAIN_MAIN);
    printf("=== test_psc_real_range complete: %d failure(s) ===\n", failures);
    return failures;
}
