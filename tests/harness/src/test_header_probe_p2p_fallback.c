/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Detective lane A2 — the stale-header repair must work with the zclassicd
 * oracle DEAD, via a P2P getdata fallback, and must be honest when NO source
 * can serve.
 *
 * Three hermetic cases:
 *   1. P2P repair path: oracle points at a dead port; the repair Condition
 *      falls back to a P2P getdata re-fetch (observable in the header_probe
 *      state dump), then — once the honest peer's block arrives and its
 *      solution is saved hash-bound (as reducer_cache_ingested_solution does on
 *      ingest) — the repair completes and is ATTRIBUTED to the P2P source.
 *   2. Missing input: oracle dead AND zero connected peers → a typed blocker
 *      names the missing input, the Condition stays active (cooldown re-arm, no
 *      operator-page latch), and it recovers cleanly when a source returns.
 *   3. Negative: a peer serving an invalid-PoW header is REJECTED and scored
 *      PEER_OFFENCE_INVALID_HEADER (the detective never adopts an unverified
 *      page); a valid header from an honest peer is NOT scored.
 */

#include "test/test_core.h"
#include "util/util.h"

#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "services/header_probe.h"
#include "services/sync_monitor.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "util/blocker.h"

/* Case 3 (net scoring) harness. */
#include "mining/miner.h"
#include "net/download.h"
#include "net/header_serve_repair.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/peer_scoring.h"
#include "validation/process_block.h"
#include "core/arith_uint256.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HPF_CHECK(name, expr) do { \
    printf("header_probe_p2p_fallback: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Condition ZCL_TESTING hooks (not exported through a header). */
void register_stale_validate_headers_repair(void);
void stale_validate_headers_repair_test_reset(void);
int stale_validate_headers_repair_test_remedy_calls(void);
void stale_validate_headers_repair_test_clear_backoff(void);
void stale_validate_headers_repair_test_set_hstar_override(int height);
void stale_validate_headers_repair_test_set_peer_count(int n);
void reducer_frontier_test_set_compiled_anchor(int32_t height);

#define HPF_NO_SOURCE_BLOCKER_ID "header_repair_no_source"

/* ── progress-store fixture helpers (mirrors
 *    test_stale_validate_headers_repair_condition.c) ───────────────────── */

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("SQL failed: %s\n", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool seed_schema(sqlite3 *db)
{
    return
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "fail_reason TEXT, validated_at INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_fetch_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, source TEXT NOT NULL,"
            "bytes INTEGER NOT NULL DEFAULT 0, fetched_at INTEGER NOT NULL,"
            "ok INTEGER NOT NULL, fail_reason TEXT)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_persist_log ("
            "height INTEGER PRIMARY KEY, source TEXT, ok INTEGER,"
            "persisted_at INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER, "
            "block_hash BLOB)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS proof_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)");
}

static bool seed_proven_authority(sqlite3 *db, int64_t applied_height)
{
    if (!exec_sql(db, "CREATE TABLE IF NOT EXISTS progress_meta "
                      "(key TEXT PRIMARY KEY, value BLOB)") ||
        !exec_sql(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB)") ||
        !exec_sql(db, "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00')"))
        return false;
    uint8_t ah[8];
    for (int i = 0; i < 8; i++)
        ah[i] = (uint8_t)((uint64_t)applied_height >> (8 * i));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, ah, 8, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;
    uint8_t one = 1;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool seed_cursors(sqlite3 *db, int validate_cursor, int downstream_cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    static const char *const names[] = {
        "validate_headers", "body_fetch", "body_persist", "script_validate",
        "proof_validate", "utxo_apply", "tip_finalize",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_text(st, 1, names[i], -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 2, i == 0 ? validate_cursor : downstream_cursor);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return false;
        }
    }
    sqlite3_finalize(st);
    return true;
}

static bool seed_poison_rows(sqlite3 *db, int height, const char *vh_reason,
                             int vh_ok)
{
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height,hash,ok,fail_reason,validated_at) "
        "VALUES(%d,zeroblob(32),%d,%s,1);"
        "INSERT OR REPLACE INTO body_fetch_log"
        "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
        "VALUES(%d,zeroblob(32),'skipped_invalid',0,1,0,"
        "'header_validation_failed');"
        "INSERT OR REPLACE INTO body_persist_log"
        "(height,source,ok,persisted_at) VALUES(%d,'upstream_failed',0,1);"
        "INSERT OR REPLACE INTO script_validate_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);"
        "INSERT OR REPLACE INTO proof_validate_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);"
        "INSERT OR REPLACE INTO utxo_apply_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);"
        "INSERT OR REPLACE INTO utxo_apply_delta(height) VALUES(%d);"
        "INSERT OR REPLACE INTO tip_finalize_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);",
        height, vh_ok, vh_reason ? vh_reason : "NULL",
        height, height, height, height, height, height, height);
    return exec_sql(db, sql);
}

static bool seed_reducer_success(sqlite3 *db, int height)
{
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height,hash,ok,fail_reason,validated_at) "
        "VALUES(%d,zeroblob(32),1,NULL,1);"
        "INSERT OR REPLACE INTO body_persist_log"
        "(height,source,ok,persisted_at) VALUES(%d,'test',1,1);"
        "INSERT OR REPLACE INTO script_validate_log"
        "(height,status,ok,block_hash) VALUES(%d,'ok',1,zeroblob(32));"
        "INSERT OR REPLACE INTO proof_validate_log"
        "(height,status,ok) VALUES(%d,'ok',1);"
        "INSERT OR REPLACE INTO utxo_apply_log"
        "(height,status,ok) VALUES(%d,'ok',1);"
        "INSERT OR REPLACE INTO tip_finalize_log"
        "(height,status,ok) VALUES(%d,'finalized',1);",
        height, height, height, height, height, height);
    return exec_sql(db, sql);
}

/* Set a 32-byte hash column (validate_headers_log.hash /
 * script_validate_log.block_hash) to the canonical block hash so a folded
 * success column matches the on-chain header (no hash-mismatch poison). */
static bool set_hash_col(sqlite3 *db, const char *table, const char *col,
                         int height, const struct uint256 *h)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "UPDATE %s SET %s=? WHERE height=?", table, col);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, h->data, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Build a deterministic solutionless-mode repair header for `height`. Its hash
 * is wired into the on-chain block_index entry so the hash-bound availability
 * check (stage_repair_header_solution_available with canon) accepts it. The
 * 32-byte solution stands in for the real Equihash witness — validate_headers
 * (not this table) re-runs PoW in production; this test exercises the repair
 * plumbing + source attribution, matching the sibling condition tests. */
static void build_repair_header(int height, struct block_header *out)
{
    block_header_init(out);
    out->nVersion = 4;
    out->hashPrevBlock.data[0] = (uint8_t)(height - 1);
    out->hashPrevBlock.data[1] = 0xA7;
    out->hashMerkleRoot.data[0] = (uint8_t)height;
    out->hashMerkleRoot.data[1] = 0xB8;
    out->hashFinalSaplingRoot.data[0] = (uint8_t)height;
    out->hashFinalSaplingRoot.data[1] = 0xC9;
    out->nTime = 1700000000u + (uint32_t)height;
    out->nBits = 0x1f07ffff;
    out->nNonce.data[0] = (uint8_t)height;
    out->nNonce.data[1] = 0xDA;
    out->nSolutionSize = 32;
    for (size_t i = 0; i < out->nSolutionSize; i++)
        out->nSolution[i] = (uint8_t)(height + (int)i);
}

/* main_state with genesis + one block at `height` whose hash == hash(repair
 * header at `height`), so canon-bound availability works. HAVE_DATA set so the
 * P2P re-fetch has an indexed height to clear. */
static void setup_main_state_wired(struct main_state *ms,
                                   struct block_index blocks[2],
                                   struct uint256 hashes[2],
                                   const struct uint256 *repair_hash)
{
    main_state_init(ms);
    block_index_init(&blocks[0]);
    memset(&hashes[0], 0, sizeof(hashes[0]));
    hashes[0].data[1] = 0xA7;
    blocks[0].phashBlock = &hashes[0];
    blocks[0].nHeight = 0;
    blocks[0].nStatus = BLOCK_VALID_TREE;

    block_index_init(&blocks[1]);
    hashes[1] = *repair_hash;
    blocks[1].phashBlock = &hashes[1];
    blocks[1].nHeight = 1;
    blocks[1].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    blocks[1].pprev = &blocks[0];
    active_chain_move_window_tip(&ms->chain_active, &blocks[1]);
    ms->pindex_best_header = &blocks[1];
}

/* Point header_probe's oracle at a dead port so the pull genuinely attempts a
 * connection and fails (rpc_errors climbs), then the remedy falls to P2P. */
static void init_dead_oracle(struct main_state *ms)
{
    const struct chain_params *params = chain_params_get();
    struct header_probe_config cfg = {
        .rpc_host = "127.0.0.1",
        .rpc_port = 1,          /* privileged, never listened by a user proc */
        .rpc_user = "u",
        .rpc_password = "p",
        .batch_size = 8,
        .lag_threshold = 1,
    };
    (void)header_probe_init(&cfg, ms, params);
}

static bool case_setup(const char *tag, char *dir, size_t dir_n,
                       struct main_state *ms, struct block_index blocks[2],
                       struct uint256 hashes[2],
                       const struct uint256 *repair_hash,
                       struct download_manager *dm)
{
    condition_engine_reset_for_testing();
    stale_validate_headers_repair_test_reset();
    header_probe_reset_for_test();
    header_serve_repair_test_reset();
    blocker_reset_for_testing();
    reducer_frontier_test_set_compiled_anchor(1);
    stale_validate_headers_repair_test_set_hstar_override(0);
    test_make_tmpdir(dir, dir_n, "hp_p2p_fallback", tag);
    if (!progress_store_open(dir))
        return false;
    setup_main_state_wired(ms, blocks, hashes, repair_hash);
    dl_init(dm);
    sync_monitor_init();
    sync_monitor_set_context(NULL, dm, ms);
    condition_engine_set_main_state(ms);
    init_dead_oracle(ms);
    register_stale_validate_headers_repair();
    return seed_schema(progress_store_db()) &&
           seed_proven_authority(progress_store_db(), 1);
}

static void case_teardown(const char *dir, struct main_state *ms,
                          struct download_manager *dm)
{
    sync_monitor_set_context(NULL, NULL, NULL);
    condition_engine_set_main_state(NULL);
    header_probe_reset_for_test();
    header_serve_repair_test_reset();
    dl_free(dm);
    main_state_free(ms);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    reducer_frontier_test_set_compiled_anchor(-1);
    stale_validate_headers_repair_test_set_hstar_override(-1);
    condition_engine_reset_for_testing();
    blocker_reset_for_testing();
}

/* ── Case 3 net harness (mirrors test_process_headers_adversarial.c) ────── */

static struct net_manager g_hpf_nm;

static void hpf_setup_node(struct p2p_node *node)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "203.0.113.9:8033");
    node->id = 9;
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 1;
    node->addr.svc.addr.ip[13] = 2;
    node->addr.svc.addr.ip[14] = 3;
    node->addr.svc.addr.ip[15] = 4;
}

static bool hpf_mine_header(struct block_header *out, int height,
                            const struct uint256 *prev,
                            const struct chain_params *cp)
{
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.hashPrevBlock = *prev;
    uint256_set_null(&blk.header.hashMerkleRoot);
    blk.header.hashMerkleRoot.data[0] = (uint8_t)height;
    uint256_set_null(&blk.header.hashFinalSaplingRoot);
    blk.header.nTime = 1600000000u + (uint32_t)height;
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk.header.nBits = arith_uint256_get_compact(&pow_limit, false);
    bool ok = mine_block_pow(&blk, height, cp, 0);
    if (ok)
        *out = blk.header;
    block_free(&blk);
    return ok;
}

static bool hpf_write_header(struct byte_stream *s,
                             const struct block_header *hdr)
{
    return block_header_serialize(hdr, s) &&
           stream_write_compact_size(s, 0);
}

/* Drive a single-header `headers` message and return the peer's misbehavior. */
static int hpf_drive_one_header(struct msg_processor *mp, struct p2p_node *node,
                                const struct block_header *hdr)
{
    node->disconnect = false;
    atomic_store(&node->misbehavior, 0);
    struct byte_stream s;
    stream_init(&s, 1024);
    stream_write_compact_size(&s, 1);
    hpf_write_header(&s, hdr);
    (void)process_headers(mp, node, &s);
    stream_free(&s);
    return atomic_load(&node->misbehavior);
}

/* ── Cases 1 & 2 (P2P repair + missing-input) ──────────────────────────── */

static int run_p2p_repair_case(void)
{
    int failures = 0;
    char dir[256];
    struct main_state ms;
    struct block_index blocks[2];
    struct uint256 hashes[2];
    struct download_manager dm;

    struct block_header rh;
    build_repair_header(1, &rh);
    struct uint256 rhash;
    block_header_get_hash(&rh, &rhash);

    bool ok = case_setup("p2p_repair", dir, sizeof(dir), &ms, blocks, hashes,
                         &rhash, &dm);
    sqlite3 *db = progress_store_db();
    ok = ok && seed_cursors(db, 5, 5);
    ok = ok && seed_poison_rows(
        db, 1, "'no-header-solution-backfill-required'", 0);

    /* An honest peer is reachable for the getdata re-fetch. */
    stale_validate_headers_repair_test_set_peer_count(1);

    /* Tick 1: oracle dead → P2P getdata re-fetch requested (observable). */
    condition_engine_tick();

    struct header_probe_repair_stats s1;
    header_probe_test_get_repair_stats(&s1);
    ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
    ok = ok && condition_engine_get_active_count() == 1;
    ok = ok && (blocks[1].nStatus & BLOCK_HAVE_DATA) == 0;   /* cleared for refetch */
    ok = ok && s1.p2p_requests == 1;
    ok = ok && s1.p2p_no_peer_events == 0;                   /* peers available */
    ok = ok && s1.p2p_repairs == 0;                          /* not served yet */
    ok = ok && s1.last_repair_height == 1;
    ok = ok && header_serve_repair_test_armed();
    ok = ok && header_serve_repair_test_expected_count() == 1;
    ok = ok && header_serve_repair_wants(&blocks[1]);
    ok = ok && dm.queue_len == 1 && dm.queue_heights[0] == 1;
    ok = ok && uint256_eq(&dm.queue[0], &rhash);
    ok = ok && !blocker_exists(HPF_NO_SOURCE_BLOCKER_ID);
    HPF_CHECK("oracle dead → bounded header-only repair armed + full-block "
              "fallback requested (no premature repair or missing-input "
              "blocker)", ok);

    /* Simulate the honest peer's block arriving: reducer_cache_ingested_solution
     * saves the re-validated solution hash-bound into the repair table. */
    ok = ok && stage_repair_header_solution_save(db, 1, &rhash, &rh);
    ok = ok && stage_repair_header_solution_available(db, 1, &rhash);

    /* Tick 2: remedy sees the solution present, attributes it to P2P. */
    stale_validate_headers_repair_test_clear_backoff();
    condition_engine_tick();

    struct header_probe_repair_stats s2;
    header_probe_test_get_repair_stats(&s2);
    ok = ok && stale_validate_headers_repair_test_remedy_calls() == 2;
    ok = ok && s2.p2p_repairs == 1;
    ok = ok && s2.oracle_repairs == 0;
    ok = ok && s2.last_repair_source == HEADER_PROBE_SRC_P2P;
    ok = ok && s2.last_repair_height == 1;
    HPF_CHECK("P2P-delivered canonical solution re-validates + repair is "
              "attributed to the P2P source", ok);

    /* The reducer folds the re-fetched block all the way through (a fully
     * consistent success column at the frontier) → detect goes false and the
     * Condition deactivates. Proves the repair is not a latch. */
    ok = ok && seed_reducer_success(db, 1);
    ok = ok && exec_sql(db,
        "UPDATE body_fetch_log SET ok=1, source='p2p', fail_reason=NULL "
        "WHERE height=1");
    /* Match the folded stage hashes to the canonical on-chain header so no
     * hash-mismatch poison remains, and model H* advancing to the repaired
     * height (the sole witness success predicate). */
    ok = ok && set_hash_col(db, "validate_headers_log", "hash", 1, &rhash);
    ok = ok && set_hash_col(db, "script_validate_log", "block_hash", 1, &rhash);
    stale_validate_headers_repair_test_set_hstar_override(1);
    stale_validate_headers_repair_test_clear_backoff();
    condition_engine_tick();
    ok = ok && condition_engine_get_active_count() == 0;
    HPF_CHECK("repaired frontier folds through + H* advances → Condition "
              "clears (no latch)", ok);

    case_teardown(dir, &ms, &dm);
    return failures;
}

static int run_missing_input_case(void)
{
    int failures = 0;
    char dir[256];
    struct main_state ms;
    struct block_index blocks[2];
    struct uint256 hashes[2];
    struct download_manager dm;

    struct block_header rh;
    build_repair_header(1, &rh);
    struct uint256 rhash;
    block_header_get_hash(&rh, &rhash);

    bool ok = case_setup("missing_input", dir, sizeof(dir), &ms, blocks, hashes,
                         &rhash, &dm);
    sqlite3 *db = progress_store_db();
    ok = ok && seed_cursors(db, 5, 5);
    ok = ok && seed_poison_rows(
        db, 1, "'no-header-solution-backfill-required'", 0);

    /* Oracle dead AND no peers: neither source can serve right now. */
    stale_validate_headers_repair_test_set_peer_count(0);

    condition_engine_tick();

    struct header_probe_repair_stats s1;
    header_probe_test_get_repair_stats(&s1);
    struct condition_runtime_snapshot snap;
    bool got = condition_engine_get_registered_snapshot(
        "stale_validate_headers_repair", &snap);
    ok = ok && stale_validate_headers_repair_test_remedy_calls() == 1;
    ok = ok && got && snap.last_outcome == COND_REMEDY_SKIP;   /* not FAILED */
    ok = ok && condition_engine_get_active_count() == 1;       /* stays active */
    ok = ok && s1.p2p_requests == 1;
    ok = ok && s1.p2p_no_peer_events == 1;
    ok = ok && blocker_exists(HPF_NO_SOURCE_BLOCKER_ID);       /* named input */
    ok = ok && blocker_class_for(HPF_NO_SOURCE_BLOCKER_ID) == BLOCKER_TRANSIENT;
    HPF_CHECK("no oracle + no peers → typed blocker names the missing input, "
              "Condition stays active + defers (no operator-page latch)", ok);

    /* A source returns: peer reachable + block delivered → repair completes and
     * the blocker clears. */
    stale_validate_headers_repair_test_set_peer_count(1);
    ok = ok && stage_repair_header_solution_save(db, 1, &rhash, &rh);
    stale_validate_headers_repair_test_clear_backoff();
    condition_engine_tick();

    struct header_probe_repair_stats s2;
    header_probe_test_get_repair_stats(&s2);
    ok = ok && s2.p2p_repairs == 1;
    ok = ok && s2.last_repair_source == HEADER_PROBE_SRC_P2P;
    ok = ok && !blocker_exists(HPF_NO_SOURCE_BLOCKER_ID);      /* cleared */
    HPF_CHECK("blocker clears + repair serves once a P2P source returns "
              "(recoverable class never permanently gives up)", ok);

    case_teardown(dir, &ms, &dm);
    return failures;
}

static int run_invalid_header_scoring_case(void)
{
    int failures = 0;

    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    peer_scoring_init();

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "hp_p2p_score", "main");
    SetDataDir(dir);

    struct main_state ms;
    main_state_init(&ms);
    struct uint256 gh = cp->consensus.hashGenesisBlock;
    struct block_index *gen =
        chainstate_insert_block_index((struct chainstate *)&ms, &gh);
    if (gen) {
        gen->nHeight = 0;
        gen->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        gen->nTx = 1;
        gen->nChainTx = 1;
        active_chain_move_window_tip(&ms.chain_active, gen);
        ms.pindex_best_header = gen;
    }

    memset(&g_hpf_nm, 0, sizeof(g_hpf_nm));
    struct msg_processor mp;
    msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_hpf_nm, NULL);

    struct p2p_node node;
    hpf_setup_node(&node);

    /* Control: an honest, PoW-valid header must NOT be penalized. */
    struct block_header good;
    bool mined = gen && hpf_mine_header(&good, 1, &gh, cp);
    HPF_CHECK("valid regtest header mined", mined);
    if (mined) {
        int score = hpf_drive_one_header(&mp, &node, &good);
        HPF_CHECK("honest peer serving a valid header is NOT scored",
                  score == 0 && !node.disconnect);
    }

    /* Negative: corrupt the Equihash solution so the header fails PoW. The
     * detective rejects it (validate_headers never adopts it) and scores the
     * peer PEER_OFFENCE_INVALID_HEADER (weight 50). Child of genesis so the
     * parent is known and check_block_header's PoW gate runs. */
    struct block_header forged;
    bool forged_ok = gen && hpf_mine_header(&forged, 1, &gh, cp);
    if (forged_ok && forged.nSolutionSize > 0)
        forged.nSolution[0] ^= 0xFFu;   /* break the Equihash witness */
    HPF_CHECK("forged (bad-PoW) header built", forged_ok);
    if (forged_ok) {
        struct uint256 forged_hash;
        block_header_get_hash(&forged, &forged_hash);
        int score = hpf_drive_one_header(&mp, &node, &forged);
        HPF_CHECK("peer serving an invalid-PoW header is scored "
                  "PEER_OFFENCE_INVALID_HEADER (weight 50)",
                  score == peer_offence_weight(PEER_OFFENCE_INVALID_HEADER));
        /* 50 < 100 ban threshold: scored but not yet banned — the repair keeps
         * waiting rather than adopting the forged page. */
        HPF_CHECK("scored below ban threshold — forged page not adopted, "
                  "repair keeps waiting",
                  !node.disconnect);
    }

    main_state_free(&ms);
    SetDataDir("");
    ClearDataDirCache();
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);
    return failures;
}

int test_header_probe_p2p_fallback(void);
int test_header_probe_p2p_fallback(void)
{
    printf("\n=== header_probe P2P fallback (Detective A2) tests ===\n");
    int failures = 0;

    if (!blocker_module_init())
        printf("header_probe_p2p_fallback: WARN blocker_module_init failed\n");

    failures += run_p2p_repair_case();
    failures += run_missing_input_case();
    failures += run_invalid_header_scoring_case();

    printf("header_probe P2P fallback tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
