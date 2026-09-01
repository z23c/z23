/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for load_block_index_from_projection() — the event-log
 * boot rebuild (event_log -> block_index_projection -> in-memory map +
 * tip seeded from the tip_finalize cursor).
 *
 * This proves the projection-backed rebuilder in isolation:
 *
 *   1. Emit N chained EV_BLOCK_HEADER into a fresh event log (heights
 *      0..N-1, each hashPrev = the prior block's hash, genesis hashPrev
 *      = all-zero).
 *   2. Open a projection over that log; open a progress.kv store and seed
 *      the tip_finalize cursor = N with the tip hash at height N-1.
 *   3. Call load_block_index_from_projection on a fresh main_state.
 *   4. Assert: map size == N, every height/pprev linked to genesis, the
 *      active tip height == cursor-1 (== N-1) and its hash matches.
 *
 * Also covers the empty-projection (cold datadir) case: rebuild returns
 * true with an empty map and no tip.
 *
 * Scratch files live under ./test-tmp/bir_<pid>_<tag>/ in line with the
 * project's no-/tmp convention. */

#include "test/test_core.h"

#include "services/block_index_loader.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/block_index_projection.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"

#include <errno.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BIR_CHECK(name, expr) do { \
    printf("block_index_rebuild: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); (*failures)++; } \
} while (0)

/* Deterministic per-height block hash. Distinct from the all-zero
 * genesis-prev sentinel for every height >= 0. */
static struct uint256 bir_hash_at(int height)
{
    struct uint256 h;
    memset(&h, 0, sizeof(h));
    h.data[0] = (uint8_t)((height + 1) & 0xFF);
    h.data[1] = (uint8_t)(((height + 1) >> 8) & 0xFF);
    h.data[2] = (uint8_t)(((height + 1) >> 16) & 0xFF);
    h.data[31] = 0xC3;  /* tag so it can't collide with the zero sentinel */
    return h;
}

/* Build + emit one EV_BLOCK_HEADER for `height`, chaining hashPrev to
 * height-1 (all-zero for genesis). Sets HAVE_DATA | VALID_SCRIPTS so the
 * rebuilt entry looks like a finalized block. */
static bool bir_emit_height(event_log_t *log, int height)
{
    struct ev_block_header h;
    memset(&h, 0, sizeof(h));

    struct uint256 hash = bir_hash_at(height);
    memcpy(h.hash, hash.data, 32);
    if (height > 0) {
        struct uint256 prev = bir_hash_at(height - 1);
        memcpy(h.hashPrev, prev.data, 32);
    }
    h.height   = height;
    h.nStatus  = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    h.nFile    = height / 1000;
    h.nDataPos = (uint32_t)(height * 2048 + 100);
    h.nUndoPos = (uint32_t)(height * 64 + 7);
    h.nTime    = 1700000000u + (uint32_t)height * 150u;
    h.nBits    = 0x1f07ffffu;
    h.nVersion = 4;
    h.nTx      = 1;
    h.nSolutionSize = 0;

    uint8_t buf[256];
    size_t written = 0;
    if (!ev_block_header_serialize(&h, NULL, buf, sizeof(buf), &written))
        return false;
    return event_log_append(log, EV_BLOCK_HEADER, buf, written) != UINT64_MAX;
}

/* Deterministic per-height STALE-FORK block hash, distinct from both the
 * canonical hash (bir_hash_at) and the zero sentinel. Models a competing
 * block at a shared height as a real zclassicd index carries. */
static struct uint256 bir_fork_hash_at(int height)
{
    struct uint256 h;
    memset(&h, 0, sizeof(h));
    h.data[0] = (uint8_t)((height + 1) & 0xFF);
    h.data[1] = (uint8_t)(((height + 1) >> 8) & 0xFF);
    h.data[2] = (uint8_t)(((height + 1) >> 16) & 0xFF);
    h.data[30] = 0xF0;  /* fork tag */
    h.data[31] = 0xC3;
    return h;
}

/* Emit a competing fork block at `height` whose parent is the CANONICAL
 * block at height-1 (a sibling of the canonical block at this height).
 * Marked HAVE_DATA | VALID_SCRIPTS so it is a finalize-eligible candidate
 * — exactly the trap the canonical-only seed must not fall into. */
static bool bir_emit_fork(event_log_t *log, int height)
{
    struct ev_block_header h;
    memset(&h, 0, sizeof(h));

    struct uint256 hash = bir_fork_hash_at(height);
    memcpy(h.hash, hash.data, 32);
    struct uint256 prev = bir_hash_at(height - 1);  /* canonical parent */
    memcpy(h.hashPrev, prev.data, 32);
    h.height   = height;
    h.nStatus  = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    h.nFile    = height / 1000;
    h.nDataPos = (uint32_t)(height * 4096 + 200);
    h.nUndoPos = (uint32_t)(height * 128 + 9);
    h.nTime    = 1700000000u + (uint32_t)height * 150u;
    h.nBits    = 0x1f07ffffu;
    h.nVersion = 4;
    h.nTx      = 1;
    h.nSolutionSize = 0;

    uint8_t buf[256];
    size_t written = 0;
    if (!ev_block_header_serialize(&h, NULL, buf, sizeof(buf), &written))
        return false;
    return event_log_append(log, EV_BLOCK_HEADER, buf, written) != UINT64_MAX;
}

/* Seed the tip_finalize cursor + an ANCHOR row at `tip_height` in the
 * progress.kv store. This DELIBERATELY uses the LEGACY +1 lattice (anchor
 * row at T carrying the block's OWN hash, cursor at T+1) — even though
 * tip_finalize_stage_seed_anchor now stamps the cursor to T (the served-tip
 * convention, task #31) — precisely to keep coverage that
 * tip_finalize_stage_resolve_durable_tip tolerates BOTH conventions: its
 * cursor-then-cursor-1 fold resolves T from a cursor of T+1 here. The
 * earlier version wrote a 'finalized' row at T carrying hash(T) — a
 * convention that does not exist in the live store (finalized rows carry the
 * LOOKAHEAD hash(T+1)); it only passed because the loader used the same
 * convention-blind raw read this seeding mirrored. The loader now resolves
 * via tip_finalize_stage_resolve_durable_tip. */
static bool bir_seed_tip_cursor(sqlite3 *pk, int tip_height,
                                const struct uint256 *tip_hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pk,
        "INSERT OR REPLACE INTO stage_cursor (name, cursor, updated_at) "
        "VALUES ('tip_finalize', ?, 0)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, (int64_t)tip_height + 1);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;

    /* tip_finalize_log row carrying the tip hash at the finalized height.
     * Mirror the columns tip_finalize_stage_finalized_tip_at reads. */
    if (sqlite3_exec(pk,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  work_delta_high INTEGER NOT NULL, work_delta_low INTEGER NOT NULL,"
        "  utxo_size_after INTEGER NOT NULL, reorg_depth INTEGER NOT NULL,"
        "  finalized_at INTEGER NOT NULL, tip_hash BLOB)",
        NULL, NULL, NULL) != SQLITE_OK)
        return false;

    st = NULL;
    if (sqlite3_prepare_v2(pk,
        "INSERT OR REPLACE INTO tip_finalize_log "
        "(height,status,ok,work_delta_high,work_delta_low,utxo_size_after,"
        " reorg_depth,finalized_at,tip_hash) "
        "VALUES (?, 'anchor', 1, 0, 0, 0, 0, 0, ?)", -1, &st, NULL)
        != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, tip_height);
    sqlite3_bind_blob(st, 2, tip_hash->data, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* ── Test 1: N synthetic headers fold into a map of size N, tip=cursor-1 ── */

static int run_rebuild_n_headers(int *failures)
{
    int start_failures = *failures;
    const int N = 64;

    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/bir_%d_n", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/event_log.dat", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/bip.db", dir);

    event_log_t *log = event_log_open(el_path);
    BIR_CHECK("n: event log opens", log != NULL);
    if (!log) goto done;

    bool emit_ok = true;
    for (int h = 0; h < N; h++)
        emit_ok = emit_ok && bir_emit_height(log, h);
    BIR_CHECK("n: emitted N chained headers", emit_ok);

    block_index_projection_t *bip = block_index_projection_open(db_path, log);
    BIR_CHECK("n: projection opens", bip != NULL);
    if (!bip) { event_log_close(log); goto done; }

    /* progress.kv: cursor=N, tip hash at height N-1. Close any store a
     * prior test left open so this datadir wins (singleton, one path). */
    progress_store_close();
    bool pk_ok = progress_store_open(dir);
    BIR_CHECK("n: progress store opens", pk_ok);
    sqlite3 *pk = progress_store_db();
    struct uint256 tip_hash = bir_hash_at(N - 1);
    BIR_CHECK("n: seed tip cursor", pk && bir_seed_tip_cursor(pk, N - 1, &tip_hash));

    /* Fresh chainstate. */
    struct main_state ms;
    main_state_init(&ms);

    const struct chain_params *params = chain_params_get();
    bool rebuilt = load_block_index_from_projection(&ms, params, bip, pk).ok;
    BIR_CHECK("n: rebuild returns true", rebuilt);

    /* N folded headers + the bare genesis node the loader inserts so block
     * 1's pprev resolves (the synthetic height-0 hash != params genesis, so
     * the loader's genesis-ensure at block_index_loader_rebuild.c:345 adds
     * one). In production the height-0 block IS genesis, so no extra node. */
    BIR_CHECK("n: map size == N (+1 loader genesis)",
              ms.map_block_index.size == (size_t)(N + 1));

    /* Every height present, heights match. */
    bool heights_ok = true;
    for (int h = 0; h < N && heights_ok; h++) {
        struct uint256 hh = bir_hash_at(h);
        struct block_index *bi = block_map_find(&ms.map_block_index, &hh);
        if (!bi || bi->nHeight != h) heights_ok = false;
        if (bi && !(bi->nStatus & BLOCK_HAVE_DATA)) heights_ok = false;
    }
    BIR_CHECK("n: all heights present with HAVE_DATA", heights_ok);

    /* pprev chain walks from tip to genesis (N hops). */
    struct uint256 tip_h = bir_hash_at(N - 1);
    struct block_index *tip = block_map_find(&ms.map_block_index, &tip_h);
    int hops = 0;
    for (struct block_index *p = tip; p && hops <= N; p = p->pprev) hops++;
    BIR_CHECK("n: pprev walk tip->genesis is N hops", hops == N);

    /* nChainWork strictly increases tip > genesis (forward pass ran). */
    struct uint256 gen_h = bir_hash_at(0);
    struct block_index *gen = block_map_find(&ms.map_block_index, &gen_h);
    BIR_CHECK("n: chain work tip > genesis",
              tip && gen &&
              arith_uint256_compare(&tip->nChainWork, &gen->nChainWork) > 0);

    /* Active tip == cursor-1 (== N-1) and hash matches the seed. */
    struct block_index *active = active_chain_tip(&ms.chain_active);
    BIR_CHECK("n: active tip set", active != NULL);
    BIR_CHECK("n: active tip height == cursor-1",
              active && active->nHeight == N - 1);
    BIR_CHECK("n: active tip hash matches cursor row",
              active && active->phashBlock &&
              uint256_eq(active->phashBlock, &tip_h));
    BIR_CHECK("n: tip_finalize last_height == cursor-1",
              tip_finalize_stage_last_height() == N - 1);

    main_state_free(&ms);
    block_index_projection_close(bip);
    progress_store_close();
    event_log_close(log);
    test_cleanup_tmpdir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 2: empty projection (cold datadir) -> empty map, no tip, true ── */

static int run_rebuild_empty(int *failures)
{
    int start_failures = *failures;

    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/bir_%d_empty", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/event_log.dat", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/bip.db", dir);

    event_log_t *log = event_log_open(el_path);
    if (!log) { *failures += 1; printf("empty: event_log_open FAIL\n"); goto done; }

    block_index_projection_t *bip = block_index_projection_open(db_path, log);
    if (!bip) { event_log_close(log); *failures += 1; goto done; }

    progress_store_close();
    bool pk_ok = progress_store_open(dir);
    sqlite3 *pk = pk_ok ? progress_store_db() : NULL;

    struct main_state ms;
    main_state_init(&ms);

    bool rebuilt = load_block_index_from_projection(&ms, chain_params_get(),
                                                    bip, pk).ok;
    BIR_CHECK("empty: rebuild returns true on empty projection", rebuilt);
    BIR_CHECK("empty: map is empty", ms.map_block_index.size == 0);
    BIR_CHECK("empty: no active tip",
              active_chain_tip(&ms.chain_active) == NULL);

    main_state_free(&ms);
    block_index_projection_close(bip);
    progress_store_close();
    event_log_close(log);
    test_cleanup_tmpdir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 3: NULL projection is a safe no-op (returns true, empty map) ── */

static int run_rebuild_null_bip(int *failures)
{
    int start_failures = *failures;

    struct main_state ms;
    main_state_init(&ms);

    bool rebuilt = load_block_index_from_projection(&ms, chain_params_get(),
                                                    NULL, NULL).ok;
    BIR_CHECK("null: rebuild returns true with NULL projection", rebuilt);
    BIR_CHECK("null: map is empty", ms.map_block_index.size == 0);

    main_state_free(&ms);
    return *failures - start_failures;
}

/* ── Test 4: competing fork at a shared height — the tip seeds CANONICAL ──
 *
 * A real zclassicd block index carries stale forks at shared heights. The
 * tip_finalize cursor records the CANONICAL tip hash, so even though the
 * fork block is folded into the map (HAVE_DATA + VALID_SCRIPTS, identical
 * height), the rebuild must seed the active tip from the cursor's canonical
 * hash, NOT the fork. A linear fixture would falsely pass this contract, so
 * this fixture preserves the competing-fork regression case. */
static int run_rebuild_competing_fork(int *failures)
{
    int start_failures = *failures;
    const int N = 32;           /* canonical heights 0..N-1 */
    const int FORK_AT = N - 1;  /* fork competes at the tip height */

    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/bir_%d_fork", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/event_log.dat", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/bip.db", dir);

    event_log_t *log = event_log_open(el_path);
    BIR_CHECK("fork: event log opens", log != NULL);
    if (!log) goto done;

    bool emit_ok = true;
    for (int h = 0; h < N; h++)
        emit_ok = emit_ok && bir_emit_height(log, h);
    /* Emit the competing fork at the tip height AFTER the canonical block,
     * so naive last-writer/iteration-order logic would prefer the fork. */
    emit_ok = emit_ok && bir_emit_fork(log, FORK_AT);
    BIR_CHECK("fork: emitted canonical chain + competing fork", emit_ok);

    block_index_projection_t *bip = block_index_projection_open(db_path, log);
    BIR_CHECK("fork: projection opens", bip != NULL);
    if (!bip) { event_log_close(log); goto done; }

    /* Cursor records the CANONICAL tip hash at height N-1. */
    progress_store_close();
    bool pk_ok = progress_store_open(dir);
    BIR_CHECK("fork: progress store opens", pk_ok);
    sqlite3 *pk = progress_store_db();
    struct uint256 canon_tip = bir_hash_at(FORK_AT);
    BIR_CHECK("fork: seed canonical tip cursor",
              pk && bir_seed_tip_cursor(pk, FORK_AT, &canon_tip));

    struct main_state ms;
    main_state_init(&ms);

    bool rebuilt = load_block_index_from_projection(&ms, chain_params_get(),
                                                    bip, pk).ok;
    BIR_CHECK("fork: rebuild returns true", rebuilt);

    /* Both the canonical block AND the fork are in the map (N canonical +
     * 1 fork), plus the bare genesis node the loader inserts (see above) =
     * N+2 entries. The fold keeps every header; only the tip selection must
     * be canonical. */
    BIR_CHECK("fork: map holds canonical + fork (+1 loader genesis)",
              ms.map_block_index.size == (size_t)(N + 2));

    struct uint256 fork_hash = bir_fork_hash_at(FORK_AT);
    struct block_index *fork_bi = block_map_find(&ms.map_block_index, &fork_hash);
    BIR_CHECK("fork: fork block present in map", fork_bi != NULL);

    /* THE contract: active tip is the CANONICAL hash, not the fork. */
    struct block_index *active = active_chain_tip(&ms.chain_active);
    BIR_CHECK("fork: active tip set", active != NULL);
    BIR_CHECK("fork: active tip height == N-1",
              active && active->nHeight == FORK_AT);
    BIR_CHECK("fork: active tip is CANONICAL hash (not the fork)",
              active && active->phashBlock &&
              uint256_eq(active->phashBlock, &canon_tip));
    BIR_CHECK("fork: active tip is NOT the fork hash",
              active && active->phashBlock &&
              !uint256_eq(active->phashBlock, &fork_hash));

    main_state_free(&ms);
    block_index_projection_close(bip);
    progress_store_close();
    event_log_close(log);
    test_cleanup_tmpdir(dir);
done:
    return *failures - start_failures;
}

int test_block_index_rebuild(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== block_index_rebuild tests ===\n");
    int failures = 0;

    run_rebuild_n_headers(&failures);
    run_rebuild_empty(&failures);
    run_rebuild_null_bip(&failures);
    run_rebuild_competing_fork(&failures);

    printf("block_index_rebuild: %d failures\n", failures);
    return failures;
}
