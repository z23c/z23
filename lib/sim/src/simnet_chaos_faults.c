/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet chaos-fault injectors. See sim/simnet_chaos_faults.h for the
 * per-fault contract and the mission this file serves.
 *
 * Fixture idioms below are deliberately copied (not `#include`d — the
 * originals are file-static) from three already-reviewed regression tests,
 * so the row shapes and column lists are proven-correct, not reinvented:
 *   - lib/test/src/test_reducer_frontier.c   (put_consistent_height family)
 *   - lib/test/src/test_block_index_loader.c (genesis-root seed_tip fixture)
 *   - lib/test/src/test_segment_corruption.c (seal/tamper/detect/repair)
 *   - lib/test/src/test_supervisor.c         (freeze/deadline-stall pattern)
 *   - lib/test/src/test_condition_engine.c   (condition + EV_OPERATOR_NEEDED
 *                                              counting pattern)
 */

#include "sim/simnet_chaos_faults.h"

#include "test/test_helpers.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "coins/coins_view.h"
#include "conditions/segment_corruption.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "event/event.h"
#include "framework/condition.h"
#include "json/json.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_rederive_range.h"
#include "jobs/stage_repair.h"
#include "jobs/stage_row_itag.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "net/download.h"
#include "net/file_service.h"
#include "net/rom_fetch.h"
#include "net/rom_journal.h"
#include "net/rom_peer_scoring.h"
#include "net/rom_seed.h"
#include "platform/time_compat.h"
#include "sim/simnet.h"
#include "sim/simnet_byzantine.h"
#include "storage/chain_segment.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "sync/sync_planner.h"
#include "sync/sync_reduce.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "util/supervisor.h"
#include "validation/chainstate.h"
#include "validation/connect_block.h"
#include "validation/main_state.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void chaos_note(struct chaos_fault_result *out, const char *fmt, ...)
{
    if (!out) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out->note, sizeof(out->note), fmt, ap);
    va_end(ap);
}

static void chaos_result_init(struct chaos_fault_result *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->hstar_before = -1;
    out->hstar_after = -1;
}

/* ── shared stage-log fixture helpers (mirrors test_reducer_frontier.c) ─── */

/* The per-stage *_log tables (plus the header_admit_log MODEL table and the
 * utxo_apply_delta sidecar) are lazily created by their owning module the
 * first time its production init/step path runs — this fixture never runs
 * the full stage machinery (only tip_finalize_stage_init, for the anchor
 * write), so the rest would not exist yet. reducer_frontier_compute_hstar's
 * hash-agreement cross-check (reducer_frontier_evidence.c) additionally
 * JOINs header_admit_log and utxo_apply_delta against validate_headers_log,
 * so both need real, hash-matching rows too, not just the six k_logs[]
 * tables. CREATE TABLE IF NOT EXISTS with the EXACT production column list
 * (verified against the live source above) is idempotent and safe to call
 * unconditionally: a real ensure_schema call elsewhere on the same db is a
 * silent no-op against identical DDL text. */
static bool chaos_ensure_log_tables(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height      INTEGER PRIMARY KEY,"
        "  hash        BLOB    NOT NULL,"
        "  parent_hash BLOB,"
        "  admitted_at INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "  height       INTEGER PRIMARY KEY,"
        "  branch_hash  BLOB    NOT NULL,"
        "  spent_blob   BLOB    NOT NULL,"
        "  added_blob   BLOB    NOT NULL"
        ");"
        /* The six stage *_log tables carry the production `itag` column and the
         * fixture stamps it on every write (chaos_itag), so the reducer fold's
         * per-row integrity check verifies them exactly as it does a live datadir
         * — no untagged (ABSENT) rows, no stale (MISMATCH) rows. In fault (a) the
         * production seed path creates utxo_apply_log/tip_finalize_log first; the
         * CREATE-IF-NOT-EXISTS here is then a no-op and those tables keep the
         * production schema (which already ALTER-adds itag). */
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height       INTEGER PRIMARY KEY,"
        "  hash         BLOB    NOT NULL,"
        "  ok           INTEGER NOT NULL,"
        "  fail_reason  TEXT,"
        "  validated_at INTEGER NOT NULL,"
        "  itag         BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height             INTEGER PRIMARY KEY,"
        "  status             TEXT    NOT NULL,"
        "  ok                 INTEGER NOT NULL,"
        "  tx_count           INTEGER NOT NULL,"
        "  input_count        INTEGER NOT NULL,"
        "  first_failure_txid BLOB,"
        "  first_failure_vin  INTEGER,"
        "  first_failure_serror INTEGER,"
        "  validated_at       INTEGER NOT NULL,"
        "  block_hash         BLOB,"
        "  source_epoch_digest BLOB,"
        "  itag               BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height       INTEGER PRIMARY KEY,"
        "  source       TEXT    NOT NULL,"
        "  ok           INTEGER NOT NULL,"
        "  persisted_at INTEGER NOT NULL,"
        "  itag         BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height                  INTEGER PRIMARY KEY,"
        "  status                  TEXT    NOT NULL,"
        "  ok                      INTEGER NOT NULL,"
        "  sapling_spends_total    INTEGER NOT NULL,"
        "  sapling_outputs_total   INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL,"
        "  block_hash              BLOB,"
        "  source_epoch_digest     BLOB,"
        "  first_failure_txid      BLOB,"
        "  first_failure_proof_type TEXT,"
        "  validated_at            INTEGER NOT NULL,"
        "  itag                    BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height               INTEGER PRIMARY KEY,"
        "  status               TEXT    NOT NULL,"
        "  ok                   INTEGER NOT NULL,"
        "  spent_count          INTEGER NOT NULL,"
        "  added_count          INTEGER NOT NULL,"
        "  total_value_delta    INTEGER NOT NULL,"
        "  first_failure_kind   TEXT,"
        "  first_failure_detail BLOB,"
        "  applied_at           INTEGER NOT NULL,"
        "  itag                 BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height           INTEGER PRIMARY KEY,"
        "  status           TEXT    NOT NULL,"
        "  ok               INTEGER NOT NULL,"
        "  work_delta_high  INTEGER NOT NULL,"
        "  work_delta_low   INTEGER NOT NULL,"
        "  utxo_size_after  INTEGER NOT NULL,"
        "  reorg_depth      INTEGER NOT NULL,"
        "  finalized_at     INTEGER NOT NULL,"
        "  itag             BLOB"
        ");";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {  // raw-sql-ok:test-fixture-schema
        fprintf(stderr, "[chaos] ensure_log_tables: %s\n", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* Each helper below matches the EXACT real CREATE TABLE column list emitted
 * by the corresponding production module (re-checked against the live
 * source at the time this file was written — every NOT NULL column without
 * a DEFAULT gets an explicit harmless value; compute_hstar's contiguity scan
 * only ever reads height/ok/status/hash, its hash-agreement cross-check also
 * reads hash/block_hash/branch_hash, so the placeholder values in the rest
 * are inert).
 *
 * Every write here is an UPSERT (INSERT ... ON CONFLICT(height) DO UPDATE),
 * not a plain INSERT: tip_finalize_stage_seed_anchor's trusted-seed path
 * ALSO writes a real production row at the anchor height into utxo_apply_log
 * (status='anchor', so it can self-finalize the first C→C+1 transition —
 * see the "seed utxo_apply anchor row" comment in
 * app/jobs/src/tip_finalize_anchor.c). utxo_apply_log is profile_bound
 * (log_success_requires_full_validation), so a status of 'anchor' fails the
 * VERIFIED parse and would silently cap the contiguous prefix one height
 * short — exactly the off-by-one this upsert avoids. The fixture's own
 * consistent, hash-agreeing row must always win at every height it stamps,
 * never lose to whatever a production seed path wrote first. tip_finalize_log
 * is the one exception (kept OR IGNORE, see chaos_put_tip_finalize) since
 * overwriting its anchor row's status would itself change which row
 * reducer_trusted_anchor's own status='anchor' lookup finds. */

/* Compute the production integrity tag for an ok=1 stage-log row exactly as the
 * live writers do (stage_row_itag_compute decides internally whether `status` is
 * folded in — only for the three status-covered logs), so the reducer fold's
 * per-row verify MATCHes every fixture row instead of seeing a stale/absent tag.
 * All fixture rows are ok=1 (a fully consistent prefix). */
static void chaos_itag(const char *table, int32_t h, const char *status,
                       uint8_t out[STAGE_ROW_ITAG_LEN])
{
    stage_row_itag_compute(table, (int64_t)h, 1,
                           status, status ? strlen(status) : 0, out);
}

static bool chaos_put_header_admit(sqlite3 *db, int32_t h,
                                   const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO header_admit_log(height,hash,admitted_at) "
            "VALUES(?,?,0) ON CONFLICT(height) DO UPDATE SET "
            "hash=excluded.hash", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_validate_headers(sqlite3 *db, int32_t h,
                                       const uint8_t hash[32])
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("validate_headers_log", h, NULL, itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO validate_headers_log(height,hash,ok,validated_at,itag) "
            "VALUES(?,?,1,0,?) ON CONFLICT(height) DO UPDATE SET "
            "hash=excluded.hash, ok=1, itag=excluded.itag", -1, &st, NULL)
            != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_script_validate(sqlite3 *db, int32_t h,
                                      const uint8_t hash[32])
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("script_validate_log", h, "verified", itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO script_validate_log"
            "(height,status,ok,tx_count,input_count,validated_at,block_hash,itag) "
            "VALUES(?,'verified',1,1,1,0,?,?) ON CONFLICT(height) DO UPDATE "
            "SET status='verified', ok=1, block_hash=excluded.block_hash, "
            "itag=excluded.itag",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_body_persist(sqlite3 *db, int32_t h)
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("body_persist_log", h, NULL, itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO body_persist_log(height,source,ok,persisted_at,itag) "
            "VALUES(?,'chaos_fixture',1,0,?) ON CONFLICT(height) DO UPDATE "
            "SET ok=1, itag=excluded.itag", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_proof_validate(sqlite3 *db, int32_t h,
                                     const uint8_t hash[32])
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("proof_validate_log", h, "verified", itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO proof_validate_log"
            "(height,status,ok,sapling_spends_total,sapling_outputs_total,"
            "sprout_joinsplits_total,block_hash,validated_at,itag) "
            "VALUES(?,'verified',1,0,0,0,?,0,?) ON CONFLICT(height) DO UPDATE "
            "SET status='verified', ok=1, block_hash=excluded.block_hash, "
            "itag=excluded.itag",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_utxo_apply(sqlite3 *db, int32_t h)
{
    /* status is overwritten 'anchor'->'verified' when this UPSERTs the row the
     * production tip_finalize seed anchor wrote (see the header comment above):
     * utxo_apply_log is status-covered, so the seed's itag (over 'anchor') would
     * no longer recompute and the fold would read a MISMATCH and cap H* one short.
     * Re-stamp the itag over the NEW ('verified') fields via excluded.itag so the
     * overwritten row verifies cleanly and H* climbs to the full height. */
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("utxo_apply_log", h, "verified", itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_log"
            "(height,status,ok,spent_count,added_count,total_value_delta,"
            "applied_at,itag) VALUES(?,'verified',1,0,0,0,0,?) "
            "ON CONFLICT(height) DO UPDATE SET status='verified', ok=1, "
            "itag=excluded.itag",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_utxo_apply_delta(sqlite3 *db, int32_t h,
                                       const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(?,?,x'',x'') ON CONFLICT(height) DO UPDATE SET "
            "branch_hash=excluded.branch_hash", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

/* OR IGNORE (not upsert): fault (a) may call this for the height whose
 * tip_finalize_log row was already written by
 * tip_finalize_stage_seed_anchor() (the anchor row at N is pipeline-owned —
 * see reducer_frontier.h's frontier_next_cursor commentary). Its status
 * text ('anchor') is load-bearing for reducer_trusted_anchor's own lookup
 * (`WHERE status='anchor'`) — overwriting it would change which row that
 * scan finds, an unrelated behavior this fixture must not perturb. Silently
 * keeping the existing ok=1 row is correct: tip_finalize_log is not
 * profile_bound, so contiguity only cares about ok, not status. */
static bool chaos_put_tip_finalize(sqlite3 *db, int32_t h)
{
    /* tip_finalize_log is NOT status-covered: its itag folds only (table,height,
     * ok), so the production seed anchor row this OR IGNORE preserves at height N
     * verifies over the same fields the fixture rows below N are stamped with. */
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("tip_finalize_log", h, NULL, itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR IGNORE INTO tip_finalize_log"
            "(height,status,ok,work_delta_high,work_delta_low,"
            "utxo_size_after,reorg_depth,finalized_at,itag) "
            "VALUES(?,'ok',1,0,0,0,0,0,?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

/* Deterministic 32-byte hash keyed by height. */
static void chaos_synth_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[31] = 0xC5;
}

/* Write a full, mutually-consistent ok=1 row across every table
 * reducer_frontier_compute_hstar's contiguity scan AND hash-agreement
 * cross-check touch at height h — the same synthetic hash in
 * header_admit_log.hash, validate_headers_log.hash, script_validate_log.
 * block_hash, proof_validate_log.block_hash, and utxo_apply_delta.
 * branch_hash so the JOIN in reducer_frontier_evidence.c finds every leg
 * agreeing (no manufactured hash-split). */
static bool chaos_put_consistent_height(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    chaos_synth_hash(hh, h);
    return chaos_put_header_admit(db, h, hh) &&
           chaos_put_validate_headers(db, h, hh) &&
           chaos_put_script_validate(db, h, hh) &&
           chaos_put_body_persist(db, h) &&
           chaos_put_proof_validate(db, h, hh) &&
           chaos_put_utxo_apply(db, h) &&
           chaos_put_utxo_apply_delta(db, h, hh) &&
           chaos_put_tip_finalize(db, h);
}

/* Stamp a full consistent prefix [0, n] and the matching stage_cursor rows
 * (upstream stages count "next height"; tip_finalize is served-tip
 * convention, so its cursor is n itself, not n+1). Returns false on the
 * first sqlite error. */
static bool chaos_stamp_prefix(sqlite3 *db, int32_t n)
{
    if (!chaos_ensure_log_tables(db))
        return false;
    for (int32_t h = 0; h <= n; h++)
        if (!chaos_put_consistent_height(db, h))
            return false;
    return stage_set_named_cursor(db, "validate_headers", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "script_validate", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "body_persist", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "proof_validate", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "utxo_apply", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "tip_finalize", (uint64_t)n);
}

/* ══════════════════════════════════════════════════════════════════════
 * (a) Pillar-0: full block index, empty active-chain window
 * ══════════════════════════════════════════════════════════════════════ */

/* Forward declaration, not `#include "services/block_index_loader.h"`:
 * lib/ → app/services|controllers|models|views is a HARD layering gate
 * (tools/scripts/check_lib_layering.sh) — lib/sim must not depend on the
 * app/ shape headers. The real symbol still links fine (one binary, see
 * this file's header comment); only the SOURCE INCLUDE crosses the
 * boundary, and a bare prototype avoids that without an override marker.
 * Signature verified against app/services/include/services/
 * block_index_loader.h at the time this file was written. */
int block_index_loader_seed_tip_from_finalized(struct main_state *ms,
                                               const struct chain_params *params,
                                               struct sqlite3 *progress_db);

static struct uint256 chaos_chain_hash(const struct uint256 *genesis, int h)
{
    if (h == 0) return *genesis;
    struct uint256 hh;
    memset(&hh, 0, sizeof(hh));
    hh.data[0] = (uint8_t)(h & 0xFF);
    hh.data[1] = (uint8_t)((h >> 8) & 0xFF);
    hh.data[2] = (uint8_t)((h >> 16) & 0xFF);
    hh.data[3] = (uint8_t)((h >> 24) & 0xFF);
    hh.data[31] = 0xC2;
    return hh;
}

bool chaos_fault_empty_active_chain_window(int gap_height,
                                           struct chaos_fault_result *out)
{
    chaos_result_init(out);
    if (gap_height < 1 || gap_height > 2000000) {
        chaos_note(out, "gap_height %d out of harness range", gap_height);
        return false;
    }

    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    const struct uint256 gen = cp->consensus.hashGenesisBlock;
    int N = gap_height;

    char dir[256];
    mkdir("./test-tmp", 0755);
    test_fmt_tmpdir(dir, sizeof(dir), "chaos_empty_window", "main");
    mkdir(dir, 0755);

    progress_store_close();
    bool store_ok = progress_store_open(dir);
    sqlite3 *db = store_ok ? progress_store_db() : NULL;
    if (!db) {
        chaos_note(out, "progress_store failed to open fixture dir");
        chain_params_select(CHAIN_MAIN);
        return false;
    }

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    block_map_init(&ms.map_block_index);
    active_chain_init(&ms.chain_active);  /* NULL tip: the empty window */

    /* Build the FULL block index: genesis..N, contiguous, HAVE_DATA +
     * VALID_SCRIPTS — "the block-index map is full". */
    struct block_index *tipN = NULL;
    for (int h = 0; h <= N; h++) {
        struct uint256 hh = chaos_chain_hash(&gen, h);
        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hh);
        if (!pi) {
            chaos_note(out, "block_map insert failed at h=%d", h);
            goto cleanup;
        }
        pi->nHeight = h;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        pi->nBits = 0x200f0f0f;
        pi->hashBlock = hh;
        pi->phashBlock = &pi->hashBlock;
        if (h > 0) {
            struct uint256 prev_hash = chaos_chain_hash(&gen, h - 1);
            struct block_index *prev = block_map_find(&ms.map_block_index,
                                                       &prev_hash);
            pi->pprev = prev;
            if (prev) {
                struct arith_uint256 proof = GetBlockProof(pi);
                arith_uint256_add(&pi->nChainWork, &prev->nChainWork, &proof);
                pi->nChainTx = prev->nChainTx + pi->nTx;
            }
        } else {
            pi->nChainWork = GetBlockProof(pi);
            pi->nChainTx = 1;
        }
        if (h == N) tipN = pi;
    }

    bool tf_init = tip_finalize_stage_init(&ms);
    bool anchor_ok = tf_init &&
        tip_finalize_stage_seed_anchor(N, tipN->hashBlock.data, true);
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    bool coins_ok = utxo_apply_frontier_set_in_tx(db, N + 1);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    if (!anchor_ok || !coins_ok) {
        chaos_note(out, "fixture anchor/coins seed failed");
        goto cleanup;
    }

    /* THE FAULT: block index map is full, active_chain_tip() is NULL. Drive
     * the real boot repair path. */
    int r = block_index_loader_seed_tip_from_finalized(&ms, cp, db);
    bool installed = (r == 1) && active_chain_tip(&ms.chain_active) == tipN &&
                     active_chain_height(&ms.chain_active) == N;
    out->ok = installed;
    out->recovered = installed;

    if (installed) {
        /* H* CLIMBS, not merely "tip non-NULL": stamp the matching stage-log
         * prefix and read H* back through the real algorithm. */
        if (!chaos_stamp_prefix(db, N)) {
            chaos_note(out, "stage-log prefix stamp failed post-install");
            out->ok = false;
            goto cleanup;
        }
        int32_t hstar = -1, served = -1;
        if (!reducer_frontier_compute_hstar(db, &hstar, &served)) {
            chaos_note(out, "compute_hstar failed post-install");
            out->ok = false;
            goto cleanup;
        }
        out->hstar_before = -1;
        out->hstar_after = hstar;
        out->recovered = (hstar == N);
        chaos_note(out,
            "gap=%d INSTALLED: tip=h%d locator-anchored-at-best-header, "
            "H* climbed to %d", gap_height, N, hstar);
    } else {
        chaos_note(out,
            "gap=%d REFUSED (r=%d): active_chain_tip stays NULL — the "
            "documented Pillar-0 wedge at this gap scale", gap_height, r);
    }

cleanup:
    tip_finalize_stage_shutdown();
    progress_store_close();
    block_map_free(&ms.map_block_index);
    test_cleanup_tmpdir(dir);
    chain_params_select(CHAIN_MAIN);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (b) kill/restart mid-fold
 * ══════════════════════════════════════════════════════════════════════ */

bool chaos_fault_kill_restart_mid_fold(struct chaos_fault_result *out)
{
    chaos_result_init(out);
    const int32_t K = 37;

    char dir[256];
    mkdir("./test-tmp", 0755);
    test_fmt_tmpdir(dir, sizeof(dir), "chaos_kill_restart", "main");
    mkdir(dir, 0755);

    progress_store_close();
    if (!progress_store_open(dir)) {
        chaos_note(out, "progress_store failed to open fixture dir");
        test_cleanup_tmpdir(dir);
        return false;
    }
    sqlite3 *db = progress_store_db();
    if (!db || !chaos_stamp_prefix(db, K)) {
        chaos_note(out, "fixture stamp failed");
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return false;
    }

    int32_t hstar_before = -1, served_before = -1;
    bool ok1 = reducer_frontier_compute_hstar(db, &hstar_before, &served_before);

    /* THE FAULT: abrupt close (kill -9 before the next stage advance would
     * have committed anything further) then a fresh reopen (the restart) —
     * no in-RAM state survives; everything must be re-derived from disk. */
    progress_store_close();
    bool reopened = progress_store_open(dir);
    sqlite3 *db2 = reopened ? progress_store_db() : NULL;

    int32_t hstar_after = -1, served_after = -1;
    bool ok2 = db2 && reducer_frontier_compute_hstar(db2, &hstar_after,
                                                     &served_after);

    out->ok = ok1 && reopened && ok2;
    out->hstar_before = hstar_before;
    out->hstar_after = hstar_after;
    out->recovered = out->ok && hstar_after == hstar_before &&
                     hstar_after == K && served_after <= hstar_after;
    chaos_note(out,
        "kill/restart mid-fold: H* before=%d after=%d (served=%d) — "
        "%s", hstar_before, hstar_after, served_after,
        out->recovered ? "resumed identically, nothing lost"
                       : "DIVERGED across the restart");

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (c) corrupt a sealed chain_segment
 * ══════════════════════════════════════════════════════════════════════ */

/* test_make_tmpdir / test_rm_rf_recursive are ordinary (non-inline)
 * lib/test/src/test_helpers.c symbols, only linked into the test_zcl /
 * test_parallel binaries (lib/test is not a LIB_MODULE, so it never links
 * into production zclassic23). Guard this fault the same way as (d)/(e) so
 * a production compile never references an unresolved symbol. */
#ifdef ZCL_TESTING
static bool chaos_tiny_body(void *user, uint32_t h, uint8_t **bytes,
                            size_t *len)
{
    (void)user;
    size_t n = 24;
    uint8_t *b = malloc(n); // raw-alloc-ok:test
    if (!b) return false;
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(h * 7u + i);
    *bytes = b; *len = n;
    return true;
}

bool chaos_fault_corrupt_sealed_segment(struct chaos_fault_result *out)
{
    chaos_result_init(out);
    char err[256];
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "chaos_segment_corrupt", "flow");

    enum cseg_status s1 = chain_segment_seal_range(dir, chaos_tiny_body, NULL, // writer-below-frontier-ok: fault-injection fixture; seals only into the tmpdir it owns and deletes, never the live <datadir>/segments store
                                                   0, 10, err, sizeof(err));
    enum cseg_status s2 = chain_segment_seal_range(dir, chaos_tiny_body, NULL, // writer-below-frontier-ok: same tmpdir fixture as s1 above
                                                   500, 7, err, sizeof(err));
    if (s1 != CSEG_OK || s2 != CSEG_OK) {
        chaos_note(out, "fixture seal failed: %s", err);
        test_rm_rf_recursive(dir);
        return false;
    }

    /* THE FAULT: tamper one byte in the second segment's block-data region
     * (past the 32B header + 7*48B index). */
    char path[512];
    snprintf(path, sizeof(path), "%s/seg-500-7.dat", dir);
    chmod(path, 0644);
    FILE *f = fopen(path, "r+b");
    bool tampered = false;
    if (f) {
        long off = 32 + 7 * 48 + 3;
        fseek(f, off, SEEK_SET); int c = fgetc(f);
        fseek(f, off, SEEK_SET); fputc(c ^ 0xff, f);
        fclose(f); tampered = true;
    }
    if (!tampered) {
        chaos_note(out, "tamper write failed");
        test_rm_rf_recursive(dir);
        return false;
    }

    /* DETECT: bounded round-robin spot-verify, same primitive the
     * segment_corruption condition polls with. */
    uint32_t cursor = 1, first = 0, count = 0;
    enum cseg_status detect = segment_corruption_scan_one(dir, &cursor, &first,
                                                          &count, err,
                                                          sizeof(err));
    bool detected = detect != CSEG_OK && detect != CSEG_ERR_NOT_FOUND &&
                    first == 500 && count == 7;

    /* REMEDY: unlink + rebuild the manifest. */
    enum cseg_status remedy = CSEG_ERR_ARG;
    if (detected)
        remedy = segment_corruption_repair(dir, 500, 7, err, sizeof(err));

    /* WITNESS: reopen and confirm the corrupt range no longer verifies
     * corrupt (it's gone) while the survivor still verifies clean — reads
     * fall back to blk*.dat instead of ever serving bad bytes. */
    bool witnessed = false;
    if (remedy == CSEG_OK) {
        struct chain_segment_store *store = NULL;
        enum cseg_status ost = chain_segment_store_open(dir, &store, err,
                                                        sizeof(err));
        witnessed = ost == CSEG_OK && store &&
                   !chain_segment_store_covers(store, 500) &&
                   chain_segment_store_covers(store, 0) &&
                   chain_segment_store_segment_count(store) == 1 &&
                   chain_segment_store_verify_index(store, 0, err,
                                                    sizeof(err)) == CSEG_OK;
        if (store) chain_segment_store_close(store);
    }

    out->ok = detected && remedy == CSEG_OK;
    out->recovered = witnessed;
    chaos_note(out,
        "sealed-segment tamper: detected=%d repair=%s witnessed=%d",
        detected, cseg_status_str(remedy), witnessed);

    test_rm_rf_recursive(dir);
    return true;
}
#else
bool chaos_fault_corrupt_sealed_segment(struct chaos_fault_result *out)
{
    chaos_result_init(out);
    chaos_note(out, "unavailable: built without ZCL_TESTING");
    return false;
}
#endif /* ZCL_TESTING */

/* ══════════════════════════════════════════════════════════════════════
 * (d) freeze the reducer drive (supervisor liveness layer)
 * ══════════════════════════════════════════════════════════════════════ */

/* supervisor_reset_for_testing / supervisor_sweep_once_for_testing are only
 * declared under ZCL_TESTING (lib/util/include/util/supervisor.h); this
 * file also compiles into the production zclassic23 binary (lib/sim is a
 * LIB_MODULE linked into every target — see the Makefile's ALL_SRCS), which
 * builds WITHOUT ZCL_TESTING. The harness's own binaries (test_zcl,
 * test_parallel) always define ZCL_TESTING, so the real body below is what
 * ever executes; the #else stub exists only so a production compile — which
 * never calls this function — still links. Every helper this fault needs is
 * scoped inside the same guard so a non-ZCL_TESTING build never sees an
 * unused-static-function warning (-Werror). */
#ifdef ZCL_TESTING
static void chaos_sleep_ms(int ms)
{
    struct timespec ts = { .tv_sec = ms / 1000,
                           .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

bool chaos_fault_freeze_reducer_drive(struct chaos_fault_result *out)
{
    chaos_result_init(out);

    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(5);

    static struct liveness_contract c;
    liveness_contract_init(&c, "chaos.reducer_drive");
    atomic_store(&c.deadline_secs, 1);
    /* Gate #21 (check_supervisor_domain): production registrations must name
     * a domain grouping, not the bare root registry — this synthetic child
     * gets its own "chaos" domain rather than an override marker. */
    supervisor_domain_t *domain = supervisor_create_domain("chaos");
    supervisor_child_id id = domain
        ? supervisor_register_in_domain(domain, &c)
        : SUPERVISOR_INVALID_ID;
    if (id == SUPERVISOR_INVALID_ID) {
        chaos_note(out, "supervisor_register_in_domain failed");
        return false;
    }

    /* THE FAULT: freeze the heartbeat — backdate last_tick_us so the
     * deadline lapses on the next sweep, exactly as a wedged reducer-drive
     * thread would present to the supervisor. */
    atomic_store(&c.last_tick_us, atomic_load(&c.last_tick_us) - 5000000);

    bool started = supervisor_start();
    chaos_sleep_ms(80);

    bool stall_fired = atomic_load(&c.stall_fires) >= 1u;
    bool stall_named = atomic_load(&c.stall_reason) ==
                       SUPERVISOR_STALL_TIME_DEADLINE;

    /* UNFREEZE: a fresh heartbeat — the "self-healed" half of the fault. */
    atomic_store(&c.last_tick_us, 0); /* liveness_contract_init set now; a
                                       * fresh progress marker + tick below
                                       * proves the child is alive again. */
    supervisor_progress(id, 1);
    uint32_t ticks_before = atomic_load(&c.ticks_run);
    /* Re-arm: give it a live heartbeat close to "now" so the next sweep's
     * deadline check passes, then request one more sweep window. */
    atomic_store(&c.deadline_secs, 60);
    supervisor_sweep_once_for_testing();
    chaos_sleep_ms(40);
    uint32_t ticks_after = atomic_load(&c.ticks_run);

    supervisor_stop();

    out->ok = started && stall_fired;
    out->recovered = stall_named && ticks_after >= ticks_before;
    out->operator_paged = false; /* the supervisor layer names a blocker via
                                  * stall_reason; it does not itself page an
                                  * operator for a single TIME_DEADLINE edge —
                                  * escalation is the condition-engine's job
                                  * (fault (e)), which this fault does not
                                  * exercise. */
    chaos_note(out,
        "reducer-drive freeze: stall_fires=%u reason=%s ticks %u->%u",
        atomic_load(&c.stall_fires),
        supervisor_stall_reason_name(atomic_load(&c.stall_reason)),
        ticks_before, ticks_after);

    supervisor_reset_for_testing();
    return true;
}
#else
bool chaos_fault_freeze_reducer_drive(struct chaos_fault_result *out)
{
    chaos_result_init(out);
    chaos_note(out, "unavailable: built without ZCL_TESTING");
    return false;
}
#endif /* ZCL_TESTING */

/* ══════════════════════════════════════════════════════════════════════
 * (e) stall a single stage — typed blocker + condition engine
 * ══════════════════════════════════════════════════════════════════════ */

/* condition_engine_reset_for_testing is ZCL_TESTING-only (see the comment
 * above chaos_fault_freeze_reducer_drive — the same reasoning applies); every
 * helper below is scoped inside the same guard for the same reason. */
#ifdef ZCL_TESTING
static _Atomic bool g_chaos_stage_cleared;
static _Atomic int  g_chaos_operator_events;

static bool chaos_stage_detect(void)
{
    return !atomic_load(&g_chaos_stage_cleared);
}

static enum condition_remedy_result chaos_stage_remedy(void)
{
    struct blocker_record rec;
    if (blocker_init(&rec, "chaos.stage_stall", "chaos_harness",
                     BLOCKER_TRANSIENT,
                     "synthetic single-stage stall (chaos harness)"))
        blocker_set(&rec);
    /* Self-heal after a couple of remedy attempts — models a stage whose
     * transient blocker (peer down / queue full) clears on its own. */
    static _Atomic int attempts;
    if (atomic_fetch_add(&attempts, 1) >= 1) {
        atomic_store(&g_chaos_stage_cleared, true);
        blocker_clear("chaos.stage_stall");
    }
    return COND_REMEDY_OK;
}

static bool chaos_stage_witness(int64_t target_at_detect)
{
    (void)target_at_detect;
    return atomic_load(&g_chaos_stage_cleared);
}

static void chaos_operator_observer(enum event_type type, uint32_t peer_id,
                                    const void *payload, uint32_t payload_len,
                                    void *ctx)
{
    (void)type; (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    atomic_fetch_add(&g_chaos_operator_events, 1);
}

bool chaos_fault_stall_single_stage(struct chaos_fault_result *out)
{
    chaos_result_init(out);

    condition_engine_reset_for_testing();
    event_log_init();
    atomic_store(&g_chaos_stage_cleared, false);
    atomic_store(&g_chaos_operator_events, 0);

    /* NOT const: the condition engine mutates `.state` in place through this
     * exact static instance (matches lib/test/src/test_condition_engine.c's
     * convention) — a `const`-qualified object risks living in read-only
     * storage the engine then can't atomically update. */
    static struct condition cond = {
        .name = "chaos_stage_stall",
        .severity = COND_WARN,
        .poll_secs = 1,
        .backoff_secs = 0,
        .max_attempts = 10,        /* generous budget: never exhausts within
                                    * this fixture's few ticks — models a
                                    * genuinely RECOVERABLE cause. */
        .detect = chaos_stage_detect,
        .remedy = chaos_stage_remedy,
        .witness = chaos_stage_witness,
        .witness_window_secs = 60,
    };

    if (!condition_register(&cond)) {
        chaos_note(out, "condition_register failed");
        return false;
    }
    event_observe(EV_OPERATOR_NEEDED, chaos_operator_observer, NULL);

    /* THE FAULT: drive the engine while the stage is stalled. Two ticks are
     * enough for the fixture remedy to self-clear (see chaos_stage_remedy). */
    condition_engine_tick();
    condition_engine_tick();
    condition_engine_tick();

    bool blocker_gone = !blocker_exists("chaos.stage_stall");
    bool no_pages = atomic_load(&g_chaos_operator_events) == 0;
    bool cleared = condition_engine_get_active_count() == 0 &&
                  atomic_load(&g_chaos_stage_cleared);

    out->ok = true;
    out->recovered = cleared && blocker_gone;
    out->operator_paged = !no_pages;
    chaos_note(out,
        "single-stage stall: cleared=%d blocker_gone=%d operator_events=%d",
        cleared, blocker_gone, atomic_load(&g_chaos_operator_events));

    condition_engine_reset_for_testing();
    blocker_clear("chaos.stage_stall");
    return true;
}
#else
bool chaos_fault_stall_single_stage(struct chaos_fault_result *out)
{
    chaos_result_init(out);
    chaos_note(out, "unavailable: built without ZCL_TESTING");
    return false;
}
#endif /* ZCL_TESTING */

/* ══════════════════════════════════════════════════════════════════════
 * (f) kill/restart mid-RECOVERY (inside an open rederive/rewind window)
 * ══════════════════════════════════════════════════════════════════════ */

/* Only test_fmt_tmpdir / test_cleanup_tmpdir (both `static inline` in
 * test/test_helpers.h) are used below — no ZCL_TESTING guard needed, same
 * as (a)/(b) (see the comment on (c) for why some faults DO need one). */

bool chaos_fault_kill_restart_mid_recovery(struct chaos_fault_result *out)
{
    chaos_result_init(out);
    const int32_t N = 40;     /* full consistent prefix [0, N] */
    const int32_t HOLE = 25;  /* recovery-window target: rederive [HOLE,HOLE] */

    char dir[256];
    mkdir("./test-tmp", 0755);
    test_fmt_tmpdir(dir, sizeof(dir), "chaos_kill_recovery", "main");
    mkdir(dir, 0755);

    progress_store_close();
    if (!progress_store_open(dir)) {
        chaos_note(out, "progress_store failed to open fixture dir");
        test_cleanup_tmpdir(dir);
        return false;
    }
    sqlite3 *db = progress_store_db();
    if (!db || !chaos_stamp_prefix(db, N)) {
        chaos_note(out, "fixture stamp failed");
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return false;
    }

    /* Open the RECOVERY WINDOW: the real primitive a self-heal rung calls
     * (app/jobs/src/stage_rederive_range.c) rewinds the body-dependent
     * stage cursors to HOLE, deletes the stale suffix rows [HOLE, N], and
     * (HOLE sits below the coins-applied frontier N+1) inverse-rewinds the
     * coins-applied frontier to HOLE — all in one committed transaction.
     * This is the state a real crash mid-recovery lands in: the window is
     * open (rewound + committed) but the drive has NOT yet re-folded
     * [HOLE, N] forward. `ms` may be NULL (see the header: the forward
     * fold re-creates created_outputs itself). */
    struct stage_rederive_range_result rr;
    bool opened = stage_rederive_range(db, NULL, HOLE, HOLE, &rr);
    if (!opened || !rr.ok) {
        chaos_note(out,
            "stage_rederive_range failed to open the recovery window "
            "(opened=%d ok=%d refused_no_inverse=%d)",
            opened, rr.ok, rr.refused_no_inverse);
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return false;
    }

    int32_t hstar_mid = -1, served_mid = -1;
    bool ok_mid = reducer_frontier_compute_hstar(db, &hstar_mid, &served_mid);
    int32_t coins_mid = -1;
    bool coins_found_mid = false;
    bool coins_ok_mid =
        coins_kv_get_applied_height(db, &coins_mid, &coins_found_mid);

    /* THE FAULT: kill -9 INSIDE the open recovery window — abrupt close
     * (nothing further ever committed) then the restart (fresh reopen; no
     * in-RAM state survives, exactly like (b) but from a rewound state
     * instead of a fully-folded one). */
    progress_store_close();
    bool reopened = progress_store_open(dir);
    sqlite3 *db2 = reopened ? progress_store_db() : NULL;

    int32_t hstar_after = -1, served_after = -1;
    bool ok_after = db2 && reducer_frontier_compute_hstar(db2, &hstar_after,
                                                           &served_after);
    int32_t coins_after = -1;
    bool coins_found_after = false;
    bool coins_ok_after =
        db2 && coins_kv_get_applied_height(db2, &coins_after,
                                           &coins_found_after);

    /* CONVERGES: the next boot pass calls the SAME primitive over the SAME
     * range again — it must succeed idempotently (no error, no duplicate
     * rewind) so the drive can resume folding [HOLE, N] forward instead of
     * stalling or re-deriving a second time. */
    struct stage_rederive_range_result rr2;
    bool resumed = db2 && stage_rederive_range(db2, NULL, HOLE, HOLE, &rr2);

    out->ok = ok_mid && coins_ok_mid && reopened && ok_after && coins_ok_after;
    out->hstar_before = hstar_mid;
    out->hstar_after = hstar_after;
    /* NEVER a silent stall: hstar_after names the exact rewound height
     * (HOLE-1) identically before/after the kill — never undefined, never a
     * value ABOVE HOLE-1 (which would mean the log silently re-served rows
     * it never actually re-derived). NEVER a wipe of seeded coins: the
     * coins-applied frontier is FOUND (not reset to "absent") and reads
     * back HOLE identically before/after the kill. resumed+rr2.ok is the
     * "next boot converges" proof. */
    out->recovered = out->ok && resumed && rr2.ok &&
                     hstar_after == hstar_mid && hstar_after == HOLE - 1 &&
                     coins_found_mid && coins_found_after &&
                     coins_mid == HOLE && coins_after == HOLE;
    chaos_note(out,
        "kill mid-recovery: H* mid=%d after=%d (want %d) coins mid=%d "
        "after=%d (want %d, found mid=%d after=%d) resumed=%d — %s",
        hstar_mid, hstar_after, HOLE - 1, coins_mid, coins_after, HOLE,
        coins_found_mid, coins_found_after, resumed,
        out->recovered
            ? "converges — cursor + coins frontier survive the kill "
              "identically, next pass resumes cleanly"
            : "DIVERGED or FAILED to converge across the kill");

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (g)-(l): the sync/ROM-artifact fault matrix (lane G3). See
 * sim/simnet_chaos_faults.h for the per-fault contract.
 * ══════════════════════════════════════════════════════════════════════ */

static void sfm_capsule_init(struct sync_fault_capsule *out, uint64_t seed)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->base.hstar_before = -1;
    out->base.hstar_after = -1;
    out->seed = seed;
}

/* mirrors chaos_note() above, writing into the embedded base.note. */
static void sfm_note(struct sync_fault_capsule *out, const char *fmt, ...)
{
    if (!out) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out->base.note, sizeof(out->base.note), fmt, ap);
    va_end(ap);
}

/* ── shared ROM-artifact fixture helpers (mirror lib/test/src/
 * test_rom_journal_resume.c's proven fixture idioms) ───────────────────── */

#define SFM_ARTIFACT_BYTES 8192u /* < ROM_SEED_CHUNK_SIZE: one short chunk,
                                  * real content, fast to build/transfer */

static void sfm_gen_content(uint8_t *buf, size_t size, uint64_t seed)
{
    static const uint8_t magic[16] = "SQLite format 3";
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 131u + 7u + seed) & 0xffu);
    if (size >= 16)
        memcpy(buf, magic, 16);
}

static bool sfm_write_file(const char *dir, const char *name,
                           const uint8_t *buf, size_t size)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < size) {
        ssize_t w = write(fd, buf + off, size - off);
        if (w <= 0) { close(fd); return false; }
        off += (size_t)w;
    }
    close(fd);
    return true;
}

static uint16_t sfm_start_fs_server(const char *dir, const uint16_t *cand,
                                    size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fs_server_start(dir, cand[i]);
        for (int w = 0; w < 40 && !fs_server_is_running(); w++)
            platform_sleep_ms(50); /* up to 2 s for bind+listen */
        if (fs_server_is_running())
            return cand[i];
        fs_server_stop();
    }
    return 0;
}

static void sfm_manifest_from_artifact(const struct rom_artifact *a,
                                       struct rom_fetch_manifest *m)
{
    memset(m, 0, sizeof(*m));
    m->used = true;
    snprintf(m->filename, sizeof(m->filename), "%s", a->filename);
    m->size_bytes = a->size_bytes;
    m->chunk_size = a->chunk_size;
    m->num_chunks = a->num_chunks;
    memcpy(m->chunk_root, a->chunk_root, 32);
    memcpy(m->whole_sha3, a->whole_sha3, 32);
}

static int64_t sfm_seed_chunks_served(void)
{
    struct json_value dj;
    json_init(&dj);
    (void)rom_seed_dump_state_json(&dj, NULL);
    int64_t n = json_get_int(json_get(&dj, "chunks_served"));
    json_free(&dj);
    return n;
}

/* ══════════════════════════════════════════════════════════════════════
 * (g) two peers, same chunk index, different bytes
 * ══════════════════════════════════════════════════════════════════════ */

/* fs_send_chunk_fast has external linkage (lib/net/src/file_service.c) but
 * is not exposed via net/file_service.h — it is the honest serve path's
 * internal wire-framing + MAC primitive. This forward declaration (not a
 * #include; the real symbol links fine in this one-binary build — same
 * rationale as block_index_loader_seed_tip_from_finalized above) lets this
 * fixture's hand-built "bad peer" thread reuse the REAL frame+MAC format
 * instead of reimplementing it, while feeding it deliberately wrong chunk
 * bytes. Signature verified against lib/net/src/file_service.c at the time
 * this file was written. */
bool fs_send_chunk_fast(struct fs_session *s, const uint8_t *data,
                        uint32_t size, const uint8_t sha3[32]);

/* The BAD peer: a minimal, hand-driven listener speaking just enough real
 * file-service wire protocol (fs_session_init/fs_handshake/fs_recv_frame/
 * fs_parse_rom_request/fs_send_chunk_fast — every one a real production
 * primitive) to answer ONE ROM chunk request with deliberately wrong bytes.
 * The transport MAC it sends is real and self-consistent — fs_send_chunk_fast
 * binds the MAC to whatever (data, sha3) it is given, and the honest server
 * does the exact same thing with its own real data, so the MAC alone can
 * never distinguish this from an honest reply. Only the CALLER's separate
 * content check (rom_fetch_verify_chunk against the manifest's committed
 * digest) catches it — which is exactly the property this fault proves. */
struct sfm_bad_peer {
    int          listen_fd;
    uint16_t     port;
    pthread_t    thread;
    uint32_t     reply_bytes;
    uint8_t      fill;
    _Atomic bool got_request;
};

static void *sfm_bad_peer_loop(void *arg)
{
    struct sfm_bad_peer *bp = (struct sfm_bad_peer *)arg;
    int fd = accept(bp->listen_fd, NULL, NULL);
    if (fd < 0)
        return NULL;

    struct fs_session s;
    fs_session_init(&s, fd);
    uint8_t zero_root[32];
    memset(zero_root, 0, sizeof(zero_root));
    if (!fs_handshake(&s, zero_root, false)) {
        fs_session_cleanup(&s); close(fd);
        return NULL;
    }

    uint8_t type;
    const uint8_t *payload;
    uint32_t plen;
    if (fs_recv_frame(&s, &type, &payload, &plen) && type == FS_REQUEST) {
        uint8_t root[32];
        uint32_t idx = 0;
        if (fs_parse_rom_request(payload, plen, root, &idx)) {
            atomic_store(&bp->got_request, true);
            uint8_t *wrong = malloc(bp->reply_bytes); // raw-alloc-ok:test
            if (wrong) {
                for (uint32_t i = 0; i < bp->reply_bytes; i++)
                    wrong[i] = (uint8_t)(bp->fill ^ (uint8_t)(i * 61u + 13u));
                uint8_t wrong_sha3[32];
                sha3_256(wrong, bp->reply_bytes, wrong_sha3);
                (void)fs_send_chunk_fast(&s, wrong, bp->reply_bytes,
                                         wrong_sha3);
                free(wrong);
            }
        } else {
            (void)fs_send_frame(&s, FS_DONE, NULL, 0);
        }
    }
    fs_session_cleanup(&s); close(fd);
    return NULL;
}

static bool sfm_bad_peer_start(struct sfm_bad_peer *bp, uint32_t reply_bytes,
                               uint64_t seed)
{
    memset(bp, 0, sizeof(*bp));
    bp->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (bp->listen_fd < 0)
        return false;
    int one = 1;
    setsockopt(bp->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0; /* ephemeral — no fixed-port collision risk */
    if (bind(bp->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(bp->listen_fd);
        return false;
    }
    socklen_t sl = sizeof(sa);
    if (getsockname(bp->listen_fd, (struct sockaddr *)&sa, &sl) < 0) {
        close(bp->listen_fd);
        return false;
    }
    bp->port = ntohs(sa.sin_port);
    if (listen(bp->listen_fd, 1) < 0) {
        close(bp->listen_fd);
        return false;
    }
    bp->reply_bytes = reply_bytes;
    bp->fill = (uint8_t)(seed ^ 0xA5u);
    /* raw-pthread-ok: single accept()->reply->exit, joined immediately below */
    if (pthread_create(&bp->thread, NULL, sfm_bad_peer_loop, bp) != 0) {
        close(bp->listen_fd);
        return false;
    }
    return true;
}

/* shutdown()+close() BEFORE join(): if the client never connected (an early
 * error-path teardown), the thread is still blocked inside accept() on this
 * exact fd — closing it first is what unblocks that accept() call. Safe to
 * call unconditionally either way (mirrors test_header_probe.c's
 * hp_mock_stop ordering). */
static void sfm_bad_peer_join(struct sfm_bad_peer *bp)
{
    shutdown(bp->listen_fd, SHUT_RDWR);
    close(bp->listen_fd);
    pthread_join(bp->thread, NULL);
}

bool chaos_fault_conflicting_chunk_peers(uint64_t seed,
                                         struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "chunk 0 fetched from two real peers under one committed digest");

    fs_server_stop();
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    rom_seed_set_peer_bps_cap(1ull << 30);
    rom_seed_set_global_bps_cap(1ull << 30);

    char sroot[] = "/tmp/zcl_sfm_g_srv_XXXXXX";
    char *sdir = mkdtemp(sroot);
    char croot[] = "/tmp/zcl_sfm_g_cli_XXXXXX";
    char *cdir = mkdtemp(croot);
    if (!sdir || !cdir) {
        sfm_note(out, "mkdtemp failed");
        return false;
    }

    uint8_t content[SFM_ARTIFACT_BYTES];
    sfm_gen_content(content, sizeof(content), seed);
    bool wrote = sfm_write_file(sdir, "consensus-state-bundle-sfmg.sqlite",
                                content, sizeof(content));
    struct rom_artifact art;
    bool reg = wrote && rom_seed_register(
        sdir, "consensus-state-bundle-sfmg.sqlite", NULL, &art) == ROM_REG_OK;
    if (!reg || art.num_chunks != 1) {
        sfm_note(out, "fixture registration failed (wrote=%d reg=%d)",
                 wrote, reg);
        rmdir(sdir); rmdir(cdir);
        return false;
    }

    static const uint16_t good_ports[] = { 18941, 18945, 18949 };
    uint16_t good_port = sfm_start_fs_server(sdir, good_ports, 3);
    if (good_port == 0) {
        sfm_note(out, "good fs_server failed to bind");
        rmdir(sdir); rmdir(cdir);
        return false;
    }

    struct sfm_bad_peer bad;
    if (!sfm_bad_peer_start(&bad, (uint32_t)art.size_bytes, seed)) {
        sfm_note(out, "bad peer listener failed to start");
        fs_server_stop();
        rmdir(sdir); rmdir(cdir);
        return false;
    }

    char part_path[1300];
    snprintf(part_path, sizeof(part_path),
             "%s/consensus-state-bundle-sfmg.sqlite.part", cdir);
    char jrnl_path[1364];
    snprintf(jrnl_path, sizeof(jrnl_path), "%s.journal", part_path);
    int fd = open(part_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    struct rom_journal *j = fd >= 0
        ? rom_journal_open(jrnl_path, art.chunk_root, art.whole_sha3,
                           art.chunk_size, art.num_chunks)
        : NULL;

    /* GOOD fetch first: real bytes, verifies, durably journaled + on disk. */
    uint8_t *good_buf = malloc(art.chunk_size); // raw-alloc-ok:test
    uint32_t good_got = 0;
    bool good_ok = fd >= 0 && j && good_buf &&
        rom_fetch_chunk("127.0.0.1", good_port, art.chunk_root, 0, good_buf,
                        art.chunk_size, &good_got) &&
        rom_fetch_verify_chunk(good_buf, good_got, art.chunk_sha3[0]) &&
        pwrite(fd, good_buf, good_got, 0) == (ssize_t)good_got &&
        fdatasync(fd) == 0 && rom_journal_mark(j, 0);
    snprintf(out->state_before, sizeof(out->state_before),
             "good peer fetched+verified+journaled chunk 0 (%u bytes)",
             good_got);
    if (!good_ok) {
        sfm_note(out, "good-peer baseline fetch/verify/mark failed");
        if (j) rom_journal_close(j);
        if (fd >= 0) close(fd);
        free(good_buf);
        sfm_bad_peer_join(&bad);
        fs_server_stop();
        rmdir(sdir); rmdir(cdir);
        return false;
    }

    /* BAD fetch: same chunk_root/index, a DIFFERENT real peer, DIFFERENT
     * real bytes. Transport succeeds (self-consistent MAC); content verify
     * must fail against the SAME committed digest the good peer satisfied. */
    uint8_t *bad_buf = malloc(art.chunk_size); // raw-alloc-ok:test
    uint32_t bad_got = 0;
    bool transport_ok = bad_buf &&
        rom_fetch_chunk("127.0.0.1", bad.port, art.chunk_root, 0, bad_buf,
                        art.chunk_size, &bad_got);
    bool content_differs = transport_ok && bad_got == good_got &&
        memcmp(bad_buf, good_buf, good_got) != 0;
    bool content_rejected = transport_ok &&
        !rom_fetch_verify_chunk(bad_buf, bad_got, art.chunk_sha3[0]);
    bool named = content_rejected &&
        rom_peer_note_bad_chunk("127.0.0.1", bad.port, 0, "digest");
    bool deprioritized = named &&
        rom_peer_is_deprioritized("127.0.0.1", bad.port);

    /* The good chunk is KEPT: this fixture never pwrites/marks the bad
     * bytes (mirrors rf_ver_worker's real "verify BEFORE any durable write"
     * ordering), so both the journal bit AND the on-disk .part bytes for
     * chunk 0 must still read back exactly what the good peer served. */
    uint8_t reread[SFM_ARTIFACT_BYTES];
    bool part_kept = pread(fd, reread, good_got, 0) == (ssize_t)good_got &&
                     memcmp(reread, good_buf, good_got) == 0;
    bool journal_kept = rom_journal_is_done(j, 0) &&
                        rom_journal_count_done(j) == 1;

    snprintf(out->state_after, sizeof(out->state_after),
             "bad peer transport_ok=%d content_differs=%d rejected=%d "
             "named=%d deprioritized=%d good chunk kept(part=%d,journal=%d)",
             transport_ok, content_differs, content_rejected, named,
             deprioritized, part_kept, journal_kept);
    out->event_number = 2; /* fetch #1 = good peer, fetch #2 = bad peer */
    snprintf(out->phase, sizeof(out->phase), "content_verify");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_conflicting_chunk_peers(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = true;
    out->base.recovered = transport_ok && content_differs && content_rejected &&
                          named && deprioritized && part_kept && journal_kept;
    out->base.operator_paged = false;
    sfm_note(out, "conflicting chunk peers: good=%u/%u bad=%u/%u differ=%d "
             "reject=%d named=%d deprio=%d part_kept=%d journal_kept=%d",
             good_got, art.chunk_size, bad_got, art.chunk_size,
             content_differs, content_rejected, named, deprioritized,
             part_kept, journal_kept);

    free(good_buf);
    free(bad_buf);
    rom_journal_close(j);
    close(fd);
    sfm_bad_peer_join(&bad);
    fs_server_stop();
    char p[1024];
    snprintf(p, sizeof(p), "%s/consensus-state-bundle-sfmg.sqlite", sdir);
    unlink(p);
    rmdir(sdir);
    unlink(jrnl_path);
    unlink(part_path);
    rmdir(cdir);
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (h) ENOSPC (write failure) during a journal bitmap commit
 * ══════════════════════════════════════════════════════════════════════ */

bool chaos_fault_journal_commit_enospc(uint64_t seed,
                                       struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "rom_journal_mark()'s pwrite of the bitmap byte");

    char dir[256];
    mkdir("./test-tmp", 0755);
    test_fmt_tmpdir(dir, sizeof(dir), "chaos_journal_enospc", "main");
    mkdir(dir, 0755);
    char jrnl_path[512];
    snprintf(jrnl_path, sizeof(jrnl_path), "%s/journal", dir);

    uint8_t root[32], whole[32];
    memset(root, (uint8_t)(seed & 0xff), 32);
    memset(whole, (uint8_t)((seed >> 8) & 0xff), 32);
    const uint32_t num_chunks = 8; /* single-byte bitmap: every mark() below
                                    * touches the SAME on-disk byte offset, so
                                    * one rlimit boundary covers every index */
    struct rom_journal *j = rom_journal_open(jrnl_path, root, whole, 4096,
                                             num_chunks);
    if (!j) {
        sfm_note(out, "journal open failed");
        test_cleanup_tmpdir(dir);
        return false;
    }
    if (!rom_journal_mark(j, 0)) {
        sfm_note(out, "baseline mark(0) failed (harness defect)");
        rom_journal_close(j);
        test_cleanup_tmpdir(dir);
        return false;
    }
    snprintf(out->state_before, sizeof(out->state_before),
             "count_done=1 (chunk 0 durably marked)");

    /* The bitmap byte's real on-disk offset is RJ_BITMAP_OFFSET==88 (right
     * after the 88-byte header), single byte for num_chunks<=8 — set the
     * rlimit exactly one byte below the file's current size so a pwrite AT
     * that offset fails (EFBIG — see sim/simnet_chaos_faults.h (h) for why
     * this is the privilege-free substitute for a literal full filesystem
     * in a sandboxed worktree), while the already-durable header + bit 0
     * stay untouched. */
    struct stat st;
    if (stat(jrnl_path, &st) != 0 || st.st_size < 89) {
        sfm_note(out, "journal file layout unexpected (size=%lld)",
                 (long long)st.st_size);
        rom_journal_close(j);
        test_cleanup_tmpdir(dir);
        return false;
    }
    rlim_t limit = (rlim_t)(st.st_size - 1);

    struct rlimit orig;
    if (getrlimit(RLIMIT_FSIZE, &orig) != 0) {
        sfm_note(out, "getrlimit failed");
        rom_journal_close(j);
        test_cleanup_tmpdir(dir);
        return false;
    }
    struct sigaction old_sa, ign_sa;
    memset(&ign_sa, 0, sizeof(ign_sa));
    ign_sa.sa_handler = SIG_IGN; /* EFBIG return instead of process death */
    sigaction(SIGXFSZ, &ign_sa, &old_sa);
    struct rlimit tight = { .rlim_cur = limit, .rlim_max = orig.rlim_max };
    bool limited = setrlimit(RLIMIT_FSIZE, &tight) == 0;

    bool mark_failed = limited && !rom_journal_mark(j, 1);
    bool bit_rolled_back = mark_failed && !rom_journal_is_done(j, 1);
    bool count_unaffected = mark_failed && rom_journal_count_done(j) == 1;

    /* Restore: raising the soft limit back toward the original is always
     * permitted (never requires privilege). */
    setrlimit(RLIMIT_FSIZE, &orig);
    sigaction(SIGXFSZ, &old_sa, NULL);

    bool retry_ok = mark_failed && rom_journal_mark(j, 1);
    rom_journal_close(j);

    /* Reopen fresh from disk: the failed attempt left ZERO trace — a set bit
     * ALWAYS implies durable data, never a half-committed one. */
    struct rom_journal *j2 = rom_journal_open(jrnl_path, root, whole, 4096,
                                              num_chunks);
    bool reopen_agrees = j2 && rom_journal_is_done(j2, 0) &&
                        rom_journal_is_done(j2, 1) &&
                        rom_journal_count_done(j2) == 2;
    rom_journal_close(j2);

    snprintf(out->state_after, sizeof(out->state_after),
             "mark_failed=%d rolled_back=%d count_unaffected=%d retry_ok=%d "
             "reopen_agrees=%d", mark_failed, bit_rolled_back,
             count_unaffected, retry_ok, reopen_agrees);
    out->event_number = 2; /* mark(0) baseline, mark(1) is the injected fault */
    snprintf(out->phase, sizeof(out->phase), "journal_mark");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_journal_commit_enospc(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = limited;
    out->base.recovered = mark_failed && bit_rolled_back && count_unaffected &&
                          retry_ok && reopen_agrees;
    out->base.operator_paged = false;
    sfm_note(out, "journal write-failure (ENOSPC substitute): "
             "mark_failed=%d rolled_back=%d retry_ok=%d reopen_agrees=%d",
             mark_failed, bit_rolled_back, retry_ok, reopen_agrees);

    test_cleanup_tmpdir(dir);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (i) kill at the two resume boundaries rom_journal.h documents
 * ══════════════════════════════════════════════════════════════════════ */

bool chaos_fault_kill_resume_boundary(uint64_t seed, bool after_bitmap_commit,
                                      struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             after_bitmap_commit
                 ? "kill after every chunk's bitmap bit, before the rename"
                 : "kill after data fsync, before that chunk's bitmap bit");

    fs_server_stop();
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    rom_seed_set_peer_bps_cap(1ull << 30);
    rom_seed_set_global_bps_cap(1ull << 30);

    char sroot[] = "/tmp/zcl_sfm_i_srv_XXXXXX";
    char *sdir = mkdtemp(sroot);
    char croot[] = "/tmp/zcl_sfm_i_cli_XXXXXX";
    char *cdir = mkdtemp(croot);
    if (!sdir || !cdir) {
        sfm_note(out, "mkdtemp failed");
        return false;
    }

    size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096; /* 2 chunks */
    uint8_t *content = malloc(size); // raw-alloc-ok:test
    if (!content) {
        sfm_note(out, "content alloc failed");
        rmdir(sdir); rmdir(cdir);
        return false;
    }
    sfm_gen_content(content, size, seed);
    char fname[80];
    snprintf(fname, sizeof(fname), "consensus-state-bundle-sfmi%s.sqlite",
             after_bitmap_commit ? "b" : "a");
    bool wrote = sfm_write_file(sdir, fname, content, size);

    struct rom_artifact art;
    bool reg = wrote &&
        rom_seed_register(sdir, fname, NULL, &art) == ROM_REG_OK;
    if (!reg || art.num_chunks != 2) {
        sfm_note(out, "fixture registration failed");
        free(content); rmdir(sdir); rmdir(cdir);
        return false;
    }
    struct rom_fetch_manifest m;
    sfm_manifest_from_artifact(&art, &m);

    static const uint16_t ports[] = { 18951, 18955, 18959 };
    uint16_t port = sfm_start_fs_server(sdir, ports, 3);
    if (port == 0) {
        sfm_note(out, "fs_server failed to bind");
        free(content); rmdir(sdir); rmdir(cdir);
        return false;
    }

    char part_path[1300];
    snprintf(part_path, sizeof(part_path), "%s/%s%s", cdir, m.filename,
             ROM_FETCH_PART_SUFFIX);
    char jrnl_path[1364];
    snprintf(jrnl_path, sizeof(jrnl_path), "%s.journal", part_path);

    int fd = open(part_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    struct rom_journal *j = fd >= 0
        ? rom_journal_open(jrnl_path, m.chunk_root, m.whole_sha3,
                           m.chunk_size, m.num_chunks)
        : NULL;
    uint8_t *cbuf = malloc(ROM_SEED_CHUNK_SIZE); // raw-alloc-ok:test
    bool built = fd >= 0 && j && cbuf;
    /* Chunk 0: always fully durable + marked — established prior progress. */
    if (built) {
        uint32_t got = 0;
        built = rom_fetch_chunk("127.0.0.1", port, m.chunk_root, 0, cbuf,
                                ROM_SEED_CHUNK_SIZE, &got) &&
               rom_fetch_verify_chunk(cbuf, got, art.chunk_sha3[0]) &&
               pwrite(fd, cbuf, got, 0) == (ssize_t)got &&
               fdatasync(fd) == 0 && rom_journal_mark(j, 0);
    }
    /* Chunk 1 (the short tail): data written+fsynced either way — the fault
     * is whether the BITMAP BIT was committed before the simulated kill. */
    if (built) {
        uint32_t got = 0;
        built = rom_fetch_chunk("127.0.0.1", port, m.chunk_root, 1, cbuf,
                                ROM_SEED_CHUNK_SIZE, &got) &&
               rom_fetch_verify_chunk(cbuf, got, art.chunk_sha3[1]) &&
               pwrite(fd, cbuf, got, (off_t)m.chunk_size) == (ssize_t)got &&
               fdatasync(fd) == 0;
        if (built && after_bitmap_commit)
            built = rom_journal_mark(j, 1); /* commit past this boundary too */
        /* else: bytes are durable on disk; the mark is deliberately skipped
         * — the simulated kill lands exactly between fdatasync(.part) and
         * rom_journal_mark(), the "before bitmap commit" boundary. */
    }
    free(cbuf);
    if (!built) {
        sfm_note(out, "fixture boundary construction failed");
        if (j) rom_journal_close(j);
        if (fd >= 0) close(fd);
        fs_server_stop(); free(content); rmdir(sdir); rmdir(cdir);
        return false;
    }
    uint32_t done_before_kill = rom_journal_count_done(j);
    snprintf(out->state_before, sizeof(out->state_before),
             "journal count_done=%u/2, .part fully written on disk, final "
             "rename not yet performed", done_before_kill);
    close(fd);
    rom_journal_close(j); /* "process dies" here — no clean shutdown */
    /* The response completes before the server records it; await setup. */
    for (int i = 0; i < 40 && sfm_seed_chunks_served() < 2; i++)
        platform_sleep_ms(50);
    int64_t served_before = sfm_seed_chunks_served();
    /* "Restart": resume through the real driver. */
    bool resumed = rom_fetch_download_verified(
        "127.0.0.1", port, &m, art.chunk_sha3, m.num_chunks, cdir, NULL, NULL);
    int64_t served_after = sfm_seed_chunks_served();
    int64_t refetched = served_after - served_before;
    char final_path[1300];
    snprintf(final_path, sizeof(final_path), "%s/%s", cdir, m.filename);
    bool verifies = resumed && rom_fetch_verify_file(final_path, &m);
    struct stat jst;
    bool journal_cleaned = resumed && stat(jrnl_path, &jst) != 0;

    int64_t want_refetch = after_bitmap_commit ? 0 : 1;
    snprintf(out->state_after, sizeof(out->state_after),
             "resumed=%d refetched=%lld (want %lld, always <=1) verifies=%d "
             "journal_cleaned=%d", resumed, (long long)refetched,
             (long long)want_refetch, verifies, journal_cleaned);
    out->event_number = 3;
    snprintf(out->phase, sizeof(out->phase), "resume");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_kill_resume_boundary(0x%016llx, %s, &out)",
             (unsigned long long)seed, after_bitmap_commit ? "true" : "false");

    out->base.ok = true;
    out->base.recovered = served_before >= 2 && resumed &&
                          refetched == want_refetch && refetched <= 1 &&
                          verifies && journal_cleaned;
    out->base.operator_paged = false;
    sfm_note(out, "kill at resume boundary (%s): refetched=%lld verifies=%d "
             "journal_cleaned=%d",
             after_bitmap_commit ? "after bitmap, before rename"
                                  : "before bitmap, after data fsync",
             (long long)refetched, verifies, journal_cleaned);

    fs_server_stop();
    free(content);
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s", sdir, fname);
    unlink(p);
    unlink(final_path);
    unlink(part_path);
    unlink(jrnl_path);
    rmdir(sdir);
    rmdir(cdir);
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (j) header reorg during an artifact download — the PURE kernel, no IO
 * ══════════════════════════════════════════════════════════════════════ */

bool chaos_fault_reorg_during_artifact_download(uint64_t seed,
                                                struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "PEER_LOST fired mid-RECEIVING (the reorged-anchor signal)");

    uint64_t sid = 1000ull + (seed % 1000ull);
    struct sync_kernel_state st;
    memset(&st, 0, sizeof(st));
    st.session_id.value = sid;
    st.phase = SYNC_PHASE_IDLE;
    uint32_t evn = 0;

    struct sync_event e;
#define SFM_STEP(kind_) do {                                               \
        memset(&e, 0, sizeof(e));                                          \
        e.session_id.value = sid;                                          \
        e.kind = (kind_);                                                  \
        struct sync_transition d = sync_reduce(st, e);                     \
        st.phase = d.next_state.phase;                                     \
        evn++;                                                             \
    } while (0)

    /* Legitimate negotiation with a couple chunks already in flight. */
    SFM_STEP(SYNC_EVENT_START);
    SFM_STEP(SYNC_EVENT_OFFER_RECEIVED);
    SFM_STEP(SYNC_EVENT_OFFER_ACCEPTED);
    SFM_STEP(SYNC_EVENT_CHUNK_RECEIVED);
    SFM_STEP(SYNC_EVENT_CHUNK_RECEIVED);
    bool receiving_before = (st.phase == SYNC_PHASE_RECEIVING);
    snprintf(out->state_before, sizeof(out->state_before),
             "phase=%s (mid-download, chunks already in flight)",
             sync_phase_name(st.phase));

    /* THE FAULT: PEER_LOST — the kernel's typed stand-in for "the anchor
     * this session was chasing was reorged out from under it" (no separate
     * REORG event exists in the catalog; see sim/simnet_chaos_faults.h (j)). */
    memset(&e, 0, sizeof(e));
    e.session_id.value = sid;
    e.kind = SYNC_EVENT_PEER_LOST;
    struct sync_transition fault_decision = sync_reduce(st, e);
    st.phase = fault_decision.next_state.phase;
    evn++;

    bool failed_named = fault_decision.next_state.phase == SYNC_PHASE_FAILED &&
                        fault_decision.has_blocker &&
                        fault_decision.blocker == SYNC_BLOCKER_PEER_LOST &&
                        fault_decision.action_count == 1 &&
                        fault_decision.actions[0] == SYNC_ACTION_FAIL;

    /* NEVER installed: further progress on the SAME (now-stale-anchor)
     * session — even a PASSING proof — must never reach STAGE_BUNDLE. */
    SFM_STEP(SYNC_EVENT_CHUNK_RECEIVED);
    SFM_STEP(SYNC_EVENT_RECEIVE_COMPLETE);
    memset(&e, 0, sizeof(e));
    e.session_id.value = sid;
    e.kind = SYNC_EVENT_PROOF_VERIFIED;
    e.proof_ok = true;
    struct sync_transition final_decision = sync_reduce(st, e);
    st.phase = final_decision.next_state.phase;
    evn++;
#undef SFM_STEP

    bool never_reactivated = st.phase == SYNC_PHASE_FAILED;
    bool never_staged = true;
    for (int i = 0; i < final_decision.action_count; i++)
        if (final_decision.actions[i] == SYNC_ACTION_STAGE_BUNDLE)
            never_staged = false;

    const char *blocker_str = fault_decision.has_blocker &&
                              fault_decision.blocker == SYNC_BLOCKER_PEER_LOST
        ? "peer_lost" : "none";
    snprintf(out->state_after, sizeof(out->state_after),
             "phase=%s blocker=%s never_staged=%d never_reactivated=%d",
             sync_phase_name(st.phase), blocker_str, never_staged,
             never_reactivated);
    out->event_number = evn;
    snprintf(out->phase, sizeof(out->phase), "%s",
             sync_phase_name(SYNC_PHASE_RECEIVING));
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_reorg_during_artifact_download(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = receiving_before;
    out->base.recovered = failed_named && never_staged && never_reactivated;
    /* FAILED + a typed blocker IS this fault's intended outcome — the pure
     * kernel does not itself page an operator (that is the condition
     * engine's job, exercised by faults (e)/(k)); no page is expected here. */
    out->base.operator_paged = false;
    sfm_note(out, "reorg mid-download: PEER_LOST -> phase=%s blocker=%s "
             "never_staged=%d never_reactivated=%d", sync_phase_name(st.phase),
             blocker_str, never_staged, never_reactivated);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (k) slow-loris seeder — bounded stall, never a silent hang
 * ══════════════════════════════════════════════════════════════════════ */

/* Guarded exactly like (d)/(e) above: supervisor_reset_for_testing /
 * supervisor_sweep_once_for_testing are ZCL_TESTING-only, and this file also
 * compiles into the production zclassic23 binary (lib/sim is a LIB_MODULE
 * linked into every target) which builds WITHOUT ZCL_TESTING. Reuses the
 * `chaos_sleep_ms` helper defined above (d)'s block — still in scope here,
 * same translation unit. */
#ifdef ZCL_TESTING
bool chaos_fault_slow_loris_seeder(uint64_t seed,
                                   struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "seeder accepted the connection, then sent nothing");

    supervisor_reset_for_testing();
    supervisor_set_tick_ms_for_testing(5);

    static struct liveness_contract c;
    liveness_contract_init(&c, "chaos.rom_fetch_wait");
    atomic_store(&c.deadline_secs, 1);
    supervisor_domain_t *domain = supervisor_create_domain("chaos");
    supervisor_child_id id = domain
        ? supervisor_register_in_domain(domain, &c)
        : SUPERVISOR_INVALID_ID;
    if (id == SUPERVISOR_INVALID_ID) {
        sfm_note(out, "supervisor_register_in_domain failed");
        return false;
    }

    /* THE FAULT: the seeder accepted the connection (the client would be
     * blocked in a real recv() on the socket) but never sends a byte —
     * modeled at the same supervisor liveness primitive every bounded-stall
     * class in this codebase surfaces through (mirrors
     * chaos_fault_freeze_reducer_drive exactly, a distinct domain/contract);
     * see sim/simnet_chaos_faults.h (k) for why this stays off rom_fetch.c's
     * real multi-second I/O timeouts. */
    atomic_store(&c.last_tick_us, atomic_load(&c.last_tick_us) - 5000000);

    bool started = supervisor_start();
    chaos_sleep_ms(80);

    bool stall_fired = atomic_load(&c.stall_fires) >= 1u;
    bool stall_named = atomic_load(&c.stall_reason) ==
                       SUPERVISOR_STALL_TIME_DEADLINE;
    snprintf(out->state_before, sizeof(out->state_before),
             "stall_fires=%u reason=%s", atomic_load(&c.stall_fires),
             supervisor_stall_reason_name(atomic_load(&c.stall_reason)));

    /* Recovery: the connection is abandoned and retried elsewhere — a fresh
     * heartbeat proves the stall was BOUNDED, never a permanent hang. */
    atomic_store(&c.last_tick_us, 0);
    supervisor_progress(id, 1);
    uint32_t ticks_before = atomic_load(&c.ticks_run);
    atomic_store(&c.deadline_secs, 60);
    supervisor_sweep_once_for_testing();
    chaos_sleep_ms(40);
    uint32_t ticks_after = atomic_load(&c.ticks_run);

    supervisor_stop();

    snprintf(out->state_after, sizeof(out->state_after),
             "ticks %u->%u (resumed=%d)", ticks_before, ticks_after,
             ticks_after >= ticks_before);
    out->event_number = 1;
    snprintf(out->phase, sizeof(out->phase), "stalled");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_slow_loris_seeder(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = started && stall_fired;
    out->base.recovered = stall_named && ticks_after >= ticks_before;
    out->base.operator_paged = false;
    sfm_note(out, "slow-loris seeder: stall_fires=%u reason=%s ticks %u->%u",
             atomic_load(&c.stall_fires),
             supervisor_stall_reason_name(atomic_load(&c.stall_reason)),
             ticks_before, ticks_after);

    supervisor_reset_for_testing();
    return true;
}
#else
bool chaos_fault_slow_loris_seeder(uint64_t seed,
                                   struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    sfm_note(out, "unavailable: built without ZCL_TESTING");
    return false;
}
#endif /* ZCL_TESTING */

/* ══════════════════════════════════════════════════════════════════════
 * (l) a valid multi-block "bundle" followed by one invalid TAIL block
 * ══════════════════════════════════════════════════════════════════════ */

bool chaos_fault_invalid_tail_block(uint64_t seed,
                                    struct sync_fault_capsule *out)
{
    sfm_capsule_init(out, seed);
    snprintf(out->fault_point, sizeof(out->fault_point),
             "malformed tail block right after a valid bundle prefix");

    struct simnet sim;
    if (!simnet_init(&sim)) {
        sfm_note(out, "simnet_init failed");
        return false;
    }

    /* "The bundle": a few legitimately minted, connected blocks — the
     * trusted prefix a checkpoint/artifact install would have left. */
    const int prefix_blocks = 1 + (int)(seed % 3); /* deterministic, 1..3 */
    bool prefix_ok = true;
    for (int i = 0; i < prefix_blocks && prefix_ok; i++)
        prefix_ok = simnet_mint_coinbase(&sim, NULL);
    int bundle_height = simnet_tip_height(&sim);
    snprintf(out->state_before, sizeof(out->state_before),
             "bundle-installed prefix at height %d (%d valid block(s))",
             bundle_height, prefix_blocks);
    if (!prefix_ok) {
        sfm_note(out, "prefix minting failed (harness defect)");
        simnet_free(&sim);
        return false;
    }

    /* THE TAIL BLOCK: one malformed block right after the bundle's last
     * height, built + connected through the REAL Byzantine-fixture path
     * (sim/simnet_byzantine.h) — the same connect_block(...,just_check=false)
     * on a scratch coins view that path documents, reused here so the
     * malformed-block construction is never reinvented. */
    struct simnet_byzantine_block_case c;
    bool built = simnet_byzantine_build_bad_merkle(&sim, &c);
    if (!built) {
        sfm_note(out, "malformed tail-block build failed (harness defect)");
        simnet_free(&sim);
        return false;
    }

    struct coins_view parent_view;
    coins_view_cache_as_view(&parent_view, &sim.view);
    struct coins_view_cache scratch;
    coins_view_cache_init(&scratch, &parent_view);

    struct uint256 block_hash;
    block_header_get_hash(&c.block.header, &block_hash);
    struct block_index idx;
    block_index_init(&idx);
    idx.hashBlock = block_hash;
    idx.phashBlock = &idx.hashBlock;
    idx.pprev = &sim.tip;
    idx.nHeight = c.height;
    idx.nVersion = c.block.header.nVersion;
    idx.nTime = c.block.header.nTime;
    idx.nBits = c.block.header.nBits;
    idx.hashMerkleRoot = c.block.header.hashMerkleRoot;

    struct validation_state vs;
    validation_state_init(&vs);
    bool tail_accepted = connect_block(&c.block, &vs, &idx, &scratch,
                                       &sim.params, false);
    coins_view_cache_free(&scratch);

    bool tip_unmoved = simnet_tip_height(&sim) == bundle_height;
    bool tail_rejected = !tail_accepted && vs.reject_reason[0] != '\0';

    /* Recovery: an HONEST block at the same next height still connects
     * cleanly right after — the rejected tail never wedges the chain. */
    bool honest_after = simnet_mint_coinbase(&sim, NULL);
    bool honest_advanced = honest_after &&
        simnet_tip_height(&sim) == bundle_height + 1;
    int final_height = simnet_tip_height(&sim);

    simnet_byzantine_block_case_free(&c);
    simnet_free(&sim);

    snprintf(out->state_after, sizeof(out->state_after),
             "tail_accepted=%d reject=%s tip_unmoved=%d honest_advanced=%d",
             tail_accepted, vs.reject_reason, tip_unmoved, honest_advanced);
    out->event_number = (uint32_t)(prefix_blocks + 1); /* +1 for the tail */
    snprintf(out->phase, sizeof(out->phase), "connect_block");
    snprintf(out->replay_command, sizeof(out->replay_command),
             "chaos_fault_invalid_tail_block(0x%016llx, &out)",
             (unsigned long long)seed);

    out->base.ok = true;
    out->base.hstar_before = bundle_height;
    out->base.hstar_after = final_height;
    out->base.recovered = tail_rejected && tip_unmoved && honest_advanced;
    out->base.operator_paged = false;
    sfm_note(out, "invalid tail block after valid bundle: prefix_h=%d "
             "tail_rejected=%d tip_unmoved=%d honest_advanced=%d",
             bundle_height, tail_rejected, tip_unmoved, honest_advanced);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (m) P2P body-download disruption/resume — BLOCK_HAVE_DATA no-refetch
 * ══════════════════════════════════════════════════════════════════════ */

/* Deterministic 32-byte hash for the (m) fixture. Tag byte 0xD0 keeps it
 * disjoint from chaos_synth_hash's 0xC5 (a)-(f) tag and synth_chain_bf's
 * 0xB4 (lib/test/src/test_body_fetch_stage.c) so a shared debugging
 * session never confuses the three synthetic-chain families. */
static void bdr_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[31] = 0xD0;
}

bool chaos_fault_peer_disconnect_mid_body_download(
    int32_t chain_len, struct body_download_resume_result *out)
{
    struct body_download_resume_result empty = {0};
    if (!out) return false;
    *out = empty;
    out->base.hstar_before = -1;
    out->base.hstar_after = -1;

    if (chain_len < 8) {
        chaos_note(&out->base, "harness defect: chain_len must be >= 8 "
                   "(got %d)", chain_len);
        return false;
    }

    int32_t n = chain_len;  /* heights 0..n inclusive, n+1 entries */
    struct block_index *chain = zcl_calloc((size_t)n + 1, sizeof(*chain),
                                           "bdr_chain");
    struct uint256 *hashes = zcl_calloc((size_t)n + 1, sizeof(*hashes),
                                        "bdr_hashes");
    if (!chain || !hashes) {
        free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: OOM building %d-height "
                   "chain", n);
        return false;
    }
    for (int32_t h = 0; h <= n; h++) {
        block_index_init(&chain[h]);
        bdr_hash(hashes[h].data, h);
        chain[h].phashBlock = &hashes[h];
        chain[h].nHeight = h;
        chain[h].nVersion = 4;
        if (h > 0) chain[h].pprev = &chain[h - 1];
    }

    /* Fixed, deterministic proportions of the chain:
     *   [1, baseline]              — already durably persisted (HAVE_DATA)
     *                                 before this run even starts.
     *   (baseline, batch_end]      — the doomed peer's assigned window.
     *   (baseline, completed_kill] — the part of that window that actually
     *                                 completed (real forward progress)
     *                                 before the peer died mid-transfer.
     *   (completed_kill, batch_end]— interrupted in-flight at the kill.
     *   (batch_end, n]             — never even assigned yet. */
    int32_t baseline = n / 4;
    int32_t batch_end = n / 2;
    int32_t completed_kill = baseline + (batch_end - baseline) / 3;

    for (int32_t h = 1; h <= baseline; h++)
        chain[h].nStatus |= BLOCK_HAVE_DATA;

    struct download_manager dm;
    dl_init(&dm);
    if (!dm.slots) {
        dl_free(&dm); free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: dl_init allocation failed");
        return false;
    }

    const uint32_t PEER_A = 1001, PEER_B = 2002;
    struct block_index *candidate = &chain[n];
    struct block_index *tip0 = &chain[baseline];

    /* ── Phase 1: the FIRST header-driven scan, at the durable baseline —
     * exactly what msg_headers.c runs the moment headers up to `candidate`
     * are admitted. ────────────────────────────────────────────────── */
    enum { BDR_MAX_COLLECT = 4096 };
    struct uint256 need_hashes[BDR_MAX_COLLECT];
    int32_t need_heights[BDR_MAX_COLLECT];
    struct sync_needed_blocks needed;
    syncsvc_collect_needed_blocks(&needed, candidate, tip0, baseline,
                                  need_hashes, need_heights, BDR_MAX_COLLECT);
    if (!needed.chains_from_tip || needed.count == 0) {
        dl_free(&dm); free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: initial collect found "
                   "chains_from_tip=%d count=%zu (want true, >0)",
                   needed.chains_from_tip, needed.count);
        return false;
    }
    dl_queue_blocks(&dm, need_hashes, need_heights, needed.count);

    struct uint256 out_hashes[BDR_MAX_COLLECT];
    size_t want = (size_t)(batch_end - baseline);
    size_t assigned = dl_assign_to_peer(&dm, PEER_A, out_hashes, want);
    if (assigned != want) {
        dl_free(&dm); free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: peer A got %zu of %zu "
                   "requested", assigned, want);
        return false;
    }

    /* dl_assign_to_peer hands back heights in ascending order (the queue is
     * height-sorted), so the first `completed_count` entries are exactly
     * heights (baseline, baseline+completed_count]. */
    int32_t completed_count = completed_kill - baseline;
    for (int32_t i = 0; i < completed_count; i++) {
        int32_t h = baseline + 1 + i;
        uint32_t got_peer = dl_mark_received(&dm, &out_hashes[i]);
        if (got_peer != PEER_A) {
            dl_free(&dm); free(chain); free(hashes);
            chaos_note(&out->base, "harness defect: mark_received(h=%d) "
                       "peer=%u want=%u", h, got_peer, PEER_A);
            return false;
        }
        chain[h].nStatus |= BLOCK_HAVE_DATA;
    }
    int32_t our_height = completed_kill;   /* genuine forward progress */

    /* ── Phase 2: DISRUPTION — the peer dies mid-transfer. Everything it
     * held in-flight but never delivered goes back to the pending queue;
     * a received/persisted height cannot be among them (dl_mark_received
     * already removed it from the in-flight table). ──────────────────── */
    size_t requeued = dl_peer_disconnected(&dm, PEER_A);

    /* ── Phase 3: reconnect — re-run the SAME production decision fresh
     * against the post-disruption block_index. The core assertion this
     * fault exists to prove: no height <= our_height (already durable)
     * ever reappears, from EITHER the fresh collect pass or the download
     * manager's own in-flight table. ─────────────────────────────────── */
    struct block_index *tip1 = &chain[our_height];
    struct sync_needed_blocks needed2;
    int64_t t_disconnect_us = platform_time_monotonic_us();
    syncsvc_collect_needed_blocks(&needed2, candidate, tip1, our_height,
                                  need_hashes, need_heights, BDR_MAX_COLLECT);

    uint64_t duplicate_persisted = 0;
    for (size_t i = 0; i < needed2.count; i++)
        if (need_heights[i] <= our_height)
            duplicate_persisted++;
    for (int32_t h = 1; h <= our_height; h++) {
        struct uint256 hh;
        bdr_hash(hh.data, h);
        if (dl_is_in_flight(&dm, &hh))
            duplicate_persisted++;
    }
    dl_queue_blocks(&dm, need_hashes, need_heights, needed2.count);

    /* Deliberately small first reconnect window (a fresh, unscored peer) so
     * the steady-state re-collect/re-assign loop below actually runs more
     * than once — a stronger regression proof than a single giant batch. */
    size_t reconnect_assign = dl_assign_to_peer(&dm, PEER_B, out_hashes, 8);
    int64_t t_assigned_us = platform_time_monotonic_us();
    out->reconnect_decision_us = t_assigned_us - t_disconnect_us;

    if (reconnect_assign == 0) {
        dl_free(&dm); free(chain); free(hashes);
        chaos_note(&out->base, "harness defect: peer B got 0 blocks on "
                   "reconnect (requeued=%zu queued2=%zu)",
                   requeued, needed2.count);
        return false;
    }

    /* ── Phase 4: drive the resumed peer to tip, re-collecting/re-
     * assigning as its window empties — the real steady-state tick
     * (gap_fill_service / block_sync_service). A small per-block sleep
     * models a real LAN body round-trip so resume_latency_us reports a
     * representative figure instead of a meaningless sub-microsecond
     * in-process one. ────────────────────────────────────────────────── */
    int64_t t_first_progress_us = 0;
    bool measured_first = false;
    int32_t cur_height = our_height;
    size_t batch_off = 0, batch_len = reconnect_assign;
    int guard = 0;
    while (cur_height < n && guard++ < 4 * (n + 1)) {
        if (batch_off >= batch_len) {
            struct sync_needed_blocks more;
            struct block_index *tipN = &chain[cur_height];
            syncsvc_collect_needed_blocks(&more, candidate, tipN, cur_height,
                                          need_hashes, need_heights,
                                          BDR_MAX_COLLECT);
            for (size_t i = 0; i < more.count; i++)
                if (need_heights[i] <= our_height)
                    duplicate_persisted++;
            dl_queue_blocks(&dm, need_hashes, need_heights, more.count);
            batch_len = dl_assign_to_peer(&dm, PEER_B, out_hashes,
                                          BDR_MAX_COLLECT);
            batch_off = 0;
            if (batch_len == 0) break;   /* nothing assignable; real stall */
        }

        struct uint256 *hh = &out_hashes[batch_off++];
        struct timespec xfer = { .tv_sec = 0, .tv_nsec = 2 * 1000 * 1000 };
        nanosleep(&xfer, NULL);   /* simulated LAN body-transfer latency */
        uint32_t got_peer = dl_mark_received(&dm, hh);
        if (got_peer != PEER_B) {
            dl_free(&dm); free(chain); free(hashes);
            chaos_note(&out->base, "harness defect: post-resume "
                       "mark_received peer=%u want=%u at h=%d",
                       got_peer, PEER_B, cur_height + 1);
            return false;
        }
        if (!measured_first) {
            t_first_progress_us = platform_time_monotonic_us();
            measured_first = true;
        }
        cur_height++;
        chain[cur_height].nStatus |= BLOCK_HAVE_DATA;
        dl_add_bytes_received(&dm, 512);
    }

    uint64_t requested_total = 0;
    dl_get_stats(&dm, &requested_total, NULL, NULL, NULL, NULL);

    out->chain_len = n;
    out->persisted_at_disruption = our_height;
    out->final_height = cur_height;
    out->requested_total = requested_total;
    out->duplicate_persisted_requests = duplicate_persisted;
    out->resume_latency_us = measured_first
        ? t_first_progress_us - t_assigned_us : -1;

    out->base.ok = true;
    out->base.recovered = (cur_height == n) && (duplicate_persisted == 0);
    /* This path never touches the blocker/condition/event escalation
     * surface — a stalled body fetch is body_fetch_missing_have_data's
     * typed blocker, not an operator page. */
    out->base.operator_paged = false;
    chaos_note(&out->base,
               "chain=%d baseline=%d disrupted_at=%d final=%d requeued=%zu "
               "requested_total=%llu duplicates=%llu "
               "reconnect_decision_us=%lld resume_latency_us=%lld",
               n, baseline, our_height, cur_height, requeued,
               (unsigned long long)requested_total,
               (unsigned long long)duplicate_persisted,
               (long long)out->reconnect_decision_us,
               (long long)out->resume_latency_us);

    dl_free(&dm);
    free(chain);
    free(hashes);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (n) torn progress.kv WAL — an unclean crash mid-write leaves a
 *     partially-written write-ahead log at reopen
 * ══════════════════════════════════════════════════════════════════════ */

static bool chaos_copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in)
        return false;
    FILE *out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return false;
    }
    uint8_t buf[65536];
    size_t n;
    bool ok = true;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            ok = false;
            break;
        }
    }
    if (ferror(in))
        ok = false;
    fclose(out);
    fclose(in);
    return ok;
}

bool chaos_fault_torn_progress_wal(struct chaos_fault_result *out)
{
    chaos_result_init(out);
    const int32_t BASE = 8;   /* checkpointed into the main db (never at risk) */
    const int32_t K = 24;     /* stamped into the un-checkpointed WAL suffix */

    char dir[256], torn[256];
    mkdir("./test-tmp", 0755);
    test_fmt_tmpdir(dir, sizeof(dir), "chaos_torn_wal", "main");
    test_fmt_tmpdir(torn, sizeof(torn), "chaos_torn_wal", "torn");
    mkdir(dir, 0755);
    mkdir(torn, 0755);

    progress_store_close();
    if (!progress_store_open(dir)) {
        chaos_note(out, "progress_store failed to open fixture dir");
        test_cleanup_tmpdir(dir);
        test_cleanup_tmpdir(torn);
        return false;
    }
    sqlite3 *db = progress_store_db();
    if (!db || !chaos_stamp_prefix(db, BASE)) {
        chaos_note(out, "fixture base stamp failed");
        progress_store_close();
        test_cleanup_tmpdir(dir);
        test_cleanup_tmpdir(torn);
        return false;
    }
    /* Force [0,BASE] + the schema fully into the main db, then disable
     * auto-checkpoint so the [BASE+1,K] suffix stays resident ONLY in the WAL —
     * the frames a torn crash can lose. */
    sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    sqlite3_exec(db, "PRAGMA wal_autocheckpoint=0", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    if (!chaos_stamp_prefix(db, K)) {
        chaos_note(out, "fixture WAL-suffix stamp failed");
        progress_store_close();
        test_cleanup_tmpdir(dir);
        test_cleanup_tmpdir(torn);
        return false;
    }

    int32_t hstar_before = -1, served_before = -1;
    bool ok1 = reducer_frontier_compute_hstar(db, &hstar_before, &served_before);

    /* Copy the live db + WAL (NOT the -shm, which SQLite rebuilds) to a sibling
     * dir while the handle is open — the page cache is coherent for a same-host
     * copy, so the copy captures every committed frame. The store owns its own
     * file name, so ask it rather than hardcoding one. */
    char src_db[PROGRESS_STORE_PATH_MAX];
    char src_wal[PROGRESS_STORE_PATH_MAX + 8];
    char dst_db[PROGRESS_STORE_PATH_MAX];
    char dst_wal[PROGRESS_STORE_PATH_MAX + 8];
    bool copied = false;
    if (progress_store_path(src_db, sizeof(src_db))) {
        const char *base = strrchr(src_db, '/');
        base = base ? base + 1 : src_db;
        snprintf(src_wal, sizeof(src_wal), "%s-wal", src_db);
        snprintf(dst_db, sizeof(dst_db), "%s/%s", torn, base);
        snprintf(dst_wal, sizeof(dst_wal), "%s-wal", dst_db);
        copied = chaos_copy_file(src_db, dst_db) &&
                 chaos_copy_file(src_wal, dst_wal);
    }
    progress_store_close();  /* the original truncates its WAL; the copy is torn */
    if (!copied) {
        chaos_note(out, "hot-copy of db+wal failed");
        test_cleanup_tmpdir(dir);
        test_cleanup_tmpdir(torn);
        return false;
    }

    /* THE FAULT: truncate the copied WAL mid-stream — SQLite ignores every
     * frame from the first incomplete/absent one onward, exactly the recovery a
     * kill -9 between commits leaves. */
    struct stat sb;
    bool torn_ok = false;
    if (stat(dst_wal, &sb) == 0 && sb.st_size > 40) {
        off_t keep = 32 + (sb.st_size - 32) / 2;  /* header + ~half the frames */
        torn_ok = truncate(dst_wal, keep) == 0;
    }
    if (!torn_ok) {
        chaos_note(out, "WAL truncation failed (size=%lld)",
                   (long long)(stat(dst_wal, &sb) == 0 ? sb.st_size : -1));
        test_cleanup_tmpdir(dir);
        test_cleanup_tmpdir(torn);
        return false;
    }

    /* RESTART on the torn copy: the store must reopen cleanly and H* must land
     * on a CONSISTENT prefix in [BASE, K] — never a value above the last commit,
     * never below the checkpointed floor, never a crash. */
    bool reopened = progress_store_open(torn);
    sqlite3 *db2 = reopened ? progress_store_db() : NULL;
    int32_t hstar_after = -1, served_after = -1;
    bool ok2 = db2 && reducer_frontier_compute_hstar(db2, &hstar_after,
                                                     &served_after);

    out->ok = ok1 && reopened && ok2;
    out->hstar_before = hstar_before;
    out->hstar_after = hstar_after;
    out->recovered = out->ok && hstar_after >= BASE && hstar_after <= K &&
                     hstar_before == K;
    chaos_note(out,
        "torn WAL: H* before=%d after=%d (checkpointed floor=%d, WAL tip=%d) — "
        "%s", hstar_before, hstar_after, BASE, K,
        out->recovered
            ? "reopened clean on a consistent prefix — nothing above the last "
              "commit, nothing below the checkpoint"
            : "torn WAL yielded an inconsistent or lost frontier");

    progress_store_close();
    test_cleanup_tmpdir(dir);
    test_cleanup_tmpdir(torn);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (o) disk-full pause — a write hits ENOSPC (modeled with SQLite's own
 *     SQLITE_FULL via PRAGMA max_page_count) and must fail SAFE
 * ══════════════════════════════════════════════════════════════════════ */

static int64_t chaos_pragma_get_int(sqlite3 *db, const char *pragma)
{
    char sql[64];
    snprintf(sql, sizeof(sql), "PRAGMA %s", pragma);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int64_t v = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-fixture-seeding
        v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static void chaos_pragma_set_int(sqlite3 *db, const char *pragma, int64_t v)
{
    char sql[80];
    snprintf(sql, sizeof(sql), "PRAGMA %s=%lld", pragma, (long long)v);
    sqlite3_exec(db, sql, NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
}

static void chaos_fill_txid(uint8_t txid[32], int32_t seed)
{
    memset(txid, 0, 32);
    txid[0] = (uint8_t)(seed & 0xff);
    txid[1] = (uint8_t)((seed >> 8) & 0xff);
    txid[2] = (uint8_t)((seed >> 16) & 0xff);
    txid[31] = 0xD5;
}

/* Add `n` synthetic live outputs through the RAW (overlay-bypassing) coins
 * write path, inside one BEGIN IMMEDIATE the caller does not hold. Returns
 * the result of coins_kv_add_many_sqlite (false on SQLITE_FULL) and rolls the
 * txn back on failure so a full disk never leaves a partial commit. */
static bool chaos_coins_add_batch(sqlite3 *db, int32_t first_seed, size_t n)
{
    struct coins_kv_add_row *rows =
        calloc(n, sizeof(*rows)); // raw-alloc-ok:test
    uint8_t (*txids)[32] = calloc(n, 32); // raw-alloc-ok:test
    if (!rows || !txids) {
        free(rows);
        free(txids);
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        chaos_fill_txid(txids[i], first_seed + (int32_t)i);
        rows[i].txid = txids[i];
        rows[i].vout = 0;
        rows[i].value = 1000 + (int64_t)i;
        rows[i].height = 1;
        rows[i].is_coinbase = false;
        rows[i].script = NULL;
        rows[i].script_len = 0;
    }
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    bool ok = coins_kv_add_many_sqlite(db, rows, n);
    if (ok)
        ok = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;  // raw-sql-ok:test-fixture-seeding
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    free(rows);
    free(txids);
    return ok;
}

bool chaos_fault_disk_full_pause(struct chaos_fault_result *out)
{
    chaos_result_init(out);

    char dir[256];
    mkdir("./test-tmp", 0755);
    test_fmt_tmpdir(dir, sizeof(dir), "chaos_disk_full", "main");
    mkdir(dir, 0755);

    progress_store_close();
    if (!progress_store_open(dir)) {
        chaos_note(out, "progress_store failed to open fixture dir");
        test_cleanup_tmpdir(dir);
        return false;
    }
    sqlite3 *db = progress_store_db();
    if (!db || !coins_kv_ensure_schema(db) ||
        !chaos_coins_add_batch(db, 1, 64)) {
        chaos_note(out, "coins fixture seed failed");
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return false;
    }
    int64_t count0 = coins_kv_count_sqlite(db);

    /* THE FAULT: cap the db at its current page count (zero head-room) so the
     * next growth returns SQLITE_FULL — SQLite's exact disk-full signal. */
    sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    int64_t pages = chaos_pragma_get_int(db, "page_count");
    chaos_pragma_set_int(db, "max_page_count", pages);

    bool wrote_under_full = chaos_coins_add_batch(db, 1000, 4096);
    int64_t count1 = coins_kv_count_sqlite(db);

    /* RECOVER: "free space" (lift the cap) and re-run the identical write. */
    chaos_pragma_set_int(db, "max_page_count", 2147483646);
    bool wrote_after_free = chaos_coins_add_batch(db, 1000, 4096);
    int64_t count2 = coins_kv_count_sqlite(db);

    out->ok = count0 >= 0 && count1 >= 0 && count2 >= 0;
    /* Fail-safe: the write REPORTED its failure (never silently dropped),
     * the coin set never SHRANK across the ENOSPC (no wipe), and the very same
     * write succeeds once space returns and the set grows. */
    out->recovered = out->ok && !wrote_under_full && count1 == count0 &&
                     wrote_after_free && count2 > count0;
    out->operator_paged = false;
    chaos_note(out,
        "disk-full: write-under-FULL=%s coins %lld->%lld (no wipe) -> after "
        "free %s coins=%lld — %s",
        wrote_under_full ? "committed(!)" : "refused",
        (long long)count0, (long long)count1,
        wrote_after_free ? "committed" : "still-failed",
        (long long)count2,
        out->recovered ? "failed safe, then resumed — no partial, no wipe"
                       : "disk-full write was NOT fail-safe");

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (p) HAVE_DATA cleared at height H — a persisted body vanished; the
 *     body-fetch stage must NAME the gap at that exact height
 * ══════════════════════════════════════════════════════════════════════ */

static bool chaos_ensure_body_fetch_table(sqlite3 *db)
{
    return sqlite3_exec(db,  // raw-sql-ok:test-fixture-schema
        "CREATE TABLE IF NOT EXISTS body_fetch_log ("
        "  height       INTEGER PRIMARY KEY,"
        "  hash         BLOB,"
        "  source       TEXT,"
        "  bytes        INTEGER,"
        "  fetched_at   INTEGER,"
        "  ok           INTEGER,"
        "  fail_reason  TEXT"
        ");", NULL, NULL, NULL) == SQLITE_OK;
}

static bool chaos_put_body_fetch_ok(sqlite3 *db, int32_t h)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO body_fetch_log(height,source,bytes,fetched_at,ok) "
            "VALUES(?,'chaos_fixture',0,0,1) ON CONFLICT(height) DO UPDATE "
            "SET ok=1", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

bool chaos_fault_cleared_have_data_hole(struct chaos_fault_result *out)
{
    chaos_result_init(out);
    const int32_t V = 20;    /* headers validated through here */
    const int32_t HOLE = 10; /* body_fetch stalls here: its body vanished */

    char dir[256];
    mkdir("./test-tmp", 0755);
    test_fmt_tmpdir(dir, sizeof(dir), "chaos_have_data_hole", "main");
    mkdir(dir, 0755);

    progress_store_close();
    if (!progress_store_open(dir)) {
        chaos_note(out, "progress_store failed to open fixture dir");
        test_cleanup_tmpdir(dir);
        return false;
    }
    sqlite3 *db = progress_store_db();
    if (!db || !chaos_ensure_log_tables(db) ||
        !chaos_ensure_body_fetch_table(db)) {
        chaos_note(out, "fixture schema ensure failed");
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return false;
    }

    /* Headers validated [0,V]; bodies observed [0,HOLE-1] only — the row at
     * HOLE is ABSENT (the vanished / never-re-fetched body). Cursors: headers
     * ran ahead (V+1), body_fetch stalled AT the hole. */
    bool seeded = true;
    for (int32_t h = 0; seeded && h <= V; h++) {
        uint8_t hh[32];
        chaos_synth_hash(hh, h);
        seeded = chaos_put_validate_headers(db, h, hh);
    }
    for (int32_t h = 0; seeded && h < HOLE; h++)
        seeded = chaos_put_body_fetch_ok(db, h);
    seeded = seeded &&
             stage_set_named_cursor(db, "validate_headers", (uint64_t)(V + 1)) &&
             stage_set_named_cursor(db, "body_fetch", (uint64_t)HOLE);
    if (!seeded) {
        chaos_note(out, "fixture row/cursor seed failed");
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return false;
    }

    /* DETECT: the production body-fetch-gap predicate must NAME the hole at the
     * exact stalled height — a validated header with no observed body. */
    struct stage_repair_body_fetch_gap gap;
    bool named = stage_repair_body_fetch_missing_have_data_candidate(db, HOLE,
                                                                     &gap);
    bool named_correctly = named && gap.ready && gap.target_height == HOLE &&
                           gap.validate_cursor == V + 1 &&
                           gap.body_fetch_cursor == HOLE &&
                           !gap.body_observed;

    /* REMEDY: the body is re-fetched (row written, cursor advances past the
     * hole). The gap must then be GONE — no silent forever-stall. */
    bool refetched = chaos_put_body_fetch_ok(db, HOLE) &&
                     stage_set_named_cursor(db, "body_fetch",
                                            (uint64_t)(HOLE + 1));
    struct stage_repair_body_fetch_gap gap2;
    bool still_named =
        stage_repair_body_fetch_missing_have_data_candidate(db, HOLE, &gap2);

    out->ok = seeded && refetched;
    out->recovered = named_correctly && !still_named;
    out->operator_paged = false;
    chaos_note(out,
        "HAVE_DATA hole: gap named at h=%d (ready=%d cursor=%d validate=%d) -> "
        "re-fetched -> still_named=%d — %s",
        HOLE, gap.ready, gap.body_fetch_cursor, gap.validate_cursor,
        still_named,
        out->recovered ? "body-fetch stage named the vanished body at a known "
                         "height, then cleared on re-fetch"
                       : "the vanished body was NOT named or did not clear");

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return true;
}
