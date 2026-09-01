/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_odelta_scan — the boot "O(delta), never O(chain)" ratchet.
 *
 * The load-bearing law is: boot re-derives only the DELTA above the sealed
 * trust floor, never the whole chain. This test makes that law self-proving.
 * It drives the L0 progress-store fold (reducer_frontier_compute_hstar, the
 * single most representative boot-time data scanner) over a ~50k-row fixture
 * TWICE and reads the per-step iteration counter that boot_scan wires into the
 * contiguity walk:
 *
 *   COLD boot  — a freshly-restored datadir whose trusted anchor sits at the
 *                compiled SHA3 checkpoint A. The fold walks the full delta
 *                [A+1 .. A+N] of every stage log (N == COLD_N). The counter
 *                lands at ~ k_logs * N.
 *
 *   WARM boot  — the SAME datadir after the prior boot finalized+anchored that
 *                prefix (the durable trusted-base declaration rose to A+N) and
 *                the node advanced +DELTA blocks. The fold now walks only
 *                [A+N+1 .. A+N+DELTA]. The counter lands at ~ k_logs * DELTA.
 *
 * The ratchet: warm_rows * 10 < cold_rows. A future change that makes the fold
 * re-scan from genesis / the compiled checkpoint on the warm boot (ignoring the
 * risen trusted anchor) balloons warm_rows back to O(chain) and fails this test
 * with the offending step named — exactly the "slow rebuild" regression class
 * the boot-is-O(delta) law exists to forbid.
 *
 * Fixtures build the durable image directly with sqlite3_exec/INSERT — this is
 * TEST scaffolding, not production reducer code, so it does not route through
 * the AR lifecycle. compute_hstar (SELECT-only) is the unit under test.
 *
 * NOTE on the THIRD boot_scan counter, chain_restore.disk_rebuild_rows: it is
 * deliberately NOT an O(delta) scanner and is characterized separately by
 * test_rebuild_active_chain_is_o_chain_not_delta (test_chain_restore_service.c).
 * The disk-backed active-chain rebuild walks tip->genesis (O(chain height)) and
 * boot reaches it on an UNCLEAN warm restart (crash / kill -9 / OOM) — a known
 * slow-boot defect, NOT a delta path. See docs/AGENT_TRAPS.md; do not "fix" it
 * by asserting it here as O(delta). */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "jobs/reducer_frontier.h"
#include "storage/block_index_projection.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "util/boot_scan.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The compiled SHA3-checkpoint anchor the production fold clamps to (mainnet;
 * the parallel harness selects CHAIN_MAIN). Fixtures sit just above it. */
#define A     REDUCER_FRONTIER_TRUSTED_ANCHOR  /* 3056758 */
#define COLD_N   50000   /* delta the COLD fold must walk (full restored span) */
#define DELTA      100   /* +blocks the WARM boot added above the risen anchor */

#define ODS_CHECK(name, expr) do {                                 \
    printf("boot_odelta_scan: %s... ", (name));                    \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* ── fixture builders ─────────────────────────────────────────────────── */

static bool build_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS stage_cursor ("
        "  name TEXT PRIMARY KEY, cursor INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS progress_meta ("
        "  key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        "  parent_hash BLOB, admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  spent_count INTEGER, added_count INTEGER);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "  height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
        "  spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[test_boot_odelta_scan] schema: %s\n",
                err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static void synth_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[3] = (uint8_t)((h >> 24) & 0xff);
}

static bool set_meta(sqlite3 *db, const char *key, const void *blob, int len)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, blob, len, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Stamp coins_kv proven-authority so compute_hstar treats the baked anchor as
 * a REAL finality floor (the production path on any seeded datadir). Mirrors
 * coins_kv_is_proven_authority: a non-empty `coins` table, an 8-byte LE
 * coins_applied_height, and the 1-byte migration-complete stamp. */
static bool stamp_proven_authority(sqlite3 *db, int64_t applied_height)
{
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');",
            NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return false;
    }
    uint8_t ah[8];
    for (int i = 0; i < 8; i++)
        ah[i] = (uint8_t)((uint64_t)applied_height >> (8 * i));
    uint8_t one = 1;
    return set_meta(db, "coins_applied_height", ah, 8)
        && set_meta(db, "coins_kv_migration_complete", &one, 1);
}

/* Raise the durable raise-only trusted-base declaration to `height` — the
 * production tip_finalize seed/anchor path's side effect. This is what lets the
 * WARM fold start its contiguity walk at height+1 instead of the compiled
 * checkpoint. */
static bool declare_trusted_base(sqlite3 *db, int32_t height)
{
    uint8_t hb[8];
    for (int i = 0; i < 8; i++)
        hb[i] = (uint8_t)(((uint64_t)height >> (8 * i)) & 0xff);
    uint8_t hash[32];
    synth_hash(hash, height);
    return set_meta(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY, hb, 8)
        && set_meta(db, REDUCER_TRUSTED_BASE_HASH_KEY, hash, 32);
}

static bool set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name,cursor,updated_at) VALUES(?,?,0) "
            "ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool set_all_cursors(sqlite3 *db, int64_t c)
{
    return set_cursor(db, "validate_headers", c)
        && set_cursor(db, "body_fetch", c)
        && set_cursor(db, "body_persist", c)
        && set_cursor(db, "proof_validate", c)
        && set_cursor(db, "script_validate", c)
        && set_cursor(db, "utxo_apply", c)
        && set_cursor(db, "tip_finalize", c);
}

/* Bulk-populate a fully-consistent ok=1 image across every stage log for the
 * inclusive height range [lo, hi], hashes agreeing so the C3 hash-agreement
 * pass does not clamp H*. One prepared statement per table, reused across the
 * range, all inside the caller's transaction — fast enough for ~50k heights. */
static bool populate_range(sqlite3 *db, int32_t lo, int32_t hi)
{
    static const char *const sql[] = {
        "INSERT INTO header_admit_log(height,hash,admitted_at) VALUES(?,?,0)",
        "INSERT INTO validate_headers_log(height,hash,ok) VALUES(?,?,1)",
        "INSERT INTO script_validate_log(height,status,ok,block_hash) "
            "VALUES(?,'verified',1,?)",
        "INSERT INTO body_persist_log(height,ok) VALUES(?,1)",
        "INSERT INTO proof_validate_log(height,status,ok,block_hash) "
            "VALUES(?,'verified',1,?)",
        "INSERT INTO utxo_apply_log(height,status,ok) VALUES(?,'verified',1)",
        "INSERT INTO utxo_apply_delta(height,branch_hash,spent_blob,added_blob)"
            " VALUES(?,?,x'',x'')",
        "INSERT INTO tip_finalize_log(height,status,ok) VALUES(?,'ok',1)",
    };
    enum { NST = (int)(sizeof(sql) / sizeof(sql[0])) };
    sqlite3_stmt *st[NST] = {0};
    bool ok = true;
    for (int i = 0; i < NST && ok; i++)
        ok = sqlite3_prepare_v2(db, sql[i], -1, &st[i], NULL) == SQLITE_OK;

    for (int32_t h = lo; h <= hi && ok; h++) {
        uint8_t hh[32];
        synth_hash(hh, h);
        /* header_admit(hash), validate_headers(hash), script(block_hash),
         * proof(block_hash), utxo_delta(branch_hash) all carry hh; the plain
         * logs bind only the height. */
        static const int has_hash[NST] = {1, 1, 1, 0, 1, 0, 1, 0};
        for (int i = 0; i < NST && ok; i++) {
            sqlite3_reset(st[i]);
            sqlite3_bind_int64(st[i], 1, h);
            if (has_hash[i])
                sqlite3_bind_blob(st[i], 2, hh, 32, SQLITE_TRANSIENT);
            ok = sqlite3_step(st[i]) == SQLITE_DONE;
        }
    }
    for (int i = 0; i < NST; i++)
        if (st[i]) sqlite3_finalize(st[i]);
    return ok;
}

/* ── projection catch-up fixture ──────────────────────────────────────── */

/* Append one distinct EV_BLOCK_HEADER (unique hash/height per seed) to the
 * event log — the unit the block_index_projection catch-up folds. Mirrors the
 * shape of bip_emit in test_projection_replay_invariant.c but stands alone so
 * this ratchet does not couple to that test's internals. */
static bool ods_emit_header(event_log_t *log, uint32_t seed)
{
    struct ev_block_header h;
    memset(&h, 0, sizeof(h));
    for (int i = 0; i < 32; i++)
        h.hash[i] = (uint8_t)((seed >> ((i % 4) * 8)) & 0xff);
    for (int i = 0; i < 32; i++)
        h.hashPrev[i] = (uint8_t)(((seed + 1) >> ((i % 4) * 8)) & 0xff);
    h.height   = (int32_t)seed;
    h.nStatus  = 0x60u; /* ACTIVE-ish */
    h.nTime    = 1700000000u + seed;
    h.nBits    = 0x1d00ffffu;
    h.nVersion = 4;
    h.nTx      = 1;
    uint8_t sol[8];
    for (size_t i = 0; i < sizeof(sol); i++) sol[i] = (uint8_t)((seed + i) & 0xff);
    h.nSolutionSize = (uint16_t)sizeof(sol);
    uint8_t buf[512];
    size_t written = 0;
    if (!ev_block_header_serialize(&h, sol, buf, sizeof(buf), &written))
        return false;
    return event_log_append(log, EV_BLOCK_HEADER, buf, written) != UINT64_MAX;
}

/* SECOND ratchet, a different subsystem: the block_index_projection catch-up.
 * A cold catch-up folds every header in the event log (fresh projection); a
 * warm catch-up after +DELTA new headers folds ONLY those DELTA — it streams
 * from the persisted last_consumed_offset, never from offset 0. Proves a second
 * synchronous boot data-scanner is O(delta). Returns failures. */
#define PROJ_COLD_HDRS 5000
#define PROJ_DELTA      100

static int projection_catch_up_ratchet(void)
{
    int failures = 0;
    const char *const CTR = "block_index_projection.catch_up_events";

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_odelta", "proj");
    char log_path[400], db_path[400];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);
    snprintf(db_path,  sizeof(db_path),  "%s/bip.db",     dir);

    event_log_t *log = event_log_open(log_path);
    block_index_projection_t *bip = block_index_projection_open(db_path, log);
    ODS_CHECK("projection: open log + db", log && bip);
    if (!log || !bip) {
        if (bip) block_index_projection_close(bip);
        if (log) event_log_close(log);
        test_cleanup_tmpdir(dir);
        return failures + 1;
    }
    /* Batch durability: skip the twice-per-append fsync so the multi-thousand
     * header fixture builds in milliseconds; flush once before each catch-up. */
    event_log_set_deferred_sync(log, true);

    /* The counter is process-global and cumulative; it starts at 0 here (no
     * prior phase folds a projection). Read it after each catch-up and diff. */
    uint64_t base = boot_scan_value(CTR);

    bool emit_ok = true;
    for (uint32_t s = 1; s <= PROJ_COLD_HDRS && emit_ok; s++)
        emit_ok = ods_emit_header(log, 0x100000u + s);
    ODS_CHECK("projection: cold headers emitted", emit_ok);
    ODS_CHECK("projection: cold flush", event_log_flush(log));

    /* COLD catch-up: fresh projection folds the whole log. */
    bool cold_ok = block_index_projection_catch_up(bip) != (uint64_t)-1;
    uint64_t cold_rows = boot_scan_value(CTR) - base;
    ODS_CHECK("projection: cold catch_up ok", cold_ok);
    ODS_CHECK("projection: cold folded the full log",
              cold_rows == (uint64_t)PROJ_COLD_HDRS);
    printf("boot_odelta_scan: proj cold_rows=%llu (hdrs=%d)\n",
           (unsigned long long)cold_rows, PROJ_COLD_HDRS);

    /* WARM catch-up: +DELTA new headers, re-fold. The stream resumes from the
     * persisted last_consumed_offset, so only the DELTA is touched. */
    emit_ok = true;
    for (uint32_t s = 1; s <= PROJ_DELTA && emit_ok; s++)
        emit_ok = ods_emit_header(log, 0x200000u + s);
    ODS_CHECK("projection: warm headers emitted", emit_ok);
    ODS_CHECK("projection: warm flush", event_log_flush(log));

    uint64_t before_warm = boot_scan_value(CTR);
    bool warm_ok = block_index_projection_catch_up(bip) != (uint64_t)-1;
    uint64_t warm_rows = boot_scan_value(CTR) - before_warm;
    ODS_CHECK("projection: warm catch_up ok", warm_ok);
    ODS_CHECK("projection: warm folded only the delta",
              warm_rows == (uint64_t)PROJ_DELTA);
    printf("boot_odelta_scan: proj warm_rows=%llu (delta=%d)\n",
           (unsigned long long)warm_rows, PROJ_DELTA);

    /* The RATCHET: the warm catch-up must not re-fold the sealed prefix. */
    bool o_delta = warm_rows > 0 && warm_rows * 10 < cold_rows;
    if (!o_delta)
        printf("boot_odelta_scan: RATCHET BROKEN — step '%s' is O(chain): "
               "warm folded %llu events, not the %d-event delta "
               "(cold=%llu). The projection catch-up re-streamed the log "
               "from offset 0 instead of the persisted cursor.\n",
               CTR, (unsigned long long)warm_rows, PROJ_DELTA,
               (unsigned long long)cold_rows);
    ODS_CHECK("projection O(delta): warm_rows * 10 < cold_rows", o_delta);

    block_index_projection_close(bip);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── the ratchet ─────────────────────────────────────────────────────── */

int test_boot_odelta_scan(void)
{
    int failures = 0;
    const char *const CTR = "reducer_frontier.contiguity_rows";

    /* This fixture proves the compiled MAINNET checkpoint delta. Earlier
     * monolith groups may intentionally select regtest and leave it active;
     * make the network premise explicit and drop the per-boot tag watermark. */
    chain_params_select(CHAIN_MAIN);
    reducer_frontier_provable_tip_reset();

    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        printf("boot_odelta_scan: open :memory:... FAIL\n");
        return 1;
    }
    ODS_CHECK("schema", build_schema(db));
    ODS_CHECK("proven authority", stamp_proven_authority(db, A + 1));

    /* Build the full restored span [A+1 .. A+COLD_N] in one transaction. */
    sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    bool built = populate_range(db, A + 1, A + COLD_N);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    ODS_CHECK("cold span built", built);
    ODS_CHECK("cold cursors", set_all_cursors(db, A + COLD_N + 1));

    /* ── COLD boot: anchor at the compiled checkpoint, fold walks the delta
     *    [A+1 .. A+COLD_N] of every stage log. ── */
    boot_scan_reset_for_testing();
    int32_t hstar = -1, served = -1;
    bool cold_ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    uint64_t cold_rows = boot_scan_value(CTR);
    ODS_CHECK("cold compute returns true", cold_ok);
    /* H* reaches the tip: hashes agree and every log is contiguous. */
    ODS_CHECK("cold hstar == tip", hstar == A + COLD_N);
    /* The fold really walked the whole restored span, once per stage log. The
     * counter is the O(delta) witness — it must be at least the span length
     * (k_logs >= 1), and comfortably larger since there are 6 stage logs. */
    ODS_CHECK("cold scanned the full span", cold_rows >= (uint64_t)COLD_N);
    printf("boot_odelta_scan: cold_rows=%llu (span=%d)\n",
           (unsigned long long)cold_rows, COLD_N);

    /* ── WARM boot: the prior boot finalized+anchored the [A+1 .. A+COLD_N]
     *    prefix (trusted base rose to A+COLD_N) and the node advanced +DELTA
     *    blocks. Add the new rows, advance the cursors, and re-fold. ── */
    sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    bool grown = populate_range(db, A + COLD_N + 1, A + COLD_N + DELTA);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    ODS_CHECK("warm delta built", grown);
    ODS_CHECK("warm anchor raised",
              declare_trusted_base(db, A + COLD_N)
              && stamp_proven_authority(db, A + COLD_N + 1));
    ODS_CHECK("warm cursors", set_all_cursors(db, A + COLD_N + DELTA + 1));

    boot_scan_reset_for_testing();
    hstar = -1; served = -1;
    bool warm_ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    uint64_t warm_rows = boot_scan_value(CTR);
    ODS_CHECK("warm compute returns true", warm_ok);
    ODS_CHECK("warm hstar == new tip", hstar == A + COLD_N + DELTA);
    printf("boot_odelta_scan: warm_rows=%llu (delta=%d)\n",
           (unsigned long long)warm_rows, DELTA);

    /* The RATCHET. On a warm restart whose trusted anchor tracks the folded
     * prefix, the fold walks only the +DELTA new heights — not the whole
     * chain. If a regression makes it re-scan from the compiled checkpoint,
     * warm_rows tracks COLD_N (not DELTA) and this fails, naming the step. */
    bool o_delta = warm_rows > 0 && warm_rows * 10 < cold_rows;
    if (!o_delta)
        printf("boot_odelta_scan: RATCHET BROKEN — step '%s' is O(chain): "
               "warm_rows=%llu did NOT shrink below cold_rows/10=%llu "
               "(cold_rows=%llu). A boot data scanner is re-walking the "
               "sealed history instead of just the delta.\n",
               CTR, (unsigned long long)warm_rows,
               (unsigned long long)(cold_rows / 10),
               (unsigned long long)cold_rows);
    ODS_CHECK("O(delta): warm_rows * 10 < cold_rows", o_delta);

    /* Sanity: the warm walk is bounded by the delta it was asked to cover
     * (k_logs stage logs * DELTA heights, with a little slack). This catches a
     * regression that scans MORE than the delta without going fully O(chain). */
    ODS_CHECK("warm bounded by delta",
              warm_rows <= (uint64_t)DELTA * 16);

    sqlite3_close(db);

    /* Second, independent ratchet across a DIFFERENT boot data-scanner. */
    failures += projection_catch_up_ratchet();

    /* Do not export this fixture's high verification watermark to the next
     * group in the single-process coverage runner. */
    reducer_frontier_provable_tip_reset();

    return failures;
}
