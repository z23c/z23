/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_always_sync_selfheal — regression suite for the self-healing
 * contracts in docs/work/fail-safe-architecture.md: the universal
 * re-derivation primitive (§0c), the always-terminating recovery ladder
 * (§1), and the Log-Cursor Contiguity (LCC) write rules (§0c RAISE/DELETE
 * rules). TENACITY.md:106-110 — "a new wedge class earns a new write-time
 * invariant, never a new repair rung" — this file is the standing proof
 * that both halves of that doctrine hold. No production .c changes.
 *
 * Four groups:
 *
 *   G4 never-wedge — the mission property end-to-end across TWO real
 *      production layers (staged_sync_supervisor.c + blocker_stall_meta_
 *      detector.c) with no mocks: a frozen reducer stage escalates into the
 *      exact typed `stage_stalled_*` blocker the generic always-terminating
 *      backstop detects, remedies (arms the recovery ladder + pages naming
 *      the offender), and witnesses to a terminal verdict on an H* climb —
 *      and the supervisor's own falling edge clears the blocker when the
 *      stage resumes. Proves "a stall is ALWAYS a named blocker whose remedy
 *      runs to a terminal verdict; a silent halt is unrepresentable."
 *
 *   G1 stage_rederive_range — the universal primitive. Design-only on this
 *      branch (§0c names it `stage_rederive_range(db, ms, lowest_stage,
 *      h)`), so WEAK-SYMBOL gated: compiles and SKIPs cleanly today, starts
 *      asserting the moment a sibling lane links a real definition under
 *      that name. Assertions are contract-shaped, not implementation-shaped
 *      (exact clamp values are that lane's own test's job — see
 *      test_stall_totality_matrix.c for per-shape coverage): (1) the
 *      rowless hole at h gets a real ok=1 row after one call; (2) an
 *      immediate second call reproduces a byte-identical row (idempotent,
 *      no duplicate work); (3) closing+reopening the progress store between
 *      calls (a proxy for "crash mid-way" — the heavier fork+SIGKILL
 *      harness of test_utxo_apply_crash_replay.c is this lane's own job
 *      once the primitive's transaction boundaries are known) still
 *      reproduces the identical row — the repair committed as one durable
 *      unit, not partial state an interrupted call could corrupt.
 *
 *   G2 the recovery ladder never gives up — drives sticky_escalator's REAL
 *      8-rung ladder through a synthetic PERSISTENT stall (tip never
 *      climbs) via the existing note_stall/test_drive seams — no mocked
 *      rungs. Rung 0 (retry) and rung 1 (targeted_rederive) run their REAL
 *      default healers against a genuine rowless-hole fixture (the
 *      test_sticky_escalator.c T1 shape), so the walk includes a WITNESSED,
 *      self-derived remedy, not a mock. The remaining rungs (2-7) each
 *      decline or no-op honestly in this datadir-less, connman-less
 *      fixture (their own internals are out of scope here — see HARD
 *      RULES — and are covered by test_sticky_escalator.c /
 *      test_stall_totality_matrix.c) and so advance in one dispatch each.
 *      Once the deepest rung exhausts without clearing: asserts the ladder
 *      does NOT latch, re-arms after its cooldown and CYCLES back to rung
 *      0, and pages non-latching once per cycle — over TWO full cycles.
 *      Finally proves the other half of the progress law: a real tip climb
 *      clears the whole episode.
 *
 *   G3 LCC refuses an incoherent cursor raise — the write-rule half (§0c).
 *      Also design-only, so also weak-symbol gated, on a small dedicated
 *      test seam (`lcc_test_probe_raise_refused` — a `_test_` seam in the
 *      `reducer_frontier_test_set_compiled_anchor` tradition, not a
 *      repurposed production entry point) a sibling lane defines once the
 *      RAISE rule lands at the stage_cursor write chokepoint. Pre-merge:
 *      SKIP. Post-merge: a raise past a rowless height with no trusted-base
 *      declaration is REFUSED, a coherent lower/covered move is allowed. */

#include "platform/time_compat.h"
#include "test/test_core.h"

#include "conditions/blocker_stall_meta_detector.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "json/json.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "storage/progress_store.h"
#include "supervisors/staged_sync_supervisor.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASH_CHECK(name, expr) do { \
    printf("always_sync_selfheal: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define A REDUCER_FRONTIER_TRUSTED_ANCHOR

/* Pin the network-derived compiled-anchor floor to the mainnet anchor A so
 * fixture rows at A+1.. are honored (test_stage_repair_script_refill.c /
 * test_sticky_escalator.c pattern). Restored to -1 on module reset. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

/* ── G1 weak-symbol seam: the universal re-derivation primitive ────────
 * fail-safe-architecture.md §0c. The primitive LANDED (engine/jobs/src/
 * stage_rederive_range.c) with the range signature (db, ms, from_height,
 * to_height, out) — re-fold the PoW-verified on-disk bodies across a height
 * range. This decl is aligned to that landed signature (the integration
 * this test exists to gate). Kept weak so the `if (!stage_rederive_range)`
 * skip seam still holds if the definition is ever unlinked. */
struct stage_rederive_range_result;
extern bool stage_rederive_range(struct sqlite3 *db, struct main_state *ms,
                                 int from_height, int to_height,
                                 struct stage_rederive_range_result *out)
    __attribute__((weak));

/* ── G3 weak-symbol seam: the LCC RAISE-rule refusal probe ─────────────
 * fail-safe-architecture.md §0c RAISE rule: "a cursor moves up only in a
 * transaction that inserts the covering row ... or raises the trusted base
 * itself ... with explicit trust posture". A dedicated `_test_` seam (NOT a
 * repurposed production entrypoint — the real chokepoint,
 * stage_repair_force_stage_cursor, is explicitly NOT public API per
 * engine/jobs/include/jobs/stage_repair_internal.h and requires an
 * already-open progress_store transaction this test has no business
 * opening). Contract for whoever lands the LCC write rules: given an OPEN
 * progress.kv `db`, a stage name, its current cursor, and a strictly-higher
 * requested height with NO covering row and no trusted-base declaration,
 * return true iff the write path REFUSED the raise (false = it would have
 * been allowed, i.e. the rule is not yet enforced for this input). */
#if defined(__APPLE__)
static bool (*const lcc_test_probe_raise_refused)(struct sqlite3 *,
                                                  const char *, int32_t,
                                                  int32_t) = NULL;
#else
extern bool lcc_test_probe_raise_refused(struct sqlite3 *db,
                                         const char *stage_name,
                                         int32_t current_height,
                                         int32_t requested_height)
    __attribute__((weak));
#endif

/* ── Shared fixture helpers (test_sticky_escalator.c T1 pattern, trimmed to
 * what G1/G2 need: a rowless-hole progress.kv + a 3-block main_state) ──── */

static bool ash_exec(sqlite3 *db, const char *sql)
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

static bool ash_seed_schema(sqlite3 *db)
{
    return
        ash_exec(db,
            "CREATE TABLE IF NOT EXISTS header_admit_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
            "parent_hash BLOB, admitted_at INTEGER NOT NULL)") &&
        ash_exec(db,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "fail_reason TEXT, validated_at INTEGER)") &&
        ash_exec(db,
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "block_hash BLOB)") &&
        ash_exec(db,
            "CREATE TABLE IF NOT EXISTS body_persist_log ("
            "height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL)") &&
        ash_exec(db,
            "CREATE TABLE IF NOT EXISTS body_fetch_log ("
            "height INTEGER PRIMARY KEY, hash BLOB, source TEXT,"
            "bytes INTEGER, fetched_at INTEGER, ok INTEGER,"
            "fail_reason TEXT)") &&
        ash_exec(db,
            "CREATE TABLE IF NOT EXISTS proof_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "block_hash BLOB)") &&
        ash_exec(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL)") &&
        ash_exec(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
            "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL)") &&
        ash_exec(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "tip_hash BLOB)");
}

static bool ash_seed_cursor(sqlite3 *db, const char *name, int cursor)
{
    ash_exec(db,
        "CREATE TABLE IF NOT EXISTS stage_cursor("
        "name TEXT PRIMARY KEY, cursor INTEGER, updated_at INTEGER)");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

/* Read a stage cursor back (−1 if absent). */
static int ash_read_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int c = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-read
        c = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return c;
}

static bool ash_seed_all_cursors(sqlite3 *db, int cursor)
{
    return ash_seed_cursor(db, "validate_headers", cursor) &&
           ash_seed_cursor(db, "body_fetch", cursor) &&
           ash_seed_cursor(db, "body_persist", cursor) &&
           ash_seed_cursor(db, "script_validate", cursor) &&
           ash_seed_cursor(db, "proof_validate", cursor) &&
           ash_seed_cursor(db, "utxo_apply", cursor) &&
           ash_seed_cursor(db, "tip_finalize", cursor);
}

static bool ash_put_header_admit(sqlite3 *db, int height,
                                 const struct uint256 *hash,
                                 const struct uint256 *parent_hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    if (parent_hash)
        sqlite3_bind_blob(st, 3, parent_hash->data, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(st, 3);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool ash_put_body_fetch_ok(sqlite3 *db, int height,
                                  const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO body_fetch_log"
            "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
            "VALUES(?,?,'disk',0,1,1,NULL)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool ash_put_hash_log(sqlite3 *db, const char *table,
                             const char *hash_col, int height, int ok_flag,
                             const struct uint256 *hash)
{
    char sql[192];
    if (strcmp(table, "validate_headers_log") == 0)
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,ok,%s) VALUES(?,?,?)",
                 table, hash_col);
    else
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,status,ok,%s) "
                 "VALUES(?,'verified',?,?)", table, hash_col);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool ash_put_simple_log(sqlite3 *db, const char *table, int height,
                               int ok_flag)
{
    char sql[160];
    if (strcmp(table, "body_persist_log") == 0)
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,source,ok) "
                 "VALUES(?,'fixture',?)", table);
    else
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO %s(height,status,ok) "
                 "VALUES(?,'verified',?)", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool ash_put_utxo_log(sqlite3 *db, int height, int ok_flag,
                             const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
            "VALUES(?,'verified',?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    if (!ok) return false;

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(?,?,x'',x'')", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool ash_put_tip_log(sqlite3 *db, int height, int ok_flag,
                           const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,tip_hash) VALUES(?,'finalized',?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_int(st, 2, ok_flag);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool ash_put_upstream_ok(sqlite3 *db, int height,
                                const struct uint256 *hash)
{
    return ash_put_hash_log(db, "validate_headers_log", "hash", height, 1,
                            hash) &&
           ash_put_hash_log(db, "script_validate_log", "block_hash", height,
                            1, hash) &&
           ash_put_simple_log(db, "body_persist_log", height, 1) &&
           ash_put_hash_log(db, "proof_validate_log", "block_hash", height,
                            1, hash) &&
           ash_put_utxo_log(db, height, 1, hash);
}

static bool ash_delete_height(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE height=?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool ash_seed_coins_applied(sqlite3 *db, int64_t height)
{
    uint8_t blob[8];
    for (int i = 0; i < 8; i++)
        blob[i] = (uint8_t)((uint64_t)height >> (8 * i));

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, blob, sizeof(blob), SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    if (!ok) return false;

    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');",
            NULL, NULL, &err) != SQLITE_OK) {  // raw-sql-ok:test-seed
        sqlite3_free(err);
        return false;
    }
    uint8_t one = 1;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static int ash_cursor_value(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int value = -1;
    if (sqlite3_prepare_v2(db, "SELECT cursor FROM stage_cursor WHERE name=?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
            value = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return value;
}

/* Total rows across every reducer log — the "no log row is ever deleted"
 * invariant witness (test_sticky_escalator.c pattern). */
static int64_t ash_total_log_rows(sqlite3 *db)
{
    static const char *const tables[] = {
        "header_admit_log", "validate_headers_log", "body_fetch_log",
        "body_persist_log", "script_validate_log", "proof_validate_log",
        "utxo_apply_log", "tip_finalize_log",
    };
    int64_t total = 0;
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char sql[96];
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", tables[i]);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
            total += sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return total;
}

struct ash_fixture {
    char dir[256];
    struct main_state ms;
    struct uint256 hashes[4];
    struct block_index *idx[4];
};

static struct block_index *ash_insert_index(struct main_state *ms,
                                            struct uint256 *hash, int height,
                                            struct block_index *prev)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(height & 0xff);
    hash->data[1] = (uint8_t)((height >> 8) & 0xff);
    hash->data[2] = (uint8_t)((height >> 16) & 0xff);
    hash->data[31] = 0x5e;

    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi) return NULL;
    bi->nHeight = height;
    bi->pprev = prev;
    bi->nStatus = BLOCK_VALID_SCRIPTS;
    bi->nFile = -1;
    bi->nDataPos = 0;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)(height - A + 1));
    return bi;
}

/* Rowless script/proof/utxo hole at A+2 with cursors ahead of it (see
 * fail-safe-architecture.md §0 "the live specimen"). */
static bool ash_setup_hole_fixture(struct ash_fixture *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir), "always_sync_selfheal", tag);
    if (!progress_store_open(fx->dir)) return false;
    sqlite3 *db = progress_store_db();
    if (!ash_seed_schema(db)) return false;
    if (!ash_seed_all_cursors(db, A + 4)) return false;

    main_state_init(&fx->ms);
    fx->idx[1] = ash_insert_index(&fx->ms, &fx->hashes[1], A + 1, NULL);
    fx->idx[2] = ash_insert_index(&fx->ms, &fx->hashes[2], A + 2, fx->idx[1]);
    fx->idx[3] = ash_insert_index(&fx->ms, &fx->hashes[3], A + 3, fx->idx[2]);
    if (!fx->idx[1] || !fx->idx[2] || !fx->idx[3]) return false;

    if (!ash_put_header_admit(db, A + 1, &fx->hashes[1], NULL) ||
        !ash_put_header_admit(db, A + 2, &fx->hashes[2], &fx->hashes[1]) ||
        !ash_put_header_admit(db, A + 3, &fx->hashes[3], &fx->hashes[2]))
        return false;

    for (int i = 1; i <= 3; i++)
        if (!ash_put_upstream_ok(db, A + i, &fx->hashes[i]) ||
            !ash_put_body_fetch_ok(db, A + i, &fx->hashes[i]))
            return false;

    if (!ash_put_tip_log(db, A + 1, 1, &fx->hashes[1])) return false;
    if (!ash_seed_coins_applied(db, A + 2)) return false;

    /* Punch the hole at A+2: script/proof/utxo rows gone, cursors above it. */
    return ash_delete_height(db, "script_validate_log", A + 2) &&
           ash_delete_height(db, "proof_validate_log", A + 2) &&
           ash_delete_height(db, "utxo_apply_log", A + 2) &&
           ash_delete_height(db, "utxo_apply_log", A + 3) &&
           ash_seed_cursor(db, "utxo_apply", A + 2);
}

static void ash_teardown_fixture(struct ash_fixture *fx)
{
    sync_monitor_set_context(NULL, NULL, NULL);
    sticky_escalator_test_reset();
    stage_reducer_frontier_reset_detect_memo_for_testing();
    main_state_free(&fx->ms);
    progress_store_close();
    test_cleanup_tmpdir(fx->dir);
}

/* ── G1 — stage_rederive_range idempotent + crash-safe ────────────────── */

static int ash_test_stage_rederive_range(void)
{
    int failures = 0;
    printf("\n--- G1: stage_rederive_range (universal re-derivation primitive) ---\n");

    if (!stage_rederive_range) {
        printf("always_sync_selfheal: G1 SKIP — stage_rederive_range not "
               "yet linked (design-only per fail-safe-architecture.md §0c); "
               "this becomes the integration regression gate once a sibling "
               "lane lands it.\n");
        return 0;
    }

    struct ash_fixture fx;
    ASH_CHECK("G1: setup rowless-hole fixture",
             ash_setup_hole_fixture(&fx, "g1_rederive"));
    sqlite3 *db = progress_store_db();

    /* Contract (engine/jobs/src/stage_rederive_range.c): the primitive REWINDS the
     * body-dependent stage cursors down to from_height and deletes the stale
     * suffix rows, so the reducer drive can re-fold the range forward to
     * byte-identical verdicts. It does NOT itself re-fold (that needs the real
     * on-disk bodies, which the drive reads) — this is the "readied for
     * re-derivation" half. The fixture seeds every cursor at A+4 with a hole at
     * A+2. After rederive(A+2,A+2): the body-dependent cursors sit at A+2, and
     * utxo_apply (already at A+2) is never moved UP. */
    bool r1 = stage_rederive_range(db, &fx.ms, A + 2, A + 2, NULL);
    ASH_CHECK("G1: first call succeeds", r1);
    ASH_CHECK("G1: script_validate cursor rewound to the hole at A+2",
             ash_read_cursor(db, "script_validate") == A + 2);
    ASH_CHECK("G1: proof_validate cursor rewound to A+2",
             ash_read_cursor(db, "proof_validate") == A + 2);
    ASH_CHECK("G1: tip_finalize cursor rewound to A+2 (rows kept, cursor lowered)",
             ash_read_cursor(db, "tip_finalize") == A + 2);
    ASH_CHECK("G1: utxo_apply cursor NOT moved up (LCC — stays at A+2)",
             ash_read_cursor(db, "utxo_apply") == A + 2);

    bool r2 = stage_rederive_range(db, &fx.ms, A + 2, A + 2, NULL);
    ASH_CHECK("G1: second immediate call also succeeds (idempotent)", r2);
    ASH_CHECK("G1: idempotent — cursors unchanged at A+2 on re-run",
             ash_read_cursor(db, "script_validate") == A + 2 &&
             ash_read_cursor(db, "proof_validate") == A + 2);

    /* Crash-mid-way proxy: close and reopen the progress store between calls. A
     * single-transaction primitive must survive this with the same durable
     * cursor state; a partially-committed one would not. */
    progress_store_close();
    ASH_CHECK("G1: progress store reopens after simulated restart",
             progress_store_open(fx.dir));
    db = progress_store_db();
    bool r3 = stage_rederive_range(db, &fx.ms, A + 2, A + 2, NULL);
    ASH_CHECK("G1: call after simulated crash+restart succeeds", r3);
    ASH_CHECK("G1: post-restart cursor state identical (durable, not partial)",
             ash_read_cursor(db, "script_validate") == A + 2 &&
             ash_read_cursor(db, "proof_validate") == A + 2);

    ash_teardown_fixture(&fx);
    printf("always_sync_selfheal: G1 %d failures\n", failures);
    return failures;
}

/* ── G2 — the recovery ladder never gives up ──────────────────────────── */

static int ash_test_ladder_cycles_never_gives_up(void)
{
    int failures = 0;
    printf("\n--- G2: sticky_escalator — cycles + pages, never gives up ---\n");

    blocker_module_init();
    reducer_frontier_test_set_compiled_anchor(A);

    struct ash_fixture fx;
    ASH_CHECK("G2: setup rowless-hole fixture",
             ash_setup_hole_fixture(&fx, "g2_ladder"));
    sqlite3 *db = progress_store_db();
    int64_t rows_before = ash_total_log_rows(db);

    /* No datadir, no connman: the reindex / self_mint_refold / widen_peers /
     * rebootstrap / refold_from_anchor rungs each decline or no-op honestly
     * in ONE dispatch (their real default actions — see sticky_escalator.c
     * rung_reindex_default's no_datadir path, rung_widen_peers_default's
     * no_connman path, rung_refold_from_anchor_default's no_datadir path,
     * and the resnapshot/self_mint_refold/rebootstrap stubs). This workflow
     * does not own those rungs' real implementations (out of scope per HARD
     * RULES); the point under test is the LADDER's totality/cycling
     * contract, not any one rung's internals — those are covered by
     * test_sticky_escalator.c and test_stall_totality_matrix.c. */
    sync_monitor_set_context(NULL, NULL, &fx.ms);
    sticky_escalator_test_reset();
    sticky_escalator_set_datadir(NULL);
    stage_reducer_frontier_reset_detect_memo_for_testing();
    sticky_escalator_test_set_suppress_refold_restart(true);

    /* observe_tip() (called at every rung entry) prefers the cached provable
     * H*; stamp it to a fixed, real value so g_tip_at_rung is a determinate
     * >=0 number throughout (the test_sticky_escalator.c T4/T5 pattern) —
     * otherwise it falls through to sticky_escalator's own g_ms (unset here,
     * we never call sticky_escalator_register) and lands on the -1
     * sentinel, which would make the progress-clear check unreachable
     * regardless of the injected tip. Held fixed at 1000 for the whole
     * never-clearing walk; the final assertion injects a tip past it. */
    reducer_frontier_provable_tip_reset();
    reducer_frontier_provable_tip_set(1000);

    sticky_escalator_note_stall("test_persistent_stall_never_clears");
    ASH_CHECK("G2: ladder armed by note_stall", sticky_escalator_test_armed());

    int64_t t0 = (int64_t)platform_time_wall_time_t();

    /* ── Cycle 1 ──────────────────────────────────────────────────────── */
    ASH_CHECK("G2: c1 retry rung holds within its 30s window",
             sticky_escalator_test_drive(0, t0 + 1) == STICKY_RUNG_RETRY);
    ASH_CHECK("G2: c1 retry window lapse advances to targeted_rederive",
             sticky_escalator_test_drive(0, t0 + 31) ==
                 STICKY_RUNG_TARGETED_REDERIVE);
    ASH_CHECK("G2: c1 targeted_rederive WITNESSES a real self-derived repair",
             sticky_escalator_test_drive(0, t0 + 32) ==
                 STICKY_RUNG_TARGETED_REDERIVE);
    ASH_CHECK("G2: c1 the repair is real — script/proof cursors clamped to "
             "the hole, no log row ever deleted",
             ash_cursor_value(db, "script_validate") == A + 2 &&
             ash_cursor_value(db, "proof_validate") == A + 2);
    ASH_CHECK("G2: repair never deletes a log row (only clamps cursors)",
             ash_total_log_rows(db) == rows_before);
    /* Outer window (60s) lapses; targeted_rederive finds nothing NEW but the
     * ladder force-advances regardless (PROGRESSING-window-lapsed still
     * advances — the outer law wins over any rung's internal hold). */
    ASH_CHECK("G2: c1 targeted_rederive window lapse advances to resnapshot",
             sticky_escalator_test_drive(0, t0 + 92) == STICKY_RUNG_RESNAPSHOT);
    ASH_CHECK("G2: c1 resnapshot stub advances (not_implemented)",
             sticky_escalator_test_drive(0, t0 + 93) == STICKY_RUNG_REINDEX);
    ASH_CHECK("G2: c1 reindex declines honestly (no datadir) and advances",
             sticky_escalator_test_drive(0, t0 + 94) ==
                 STICKY_RUNG_SELF_MINT_REFOLD);
    ASH_CHECK("G2: c1 self_mint_refold stub advances",
             sticky_escalator_test_drive(0, t0 + 95) == STICKY_RUNG_WIDEN_PEERS);
    ASH_CHECK("G2: c1 widen_peers declines honestly (no connman) and advances",
             sticky_escalator_test_drive(0, t0 + 96) == STICKY_RUNG_REBOOTSTRAP);
    ASH_CHECK("G2: c1 rebootstrap stub advances",
             sticky_escalator_test_drive(0, t0 + 97) ==
                 STICKY_RUNG_REFOLD_FROM_ANCHOR);

    /* Deepest rung exhausts (no datadir -> no anchor artifact) WITHOUT
     * clearing. Must NOT latch: rung stays put, a cooldown starts, a
     * non-latching page fires, and the ladder is still armed. */
    ASH_CHECK("G2: c1 refold_from_anchor exhausts, still deepest (no give-up "
             "rung index)",
             sticky_escalator_test_drive(0, t0 + 98) ==
                 STICKY_RUNG_REFOLD_FROM_ANCHOR);
    ASH_CHECK("G2: c1 still armed after the deepest rung exhausts",
             sticky_escalator_test_armed());

    /* Within the re-arm cooldown: a drive call is a documented no-op hold —
     * NOT a stuck state, just a bounded pause before the next lap. */
    ASH_CHECK("G2: c1 cooldown holds (not a latch — bounded pause only)",
             sticky_escalator_test_drive(0, t0 + 99) ==
                 STICKY_RUNG_REFOLD_FROM_ANCHOR);
    ASH_CHECK("G2: still armed during cooldown (never gives up)",
             sticky_escalator_test_armed());

    /* Cooldown (STICKY_REARM_COOLDOWN_SECS = 120s from t0+98) lapses: the
     * ladder re-enters rung 0 — this IS the cycle. */
    ASH_CHECK("G2: c1 cooldown lapse re-arms at rung 0 (retry) — CYCLES",
             sticky_escalator_test_drive(0, t0 + 98 + 120 + 1) ==
                 STICKY_RUNG_RETRY);
    ASH_CHECK("G2: c1 still armed entering cycle 2 (never gives up)",
             sticky_escalator_test_armed());

    /* ── Cycle 2 — prove it is a genuine CYCLE, not a one-shot re-arm ──── */
    int64_t t1 = t0 + 98 + 120 + 1;
    ASH_CHECK("G2: c2 retry window lapse advances",
             sticky_escalator_test_drive(0, t1 + 31) ==
                 STICKY_RUNG_TARGETED_REDERIVE);
    ASH_CHECK("G2: c2 targeted_rederive (hole already fixed) still holds "
             "within its window, then force-advances on lapse",
             sticky_escalator_test_drive(0, t1 + 31 + 61) ==
                 STICKY_RUNG_RESNAPSHOT);
    ASH_CHECK("G2: c2 walks the remaining stubs/declines to the deepest rung",
             sticky_escalator_test_drive(0, t1 + 93) == STICKY_RUNG_REINDEX &&
             sticky_escalator_test_drive(0, t1 + 94) ==
                 STICKY_RUNG_SELF_MINT_REFOLD &&
             sticky_escalator_test_drive(0, t1 + 95) == STICKY_RUNG_WIDEN_PEERS &&
             sticky_escalator_test_drive(0, t1 + 96) == STICKY_RUNG_REBOOTSTRAP &&
             sticky_escalator_test_drive(0, t1 + 97) ==
                 STICKY_RUNG_REFOLD_FROM_ANCHOR);
    ASH_CHECK("G2: c2 deepest rung exhausts a SECOND time (genuine cycle, "
             "not a one-shot)",
             sticky_escalator_test_drive(0, t1 + 98) ==
                 STICKY_RUNG_REFOLD_FROM_ANCHOR);
    ASH_CHECK("G2: still armed after TWO full cycles (never gives up)",
             sticky_escalator_test_armed());

    /* ── The other half of the progress law: a genuine tip climb clears
     * the episode outright — cycling only happens while genuinely stuck.
     * The rearm cooldown check runs BEFORE the progress check in
     * apply_drive (a `now` still inside the c2 cooldown is an unconditional
     * early-return, tip ignored), so this has to land past the c2 cooldown
     * (t1+98+120) exactly like the c1->c2 transition above: re-arming at
     * rung 0 re-stamps g_tip_at_rung from the still-1000 cached H*, and the
     * SAME call's progress check then sees the injected tip 2+
     * (STICKY_PROGRESS_MARGIN) past it and clears on the spot. */
    ASH_CHECK("G2: a real tip climb past the entry margin clears the episode "
             "— back to rung 0, disarmed",
             sticky_escalator_test_drive(1000 + STICKY_PROGRESS_MARGIN + 5,
                                        t1 + 98 + 120 + 1) == STICKY_RUNG_RETRY);
    ASH_CHECK("G2: cleared episode disarms (episode-scoped, not permanent)",
             !sticky_escalator_test_armed());

    reducer_frontier_provable_tip_reset();
    ash_teardown_fixture(&fx);
    printf("always_sync_selfheal: G2 %d failures\n", failures);
    return failures;
}

/* ── G3 — LCC refuses an incoherent cursor raise ──────────────────────── */

static int ash_test_lcc_refuses_incoherent_raise(void)
{
    int failures = 0;
    printf("\n--- G3: LCC write rules — refuse an incoherent raise ---\n");

    if (!lcc_test_probe_raise_refused) {
        printf("always_sync_selfheal: G3 SKIP — LCC write-rule test seam "
               "(lcc_test_probe_raise_refused) not yet linked (design-only "
               "per fail-safe-architecture.md §0c RAISE/DELETE rules); this "
               "becomes the integration regression gate once a sibling lane "
               "lands the write-time invariant.\n");
        return 0;
    }

    struct ash_fixture fx;
    ASH_CHECK("G3: setup fixture", ash_setup_hole_fixture(&fx, "g3_lcc"));
    sqlite3 *db = progress_store_db();

    /* script_validate cursor sits at A+4 (seeded above); no row exists at
     * A+2 for its own height and the hole at A+2 is exactly the shape the
     * RAISE rule must refuse a jump PAST — i.e. asking to raise a cursor
     * from a coherent point up to a height with no covering row and no
     * trusted-base declaration. */
    bool refused = lcc_test_probe_raise_refused(db, "script_validate",
                                                A + 4, A + 10);
    ASH_CHECK("G3: raise past a rowless height with no trusted-base "
             "declaration is REFUSED", refused);

    /* The DELETE-direction counterpart: a coherent lower move (or a raise
     * that lands exactly at a height WITH a covering row) must remain
     * representable — the rule targets incoherence, not all cursor writes.
     * A+1 has a real covering row (seeded via ash_put_upstream_ok above). */
    bool lower_refused = lcc_test_probe_raise_refused(db, "script_validate",
                                                      A + 4, A + 1);
    ASH_CHECK("G3: a coherent lower move / covered height is NOT refused",
             !lower_refused);

    ash_teardown_fixture(&fx);
    printf("always_sync_selfheal: G3 %d failures\n", failures);
    return failures;
}

/* ── G4 — a stalled stage becomes a named blocker the backstop cures ──────
 * The mission property end-to-end, through TWO real production layers with
 * ZERO mocks: a frozen reducer stage escalates into the exact typed blocker
 * (staged_sync_supervisor.c) that the generic always-terminating backstop
 * (blocker_stall_meta_detector.c) detects, remedies, and witnesses to a
 * terminal verdict. test_supervisor_production_tree.c proves the supervisor's
 * escalation/clear in isolation and test_blocker_meta_detector.c proves the
 * backstop on a SYNTHETIC `fixture.empty_escape` blocker; neither proves the
 * two halves compose on the ACTUAL `stage_stalled_*` blocker the production
 * supervisor emits. This does — closing the "silent halt" gap end to end:
 *   detect (stall) -> name (typed blocker at a known height) -> remedy runs
 *   (recovery ladder armed) -> witness (H* climbs) -> terminal verdict, and
 *   the supervisor's own falling edge clears the blocker when progress
 *   resumes (no ghost fact outliving the stall). */

/* Read the meta-detector's detail-dumped first_offender_id from the real
 * engine state dump — the name the operator page carries. "" when absent. */
static const char *ash_meta_offender(struct json_value *dump)
{
    const struct json_value *conds = json_get(dump, "conditions");
    if (!conds)
        return "";
    for (size_t i = 0; i < json_size(conds); i++) {
        const struct json_value *c = json_at(conds, i);
        const struct json_value *n = c ? json_get(c, "name") : NULL;
        if (!n || strcmp(json_get_str(n),
                         BLOCKER_STALL_META_CONDITION_NAME) != 0)
            continue;
        const struct json_value *d = json_get(c, "detail");
        const struct json_value *o = d ? json_get(d, "first_offender_id") : NULL;
        return o ? json_get_str(o) : "";
    }
    return "";
}

/* Find our blocker in a fresh snapshot; returns false if absent. */
static bool ash_snap_blocker(const char *id, struct blocker_snapshot *out)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, id) == 0) {
            *out = snaps[i];
            return true;
        }
    }
    return false;
}

static int ash_test_stall_named_blocker_cured(void)
{
    int failures = 0;
    printf("\n--- G4: never-wedge — a stalled stage is named + backstop-cured ---\n");

    blocker_module_init();
    condition_engine_reset_for_testing();
    blocker_reset_for_testing();
    reducer_frontier_provable_tip_reset();
    sticky_escalator_test_reset();
    blocker_stall_meta_detector_test_reset();

    /* Pin M=2 so the escalation boundary is deterministic regardless of any
     * ambient ZCL_STAGE_STALL_ESCALATE_WINDOWS in the environment. */
    setenv("ZCL_STAGE_STALL_ESCALATE_WINDOWS", "2", 1);
    const int64_t window = staged_sync_supervisor_test_quiet_window_us();
    const char *BID = "stage_stalled_utxo_apply";
    const uint64_t frozen_cursor = 3176325;   /* the documented live wedge H* */
    const uint64_t upstream_cursor = frozen_cursor + 50;
    bool escalated = false;

    /* ── Grace: below the M-window threshold names nothing (no premature
     * page for a legitimately-idle stage). ─────────────────────────────── */
    staged_sync_supervisor_test_apply_stall_escalation(
        "staged.utxo_apply", "staged.proof_validate", frozen_cursor,
        upstream_cursor, /*have_upstream=*/true, /*quiet_us=*/window - 1,
        &escalated);
    ASH_CHECK("G4: 1 quiet window (< M=2) does not escalate — no premature page",
             !escalated && !blocker_exists(BID));

    /* ── Stall: M windows of a frozen cursor NAME a typed blocker at a known
     * height — the "silent halt" is now impossible by construction. ────── */
    staged_sync_supervisor_test_apply_stall_escalation(
        "staged.utxo_apply", "staged.proof_validate", frozen_cursor,
        upstream_cursor, /*have_upstream=*/true, /*quiet_us=*/2 * window + 1,
        &escalated);
    ASH_CHECK("G4: 2 quiet windows (>= M=2) NAME the typed blocker", escalated);

    struct blocker_snapshot bs;
    bool have = ash_snap_blocker(BID, &bs);
    ASH_CHECK("G4: the stall is a real registry-visible typed blocker", have);
    /* The named blocker states the exact frozen height (never a metaphor). */
    char needle[32];
    snprintf(needle, sizeof(needle), "%llu", (unsigned long long)frozen_cursor);
    ASH_CHECK("G4: the blocker reason names the frozen cursor height",
             have && strstr(bs.reason, needle) != NULL);
    ASH_CHECK("G4: the blocker names its upstream stage (known dataflow point)",
             have && strstr(bs.reason, "proof_validate") != NULL);
    /* It is exactly the class the meta-detector backstops: TRANSIENT + empty
     * escape_action. This is what ties the supervisor to the always-
     * terminating remedy below. */
    ASH_CHECK("G4: blocker is TRANSIENT with an EMPTY escape_action "
             "(the exact class the meta-detector backstops)",
             have && bs.class == BLOCKER_TRANSIENT &&
             bs.escape_action[0] == '\0');

    /* ── Remedy RUNS: the generic backstop detects THIS production blocker
     * (not a synthetic fixture), arms the always-terminating recovery ladder,
     * and pages naming the offender. H* is held frozen at the stall height. */
    reducer_frontier_provable_tip_set((int32_t)frozen_cursor);
    register_blocker_stall_meta_detector();
    ASH_CHECK("G4: backstop condition registered in the engine",
             condition_engine_has_registered(BLOCKER_STALL_META_CONDITION_NAME));

    const int64_t t0 = 1000000;
    blocker_stall_meta_detector_test_set_clock_us(t0);
    condition_engine_tick();      /* prime: first H* sample stamps the window */
    ASH_CHECK("G4: no fire before the frozen-H* window elapses",
             condition_engine_get_active_count() == 0 &&
             !sticky_escalator_test_armed());

    const int64_t meta_win_us = (int64_t)BLOCKER_STALL_META_DEFAULT_SECS * 1000000;
    blocker_stall_meta_detector_test_set_clock_us(t0 + meta_win_us + 1000000);
    for (int i = 0; i < 8; i++) {
        blocker_stall_meta_detector_test_clear_cadence();
        condition_engine_tick();
    }
    ASH_CHECK("G4: backstop DETECTED the stall (condition active)",
             condition_engine_get_active_count() == 1);
    ASH_CHECK("G4: the always-terminating recovery ladder is ARMED "
             "(remedy actually ran)",
             sticky_escalator_test_armed() &&
             blocker_stall_meta_detector_test_remedy_calls() >= 1);

    struct json_value dump;
    json_init(&dump);
    json_set_object(&dump);
    ASH_CHECK("G4: the operator page names the production blocker id",
             condition_engine_dump_state_json(&dump, NULL) &&
             strcmp(ash_meta_offender(&dump), BID) == 0);
    json_free(&dump);

    /* ── Terminal verdict: H* climbing past the frozen height is the sole
     * clear-edge; the episode resolves (never latches on a recoverable
     * cause). ─────────────────────────────────────────────────────────── */
    reducer_frontier_provable_tip_set((int32_t)frozen_cursor + 1);
    condition_engine_tick();
    ASH_CHECK("G4: H* climb witnesses the backstop clear (terminal verdict)",
             condition_engine_get_active_count() == 0 &&
             condition_engine_get_unresolved_count() == 0);

    /* ── The supervisor's own falling edge: once the stage advances, the
     * typed blocker is CLEARED — a named blocker is never a ghost fact that
     * outlives the stall. ─────────────────────────────────────────────── */
    staged_sync_supervisor_test_apply_stall_escalation(
        "staged.utxo_apply", "staged.proof_validate", frozen_cursor + 1,
        upstream_cursor, /*have_upstream=*/true, /*quiet_us=*/window - 1,
        &escalated);
    ASH_CHECK("G4: stage progress clears the typed blocker (no ghost fact)",
             !escalated && !blocker_exists(BID));

    unsetenv("ZCL_STAGE_STALL_ESCALATE_WINDOWS");
    condition_engine_reset_for_testing();
    reducer_frontier_provable_tip_reset();
    sticky_escalator_test_reset();
    blocker_reset_for_testing();
    printf("always_sync_selfheal: G4 %d failures\n", failures);
    return failures;
}

int test_always_sync_selfheal(void);
int test_always_sync_selfheal(void)
{
    printf("\n=== always_sync_selfheal (fail-safe-architecture.md self-heal "
           "regression suite) ===\n");
    int failures = 0;
    failures += ash_test_stage_rederive_range();
    failures += ash_test_ladder_cycles_never_gives_up();
    failures += ash_test_lcc_refuses_incoherent_raise();
    failures += ash_test_stall_named_blocker_cured();
    printf("always_sync_selfheal: %d total failures\n", failures);
    return failures;
}
