/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_utxo_parity_service — drives the standing UTXO parity service through
 * its FIXTURE reference (no live oracle, no sockets). The teeth are a paired
 * negative/positive control:
 *   CASE 1  same-height MATCH    → no operator page (subset-complete sentinel)
 *   CASE 2  same-height MISMATCH → persists drift, Condition pages
 *   CASE 3  COARSE reference     → never pages, clears any stale drift flag
 *   CASE 4  height skew          → never pages (LOCAL_ONLY)
 *   CASE 5  disabled tick        → no-op
 *   CASE 6  enabled tick         → waits while reorg-unsafe, then checks at the
 *                                  true applied height (exercises the live
 *                                  supervised path, not just the comparator)
 *
 * The same-height discipline (CASE 1 vs CASE 2 at one height) is the
 * subset-complete sentinel: a MATCH that pages, or a MISMATCH that does not,
 * fails the negative control.
 */

#include "test/test_core.h"

#include "services/utxo_parity_service.h"
#include "services/utxo_reference_source.h"
#include "services/utxo_audit_service.h"
#include "conditions/utxo_drift_detected.h"
#include "coins/utxo_commitment.h"
#include "config/runtime.h"
#include "models/database.h"
#include "event/event.h"
#include "framework/condition.h"
#include "json/json.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "test/setup_result.h"

/* The fixture reference is height-independent, so the parity tick path
 * (which reads the live applied height) is exercised via the synchronous
 * utxo_parity_check_height(); the height we pass is the same-height label. */
#define PARITY_TEST_HEIGHT 3078015

static _Atomic int g_op_events;

static void op_obs(enum event_type type, uint32_t peer_id,
                   const void *payload, uint32_t payload_len, void *ctx)
{
    (void)type; (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    atomic_fetch_add(&g_op_events, 1);
}

static bool insert_test_utxo(struct node_db *ndb, uint8_t tag)
{
    sqlite3_stmt *s = NULL;
    const char *sql =
        "INSERT INTO utxos (txid,vout,value,script,script_type,"
        "address_hash,height,is_coinbase) VALUES (?,?,?,?,?,?,?,?)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK)
        return false;

    uint8_t txid[32] = {0};
    uint8_t script[3] = {0x51, tag, 0xac};
    uint8_t addr[20] = {0};
    txid[0] = tag;
    addr[0] = tag;

    bool ok = sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(s, 2, 0) == SQLITE_OK &&
              sqlite3_bind_int64(s, 3, 1000 + tag) == SQLITE_OK &&
              sqlite3_bind_blob(s, 4, script, sizeof(script), SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(s, 5, 1) == SQLITE_OK &&
              sqlite3_bind_blob(s, 6, addr, sizeof(addr), SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(s, 7, 100 + tag) == SQLITE_OK &&
              sqlite3_bind_int(s, 8, 0) == SQLITE_OK &&
              sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

static void hash_to_hex(const uint8_t hash[32], char out[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", hash[i]);
}

/* Open a temp node.db with one UTXO and return its local commitment hex. */
static bool open_ndb_with_local(struct node_db *ndb, char *path_io,
                                char local_hex[65])
{
    int fd = mkstemp(path_io);
    if (fd < 0)
        return false;
    close(fd);
    if (!node_db_open(ndb, path_io))
        return false;
    if (!insert_test_utxo(ndb, 0x24))
        return false;
    uint8_t local_hash[32];
    uint64_t count = 0;
    utxo_commitment_sha3_compute(ndb->db, local_hash, &count);
    hash_to_hex(local_hash, local_hex);
    return true;
}

static void cleanup_case(struct node_db *ndb, const char *path)
{
    event_clear_observers(EV_OPERATOR_NEEDED);
    condition_engine_reset_for_testing();
    utxo_drift_detected_test_reset();
    utxo_parity_reset_for_test();
    node_db_close(ndb);
    unlink(path);
    atomic_store(&g_op_events, 0);
}

/* Shared per-case wiring: parity service + reference + drift Condition. */
static void wire_case(struct node_db *ndb,
                      const struct utxo_reference_source *src)
{
    struct utxo_parity_config cfg = {
        .enabled = true, .finality_depth = 0, .max_checks_per_tick = 1,
    };
    utxo_parity_reset_for_test();
    ZCL_TEST_SETUP(utxo_parity_init(&cfg, ndb));
    utxo_parity_set_reference_source(src);

    condition_engine_reset_for_testing();
    utxo_drift_detected_test_reset();
    utxo_drift_detected_test_set_node_db(ndb);
    register_utxo_drift_detected();

    atomic_store(&g_op_events, 0);
    event_observe(EV_OPERATOR_NEEDED, op_obs, NULL);
}

/* Wiring for block-hash-only tests: arms the service (enabled) + Condition
 * but wires NO SHA3 reference so only parity_coarse_block_hash_tick runs.
 * The tick's "!ref && !rpc_has_creds → quiet dormant" guard keeps the
 * service a no-op until wire_bh_seams() injects the RPC mock. */
static void wire_bh_only_case(struct node_db *ndb)
{
    struct utxo_parity_config cfg = {
        .enabled = true, .finality_depth = 0, .max_checks_per_tick = 1,
    };
    utxo_parity_reset_for_test();
    ZCL_TEST_SETUP(utxo_parity_init(&cfg, ndb));
    utxo_parity_set_reference_source(NULL);  /* no SHA3 ref — BH path only */

    condition_engine_reset_for_testing();
    utxo_drift_detected_test_reset();
    utxo_drift_detected_test_set_node_db(ndb);
    register_utxo_drift_detected();

    atomic_store(&g_op_events, 0);
    event_observe(EV_OPERATOR_NEEDED, op_obs, NULL);
}

static int case_match_no_page(void)
{
    int failures = 0;
    TEST("utxo_parity: same-height MATCH does not page (negative control)") {
        char path[] = "/tmp/zcl23-parity-match-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "unit-fixture",
                                           local_hex, PARITY_TEST_HEIGHT, true);
        wire_case(&ndb, &src);

        /* Exercise the observer/marker path as well. */
        event_emitf(EV_CHAIN_TIP_COMMIT, 0, "from=%d to=%d reason=test",
                    PARITY_TEST_HEIGHT - 1, PARITY_TEST_HEIGHT);

        struct utxo_audit_result res;
        ASSERT(utxo_parity_check_height(PARITY_TEST_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_MATCH);

        int64_t drift = -1;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 0);

        condition_engine_tick();
        ASSERT(atomic_load(&g_op_events) == 0);
        ASSERT(condition_engine_get_active_count() == 0);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

static int case_mismatch_pages(void)
{
    int failures = 0;
    TEST("utxo_parity: same-height MISMATCH persists drift and pages") {
        char path[] = "/tmp/zcl23-parity-drift-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        /* Nibble-flip the local hash → a same-height byte mismatch. */
        char remote_hex[65];
        memcpy(remote_hex, local_hex, 65);
        remote_hex[0] = remote_hex[0] == '0' ? '1' : '0';

        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "unit-fixture",
                                           remote_hex, PARITY_TEST_HEIGHT, true);
        wire_case(&ndb, &src);

        struct utxo_audit_result res;
        ASSERT(utxo_parity_check_height(PARITY_TEST_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_DRIFT);

        int64_t drift = 0;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 1);

        /* Condition picks up the persisted flag and pages on the first tick
         * (max_attempts=1, remedy FAILED). */
        condition_engine_tick();
        ASSERT(atomic_load(&g_op_events) >= 1);
        ASSERT(condition_engine_get_unresolved_count() == 1);

        /* Full loop: clear the flag → the witness clears the Condition. */
        ASSERT(node_db_state_set_int(&ndb, "utxo_drift_detected", 0));
        condition_engine_tick();
        ASSERT(condition_engine_get_active_count() == 0);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

static int case_coarse_never_pages(void)
{
    int failures = 0;
    TEST("utxo_parity: coarse reference never pages and clears stale drift") {
        char path[] = "/tmp/zcl23-parity-coarse-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        /* Pre-seed a stale drift flag from a prior exact divergence. The
         * coarse check must CLEAR it (a height confirmation cannot prove
         * bytes, but it must not let an old drift keep paging). */
        ASSERT(node_db_state_set_int(&ndb, "utxo_drift_detected", 1));

        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "coarse-fixture",
                                           "", PARITY_TEST_HEIGHT, false);
        wire_case(&ndb, &src);

        struct utxo_audit_result res;
        ASSERT(utxo_parity_check_height(PARITY_TEST_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_MATCH); /* heights agree, height-only */
        ASSERT(res.drift_detected == false);

        int64_t drift = -1;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 0); /* coarse explicitly cleared the stale flag */

        condition_engine_tick();
        ASSERT(atomic_load(&g_op_events) == 0);
        ASSERT(condition_engine_get_active_count() == 0);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

static int case_height_skew_no_page(void)
{
    int failures = 0;
    TEST("utxo_parity: exact reference at a different height never DRIFTs") {
        char path[] = "/tmp/zcl23-parity-skew-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        /* An exact reference whose hash differs AND whose height differs from
         * the local applied height: the same-height guard must record this as
         * LOCAL_ONLY (height skew), never a byte DRIFT — the structural
         * false-DRIFT defense. */
        char remote_hex[65];
        memcpy(remote_hex, local_hex, 65);
        remote_hex[0] = remote_hex[0] == '0' ? '1' : '0';

        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "skew-fixture",
                                           remote_hex,
                                           PARITY_TEST_HEIGHT - 50, true);
        wire_case(&ndb, &src);

        struct utxo_audit_result res;
        ASSERT(utxo_parity_check_height(PARITY_TEST_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_LOCAL_ONLY);
        ASSERT(res.drift_detected == false);

        int64_t drift = -1;
        /* utxo_audit_local persists 'utxo_drift_detected' only on the
         * compare_remote path, so the skew branch leaves it untouched —
         * verify it is not raised. */
        if (node_db_state_get_int(&ndb, "utxo_drift_detected", &drift))
            ASSERT(drift == 0);

        condition_engine_tick();
        ASSERT(atomic_load(&g_op_events) == 0);
        ASSERT(condition_engine_get_active_count() == 0);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

static int case_dormant(void)
{
    int failures = 0;
    TEST("utxo_parity: tick is a no-op when disabled or without a frontier") {
        char path[] = "/tmp/zcl23-parity-dormant-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        /* Disabled config + no reference: the supervised tick must do nothing
         * (no checks, no page), even if a frontier marker exists. */
        struct utxo_parity_config cfg = {
            .enabled = false, .finality_depth = 100, .max_checks_per_tick = 1,
        };
        utxo_parity_reset_for_test();
        ZCL_TEST_SETUP(utxo_parity_init(&cfg, &ndb));
        utxo_parity_set_frontier_for_test(PARITY_TEST_HEIGHT);

        atomic_store(&g_op_events, 0);
        event_observe(EV_OPERATOR_NEEDED, op_obs, NULL);

        utxo_parity_tick_once();
        ASSERT(atomic_load(&g_op_events) == 0);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

/* Read one int field out of the parity service's native dumpstate output.
 * Returns -1 if absent. */
static int64_t parity_dump_int(const char *field)
{
    struct json_value dump;
    json_init(&dump);
    if (!utxo_parity_dump_state_json(&dump, NULL)) {
        json_free(&dump);
        return -1;
    }
    const struct json_value *v = json_get(&dump, field);
    int64_t out = v ? json_get_int(v) : -1;
    json_free(&dump);
    return out;
}

/* Read one bool field out of the parity service state dump. */
static bool parity_dump_bool(const char *field)
{
    struct json_value dump;
    json_init(&dump);
    if (!utxo_parity_dump_state_json(&dump, NULL)) {
        json_free(&dump);
        return false;
    }
    const struct json_value *v = json_get(&dump, field);
    bool out = v ? json_get_bool(v) : false;
    json_free(&dump);
    return out;
}

/* Activation gating — the C8 default ("ON when an oracle is wired, quietly
 * dormant otherwise") must hold without any env var requirement. Two controls:
 *   NO ORACLE  : enabled but NO reference wired → active=false, tick a no-op
 *                (no check recorded, no page) even with a frontier present.
 *   WITH ORACLE: enabled + reference wired → active=true, tick runs a check at
 *                the reorg-safe applied height (checks_total advances). */
static int case_activation_gating_no_env(void)
{
    int failures = 0;
    TEST("utxo_parity: activates on a wired oracle without any env var") {
        char path[] = "/tmp/zcl23-parity-activate-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        int32_t applied = (int32_t)app_runtime_node_db_utxo_max_height(&ndb);
        ASSERT(applied > 0);

        /* (1) NO ORACLE: enabled, but no reference wired. The activation
         * predicate (`active`) is false and the tick must do nothing — quiet
         * dormancy — even though a frontier is present and reorg-safe. */
        struct utxo_parity_config cfg = {
            .enabled = true, .finality_depth = 100, .max_checks_per_tick = 1,
        };
        utxo_parity_reset_for_test();
        ZCL_TEST_SETUP(utxo_parity_init(&cfg, &ndb));
        utxo_parity_set_reference_source(NULL);   /* no oracle */
        utxo_parity_set_frontier_for_test(applied + 200);

        ASSERT(parity_dump_bool("enabled") == true);
        ASSERT(parity_dump_bool("active") == false);  /* no reference → inert */

        atomic_store(&g_op_events, 0);
        event_observe(EV_OPERATOR_NEEDED, op_obs, NULL);
        utxo_parity_tick_once();
        ASSERT(parity_dump_int("checks_total") == 0);  /* no check ran */
        ASSERT(atomic_load(&g_op_events) == 0);

        /* (2) WITH ORACLE: wire an exact fixture reference at the applied
         * height. Now active=true and the tick runs a real same-height check
         * (checks_total advances). */
        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "activate-fixture",
                                           local_hex, applied, true);
        utxo_parity_set_reference_source(&src);

        ASSERT(parity_dump_bool("active") == true);    /* enabled + reference */
        utxo_parity_tick_once();
        ASSERT(parity_dump_int("checks_total") >= 1);  /* the tick ran a check */
        ASSERT(parity_dump_int("matches") == 1);       /* and it MATCHED */
        ASSERT(parity_dump_int("mismatches") == 0);
        ASSERT(atomic_load(&g_op_events) == 0);        /* a match never pages */

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

/* Exercise the live supervised tick (not just the synchronous comparator):
 * it must WAIT while the live applied height is still reorg-unsafe, then run a
 * same-height check at the TRUE applied height once it is reorg-safe. This is
 * the regression guard for the same-height label fix — the tick must never
 * compare the live set against a reference at a relabeled stable_ceiling. */
static int case_enabled_tick_checks_at_applied(void)
{
    int failures = 0;
    TEST("utxo_parity: enabled tick waits while reorg-unsafe, checks at applied") {
        char path[] = "/tmp/zcl23-parity-tick-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        /* The single test UTXO sets the live applied height. */
        int32_t applied = (int32_t)app_runtime_node_db_utxo_max_height(&ndb);
        ASSERT(applied > 0);

        /* Exact fixture AT the applied height with the matching local hash. */
        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "tick-fixture",
                                           local_hex, applied, true);
        wire_case(&ndb, &src);  /* finality_depth defaults to 100 */

        /* Reorg-UNSAFE: applied sits ABOVE frontier - finality_depth, so there
         * is no reorg-safe height the live set reflects → the tick must not
         * run any check (no audit state written). */
        utxo_parity_set_frontier_for_test(applied + 50);  /* ceiling = applied-50 */
        utxo_parity_tick_once();
        int64_t h = -1;
        ASSERT(!node_db_state_get_int(&ndb, "utxo_audit_last_height", &h));

        /* Reorg-SAFE: frontier far enough ahead that applied <= ceiling → the
         * tick checks at exactly the applied height (MATCH, no page). */
        utxo_parity_set_frontier_for_test(applied + 200); /* ceiling = applied+100 */
        utxo_parity_tick_once();

        ASSERT(node_db_state_get_int(&ndb, "utxo_audit_last_height", &h));
        ASSERT(h == applied);  /* checked at the TRUE applied height, not a clamp */
        int64_t drift = -1;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 0);

        condition_engine_tick();
        ASSERT(atomic_load(&g_op_events) == 0);
        ASSERT(condition_engine_get_active_count() == 0);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Block-hash parity unit tests ─────────────────────────────────
 *
 * These tests exercise parity_coarse_block_hash_tick() through the full
 * utxo_parity_tick_once() call path using injected test seams so no live
 * block index or open sockets are needed.
 *
 * Shared mock state for the test seams. */

struct bh_mock {
    char  local_hex[65];   /* returned by the local hash seam */
    bool  local_ok;        /* false → local hash unavailable */
    char  ref_hex[65];     /* returned by the ref hash seam */
    bool  ref_ok;          /* false → transport failure */
    /* ref_height_offset: added to the requested height for ref_height_out.
     * 0 = echo back exactly the height that was requested (the normal case);
     * negative = simulate "height behind h_check" (the skip case). */
    int32_t ref_height_offset;
};

static bool mock_local_hash(void *ctx, int32_t height, char out_hex[65])
{
    (void)height;
    struct bh_mock *m = ctx;
    if (!m->local_ok) { out_hex[0] = '\0'; return false; }
    memcpy(out_hex, m->local_hex, 65);
    return true;
}

static bool mock_ref_hash(void *ctx, int32_t height, char out_hex[65],
                          int32_t *ref_height_out, char err[128])
{
    struct bh_mock *m = ctx;
    if (!m->ref_ok) {
        snprintf(err, 128, "mock transport failure");
        return false;
    }
    memcpy(out_hex, m->ref_hex, 65);
    /* Echo back (height + offset): offset=0 means "I have exactly this height",
     * offset=-1 simulates the reference being one block behind h_check. */
    *ref_height_out = height + m->ref_height_offset;
    return true;
}

/* Wire the block-hash seams into the service (called after wire_case). */
static void wire_bh_seams(struct bh_mock *m)
{
    utxo_parity_set_local_hash_fn(mock_local_hash, m);
    utxo_parity_set_ref_hash_fn(mock_ref_hash, m);
}

/* CASE BH-1: block-hash MATCH → checks_total++ and no page. */
static int case_bh_match_counts(void)
{
    int failures = 0;
    TEST("utxo_parity: block-hash MATCH increments checks_total, no page") {
        char path[] = "/tmp/zcl23-parity-bh-match-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        /* No SHA3 reference: the UTXO SHA3 path is dormant; only the
         * block-hash check fires (once wire_bh_seams injects the RPC mock). */
        wire_bh_only_case(&ndb);

        /* h_check = min(applied, frontier) - finality_depth.
         * finality_depth defaults to 100 (PARITY_DEFAULT_FINALITY_DEPTH).
         * frontier = applied + 200 → safe_top = applied → h_check = applied-100.
         * The mock echoes back exactly the requested height (offset=0). */
        int32_t applied = (int32_t)app_runtime_node_db_utxo_max_height(&ndb);
        ASSERT(applied > 0);
        ASSERT(applied > 100);  /* h_check must be >0 */
        utxo_parity_set_frontier_for_test(applied + 200);

        int32_t expected_h_check = applied - 100;

        char fake_hash[65] =
            "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
        struct bh_mock m = {
            .local_ok = true,  .ref_ok = true,
            .ref_height_offset = 0,  /* echo back h_check exactly */
        };
        memcpy(m.local_hex, fake_hash, 65);
        memcpy(m.ref_hex,   fake_hash, 65);
        wire_bh_seams(&m);

        utxo_parity_tick_once();

        ASSERT(parity_dump_int("block_hash_checks") == 1);
        ASSERT(parity_dump_int("checks_total") >= 1);
        ASSERT(parity_dump_int("matches") >= 1);
        ASSERT(parity_dump_int("mismatches") == 0);
        ASSERT(parity_dump_int("skips_total") == 0);
        ASSERT(parity_dump_int("last_bh_checked_height") == expected_h_check);
        ASSERT(atomic_load(&g_op_events) == 0);  /* match never pages */

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

/* CASE BH-2: block-hash MISMATCH → drift flag set, Condition pages. */
static int case_bh_mismatch_pages(void)
{
    int failures = 0;
    TEST("utxo_parity: block-hash MISMATCH sets drift flag and pages") {
        char path[] = "/tmp/zcl23-parity-bh-mismatch-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        /* No SHA3 reference so only the block-hash check runs; the coarse
         * SHA3 path cannot interfere with the drift flag we're testing. */
        wire_bh_only_case(&ndb);

        int32_t applied = (int32_t)app_runtime_node_db_utxo_max_height(&ndb);
        ASSERT(applied > 0);
        ASSERT(applied > 100);
        utxo_parity_set_frontier_for_test(applied + 200);

        char local_hash[65] =
            "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
        char ref_hash[65] =
            "11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd";
        struct bh_mock m = {
            .local_ok = true, .ref_ok = true,
            .ref_height_offset = 0,  /* echo back h_check exactly */
        };
        memcpy(m.local_hex, local_hash, 65);
        memcpy(m.ref_hex,   ref_hash,   65);
        wire_bh_seams(&m);

        utxo_parity_tick_once();

        ASSERT(parity_dump_int("mismatches") >= 1);
        ASSERT(parity_dump_int("matches") == 0);

        /* The BH path latches its OWN key — never the SHA3 path's
         * utxo_drift_detected, whose confirmations would clear it. */
        int64_t bh_drift = 0;
        ASSERT(node_db_state_get_int(&ndb, "parity_bh_drift_detected",
                                     &bh_drift));
        ASSERT(bh_drift == 1);
        int64_t bh_height = 0;
        ASSERT(node_db_state_get_int(&ndb, "parity_bh_drift_height",
                                     &bh_height));
        ASSERT(bh_height == applied - 100);

        /* Condition picks it up and pages. */
        condition_engine_tick();
        ASSERT(atomic_load(&g_op_events) >= 1);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

/* CASE BH-3: reference unreachable → skip, no page. */
static int case_bh_ref_unreachable_skip(void)
{
    int failures = 0;
    TEST("utxo_parity: block-hash reference unreachable → skip, no page") {
        char path[] = "/tmp/zcl23-parity-bh-unreach-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        wire_bh_only_case(&ndb);

        int32_t applied = (int32_t)app_runtime_node_db_utxo_max_height(&ndb);
        ASSERT(applied > 0);
        utxo_parity_set_frontier_for_test(applied + 200);

        /* ref_ok=false → the ref seam simulates transport failure. */
        struct bh_mock m = {
            .local_ok = true, .ref_ok = false,
            .ref_height_offset = 0,
        };
        memcpy(m.local_hex,
               "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
               65);
        wire_bh_seams(&m);

        utxo_parity_tick_once();

        ASSERT(parity_dump_int("skips_total") >= 1);
        ASSERT(parity_dump_int("block_hash_checks") == 0);  /* no comparison */
        ASSERT(parity_dump_int("mismatches") == 0);
        ASSERT(atomic_load(&g_op_events) == 0);  /* NEVER page on unreachability */

        /* drift_detected must NOT have been set. */
        int64_t drift = -1;
        if (node_db_state_get_int(&ndb, "utxo_drift_detected", &drift))
            ASSERT(drift == 0);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

/* CASE BH-4: reference height behind h_check → skip, no page. */
static int case_bh_ref_height_behind_skip(void)
{
    int failures = 0;
    TEST("utxo_parity: block-hash ref height < h_check → skip, no page") {
        char path[] = "/tmp/zcl23-parity-bh-behind-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        wire_bh_only_case(&ndb);

        int32_t applied = (int32_t)app_runtime_node_db_utxo_max_height(&ndb);
        ASSERT(applied > 0);
        ASSERT(applied > 100);
        utxo_parity_set_frontier_for_test(applied + 200);
        /* h_check = applied - 100 (PARITY_DEFAULT_FINALITY_DEPTH) */

        /* ref_height_offset = -1 → the seam reports height-1 back, which is one
         * below the requested h_check → triggers the "height behind" skip path. */
        struct bh_mock m = {
            .local_ok = true, .ref_ok = true,
            .ref_height_offset = -1,  /* one below h_check */
        };
        memcpy(m.local_hex,
               "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
               65);
        memcpy(m.ref_hex,
               "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
               65);
        wire_bh_seams(&m);

        utxo_parity_tick_once();

        ASSERT(parity_dump_int("skips_total") >= 1);
        ASSERT(parity_dump_int("block_hash_checks") == 0);
        ASSERT(parity_dump_int("mismatches") == 0);
        ASSERT(atomic_load(&g_op_events) == 0);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

/* CASE BH-5: same height not re-checked (advance-only cursor). */
static int case_bh_no_recheck_same_height(void)
{
    int failures = 0;
    TEST("utxo_parity: block-hash same height is not re-checked each tick") {
        char path[] = "/tmp/zcl23-parity-bh-advance-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        wire_bh_only_case(&ndb);

        int32_t applied = (int32_t)app_runtime_node_db_utxo_max_height(&ndb);
        ASSERT(applied > 0);
        ASSERT(applied > 100);
        utxo_parity_set_frontier_for_test(applied + 200);

        char hash[65] =
            "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
        struct bh_mock m = {
            .local_ok = true, .ref_ok = true,
            .ref_height_offset = 0,  /* echo back h_check exactly */
        };
        memcpy(m.local_hex, hash, 65);
        memcpy(m.ref_hex,   hash, 65);
        wire_bh_seams(&m);

        /* First tick: comparison runs. */
        utxo_parity_tick_once();
        int64_t checks_after_first = parity_dump_int("block_hash_checks");
        ASSERT(checks_after_first == 1);

        /* Second tick at the SAME frontier/applied: same h_check → no
         * re-check (advance-only cursor guards it). */
        utxo_parity_tick_once();
        ASSERT(parity_dump_int("block_hash_checks") == 1); /* still 1 */

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

/* CASE BH-6 (the wave-3 review finding, PRODUCTION config): both the coarse
 * SHA3 reference AND the block-hash check are armed — exactly how boot wires
 * a co-located zclassicd. A BH MISMATCH must page even though the SHA3 path
 * confirms parity at its own height in the SAME tick and writes
 * utxo_drift_detected=0. Before the latch fix, that write erased the BH
 * detection and the advance-only cursor guaranteed the divergent height was
 * never re-examined — a permanently lost page. */
static int case_bh_latch_survives_sha3_confirm(void)
{
    int failures = 0;
    TEST("utxo_parity: BH mismatch latch survives same-tick SHA3 confirm") {
        char path[] = "/tmp/zcl23-parity-bh-latch-XXXXXX";
        struct node_db ndb;
        char local_hex[65];
        ASSERT(open_ndb_with_local(&ndb, path, local_hex));

        int32_t applied = (int32_t)app_runtime_node_db_utxo_max_height(&ndb);
        ASSERT(applied > 100);  /* h_check = applied-100 must be > 0 */

        /* Exact SHA3 fixture AT the applied height with the MATCHING local
         * hash: the SHA3 path will confirm parity and write
         * utxo_drift_detected=0 — the interfering write. */
        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "tick-fixture",
                                           local_hex, applied, true);
        wire_case(&ndb, &src);  /* finality_depth defaults to 100 */

        /* BH mock with a MISMATCH at h_check = applied-100. */
        char local_hash[65] =
            "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
        char ref_hash[65] =
            "11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd";
        struct bh_mock m = {
            .local_ok = true, .ref_ok = true,
            .ref_height_offset = 0,
        };
        memcpy(m.local_hex, local_hash, 65);
        memcpy(m.ref_hex,   ref_hash,   65);
        wire_bh_seams(&m);

        /* Frontier high enough that BOTH checks run in one tick:
         * BH at applied-100, SHA3 at applied (<= ceiling = applied+100). */
        utxo_parity_set_frontier_for_test(applied + 200);
        utxo_parity_tick_once();

        /* The SHA3 confirmation DID run and DID write its key to 0 ... */
        int64_t drift = -1;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 0);
        int64_t h = -1;
        ASSERT(node_db_state_get_int(&ndb, "utxo_audit_last_height", &h));
        ASSERT(h == applied);

        /* ... and the BH latch SURVIVED it. */
        int64_t bh_drift = 0;
        ASSERT(node_db_state_get_int(&ndb, "parity_bh_drift_detected",
                                     &bh_drift));
        ASSERT(bh_drift == 1);
        int64_t bh_height = 0;
        ASSERT(node_db_state_get_int(&ndb, "parity_bh_drift_height",
                                     &bh_height));
        ASSERT(bh_height == applied - 100);

        /* The Condition pages off the latch. */
        condition_engine_tick();
        ASSERT(atomic_load(&g_op_events) >= 1);
        ASSERT(condition_engine_get_unresolved_count() == 1);

        /* A later tick (advance-only: no re-check, SHA3 already current)
         * must not clear the latch either. */
        utxo_parity_tick_once();
        bh_drift = 0;
        ASSERT(node_db_state_get_int(&ndb, "parity_bh_drift_detected",
                                     &bh_drift));
        ASSERT(bh_drift == 1);

        cleanup_case(&ndb, path);
        PASS();
    } _test_next:;
    return failures;
}

int test_utxo_parity_service(void)
{
    int failures = 0;
    /* Enable synchronous event dispatch (and start from a clean observer
     * table) so the EV_OPERATOR_NEEDED page reaches our observer even under
     * ZCL_TEST_ONLY, which skips the full-harness event_log_init. */
    event_log_init();
    failures += case_match_no_page();
    failures += case_mismatch_pages();
    failures += case_coarse_never_pages();
    failures += case_height_skew_no_page();
    failures += case_dormant();
    failures += case_activation_gating_no_env();
    failures += case_enabled_tick_checks_at_applied();
    /* Block-hash parity cases (task #36 — at-tip coarse check). */
    failures += case_bh_match_counts();
    failures += case_bh_mismatch_pages();
    failures += case_bh_ref_unreachable_skip();
    failures += case_bh_ref_height_behind_skip();
    failures += case_bh_no_recheck_same_height();
    failures += case_bh_latch_survives_sha3_confirm();
    return failures + ZCL_TEST_SETUP_FAILURES();
}
