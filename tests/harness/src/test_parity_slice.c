/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_parity_slice: hermetic slice gate for MVP C8 (consensus parity).
 *
 * The full claim (0 UTXO mismatches vs the zclassicd oracle over RPC 8232)
 * needs a live oracle. This slice protects the parity service's
 * mismatch-detection machinery using the in-process FIXTURE reference (no
 * sockets, no oracle, no params): a paired control over the service's own
 * `mismatches` stat (via utxo_parity_dump_state_json), driven by real UTXO
 * sets through the live SHA3 commitment.
 *
 *   (A) CONSISTENT  reducer-vs-fixture set at one height: MATCH, mismatches==0.
 *   (B) INJECTED    an extra outpoint makes the local SHA3 diverge: status
 *                   DRIFT, drift flag persisted, mismatches>0.
 *
 * (A)/(B) exercise the EXACT branch. The production oracle is exact=false, so
 * the live claim runs the COARSE branch (utxo_audit_service.c:158-173):
 *
 *   (C1) COARSE same-height  -> MATCH, empty remote SHA3, bucketed in
 *                               coarse_checks, no drift.
 *   (C2) COARSE height-skew  -> LOCAL_ONLY, never a DRIFT, never counted.
 *   (C3) COARSE confirmation -> clears a prior exact DRIFT flag.
 *
 * Process-global singletons are driven, so the body is opt-in behind
 * ZCL_STRESS_TESTS and runs via `make mvp-parity-slice`
 * (ZCL_TEST_ONLY=parity_slice). */

#include "test/test_core.h"

#include "services/utxo_parity_service.h"
#include "services/utxo_reference_source.h"
#include "services/utxo_audit_service.h"
#include "coins/utxo_commitment.h"
#include "models/database.h"
#include "json/json.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "test/setup_result.h"

/* Height label the fixture is pinned at; the comparator only declares a byte
 * DRIFT when the (exact) reference height equals the local applied height, so
 * we use the same value on both sides. */
#define PARITY_SLICE_HEIGHT 3078015

/* Insert one deterministic UTXO keyed by `tag` (distinct txid/value/addr). */
static bool slice_insert_utxo(struct node_db *ndb, uint8_t tag)
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

static void slice_hash_to_hex(const uint8_t hash[32], char out[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", hash[i]);
}

/* Snapshot the local SHA3 UTXO commitment over the live utxos table. */
static void slice_local_commitment(struct node_db *ndb, char hex_out[65])
{
    uint8_t hash[32];
    uint64_t count = 0;
    utxo_commitment_sha3_compute(ndb->db, hash, &count);
    slice_hash_to_hex(hash, hex_out);
}

/* Read one int field out of the parity service's state dump (the same surface
 * dumpstate exposes), so the gate asserts the SERVICE counter, not just the
 * one-shot comparator return. Returns -1 if absent. */
static int64_t slice_parity_stat(const char *field)
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

/* Wire the parity service (enabled, exact fixture) against `ndb`/`src`. */
static void slice_wire(struct node_db *ndb,
                       const struct utxo_reference_source *src)
{
    struct utxo_parity_config cfg = {
        .enabled = true, .finality_depth = 0, .max_checks_per_tick = 1,
    };
    utxo_parity_reset_for_test();
    ZCL_TEST_SETUP(utxo_parity_init(&cfg, ndb));
    utxo_parity_set_reference_source(src);
}

/* (A) CONSISTENT set: fixture carries the live local SHA3 at the same height →
 * MATCH and the service's mismatches counter stays 0. */
static int slice_case_consistent_zero_mismatch(void)
{
    int failures = 0;
    TEST("parity_slice (A): consistent reducer-vs-fixture set -> 0 mismatches") {
        char path[512];
        int fd = test_mkstemp(path, sizeof(path), "zcl23-parity-slice-ok");
        ASSERT(fd >= 0);
        close(fd);

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, path));
        ASSERT(slice_insert_utxo(&ndb, 0x10));
        ASSERT(slice_insert_utxo(&ndb, 0x20));
        ASSERT(slice_insert_utxo(&ndb, 0x30));

        char local_hex[65];
        slice_local_commitment(&ndb, local_hex);

        /* Exact fixture == the live local commitment at the SAME height. */
        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "slice-consistent",
                                           local_hex, PARITY_SLICE_HEIGHT, true);
        slice_wire(&ndb, &src);

        struct utxo_audit_result res;
        ASSERT(utxo_parity_check_height(PARITY_SLICE_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_MATCH);
        ASSERT(res.drift_detected == false);
        ASSERT(strcmp(res.local_sha3, res.remote_sha3) == 0);

        /* The service-level parity assertion: zero mismatches recorded. */
        ASSERT(slice_parity_stat("mismatches") == 0);
        ASSERT(slice_parity_stat("matches") == 1);

        int64_t drift = -1;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 0);

        utxo_parity_reset_for_test();
        node_db_close(&ndb);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

/* (B) INJECTED mismatch: build the reference from a set MISSING one outpoint,
 * then add that extra outpoint to the local set so the live SHA3 genuinely
 * diverges at the same height → the service DETECTS drift and counts it. */
static int slice_case_injected_mismatch_detected(void)
{
    int failures = 0;
    TEST("parity_slice (B): injected extra outpoint -> service detects mismatch") {
        char path[512];
        int fd = test_mkstemp(path, sizeof(path), "zcl23-parity-slice-drift");
        ASSERT(fd >= 0);
        close(fd);

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, path));

        /* Reference set: two outpoints. Capture its SHA3 as the trusted ref. */
        ASSERT(slice_insert_utxo(&ndb, 0x10));
        ASSERT(slice_insert_utxo(&ndb, 0x20));
        char ref_hex[65];
        slice_local_commitment(&ndb, ref_hex);

        /* Inject a REAL divergence: a third outpoint the reference never saw.
         * This changes the canonical SHA3 — an honest changed-set, not a hash
         * edit — so the local set no longer equals the reference. */
        ASSERT(slice_insert_utxo(&ndb, 0x30));
        char local_hex[65];
        slice_local_commitment(&ndb, local_hex);
        ASSERT(strcmp(local_hex, ref_hex) != 0); /* the injection took effect */

        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "slice-injected",
                                           ref_hex, PARITY_SLICE_HEIGHT, true);
        slice_wire(&ndb, &src);

        struct utxo_audit_result res;
        ASSERT(utxo_parity_check_height(PARITY_SLICE_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_DRIFT);          /* verdict has teeth */
        ASSERT(res.drift_detected == true);
        ASSERT(strcmp(res.local_sha3, res.remote_sha3) != 0);

        /* The negative control at the SERVICE counter: mismatch was counted. */
        ASSERT(slice_parity_stat("mismatches") > 0);
        ASSERT(slice_parity_stat("matches") == 0);
        ASSERT(slice_parity_stat("last_mismatch_height") == PARITY_SLICE_HEIGHT);

        /* The drift flag the utxo_drift_detected Condition pages on. */
        int64_t drift = 0;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 1);

        utxo_parity_reset_for_test();
        node_db_close(&ndb);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

/* (C1) COARSE source, heights agree. The production zclassicd oracle is
 * exact=false (height only), so the live claim runs the coarse branch
 * (utxo_audit_service.c:158-173). A coarse same-height confirmation is a
 * MATCH with an empty remote SHA3, never a DRIFT, bucketed in coarse_checks. */
static int slice_case_coarse_match_no_drift(void)
{
    int failures = 0;
    TEST("parity_slice (C1): coarse same-height -> MATCH, empty ref, no drift") {
        char path[512];
        int fd = test_mkstemp(path, sizeof(path), "zcl23-parity-slice-coarse-ok");
        ASSERT(fd >= 0);
        close(fd);

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, path));
        ASSERT(slice_insert_utxo(&ndb, 0x10));
        ASSERT(slice_insert_utxo(&ndb, 0x20));

        /* exact=false coarse reference: empty hex, SAME height as local. */
        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "slice-coarse-ok",
                                           "", PARITY_SLICE_HEIGHT, false);
        slice_wire(&ndb, &src);

        struct utxo_audit_result res;
        ASSERT(utxo_parity_check_height(PARITY_SLICE_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_MATCH);
        ASSERT(res.drift_detected == false);
        ASSERT(res.remote_sha3[0] == '\0');   /* coarse cannot attest bytes */

        /* Coarse checks are bucketed SEPARATELY: never a match or a mismatch,
         * so a coarse confirmation can never masquerade as a byte-MATCH. */
        ASSERT(slice_parity_stat("coarse_checks") == 1);
        ASSERT(slice_parity_stat("matches") == 0);
        ASSERT(slice_parity_stat("mismatches") == 0);

        int64_t drift = -1;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 0);

        utxo_parity_reset_for_test();
        node_db_close(&ndb);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

/* (C2) COARSE source, height SKEW: LOCAL_ONLY, never a DRIFT, never counted
 * in either bucket, never sets the paging flag. */
static int slice_case_coarse_skew_local_only(void)
{
    int failures = 0;
    TEST("parity_slice (C2): coarse height-skew -> LOCAL_ONLY, never drift") {
        char path[512];
        int fd = test_mkstemp(path, sizeof(path), "zcl23-parity-slice-coarse-skew");
        ASSERT(fd >= 0);
        close(fd);

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, path));
        ASSERT(slice_insert_utxo(&ndb, 0x10));
        ASSERT(slice_insert_utxo(&ndb, 0x20));

        /* Coarse reference one height AHEAD of the local applied height. */
        struct utxo_reference_source src;
        struct utxo_reference_source_fixture fx;
        utxo_reference_source_fixture_init(&src, &fx, "slice-coarse-skew",
                                           "", PARITY_SLICE_HEIGHT + 1, false);
        slice_wire(&ndb, &src);

        struct utxo_audit_result res;
        ASSERT(utxo_parity_check_height(PARITY_SLICE_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_LOCAL_ONLY);
        ASSERT(res.drift_detected == false);

        ASSERT(slice_parity_stat("coarse_checks") == 1);
        ASSERT(slice_parity_stat("matches") == 0);
        ASSERT(slice_parity_stat("mismatches") == 0);

        int64_t drift = -1;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 0);

        utxo_parity_reset_for_test();
        node_db_close(&ndb);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

/* (C3) A coarse confirmation CLEARS a prior exact DRIFT flag. A height-only
 * attestation must not let a stale byte-drift keep paging forever
 * (utxo_audit_service.c:160-172). Drive a REAL exact DRIFT first (the paging
 * flag latches), then a coarse same-height check, and assert the flag clears. */
static int slice_case_coarse_clears_prior_exact_drift(void)
{
    int failures = 0;
    TEST("parity_slice (C3): coarse confirmation clears a prior exact drift") {
        char path[512];
        int fd = test_mkstemp(path, sizeof(path), "zcl23-parity-slice-coarse-clear");
        ASSERT(fd >= 0);
        close(fd);

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, path));

        /* Reference = two outpoints; capture its SHA3 as the trusted exact ref. */
        ASSERT(slice_insert_utxo(&ndb, 0x10));
        ASSERT(slice_insert_utxo(&ndb, 0x20));
        char ref_hex[65];
        slice_local_commitment(&ndb, ref_hex);

        /* Inject a real divergence so the EXACT comparison genuinely drifts. */
        ASSERT(slice_insert_utxo(&ndb, 0x30));

        /* (1) Exact DRIFT: the paging flag latches to 1. */
        struct utxo_reference_source esrc;
        struct utxo_reference_source_fixture efx;
        utxo_reference_source_fixture_init(&esrc, &efx, "slice-c3-exact",
                                           ref_hex, PARITY_SLICE_HEIGHT, true);
        slice_wire(&ndb, &esrc);

        struct utxo_audit_result res;
        ASSERT(utxo_parity_check_height(PARITY_SLICE_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_DRIFT);
        int64_t drift = 0;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 1);   /* the Condition is now paging */

        /* (2) Coarse same-height confirmation must clear the latched flag.
         * slice_wire keeps the node.db state row, so the flag cleared is the
         * one (1) set. */
        struct utxo_reference_source csrc;
        struct utxo_reference_source_fixture cfx;
        utxo_reference_source_fixture_init(&csrc, &cfx, "slice-c3-coarse",
                                           "", PARITY_SLICE_HEIGHT, false);
        slice_wire(&ndb, &csrc);

        ASSERT(utxo_parity_check_height(PARITY_SLICE_HEIGHT, &res).ok);
        ASSERT(res.status == UTXO_AUDIT_MATCH);
        ASSERT(res.drift_detected == false);
        ASSERT(slice_parity_stat("coarse_checks") == 1);

        drift = -1;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 0);   /* CLEARED — the stale exact drift stops paging */

        utxo_parity_reset_for_test();
        node_db_close(&ndb);
        unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

int test_parity_slice(void);
int test_parity_slice(void)
{
    printf("\n=== parity slice "
           "(MVP C8: parity service mismatch-detection machinery, hermetic) ===\n");
    int failures = 0;

    /* Drives parity service process-globals, so OPT-IN behind
     * ZCL_STRESS_TESTS; runs for real via `make mvp-parity-slice`. */
    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("parity_slice: SKIP "
               "(set ZCL_STRESS_TESTS=1 and run isolated via "
               "`make mvp-parity-slice`)\n");
        return 0;
    }

    /* (A)/(B): the EXACT branch (a byte-faithful reference) — match + drift. */
    failures += slice_case_consistent_zero_mismatch();   /* (A) 0 mismatches  */
    failures += slice_case_injected_mismatch_detected();  /* (B) detects drift */
    /* (C1)-(C3): the COARSE (exact=false) branch the production zclassicd
     * oracle hits: height-only attestation never declares a byte DRIFT and
     * clears a stale exact drift. */
    failures += slice_case_coarse_match_no_drift();          /* (C1) coarse MATCH */
    failures += slice_case_coarse_skew_local_only();         /* (C2) coarse skew  */
    failures += slice_case_coarse_clears_prior_exact_drift();/* (C3) coarse clears*/

    printf("=== parity slice: %d failure(s) ===\n", failures);
    return failures + ZCL_TEST_SETUP_FAILURES();
}
