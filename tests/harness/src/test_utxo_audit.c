/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "conditions/utxo_drift_detected.h"
#include "services/utxo_audit_service.h"
#include "coins/utxo_commitment.h"
#include "models/database.h"
#include "event/event.h"
#include "framework/condition.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <string.h>
#include <unistd.h>

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

static int test_utxo_audit_detects_drift(void)
{
    int failures = 0;

    TEST("utxo_audit: detects commitment drift and persists advisory flag") {
        char path[] = "/tmp/zclassic23-utxo-audit-XXXXXX";
        int fd = mkstemp(path);
        ASSERT(fd >= 0);
        close(fd);

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, path));
        ASSERT(insert_test_utxo(&ndb, 0x24));

        uint8_t local_hash[32];
        uint64_t count = 0;
        utxo_commitment_sha3_compute(ndb.db, local_hash, &count);
        char remote_hex[65];
        hash_to_hex(local_hash, remote_hex);
        remote_hex[0] = remote_hex[0] == '0' ? '1' : '0';

        struct utxo_audit_result result;
        ASSERT(utxo_audit_compare_remote(&ndb, remote_hex, 3078015,
                                         "unit-peer", &result).ok);
        ASSERT(result.status == UTXO_AUDIT_DRIFT);
        ASSERT(result.local_utxo_count == count);
        ASSERT(strcmp(result.remote_sha3, remote_hex) == 0);

        int64_t drift = 0;
        ASSERT(node_db_state_get_int(&ndb, "utxo_drift_detected", &drift));
        ASSERT(drift == 1);

        node_db_close(&ndb);
        unlink(path);
        PASS();
    } _test_next:;

    return failures;
}

static int test_utxo_drift_condition_escalates_and_clears(void)
{
    int failures = 0;

    TEST("utxo_drift_detected condition escalates persisted audit drift") {
        char path[] = "/tmp/zclassic23-utxo-drift-cond-XXXXXX";
        int fd = mkstemp(path);
        ASSERT(fd >= 0);
        close(fd);

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, path));
        ASSERT(node_db_state_set_int(&ndb, "utxo_drift_detected", 1));
        ASSERT(node_db_state_set_int(&ndb, "utxo_audit_last_height", 3078015));
        ASSERT(node_db_state_set(&ndb, "utxo_audit_last_local_sha3",
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                 64));
        ASSERT(node_db_state_set(&ndb, "utxo_audit_last_remote_sha3",
                                 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                 64));

        condition_engine_reset_for_testing();
        utxo_drift_detected_test_reset();
        utxo_drift_detected_test_set_node_db(&ndb);
        blocker_module_init();
        blocker_reset_for_testing();
        register_utxo_drift_detected();
        condition_engine_tick();

        ASSERT(utxo_drift_detected_test_remedy_calls() == 1);
        ASSERT(condition_engine_get_active_count() == 1);
        ASSERT(condition_engine_get_unresolved_count() == 1);

        /* B2: the remedy is a deliberate no-op (never auto-run a
         * destructive wipe/reimport) but must still surface a named,
         * typed blocker so blocker_stall_meta_detector / `dumpstate
         * blocker` can see the unresolved drift instead of it being
         * invisible to the safety net. */
        ASSERT(blocker_exists("utxo.parity_bh_drift"));
        struct blocker_snapshot snaps[16];
        int n = blocker_snapshot_all(snaps, 16);
        bool found = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, "utxo.parity_bh_drift") == 0) {
                found = true;
                ASSERT(snaps[i].class == BLOCKER_DEPENDENCY);
                ASSERT(snaps[i].retry_budget == -1);
                ASSERT(strcmp(snaps[i].owner_subsystem,
                             "utxo_drift_detected") == 0);
                break;
            }
        }
        ASSERT(found);

        ASSERT(node_db_state_set_int(&ndb, "utxo_drift_detected", 0));
        condition_engine_tick();
        ASSERT(condition_engine_get_active_count() == 0);
        ASSERT(condition_engine_get_unresolved_count() == 0);

        condition_engine_reset_for_testing();
        utxo_drift_detected_test_reset();
        blocker_reset_for_testing();
        node_db_close(&ndb);
        unlink(path);
        PASS();
    } _test_next:;

    return failures;
}

int test_utxo_audit(void)
{
    int failures = 0;
    failures += test_utxo_audit_detects_drift();
    failures += test_utxo_drift_condition_escalates_and_clears();
    return failures;
}
