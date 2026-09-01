/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the fail-loud validation pack check 7 (+ check 5 post-import
 * half) — engine/services/src/seed_integrity_gate.c:
 *
 *   - empty blocks projection: vacuous pass (fresh datadir non-fire);
 *   - healthy linked suffix: pass (cold-import non-fire);
 *   - suffix that ends (snapshot seeds lack deep rows): pass;
 *   - seed-tip pair mismatch (row labeled differently): REFUSED +
 *     PERMANENT seed.linkage_gate blocker, process alive (crash-only);
 *   - linkage break (parent labeled h-7, the splice-at-birth shape):
 *     REFUSED naming the break;
 *   - absent tip row: pass-with-warn (projection backfill ordering);
 *   - memo: re-running the same (height,hash) returns the cached verdict.
 */

#include "test/test_core.h"

#include "models/database.h"
#include "services/seed_integrity_gate.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SIG_CHECK(name, expr) do {                  \
    printf("seed_integrity_gate: %s... ", (name));  \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

static void sig_hash(uint8_t out[32], int h, uint8_t salt)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xFF);
    out[1] = (uint8_t)((h >> 8) & 0xFF);
    out[2] = (uint8_t)((h >> 16) & 0xFF);
    out[3] = salt;
}

static bool sig_insert(struct node_db *ndb, const uint8_t hash[32],
                       int height, const uint8_t prev[32])
{
    sqlite3_stmt *st = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO blocks"
        "(hash,height,prev_hash,version,merkle_root,time,bits,nonce,"
        " solution,chain_work,status,num_tx)"
        " VALUES(?,?,?,4,?,?,0,?,?,?,3,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    static const uint8_t zeros[32] = {0};
    static const uint8_t solution[1] = {0};
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, height);
    sqlite3_bind_blob(st, 3, prev ? prev : zeros, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, 1700000000 + height);
    sqlite3_bind_blob(st, 6, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 7, solution, sizeof(solution), SQLITE_STATIC);
    sqlite3_bind_blob(st, 8, zeros, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

/* Build a healthy linked span [lo..hi] with the given salt; out_tip gets
 * the hash at hi. */
static bool sig_build_span(struct node_db *ndb, int lo, int hi,
                           uint8_t salt, uint8_t out_tip[32])
{
    uint8_t prev[32]; memset(prev, 0, 32);
    uint8_t cur[32];
    for (int h = lo; h <= hi; h++) {
        sig_hash(cur, h, salt);
        if (!sig_insert(ndb, cur, h, (h == lo) ? NULL : prev))
            return false;
        memcpy(prev, cur, 32);
    }
    memcpy(out_tip, prev, 32);
    return true;
}

int test_seed_integrity_gate(void)
{
    printf("\n=== seed_integrity_gate tests ===\n");
    int failures = 0;

    blocker_module_init();
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();

    struct node_db ndb;
    if (!node_db_open(&ndb, ":memory:")) {
        SIG_CHECK("fixture: in-memory node_db opens", false);
        return failures;
    }
    seed_integrity_gate_set_node_db_for_testing(&ndb);

    /* 1. Empty projection: absent tip row -> pass with warn. */
    {
        uint8_t tip[32]; sig_hash(tip, 50, 0x01);
        bool ok = seed_integrity_gate_check(50, tip, false);
        SIG_CHECK("empty projection: pass (absent tip row = warn)", ok);
    }

    /* 2. Healthy linked suffix [0..60]: pass (untrusted seed: linkage
     * walk only). */
    {
        seed_integrity_gate_reset_for_testing();
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        uint8_t tip[32];
        bool built = sig_build_span(&ndb, 0, 60, 0x02, tip);
        bool ok = built && seed_integrity_gate_check(60, tip, false);
        SIG_CHECK("healthy linked chain [0..60]: pass", ok);
        SIG_CHECK("healthy: no blocker",
                  !blocker_exists("seed.linkage_gate"));
    }

    /* 3. Suffix ends mid-walk (snapshot shape: rows only above base):
     * pass. */
    {
        seed_integrity_gate_reset_for_testing();
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        uint8_t tip[32];
        bool built = sig_build_span(&ndb, 100, 130, 0x03, tip);
        /* parent of row 100 is absent: walk stops cleanly */
        bool ok = built && seed_integrity_gate_check(130, tip, false);
        SIG_CHECK("snapshot suffix (rows only above base): pass", ok);
    }

    /* 4. Seed-tip pair mismatch: row labeled 206 while the seed claims
     * 200 -> refused at birth. */
    {
        seed_integrity_gate_reset_for_testing();
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        uint8_t tip[32]; sig_hash(tip, 206, 0x04);
        bool built = sig_insert(&ndb, tip, 206, NULL);
        bool refused = built && !seed_integrity_gate_check(200, tip, false);
        SIG_CHECK("seed pair mismatch (+6 label): REFUSED", refused);
        SIG_CHECK("refusal registered PERMANENT seed.linkage_gate",
                  blocker_exists("seed.linkage_gate") &&
                  blocker_class_for("seed.linkage_gate") ==
                      BLOCKER_PERMANENT);
        blocker_clear("seed.linkage_gate");
    }

    /* 5. Linkage break at birth: chain [300..310] healthy, then the
     * parent of 311 is labeled 304 (the +6 splice boundary). */
    {
        seed_integrity_gate_reset_for_testing();
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        uint8_t base_tip[32];
        bool built = sig_build_span(&ndb, 300, 310, 0x05, base_tip);
        /* mislabel the row at 310: rewrite it with height 304 */
        built = built && sig_insert(&ndb, base_tip, 304, NULL);
        /* child at 311 links to it by hash */
        uint8_t child[32]; sig_hash(child, 311, 0x05);
        built = built && sig_insert(&ndb, child, 311, base_tip);
        bool refused = built && !seed_integrity_gate_check(311, child,
                                                           false);
        SIG_CHECK("linkage break (parent labeled h-7): REFUSED at birth",
                  refused);
        SIG_CHECK("break registered seed.linkage_gate blocker",
                  blocker_exists("seed.linkage_gate"));

        /* 6. Memo: the same (height,hash) re-check returns the cached
         * refusal without re-walking. */
        bool memo_refused = !seed_integrity_gate_check(311, child, false);
        SIG_CHECK("memo: repeat check returns cached refusal",
                  memo_refused);
        blocker_clear("seed.linkage_gate");
    }

    /* crash-only proof: refusals above were plain false returns;
     * the process (this test) is alive. */
    seed_integrity_gate_reset_for_testing();
    blocker_reset_for_testing();
    node_db_close(&ndb);
    return failures;
}
