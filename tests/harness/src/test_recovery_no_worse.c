/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_recovery_no_worse — the "RECOVERY NEVER MAKES IT WORSE" invariant.
 *
 * This builds no recovery machinery. It drives the REAL production entry
 * points for two recovery actions and asserts the safety contract that makes
 * falling back to a deeper recovery layer safe in the first place:
 *
 *   (1) NEVER delete state the action cannot locally rebuild — a reindex on a
 *       bodyless datadir REFUSES; it does not wipe.
 *   (2) NEVER spend an unbounded number of destructive attempts — a sentinel
 *       exhausts into a NAMED terminal marker, not a retry loop.
 *   (3) After the action plus a simulated reboot, the datadir CONVERGES: the
 *       preserved state is still there and the terminal marker never silently
 *       re-arms.
 *
 * Two actions are covered here because their contracts are otherwise unproven:
 *
 *   SECTION B — reindex-chainstate coins-state clear. Main proves the
 *       destructive helper boot_index_clear_coins_state() WIPES correctly
 *       (test_coins_anchor_reconcile.c). This proves the GUARD: composed with
 *       boot_index_reindex_replay_executable() in the exact order engine/composition/src/
 *       boot.c uses them, a bodyless (cold-import) datadir refuses, so the
 *       wipe never runs and the un-rebuildable coins state survives — across a
 *       reopen.
 *
 *   SECTION D — the auto_refold boot sentinel. Its auto_reindex sibling is
 *       proven end-to-end by test_boot_reindex_terminates.c; storage/
 *       boot_auto_refold.h had no budget/terminal coverage at all. Attempts
 *       must climb at CONSUME time (not arm time), exhaust into a durable
 *       terminal marker, and never re-arm across further reboots — while a
 *       genuinely-recovered episode still starts fresh.
 */

#include "test/test_core.h"

#include "config/boot_internal.h"
#include "models/database.h"
#include "storage/boot_auto_refold.h"
#include "storage/txdb.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define NW_CHECK(name, expr) do {                                    \
    printf("  recovery_no_worse: %s... ", (name));                   \
    if (expr) printf("OK\n");                                        \
    else { printf("FAIL\n"); failures++; }                           \
} while (0)

/* COUNT(*) over `sql` on an open node_db, or -1 on any error. */
static int nw_count(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

int test_recovery_no_worse(void);
int test_recovery_no_worse(void)
{
    printf("\n=== recovery_no_worse: RECOVERY NEVER MAKES IT WORSE ===\n");
    int failures = 0;

    /* ════════════════════════════════════════════════════════════════
     * SECTION B — reindex-chainstate / coins-state clear: compose the
     * executability probe and the destructive clear in the exact order
     * engine/composition/src/boot.c uses them. A bodyless datadir must REFUSE.
     * ════════════════════════════════════════════════════════════════ */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "recovery_no_worse",
                         "reindex_bodyless");
        char dbpath[512];
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

        struct node_db ndb;
        NW_CHECK("B: node_db opens", node_db_open(&ndb, dbpath));
        NW_CHECK("B: seed a near-tip utxo row",
                 node_db_exec(&ndb,
                     "INSERT INTO utxos(txid,vout,value,script,script_type,"
                     "address_hash,height,is_coinbase) "
                     "VALUES(x'2222',0,5000,x'00',0,NULL,777,0)"));
        NW_CHECK("B: seed coins-best + commitment cache",
                 node_db_exec(&ndb,
                     "INSERT OR REPLACE INTO node_state(key,value)"
                     " VALUES('coins_best_block',x'deadbeef')") &&
                 node_db_exec(&ndb,
                     "INSERT OR REPLACE INTO node_state(key,value)"
                     " VALUES('utxo_sha3',x'01')") &&
                 node_db_exec(&ndb,
                     "INSERT OR REPLACE INTO node_state(key,value)"
                     " VALUES('utxo_commitment',x'02')"));

        char btpath[512];
        snprintf(btpath, sizeof(btpath), "%s/blocktree", dir);
        struct block_tree_db btdb;
        bool btdb_open = block_tree_db_open(&btdb, btpath, 1 << 20, false, true);
        NW_CHECK("B: bodyless block-tree db opens (no genesis body)", btdb_open);

        bool executable = boot_index_reindex_replay_executable(NULL, &btdb,
                                                               btdb_open, dir);
        NW_CHECK("B: replay NOT executable on a bodyless datadir "
                 "(genesis unreadable -> refuses)", !executable);

        /* Mirror boot.c's guard exactly: the destructive clear is gated
         * STRICTLY on the executability probe. */
        if (executable)
            boot_index_clear_coins_state(&ndb);

        NW_CHECK("B: no-worse (1) — utxos row survives (never wipe state we "
                 "cannot rebuild)",
                 nw_count(&ndb, "SELECT COUNT(*) FROM utxos") == 1);
        NW_CHECK("B: no-worse (1) — coins-best/commitment cache survives",
                 nw_count(&ndb,
                     "SELECT COUNT(*) FROM node_state WHERE key IN "
                     "('coins_best_block','utxo_commitment','utxo_sha3')") == 3);

        node_db_close(&ndb);
        if (btdb_open)
            block_tree_db_close(&btdb);

        /* No-worse (3): simulated reboot — the preserved state is DURABLE. */
        struct node_db ndb2;
        NW_CHECK("B: reboot — node_db reopens", node_db_open(&ndb2, dbpath));
        NW_CHECK("B: reboot — utxos row still present after reopen",
                 nw_count(&ndb2, "SELECT COUNT(*) FROM utxos") == 1);
        NW_CHECK("B: reboot — commitment cache still present after reopen",
                 nw_count(&ndb2,
                     "SELECT COUNT(*) FROM node_state WHERE key IN "
                     "('coins_best_block','utxo_commitment','utxo_sha3')") == 3);
        node_db_close(&ndb2);

        test_rm_rf(dir);
    }

    /* ════════════════════════════════════════════════════════════════
     * SECTION D — auto_refold sentinel: bounded-budget convergence.
     * The boot_auto_refold sibling of the proven auto_reindex sentinel.
     * ════════════════════════════════════════════════════════════════ */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "recovery_no_worse",
                         "refold_sentinel");
        const int32_t ANCHOR = 3056758;

        int n1 = boot_auto_refold_request(dir, ANCHOR);
        NW_CHECK("D: fresh arm -> count 1, pending, not terminal",
                 n1 == 1 && boot_auto_refold_pending(dir) &&
                 !boot_auto_refold_is_terminal(dir));

        /* Re-arming at the SAME anchor before any consume must NOT climb the
         * count — only a real boot attempt spends budget. */
        NW_CHECK("D: re-arm before consume does not climb the budget",
                 boot_auto_refold_request(dir, ANCHOR) == 1);

        bool climbs = true;
        for (int i = 1; i <= BOOT_AUTO_REFOLD_MAX; i++) {
            NW_CHECK("D: consume within budget returns true",
                     boot_auto_refold_consume(dir));
            int32_t a = 0;
            int cnt = -1;
            boot_auto_refold_status(dir, &a, &cnt);
            climbs &= (cnt == i && a == ANCHOR);
        }
        NW_CHECK("D: attempts climb 1..MAX at CONSUME time (never at arm time)",
                 climbs);

        /* The MAX+1'th boot's consume: budget exhausted -> a NAMED terminal
         * marker, never an unbounded destructive retry loop. */
        NW_CHECK("D: exhausted consume returns false (never retries past "
                 "budget)", !boot_auto_refold_consume(dir));
        NW_CHECK("D: terminal marker persisted, no longer pending",
                 boot_auto_refold_is_terminal(dir) &&
                 !boot_auto_refold_pending(dir));

        /* No-worse (3): many further simulated reboots — durably immutable,
         * never silently re-arming a fresh destructive attempt. */
        bool durable = true;
        for (int i = 0; i < 25; i++) {
            durable &= (boot_auto_refold_request(dir, ANCHOR) ==
                            BOOT_AUTO_REFOLD_TERMINAL) &&
                       !boot_auto_refold_consume(dir) &&
                       boot_auto_refold_is_terminal(dir);
        }
        NW_CHECK("D: 25 simulated reboots never re-arm the exhausted budget",
                 durable);

        test_cleanup_tmpdir(dir);
    }

    /* Section D companion: a genuinely RECOVERED episode is not falsely
     * exhausted — the reindex sentinel's proven pattern, for refold. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "recovery_no_worse",
                         "refold_recover");
        const int32_t A1 = 111, A2 = 222;

        NW_CHECK("D2: fresh arm", boot_auto_refold_request(dir, A1) == 1);
        NW_CHECK("D2: attempt 1 consumes", boot_auto_refold_consume(dir));
        boot_auto_refold_clear(dir);  /* the refold reset committed: success */
        NW_CHECK("D2: clear -> not pending, not terminal",
                 !boot_auto_refold_pending(dir) &&
                 !boot_auto_refold_is_terminal(dir));
        NW_CHECK("D2: a genuinely-new episode starts fresh at count 1",
                 boot_auto_refold_request(dir, A2) == 1);

        test_cleanup_tmpdir(dir);
    }

    if (failures == 0)
        printf("=== recovery_no_worse: ALL PASS ===\n\n");
    else
        printf("recovery_no_worse: failures=%d\n", failures);
    return failures;
}
