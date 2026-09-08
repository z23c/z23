/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the op_return_index_legacy_state self-heal condition
 * (engine/conditions/src/op_return_index_legacy_state.c). Exercised via the
 * ZCL_TESTING hooks against a real in-memory node_db with a planted legacy
 * v1 record, mirroring test_catalog_lag_exceeded.c / test_utxo_drift_
 * detected's shape:
 *
 *   - detect() is true while the persisted state is a refused legacy_v1
 *     record, false once a rebuild lands a fresh v2 record;
 *   - the remedy raises the typed named blocker "op_return_index.legacy_
 *     state" (non-destructive — no store touched, no cursor rewound) and
 *     is countable;
 *   - the underlying op_return_index_get_cursor() keeps refusing by name
 *     across repeated polls while the condition is active;
 *   - the witness clears the blocker exactly when the rebuild lands.
 */

#include "test/test_core.h"

#include "conditions/op_return_index_legacy_state.h"
#include "framework/condition.h"
#include "models/database.h"
#include "models/op_return_index.h"
#include "util/blocker.h"

#include <stdio.h>
#include <string.h>

#define OIL_CHECK(name, expr) do { \
    printf("  op_return_index_legacy_state: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_op_return_index_legacy_state(void)
{
    int failures = 0;

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    OIL_CHECK("fresh in-memory db opens", node_db_open(&ndb, ":memory:") &&
                                              ndb.open);

    op_return_index_legacy_state_test_reset();
    op_return_index_legacy_state_test_set_node_db(&ndb);

    OIL_CHECK("detect() is false on a fresh (EMPTY) db",
             !op_return_index_legacy_state_test_detect());

    /* Plant a legacy v1 record — the exact fixture shape test_op_return_
     * index.c uses for its own refusal test. */
    uint8_t legacy_digest[32];
    memset(legacy_digest, 0x3C, 32);
    bool planted =
        node_db_state_set_int(&ndb, "op_return_index_cursor_height", 1234) &&
        node_db_state_set(&ndb, "op_return_index_digest", legacy_digest, 32);
    OIL_CHECK("legacy v1 record planted", planted);

    OIL_CHECK("detect() is true once the persisted state is legacy_v1",
             op_return_index_legacy_state_test_detect());

    /* The underlying model keeps refusing by name across repeated polls —
     * the condition names it; op_return_index.c's own throttle/backoff
     * (tested directly in test_op_return_index.c) keeps that cheap. */
    for (int i = 0; i < 5; i++) {
        struct op_return_index_cursor cur;
        memset(&cur, 0xEE, sizeof(cur));
        OIL_CHECK("get_cursor refuses while legacy_state is active",
                 !op_return_index_get_cursor(&ndb, &cur));
    }

    OIL_CHECK("remedy raises the blocker (non-destructive)",
             op_return_index_legacy_state_test_remedy() == COND_REMEDY_OK);
    OIL_CHECK("remedy is countable",
             op_return_index_legacy_state_test_remedy_calls() == 1);

    {
        struct blocker_snapshot snap[8];
        int n = blocker_snapshot_all(snap, 8);
        bool found = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snap[i].id, "op_return_index.legacy_state") == 0) {
                found = true;
                OIL_CHECK("blocker class is DEPENDENCY",
                         snap[i].class == BLOCKER_DEPENDENCY);
            }
        }
        OIL_CHECK("named blocker op_return_index.legacy_state is active",
                 found);
    }

    OIL_CHECK("witness does NOT clear while still legacy_v1",
             !op_return_index_legacy_state_test_witness());

    /* The rebuild is the documented escape: truncate drops the legacy
     * record and re-derives an EMPTY v2 chain. Never destructive to any
     * OTHER store — this condition's remedy never calls it itself. */
    OIL_CHECK("op_return_index_truncate re-derives a fresh v2 chain",
             op_return_index_truncate(&ndb));

    OIL_CHECK("detect() is false again after the rebuild",
             !op_return_index_legacy_state_test_detect());

    OIL_CHECK("witness clears once the rebuild lands",
             op_return_index_legacy_state_test_witness());

    {
        struct blocker_snapshot snap[8];
        int n = blocker_snapshot_all(snap, 8);
        bool still_present = false;
        for (int i = 0; i < n; i++)
            if (strcmp(snap[i].id, "op_return_index.legacy_state") == 0)
                still_present = true;
        OIL_CHECK("blocker cleared after the witnessed rebuild",
                 !still_present);
    }

    {
        struct op_return_index_cursor cur;
        memset(&cur, 0xEE, sizeof(cur));
        OIL_CHECK("get_cursor succeeds again post-rebuild",
                 op_return_index_get_cursor(&ndb, &cur) &&
                     cur.height == -1);
    }

    /* Registration + rearm-forever cooldown posture (state_auditor_
     * mismatch's / catalog_lag_exceeded's shape). */
    condition_engine_reset_for_testing();
    register_op_return_index_legacy_state();
    OIL_CHECK("registered in condition engine",
             condition_engine_has_registered("op_return_index_legacy_state"));
    {
        struct condition_runtime_snapshot snap;
        if (condition_engine_get_registered_snapshot(
                "op_return_index_legacy_state", &snap)) {
            OIL_CHECK("severity == COND_WARN", snap.severity == COND_WARN);
            OIL_CHECK("cooldown rearm-forever (600s, unbounded rearms)",
                     snap.cooldown_secs == 600 &&
                         snap.cooldown_max_rearms == 0);
            OIL_CHECK("finite max_attempts before paging",
                     snap.max_attempts == 5);
        } else {
            OIL_CHECK("registered snapshot retrievable", false);
        }
    }

    blocker_reset_for_testing();
    op_return_index_legacy_state_test_reset();
    node_db_close(&ndb);
    printf("op_return_index_legacy_state: %d failures\n", failures);
    return failures;
}
