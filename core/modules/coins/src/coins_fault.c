/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * coins_fault — arming surface for the test-only UTXO-map hash collapse.
 * The rationale, the bug class it models, and the empty-map arming contract
 * are documented in coins/coins_fault.h. Nothing in the node ever calls
 * these; the callers are the perf detector (engine/modules/sim/src/simnet_perf.c) and
 * its self-test (tests/harness/src/test_simnet_perf.c).
 */

#include "coins/coins_fault.h"

#include "coins/coins_view.h"
#include "util/log_macros.h"

bool coins_fault_arm_map_hash_collapse(struct coins_map *m, bool on)
{
    if (!m)
        LOG_FAIL("coins_fault", "NULL coins_map");
    if (m->size != 0)
        LOG_FAIL("coins_fault",
                 "refusing to change the bucket hash of a populated map "
                 "(size=%zu) — every live entry's slot was chosen by the "
                 "hash in force when it was inserted",
                 m->size);
    m->degraded_hash = on;
    return true;
}

bool coins_fault_map_hash_collapsed(const struct coins_map *m)
{
    return m ? m->degraded_hash : false;
}
