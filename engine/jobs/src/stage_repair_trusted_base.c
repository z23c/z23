/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Preserve a completed checkpoint-base finalize transition. */
// repair-rung-ok:test_stage_repair

#include "jobs/stage_repair.h"
#include "jobs/reducer_frontier.h"
#include "stage_repair_reducer_frontier_internal.h"

#include "platform/time_compat.h"
#include "tip_finalize_log_store.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

bool stage_repair_preserve_trusted_base_transition(
    sqlite3 *db, int hstar, int cursor,
    const struct stage_reducer_frontier_reconcile_result *out)
{
    if (!db || !out || hstar < 0 || cursor != hstar + 1 ||
        !out->coins_applied_found || out->coins_applied_height != cursor)
        return false; /* raw-return-ok:not the narrow transition shape */

    uint8_t trusted_hash[32] = {0};
    int32_t trusted_height = -1;
    bool trusted_found = false;
    if (!reducer_frontier_trusted_base_read(
            db, &trusted_height, trusted_hash, &trusted_found))
        return false; /* raw-return-ok:canonical reader logged failure */
    if (!trusted_found || trusted_height != hstar)
        return false; /* raw-return-ok:not the trusted-base height */

    struct finalized_tip_row row;
    if (!finalized_tip_row_at(db, hstar, &row))
        LOG_FAIL("stage_repair", "trusted-base transition row read failed");
    if (!row.found || !row.ok || row.is_anchor || !row.has_tip_hash ||
        memcmp(row.tip_hash.data, trusted_hash, sizeof(trusted_hash)) == 0)
        return false; /* raw-return-ok:transition is absent or incomplete */

    static struct log_throttle throttle = LOG_THROTTLE_INIT;
    uint64_t repeats = 0;
    if (log_throttle_should_emit(&throttle, (uint64_t)(uint32_t)hstar,
                                 platform_time_wall_unix(), 300, &repeats))
        LOG_INFO("stage_repair",
                 "[stage_repair] preserving completed trusted-base "
                 "transition hstar=%d cursor=%d coins_applied=%d repeats=%llu",
                 hstar, cursor, out->coins_applied_height,
                 (unsigned long long)repeats);
    return true;
}
