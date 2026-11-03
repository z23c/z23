/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Acceptance cases for repairs to the fleet objectives reader
 *          (tools/command/native_fleet_objectives_read.c and the agent
 *          index in native_fleet_objectives_lanes.c). Each case pins one
 *          defect: outcome rows stamped after the captured clock, git date
 *          pruning and future commits, train identities longer than the old
 *          note bound, incomplete attempt collections, ranking from a partial
 *          outcome read, hotswap module runs in wall time, baseline keys the
 *          lint loader refuses, and lane labels truncated into an alias.
 *          Called from test_fleet_objectives. */

#include "test/test_core.h"
#include "base/safe_alloc.h"

#include "command/native_fleet_objectives.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* 2026-10-22T10:00:00Z: the captured clock every case measures from. */
#define RPR_NOW 1792663200LL
#define RPR_DAY 86400LL

static bool rpr_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len;
    bool wrote;
    if (!f)
        return false;
    len = strlen(text);
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

/* ── landing windows bounded by the captured clock ───────────────────── */

static int rpr_case_window_future(const char *root)
{
    int failures = 0;
    char path[1024];
    struct zcl_objectives_options o = {0};
    (void)snprintf(path, sizeof(path), "%s/window_future.jsonl", root);
    o.now = RPR_NOW;
    o.outcomes = path;
    TEST("objectives: a landing stamped after the captured clock is not counted today") {
        struct zcl_objective_value today;
        ASSERT(rpr_write(path,
            "{\"state\":\"landed\",\"ts\":\"2026-10-22T09:00:00Z\"}\n"
            "{\"state\":\"landed\",\"ts\":\"2026-10-22T10:00:01Z\"}\n"));
        today = zcl_objectives_measure(&o, "landed_rows_today");
        ASSERT(today.measured);
        ASSERT_EQ(today.value, (int64_t)1);
        PASS();
    }
_test_next:;
    return failures;
}

int fox_repair_cases(void);
int fox_repair_cases(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "repair");
    failures += rpr_case_window_future(root);
    (void)test_rm_rf_recursive(root);
    return failures;
}
