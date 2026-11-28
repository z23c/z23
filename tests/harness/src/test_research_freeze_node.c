/* purpose: Exercise research rules on an isolated Ironwood node. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "research_freeze_fixture.h"

#define RF_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "research_freeze_node:%d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static int rf_schedule(struct rf_fixture *f)
{
    RF_CHECK(rf_height(f, 0));
    RF_CHECK(rf_mine(f, 119, false));
    RF_CHECK(rf_height(f, 119));
    char raw[RNF_RAW], ballot[160];
    snprintf(ballot, sizeof(ballot), "{\"catalog\":\"%s\",\"slots\":[0,1]}", rf_digest);
    const char *const early[] = {"generatetoaddress", "1", f->address, ballot, NULL};
    RF_CHECK(rf_rpc(f, early, raw, sizeof(raw)) != 0);
    RF_CHECK(strstr(raw, "Template height outside the pinned voting window"));
    RF_CHECK(rf_height(f, 119));
    RF_CHECK(rf_mine(f, 1, false));
    for (int h = 121; h <= 140; ++h) {
        RF_CHECK(rf_mine(f, 1, h != 130));
        RF_CHECK(rf_height(f, h));
        RF_CHECK(rf_status(f, h, h - 120 - (h >= 130), h == 140 ? "locked_in" : "voting"));
    }
    RF_CHECK(rf_mine(f, 6, false));
    RF_CHECK(rf_height(f, 146));
    RF_CHECK(rf_status(f, 146, 19, "active"));
    return 0;
}

int test_research_freeze_node(void)
{
    struct rf_fixture f = {0};
    int failures = 0;
    if (!rf_setup(&f)) {
        fprintf(stderr, "research_freeze_node: setup failed\n");
        failures = 1;
    } else {
        failures = rf_schedule(&f);
    }
    if (failures && f.node.work[0]) rnf_log_tail(&f.node);
    rnf_cleanup(&f.node);
    return failures;
}
