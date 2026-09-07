/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the sync-diagnostics agent-projection test
 * scenario check files (test_syncdiag_agent_projection.c and its
 * test_syncdiag_agent_projection_*.c siblings). No sibling declares
 * its own file-scope mutable state; each scenario's own fixture
 * context (struct sd_agent_stalled_catchup_ctx,
 * struct sd_agent_dispatch_idle_ctx, struct sd_agent_cache_miss_ctx,
 * struct sd_diag_lookahead_ctx) stays private to the sibling file that
 * declares and uses it — only the group entry point in
 * test_syncdiag_agent_projection.c needs to call every scenario across
 * the split files.
 */

#ifndef TEST_SYNCDIAG_AGENT_PROJECTION_PRIV_H
#define TEST_SYNCDIAG_AGENT_PROJECTION_PRIV_H

#include <stdbool.h>

/* test_syncdiag_agent_projection_budget_and_download.c — bounded
 * optional detail, stale mirror-latch suppression, stalled catch-up
 * and idle download-dispatch telemetry, and fast-cache-miss detail
 * retention. */
bool sd_agent_budget_bound_scenario(void);
bool sd_agent_stale_mirror_latch_scenario(void);
bool sd_agent_stalled_catchup_scenario(void);
bool sd_agent_dispatch_idle_scenario(void);
bool sd_agent_cache_miss_scenario(void);

/* test_syncdiag_agent_projection_lookahead.c — the one-block-lookahead
 * agentdiagnose narrative. */
bool sd_diag_lookahead_scenario(void);

#endif
