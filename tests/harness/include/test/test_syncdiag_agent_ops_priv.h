/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the sync-diagnostics agentops test scenario
 * check files (test_syncdiag_agent_ops.c and its
 * test_syncdiag_agent_ops_*.c siblings). struct sd_agent_ops_ctx (one
 * RPC table plus one reusable empty-array params value) and struct
 * sd_quality_fixture (the on-disk background-quality fixture shared by
 * the agentbuild scenario and its deferred-collector follow-up) are
 * built and torn down once in test_syncdiag_agent_ops.c's group entry
 * point and threaded by pointer into every scenario below — neither
 * struct is file-scope mutable state, and no sibling declares any of
 * its own.
 */

#ifndef TEST_SYNCDIAG_AGENT_OPS_PRIV_H
#define TEST_SYNCDIAG_AGENT_OPS_PRIV_H

#include <stdbool.h>

struct sd_agent_ops_ctx {
    struct rpc_table tbl;
    struct json_value params;
};

struct sd_quality_fixture {
    bool ok;
    bool env_was_set;
    char env_buf[4096];
    char tmp[32];
    char status_dir[4096];
    char fuzz_file[4096];
    char *root;
};

/* test_syncdiag_agent_ops_surface_and_timeline.c — agentops top-level
 * fields, agentdiagnose, the inferred runtime lane, the event timeline
 * (basic, filtered, and CLI-style filters), the state catalog, and
 * agentlanes. */
bool sd_ops_fields_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_diagnose_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_inferred_lane_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_timeline_basic_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_timeline_filtered_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_timeline_cli_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_statecatalog_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_lanes_scenario(struct sd_agent_ops_ctx *ctx);

/* test_syncdiag_agent_ops_build_and_liveness.c — agentbuild and its
 * deferred-collector follow-up, agentdevstatus, and agentliveness in
 * brief, full, and probed detail modes. */
bool sd_build_scenario(struct sd_agent_ops_ctx *ctx,
                       const struct sd_quality_fixture *fx);
bool sd_build_deferred_scenario(struct sd_agent_ops_ctx *ctx,
                                const struct sd_quality_fixture *fx);
bool sd_devstatus_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_liveness_brief_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_liveness_full_scenario(struct sd_agent_ops_ctx *ctx);
bool sd_liveness_probed_scenario(struct sd_agent_ops_ctx *ctx);

#endif
