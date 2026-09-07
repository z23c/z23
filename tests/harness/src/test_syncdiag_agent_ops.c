/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agentops case: the operator work surface and everything it fans out
 * to — agentdiagnose, the event timeline, the state catalog,
 * agentlanes, agentbuild, agentdevstatus, and the agentliveness rollup
 * in compact and full detail modes.
 *
 * This file owns the shared fixtures (struct sd_agent_ops_ctx and
 * struct sd_quality_fixture, declared in test_syncdiag_agent_ops_priv.h)
 * and the group entry point; the scenarios themselves live in its
 * test_syncdiag_agent_ops_*.c siblings, grouped by what they exercise.
 * Each scenario is a named check: build the params or event fixture,
 * call the RPC through the shared table, assert on the result, and
 * free what it owns. `syncdiag_cases_agent_ops` runs every scenario in
 * turn and reports one OK/FAIL line per scenario.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "test/test_syncdiag_agent_ops_priv.h"

/* Shared fixture used by every scenario across this file's siblings:
 * one RPC table and one reusable empty-array params value, exactly as
 * the single function this file used to be shared them. */
static void sd_agent_ops_ctx_init(struct sd_agent_ops_ctx *ctx)
{
    rpc_table_init(&ctx->tbl);
    register_event_rpc_commands(&ctx->tbl);
    register_diagnostics_rpc_commands(&ctx->tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();
    json_init(&ctx->params);
    json_set_array(&ctx->params);
}

static void sd_agent_ops_ctx_free(struct sd_agent_ops_ctx *ctx)
{
    json_free(&ctx->params);
}

/* The agentbuild scenario and its deferred-collector follow-up share one
 * on-disk background-quality fixture; it outlives both scenarios and is
 * torn down once the last dependent scenario (agentliveness, which also
 * reads background_quality_status) has run — matching the lifetime the
 * original single function gave it. */
static bool sd_quality_fixture_setup(struct sd_quality_fixture *fx)
{
    const char *old_quality_env = getenv("ZCL_QUALITY_STATE_DIR");
    fx->env_was_set = old_quality_env != NULL;
    bool env_saved = true;
    memcpy(fx->tmp, "/tmp/zcl_quality_rpc_XXXXXX",
          sizeof "/tmp/zcl_quality_rpc_XXXXXX");
    fx->root = mkdtemp(fx->tmp);
    fx->ok = fx->root != NULL;
    if (fx->env_was_set) {
        int n = snprintf(fx->env_buf, sizeof fx->env_buf, "%s",
                         old_quality_env);
        env_saved = n >= 0 && (size_t)n < sizeof fx->env_buf;
    }
    if (fx->ok) {
        int n = snprintf(fx->status_dir, sizeof fx->status_dir, "%s/status",
                         fx->root);
        fx->ok = n >= 0 && (size_t)n < sizeof fx->status_dir &&
            mkdir(fx->status_dir, 0700) == 0;
    }
    if (fx->ok) {
        int n = snprintf(fx->fuzz_file, sizeof fx->fuzz_file,
                         "%s/fuzz.json", fx->status_dir);
        fx->ok = n >= 0 && (size_t)n < sizeof fx->fuzz_file;
    }
    if (fx->ok) {
        FILE *f = fopen(fx->fuzz_file, "wb");
        fx->ok = f != NULL;
        if (f) {
            fprintf(f,
                    "{\"schema\":\"zcl.background_quality_lane.v1\","
                    "\"lane\":\"fuzz\",\"status\":\"passed\","
                    "\"started_at\":\"2026-07-05T00:00:00Z\","
                    "\"finished_at\":\"2026-07-05T00:01:00Z\","
                    "\"elapsed_seconds\":60,\"exit_code\":0,"
                    "\"source_id_sha256\":\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\","
                    "\"commit\":\"%s\",\"log\":\"/tmp/fuzz.log\","
                    "\"artifacts\":\"/tmp/artifacts\","
                    "\"detail\":\"fixture\"}\n",
                    zcl_build_commit());
            fx->ok = fclose(f) == 0;
        }
    }
    if (fx->ok)
        fx->ok = setenv("ZCL_QUALITY_STATE_DIR", fx->root, 1) == 0;
    return env_saved && fx->ok;
}

static void sd_quality_fixture_teardown(const struct sd_quality_fixture *fx)
{
    if (fx->env_was_set)
        setenv("ZCL_QUALITY_STATE_DIR", fx->env_buf, 1);
    else
        unsetenv("ZCL_QUALITY_STATE_DIR");
    if (fx->ok) {
        unlink(fx->fuzz_file);
        rmdir(fx->status_dir);
        rmdir(fx->tmp);
    }
}

static void sd_report(const char *desc, bool ok, int *failures)
{
    printf("%s", desc);
    if (ok)
        printf("OK\n");
    else {
        printf("FAIL\n");
        (*failures)++;
    }
}

int syncdiag_cases_agent_ops(void)
{
    int failures = 0;
    struct sd_agent_ops_ctx ctx;
    sd_agent_ops_ctx_init(&ctx);

    sd_report("api: agentops top-level fields, direct_commands, workflow, "
              "gaps, and architecture_review... ",
              sd_ops_fields_scenario(&ctx), &failures);
    sd_report("api: agentdiagnose full detail, peer_incidents, timeline, "
              "and first_call... ",
              sd_diagnose_scenario(&ctx), &failures);
    sd_report("api: agentops infers the runtime lane from an exact boot "
              "topology... ",
              sd_inferred_lane_scenario(&ctx), &failures);
    sd_report("api: timeline returns the sync category with a semantic "
              "summary and drilldowns... ",
              sd_timeline_basic_scenario(&ctx), &failures);
    sd_report("api: timeline filters server-side by peer, height, stage, "
              "condition, deploy, and lane... ",
              sd_timeline_filtered_scenario(&ctx), &failures);
    sd_report("api: timeline accepts the same filters as one CLI-style "
              "JSON argument... ",
              sd_timeline_cli_scenario(&ctx), &failures);
    sd_report("api: statecatalog lists block_index and reducer_frontier "
              "subsystems... ",
              sd_statecatalog_scenario(&ctx), &failures);
    sd_report("api: agentlanes reports commands, runtime services, and "
              "canonical/dev deployment safety... ",
              sd_lanes_scenario(&ctx), &failures);

    struct sd_quality_fixture fx;
    memset(&fx, 0, sizeof fx);
    bool fixture_ok = sd_quality_fixture_setup(&fx);

    sd_report("api: agentbuild reports loop, indexing, benchmark, cache, "
              "history, and background-quality sections... ",
              sd_build_scenario(&ctx, &fx) && fixture_ok, &failures);
    sd_report("api: agentbuild's collectors defer outside the repository "
              "checkout... ",
              sd_build_deferred_scenario(&ctx, &fx), &failures);
    sd_report("api: agentdevstatus reflects the mocked worker_lane and "
              "next_action... ",
              sd_devstatus_scenario(&ctx), &failures);
    sd_report("api: agentliveness brief mode omits embedded "
              "drilldowns... ",
              sd_liveness_brief_scenario(&ctx), &failures);
    sd_report("api: agentliveness full mode embeds methods, lanes, and "
              "domains... ",
              sd_liveness_full_scenario(&ctx), &failures);
    sd_report("api: agentliveness reports target_runtime_reachable once "
              "probed... ",
              sd_liveness_probed_scenario(&ctx), &failures);

    sd_quality_fixture_teardown(&fx);
    sd_agent_ops_ctx_free(&ctx);
    return failures;
}
