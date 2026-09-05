/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot.h"

#include <stdio.h>
#include <string.h>

#define APPCTX_CHECK(name, expr) do {                                  \
    printf("app_context: %s... ", (name));                            \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)


/* ── Tor admission policy ────────────────────────────────────────────
 *
 * This test binary links whichever Tor the build chose, so it can never
 * answer for both build identities by asking. It does not have to:
 * app_tor_policy_refusal_code() takes `real_tor_linked` as a PARAMETER (the
 * production caller in args.c injects app_tor_real_build_linked()), so both
 * branches are exercised here without relinking anything.
 *
 * Every expectation below is written against the APP_TOR_REFUSE_* macros, so
 * this test and the refusal site assert the same literal code string and
 * neither can drift from the other silently. */
static void tor_ctx(struct app_context *ctx, enum zcl_operator_lane lane)
{
    app_context_defaults(ctx);
    ctx->operator_lane = lane;
}

static bool tor_code_is(const char *got, const char *want)
{
    return got != NULL && strcmp(got, want) == 0;
}

static int test_app_context_tor_policy(void)
{
    int failures = 0;
    struct app_context ctx;

    /* (a) A stub-stamped binary refuses every way of asking for an onion.
     * Each ask is checked on its own, because one arm covering for another
     * is exactly how a flag stops being policed. */
    {
        bool ok = true;

        tor_ctx(&ctx, ZCL_OPERATOR_LANE_DEV);
        ctx.tor = true;
        ok = ok && tor_code_is(app_tor_policy_refusal_code(&ctx, false),
                               APP_TOR_REFUSE_STUB_BUILD_ASKED_FOR_TOR);

        tor_ctx(&ctx, ZCL_OPERATOR_LANE_DEV);
        ctx.onion_persist = true;
        ok = ok && tor_code_is(app_tor_policy_refusal_code(&ctx, false),
                               APP_TOR_REFUSE_STUB_BUILD_ASKED_FOR_TOR);

        tor_ctx(&ctx, ZCL_OPERATOR_LANE_DEV);
        ctx.onion_rotate = true;
        ok = ok && tor_code_is(app_tor_policy_refusal_code(&ctx, false),
                               APP_TOR_REFUSE_STUB_BUILD_ASKED_FOR_TOR);

        tor_ctx(&ctx, ZCL_OPERATOR_LANE_DEV);
        ctx.runtime_profile = ZCL_RUNTIME_ONION_NODE;
        ok = ok && tor_code_is(app_tor_policy_refusal_code(&ctx, false),
                               APP_TOR_REFUSE_STUB_BUILD_ASKED_FOR_TOR);

        APPCTX_CHECK("stub build refuses -tor, -onion-persist, "
                     "-onion-rotate and -profile=onion-node", ok);
    }

    /* The same argv on a real-Tor build is admissible: the refusal is about
     * what the binary CAN do, not about disliking the flags. A test that
     * only proved the refusal would pass just as well against a function
     * that refused everything. */
    {
        bool ok = true;

        tor_ctx(&ctx, ZCL_OPERATOR_LANE_CANONICAL);
        ctx.tor = true;
        ctx.onion_persist = true;
        ok = ok && app_tor_policy_refusal_code(&ctx, true) == NULL;

        tor_ctx(&ctx, ZCL_OPERATOR_LANE_CANONICAL);
        ctx.runtime_profile = ZCL_RUNTIME_ONION_NODE;
        ok = ok && app_tor_policy_refusal_code(&ctx, true) == NULL;

        /* And a stub build that asks for NOTHING still boots — the refusal
         * is triggered by the ask, not by the build identity alone. */
        tor_ctx(&ctx, ZCL_OPERATOR_LANE_DEV);
        ok = ok && app_tor_policy_refusal_code(&ctx, false) == NULL;

        APPCTX_CHECK("a real-Tor build admits every onion ask, and a stub "
                     "build that asks for nothing still boots", ok);
    }

    /* (b) The dev escape is refused on every lane that serves the network,
     * and admitted on the lanes it exists for. */
    {
        bool ok = true;
        const enum zcl_operator_lane serving[] = {
            ZCL_OPERATOR_LANE_CANONICAL,
            ZCL_OPERATOR_LANE_SOAK,
            ZCL_OPERATOR_LANE_STANDBY,
        };
        const enum zcl_operator_lane offline[] = {
            ZCL_OPERATOR_LANE_DEV,
            ZCL_OPERATOR_LANE_TEST,
            ZCL_OPERATOR_LANE_COPY,
            ZCL_OPERATOR_LANE_UNKNOWN,
        };

        for (size_t i = 0; i < sizeof(serving) / sizeof(serving[0]); i++) {
            /* Refused on a real-Tor build AND on a stub build: the escape is
             * about who may weaken the rule, not about which rule. */
            tor_ctx(&ctx, serving[i]);
            ctx.allow_tor_stub_dev = true;
            ok = ok && tor_code_is(app_tor_policy_refusal_code(&ctx, false),
                                   APP_TOR_REFUSE_STUB_ESCAPE_ON_SERVING_LANE);
            ok = ok && tor_code_is(app_tor_policy_refusal_code(&ctx, true),
                                   APP_TOR_REFUSE_STUB_ESCAPE_ON_SERVING_LANE);

            /* The escape must not buy a serving lane past the stub-build
             * refusal either — it is still the escape that is refused. */
            ctx.tor = true;
            ok = ok && tor_code_is(app_tor_policy_refusal_code(&ctx, false),
                                   APP_TOR_REFUSE_STUB_ESCAPE_ON_SERVING_LANE);
        }

        for (size_t i = 0; i < sizeof(offline) / sizeof(offline[0]); i++) {
            tor_ctx(&ctx, offline[i]);
            ctx.allow_tor_stub_dev = true;
            ctx.tor = true;
            ok = ok && app_tor_policy_refusal_code(&ctx, false) == NULL;
        }

        APPCTX_CHECK("-allow-tor-stub-dev is refused on canonical, soak and "
                     "standby and admitted on dev/test/copy", ok);
    }

    /* (c) -no-tor is refused on every lane that serves the network. */
    {
        bool ok = true;
        const enum zcl_operator_lane serving[] = {
            ZCL_OPERATOR_LANE_CANONICAL,
            ZCL_OPERATOR_LANE_SOAK,
            ZCL_OPERATOR_LANE_STANDBY,
        };
        const enum zcl_operator_lane offline[] = {
            ZCL_OPERATOR_LANE_DEV,
            ZCL_OPERATOR_LANE_TEST,
            ZCL_OPERATOR_LANE_COPY,
            ZCL_OPERATOR_LANE_UNKNOWN,
        };

        for (size_t i = 0; i < sizeof(serving) / sizeof(serving[0]); i++) {
            tor_ctx(&ctx, serving[i]);
            ctx.no_tor = true;
            ok = ok && tor_code_is(app_tor_policy_refusal_code(&ctx, true),
                                   APP_TOR_REFUSE_DISABLE_ON_SERVING_LANE);
            ok = ok && tor_code_is(app_tor_policy_refusal_code(&ctx, false),
                                   APP_TOR_REFUSE_DISABLE_ON_SERVING_LANE);
        }

        for (size_t i = 0; i < sizeof(offline) / sizeof(offline[0]); i++) {
            tor_ctx(&ctx, offline[i]);
            ctx.no_tor = true;
            ok = ok && app_tor_policy_refusal_code(&ctx, true) == NULL;
        }

        APPCTX_CHECK("-no-tor is refused on canonical, soak and standby and "
                     "admitted on dev/test/copy", ok);
    }

    APPCTX_CHECK("the network-serving lanes are exactly canonical, soak and "
                 "standby",
                 app_operator_lane_serves_network(
                     ZCL_OPERATOR_LANE_CANONICAL) &&
                 app_operator_lane_serves_network(ZCL_OPERATOR_LANE_SOAK) &&
                 app_operator_lane_serves_network(ZCL_OPERATOR_LANE_STANDBY) &&
                 !app_operator_lane_serves_network(ZCL_OPERATOR_LANE_DEV) &&
                 !app_operator_lane_serves_network(ZCL_OPERATOR_LANE_TEST) &&
                 !app_operator_lane_serves_network(ZCL_OPERATOR_LANE_COPY) &&
                 !app_operator_lane_serves_network(
                     ZCL_OPERATOR_LANE_UNKNOWN));

    /* Tor is ON by default on a real build, OFF only for -no-tor, and never
     * claimed by a stub build. */
    APPCTX_CHECK("Tor starts by default on a real build and never on a stub "
                 "build",
                 app_tor_should_start(true, false) &&
                 !app_tor_should_start(true, true) &&
                 !app_tor_should_start(false, false) &&
                 !app_tor_should_start(false, true));

    /* A NULL context must not be read as "nothing was asked for" by
     * accident; it is simply not a refusal this function can decide. */
    APPCTX_CHECK("a NULL context yields no refusal code",
                 app_tor_policy_refusal_code(NULL, false) == NULL &&
                 app_tor_policy_refusal_code(NULL, true) == NULL);

    /* app_tor_real_build_linked() reads a link-time fact, so this binary can
     * only observe its OWN answer — but that answer must be stable, not a
     * function of when it is called. */
    APPCTX_CHECK("the linked-Tor fact is stable within a process",
                 app_tor_real_build_linked() == app_tor_real_build_linked());

    return failures;
}
int test_app_context(void)
{
    int failures = 0;

    {
        struct app_context ctx;
        memset(&ctx, 0xff, sizeof(ctx));

        app_context_defaults(&ctx);

        APPCTX_CHECK("defaults select full public node profile",
                     ctx.datadir == NULL &&
                     ctx.params_dir == NULL &&
                     ctx.rpc_port == 18232 &&
                     ctx.p2p_port == 8033 &&
                     ctx.https_port == 8443 &&
                     ctx.fs_port == 18034 &&
                     ctx.listen &&
                     ctx.checkpoints_enabled &&
                     ctx.runtime_profile == ZCL_RUNTIME_FULL &&
                     ctx.operator_lane == ZCL_OPERATOR_LANE_UNKNOWN &&
                     ctx.par_workers == 0 &&
                     !ctx.no_services &&
                     !ctx.no_legacy_auto_import &&
                     !ctx.load_verify_boot &&
                     ctx.load_snapshot_at_own_height == NULL);
    }

    {
        enum zcl_runtime_profile profile = ZCL_RUNTIME_FULL;
        bool ok = true;

        ok = ok && app_runtime_profile_parse("full", &profile) &&
             profile == ZCL_RUNTIME_FULL;
        ok = ok && app_runtime_profile_parse("zclassic", &profile) &&
             profile == ZCL_RUNTIME_ZCLASSIC_ONLY;
        ok = ok && app_runtime_profile_parse("zclassic-only", &profile) &&
             profile == ZCL_RUNTIME_ZCLASSIC_ONLY;
        ok = ok && app_runtime_profile_parse("explorer", &profile) &&
             profile == ZCL_RUNTIME_EXPLORER;
        ok = ok && app_runtime_profile_parse("onion", &profile) &&
             profile == ZCL_RUNTIME_ONION_NODE;
        ok = ok && app_runtime_profile_parse("onion-node", &profile) &&
             profile == ZCL_RUNTIME_ONION_NODE;
        ok = ok && app_runtime_profile_parse("legacy", &profile) &&
             profile == ZCL_RUNTIME_LEGACY_COMPAT;
        ok = ok && app_runtime_profile_parse("legacy-compat", &profile) &&
             profile == ZCL_RUNTIME_LEGACY_COMPAT;
        ok = ok && !app_runtime_profile_parse("unknown", &profile);
        ok = ok && !app_runtime_profile_parse(NULL, &profile);
        ok = ok && !app_runtime_profile_parse("full", NULL);

        APPCTX_CHECK("runtime profile names and aliases parse", ok);
    }

    APPCTX_CHECK("runtime profile names are stable",
                 strcmp(app_runtime_profile_name(ZCL_RUNTIME_FULL), "full") == 0 &&
                 strcmp(app_runtime_profile_name(ZCL_RUNTIME_ZCLASSIC_ONLY),
                        "zclassic-only") == 0 &&
                 strcmp(app_runtime_profile_name(ZCL_RUNTIME_EXPLORER),
                        "explorer") == 0 &&
                 strcmp(app_runtime_profile_name(ZCL_RUNTIME_ONION_NODE),
                        "onion-node") == 0 &&
                 strcmp(app_runtime_profile_name(ZCL_RUNTIME_LEGACY_COMPAT),
                        "legacy-compat") == 0 &&
                 strcmp(app_runtime_profile_name((enum zcl_runtime_profile)999),
                        "unknown") == 0);

    {
        enum zcl_operator_lane lane = ZCL_OPERATOR_LANE_UNKNOWN;
        bool ok = true;

        ok = ok && app_operator_lane_parse("canonical", &lane) &&
             lane == ZCL_OPERATOR_LANE_CANONICAL;
        ok = ok && app_operator_lane_parse("live", &lane) &&
             lane == ZCL_OPERATOR_LANE_CANONICAL;
        ok = ok && app_operator_lane_parse("main", &lane) &&
             lane == ZCL_OPERATOR_LANE_CANONICAL;
        ok = ok && app_operator_lane_parse("soak", &lane) &&
             lane == ZCL_OPERATOR_LANE_SOAK;
        ok = ok && app_operator_lane_parse("dev", &lane) &&
             lane == ZCL_OPERATOR_LANE_DEV;
        ok = ok && app_operator_lane_parse("development", &lane) &&
             lane == ZCL_OPERATOR_LANE_DEV;
        ok = ok && app_operator_lane_parse("test", &lane) &&
             lane == ZCL_OPERATOR_LANE_TEST;
        ok = ok && app_operator_lane_parse("ci", &lane) &&
             lane == ZCL_OPERATOR_LANE_TEST;
        ok = ok && app_operator_lane_parse("copy", &lane) &&
             lane == ZCL_OPERATOR_LANE_COPY;
        ok = ok && app_operator_lane_parse("repro", &lane) &&
             lane == ZCL_OPERATOR_LANE_COPY;
        ok = ok && app_operator_lane_parse("standby", &lane) &&
             lane == ZCL_OPERATOR_LANE_STANDBY;
        ok = ok && app_operator_lane_parse("unknown", &lane) &&
             lane == ZCL_OPERATOR_LANE_UNKNOWN;
        ok = ok && !app_operator_lane_parse("prod", &lane);
        ok = ok && !app_operator_lane_parse(NULL, &lane);
        ok = ok && !app_operator_lane_parse("canonical", NULL);

        APPCTX_CHECK("operator lane names and aliases parse", ok);
    }

    APPCTX_CHECK("operator lane names are stable",
                 strcmp(app_operator_lane_name(ZCL_OPERATOR_LANE_UNKNOWN),
                        "unknown") == 0 &&
                 strcmp(app_operator_lane_name(ZCL_OPERATOR_LANE_CANONICAL),
                        "canonical") == 0 &&
                 strcmp(app_operator_lane_name(ZCL_OPERATOR_LANE_SOAK),
                        "soak") == 0 &&
                 strcmp(app_operator_lane_name(ZCL_OPERATOR_LANE_DEV),
                        "dev") == 0 &&
                 strcmp(app_operator_lane_name(ZCL_OPERATOR_LANE_TEST),
                        "test") == 0 &&
                 strcmp(app_operator_lane_name(ZCL_OPERATOR_LANE_COPY),
                        "copy") == 0 &&
                 strcmp(app_operator_lane_name(ZCL_OPERATOR_LANE_STANDBY),
                        "standby") == 0 &&
                 strcmp(app_operator_lane_name((enum zcl_operator_lane)999),
                        "unknown") == 0);

    APPCTX_CHECK("zclassic-only profile stays lean",
                 !app_runtime_profile_has_explorer(ZCL_RUNTIME_ZCLASSIC_ONLY) &&
                 !app_runtime_profile_has_store(ZCL_RUNTIME_ZCLASSIC_ONLY) &&
                 !app_runtime_profile_has_file_service(
                     ZCL_RUNTIME_ZCLASSIC_ONLY) &&
                 !app_runtime_profile_has_onion(
                     ZCL_RUNTIME_ZCLASSIC_ONLY, false) &&
                 app_runtime_profile_has_onion(
                     ZCL_RUNTIME_ZCLASSIC_ONLY, true));

    APPCTX_CHECK("application profiles expose expected surfaces",
                 app_runtime_profile_has_explorer(ZCL_RUNTIME_FULL) &&
                 app_runtime_profile_has_store(ZCL_RUNTIME_FULL) &&
                 app_runtime_profile_has_file_service(ZCL_RUNTIME_FULL) &&
                 app_runtime_profile_has_explorer(ZCL_RUNTIME_EXPLORER) &&
                 !app_runtime_profile_has_store(ZCL_RUNTIME_EXPLORER) &&
                 !app_runtime_profile_has_file_service(ZCL_RUNTIME_EXPLORER) &&
                 app_runtime_profile_has_explorer(ZCL_RUNTIME_ONION_NODE) &&
                 app_runtime_profile_has_store(ZCL_RUNTIME_ONION_NODE) &&
                 app_runtime_profile_has_file_service(ZCL_RUNTIME_ONION_NODE) &&
                 app_runtime_profile_has_onion(ZCL_RUNTIME_ONION_NODE, false) &&
                 app_runtime_profile_has_explorer(ZCL_RUNTIME_LEGACY_COMPAT) &&
                 app_runtime_profile_has_store(ZCL_RUNTIME_LEGACY_COMPAT) &&
                 app_runtime_profile_has_file_service(ZCL_RUNTIME_LEGACY_COMPAT));

    failures += test_app_context_tor_policy();

    return failures;
}
