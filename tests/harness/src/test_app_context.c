/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot.h"
#include "config/args.h"
#include "controllers/observation_site_controller.h"
#include "net/addrman.h"
#include "net/connman.h"
#include "net/netbase.h"
#include "net/nat.h"
#include "net/rom_fetch.h"
#include "net/file_service.h"
#include "config/boot_bundle_fetch.h"
#include "net/onion_service.h"
#include "rpc/legacy_rpc_client.h"
#include "services/mesh_observation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

/* (a) A stub-stamped binary refuses every way of asking for an onion.
 * Each ask is checked on its own, because one arm covering for another
 * is exactly how a flag stops being policed. */
static int tor_policy_stub_asks_refused(void)
{
    int failures = 0;
    struct app_context ctx;
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
    return failures;
}

/* The same argv on a real-Tor build is admissible: the refusal is about
 * what the binary CAN do, not about disliking the flags. A test that
 * only proved the refusal would pass just as well against a function
 * that refused everything. */
static int tor_policy_real_asks_admitted(void)
{
    int failures = 0;
    struct app_context ctx;
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
    return failures;
}

/* (b) The dev escape is refused on every lane that serves the network,
 * and admitted on the lanes it exists for. */
static int tor_policy_escape_on_lanes(void)
{
    int failures = 0;
    struct app_context ctx;
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
    return failures;
}

/* (c) -no-tor is refused on every lane that serves the network. */
static int tor_policy_no_tor_on_lanes(void)
{
    int failures = 0;
    struct app_context ctx;
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
    return failures;
}

static int tor_policy_serving_lanes_exact(void)
{
    int failures = 0;

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
    return failures;
}

static int tor_policy_start_and_null(void)
{
    int failures = 0;

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

static int test_app_context_tor_policy(void)
{
    int failures = 0;

    failures += tor_policy_stub_asks_refused();
    failures += tor_policy_real_asks_admitted();
    failures += tor_policy_escape_on_lanes();
    failures += tor_policy_no_tor_on_lanes();
    failures += tor_policy_serving_lanes_exact();
    failures += tor_policy_start_and_null();
    return failures;
}
static int test_nonmainnet_legacy_import_default(void)
{
    int failures = 0;
    bool show_metrics = false;
    struct app_context ctx;
    char *main_argv[] = { "z23" };
    char *regtest_argv[] = { "z23", "-regtest" };
    char *testnet_argv[] = { "z23", "-testnet" };

    app_context_defaults(&ctx);
    bool mainnet = args_parse_node_options(1, main_argv, &ctx,
                                           &show_metrics) == -1 &&
                   !ctx.no_legacy_auto_import;
    app_context_defaults(&ctx);
    bool regtest = args_parse_node_options(2, regtest_argv, &ctx,
                                           &show_metrics) == -1 &&
                   ctx.no_legacy_auto_import;
    app_context_defaults(&ctx);
    bool testnet = args_parse_node_options(2, testnet_argv, &ctx,
                                           &show_metrics) == -1 &&
                   ctx.no_legacy_auto_import;

    APPCTX_CHECK("non-mainnet modes refuse automatic mainnet legacy import",
                 mainnet && regtest && testnet);
    return failures;
}

/* ── -onlynet=onion / -observation=0 (private review node) ─────────── */
#define ONLYNET_ONION_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
#define ONLYNET_ONION_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"

static int onlynet_parse(char **argv, int argc, struct app_context *ctx)
{
    bool show_metrics = false;
    app_context_defaults(ctx);
    return args_parse_node_options(argc, argv, ctx, &show_metrics);
}

static int test_onlynet_onion_args(void)
{
    int failures = 0;
    struct app_context ctx;
    char *a_ok[] = { "z23", "-onlynet=onion", "-bind=127.0.0.1",
                     "-observation=0" };
    char *a_bad[] = { "z23", "-onlynet=clearnet" };
    char *a_obs[] = { "z23", "-observation=0" };
    char *a_def[] = { "z23" };

    int rc = onlynet_parse(a_ok, 4, &ctx);
    if (app_tor_real_build_linked())
        APPCTX_CHECK("-onlynet=onion -observation=0 parses",
                     rc == -1 && ctx.onlynet_onion && ctx.observation_off);
    else
        APPCTX_CHECK("-onlynet=onion is refused on a tor-stub build",
                     rc == 1);
    APPCTX_CHECK("an unknown -onlynet value is refused",
                 onlynet_parse(a_bad, 2, &ctx) == 1);
    APPCTX_CHECK("-observation=0 alone parses",
                 onlynet_parse(a_obs, 2, &ctx) == -1 &&
                 ctx.observation_off && !ctx.onlynet_onion);
    APPCTX_CHECK("both switches default off",
                 onlynet_parse(a_def, 1, &ctx) == -1 &&
                 !ctx.observation_off && !ctx.onlynet_onion);

    /* The pure admission, with the Tor identity injected. */
    app_context_defaults(&ctx);
    APPCTX_CHECK("flag off: nothing to refuse",
                 app_onlynet_onion_refusal(&ctx, false) == NULL);
    ctx.onlynet_onion = true;
    ctx.p2p_bind_address = "127.0.0.1";
    APPCTX_CHECK("-onlynet=onion + loopback bind + real tor is accepted",
                 app_onlynet_onion_refusal(&ctx, true) == NULL);
    APPCTX_CHECK("-onlynet=onion on a tor-stub build is refused",
                 app_onlynet_onion_refusal(&ctx, false) != NULL);
    ctx.no_tor = true;
    APPCTX_CHECK("-onlynet=onion with -no-tor is refused",
                 app_onlynet_onion_refusal(&ctx, true) != NULL);
    ctx.no_tor = false;
    ctx.addnode_peers[ctx.n_addnode_peers++] = "1.2.3.4:8033";
    APPCTX_CHECK("-onlynet=onion with a clearnet -addnode is refused",
                 app_onlynet_onion_refusal(&ctx, true) != NULL);
    ctx.addnode_peers[0] = ONLYNET_ONION_A ":8033";
    APPCTX_CHECK("-onlynet=onion with an .onion -addnode is accepted",
                 app_onlynet_onion_refusal(&ctx, true) == NULL);
    ctx.p2p_bind_address = NULL;
    APPCTX_CHECK("-onlynet=onion without -bind is refused (no inbound)",
                 app_onlynet_onion_refusal(&ctx, true) != NULL);
    ctx.p2p_bind_address = "0.0.0.0";
    APPCTX_CHECK("-onlynet=onion with a public bind is refused",
                 app_onlynet_onion_refusal(&ctx, true) != NULL);
    return failures;
}

static int onlynet_addrman_count(struct connman *cm)
{
    zcl_mutex_lock(&cm->manager.addrman.cs);
    size_t n = addrman_size(&cm->manager.addrman);
    zcl_mutex_unlock(&cm->manager.addrman.cs);
    return (int)n;
}

static int test_onlynet_onion_dial_and_seed_walk(void)
{
    int failures = 0;
    static const char dir[] =
        "{\"nodes\":[{\"onion\":\"" ONLYNET_ONION_B "\",\"port\":8033,"
        "\"clearnet_ip\":\"93.184.216.34\",\"clearnet_port\":8033},"
        "{\"clearnet_ip\":\"1.1.1.1\",\"clearnet_port\":8033}]}";
    struct onion_relay_hint hints[4];
    memset(hints, 0, sizeof(hints));
    APPCTX_CHECK("fixture directory carries an onion hint to harvest",
                 onion_directory_parse_relay_hints(dir, NULL, hints, 4) == 1);

    chain_params_select(CHAIN_MAIN);
    struct connman cm;
    struct node_signals sigs;
    memset(&sigs, 0, sizeof(sigs));
    bool ok = connman_init(&cm, chain_params_get(), &sigs);
    APPCTX_CHECK("connman_init for the seed-walk fixture", ok);
    if (!ok)
        return failures;

    netbase_set_onlynet_onion(false);
    int before = onlynet_addrman_count(&cm);
    int added = connman_apply_onion_seed_directory_for_test(
        &cm, ONLYNET_ONION_A, (const uint8_t *)dir, sizeof(dir) - 1);
    APPCTX_CHECK("flag off: the walk imports clearnet endpoints (unchanged)",
                 added == 2 && onlynet_addrman_count(&cm) == before + 2);
    connman_free(&cm);

    if (!connman_init(&cm, chain_params_get(), &sigs))
        return failures + 1;
    netbase_set_onlynet_onion(true);
    before = onlynet_addrman_count(&cm);
    added = connman_apply_onion_seed_directory_for_test(
        &cm, ONLYNET_ONION_A, (const uint8_t *)dir, sizeof(dir) - 1);
    APPCTX_CHECK("-onlynet=onion: the walk adds zero clearnet endpoints",
                 added == 0 && onlynet_addrman_count(&cm) == before);

    struct net_service clear, loop;
    net_service_init(&clear);
    net_service_init(&loop);
    const unsigned char clear_ip[4] = { 93, 184, 216, 34 };
    const unsigned char loop_ip[4] = { 127, 0, 0, 1 };
    net_addr_set_ipv4(&clear.addr, clear_ip);
    net_addr_set_ipv4(&loop.addr, loop_ip);
    clear.port = loop.port = 8033;
    APPCTX_CHECK("-onlynet=onion: the dialer admits no clearnet candidate",
                 !netbase_clearnet_dial_allowed(&clear) &&
                 netbase_clearnet_dial_allowed(&loop));
    zcl_socket_t s = ZCL_INVALID_SOCKET;
    APPCTX_CHECK("-onlynet=onion: connect_socket_start refuses clearnet",
                 connect_socket_start(&clear, &s) ==
                     ZCL_CONNECT_START_ERROR && s == ZCL_INVALID_SOCKET);
    struct net_address caddr;
    net_address_init(&caddr);
    caddr.svc = clear;
    connman_open_connection(&cm, &caddr);
    APPCTX_CHECK("-onlynet=onion: a clearnet addnode is not queued",
                 cm.num_addnodes == 0);
    netbase_set_onlynet_onion(false);
    APPCTX_CHECK("flag off: every dial is admitted again",
                 netbase_clearnet_dial_allowed(&clear));
    connman_free(&cm);
    return failures;
}

static size_t onlynet_test_peer_source(void *ctx,
                                       struct boot_bundle_peer_seed *out,
                                       size_t max)
{
    (void)ctx;
    if (max < 1)
        return 0;
    memset(&out[0], 0, sizeof(out[0]));
    snprintf(out[0].host, sizeof(out[0].host), "203.0.113.5");
    out[0].port = 18034;
    return 1;
}

/* ── -onlynet=onion review fixes: boot fetch, operator flags, DNS, NAT ─ */
static int test_onlynet_clearnet_leaks_closed(void)
{
    int failures = 0;
    struct app_context ctx;

    /* 1. boot bundle fetch: no hardcoded clearnet seed with the flag. */
    boot_bundle_fetch_set_peer_source(onlynet_test_peer_source, NULL);
    app_context_defaults(&ctx);
    size_t open_seeds = boot_bundle_fetch_seed_count(&ctx);
    ctx.onlynet_onion = true;
    APPCTX_CHECK("default: the bundle fetch offers a discovered clearnet peer",
                 open_seeds == 1);
    APPCTX_CHECK("-onlynet=onion: the bundle fetch seed list holds no "
                 "clearnet seed", boot_bundle_fetch_seed_count(&ctx) == 0);
    boot_bundle_fetch_set_peer_source(NULL, NULL);

    /* 1b. the rom fetch transport refuses a clearnet host before resolving. */
    char buf[256];
    unsigned before = rom_fetch_resolve_count_for_test();
    netbase_set_onlynet_onion(true);
    APPCTX_CHECK("-onlynet=onion: rom fetch to a clearnet host fails",
                 !rom_fetch_get_directory("example.com", 18034, buf,
                                          sizeof(buf)));
    APPCTX_CHECK("-onlynet=onion: ... and never reached getaddrinfo",
                 rom_fetch_resolve_count_for_test() == before);
    netbase_set_onlynet_onion(false);
    (void)rom_fetch_get_directory("localhost", 1, buf, sizeof(buf));
    APPCTX_CHECK("default: the rom fetch route still resolves",
                 rom_fetch_resolve_count_for_test() == before + 1);

    /* 2. operator flags that reach fs_client_sync are refused. */
    const char *const flag_cases[] = { "-fileservice=203.0.113.9",
                                       "-filesync=203.0.113.9",
                                       "-allow-clearnet-snapshot-fetch" };
    for (size_t i = 0; i < sizeof(flag_cases) / sizeof(flag_cases[0]); i++) {
        char *argv[] = { "z23", "-onlynet=onion", "-bind=127.0.0.1",
                         (char *)flag_cases[i] };
        APPCTX_CHECK(flag_cases[i],
                     ((void)onlynet_parse(argv, 4, &ctx), ctx.onlynet_onion &&
                      app_onlynet_onion_refusal(&ctx, true) != NULL));
    }
    app_context_defaults(&ctx);
    ctx.onlynet_onion = true;
    ctx.p2p_bind_address = "127.0.0.1";
    APPCTX_CHECK("none of those flags: accepted",
                 app_onlynet_onion_refusal(&ctx, true) == NULL);

    /* defence in depth: the client and the sockaddr gate refuse clearnet. */
    netbase_set_onlynet_onion(true);
    struct sockaddr_in pub = { .sin_family = AF_INET };
    struct sockaddr_in lo = { .sin_family = AF_INET };
    pub.sin_addr.s_addr = htonl(0xCB007109u);
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    APPCTX_CHECK("-onlynet=onion: fs_client_sync refuses a clearnet host",
                 !fs_client_sync("203.0.113.9", 18034, "build", NULL));
    APPCTX_CHECK("-onlynet=onion: a public sockaddr is refused",
                 !netbase_sockaddr_dial_allowed((struct sockaddr *)&pub,
                                                sizeof(pub)));
    APPCTX_CHECK("-onlynet=onion: a loopback sockaddr is allowed",
                 netbase_sockaddr_dial_allowed((struct sockaddr *)&lo,
                                               sizeof(lo)));
    APPCTX_CHECK("-onlynet=onion: host strings",
                 !netbase_host_dial_allowed("example.com") &&
                 !netbase_host_dial_allowed("203.0.113.9:8033") &&
                 netbase_host_dial_allowed("127.0.0.1:8033") &&
                 netbase_host_dial_allowed("localhost") &&
                 netbase_host_dial_allowed(ONLYNET_ONION_A ":8033"));

    /* 4a. a clearnet DNS name never resolves (lookup_host chokepoint). */
    struct net_addr res[1];
    size_t nres = 0;
    APPCTX_CHECK("-onlynet=onion: lookup_host refuses a DNS name",
                 !lookup_host("example.com", res, 1, &nres, true));

    /* 3. NAT / UPnP is never probed. */
    unsigned probes = nat_probe_count_for_test();
    uint8_t ip[4];
    APPCTX_CHECK("-onlynet=onion: port mapping is skipped",
                 !nat_add_port_mapping(8033, 8033, 60, "TCP", ip) &&
                 !nat_discover_public_ip(ip) &&
                 nat_probe_count_for_test() == probes);
    netbase_set_onlynet_onion(false);
    (void)nat_discover_public_ip(ip);
    APPCTX_CHECK("default: the NAT probe still runs",
                 nat_probe_count_for_test() == probes + 1);

    /* 4b. connman_add_seed_node refuses a clearnet host before resolving. */
    struct connman cm;
    struct node_signals sigs;
    memset(&sigs, 0, sizeof(sigs));
    chain_params_select(CHAIN_MAIN);
    if (!connman_init(&cm, chain_params_get(), &sigs)) {
        APPCTX_CHECK("connman_init for the seed-node fixture", false);
        return failures;
    }
    netbase_set_onlynet_onion(true);
    int addrs = onlynet_addrman_count(&cm);
    connman_add_seed_node(&cm, "8.8.8.8", 8033);
    APPCTX_CHECK("-onlynet=onion: a clearnet seed node is not added",
                 onlynet_addrman_count(&cm) == addrs);
    netbase_set_onlynet_onion(false);
    connman_add_seed_node(&cm, "8.8.8.8", 8033);
    APPCTX_CHECK("default: the same seed node is added",
                 onlynet_addrman_count(&cm) == addrs + 1);
    connman_free(&cm);
    return failures;
}

/* A response buffer under 1 KiB must not fall through to the telemetry. */
/* The legacy zclassicd RPC client (mirror sync, UTXO parity) dials a numeric
 * host: under -onlynet=onion a non-loopback one is refused before connect.
 * 192.0.2.1 is TEST-NET-1, never routed. */
static int test_onlynet_legacy_rpc(void)
{
    int failures = 0;
    char err[160] = {0};
    char *resp = NULL;
    netbase_set_onlynet_onion(true);
    bool ok = legacy_rpc_call("192.0.2.1", 8023, "u", "p", "{}", &resp,
                              err, sizeof(err));
    netbase_set_onlynet_onion(false);
    free(resp);
    APPCTX_CHECK("-onlynet=onion: the legacy RPC refuses a clearnet host "
                 "before connect", !ok && strstr(err, "refused") != NULL);
    return failures;
}

static int test_observation_small_buffer(void)
{
    int failures = 0;
    uint8_t resp[512];
    memset(resp, 'X', sizeof(resp));
    mesh_observation_set_public_disabled(true);
    size_t n = observation_site_handle_request("GET", "/observation.json",
                                               NULL, 0, resp, sizeof(resp));
    APPCTX_CHECK("-observation=0 with a 512-byte buffer: 404, no telemetry",
                 n > 0 && n < sizeof(resp) &&
                 memcmp(resp, "HTTP/1.1 404", 12) == 0);
    mesh_observation_set_public_disabled(false);
    return failures;
}

static int test_observation_switch(void)
{
    int failures = 0;
    uint8_t resp[4096];
    mesh_observation_set_public_disabled(true);
    size_t n = observation_site_handle_request("GET", "/observation.json",
                                               NULL, 0, resp,
                                               sizeof(resp) - 1);
    resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = 0;
    APPCTX_CHECK("-observation=0: 404 with the operator reason",
                 n > 0 && strstr((char *)resp, "404 Not Found") &&
                 strstr((char *)resp,
                        "disabled by operator (-observation=0)"));
    mesh_observation_set_public_disabled(false);
    n = observation_site_handle_request("GET", "/observation.json", NULL, 0,
                                        resp, sizeof(resp) - 1);
    resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = 0;
    APPCTX_CHECK("default: /observation.json is not disabled",
                 n == 0 || (!strstr((char *)resp, "404 Not Found") &&
                            !strstr((char *)resp, "disabled by operator")));
    return failures;
}

static bool app_context_defaults_paths_ports(const struct app_context *ctx)
{
    return ctx->datadir == NULL &&
           ctx->params_dir == NULL &&
           ctx->rpc_port == 18232 &&
           ctx->p2p_port == 8033 &&
           ctx->https_port == 8443;
}

static bool app_context_defaults_listen_profile(const struct app_context *ctx)
{
    return ctx->fs_port == 18034 &&
           ctx->listen &&
           ctx->checkpoints_enabled &&
           ctx->runtime_profile == ZCL_RUNTIME_FULL &&
           ctx->operator_lane == ZCL_OPERATOR_LANE_UNKNOWN;
}

static bool app_context_defaults_workers_flags(const struct app_context *ctx)
{
    return ctx->par_workers == 0 &&
           !ctx->no_services &&
           !ctx->no_legacy_auto_import &&
           !ctx->load_verify_boot &&
           ctx->load_snapshot_at_own_height == NULL;
}

static int app_context_check_defaults(void)
{
    int failures = 0;
    struct app_context ctx;
    memset(&ctx, 0xff, sizeof(ctx));

    app_context_defaults(&ctx);

    APPCTX_CHECK("defaults select full public node profile",
                 app_context_defaults_paths_ports(&ctx) &&
                 app_context_defaults_listen_profile(&ctx) &&
                 app_context_defaults_workers_flags(&ctx));
    return failures;
}

static int app_context_check_profile_parse(void)
{
    int failures = 0;
    enum zcl_runtime_profile profile = ZCL_RUNTIME_FULL;
    bool ok = true;
    static const struct {
        const char *name;
        enum zcl_runtime_profile want;
    } rows[] = {
        { "full", ZCL_RUNTIME_FULL },
        { "zclassic", ZCL_RUNTIME_ZCLASSIC_ONLY },
        { "zclassic-only", ZCL_RUNTIME_ZCLASSIC_ONLY },
        { "explorer", ZCL_RUNTIME_EXPLORER },
        { "onion", ZCL_RUNTIME_ONION_NODE },
        { "onion-node", ZCL_RUNTIME_ONION_NODE },
        { "legacy", ZCL_RUNTIME_LEGACY_COMPAT },
        { "legacy-compat", ZCL_RUNTIME_LEGACY_COMPAT },
    };

    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        ok = ok && app_runtime_profile_parse(rows[i].name, &profile) &&
             profile == rows[i].want;
    ok = ok && !app_runtime_profile_parse("unknown", &profile);
    ok = ok && !app_runtime_profile_parse(NULL, &profile);
    ok = ok && !app_runtime_profile_parse("full", NULL);

    APPCTX_CHECK("runtime profile names and aliases parse", ok);
    return failures;
}

static int app_context_check_profile_names(void)
{
    int failures = 0;

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
    return failures;
}

static int app_context_check_lane_parse(void)
{
    int failures = 0;
    enum zcl_operator_lane lane = ZCL_OPERATOR_LANE_UNKNOWN;
    bool ok = true;
    static const struct {
        const char *name;
        enum zcl_operator_lane want;
    } rows[] = {
        { "canonical", ZCL_OPERATOR_LANE_CANONICAL },
        { "live", ZCL_OPERATOR_LANE_CANONICAL },
        { "main", ZCL_OPERATOR_LANE_CANONICAL },
        { "soak", ZCL_OPERATOR_LANE_SOAK },
        { "dev", ZCL_OPERATOR_LANE_DEV },
        { "development", ZCL_OPERATOR_LANE_DEV },
        { "test", ZCL_OPERATOR_LANE_TEST },
        { "ci", ZCL_OPERATOR_LANE_TEST },
        { "copy", ZCL_OPERATOR_LANE_COPY },
        { "repro", ZCL_OPERATOR_LANE_COPY },
        { "standby", ZCL_OPERATOR_LANE_STANDBY },
        { "unknown", ZCL_OPERATOR_LANE_UNKNOWN },
    };

    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        ok = ok && app_operator_lane_parse(rows[i].name, &lane) &&
             lane == rows[i].want;
    ok = ok && !app_operator_lane_parse("prod", &lane);
    ok = ok && !app_operator_lane_parse(NULL, &lane);
    ok = ok && !app_operator_lane_parse("canonical", NULL);

    APPCTX_CHECK("operator lane names and aliases parse", ok);
    return failures;
}

static int app_context_check_lane_names(void)
{
    int failures = 0;

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
    return failures;
}

static int app_context_check_zclassic_lean(void)
{
    int failures = 0;

    APPCTX_CHECK("zclassic-only profile stays lean",
                 !app_runtime_profile_has_explorer(ZCL_RUNTIME_ZCLASSIC_ONLY) &&
                 !app_runtime_profile_has_store(ZCL_RUNTIME_ZCLASSIC_ONLY) &&
                 !app_runtime_profile_has_file_service(
                     ZCL_RUNTIME_ZCLASSIC_ONLY) &&
                 !app_runtime_profile_has_onion(
                     ZCL_RUNTIME_ZCLASSIC_ONLY, false) &&
                 app_runtime_profile_has_onion(
                     ZCL_RUNTIME_ZCLASSIC_ONLY, true));
    return failures;
}

static bool app_context_surfaces_full_explorer(void)
{
    return app_runtime_profile_has_explorer(ZCL_RUNTIME_FULL) &&
           app_runtime_profile_has_store(ZCL_RUNTIME_FULL) &&
           app_runtime_profile_has_file_service(ZCL_RUNTIME_FULL) &&
           app_runtime_profile_has_explorer(ZCL_RUNTIME_EXPLORER) &&
           !app_runtime_profile_has_store(ZCL_RUNTIME_EXPLORER) &&
           !app_runtime_profile_has_file_service(ZCL_RUNTIME_EXPLORER);
}

static bool app_context_surfaces_onion_legacy(void)
{
    return app_runtime_profile_has_explorer(ZCL_RUNTIME_ONION_NODE) &&
           app_runtime_profile_has_store(ZCL_RUNTIME_ONION_NODE) &&
           app_runtime_profile_has_file_service(ZCL_RUNTIME_ONION_NODE) &&
           app_runtime_profile_has_onion(ZCL_RUNTIME_ONION_NODE, false) &&
           app_runtime_profile_has_explorer(ZCL_RUNTIME_LEGACY_COMPAT) &&
           app_runtime_profile_has_store(ZCL_RUNTIME_LEGACY_COMPAT) &&
           app_runtime_profile_has_file_service(ZCL_RUNTIME_LEGACY_COMPAT);
}

static int app_context_check_profile_surfaces(void)
{
    int failures = 0;

    APPCTX_CHECK("application profiles expose expected surfaces",
                 app_context_surfaces_full_explorer() &&
                 app_context_surfaces_onion_legacy());
    return failures;
}

/* ── --help is a short "Start here" block; --help-all is the full list ── */

/* Parse the node flags `z23 <flag>` with stdout redirected to an unnamed
 * temp file; *rc_out is the parser's exit code. Returns the captured text
 * (malloc'd, NUL-terminated), or NULL when capture or the restore failed. */
static char *appctx_capture_help(const char *flag, size_t *len_out,
                                 int *rc_out)
{
    char *argv[] = { "z23", (char *)flag };
    struct app_context ctx;
    bool show_metrics = false;
    FILE *tmp = tmpfile();
    if (!tmp)
        return NULL;
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    if (saved < 0 || dup2(fileno(tmp), STDOUT_FILENO) < 0) {
        if (saved >= 0)
            close(saved);
        fclose(tmp);
        return NULL;
    }
    app_context_defaults(&ctx);
    *rc_out = args_parse_node_options(2, argv, &ctx, &show_metrics);
    fflush(stdout);
    bool restored = dup2(saved, STDOUT_FILENO) >= 0;
    close(saved);
    if (!restored) {
        fclose(tmp);
        fprintf(stderr, "app_context: could not restore stdout after %s\n",
                flag);
        return NULL;
    }
    long n = ftell(tmp);
    char *buf = n >= 0 ? calloc((size_t)n + 1, 1) : NULL;
    if (buf) {
        rewind(tmp);
        size_t got = fread(buf, 1, (size_t)n, tmp);
        buf[got] = '\0';
        *len_out = got;
    }
    fclose(tmp);
    return buf;
}

static size_t appctx_count_lines(const char *s)
{
    size_t n = 0;
    for (; *s; s++)
        n += *s == '\n';
    return n;
}

static int test_help_start_here_block(void)
{
    int failures = 0;
    size_t short_len = 0, all_len = 0;
    int short_rc = -1, all_rc = -1;
    char *shortb = appctx_capture_help("--help", &short_len, &short_rc);
    char *allb = appctx_capture_help("--help-all", &all_len, &all_rc);
    APPCTX_CHECK("help captured", shortb && allb);
    APPCTX_CHECK("--help and --help-all exit 0 from the flag parser",
                 short_rc == 0 && all_rc == 0);
    if (!shortb || !allb) {
        free(shortb);
        free(allb);
        return failures;
    }
    APPCTX_CHECK("--help starts with the Start here block",
                 strncmp(shortb, "Start here:\n", 12) == 0);
    APPCTX_CHECK("--help block is at most 8 lines",
                 appctx_count_lines(shortb) <= 8);
    APPCTX_CHECK("--help names status, wiki, card, discover help, --help-all",
                 strstr(shortb, "z23 status") && strstr(shortb, "z23 wiki") &&
                 strstr(shortb, "z23 card") &&
                 strstr(shortb, "z23 discover help") &&
                 strstr(shortb, "--help-all"));
    APPCTX_CHECK("--help-all keeps the full command list and node options",
                 strstr(allb, "Agent/operator API commands") &&
                 strstr(allb, "-datadir=<dir>") &&
                 appctx_count_lines(allb) > 100);
    APPCTX_CHECK("no doubled z23 prefix on any help entry",
                 strstr(allb, "z23 z23") == NULL &&
                 strstr(allb, "z23 zclassic23") == NULL);
    free(shortb);
    free(allb);
    return failures;
}

int test_app_context(void)
{
    int failures = 0;

    failures += app_context_check_defaults();
    failures += app_context_check_profile_parse();
    failures += app_context_check_profile_names();
    failures += app_context_check_lane_parse();
    failures += app_context_check_lane_names();
    failures += app_context_check_zclassic_lean();
    failures += app_context_check_profile_surfaces();
    failures += test_app_context_tor_policy();
    failures += test_nonmainnet_legacy_import_default();
    failures += test_help_start_here_block();
    failures += test_onlynet_onion_args();
    failures += test_onlynet_onion_dial_and_seed_walk();
    failures += test_observation_switch();
    failures += test_onlynet_clearnet_leaks_closed();
    failures += test_observation_small_buffer();
    failures += test_onlynet_legacy_rpc();

    return failures;
}
