/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for the persistent onion identity (-onion-persist / -onion-rotate).
 *
 * The identity lifecycle (seed mint/reuse/refuse-corrupt, hostname file,
 * rotation archive) is a pure file/crypto layer in tor_integration.c, so
 * every test here runs without a linked or running Tor: a fake datadir's
 * tor_data/onion_service directory plays the HiddenServiceDir, and two
 * onion_identity_ensure() calls play two boots. The install-into-dynhost
 * half only exists in real-Tor builds and is exercised on live boots. */

#include "test/test_core.h"
#include "net/tor_integration.h"
#include "net/net.h"
#include "platform/socket_compat.h"
#include "config/boot.h"
#include "config/args.h"
#include "util/util.h"
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

/* Remove a fixture tree by delegating to the shared test_rm_rf_recursive():
 * the top argument is normalized (trailing separators stripped) and classified
 * with platform_file_shape_read before use, a link is removed as a link and is
 * never enumerated, and each entry is classified before descent. Child paths
 * are rebuilt by name, so ancestor and concurrent swaps are NOT covered. A
 * missing path is logged by the helper and otherwise ignored. */
static void remove_tree(const char *path)
{
    (void)test_rm_rf_recursive(path);
}

static bool file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* The pure derivation must match prop224 bit-for-bit: the pubkey comes
 * from RFC 8032 ed25519 (seed 00..1f → pk 03a107bf…5531b8, cross-checked
 * against an independent implementation) and the checksum/base32 recipe is
 * pinned against Tor's own hs_build_address test vector. */
static int test_onion_identity_vector(void)
{
    int failures = 0;
    printf("test_onion_identity_vector: ");

    uint8_t seed[32];
    for (int i = 0; i < 32; i++)
        seed[i] = (uint8_t)i;

    char addr[57];
    bool ok = onion_identity_address_from_seed(seed, addr, sizeof(addr));
    const char *expected =
        "aoqqpp7tzyil4hlq3umoos6atft6jvrqtosq2xy53sdgiesvgg4bqead";

    if (ok && strcmp(addr, expected) == 0 && strlen(addr) == 56) {
        printf("OK\n");
    } else {
        printf("FAIL (ok=%d addr='%s')\n", ok, addr);
        failures++;
    }

    return failures;
}

/* Hostname file carries the standard "<addr>.onion" content. */
static bool onion_hostname_matches(const char *tmpdir, const char *addr)
{
    char hostname_path[1152];
    snprintf(hostname_path, sizeof(hostname_path),
             "%s/tor_data/onion_service/hostname", tmpdir);
    char expected_hn[80];
    snprintf(expected_hn, sizeof(expected_hn), "%s.onion", addr);
    char hline[128] = "";
    FILE *f = fopen(hostname_path, "r");
    if (f) { if (!fgets(hline, sizeof(hline), f)) hline[0] = '\0'; fclose(f); }
    size_t hl = strlen(hline);
    while (hl > 0 && (hline[hl-1] == '\n' || hline[hl-1] == '\r'))
        hline[--hl] = '\0';
    return strcmp(hline, expected_hn) == 0;
}

/* The seed is key material: mode 0600, never group/world-readable. */
static bool onion_seed_mode_owner_only(const char *tmpdir)
{
    char seed_path[1152];
    snprintf(seed_path, sizeof(seed_path),
             "%s/tor_data/onion_service/identity_seed", tmpdir);
    struct stat st;
    return stat(seed_path, &st) == 0 && (st.st_mode & 0777) == 0600;
}

/* Two onion_identity_ensure() calls on one datadir = two boots: the first
 * mints, the second reuses — the address MUST be identical. */
static int test_onion_identity_stable_across_boots(void)
{
    int failures = 0;
    printf("test_onion_identity_stable_across_boots: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "onion_identity", "boot");

    uint8_t seed1[32], seed2[32];
    char addr1[64], addr2[64];
    bool created1 = false, created2 = true;

    bool ok1 = onion_identity_ensure(tmpdir, seed1, addr1, sizeof(addr1),
                                     &created1);
    /* Simulated restart: call again on the same datadir. */
    bool ok2 = onion_identity_ensure(tmpdir, seed2, addr2, sizeof(addr2),
                                     &created2);

    bool same = ok1 && ok2 && created1 && !created2 &&
                memcmp(seed1, seed2, 32) == 0 &&
                strcmp(addr1, addr2) == 0 && strlen(addr1) == 56;

    bool hostname_ok = onion_hostname_matches(tmpdir, addr1);
    bool mode_ok = onion_seed_mode_owner_only(tmpdir);

    if (same && hostname_ok && mode_ok) {
        printf("OK\n");
    } else {
        printf("FAIL (same=%d hostname=%d mode=%d)\n",
               same, hostname_ok, mode_ok);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* A corrupt (short) seed must be a named refusal, never a silent remint
 * (which would change the address unnoticed). */
static int test_onion_identity_corrupt_seed_refused(void)
{
    int failures = 0;
    printf("test_onion_identity_corrupt_seed_refused: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "onion_identity", "corrupt");

    char dir[1152];
    snprintf(dir, sizeof(dir), "%s/tor_data/onion_service", tmpdir);
    char td[1152];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);
    mkdir(dir, 0700);

    char seed_path[1280];
    snprintf(seed_path, sizeof(seed_path), "%s/identity_seed", dir);
    FILE *f = fopen(seed_path, "w");
    if (!f) {
        printf("SKIP (cannot plant corrupt seed)\n");
        remove_tree(tmpdir);
        return 0;
    }
    fputs("ten bytes!", f);   /* 10 bytes, not 32 */
    fclose(f);

    uint8_t seed[32];
    char addr[64];
    bool refused = !onion_identity_ensure(tmpdir, seed, addr, sizeof(addr),
                                          NULL);
    /* The corrupt file is left in place for the operator to decide. */
    bool left = file_exists(seed_path);

    if (refused && left) {
        printf("OK\n");
    } else {
        printf("FAIL (refused=%d left=%d)\n", refused, left);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* -onion-rotate: archives the old identity under its address and the next
 * boot mints a DIFFERENT one. On an empty datadir rotation is a named
 * no-op (false), never an implicit mint. */
static int test_onion_identity_rotation(void)
{
    int failures = 0;
    printf("test_onion_identity_rotation: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "onion_identity", "rotate");

    uint8_t seed1[32], seed2[32];
    char addr1[64], addr2[64];
    bool ok1 = onion_identity_ensure(tmpdir, seed1, addr1, sizeof(addr1),
                                     NULL);

    char old[64];
    bool rotated = onion_identity_rotate(tmpdir, old, sizeof(old));

    /* Old identity archived under its own address; live seed gone. */
    char arch[1536];
    snprintf(arch, sizeof(arch),
             "%s/tor_data/onion_service/archive/identity_seed.%s",
             tmpdir, addr1);
    char live_seed[1280];
    snprintf(live_seed, sizeof(live_seed),
             "%s/tor_data/onion_service/identity_seed", tmpdir);
    bool archived = rotated && strcmp(old, addr1) == 0 &&
                    file_exists(arch) && !file_exists(live_seed);

    /* Next "boot" mints a fresh, different identity. */
    bool created2 = false;
    bool ok2 = onion_identity_ensure(tmpdir, seed2, addr2, sizeof(addr2),
                                     &created2);
    bool changed = ok1 && ok2 && created2 &&
                   memcmp(seed1, seed2, 32) != 0 &&
                   strcmp(addr1, addr2) != 0;

    if (archived && changed) {
        printf("OK\n");
    } else {
        printf("FAIL (archived=%d changed=%d)\n", archived, changed);
        failures++;
    }

    remove_tree(tmpdir);

    printf("test_onion_identity_rotation_empty_dir: ");
    char tmpdir2[512];
    test_make_tmpdir(tmpdir2, sizeof(tmpdir2), "onion_identity",
                     "rotate_empty");
    char old2[64];
    bool noop = !onion_identity_rotate(tmpdir2, old2, sizeof(old2));
    /* The named no-op must not mint anything implicitly. */
    char seed_path2[1280];
    snprintf(seed_path2, sizeof(seed_path2),
             "%s/tor_data/onion_service/identity_seed", tmpdir2);
    bool nothing_minted = !file_exists(seed_path2);
    if (noop && nothing_minted) {
        printf("OK\n");
    } else {
        printf("FAIL (noop=%d nothing_minted=%d)\n", noop, nothing_minted);
        failures++;
    }
    remove_tree(tmpdir2);

    return failures;
}

/* Default is ephemeral: persistence is OFF until configured, and
 * -onion-rotate without -onion-persist is ignored (prints its named
 * warning). State is reset afterwards — these globals are process-wide
 * and other groups share the test process. */
static int test_onion_ephemeral_default(void)
{
    int failures = 0;
    printf("test_onion_ephemeral_default: ");

    bool def = !tor_integration_persistence_enabled();
    struct tor_onion_port_map initial_map;
    tor_integration_port_map_snapshot(&initial_map);
    tor_integration_configure_identity(true, false);
    bool on = tor_integration_persistence_enabled();
    struct tor_onion_port_map configured_map;
    tor_integration_port_map_snapshot(&configured_map);
    tor_integration_configure_identity(false, true);   /* rotate alone */
    bool rotate_alone_ignored = !tor_integration_persistence_enabled();
    tor_integration_configure_identity(false, false);

    bool map_contract =
        initial_map.state == TOR_ONION_PORT_MAP_DISABLED &&
        initial_map.application_virtual_port == 80 &&
        initial_map.expected_route_count == 1 &&
        !initial_map.complete &&
        configured_map.persistent_identity &&
        configured_map.state == TOR_ONION_PORT_MAP_DISABLED &&
        strcmp(tor_onion_port_map_state_name(configured_map.state),
               "disabled") == 0;

    if (def && on && rotate_alone_ignored && map_contract) {
        printf("OK\n");
    } else {
        printf("FAIL (default=%d on=%d rotate_alone_ignored=%d map=%d)\n",
               def, on, rotate_alone_ignored, map_contract);
        failures++;
    }

    return failures;
}

/* The persisted worker setting reaches the node context; argv takes priority. */
static int test_buildworker_config_args_parse(void)
{
    int failures = 0;
    char dir[512], path[1024];
    test_make_tmpdir(dir, sizeof(dir), "buildworker", "config");
    snprintf(path, sizeof(path), "%s/z23.conf", dir);
    const struct {
        const char *body;
        char *flag;
        bool expected;
        int applied;
    } cases[] = {
        { "buildworker=1\n", NULL, true, 1 },
        { "buildworker=1\n", "-buildworker=0", false, 0 },
        { "buildworker=0\n", NULL, false, 1 },
        { "", NULL, false, 0 },
        { "buildworker=0\n", "-buildworker", true, 0 },
        { "buildworker=0\n", "-buildworker=1", true, 0 },
        { "", "-nobuildworker=0", false, 0 },
        { "", "--buildworker=1", false, 0 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        FILE *f = fopen(path, "w");
        if (!f) {
            printf("FAIL (buildworker row %zu: config open)\n", i);
            failures++;
            break;
        }
        bool written = fputs(cases[i].body, f) >= 0;
        if (fclose(f) != 0) written = false;
        if (!written) {
            printf("FAIL (buildworker row %zu: config write)\n", i);
            failures++;
            break;
        }
        char *argv[] = { "z23", cases[i].flag };
        int argc = cases[i].flag ? 2 : 1;
        ParseParameters(argc, (const char *const *)argv);
        int applied = ReadConfigFile(path);
        struct app_context ctx;
        app_context_defaults(&ctx);
        ctx.operator_lane = ZCL_OPERATOR_LANE_TEST;
        ctx.no_tor = true;
        bool show_metrics = false;
        int rc = args_parse_node_options(argc, argv, &ctx, &show_metrics);
        if (applied != cases[i].applied || rc != -1 ||
            ctx.build_worker != cases[i].expected) {
            printf("FAIL (buildworker row %zu: applied=%d rc=%d worker=%d)\n",
                   i, applied, rc, ctx.build_worker);
            failures++;
        }
    }
    const char *empty[] = { "z23" };
    ParseParameters(1, empty);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* The args parser must recognize both flags (an unrecognized one warns
 * every boot) and leave them off by default. */
static int test_onion_persist_args_parse(void)
{
    int failures = 0;
    printf("test_onion_persist_args_parse: ");

    struct app_context ctx = {0};
    bool show_metrics = false;
    char *argv[] = { "zclassic23", "-tor", "-onion-persist",
                     "-onion-rotate" };
    /* -1 is this function's "parsed OK" return (0 is help/version, 1 is
     * fatal) — see the return comment at the end of args.c. */
    int rc = args_parse_node_options(4, argv, &ctx, &show_metrics);
    bool parsed = rc == -1 && ctx.tor && ctx.onion_persist &&
                  ctx.onion_rotate;

    struct app_context ctx2 = {0};
    char *argv2[] = { "zclassic23" };
    int rc2 = args_parse_node_options(1, argv2, &ctx2, &show_metrics);
    bool defaults = rc2 == -1 && !ctx2.onion_persist && !ctx2.onion_rotate;

    if (parsed && defaults) {
        printf("OK\n");
    } else {
        printf("FAIL (parsed=%d defaults=%d)\n", parsed, defaults);
        failures++;
    }

    return failures;
}

/* One fleet-default argv scenario: parse these arguments into a fresh
 * context and compare the onion-persist outcome with what the scenario
 * expects; check_forced selects whether onion_persist_forced_off is part
 * of the expectation. */
static bool onion_persist_argv_scenario(int argc, char **argv,
                                        bool expect_persist,
                                        bool expect_forced_off,
                                        bool check_forced)
{
    struct app_context ctx = {0};
    bool show_metrics = false;
    int rc = args_parse_node_options(argc, argv, &ctx, &show_metrics);
    return rc == -1 && ctx.onion_persist == expect_persist &&
           (!check_forced ||
            ctx.onion_persist_forced_off == expect_forced_off);
}

/* A node that pins peers by .onion address needs its OWN onion fixed too:
 * -tor + at least one -addnode=<x>.onion defaults -onion-persist ON, a plain
 * -tor node keeps the ephemeral default, and an explicit -onion-persist=0
 * forces ephemeral even with a pinned onion peer. */
static int test_onion_persist_fleet_default(void)
{
    int failures = 0;
    printf("test_onion_persist_fleet_default: ");

    /* Direct coverage of the pure decision function. */
    const char *onion_peer[] = {
        "n3c4bry42qzoiduhfqk33ugeptdycmnsmjnrkmjirrudtpw7xvhc5kid.onion:39360"
    };
    const char *clearnet_peer[] = { "203.0.113.9:8033" };
    bool pure_off_no_tor = !args_onion_persist_default(false, onion_peer, 1);
    bool pure_on = args_onion_persist_default(true, onion_peer, 1);
    bool pure_off_no_onion_peer =
        !args_onion_persist_default(true, clearnet_peer, 1);
    bool pure_off_no_peers = !args_onion_persist_default(true, NULL, 0);

    /* -tor + a pinned .onion addnode, no explicit -onion-persist: defaults
     * ON. Order-independent — the addnode arrives before -tor here. */
    char *fleet_argv[] = {
        "zclassic23",
        "-addnode=n3c4bry42qzoiduhfqk33ugeptdycmnsmjnrkmjirrudtpw7xvhc5kid.onion:39360",
        "-tor",
    };
    bool fleet_defaults_on = onion_persist_argv_scenario(3, fleet_argv,
                                                         true, false, true);

    /* -tor alone, no pinned onion peer: still defaults OFF (ephemeral). */
    char *plain_argv[] = { "zclassic23", "-tor" };
    bool plain_stays_ephemeral =
        onion_persist_argv_scenario(2, plain_argv, false, false, false);

    /* -tor + pinned onion peer + explicit -onion-persist=0: forced off. */
    char *forced_off_argv[] = {
        "zclassic23",
        "-tor",
        "-addnode=n3c4bry42qzoiduhfqk33ugeptdycmnsmjnrkmjirrudtpw7xvhc5kid.onion:39360",
        "-onion-persist=0",
    };
    bool forced_off = onion_persist_argv_scenario(4, forced_off_argv,
                                                  false, true, true);

    /* -onion-persist=1 is the explicit-on spelling alongside the bare form. */
    char *explicit_on_argv[] = { "zclassic23", "-onion-persist=1" };
    bool explicit_on = onion_persist_argv_scenario(2, explicit_on_argv,
                                                   true, false, true);

    if (pure_off_no_tor && pure_on && pure_off_no_onion_peer &&
        pure_off_no_peers && fleet_defaults_on && plain_stays_ephemeral &&
        forced_off && explicit_on) {
        printf("OK\n");
    } else {
        printf("FAIL (pure_off_no_tor=%d pure_on=%d pure_off_no_onion_peer=%d "
               "pure_off_no_peers=%d fleet_defaults_on=%d "
               "plain_stays_ephemeral=%d forced_off=%d explicit_on=%d)\n",
               pure_off_no_tor, pure_on, pure_off_no_onion_peer,
               pure_off_no_peers, fleet_defaults_on, plain_stays_ephemeral,
               forced_off, explicit_on);
        failures++;
    }

    return failures;
}

static int test_stability_control_args_parse(void)
{
    int failures = 0;
    printf("test_stability_control_args_parse: ");

    struct app_context ctx = {0};
    bool show_metrics = false;
    char *valid[] = { "zclassic23", "-utxomirror=off",
                      "-bodyhistorybackfill=normal", "-legacyoracle=off" };
    int rc = args_parse_node_options(4, valid, &ctx, &show_metrics);
    bool parsed = rc == -1 &&
        getenv("ZCL_UTXO_MIRROR_MODE") &&
        strcmp(getenv("ZCL_UTXO_MIRROR_MODE"), "off") == 0 &&
        getenv("ZCL_BODY_HISTORY_BACKFILL_MODE") &&
        strcmp(getenv("ZCL_BODY_HISTORY_BACKFILL_MODE"), "normal") == 0 &&
        getenv("ZCL_LEGACY_ORACLE_MODE") &&
        strcmp(getenv("ZCL_LEGACY_ORACLE_MODE"), "off") == 0;

    struct app_context bad_ctx = {0};
    char *invalid[] = { "zclassic23", "-utxomirror=rebuild" };
    bool invalid_refused =
        args_parse_node_options(2, invalid, &bad_ctx, &show_metrics) == 1;

    unsetenv("ZCL_UTXO_MIRROR_MODE");
    unsetenv("ZCL_BODY_HISTORY_BACKFILL_MODE");
    unsetenv("ZCL_LEGACY_ORACLE_MODE");

    if (parsed && invalid_refused) {
        printf("OK\n");
    } else {
        printf("FAIL (parsed=%d invalid_refused=%d)\n",
               parsed, invalid_refused);
        failures++;
    }
    return failures;
}

/* -full-fold-target=<H> parsing (config/boot.h's ctx->full_fold_target doc):
 * -full-fold -full-fold-target=1234 sets both fields; a non-numeric, zero, or
 * negative value is rejected the way -utxomirror=/-legacyoracle=/etc. reject
 * garbage above (rc == 1, no partial state). Arming against a header tip is
 * covered directly against boot_full_fold_resolve_target, not here — no
 * datadir is open during argv parsing. */
static int test_full_fold_target_args_parse(void)
{
    int failures = 0;
    printf("test_full_fold_target_args_parse: ");

    struct app_context ctx = {0};
    bool show_metrics = false;
    char *argv[] = { "zclassic23", "-full-fold", "-full-fold-target=1234" };
    int rc = args_parse_node_options(3, argv, &ctx, &show_metrics);
    bool parsed = rc == -1 && ctx.full_fold && ctx.full_fold_target == 1234;

    struct app_context bad_abc = {0};
    char *abc[] = { "zclassic23", "-full-fold-target=abc" };
    bool abc_refused =
        args_parse_node_options(2, abc, &bad_abc, &show_metrics) == 1;

    struct app_context bad_zero = {0};
    char *zero[] = { "zclassic23", "-full-fold-target=0" };
    bool zero_refused =
        args_parse_node_options(2, zero, &bad_zero, &show_metrics) == 1;

    struct app_context bad_neg = {0};
    char *neg[] = { "zclassic23", "-full-fold-target=-5" };
    bool neg_refused =
        args_parse_node_options(2, neg, &bad_neg, &show_metrics) == 1;

    if (parsed && abc_refused && zero_refused && neg_refused) {
        printf("OK\n");
    } else {
        printf("FAIL (parsed=%d abc_refused=%d zero_refused=%d "
               "neg_refused=%d)\n",
               parsed, abc_refused, zero_refused, neg_refused);
        failures++;
    }
    return failures;
}

static int test_auto_local_peer_refuses_self_endpoint(void)
{
    int failures = 0;
    printf("test_auto_local_peer_refuses_self_endpoint: ");
    bool ok =
        !args_should_auto_add_local_peer(false, 8033, 8033, false) &&
        args_should_auto_add_local_peer(false, 8033, 8034, false) &&
        !args_should_auto_add_local_peer(true, 8033, 8034, false) &&
        !args_should_auto_add_local_peer(false, 8033, 8034, true) &&
        !args_should_auto_add_local_peer(false, 0, 8034, false) &&
        !args_should_auto_add_local_peer(false, 8033, 0, false);
    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    return failures;
}

static int test_p2p_bind_args_parse(void)
{
    int failures = 0;
    const char *values[] = { "127.0.0.1", "::1", "localhost", "",
                            "127.0.0.1:8033", "[::1]", "::1%lo",
                            " 127.0.0.1", "127.0.0.1 ", "::ffff:127.0.0.1" };
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); i++) {
        struct app_context ctx = {0};
        ctx.runtime_profile = ZCL_RUNTIME_ZCLASSIC_ONLY;
        ctx.p2p_port = 8033;
        bool show_metrics = false;
        char option[96];
        snprintf(option, sizeof(option), "-bind=%s", values[i]);
        char *argv[] = { "zclassic23", option };
        int rc = args_parse_node_options(2, argv, &ctx, &show_metrics);
        bool valid = i < 2;
        if (rc != (valid ? -1 : 1) || ctx.listen != valid || ctx.p2p_port != 8033) {
            printf("FAIL explicit P2P bind %s: rc=%d listen=%d port=%d\n",
                   option, rc, ctx.listen, ctx.p2p_port);
            failures++;
        }
    }
    return failures;
}

static bool p2p_bind_observed(const struct net_manager *manager, bool ipv6)
{
    if (manager->num_listen_sockets != 1 || !manager->listen_sockets[0].local_port)
        return false;
    struct sockaddr_storage actual = {0};
    size_t size = sizeof(actual);
    platform_socket_t sock = manager->listen_sockets[0].socket;
    if (platform_socket_local_address(sock, (struct sockaddr *)&actual, &size) != 0)
        return false;
    if (ipv6) {
        const unsigned char loopback[16] = { [15] = 1 };
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)&actual;
        int only = 0;
        return actual.ss_family == AF_INET6 && size == sizeof(*addr) &&
            ntohs(addr->sin6_port) == manager->listen_sockets[0].local_port &&
            memcmp(&addr->sin6_addr, loopback, sizeof(loopback)) == 0 &&
            platform_socket_get_ipv6_only(sock, &only) && only == 1;
    }
    const unsigned char loopback[4] = {127, 0, 0, 1};
    const struct sockaddr_in *addr = (const struct sockaddr_in *)&actual;
    return actual.ss_family == AF_INET && size == sizeof(*addr) &&
        ntohs(addr->sin_port) == manager->listen_sockets[0].local_port &&
        memcmp(&addr->sin_addr, loopback, sizeof(loopback)) == 0;
}

static int test_p2p_explicit_listener_addresses(void)
{
    int failures = 0;
    const char *addresses[] = { "127.0.0.1", "::1" };
    for (size_t i = 0; i < sizeof(addresses)/sizeof(addresses[0]); i++) {
        struct net_manager manager;
        net_manager_init(&manager);
        struct app_context ctx = { .listen = true, .p2p_bind_address = addresses[i] };
        bool ok = boot_p2p_listen(&manager, &ctx) && p2p_bind_observed(&manager, i == 1);
        net_manager_free(&manager);
        if (!ok) { printf("FAIL explicit P2P listener address %s\n", addresses[i]); failures++; }
    }
    return failures;
}

static int test_p2p_explicit_listener_refusal(void)
{
    struct net_manager occupied, empty;
    net_manager_init(&occupied);
    net_manager_init(&empty);
    struct app_context ctx = { .listen = true, .p2p_bind_address = "127.0.0.1" };
    bool ok = boot_p2p_listen(&occupied, &ctx) && p2p_bind_observed(&occupied, false);
    if (ok) {
        ctx.p2p_port = occupied.listen_sockets[0].local_port;
        platform_socket_t original = occupied.listen_sockets[0].socket;
        ok = !boot_p2p_listen(&empty, &ctx) && empty.num_listen_sockets == 0;
        ok = !boot_p2p_listen(&occupied, &ctx) && ok;
        ok = occupied.listen_sockets[0].socket == original && ok;
        ok = p2p_bind_observed(&occupied, false) && ok;
    }
    ctx.p2p_bind_address = "localhost";
    ok = !boot_p2p_listen(&empty, &ctx) && empty.num_listen_sockets == 0 && ok;
    ctx.listen = false;
    ok = boot_p2p_listen(&empty, &ctx) && empty.num_listen_sockets == 0 && ok;
    net_manager_free(&empty);
    net_manager_free(&occupied);
    if (!ok) printf("FAIL explicit P2P bind refusal or existing-listener preservation\n");
    return ok ? 0 : 1;
}

static int test_p2p_bind_malformed_spelling(void)
{
    int failures = 0;
    const char *options[] = { "-bind", "--bind", "--bind=127.0.0.1" };
    for (size_t i = 0; i < sizeof(options)/sizeof(options[0]); i++) {
        struct app_context ctx = {0};
        bool metrics = false;
        char *argv[] = { "zclassic23", (char *)options[i] };
        if (args_parse_node_options(2, argv, &ctx, &metrics) != 1 || ctx.listen)
            failures++;
    }
    struct app_context ctx = {0};
    bool metrics = false;
    char *twice[] = { "zclassic23", "-bind=127.0.0.1", "-bind=::1" };
    if (args_parse_node_options(3, twice, &ctx, &metrics) != 1) failures++;
    int only = 9;
    if (platform_socket_get_ipv6_only(PLATFORM_SOCKET_INVALID, &only) || only != 0)
        failures++;
    if (platform_socket_get_ipv6_only(PLATFORM_SOCKET_INVALID, NULL)) failures++;
    if (failures) printf("FAIL malformed/repeated bind or IPv6-only readback refusal\n");
    return failures;
}

static int test_p2p_ipv6_refusal_retains_custody(void)
{
    struct net_manager manager;
    net_manager_init(&manager);
    struct app_context ctx = { .listen = true, .p2p_bind_address = "127.0.0.1" };
    platform_socket_t owned[2] = { PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID };
    bool ok = boot_p2p_listen(&manager, &ctx) && p2p_bind_observed(&manager, false);
    if (ok) {
        platform_socket_t original = manager.listen_sockets[0].socket;
        ctx.p2p_bind_address = "::1";
        boot_p2p_refuse_ipv6_for_test(true);
        bool refused = !boot_p2p_listen(&manager, &ctx);
        boot_p2p_refuse_ipv6_for_test(false);
        ok = refused && manager.num_listen_sockets == 2 &&
            manager.listen_sockets[0].socket == original;
        if (ok) {
            owned[0] = manager.listen_sockets[0].socket;
            owned[1] = manager.listen_sockets[1].socket;
        }
    }
    net_manager_free(&manager);
    /* No new descriptors are created between teardown and these read-only
     * observations. Never close/retry a saved descriptor after teardown. */
    for (size_t i = 0; ok && i < 2; i++) {
        struct sockaddr_storage address = {0};
        size_t size = sizeof(address);
        ok = platform_socket_local_address(owned[i], (struct sockaddr *)&address, &size) != 0;
    }
    if (!ok) printf("FAIL forced IPv6 verification refusal lost socket custody\n");
    return ok ? 0 : 1;
}

static int test_port_args_parse(void)
{
    int failures = 0;
    const char *keys[] = { "port", "rpcport", "httpsport", "fsport" };
    const char *values[] = { "8033junk", "", "999999999999999999999",
                            "-1", "65537", "0", "1", "65535", "8443" };
    const int accepted[] = { 0, 0, 0, -1, 65537, 0, 1, 65535, 8443 };
    for (size_t k = 0; k < sizeof(keys)/sizeof(keys[0]); k++) {
        for (size_t v = 0; v < sizeof(values)/sizeof(values[0]); v++) {
            struct app_context ctx = {0};
            ctx.runtime_profile = ZCL_RUNTIME_ZCLASSIC_ONLY;
            ctx.p2p_port = 8033; ctx.rpc_port = 18232;
            ctx.https_port = 8443; ctx.fs_port = 8034;
            bool show_metrics = false;
            char option[96];
            snprintf(option, sizeof(option), "-%s=%s", keys[k], values[v]);
            char *argv[] = { "zclassic23", option };
            int *ports[] = { &ctx.p2p_port, &ctx.rpc_port,
                            &ctx.https_port, &ctx.fs_port };
            int before = *ports[k];
            bool refused = v < 3 || (k != 2 && (v == 3 || v == 4));
            int rc = args_parse_node_options(2, argv, &ctx, &show_metrics);
            int expected = refused ? before : accepted[v];
            if (rc != (refused ? 1 : -1) || *ports[k] != expected ||
                ctx.listen != (k == 0 && !refused)) {
                printf("FAIL port args %s: rc=%d port=%d listen=%d\n",
                       option, rc, *ports[k], ctx.listen);
                failures++;
            }
        }
    }
    return failures;
}

#if !defined(_WIN32)
/* Checked, non-recursive cleanup of the symlink fixture: the link first. */
static bool nofollow_cleanup(const char *root, const char *target,
                             const char *sentinel, const char *link)
{
    (void)unlink(link);
    bool clean = true;
    if (unlink(sentinel) != 0 && errno != ENOENT) clean = false;
    if (rmdir(target) != 0 && errno != ENOENT) clean = false;
    if (rmdir(root) != 0 && errno != ENOENT) clean = false;
    return clean;
}

/* The remover must unlink a symbolic link at its top, never walk through it.
 * The link points (relative) at a sibling directory this test creates and
 * fills with one sentinel; cleanup is checked unlink/rmdir only, and the link
 * is unlinked before anything else runs. */
static int test_remove_tree_does_not_follow_symlink(void)
{
    int failures = 0;
    printf("test_remove_tree_does_not_follow_symlink: ");

    char root[512], target[640], sentinel[704], link[640];
    test_make_tmpdir(root, sizeof(root), "onion_identity", "nofollow");
    snprintf(target, sizeof(target), "%s/target", root);
    snprintf(sentinel, sizeof(sentinel), "%s/keep", target);
    snprintf(link, sizeof(link), "%s/link", root);

    bool built = mkdir(target, 0700) == 0;
    int sfd = built ? open(sentinel, O_WRONLY | O_CREAT | O_EXCL, 0600) : -1;
    if (sfd >= 0) close(sfd);
    bool linked = sfd >= 0 && symlink("target", link) == 0;
    if (linked) remove_tree(link);

    struct stat st;
    bool link_gone = linked && lstat(link, &st) != 0 && errno == ENOENT;
    bool kept = linked && stat(sentinel, &st) == 0;

    bool clean = nofollow_cleanup(root, target, sentinel, link);

    if (link_gone && kept && clean) {
        printf("OK\n");
    } else {
        printf("FAIL (linked=%d link_gone=%d kept=%d clean=%d)\n",
               linked, link_gone, kept, clean);
        failures++;
    }
    return failures;
}

/* Trailing-separator control: "root/link/" must not resolve the link's
 * referent. The link points (relative) at a sibling directory this case
 * creates and fills with one sentinel. The shared normalizer strips the
 * separator, so the link is removed as a link and the sentinel and target
 * directory survive. Cleanup is checked unlink/rmdir only, link first, and
 * runs before any assertion. */
static int test_remove_tree_trailing_separator_keeps_target(void)
{
    int failures = 0;
    printf("test_remove_tree_trailing_separator_keeps_target: ");

    char root[512], target[640], sentinel[704], link[640], slashed[648];
    test_make_tmpdir(root, sizeof(root), "onion_identity", "nofollow_slash");
    snprintf(target, sizeof(target), "%s/target", root);
    snprintf(sentinel, sizeof(sentinel), "%s/keep", target);
    snprintf(link, sizeof(link), "%s/link", root);
    snprintf(slashed, sizeof(slashed), "%s/", link);

    bool built = mkdir(target, 0700) == 0;
    int sfd = built ? open(sentinel, O_WRONLY | O_CREAT | O_EXCL, 0600) : -1;
    if (sfd >= 0) close(sfd);
    bool linked = sfd >= 0 && symlink("target", link) == 0;
    if (linked) remove_tree(slashed);

    struct stat st;
    bool link_gone = linked && lstat(link, &st) != 0 && errno == ENOENT;
    bool kept = linked && stat(sentinel, &st) == 0;
    bool target_kept = linked && stat(target, &st) == 0;

    bool clean = nofollow_cleanup(root, target, sentinel, link);

    if (link_gone && kept && target_kept && clean) {
        printf("OK\n");
    } else {
        printf("FAIL (linked=%d link_gone=%d kept=%d target_kept=%d clean=%d)\n",
               linked, link_gone, kept, target_kept, clean);
        failures++;
    }
    return failures;
}
#endif

int test_onion_persistence(void)
{
    int failures = 0;
    printf("\n=== Persistent Onion Identity Tests ===\n");

    failures += test_onion_identity_vector();
    failures += test_onion_identity_stable_across_boots();
    failures += test_onion_identity_corrupt_seed_refused();
    failures += test_onion_identity_rotation();
    failures += test_onion_ephemeral_default();
    failures += test_onion_persist_args_parse();
    failures += test_buildworker_config_args_parse();
    failures += test_onion_persist_fleet_default();
    failures += test_stability_control_args_parse();
    failures += test_full_fold_target_args_parse();
    failures += test_auto_local_peer_refuses_self_endpoint();
    failures += test_port_args_parse();
    failures += test_p2p_bind_args_parse();
    failures += test_p2p_explicit_listener_addresses();
    failures += test_p2p_explicit_listener_refusal();
    failures += test_p2p_bind_malformed_spelling();
    failures += test_p2p_ipv6_refusal_retains_custody();
#if !defined(_WIN32)
    failures += test_remove_tree_does_not_follow_symlink();
    failures += test_remove_tree_trailing_separator_keeps_target();
#endif

    printf("Persistent onion identity: %d failures\n", failures);
    return failures;
}
