/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_cli_auth_robust — E4 (typed CLI self-sufficiency): proves the
 * `zclassic23` CLI's `-rpcport=<N>` cookie auto-discovery and its
 * connection-error taxonomy (docs/dev/NATIVE_COMMAND_INTERFACE.md §25) against
 * the REAL built binary, the way an operator or orchestrator monitor
 * actually invokes it — not the underlying helpers directly (they are
 * `static` in engine/entry/main.c).
 *
 * Incident shape: without -datadir the CLI could not find the right auth
 * cookie, and "Cannot connect" vs "Error: Unauthorized" were
 * indistinguishable ("nothing running" vs "wrong instance" vs "node busy").
 *
 * Isolation: a REAL in-process RPC listener (rpc_http_start, empty
 * rpc_table) gives a real cookie/port pair, never a live datadir.
 * `ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1` is set on every child so the CLI's
 * systemctl default-service lookup (cli_service_exec_arg) never reads this
 * project's real `zclassic23.service`.
 *
 * Skips (does not fail) if build/bin/zclassic23 is missing or stale vs the
 * source files that define this behavior — matching the guard pattern in
 * test_importblockindex_cli_dispatch.c.
 *
 * make t ONLY=cli_auth_robust
 */

#include "test/test_core.h"
#include "rpc/server.h"
#include "rpc/httpserver.h"
#include "kernel/command_registry.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include "devloop.h"
#include <sys/wait.h>
#endif
#include <unistd.h>

#include "platform/socket_compat.h"

#define CAR_BIN "build/bin/zclassic23"

static bool car_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static long car_file_mtime(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_mtime;
}

static const char *const car_stale_witnesses[] = {
    "engine/entry/main.c",
    "engine/modules/rpc/src/httpserver.c",
    "engine/modules/rpc/src/httpserver_auth.c",
    "engine/modules/rpc/src/httpserver_request.c",
    NULL,
};

static bool car_bin_is_fresh(const char **stale_path_out)
{
    long bin_mt = car_file_mtime(CAR_BIN);
    if (bin_mt < 0) return false;
    for (size_t i = 0; car_stale_witnesses[i]; i++) {
        long src_mt = car_file_mtime(car_stale_witnesses[i]);
        if (src_mt < 0) continue;
        if (src_mt > bin_mt) {
            if (stale_path_out) *stale_path_out = car_stale_witnesses[i];
            return false;
        }
    }
    return true;
}

/* Bind to port 0, read back the OS-assigned free port, close. Same idiom
 * as test_cookie_rotation.c's reserve_test_port(). */
static uint16_t car_reserve_port(void)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID) return 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    uint16_t port = 0;
    if (platform_socket_bind(fd, (struct sockaddr *)&addr,
                             sizeof(addr)) == 0) {
        size_t len = sizeof(addr);
        if (platform_socket_local_address(fd, (struct sockaddr *)&addr,
                                          &len) == 0)
            port = ntohs(addr.sin_port);
    }
    platform_socket_close(fd);
    return port;
}

static void car_mkdir_p(const char *path)
{
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        fprintf(stderr, "car_mkdir_p: mkdir(%s) failed: %s\n",
                path, strerror(errno));
}

static bool car_write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(content, f) >= 0;
    fclose(f);
    return ok;
}

static bool car_contains(const char *hay, const char *needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

/* Best-effort cleanup: every fixture this file creates has at most
 * `.cookie` + `.rpcport` directly inside it — no subdirectories, so a
 * shallow unlink+rmdir is enough. Failures are not test failures (a stray
 * /tmp fixture is noise, not a regression). */
static void car_rm_shallow_dir(const char *dir)
{
    char p[700];
    snprintf(p, sizeof(p), "%s/.cookie", dir);
    unlink(p);
    snprintf(p, sizeof(p), "%s/.rpcport", dir);
    unlink(p);
    rmdir(dir);
}

#if !defined(_WIN32)
static int car_capture_result(const struct zcl_devloop_process_result *result,
                               bool ran, bool restored, char *out, size_t cap,
                               bool *timed_out)
{
    bool complete = ran && restored && !result->cancelled &&
        !result->output_truncated && result->output_len < cap;
    if (timed_out) *timed_out = complete && result->timed_out;
    if (!complete || result->timed_out) {
        fprintf(stderr, "car_run_bounded: incomplete CLI observation "
                "ran=%d restored=%d timeout=%d cancelled=%d truncated=%d "
                "bytes=%zu cap=%zu exit=%d signal=%d\n",
                ran, restored, result->timed_out, result->cancelled,
                result->output_truncated, result->output_len, cap,
                result->exit_code, result->term_signal);
        return -1;
    }
    if (result->term_signal) {
        fprintf(stderr, "car_run_bounded: CLI terminated by signal %d\n",
                result->term_signal);
        return -100 - result->term_signal;
    }
    memcpy(out, result->output, result->output_len);
    out[result->output_len] = 0;
    return result->exit_code;
}
#endif

/* Capture the real CLI with an exact isolated environment. POSIX reuses the
 * bounded devloop process implementation; Windows retains its capture helper.
 * Incomplete output and harness failures must never satisfy absence checks. */
static int car_run_bounded(char *const argv[], char *const envp[], char *out,
                           size_t cap, int timeout_ms, bool *timed_out)
{
    if (timed_out) *timed_out = false;
    if (!argv || !argv[0] || !envp || !out || cap == 0 || timeout_ms <= 0) {
        fprintf(stderr, "car_run_bounded: invalid capture arguments\n");
        return -1;
    }
    out[0] = 0;
#if defined(_WIN32)
    (void)timeout_ms;
    /* No fork/execve: CreateProcess with a custom environment block and a
     * captured pipe (test_spawn_capture_env). */
    return test_spawn_capture_env(
        (const char *const *)argv, (const char *const *)envp, out, cap);
#else
    const char *prior = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    char *saved = prior ? strdup(prior) : NULL;
    if ((prior && !saved) || setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0) {
        fprintf(stderr, "car_run_bounded: cannot enable isolated process fixture\n");
        free(saved);
        return -1;
    }
    struct zcl_devloop_process_result result = {0};
    bool ran = zcl_devloop_process_run_env(".",
        (const char *const *)argv, (const char *const *)envp,
        timeout_ms, &result);
    bool restored = (saved
        ? setenv("ZCL_DEVLOOP_TEST_PROCESS", saved, 1)
        : unsetenv("ZCL_DEVLOOP_TEST_PROCESS")) == 0;
    free(saved);
    return car_capture_result(&result, ran, restored, out, cap, timed_out);
#endif
}

static int car_run(char *const argv[], char *const envp[], char *out,
                   size_t cap)
{
    return car_run_bounded(argv, envp, out, cap, 10000, NULL);
}

/* Build a minimal envp: HOME=<home>, PATH inherited from the real
 * environment (execve needs SOME PATH-independent binary resolution, but
 * we always pass an absolute CAR_BIN so PATH is not load-bearing —
 * included anyway so any child-side helper spawn behaves normally),
 * ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1 (see file header), plus one optional
 * extra "KEY=VALUE" (or NULL). Returned array + strings are static
 * scratch — NOT reentrant, fine for this single-threaded test group. */
static char car_env_home[600];
static char car_env_extra[128];
static char *car_envp[8];

static char *const *car_build_envp(const char *home, const char *extra_kv)
{
    size_t i = 0;
    snprintf(car_env_home, sizeof(car_env_home), "HOME=%s", home);
    car_envp[i++] = car_env_home;
    car_envp[i++] = (char *)"PATH=/usr/bin:/bin:/usr/local/bin";
    car_envp[i++] = (char *)"ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1";
    if (extra_kv && extra_kv[0]) {
        snprintf(car_env_extra, sizeof(car_env_extra), "%s", extra_kv);
        car_envp[i++] = car_env_extra;
    }
    car_envp[i] = NULL;
    return car_envp;
}

/* ── fixture datadir builders ────────────────────────────────────── */

/* A REAL live RPC listener with an empty command table. An authenticated RPC
 * error proves auth succeeded without depending on any real RPC handler.
 * Returns the bound port, or 0 on failure. Caller must
 * rpc_http_stop() when done. */
static uint16_t car_start_live_fixture(const char *datadir)
{
    static struct rpc_table empty_table;
    uint16_t port = car_reserve_port();
    if (port == 0) return 0;
    if (!rpc_http_start(&empty_table, port, NULL, NULL, datadir))
        return 0;
    return port;
}

/* A dead fixture: the two files an uncleanly terminated node can leave behind
 * (.rpcport + .cookie), no listener. Good enough to exercise the
 * datadir-selection scan and the CONNECT_REFUSED taxonomy. */
static void car_write_dead_fixture(const char *datadir, uint16_t port,
                                   const char *cookie_line)
{
    car_mkdir_p(datadir);
    char rpcport_path[700], cookie_path[700];
    snprintf(rpcport_path, sizeof(rpcport_path), "%s/.rpcport", datadir);
    snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", datadir);
    char port_buf[16];
    snprintf(port_buf, sizeof(port_buf), "%u", port);
    car_write_file(rpcport_path, port_buf);
    car_write_file(cookie_path, cookie_line);
}

/* ── test cases ───────────────────────────────────────────────────── */

static int car_test_autodiscover_picks_matching_fixture(const char *home)
{
    int failures = 0;
    TEST("cli auth: -rpcport=<N> with no -datadir= auto-discovers the "
         "sibling datadir recording port N, not a decoy sibling recording "
         "a different port") {
        char decoy_dir[700], live_dir[700];
        snprintf(decoy_dir, sizeof(decoy_dir), "%s/.zclassic-c23-cardecoy",
                 home);
        snprintf(live_dir, sizeof(live_dir), "%s/.zclassic-c23-carlive",
                 home);
        car_mkdir_p(live_dir);

        uint16_t decoy_port = car_reserve_port();
        ASSERT(decoy_port != 0);
        car_write_dead_fixture(decoy_dir, decoy_port, "decoyuser:decoypass");

        uint16_t live_port = car_start_live_fixture(live_dir);
        ASSERT(live_port != 0);

        char rpcport_flag[32];
        snprintf(rpcport_flag, sizeof(rpcport_flag), "-rpcport=%u",
                 live_port);
        char *argv[] = {
            (char *)CAR_BIN, rpcport_flag,
            (char *)"zcl_test_no_such_method_xyz", NULL,
        };
        char out[16384] = {0};
        char prior_status[256];
        bool prior_warmup = rpc_is_in_warmup(prior_status, sizeof(prior_status));
        set_rpc_warmup_started("cli auth fixture warmup");
        int rc = car_run(argv, car_build_envp(home, NULL), out, sizeof(out));

        rpc_http_stop();
        set_rpc_warmup_started(prior_status);
        if (!prior_warmup) set_rpc_warmup_finished();

        ASSERT(car_contains(out, "auto-discovered datadir"));
        ASSERT(car_contains(out, live_dir));
        ASSERT(!car_contains(out, decoy_dir));
        ASSERT(!car_contains(out, "AUTH_REJECTED"));
        ASSERT(car_contains(out, "Error: cli auth fixture warmup"));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_FAILED);
        PASS();
    } _test_next:;
    return failures;
}

/* D4: TWO or more sibling datadirs recording the SAME rpcport (stale fixtures
 * commonly reuse a fixed test port) must make auto-discovery refuse outright
 * on ambiguity, never pick "first match in sorted order". */
static int car_test_autodiscover_ambiguous_port_refuses(const char *home)
{
    int failures = 0;
    TEST("cli auth: -rpcport=<N> with no -datadir= REFUSES (never guesses) "
         "when two or more sibling datadirs record the same port N") {
        char dir_a[700], dir_b[700];
        snprintf(dir_a, sizeof(dir_a), "%s/.zclassic-c23-caramba", home);
        snprintf(dir_b, sizeof(dir_b), "%s/.zclassic-c23-carambb", home);

        uint16_t shared_port = car_reserve_port();
        ASSERT(shared_port != 0);
        car_write_dead_fixture(dir_a, shared_port, "usera:passa");
        car_write_dead_fixture(dir_b, shared_port, "userb:passb");

        char rpcport_flag[32];
        snprintf(rpcport_flag, sizeof(rpcport_flag), "-rpcport=%u",
                 shared_port);
        char *argv[] = {
            (char *)CAR_BIN, rpcport_flag,
            (char *)"zcl_test_no_such_method_xyz", NULL,
        };
        char out[16384] = {0};
        int rc = car_run(argv, car_build_envp(home, NULL), out, sizeof(out));

        ASSERT(!car_contains(out, "auto-discovered datadir"));
        ASSERT(car_contains(out, "error=PORT_AMBIGUOUS"));
        ASSERT(car_contains(out, "-datadir=DIR"));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);

        car_rm_shallow_dir(dir_a);
        car_rm_shallow_dir(dir_b);
        PASS();
    } _test_next:;
    return failures;
}

/* D4: zero sibling datadirs recording the requested port must ALSO refuse
 * (never silently fall through to the systemctl-default-service datadir —
 * that reintroduces the exact pre-E4 footgun for every unmatched port). */
static int car_test_autodiscover_no_match_refuses(const char *home)
{
    int failures = 0;
    TEST("cli auth: -rpcport=<N> with no -datadir= REFUSES when no sibling "
         "datadir records port N (never falls through to a default lane)") {
        uint16_t unmatched_port = car_reserve_port();
        ASSERT(unmatched_port != 0);

        char rpcport_flag[32];
        snprintf(rpcport_flag, sizeof(rpcport_flag), "-rpcport=%u",
                 unmatched_port);
        char *argv[] = {
            (char *)CAR_BIN, rpcport_flag,
            (char *)"zcl_test_no_such_method_xyz", NULL,
        };
        char out[16384] = {0};
        int rc = car_run(argv, car_build_envp(home, NULL), out, sizeof(out));

        ASSERT(!car_contains(out, "auto-discovered datadir"));
        ASSERT(car_contains(out, "error=PORT_NOT_FOUND"));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);
        PASS();
    } _test_next:;
    return failures;
}

static int car_test_explicit_datadir_wins(const char *home,
                                          const char *live_dir,
                                          uint16_t live_port)
{
    int failures = 0;
    TEST("cli auth: an explicit -datadir= is never overridden by "
         "-rpcport= auto-discovery, even when the port would match a "
         "different sibling") {
        char other_dir[700];
        snprintf(other_dir, sizeof(other_dir),
                 "%s/.zclassic-c23-carnocookie", home);
        car_mkdir_p(other_dir);

        char rpcport_flag[32], datadir_flag[750];
        snprintf(rpcport_flag, sizeof(rpcport_flag), "-rpcport=%u",
                 live_port);
        snprintf(datadir_flag, sizeof(datadir_flag), "-datadir=%s",
                 other_dir);
        char *argv[] = {
            (char *)CAR_BIN, datadir_flag, rpcport_flag,
            (char *)"zcl_test_no_such_method_xyz", NULL,
        };
        char out[16384] = {0};
        int rc = car_run(argv, car_build_envp(home, NULL), out, sizeof(out));

        ASSERT(!car_contains(out, "auto-discovered datadir"));
        ASSERT(car_contains(out, "error=CONNECT_REFUSED"));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_BLOCKED);
        (void)live_dir;
        PASS();
    } _test_next:;
    return failures;
}

static int car_test_connect_refused_taxonomy(const char *home,
                                             const char *live_dir)
{
    int failures = 0;
    TEST("cli auth: nothing listening at the target port is reported as "
         "CONNECT_REFUSED with exit code 3, naming the remedy") {
        uint16_t unused_port = car_reserve_port();
        ASSERT(unused_port != 0);

        char rpcport_flag[32], datadir_flag[750];
        snprintf(rpcport_flag, sizeof(rpcport_flag), "-rpcport=%u",
                 unused_port);
        snprintf(datadir_flag, sizeof(datadir_flag), "-datadir=%s",
                 live_dir);
        char *argv[] = {
            (char *)CAR_BIN, datadir_flag, rpcport_flag,
            (char *)"zcl_test_no_such_method_xyz", NULL,
        };
        char out[16384] = {0};
        int rc = car_run(argv, car_build_envp(home, NULL), out, sizeof(out));

        ASSERT(car_contains(out, "error=CONNECT_REFUSED"));
        ASSERT(car_contains(out, "node not running"));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_BLOCKED);
        PASS();
    } _test_next:;
    return failures;
}

static int car_test_auth_rejected_taxonomy(const char *home,
                                           const char *decoy_dir,
                                           uint16_t live_port)
{
    int failures = 0;
    TEST("cli auth: connecting to a REAL live node with the WRONG cookie "
         "(a different datadir's) is reported as AUTH_REJECTED with exit "
         "code 4, distinct from CONNECT_REFUSED") {
        char rpcport_flag[32], datadir_flag[750];
        snprintf(rpcport_flag, sizeof(rpcport_flag), "-rpcport=%u",
                 live_port);
        snprintf(datadir_flag, sizeof(datadir_flag), "-datadir=%s",
                 decoy_dir);
        char *argv[] = {
            (char *)CAR_BIN, datadir_flag, rpcport_flag,
            (char *)"zcl_test_no_such_method_xyz", NULL,
        };
        char out[16384] = {0};
        int rc = car_run(argv, car_build_envp(home, NULL), out, sizeof(out));

        ASSERT(car_contains(out, "error=AUTH_REJECTED"));
        ASSERT(car_contains(out, "-datadir=DIR"));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_DENIED);
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
/* Inspect only bytes already queued by the terminated CLI: neither accept nor
 * receive may wait. This witnesses an RPC request reaching our own fixture. */
static bool car_blackhole_received_rpc(platform_socket_t listener)
{
    if (!platform_socket_set_nonblocking(listener, true)) return false;
    struct sockaddr_in address;
    size_t address_len = sizeof(address);
    platform_socket_t client = platform_socket_accept(listener,
        (struct sockaddr *)&address, &address_len);
    if (client == PLATFORM_SOCKET_INVALID) return false;
    char request[4096] = {0};
    size_t used = 0;
    while (used < sizeof(request) - 1) {
        int received = platform_socket_receive_nonblocking(client,
            request + used, sizeof(request) - 1 - used);
        if (received <= 0) break;
        used += (size_t)received;
    }
    platform_socket_close(client);
    return car_contains(request, "\"method\":\"zcl_test_no_such_method_xyz\"");
}
#endif

static int car_test_response_timeout_case(const char *home, bool bounded)
{
    int failures = 0;
    platform_socket_t blackhole = PLATFORM_SOCKET_INVALID;
    TEST(bounded
         ? "cli auth: harness deadline stops a real CLI launch before its RPC timeout"
         : "cli auth: a peer that accepts the TCP connection but never "
         "answers is reported as RESPONSE_TIMEOUT with exit code 5 (node "
         "busy), bounded by ZCL_CLI_RPC_TIMEOUT_SEC for test speed") {
        /* A bound+listening socket completes the client's connect() via
         * the kernel accept queue even with no accept() call — exactly
         * "TCP up, nobody home to answer" (see file header + engine/entry/main.c
         * cli_rpc_call_internal_ex's RESPONSE_TIMEOUT branch). */
        blackhole = platform_socket_open(
            AF_INET, SOCK_STREAM, 0, true, false);
        ASSERT(blackhole != PLATFORM_SOCKET_INVALID);
        uint16_t port = car_reserve_port();
        ASSERT(port != 0);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        (void)platform_socket_set_reuse_address(blackhole, true);
        ASSERT(platform_socket_bind(blackhole, (struct sockaddr *)&addr,
                                    sizeof(addr)) == 0);
        ASSERT(platform_socket_listen(blackhole, 1) == 0);

        char dummy_dir[700];
        snprintf(dummy_dir, sizeof(dummy_dir), "%s/.zclassic-c23-cartimeout",
                 home);
        car_write_dead_fixture(dummy_dir, port, "dummyuser:dummypass");

        char rpcport_flag[32], datadir_flag[750];
        snprintf(rpcport_flag, sizeof(rpcport_flag), "-rpcport=%u", port);
        snprintf(datadir_flag, sizeof(datadir_flag), "-datadir=%s",
                 dummy_dir);
        char *argv[] = {
            (char *)CAR_BIN, datadir_flag, rpcport_flag,
            (char *)"zcl_test_no_such_method_xyz", NULL,
        };
        char out[16384] = {0};
        bool timed_out = false;
        int rc = car_run_bounded(argv,
                         car_build_envp(home, bounded
                             ? "ZCL_CLI_RPC_TIMEOUT_SEC=2"
                             : "ZCL_CLI_RPC_TIMEOUT_SEC=1"),
                         out, sizeof(out), bounded ? 500 : 10000, &timed_out);
        bool received_rpc = false;
#if !defined(_WIN32)
        if (bounded) received_rpc = car_blackhole_received_rpc(blackhole);
#endif
        platform_socket_close(blackhole);
        blackhole = PLATFORM_SOCKET_INVALID;

        if (bounded) {
            ASSERT(received_rpc);
            ASSERT(timed_out);
            ASSERT(rc < 0);
        } else {
            ASSERT(car_contains(out, "error=RESPONSE_TIMEOUT"));
            ASSERT_EQ(rc, ZCL_COMMAND_EXIT_TRANSIENT);
        }
        PASS();
    } _test_next:;
    if (blackhole != PLATFORM_SOCKET_INVALID) platform_socket_close(blackhole);
    return failures;
}

static int car_test_status_lists_local_instances(const char *home,
                                                  const char *live_dir,
                                                  uint16_t live_port,
                                                  const char *decoy_dir)
{
    int failures = 0;
    TEST("cli auth: bare `status`, no -datadir=/-rpcport= given and no "
         "cookie in the (empty, HOME-scoped) default datadir, lists every "
         "sibling ~/.zclassic-c23* instance instead of a bare failure") {
        char *argv[] = { (char *)CAR_BIN, (char *)"status", NULL };
        char out[65536] = {0};
        int rc = car_run(argv, car_build_envp(home, NULL), out, sizeof(out));

        ASSERT(car_contains(out, "zcl.cli_local_instances.v1"));
        ASSERT(car_contains(out, live_dir));
        ASSERT(car_contains(out, "\"state\":\"alive\""));
        ASSERT(car_contains(out, decoy_dir));
        ASSERT(car_contains(out, "\"state\":\"dead\""));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_TRANSIENT);
        (void)live_port;
        PASS();
    } _test_next:;
    return failures;
}

int test_cli_auth_robust(void);

int test_cli_auth_robust(void)
{
    int failures = 0;

    if (!car_file_exists(CAR_BIN)) {
        printf("cli_auth_robust: %s not built — SKIP (run `make` to "
               "build it)\n", CAR_BIN);
        return 0;
    }
    const char *stale_path = NULL;
    if (!car_bin_is_fresh(&stale_path)) {
        printf("cli_auth_robust: %s is stale — newer source: %s — SKIP "
               "(run `make` to rebuild)\n", CAR_BIN,
               stale_path ? stale_path : "(unknown)");
        return 0;
    }

    char home[256];
    snprintf(home, sizeof(home), "/tmp/zcl_car_home_%d", (int)getpid());
    car_mkdir_p(home);

    failures += car_test_autodiscover_picks_matching_fixture(home);
    failures += car_test_autodiscover_ambiguous_port_refuses(home);
    failures += car_test_autodiscover_no_match_refuses(home);

    /* Shared live+decoy fixtures for the remaining cases (each needs an
     * authenticatable target and a wrong-cookie source). */
    char live_dir[700], decoy_dir[700];
    snprintf(live_dir, sizeof(live_dir), "%s/.zclassic-c23-carshared", home);
    snprintf(decoy_dir, sizeof(decoy_dir), "%s/.zclassic-c23-carshareddecoy",
             home);
    car_mkdir_p(live_dir);
    uint16_t live_port = car_start_live_fixture(live_dir);
    if (live_port == 0) {
        printf("cli_auth_robust: could not start the in-process RPC "
               "fixture — SKIP remaining cases\n");
    } else {
        car_write_dead_fixture(decoy_dir, live_port, "wronguser:wrongpass");

        failures += car_test_explicit_datadir_wins(home, live_dir,
                                                    live_port);
        failures += car_test_connect_refused_taxonomy(home, live_dir);
        failures += car_test_auth_rejected_taxonomy(home, decoy_dir,
                                                     live_port);
        failures += car_test_status_lists_local_instances(home, live_dir,
                                                           live_port,
                                                           decoy_dir);
        rpc_http_stop();
    }

    failures += car_test_response_timeout_case(home, false);
#if !defined(_WIN32)
    failures += car_test_response_timeout_case(home, true);
#endif

    /* Best-effort cleanup of every fixture path this file creates. */
    static const char *const car_fixture_leaf_names[] = {
        "cardecoy", "carlive", "carnocookie", "carshared",
        "carshareddecoy", "cartimeout",
    };
    for (size_t i = 0;
         i < sizeof(car_fixture_leaf_names) / sizeof(car_fixture_leaf_names[0]);
         i++) {
        char dir[700];
        snprintf(dir, sizeof(dir), "%s/.zclassic-c23-%s", home,
                 car_fixture_leaf_names[i]);
        car_rm_shallow_dir(dir);
    }
    rmdir(home);

    return failures;
}
