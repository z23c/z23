/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_cli_argv_strict — a double-dash typo of an operator-target flag
 * (`zclassic23 --rpcport=39071 status`, no `-datadir=`) must not make
 * is_cli_mode() bail out at the unrecognized token: that shape falls through
 * main()'s dispatch into a full node boot against the DEFAULT datadir (the
 * protected live node's directory).
 *
 * Proves, against the REAL built binary (as in test_cli_auth_robust.c /
 * test_importblockindex_cli_dispatch.c):
 *
 *   1. CLI-client mode (a typed command word present) HARD REFUSES any
 *      malformed operator-target flag (double-dash typo, or a bare flag
 *      missing its "=value"), regardless of its position relative to the
 *      command word.
 *   2. Daemon mode (no command word at all) stays TOLERANT for backward
 *      compatibility, but the identical typo now gets a WARN naming the
 *      exact single-dash correction instead of a bare "ignored" notice.
 *   3. Bare `status` with NO flags at all still works — it intentionally
 *      targets the default local node and must never be refused.
 *   4. Legitimate native-command param conventions (`--next`, `--input=`,
 *      etc.) are NOT operator-target flags and must keep working
 *      unexamined — the strict validator is deliberately narrow.
 *
 * Isolation: every case sets HOME to a private /tmp fixture with
 * ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1 so default-datadir resolution and the
 * systemctl service lookup never touch the real datadir/service; the one
 * daemon-mode case that boots targets a throwaway datadir and a freshly
 * reserved port (never 39070-39073) and is killed within ~2s.
 *
 * Skips (does not fail) if build/bin/zclassic23 is missing or stale vs the
 * source files that define this behavior — matching the guard pattern in
 * the sibling CLI dispatch tests.
 *
 * make t ONLY=cli_argv_strict
 */

#include "test/test_core.h"
#include "kernel/command_registry.h"
#include "platform/socket_compat.h"
#include "config/cli_lane_defaults.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <poll.h>
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define CAS_BIN "build/bin/zclassic23"
#define CAS_DEV_BIN "build/bin/z23-dev"

static bool cas_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static long cas_file_mtime(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_mtime;
}

/* Witness sources for the behavior this group exercises: is_cli_mode()'s
 * full-argv scan, cli_main()'s strict validator, and the shared flag-
 * classification policy. */
static const char *const cas_stale_witnesses[] = {
    "engine/entry/main.c",
    "engine/entry/main_cli_modes.c",
    "engine/composition/include/config/cli_lane_defaults.h",
    "engine/composition/src/args.c",
    "engine/composition/include/config/args.h",
    "engine/composition/include/config/boot.h",
    "engine/composition/src/boot_p2p_listen.c",
    "engine/composition/src/boot_services.c",
    "platform/modules/platform/include/platform/socket_compat.h",
    "engine/composition/commands/apps.def",
    "tools/command/native_command.c",
    "engine/controllers/src/transaction_type_catalog.c",
    "engine/controllers/include/controllers/transaction_types.def",
    NULL,
};

static bool cas_bin_is_fresh(const char **stale_path_out)
{
    long bin_mt = cas_file_mtime(CAS_BIN);
    if (bin_mt < 0) return false;
    for (size_t i = 0; cas_stale_witnesses[i]; i++) {
        long src_mt = cas_file_mtime(cas_stale_witnesses[i]);
        if (src_mt < 0) continue;
        if (src_mt > bin_mt) {
            if (stale_path_out) *stale_path_out = cas_stale_witnesses[i];
            return false;
        }
    }
    return true;
}

static void cas_mkdir_p(const char *path)
{
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        fprintf(stderr, "cas_mkdir_p: mkdir(%s) failed: %s\n",
                path, strerror(errno));
}

static bool cas_contains(const char *hay, const char *needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

/* Bind to port 0, read back the OS-assigned free port, close. Same idiom as
 * test_cli_auth_robust.c's car_reserve_port() / test_cookie_rotation.c. */
static uint16_t cas_reserve_port_once(void)
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
    /* Never the live serve/soak/test lane ports (39070-39073) even if the
     * OS ephemeral range somehow handed one back. */
    if (port >= 39070 && port <= 39073)
        return 0;
    return port;
}

/* A transient bind failure under a loaded pool must not read as "no port":
 * retry a bounded number of times (each attempt asks the OS for a fresh
 * ephemeral port) before giving up. */
static uint16_t cas_reserve_port(void)
{
    for (int attempt = 0; attempt < 16; attempt++) {
        uint16_t port = cas_reserve_port_once();
        if (port != 0) return port;
    }
    return 0;
}

/* Minimal envp: HOME=<home>, a fixed PATH, ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1
 * (see file header) so the CLI's systemctl-based default-service lookup
 * never resolves to this project's real zclassic23.service. Static scratch
 * — not reentrant, fine for this single-threaded test group. */
static char cas_env_home[PATH_MAX + 8];
static char *cas_envp[5];
/* Per-fixture overrides: binary to exec (default CAS_BIN) and one extra
 * NAME=value environment entry. Reset by each fixture that sets them. */
static const char *cas_exec_path = NULL;
static char cas_extra_env[PATH_MAX + 32];
/* When set, the child PATH is only the fixture bin directory and the
 * systemctl-disable variable is absent, so a lookup really execs. */
static int cas_service_watch;
static char cas_service_path[PATH_MAX + 8];

static const char *cas_exec_target(void)
{
    return cas_exec_path ? cas_exec_path : CAS_BIN;
}

static char *const *cas_build_envp(const char *home)
{
    snprintf(cas_env_home, sizeof(cas_env_home), "HOME=%s", home);
    cas_envp[0] = cas_env_home;
    if (cas_service_watch) {
        cas_envp[1] = cas_service_path;
        cas_envp[2] = NULL;
        return cas_envp;
    }
    cas_envp[1] = (char *)"PATH=/usr/bin:/bin:/usr/local/bin";
    cas_envp[2] = (char *)"ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1";
    cas_envp[3] = cas_extra_env[0] ? cas_extra_env : NULL;
    cas_envp[4] = NULL;
    return cas_envp;
}

/* Fork/exec CAS_BIN with a caller-built argv, capture combined stdout+
 * stderr (truncated, non-blocking drain), and wait for it to EXIT on its
 * own. For CLI-client-mode cases only — cli_main() always returns. Same
 * shape as test_cli_auth_robust.c's car_run / test_importblockindex_cli_
 * dispatch.c's icd_run. */
static int cas_run(char *const argv[], const char *home, char *out,
                   size_t cap)
{
#if defined(_WIN32)
    /* No fork on this lane: the CreateProcess+pipe analogue returns the
     * child's exit code directly. */
    return test_spawn_capture_env((const char *const *)argv,
                                  (const char *const *)cas_build_envp(home),
                                  out, cap);
#else
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execve(cas_exec_target(), argv,
               cas_build_envp(home));
        _exit(127);
    }
    close(pipefd[1]);
    size_t pos = 0;
    char buf[4096];
    ssize_t r;
    while ((r = read(pipefd[0], buf, sizeof(buf))) > 0) {
        size_t take = (size_t)r;
        size_t room = (pos + 1 < cap) ? (cap - 1 - pos) : 0;
        if (take > room) take = room;
        if (take > 0) { memcpy(out + pos, buf, take); pos += take; }
    }
    out[pos < cap ? pos : cap - 1] = 0;
    close(pipefd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -100 - WTERMSIG(status);
    return -1;
#endif
}

/* Return the monotonic clock in milliseconds. Used only to bound how long the
 * daemon-mode capture below is willing to wait — never to assert on. */
static long cas_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;  // platform-ok:test-capture-deadline-bounds-a-wait-never-an-assertion
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Fork/exec a DAEMON-mode invocation (never exits on its own), accumulate its
 * combined stdout+stderr until EVERY string in `needles` is present (or the
 * deadline passes / the child hangs up), then SIGKILL it regardless and reap
 * it. Returns true iff all needles appeared. Only used for the one
 * genuinely-boots case in this file.
 *
 * Reads until EVERY needle is present: a read boundary can fall inside the
 * warning line under load, so stopping at the first match is flaky. The
 * deadline is real elapsed time, not a per-iteration count. */
static bool cas_run_daemon_wait_for(char *const argv[], const char *home,
                                    const char *const *needles, int max_ms,
                                    char *out, size_t cap)
{
#if defined(_WIN32)
    /* PeekNamedPipe-drained spawn + TerminateProcess analogue (no fork, no
     * poll-on-pipe, no SIGKILL on this lane). */
    return test_spawn_capture_kill((const char *const *)argv,
                                   (const char *const *)cas_build_envp(home),
                                   needles, max_ms, out, cap);
#else
    int pipefd[2];
    if (pipe(pipefd) != 0) return false;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execve(cas_exec_target(), argv,
               cas_build_envp(home));
        _exit(127);
    }
    close(pipefd[1]);

    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    size_t pos = 0;
    out[0] = 0;
    bool found = false;
    const long deadline = cas_now_ms() + max_ms;
    for (;;) {
        long remaining = deadline - cas_now_ms();
        if (remaining <= 0) break;
        if (remaining > 50) remaining = 50;
        struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
        int pr = poll(&pfd, 1, (int)remaining);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            char buf[4096];
            ssize_t r = read(pipefd[0], buf, sizeof(buf));
            if (r > 0) {
                size_t take = (size_t)r;
                size_t room = (pos + 1 < cap) ? (cap - 1 - pos) : 0;
                if (take > room) take = room;
                if (take > 0) {
                    memcpy(out + pos, buf, take);
                    pos += take;
                    out[pos] = 0;
                }
                bool all = true;
                for (size_t i = 0; needles[i]; i++)
                    if (!strstr(out, needles[i])) { all = false; break; }
                if (all) { found = true; break; }
            } else if (r == 0) {
                break; /* child exited before printing everything */
            }
        } else if (pr > 0 && (pfd.revents & (POLLHUP | POLLERR))) {
            break;
        }
    }
    out[pos < cap ? pos : cap - 1] = 0;

    kill(pid, SIGKILL);
    int status = 0;
    waitpid(pid, &status, 0);
    close(pipefd[0]);
    if (found) return true;
    for (size_t i = 0; needles[i]; i++)
        if (!strstr(out, needles[i])) return false;
    return true;
#endif
}

/* A systemctl that only records that it ran. The boot command must not
 * exec it; a command that still needs the user unit must. */
static int cas_write_systemctl(const char *dir, const char *log_path)
{
    char path[PATH_MAX];
    FILE *f;
    int n = snprintf(path, sizeof(path), "%s/systemctl", dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    f = fopen(path, "w");
    if (!f) return -1;
    if (fprintf(f, "#!/bin/sh\nprintf '%%s\\n' \"$*\" >> '%s'\nexit 0\n",
                log_path) < 0) {
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) return -1;
    if (chmod(path, 0700) != 0) return -1;
    return 0;
}

static bool cas_dev_bin_fresh(void)
{
    long bin_mt = cas_file_mtime(CAS_DEV_BIN);
    long cli_mt = cas_file_mtime("engine/entry/main_cli_modes.c");
    long pol_mt = cas_file_mtime(
        "engine/composition/include/config/cli_lane_defaults.h");
    if (bin_mt < 0) return false;
    if (cli_mt > bin_mt) return false;
    if (pol_mt > bin_mt) return false;
    return true;
}

static int cas_test_machine_boot_skips_service(void)
{
#if defined(_WIN32)
    return 0;
#else
    int failures = 0;
    TEST("guest boot skips systemctl; status still resolves the user unit") {
        const char *boot_params[] = {"app", "machine", "boot", "--input=x"};
        const char *land_params[] = {"land", "status"};
        char home[PATH_MAX];
        char bin[PATH_MAX];
        char log[PATH_MAX];
        char out[16384];
        char status_out[8192];
        char *boot_argv[] = {
            (char *)CAS_DEV_BIN, (char *)"dev", (char *)"app",
            (char *)"machine", (char *)"boot",
            (char *)"--input={\"kernel\":\"tests/fixtures/rvmachine/tiny.bin\",\"max_instr\":100000}",
            NULL,
        };
        char *status_argv[] = {
            (char *)CAS_DEV_BIN, (char *)"status", NULL,
        };
        int rc;
        ASSERT(zcl_cli_skips_service_lookup("dev", boot_params, 4));
        ASSERT(!zcl_cli_skips_service_lookup("dev", land_params, 2));
        ASSERT(!zcl_cli_skips_service_lookup("status", boot_params, 4));
        ASSERT(!zcl_cli_skips_service_lookup(NULL, boot_params, 4));
        ASSERT(zcl_cli_service_lookup_blocked("status", boot_params, 4)
               == (getenv("ZCL_CLI_TEST_NO_SERVICE_LOOKUP") != NULL));
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_boot_svc", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);
        ASSERT(snprintf(bin, sizeof(bin), "%s/bin", home) > 0);
        cas_mkdir_p(bin);
        ASSERT(snprintf(log, sizeof(log), "%s/systemctl.log", home) > 0);
        unlink(log);
        ASSERT(cas_write_systemctl(bin, log) == 0);
        ASSERT(snprintf(cas_service_path, sizeof(cas_service_path),
                        "PATH=%s", bin) > 0);
        cas_service_watch = 1;
        cas_exec_path = CAS_DEV_BIN;
        memset(out, 0, sizeof(out));
        rc = cas_run(boot_argv, home, out, sizeof(out));
        ASSERT_EQ(rc, 0);
        ASSERT(cas_contains(out, "\"retired\":279"));
        ASSERT(!cas_file_exists(log));
        memset(status_out, 0, sizeof(status_out));
        (void)cas_run(status_argv, home, status_out, sizeof(status_out));
        ASSERT(cas_file_exists(log));
        cas_service_watch = 0;
        cas_exec_path = NULL;
        PASS();
    } _test_next:;
    cas_service_watch = 0;
    cas_exec_path = NULL;
    return failures;
#endif
}

/* ── test cases ───────────────────────────────────────────────────── */

static int cas_test_observed_incident_refuses(void)
{
    int failures = 0;
    TEST("CLI-client argv: the exact observed incident "
         "`--port=39071 status` (double-dash typo, no -datadir=) is "
         "HARD REFUSED — never falls through to a node boot") {
        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_incident", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN, (char *)"--port=39071", (char *)"status",
            NULL,
        };
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(cas_contains(out, "error=UNRECOGNIZED_FLAG"));
        ASSERT(cas_contains(out, "--port=39071"));
        ASSERT(cas_contains(out, "-port=PORT"));
        ASSERT(cas_contains(out, "-datadir=DIR"));
        /* The core safety property: no node boot ever started. */
        ASSERT(!cas_contains(out, "starting (datadir="));
        ASSERT(!cas_contains(out, "Chain tip:"));
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_double_dash_datadir_refuses(void)
{
    int failures = 0;
    TEST("CLI-client argv: a value-less `--datadir status` is refused with "
         "the exact -datadir=DIR correction") {
        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_ddatadir", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN, (char *)"--datadir", (char *)"status", NULL,
        };
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(cas_contains(out, "error=UNRECOGNIZED_FLAG"));
        ASSERT(cas_contains(out, "-datadir=DIR"));
        ASSERT(!cas_contains(out, "starting (datadir="));
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_double_dash_targets_accepted(void)
{
    int failures = 0;
    TEST("CLI-client argv: `--datadir=DIR --rpcport=N` mean exactly "
         "`-datadir=DIR -rpcport=N`") {
        char home[PATH_MAX], datadir[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_ddok", "home");
        test_fmt_tmpdir(datadir, sizeof(datadir), "zcl_cas_ddok", "dd");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);
        cas_mkdir_p(datadir);

        char double_dd[PATH_MAX + 16], single_dd[PATH_MAX + 16];
        snprintf(double_dd, sizeof(double_dd), "--datadir=%s", datadir);
        snprintf(single_dd, sizeof(single_dd), "-datadir=%s", datadir);
        char *dbl[] = { (char *)CAS_BIN, double_dd, (char *)"--rpcport=39071",
                        (char *)"app", (char *)"transaction-types",
                        (char *)"list", NULL };
        char *sgl[] = { (char *)CAS_BIN, single_dd, (char *)"-rpcport=39071",
                        (char *)"app", (char *)"transaction-types",
                        (char *)"list", NULL };
        char out_dbl[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1] = {0};
        char out_sgl[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1] = {0};
        int rc_dbl = cas_run(dbl, home, out_dbl, sizeof(out_dbl));
        int rc_sgl = cas_run(sgl, home, out_sgl, sizeof(out_sgl));

        ASSERT_EQ(rc_dbl, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(rc_dbl, rc_sgl);
        ASSERT(!cas_contains(out_dbl, "UNRECOGNIZED_FLAG"));
        ASSERT(cas_contains(out_dbl, "zcl.transaction_types.index.v2"));
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_missing_value_refuses(void)
{
    int failures = 0;
    TEST("CLI-client argv: a bare `-rpcport` (missing \"=value\") is "
         "refused, not silently treated as the RPC method name") {
        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_missingval", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN, (char *)"-rpcport", (char *)"status", NULL,
        };
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(cas_contains(out, "error=UNRECOGNIZED_FLAG"));
        ASSERT(cas_contains(out, "-rpcport=PORT"));
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_typo_after_command_word_refuses(void)
{
    int failures = 0;
    TEST("CLI-client argv: `status --port=N` (typo AFTER the command "
         "word) is still refused — proves the classification/validation "
         "scan does not depend on flag position") {
        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_afterword", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN, (char *)"status", (char *)"--port=39071",
            NULL,
        };
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(cas_contains(out, "error=UNRECOGNIZED_FLAG"));
        ASSERT(!cas_contains(out, "starting (datadir="));
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_bare_status_still_works(void)
{
    int failures = 0;
    TEST("CLI-client argv: bare `status` with NO flags at all is NEVER "
         "refused — it intentionally targets the default local node") {
        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_barestatus", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char *argv[] = { (char *)CAS_BIN, (char *)"status", NULL };
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT(!cas_contains(out, "error=UNRECOGNIZED_FLAG"));
        /* No live node in this fresh isolated fixture's default datadir —
         * the E4 local-instances listing fallback, not a node boot. */
        ASSERT(cas_contains(out, "zcl.cli_local_instances.v1"));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_TRANSIENT);
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_native_param_conventions_unaffected(void)
{
    int failures = 0;
    TEST("CLI-client argv: legitimate native-command param conventions "
         "(--next) are NOT operator-target flags and are never refused "
         "— the strict validator is deliberately narrow") {
        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_nextparam", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN, (char *)"status", (char *)"--next", NULL,
        };
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT(!cas_contains(out, "error=UNRECOGNIZED_FLAG"));
        (void)rc;
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_extended_transaction_catalog_fits(void)
{
    int failures = 0;
    TEST("native CLI: the complete 39-type transaction catalog crosses the "
         "8 KiB boundary and still fits its declared 16 KiB budget") {
        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_tx_catalog", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN, (char *)"app", (char *)"transaction-types",
            (char *)"list", NULL,
        };
        char out[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_OK);
        ASSERT(strlen(out) > ZCL_COMMAND_LIST_BUDGET);
        ASSERT(strlen(out) <= ZCL_COMMAND_EXTENDED_LIST_BUDGET);
        ASSERT(cas_contains(out, "\"data_schema\":\"zcl.transaction_types.index.v2\""));
        ASSERT(cas_contains(out, "\"transaction_type_count\":39"));
        ASSERT(!cas_contains(out, "RESPONSE_BUDGET_EXCEEDED"));
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_extended_transaction_guide_fits(void)
{
    int failures = 0;
    TEST("native CLI: the largest transaction guide crosses the 8 KiB "
         "boundary and still fits its declared 16 KiB budget") {
        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_tx_guide", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN, (char *)"app", (char *)"transaction-types",
            (char *)"guide", (char *)"--type=zcode_release_anchor", NULL,
        };
        char out[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_OK);
        ASSERT(strlen(out) > ZCL_COMMAND_LIST_BUDGET);
        ASSERT(strlen(out) <= ZCL_COMMAND_EXTENDED_LIST_BUDGET);
        ASSERT(cas_contains(out,
                            "\"data_schema\":\"zcl.transaction_type_guide.v1\""));
        ASSERT(cas_contains(out, "\"id\":\"zcode_release_anchor\""));
        ASSERT(!cas_contains(out, "RESPONSE_BUDGET_EXCEEDED"));
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_daemon_mode_tolerant_and_warns(void)
{
    int failures = 0;
    TEST("daemon argv: NO command word present + the identical "
         "double-dash typo stays TOLERANT (still attempts to boot) but "
         "WARNs with the exact single-dash correction") {
        uint16_t port = cas_reserve_port();
        if (port == 0) {
            printf("UNOBSERVED (cli_argv_strict: could not reserve a test port — "
                   "daemon-tolerant case)\n");
            return 0;
        }
        char home[PATH_MAX], datadir[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_daemon", "home");
        test_fmt_tmpdir(datadir, sizeof(datadir), "zcl_cas_daemon", "dd");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char datadir_flag[PATH_MAX + 16], rpcport_flag[32], port_flag[32];
        snprintf(datadir_flag, sizeof(datadir_flag), "-datadir=%s", datadir);
        snprintf(rpcport_flag, sizeof(rpcport_flag), "--rpcport=%u", port);
        uint16_t p2p_port = cas_reserve_port();
        snprintf(port_flag, sizeof(port_flag), "-port=%u",
                p2p_port ? p2p_port : 0);

        /* No command word anywhere -> daemon mode. -nolegacyimport/
         * -nobgvalidation keep this fresh/empty fixture datadir from doing
         * any real chain work before the WARN (printed during argv parsing,
         * long before app_init) is captured. */
        char *argv[] = {
            (char *)CAS_BIN, datadir_flag, rpcport_flag, port_flag,
            (char *)"-nolegacyimport", (char *)"-nobgvalidation", NULL,
        };
        /* BOTH halves of the warning are named so the capture keeps reading
         * until the whole line (one fprintf in engine/composition/src/args.c)
         * is in hand regardless of pipe chunking. Generous budget: forking
         * this child under a loaded parallel run can be slow, but stays inside
         * the 300s per-group timeout. */
        static const char *const warn_needles[] = {
            "unrecognized flag '--rpcport=",
            "did you mean -rpcport=PORT?",
            NULL,
        };
        char out[16384] = {0};
        bool saw_warn = cas_run_daemon_wait_for(
            argv, home, warn_needles, 20000, out, sizeof(out));

        if (!saw_warn || !cas_contains(out, "did you mean -rpcport=PORT?"))
            fprintf(stderr, "cas_test_daemon_mode_tolerant_and_warns: "
                    "captured output:\n%s\n", out);
        ASSERT(saw_warn);
        ASSERT(cas_contains(out, "unrecognized flag '--rpcport="));
        ASSERT(cas_contains(out, "did you mean -rpcport=PORT?"));
        /* Tolerant: this is NOT the CLI-client hard refusal. */
        ASSERT(!cas_contains(out, "error=UNRECOGNIZED_FLAG"));
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
/* Keep this exact loopback port occupied throughout the child invocation.
 * CLOEXEC prevents the node from inheriting the fixture's listener. */
static platform_socket_t cas_hold_bind_collision_once(uint16_t *port)
{
    *port = 0;
    platform_socket_t sock = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (sock == PLATFORM_SOCKET_INVALID) return sock;
    struct sockaddr_in address = { .sin_family = AF_INET };
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    size_t size = sizeof(address);
    bool ok = platform_socket_bind(sock, (struct sockaddr *)&address, size) == 0 &&
        platform_socket_listen(sock, 1) == 0 &&
        platform_socket_local_address(sock, (struct sockaddr *)&address, &size) == 0;
    if (ok) *port = ntohs(address.sin_port);
    if (!*port) {
        (void)platform_socket_close(sock);
        *port = 0;
        return PLATFORM_SOCKET_INVALID;
    }
    return sock;
}

static platform_socket_t cas_hold_bind_collision(uint16_t *port)
{
    for (int attempt = 0; attempt < 16; attempt++) {
        platform_socket_t sock = cas_hold_bind_collision_once(port);
        if (sock == PLATFORM_SOCKET_INVALID) return sock; /* Real setup error. */
        if (*port < 39070 || *port > 39073) return sock;
        /* Retry only an excluded lane port, after releasing our exact socket. */
        if (platform_socket_close(sock) != 0) break;
    }
    *port = 0;
    return PLATFORM_SOCKET_INVALID;
}

static bool cas_capture_bind_refusal(const char *root, uint16_t port,
                                     char *out, size_t cap,
                                     struct zcl_spawn_binary_observation *observed)
{
    /* root is a checked PATH_MAX-sized test_mkdtemp result; each buffer
     * reserves the full fixed suffix as well as its terminating byte. */
    char home[PATH_MAX+8], datadir[PATH_MAX+8], home_env[PATH_MAX+16];
    char datadir_flag[PATH_MAX+24], port_flag[32], connect_flag[64];
    snprintf(home, sizeof(home), "%s/home", root);
    snprintf(datadir, sizeof(datadir), "%s/dd", root);
    if (mkdir(home, 0700) != 0 || mkdir(datadir, 0700) != 0) return false;
    snprintf(home_env, sizeof(home_env), "HOME=%s", home);
    snprintf(datadir_flag, sizeof(datadir_flag), "-datadir=%s", datadir);
    snprintf(port_flag, sizeof(port_flag), "-port=%u", port);
    snprintf(connect_flag, sizeof(connect_flag), "-connect=127.0.0.1:%u", port);
    const char *argv[] = {
        "/usr/bin/env", "-i", home_env, "PATH=/usr/bin:/bin:/usr/local/bin",
        "ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1", CAS_BIN, datadir_flag, port_flag,
        "-bind=127.0.0.1", connect_flag, "-regtest", "-profile=zclassic-only",
        "-operator-lane=test", "-rpcport=0", "-httpsport=-1", "-fsport=0",
        "-nolegacyimport", "-nobgvalidation", "-nofilesync", "-showmetrics=0", NULL,
    };
    /* The native capture owns its child group and bounded reap. Nonzero is
     * expected, but timeout, truncation or unobserved status never qualify. */
    struct zcl_result capture =
        zcl_spawn_capture_binary_merged(argv, out, cap-1, 20000, observed);
    bool complete_refusal = observed->exit_observed && observed->exit_code == 1 &&
        observed->eof && !observed->timed_out && !observed->overflow;
    /* Expected exit 1 makes capture.ok false; the observation is authority. */
    if (!capture.ok && !complete_refusal)
        fprintf(stderr, "bind refusal capture: %s\n", capture.message);
    size_t used = observed->output_len < cap ? observed->output_len : cap-1;
    out[used] = '\0';
    return true;
}

static bool cas_bind_refusal_observed(const char *out,
                                     const struct zcl_spawn_binary_observation *observed)
{
    return observed->exit_observed && observed->exit_code == 1 && observed->eof &&
        !observed->timed_out && !observed->overflow &&
        cas_contains(out, "P2P explicit bind failed:") &&
        cas_contains(out, "(no fallback)") && cas_contains(out, "BOOT_INIT_FAILED") &&
        cas_contains(out, "stage_reached=network_ready") &&
        !cas_contains(out, "stage_reached=ready");
}
#endif

static int cas_test_explicit_bind_failure_exits(void)
{
#if defined(_WIN32)
    printf("UNOBSERVED (explicit P2P boot refusal: bounded merged capture is POSIX-only)\n");
    return 0;
#else
    int failures = 0;
    TEST("explicit occupied P2P bind exits nonzero before ready, without fallback") {
        char root[PATH_MAX] = {0};
        bool made = test_mkdtemp(root, sizeof(root), "zcl_cas_bind_exit") != NULL;
        uint16_t port = 0;
        platform_socket_t held = made ? cas_hold_bind_collision(&port) : PLATFORM_SOCKET_INVALID;
        char out[65537] = {0};
        struct zcl_spawn_binary_observation observed = {0};
        bool dispatched = held != PLATFORM_SOCKET_INVALID &&
            cas_capture_bind_refusal(root, port, out, sizeof(out), &observed);
        bool qualified = dispatched && cas_bind_refusal_observed(out, &observed);
        if (!qualified) fprintf(stderr, "explicit P2P bind fixture output:\n%s\n", out);
        bool closed = held == PLATFORM_SOCKET_INVALID || platform_socket_close(held) == 0;
        bool cleaned = !made || test_rm_rf_recursive(root) == 0;
        ASSERT(made && dispatched);
        ASSERT(qualified);
        ASSERT(closed && cleaned);
        printf("observed exit=1 stage=network_ready bytes=%zu; owned fixture cleaned\n",
               observed.output_len);
        PASS();
    } _test_next:;
    return failures;
#endif
}

static int cas_test_noisetransport_is_recognized(void)
{
    int failures = 0;
    TEST("daemon argv: -noisetransport is a recognized GetBoolArg flag and "
         "never emits the unknown-flag warning") {
        uint16_t rpc_port = cas_reserve_port();
        uint16_t p2p_port = cas_reserve_port();
        if (rpc_port == 0 || p2p_port == 0) {
            printf("UNOBSERVED (cli_argv_strict: could not reserve test ports — "
                   "noisetransport case)\n");
            return 0;
        }
        char home[PATH_MAX], datadir[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_v2", "home");
        test_fmt_tmpdir(datadir, sizeof(datadir), "zcl_cas_v2", "dd");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char datadir_flag[PATH_MAX + 16], rpcport_flag[32], port_flag[32];
        snprintf(datadir_flag, sizeof(datadir_flag), "-datadir=%s", datadir);
        snprintf(rpcport_flag, sizeof(rpcport_flag), "-rpcport=%u", rpc_port);
        snprintf(port_flag, sizeof(port_flag), "-port=%u", p2p_port);
        char *argv[] = {
            (char *)CAS_BIN, datadir_flag, rpcport_flag, port_flag,
            (char *)"-regtest", (char *)"-nolegacyimport",
            (char *)"-nobgvalidation", (char *)"-noisetransport", NULL,
        };
        static const char *const ready_needles[] = {
            "z23 starting", NULL,
        };
        char out[16384] = {0};
        bool started = cas_run_daemon_wait_for(
            argv, home, ready_needles, 20000, out, sizeof(out));

        ASSERT(started);
        ASSERT(!cas_contains(out, "unrecognized flag '-noisetransport'"));

        uint16_t legacy_rpc_port = cas_reserve_port();
        uint16_t legacy_p2p_port = cas_reserve_port();
        if (legacy_rpc_port == 0 || legacy_p2p_port == 0) {
            printf("UNOBSERVED (cli_argv_strict: could not reserve legacy "
                   "noisetransport test ports)\n");
            return failures;
        }
        char legacy_home[PATH_MAX], legacy_datadir[PATH_MAX];
        test_fmt_tmpdir(legacy_home, sizeof(legacy_home),
                        "zcl_cas_legacy_noise", "home");
        test_fmt_tmpdir(legacy_datadir, sizeof(legacy_datadir),
                        "zcl_cas_legacy_noise", "dd");
        (void)test_ensure_tmproot();
        cas_mkdir_p(legacy_home);
        snprintf(datadir_flag, sizeof(datadir_flag), "-datadir=%s",
                 legacy_datadir);
        snprintf(rpcport_flag, sizeof(rpcport_flag), "-rpcport=%u",
                 legacy_rpc_port);
        snprintf(port_flag, sizeof(port_flag), "-port=%u", legacy_p2p_port);
        char *legacy_argv[] = {
            (char *)CAS_BIN, datadir_flag, rpcport_flag, port_flag,
            (char *)"-regtest", (char *)"-nolegacyimport",
            (char *)"-nobgvalidation", (char *)"-v2transport", NULL,
        };
        static const char *const legacy_needles[] = {
            "z23 starting", "-v2transport is deprecated", NULL,
        };
        memset(out, 0, sizeof(out));
        started = cas_run_daemon_wait_for(legacy_argv, legacy_home,
                                          legacy_needles, 20000, out,
                                          sizeof(out));
        ASSERT(started);
        ASSERT(!cas_contains(out, "unrecognized flag '-v2transport'"));
        ASSERT(cas_contains(out, "-v2transport is deprecated"));
        PASS();
    } _test_next:;
    return failures;
}

int test_cli_argv_strict(void);

/* A -datadir= value that does not fit the CLI's path buffer must refuse
 * before any routing: an unchecked copy would chop the cookie directory,
 * and the 511-byte prefix of a chosen path can name another node's
 * directory — the CLI would hand that node's cookie to the wrong lane.
 * Refusal is the standard invalid-invocation exit with a marker the
 * sibling double-dash/missing-value refusals already established. */
static int cas_test_overlong_datadir_refuses(void)
{
    int failures = 0;
    TEST("CLI-client argv: a -datadir= longer than the path buffer is "
         "refused, not chopped into another node's cookie directory") {
        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_overlong", "home");
        (void)test_ensure_tmproot();
        cas_mkdir_p(home);

        char over[600];
        memset(over, 'd', sizeof(over) - 1);
        over[sizeof(over) - 1] = '\0';
        char flag[9 + sizeof(over)];
        int fl = snprintf(flag, sizeof(flag), "-datadir=%s", over);
        ASSERT(fl > 0 && (size_t)fl < sizeof(flag));

        char *argv[] = {(char *)CAS_BIN, flag, (char *)"status", NULL};
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(cas_contains(out, "DATADIR_TOO_LONG"));
        ASSERT(cas_contains(out, "no silent truncation"));
        ASSERT(!cas_contains(out, "starting (datadir="));
        PASS();
    } _test_next:;
    return failures;
}


#define CAS_RPC_BIN "build/bin/zcl-rpc"

/* Build base + "/" + 200 x 'a' + "/" + 200 x 'b' + "/" + 'c' padding so
 * the whole string is exactly `total` bytes, creating every directory
 * level that fits below `make_upto` bytes (the decoy-bearing prefix). */
static bool cas_build_long_dir(char *out, size_t cap, const char *base,
                               size_t total, size_t make_upto)
{
    int n = snprintf(out, cap, "%s/", base);
    if (n < 0 || (size_t)n + 402 >= total || total + 1 > cap) return false;
    size_t len = (size_t)n;
    memset(out + len, 'a', 200); len += 200; out[len++] = '/';
    memset(out + len, 'b', 200); len += 200; out[len++] = '/';
    memset(out + len, 'c', total - len); out[total] = '\0';
    for (size_t i = (size_t)n; i <= total; i++) {
        if ((out[i] == '/' || i == total) && i <= make_upto) {
            char sv = out[i]; out[i] = '\0';
            cas_mkdir_p(out); out[i] = sv;
        }
    }
    if (make_upto < total) {
        char sv = out[make_upto]; out[make_upto] = '\0';
        cas_mkdir_p(out); out[make_upto] = sv;
    }
    return true;
}

static bool cas_write_decoy(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fputs("decoy:cookie\n", f);
    return fclose(f) == 0;
}

/* An over-long HOME makes the default datadir overflow the buffer; the
 * chopped 511-byte prefix is a real directory holding a decoy .cookie. The
 * client must refuse (DATADIR_TOO_LONG, invalid-invocation exit) and a
 * short explicit -datadir= must still be accepted despite that HOME. */
static int cas_test_overlong_home_default_refuses(void)
{
    int failures = 0;
    TEST("CLI-client: an over-long HOME makes the default datadir refuse "
         "(DATADIR_TOO_LONG), never a chopped prefix directory") {
        char base[PATH_MAX];
        test_fmt_tmpdir(base, sizeof(base), "zcl_cas_homelong", "root");
        (void)test_ensure_tmproot();
        cas_mkdir_p(base);

        char home[1024];
        ASSERT(cas_build_long_dir(home, sizeof(home), base, 520, 511));
        char decoy[1100];
        snprintf(decoy, sizeof(decoy), "%.511s/.cookie", home);
        ASSERT(cas_write_decoy(decoy));

        char *argv[] = {(char *)CAS_BIN, (char *)"status", NULL};
        char out[8192] = {0};
        cas_exec_path = NULL;
        cas_extra_env[0] = '\0';
        int rc = cas_run(argv, home, out, sizeof(out));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(cas_contains(out, "DATADIR_TOO_LONG"));
        ASSERT(cas_contains(out, "no silent truncation"));

        /* A short explicit target is unaffected by the long HOME. */
        char shortdd[PATH_MAX];
        test_fmt_tmpdir(shortdd, sizeof(shortdd), "zcl_cas_homelong", "dd");
        cas_mkdir_p(shortdd);
        char flag[PATH_MAX + 16];
        snprintf(flag, sizeof(flag), "-datadir=%s", shortdd);
        char *argv2[] = {(char *)CAS_BIN, flag, (char *)"status", NULL};
        char out2[8192] = {0};
        (void)cas_run(argv2, home, out2, sizeof(out2));
        ASSERT(!cas_contains(out2, "DATADIR_TOO_LONG"));
        PASS();
    } _test_next:;
    return failures;
}

/* zcl-rpc: an over-long ZCL_DATADIR is refused before any file opens. The
 * datadir is 505 bytes so "<datadir>/.cookie" (513) truncates to
 * "<datadir>/.cooki": a decoy of exactly that name is what the unchecked
 * copy would have read as the node's cookie. */
static int cas_test_zcl_rpc_overlong_datadir_refuses(void)
{
    int failures = 0;
    TEST("zcl-rpc: an over-long ZCL_DATADIR is refused (DATADIR_TOO_LONG, "
         "non-zero) and the chopped-path decoy cookie is not read") {
        if (!cas_file_exists(CAS_RPC_BIN) ||
            cas_file_mtime(CAS_RPC_BIN) < cas_file_mtime("tools/zcl-rpc.c")) {
            printf("SKIP (cli_argv_strict: %s missing or stale — zcl-rpc "
                   "fixture)\n", CAS_RPC_BIN);
            goto _test_next;
        }
        char base[PATH_MAX];
        test_fmt_tmpdir(base, sizeof(base), "zcl_cas_rpclong", "root");
        (void)test_ensure_tmproot();
        cas_mkdir_p(base);
        char dd[1024];
        ASSERT(cas_build_long_dir(dd, sizeof(dd), base, 505, 505));
        char decoy[1100];
        snprintf(decoy, sizeof(decoy), "%s/.cooki", dd);
        ASSERT(cas_write_decoy(decoy));

        char home[PATH_MAX];
        test_fmt_tmpdir(home, sizeof(home), "zcl_cas_rpclong", "home");
        cas_mkdir_p(home);
        snprintf(cas_extra_env, sizeof(cas_extra_env), "ZCL_DATADIR=%s", dd);
        cas_exec_path = CAS_RPC_BIN;
        char *argv[] = {(char *)CAS_RPC_BIN, (char *)"getblockcount", NULL};
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));
        cas_exec_path = NULL;
        cas_extra_env[0] = '\0';
        ASSERT(rc != 0);
        ASSERT(cas_contains(out, "DATADIR_TOO_LONG"));
        ASSERT(!cas_contains(out, "decoy"));
        PASS();
    } _test_next:;
    return failures;
}
int test_cli_argv_strict(void)
{
    int failures = 0;

    if (cas_dev_bin_fresh())
        failures += cas_test_machine_boot_skips_service();
    else
        printf("SKIP (cli_argv_strict: %s missing or stale for the "
               "service-lookup case)\n", CAS_DEV_BIN);

    if (!cas_file_exists(CAS_BIN)) {
        printf("SKIP (cli_argv_strict: %s not built — run `make` to "
               "build it)\n", CAS_BIN);
        return failures;
    }
    const char *stale_path = NULL;
    if (!cas_bin_is_fresh(&stale_path)) {
        printf("SKIP (cli_argv_strict: %s is stale — newer source: %s — "
               "run `make` to rebuild)\n", CAS_BIN,
               stale_path ? stale_path : "(unknown)");
        return failures;
    }

    failures += cas_test_observed_incident_refuses();
    failures += cas_test_double_dash_datadir_refuses();
    failures += cas_test_double_dash_targets_accepted();
    failures += cas_test_missing_value_refuses();
    failures += cas_test_typo_after_command_word_refuses();
    failures += cas_test_bare_status_still_works();
    failures += cas_test_native_param_conventions_unaffected();
    failures += cas_test_extended_transaction_catalog_fits();
    failures += cas_test_extended_transaction_guide_fits();
    failures += cas_test_daemon_mode_tolerant_and_warns();
    failures += cas_test_explicit_bind_failure_exits();
    failures += cas_test_noisetransport_is_recognized();
    failures += cas_test_overlong_datadir_refuses();
    failures += cas_test_overlong_home_default_refuses();
    failures += cas_test_zcl_rpc_overlong_datadir_refuses();

    return failures;
}
