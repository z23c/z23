/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_cli_argv_strict — proves the SAFETY FOOTGUN fix: `zclassic23
 * --rpcport=39071 status` (a
 * double-dash typo of `-rpcport=`, no `-datadir=`) must not have
 * is_cli_mode() bail
 * out at the unrecognized `--rpcport=39071` token before ever reaching
 * `status` — that shape falls through main()'s dispatch chain
 * into a full node boot against the DEFAULT datadir — the protected live
 * node's directory — running a read-only integrity check before its
 * shutdown watchdog kills it. Read-only that time; one flag-typo away
 * from a second process contending the live datadir.
 *
 * This group proves, against the REAL built binary (the way an operator or
 * orchestrator actually invokes it, matching test_cli_auth_robust.c /
 * test_importblockindex_cli_dispatch.c's established pattern — not the
 * static is_cli_mode()/cli_main() helpers directly):
 *
 *   1. CLI-client mode (a typed command word present) now HARD REFUSES any
 *      malformed operator-target flag (double-dash typo, or a bare flag
 *      missing its "=value") instead of silently mis-routing — including
 *      the exact observed invocation, and regardless of the flag's
 *      position relative to the command word.
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
 * ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1 (see test_cli_auth_robust.c's file
 * header) so the CLI's default-datadir resolution and the systemctl-based
 * service lookup never touch this project's real datadir/service — every
 * refusal case never even reaches datadir resolution, and the one daemon-
 * mode case that genuinely boots targets a throwaway /tmp datadir + a
 * freshly reserved (never 39070-39073) port, killed within ~2s.
 *
 * Skips (does not fail) if build/bin/zclassic23 is missing or stale vs the
 * source files that define this behavior — matching the guard pattern in
 * the sibling CLI dispatch tests.
 *
 * make t ONLY=cli_argv_strict
 */

#include "test/test_core.h"
#include "kernel/command_registry.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CAS_BIN "build/bin/zclassic23"

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
    "src/main.c",
    "src/main_cli_modes.c",
    "config/src/args.c",
    "config/include/config/args.h",
    "config/commands/apps.def",
    "tools/command/native_command.c",
    "app/controllers/src/transaction_type_catalog.c",
    "app/controllers/include/controllers/transaction_types.def",
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
static uint16_t cas_reserve_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    uint16_t port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        socklen_t len = sizeof(addr);
        if (getsockname(fd, (struct sockaddr *)&addr, &len) == 0)
            port = ntohs(addr.sin_port);
    }
    close(fd);
    /* Never the live serve/soak/test lane ports (39070-39073) even if the
     * OS ephemeral range somehow handed one back. */
    if (port >= 39070 && port <= 39073)
        return 0;
    return port;
}

/* Minimal envp: HOME=<home>, a fixed PATH, ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1
 * (see file header) so the CLI's systemctl-based default-service lookup
 * never resolves to this project's real zclassic23.service. Static scratch
 * — not reentrant, fine for this single-threaded test group. */
static char cas_env_home[600];
static char *cas_envp[4];

static char *const *cas_build_envp(const char *home)
{
    snprintf(cas_env_home, sizeof(cas_env_home), "HOME=%s", home);
    cas_envp[0] = cas_env_home;
    cas_envp[1] = (char *)"PATH=/usr/bin:/bin:/usr/local/bin";
    cas_envp[2] = (char *)"ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1";
    cas_envp[3] = NULL;
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
        execve(CAS_BIN, argv, cas_build_envp(home));
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
 * Why "every needle", and why a real deadline
 * -------------------------------------------
 * This function used to stop reading the instant ONE needle matched, and the
 * caller then asserted on a SECOND string that lives further along the same
 * log line. That works on an idle box for a reason that has nothing to do with
 * the code under test: the parent is scheduled promptly, so the warning's
 * single write() is returned by a read() all on its own and both strings land
 * in `out` together. Load breaks it. When the parent is descheduled the child
 * queues more than one 4096-byte read's worth of output, the read boundary
 * falls wherever it falls, and a boundary that lands INSIDE the warning line
 * leaves `out` holding "...unrecognized flag '--rpcport=39071' (ign" — enough
 * to satisfy the break condition, not enough to satisfy the assertion. The
 * group then fails having proven the binary behaved correctly.
 *
 * So: keep reading until everything the caller needs is actually present. The
 * old `waited += step_ms` per ITERATION was also not a time budget (a chatty
 * child burned the whole budget in reads, not in waiting); the deadline below
 * is real elapsed time. */
static bool cas_run_daemon_wait_for(char *const argv[], const char *home,
                                    const char *const *needles, int max_ms,
                                    char *out, size_t cap)
{
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
        execve(CAS_BIN, argv, cas_build_envp(home));
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
}

/* ── test cases ───────────────────────────────────────────────────── */

static int cas_test_observed_incident_refuses(void)
{
    int failures = 0;
    TEST("CLI-client argv: the exact observed incident "
         "`--rpcport=39071 status` (double-dash typo, no -datadir=) is "
         "HARD REFUSED — never falls through to a node boot") {
        char home[300];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_incident_%d",
                (int)getpid());
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN, (char *)"--rpcport=39071", (char *)"status",
            NULL,
        };
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(cas_contains(out, "error=UNRECOGNIZED_FLAG"));
        ASSERT(cas_contains(out, "--rpcport=39071"));
        ASSERT(cas_contains(out, "-rpcport=PORT"));
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
    TEST("CLI-client argv: `--datadir=... status` (double-dash typo) is "
         "refused with the exact -datadir=DIR correction") {
        char home[300];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_ddatadir_%d",
                (int)getpid());
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN,
            (char *)"--datadir=/tmp/zcl_cas_never_touched",
            (char *)"status", NULL,
        };
        char out[8192] = {0};
        int rc = cas_run(argv, home, out, sizeof(out));

        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(cas_contains(out, "error=UNRECOGNIZED_FLAG"));
        ASSERT(cas_contains(out, "-datadir=DIR"));
        ASSERT(!cas_contains(out, "starting (datadir="));
        /* Never actually touched the flag-supplied path. */
        struct stat st;
        ASSERT(stat("/tmp/zcl_cas_never_touched", &st) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int cas_test_missing_value_refuses(void)
{
    int failures = 0;
    TEST("CLI-client argv: a bare `-rpcport` (missing \"=value\") is "
         "refused, not silently treated as the RPC method name") {
        char home[300];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_missingval_%d",
                (int)getpid());
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
    TEST("CLI-client argv: `status --rpcport=N` (typo AFTER the command "
         "word) is still refused — proves the classification/validation "
         "scan does not depend on flag position") {
        char home[300];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_afterword_%d",
                (int)getpid());
        cas_mkdir_p(home);

        char *argv[] = {
            (char *)CAS_BIN, (char *)"status", (char *)"--rpcport=39071",
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
        char home[300];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_barestatus_%d",
                (int)getpid());
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
        char home[300];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_nextparam_%d",
                (int)getpid());
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
        char home[300];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_tx_catalog_%d",
                 (int)getpid());
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
        char home[300];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_tx_guide_%d",
                 (int)getpid());
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
            printf("cli_argv_strict: could not reserve a test port — SKIP "
                   "daemon-tolerant case\n");
            return 0;
        }
        char home[300], datadir[340];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_daemon_home_%d",
                (int)getpid());
        snprintf(datadir, sizeof(datadir), "/tmp/zcl_cas_daemon_dd_%d",
                 (int)getpid());
        cas_mkdir_p(home);

        char datadir_flag[400], rpcport_flag[32], port_flag[32];
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
        /* BOTH halves of the warning are named up front, so the capture keeps
         * reading until the whole line is in hand rather than stopping on the
         * first half and leaving the second to a read-boundary coin flip. The
         * two strings come from one fprintf in config/src/args.c, so on any
         * correct binary they arrive together; naming both is what makes that
         * true for the TEST regardless of how the pipe chunks them.
         *
         * Generous budget: under a full `make test-parallel` run (32
         * concurrent groups, each forking/execing its own heavy binaries),
         * scheduling this child's fork+exec+first-fprintf can take far
         * longer than it does standalone — the WARN itself is printed
         * within milliseconds of exec in an idle system, but wall-clock
         * delay under CPU contention is not this test's concern. Still
         * comfortably inside the 300s per-group timeout. */
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

static int cas_test_noisetransport_is_recognized(void)
{
    int failures = 0;
    TEST("daemon argv: -noisetransport is a recognized GetBoolArg flag and "
         "never emits the unknown-flag warning") {
        uint16_t rpc_port = cas_reserve_port();
        uint16_t p2p_port = cas_reserve_port();
        if (rpc_port == 0 || p2p_port == 0) {
            printf("cli_argv_strict: could not reserve test ports — SKIP "
                   "noisetransport case\n");
            return 0;
        }
        char home[300], datadir[340];
        snprintf(home, sizeof(home), "/tmp/zcl_cas_v2_home_%d",
                 (int)getpid());
        snprintf(datadir, sizeof(datadir), "/tmp/zcl_cas_v2_dd_%d",
                 (int)getpid());
        cas_mkdir_p(home);

        char datadir_flag[400], rpcport_flag[32], port_flag[32];
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
        PASS();
    } _test_next:;
    return failures;
}

int test_cli_argv_strict(void);

int test_cli_argv_strict(void)
{
    int failures = 0;

    if (!cas_file_exists(CAS_BIN)) {
        printf("cli_argv_strict: %s not built — SKIP (run `make` to "
               "build it)\n", CAS_BIN);
        return 0;
    }
    const char *stale_path = NULL;
    if (!cas_bin_is_fresh(&stale_path)) {
        printf("cli_argv_strict: %s is stale — newer source: %s — SKIP "
               "(run `make` to rebuild)\n", CAS_BIN,
               stale_path ? stale_path : "(unknown)");
        return 0;
    }

    failures += cas_test_observed_incident_refuses();
    failures += cas_test_double_dash_datadir_refuses();
    failures += cas_test_missing_value_refuses();
    failures += cas_test_typo_after_command_word_refuses();
    failures += cas_test_bare_status_still_works();
    failures += cas_test_native_param_conventions_unaffected();
    failures += cas_test_extended_transaction_catalog_fits();
    failures += cas_test_extended_transaction_guide_fits();
    failures += cas_test_daemon_mode_tolerant_and_warns();
    failures += cas_test_noisetransport_is_recognized();

    return failures;
}
