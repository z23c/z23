/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the -confine / -confine=serving strict node confinement profiles
 * (os_sandbox_node_confine_profile / os_sandbox_node_confine_serving_profile
 * / os_sandbox_seccomp_allow, backing the src/main.c -confine[=serving] flags
 * applied at config/src/boot.c sr_confine_enter).
 *
 * This IS the reproducible empirical derivation harness the allow-lists are
 * grounded in: a confined child runs the representative steady-state ops
 * (malloc, file I/O under the granted datadir, getrandom, a monotonic clock
 * read, and a real SQLite WAL CREATE/INSERT/SELECT against a datadir-local db)
 * under the seccomp ALLOW-list whose default action is KILL_PROCESS. If the
 * allow-list omits a syscall those ops need, the child is SIGSYS-killed and the
 * test FAILS — so the allow-list is driven to correctness for the exact tested
 * ops. Add a syscall to os_sandbox_node_confine_allowed_syscalls() (strict) or
 * os_sandbox_node_confine_serving_allowed_syscalls() (serving), re-run.
 *
 * The confinement builders MUTATE the calling process IRREVERSIBLY, so every
 * destructive assertion runs in a FRESHLY FORKED child judged by its exit
 * status / terminating signal (mirrors test_os_sandbox.c). The parent (the
 * test-group process) is never confined.
 *
 * Coverage — strict (-confine) profile:
 *   (a) normal ops work confined: enter node_confine, then file I/O in the
 *       datadir + malloc + getrandom + clock + SQLite SELECT -> child exits 0.
 *   (b) canary — Landlock: an open() of a path OUTSIDE the datadir grants
 *       (/etc/passwd) is EACCES-denied under confinement.
 *   (c) canary — seccomp: a forbidden syscall (socket) KILLs the process
 *       (SIGSYS), proving the strict allow-list is not overly permissive.
 *   (d) the allow-set is non-empty and within the BPF filter bound.
 *
 * Coverage — serving (-confine=serving) profile:
 *   (e) normal SERVING ops work confined: enter node_confine_serving, then a
 *       real loopback socket()/bind()/listen()/accept()/send()/recv() cycle
 *       PLUS a SQLite query -> child exits 0 (proves normal serving ops
 *       survive the widened allow-list).
 *   (f) canary — execve/ptrace/mount stay KILLed even under the widened
 *       serving allow-list (proves the widening is additive, not a blanket
 *       loosening).
 */

#define _GNU_SOURCE  /* getrandom / syscall — must precede every include */

#include "test/test_core.h"
#include "platform/os_sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <sys/mount.h>
#include <sys/ptrace.h>
#endif
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <sqlite3.h>

#if !defined(__linux__)

int test_confine(void)
{
    int abi = os_sandbox_landlock_abi();
    bool seccomp = os_sandbox_seccomp_supported();
    printf("\n=== -confine platform availability ===\n");
    printf("confine: Landlock ABI = %d, seccomp supported = %d; "
           "Linux confinement tests are not applicable\n", abi,
           (int)seccomp);
    return abi < 1 && !seccomp ? 0 : 1;
}

#else

#define CF_CHECK(name, expr) do { \
    printf("confine: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Fixture datadir, filled in by test_confine() before any fork. */
static char g_dir[256];

/* Run fn() in a forked child. Returns the child's exit code (>= 0) or the
 * NEGATED terminating signal (< 0). */
static int cf_run_child(int (*fn)(void))
{
    pid_t pid = fork();
    if (pid < 0) return -1000;
    if (pid == 0) _exit(fn());
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1001;
    if (WIFSIGNALED(st)) return -WTERMSIG(st);
    return WEXITSTATUS(st);
}

/* Build the node_confine profile scoped to the fixture datadir (rw) + a
 * read-only /proc/self/status grant, and enter it. Returns true on success. */
static bool cf_enter_confine(void)
{
    struct os_sandbox_path_rule rules[2];
    size_t n = 0;
    rules[n++] = (struct os_sandbox_path_rule){
        .path = g_dir, .allow_read = true, .allow_write = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = OS_SANDBOX_PROC_SELF_STATUS_PATH, .allow_read = true };
    struct os_sandbox_profile prof = os_sandbox_node_confine_profile(rules, n);
    return os_sandbox_enter(&prof).ok;
}

/* Same as cf_enter_confine() but enters the SERVING profile (the strict set
 * plus the socket family). */
static bool cf_enter_confine_serving(void)
{
    struct os_sandbox_path_rule rules[2];
    size_t n = 0;
    rules[n++] = (struct os_sandbox_path_rule){
        .path = g_dir, .allow_read = true, .allow_write = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = OS_SANDBOX_PROC_SELF_STATUS_PATH, .allow_read = true };
    struct os_sandbox_profile prof =
        os_sandbox_node_confine_serving_profile(rules, n);
    return os_sandbox_enter(&prof).ok;
}

/* (a) representative confined ops — must all succeed under the allow-list. */
static int c_confine_normal_ops(void)
{
    if (!cf_enter_confine()) return 70;

    /* malloc / free */
    void *p = malloc(1u << 20);
    if (!p) return 71;
    memset(p, 0x5a, 1u << 20);
    free(p);

    /* file I/O under the granted datadir */
    char fp[512];
    snprintf(fp, sizeof(fp), "%s/scratch", g_dir);
    int fd = open(fp, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) return 72;
    for (int i = 0; i < 64; i++) {
        char b[4096];
        memset(b, i, sizeof(b));
        if (write(fd, b, sizeof(b)) != (ssize_t)sizeof(b)) return 73;
    }
    if (fsync(fd) != 0) return 74;
    if (lseek(fd, 0, SEEK_SET) != 0) return 75;
    char rb[4096];
    if (read(fd, rb, sizeof(rb)) != (ssize_t)sizeof(rb)) return 76;
    close(fd);

    /* getrandom + monotonic clock — RAW on purpose: this test's job is to prove
     * the seccomp allow-list permits the exact __NR_getrandom / __NR_clock_
     * gettime syscalls the node makes, so routing through platform.rng/clock
     * would defeat the derivation. */
    uint8_t rnd[32];
    if (getrandom(rnd, sizeof(rnd), 0) != (ssize_t)sizeof(rnd)) return 77;  // platform-ok:confine allow-list must cover the raw getrandom syscall
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 78;  // platform-ok:confine allow-list must cover the raw clock_gettime syscall

    /* a real "storage query": SQLite WAL CREATE/INSERT/SELECT on a datadir db */
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/confine.db", g_dir);
    sqlite3 *db = NULL;
    if (sqlite3_open(dbpath, &db) != SQLITE_OK) return 80;
    char *err = NULL;
    if (sqlite3_exec(db, "PRAGMA journal_mode=WAL;", 0, 0, &err) != SQLITE_OK)
        return 81;
    if (sqlite3_exec(db, "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT);",
                     0, 0, &err) != SQLITE_OK)
        return 82;
    if (sqlite3_exec(db, "INSERT INTO t(v) VALUES('a'),('b'),('c');",
                     0, 0, &err) != SQLITE_OK)
        return 83;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM t;", -1, &st, 0)
            != SQLITE_OK)
        return 84;
    int cnt = -1;
    if (sqlite3_step(st) == SQLITE_ROW) cnt = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    sqlite3_close(db);
    if (cnt != 3) return 85;

    return 0;  /* all confined ops succeeded */
}

/* (b) Landlock canary: opening a path outside the datadir grants is EACCES. */
static int c_confine_outside_path(void)
{
    if (!cf_enter_confine()) return 70;
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 5;  /* Landlock failed to deny the outside read */
    }
    return (errno == EACCES) ? 0 : 6;  /* expect EACCES specifically */
}

/* (c) seccomp canary: a forbidden syscall (socket) must KILL the process. */
static int c_confine_forbidden_syscall(void)
{
    if (!cf_enter_confine()) return 70;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    (void)s;
    return 7;  /* reached only if the allow-list let socket() through */
}

/* (e) representative confined SERVING ops — a real loopback TCP round trip
 * (socket/bind/listen/accept/send/recv, both sides in this one child via a
 * connecting sub-process) PLUS a SQLite query, all under the node_confine_
 * serving allow-list. Must all succeed — proves normal serving ops survive. */
static int c_confine_serving_normal_ops(void)
{
    if (!cf_enter_confine_serving()) return 90;

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return 91;
    struct sockaddr_in addr = { .sin_family = AF_INET,
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 92;
    socklen_t alen = sizeof(addr);
    if (getsockname(lfd, (struct sockaddr *)&addr, &alen) != 0) return 93;
    if (listen(lfd, 1) != 0) return 94;

    /* Connect to ourselves from a second socket in the SAME confined child —
     * a nonblocking connect + accept avoids needing a second process. */
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) return 95;
    int fl = fcntl(cfd, F_GETFL, 0);
    if (fl < 0 || fcntl(cfd, F_SETFL, fl | O_NONBLOCK) != 0) return 96;
    int cr = connect(cfd, (struct sockaddr *)&addr, sizeof(addr));
    if (cr != 0 && errno != EINPROGRESS) return 97;

    /* select() readiness wait for the listener to become acceptable. */
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(lfd, &rfds);
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    int sr = select(lfd + 1, &rfds, NULL, NULL, &tv);
    if (sr <= 0) return 98;

    int sfd = accept(lfd, NULL, NULL);
    if (sfd < 0) return 99;

    /* getsockopt/setsockopt exercise. */
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(sfd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0) return 100;
    int one = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
        return 101;

    /* send()/recv() a payload across the accepted pair. */
    const char msg[] = "confine-serving";
    if (send(sfd, msg, sizeof(msg), 0) != (ssize_t)sizeof(msg)) return 102;
    char buf[sizeof(msg)];
    ssize_t got = recv(cfd, buf, sizeof(buf), 0);
    if (got != (ssize_t)sizeof(msg) || memcmp(buf, msg, sizeof(msg)) != 0)
        return 103;

    if (shutdown(sfd, SHUT_RDWR) != 0) return 104;
    close(sfd);
    close(cfd);
    close(lfd);

    /* a real "storage query" alongside the network ops, same as (a). */
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/confine_serving.db", g_dir);
    sqlite3 *db = NULL;
    if (sqlite3_open(dbpath, &db) != SQLITE_OK) return 105;
    char *dberr = NULL;
    if (sqlite3_exec(db, "PRAGMA journal_mode=WAL;", 0, 0, &dberr) != SQLITE_OK)
        return 106;
    if (sqlite3_exec(db, "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT);",
                     0, 0, &dberr) != SQLITE_OK)
        return 107;
    if (sqlite3_exec(db, "INSERT INTO t(v) VALUES('x');", 0, 0, &dberr)
            != SQLITE_OK)
        return 108;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM t;", -1, &st, 0)
            != SQLITE_OK)
        return 109;
    int cnt = -1;
    if (sqlite3_step(st) == SQLITE_ROW) cnt = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    sqlite3_close(db);
    if (cnt != 1) return 110;

    return 0;  /* all confined serving ops succeeded */
}

/* (f) seccomp canary under the WIDENED serving allow-list: execve, ptrace,
 * and mount must still KILL the process — proves the socket-family widening
 * is additive, not a blanket loosening of the whole filter. Each canary is
 * checked in its OWN forked child (a KILLed process cannot report the next
 * assertion), so this helper is parameterised by which syscall to try. */
enum confine_serving_canary {
    CANARY_EXECVE = 0,
    CANARY_PTRACE = 1,
    CANARY_MOUNT  = 2,
};
static enum confine_serving_canary g_canary_pick;
static int c_confine_serving_forbidden_syscall(void)
{
    if (!cf_enter_confine_serving()) return 70;
    switch (g_canary_pick) {
    case CANARY_EXECVE: {
        char *const argv0[] = { (char *)"/bin/true", NULL };
        execve("/bin/true", argv0, NULL);
        break;
    }
    case CANARY_PTRACE:
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        break;
    case CANARY_MOUNT:
        mount("none", "/tmp", "tmpfs", 0, NULL);
        break;
    }
    return 8;  /* reached only if the allow-list let the syscall through */
}

int test_confine(void)
{
    printf("\n=== -confine / -confine=serving strict node confinement tests ===\n");
    int failures = 0;

    test_make_tmpdir(g_dir, sizeof(g_dir), "confine", "dd");

    /* Allow-set sanity: non-empty and within the documented BPF bound, for
     * BOTH profiles. The serving set must be a strict superset in size (it
     * is defined as the steady set plus the socket family, never fewer). */
    size_t n_allowed = 0;
    const int *allowed = os_sandbox_node_confine_allowed_syscalls(&n_allowed);
    CF_CHECK("confine allow-set is non-empty", allowed && n_allowed > 0);
    CF_CHECK("confine allow-set within BPF filter bound", n_allowed < 250);

    size_t n_serving = 0;
    const int *serving =
        os_sandbox_node_confine_serving_allowed_syscalls(&n_serving);
    CF_CHECK("confine=serving allow-set is non-empty",
             serving && n_serving > 0);
    CF_CHECK("confine=serving allow-set within BPF filter bound",
             n_serving < 250);
    CF_CHECK("confine=serving allow-set is wider than the strict set",
             n_serving > n_allowed);

    int abi = os_sandbox_landlock_abi();
    printf("confine: landlock ABI = %d, seccomp supported = %d\n",
           abi, (int)os_sandbox_seccomp_supported());

    /* The enforcement teeth run only where the kernel actually enforces
     * confinement. On a kernel missing Landlock+seccomp the -confine boot
     * path degrades (logs + skips), so skipping the assertions here keeps
     * the suite honest rather than asserting a mechanism the host does not
     * provide. */
    if (abi >= 1 && os_sandbox_seccomp_supported()) {
        /* (a) normal ops still work confined (strict profile) */
        CF_CHECK("normal ops work confined (file I/O + malloc + getrandom + "
                 "clock + SQLite SELECT)", cf_run_child(c_confine_normal_ops) == 0);
        /* (b) Landlock denies an outside path (strict profile) */
        CF_CHECK("landlock: /etc/passwd open denied (EACCES) under confinement",
                 cf_run_child(c_confine_outside_path) == 0);
        /* (c) seccomp kills a forbidden syscall (strict profile still kills
         * socket() — the strict allow-list omits the socket family) */
        CF_CHECK("seccomp: forbidden socket() -> SIGSYS kill (strict profile)",
                 cf_run_child(c_confine_forbidden_syscall) == -SIGSYS);

        /* (e) normal SERVING ops (real loopback socket cycle + SQLite query)
         * work confined under the widened serving allow-list. */
        CF_CHECK("serving: real loopback socket/bind/listen/accept/send/recv "
                 "+ SQLite query work confined",
                 cf_run_child(c_confine_serving_normal_ops) == 0);

        /* (f) canaries: execve/ptrace/mount still KILL under the serving
         * profile — the socket-family widening did not loosen anything else.
         * One forked child per canary (a SIGSYS kill ends that child). */
        g_canary_pick = CANARY_EXECVE;
        CF_CHECK("serving: forbidden execve() -> SIGSYS kill",
                 cf_run_child(c_confine_serving_forbidden_syscall) == -SIGSYS);
        g_canary_pick = CANARY_PTRACE;
        CF_CHECK("serving: forbidden ptrace() -> SIGSYS kill",
                 cf_run_child(c_confine_serving_forbidden_syscall) == -SIGSYS);
        g_canary_pick = CANARY_MOUNT;
        CF_CHECK("serving: forbidden mount() -> SIGSYS kill",
                 cf_run_child(c_confine_serving_forbidden_syscall) == -SIGSYS);
    } else {
        printf("confine: kernel lacks Landlock+seccomp — skipping enforcement "
               "assertions (boot path degrades the same way)\n");
    }

    test_rm_rf_recursive(g_dir);

    printf("=== -confine / -confine=serving tests complete: %d failure(s) ===\n",
           failures);
    return failures;
}

#endif
