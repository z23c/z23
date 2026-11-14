/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Live two-node stranger app journey acceptance (CREATE, MODIFY,
 *          SHARE, DISCOVER) over real transports, one C23 binary.
 *
 * FORWARD_PLAN item 2's number: stranger-to-stranger journeys proven live
 * between two isolated nodes. This program drives the real binaries — two
 * isolated regtest nodes with embedded Tor, the public apps board over P2P,
 * and the package swarm over Tor — through the whole user app journey with
 * NO stubbed transport:
 *
 *   node A (no hosting yet)  z23 app copy tinyapp          CREATE
 *                            edit + app save               MODIFY
 *                            app build (image sha3)
 *                            app open (assert the app ran)
 *                            app share (.z23share file)    SHARE, friend path
 *   node A restarted hosting app publish                   SHARE, stranger
 *                               path: one signed zcl.app_offer.v1 posted to
 *                               board room "apps" + the version served on
 *                               the swarm
 *   node B (hosting, peer)   z23 app get <name> --yes      DISCOVER: B types
 *                               ONE name, zero hex pastes; the fetch refuses
 *                               any root/publisher mismatch; B receives,
 *                               rebuilds and opens the app; its image sha3
 *                               must equal A's local build byte for byte
 *   node A killed            B still hosts the carrier     the app outlives
 *                               its author's node
 *
 * Before the nodes start, A promotes two one-shot C23 plugin generations with
 * source and cases, and B records inert fetches for both roots. A restarts once
 * with hosting; B resumes and completes the transfers, then owner-pins root 1.
 * After A exits, B stops for checkout, refused install without the owner pin,
 * two-generation installation, reproduction under a different builder key,
 * wrong-root and corrupt-image refusals, and state-preserving rollback. B then
 * restarts on its original datadir and must recover the complete pin in a new
 * process before a fresh joiner starts. The joiner proves a failed fetch-record
 * write retains no record or checkout, then persists the request, downloads
 * root 1 from restarted B, and meets the same owner-only activation boundary.
 * Every daemon gets its persona's isolated HOME.
 *
 * The node restart between the local verbs and publish is the documented
 * single-writer package-store order: the CLI owns <datadir>/zcode while
 * hosting is off, then the node takes it with -packagehost=1.
 *
 * Deliberately opt-in (never in make ci): it spawns two real regtest
 * daemons with real Tor circuits, needs public Tor network reachability,
 * and takes minutes. It FAILS with a named reason when Tor cannot
 * bootstrap — it never silently skips the onion proof.
 *
 * Knobs: APPJ_WAIT (RPC gate, s, default 120), APPJ_TOR_WAIT (onion
 * readiness, s, default 900), APPJ_BOARD_WAIT (board propagation seen
 * through app get, s, default 300), APPJ_KEEP=1 preserves the work tree,
 * --work=DIR and --keep override. Exit 0 PASS, 2 FAIL, 3 usage.
 *
 * Scratch trees live only under the sanctioned development-scratch root
 * (or an explicit --work). On PASS the tree is removed; on FAIL it stays
 * for evidence.
 *
 * Linux split roles use --sender or --receiver, a fresh absolute --work and
 * finite --seconds execution budget. Sender writes expected.json and the typed
 * onion-status.json, then waits for an owner-created regular `finish` marker.
 * Receiver also takes --peer and --expected; --serve retains its hosting
 * node until its owner creates `finish`. Role evidence is retained;
 * supervised cleanup may continue beyond the execution deadline. */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "json/json.h"
#include "platform/clock.h"
#include "platform/supervised_process.h"
#include "platform/os_proc.h"
#include "base/safe_alloc.h"
#include "base/hex.h"
#include "sha3/sha3.h"
#include "util/write_all.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ── layout ─────────────────────────────────────────────────────────── */

static char g_repo[520];         /* the z23 checkout (binaries + fixture) */
static char g_work[560];         /* scratch root (this run's own tree) */
static char g_a_home[640], g_a_dd[640], g_b_home[640], g_b_dd[640];
static char g_repo_app[660];     /* fixture checkout (cwd semantics only) */
static char g_a_log[640], g_b_log[640];
static pid_t g_a_pgid, g_b_pgid; /* node session leaders, 0 when down */
static pid_t g_run_child = -1;   /* aj_run's direct child, for the watchdog */
static bool g_keep;
static bool g_role_worker;
static struct platform_supervised_process g_role_node;

struct aj_role_args {
    const char *work, *peer, *expected;
    long seconds;
    bool sender, receiver, worker, serve;
};

static bool aj_role_peer(const char *s)
{
    if (!s || strlen(s) < 64 || strncmp(s + 56, ".onion:", 7)) return false;
    for (size_t i = 0; i < 56; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '2' && s[i] <= '7'))) return false;
    const char *p = s + 63; unsigned port = 0;
    if (!*p) return false;
    for (; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        port = port * 10u + (unsigned)(*p - '0');
        if (port > 65535) return false;
    }
    return port > 0;
}

static bool aj_role_number(const char *s, long *out)
{
    if (!s || !*s) return false;
    char *end; errno = 0; long n = strtol(s, &end, 10);
    if (errno || *end || n < 1 || n > 86400) return false;
    *out = n; return true;
}

static bool aj_role_flag(struct aj_role_args *r, const char *a)
{
    if (!strcmp(a, "--sender") && !r->sender) { r->sender = true; return true; }
    if (!strcmp(a, "--receiver") && !r->receiver) { r->receiver = true; return true; }
    if (!strcmp(a, "--role-worker") && !r->worker) { r->worker = true; return true; }
    if (!strcmp(a, "--serve") && !r->serve) { r->serve = true; return true; }
    return false;
}

static bool aj_role_value(struct aj_role_args *r, const char *a)
{
    if (!strncmp(a, "--work=", 7) && !r->work) { r->work = a + 7; return true; }
    if (!strncmp(a, "--peer=", 7) && !r->peer) { r->peer = a + 7; return true; }
    if (!strncmp(a, "--expected=", 11) && !r->expected) { r->expected = a + 11; return true; }
    return !strncmp(a, "--seconds=", 10) && !r->seconds && aj_role_number(a + 10, &r->seconds);
}

static bool aj_role_parse(int argc, char **argv, struct aj_role_args *r)
{
    *r = (struct aj_role_args){0};
    for (int i = 1; i < argc; i++) {
        if (!aj_role_flag(r, argv[i]) && !aj_role_value(r, argv[i])) return false;
    }
    return r->sender != r->receiver && r->work && r->work[0] == '/' &&
        r->work[1] && r->seconds &&
        (r->sender ? !r->peer && !r->expected && !r->serve :
         aj_role_peer(r->peer) && r->expected && r->expected[0] == '/');
}
static const char *g_fail_first;

/* P2P ports are production reachable-port allowlist members (core net
 * port policy) so the controlled Noise reconnect between the nodes holds.
 * Fresh block against the sibling acceptance harnesses (store onion
 * 20050/20051 + 3971x/3972x, commons 20026-20028 + 2928x/2930x, dht
 * 20022-20023). Tor bootstrap SocksPorts derive from these (p2p+11966). */
#define APPJ_A_P2P 20024
#define APPJ_A_RPC 39731
#define APPJ_A_FS 39732
#define APPJ_A_HTTPS 39733
#define APPJ_B_P2P 20025
#define APPJ_B_RPC 39741
#define APPJ_B_FS 39742
#define APPJ_B_HTTPS 39743
#define APPJ_DEAD_SINK "127.0.0.1:39996"
#define APPJ_CONNECT_A "127.0.0.1:20024"

static long g_wait_s = 120, g_tor_wait_s = 900, g_board_wait_s = 300;

static void aj_note(const char *fmt, ...);
static void aj_fail(const char *fmt, ...);

/* ── small helpers ──────────────────────────────────────────────────── */

static long aj_env_long(const char *name, long fallback)
{
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    return end && !*end && n > 0 ? n : fallback;
}

static int aj_mkdir_p(const char *path)
{
    char buf[1024];
    if (snprintf(buf, sizeof(buf), "%s", path) >= (int)sizeof(buf)) return -1;
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    return mkdir(buf, 0700) != 0 && errno != EEXIST ? -1 : 0;
}

static bool aj_write_file(const char *path, const char *bytes)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fputs(bytes, f) != EOF;
    return fclose(f) == 0 && ok;
}

static bool aj_copy_file(const char *from, const char *to)
{
    int in = open(from, O_RDONLY);
    struct stat st;
    int out = in >= 0 && fstat(in, &st) == 0 && S_ISREG(st.st_mode)
        ? open(to, O_WRONLY | O_CREAT | O_EXCL, 0600) : -1;
    if (out < 0) {
        if (in >= 0) (void)close(in);
        return false;
    }
    char buf[8192];
    bool ok = true;
    for (;;) {
        ssize_t got = read(in, buf, sizeof(buf));
        if (got == 0) break;
        if (got < 0 && errno == EINTR) continue;
        if (got < 0 || !zcl_write_all(out, buf, (size_t)got)) {
            ok = false;
            break;
        }
    }
    bool closed = close(in) == 0;
    return close(out) == 0 && closed && ok;
}

static bool aj_copy_flat_entry(const char *from, const char *to, const char *name)
{
    char src[1100], dst[1100];
    struct stat st;
    return snprintf(src, sizeof(src), "%s/%s", from, name) < (int)sizeof(src) &&
           snprintf(dst, sizeof(dst), "%s/%s", to, name) < (int)sizeof(dst) &&
           lstat(src, &st) == 0 && S_ISREG(st.st_mode) && aj_copy_file(src, dst);
}

static bool aj_copy_flat(const char *from, const char *to)
{
    DIR *dir = opendir(from);
    if (!dir || mkdir(to, 0700) != 0) {
        if (dir) (void)closedir(dir);
        return false;
    }
    bool ok = true;
    unsigned files = 0;
    struct dirent *entry;
    while (ok && (entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++files > 16 || !aj_copy_flat_entry(from, to, entry->d_name)) ok = false;
    }
    return closedir(dir) == 0 && ok && files > 0;
}

static int aj_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    return (int)n;
}

static bool aj_path_join(char *out, size_t cap, const char *a, const char *b)
{
    return snprintf(out, cap, "%s/%s", a, b) < (int)cap;
}

static long aj_now_s(void)
{
    return clock_now_monotonic_ns() / 1000000000;
}

static void aj_sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* Depth-bounded recursive removal of one tree this run created. Refuses
 * anything that is not under the sanctioned scratch root or the explicit
 * --work path; no shell is ever invoked. */
static bool aj_rm_rf(const char *path, int depth)
{
    if (depth > 24) return false;
    DIR *d = opendir(path);
    if (!d) return remove(path) == 0 || errno == ENOENT;
    struct dirent *e;
    bool ok = true;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char child[1024];
        if (snprintf(child, sizeof(child), "%s/%s", path, e->d_name) >= (int)sizeof(child)) {
            ok = false;
            continue;
        }
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode)) ok = aj_rm_rf(child, depth + 1) && ok;
        else ok = remove(child) == 0 && ok;
    }
    closedir(d);
    return rmdir(path) == 0 && ok;
}

/* One "  key: value" line from front-door text output, copied bounded to
 * out. Returns false when the key is absent or the value is empty. */
static bool aj_line_value(const char *text, const char *key, char *out, size_t cap)
{
    char probe[160];
    if (snprintf(probe, sizeof(probe), "\n  %s: ", key) >= (int)sizeof(probe))
        return false;
    const char *at = strstr(text, probe);
    if (!at) {
        char first[200];
        int n = snprintf(first, sizeof(first), "  %s: ", key);
        if (n > 0 && n < (int)sizeof(first) && strncmp(text, first, (size_t)n) == 0)
            at = text;
        else return false;
    } else at += strlen(probe);
    size_t n = strcspn(at, "\n");
    while (n > 0 && (at[n - 1] == ' ' || at[n - 1] == '\r')) n--;
    if (n == 0 || n >= cap) return false;
    memcpy(out, at, n);
    out[n] = '\0';
    return true;
}

/* The resident-launch line the open/get verbs print: "opened <name> pid N".
 * Copies N. Returns false when no opened line carries a pid. */
static bool aj_opened_pid(const char *text, char *out, size_t cap)
{
    const char *line = strstr(text, "opened ");
    while (line) {
        const char *pid = strstr(line, " pid ");
        const char *eol = strchr(line, '\n');
        if (pid && (!eol || pid < eol)) {
            size_t n = 0;
            for (const char *p = pid + 5; *p >= '0' && *p <= '9' && n + 1 < cap; p++)
                out[n++] = *p;
            if (n > 0) { out[n] = '\0'; return true; }
        }
        line = eol ? strstr(eol, "opened ") : NULL;
    }
    return false;
}

/* ── process helpers ───────────────────────────────────────────────────
 * The util/spawn.h primitives carry no environment override, and every
 * app verb needs an isolated HOME (the publisher key lives under HOME).
 * These follow the same contract as util/spawn.h: between fork and exec
 * only async-signal-safe calls run, and no shell is ever invoked. */

static volatile sig_atomic_t g_alarm_fired;

static void aj_watchdog(int sig)
{
    (void)sig;
    g_alarm_fired = 1;
    if (g_run_child > 1) {
        (void)kill(g_run_child, SIGKILL);
        (void)kill(-g_run_child, SIGKILL);
    }
}

/* Post-fork child setup for aj_run: session, redirections, working
 * directory and the HOME/PATH environment, then exec. Only ever runs in
 * the forked child and never returns; _exit is used because the child may
 * not run atexit handlers of the parent's libraries. */
static void aj_run_child(const char *bin, const char *home, const char *cwd,
                         char *const argv[], int write_fd)
{
    if (setsid() == (pid_t)-1) _exit(127);
    if (dup2(write_fd, STDOUT_FILENO) < 0) _exit(127);
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull < 0 || dup2(devnull, STDIN_FILENO) < 0) _exit(127);
    int devnull2 = open("/dev/null", O_WRONLY);
    if (devnull2 < 0 || dup2(devnull2, STDERR_FILENO) < 0) _exit(127);
    if (chdir(cwd) != 0) _exit(127);
    static char home_pair[700], path_pair[64];
    if (snprintf(home_pair, sizeof(home_pair), "HOME=%s", home) >= (int)sizeof(home_pair))
        _exit(127);
    snprintf(path_pair, sizeof(path_pair), "PATH=/usr/bin:/bin");
    char *env[3] = {home_pair, path_pair, NULL};
    extern char **environ;
    environ = env;
    execv(bin, argv);
    _exit(127);
}

/* Run one program synchronously with a HOME override and a working
 * directory; capture stdout; SIGALRM bounds the wait. Returns the exit
 * status, or -1. This harness is single-threaded, so the fork/exec
 * contract's multi-threaded caveats do not apply. */
static int aj_run(const char *home, const char *cwd, int timeout_s,
                  char *out, size_t cap, char *const argv[]);

/* The capture half of aj_run: reads the child's stdout until EOF, buffer
 * full, or the deadline alarm. A resident app can inherit the CLI's
 * stdout pipe and hold its write end open long past the verb's own exit,
 * so EOF alone must not gate the wait: poll, and once the direct child
 * has exited drain briefly (the same short drain window util/spawn.h
 * uses) and stop. The deadline alarm is the last resort. */
static int aj_observe_child(pid_t pid, int flags)
{
    siginfo_t info = {0};
    int rc;
    do { rc = waitid(P_PID, (id_t)pid, &info, WEXITED | WNOWAIT | flags); }
    while (rc < 0 && errno == EINTR);
    if (rc < 0) return -1;
    return info.si_pid == pid ? 1 : 0;
}

static int aj_capture_drain(pid_t pid, bool *done, int *drains)
{
    if (!*done) {
        int observed = aj_observe_child(pid, WNOHANG);
        if (observed < 0) return -1;
        *done = observed == 1;
    }
    return *done && ++*drains >= 20 ? 1 : 0;
}

static bool aj_capture_pipe(int fd, pid_t pid, char *out, size_t cap)
{
    size_t used = 0;
    bool child_done = false;
    bool ok = true;
    int drains = 0;
    out[0] = '\0';
    for (;;) {
        if (used + 1 >= cap) break;
        if (g_alarm_fired) break;
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int pr = poll(&pfd, 1, child_done ? 100 : 500);
        if (pr < 0) {
            if (errno == EINTR) continue;
            ok = false; break;
        }
        if (pr == 0) {
            int drained = aj_capture_drain(pid, &child_done, &drains);
            if (drained < 0) { ok = false; break; }
            if (drained > 0) break; /* 2 s drain window */
            continue;
        }
        ssize_t n = read(fd, out + used, cap - 1 - used);
        if (n > 0) { used += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) ok = false;
        break;
    }
    out[used] = '\0';
    return ok;
}

static int aj_finish_child(pid_t pid, bool captured)
{
    sigset_t set, prior;
    sigemptyset(&set); sigaddset(&set, SIGALRM);
    for (;;) {
        if (sigprocmask(SIG_BLOCK, &set, &prior) != 0) return -1;
        int status; pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid || (waited < 0 && errno != EINTR)) {
            alarm(0); g_run_child = -1;
            bool ok = captured && waited == pid && WIFEXITED(status);
            int result = ok ? WEXITSTATUS(status) : -1;
            if (sigprocmask(SIG_SETMASK, &prior, NULL) != 0) return -1;
            return g_alarm_fired ? -1 : result;
        }
        if (sigprocmask(SIG_SETMASK, &prior, NULL) != 0) return -1;
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 50000000 };
        nanosleep(&pause, NULL);
    }
}

static int aj_run(const char *home, const char *cwd, int timeout_s,
                  char *out, size_t cap, char *const argv[])
{
    char bin[600];
    if (snprintf(bin, sizeof(bin), "%s/build/bin/z23", g_repo) >= (int)sizeof(bin))
        return -1;
    int fds[2];
    if (pipe(fds) != 0) return -1;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }
    if (pid == 0) {
        close(fds[0]);
        aj_run_child(bin, home, cwd, argv, fds[1]);
    }
    close(fds[1]);
    g_run_child = pid;
    void (*old_alrm)(int) = signal(SIGALRM, aj_watchdog);
    g_alarm_fired = 0;
    unsigned old_alarm = alarm((unsigned)(timeout_s > 0 ? timeout_s : 900));
    (void)old_alarm;
    bool captured = aj_capture_pipe(fds[0], pid, out, cap);
    close(fds[0]);
    int result = aj_finish_child(pid, captured);
    signal(SIGALRM, old_alrm);
    return result;
}

static bool aj_group_signal(pid_t pid, int sig)
{
    bool group = kill(-pid, sig) == 0 || errno == ESRCH;
    bool child = kill(pid, sig) == 0 || errno == ESRCH;
    return group && child;
}

static int aj_group_wait_leader(pid_t pid)
{
    for (unsigned i = 0; i < 50; i++) {
        int observed = aj_observe_child(pid, WNOHANG);
        if (observed != 0) return observed;
        aj_sleep_ms(200);
    }
    return 0;
}

/* This single-threaded harness has no competing reaper. Pin its owned leader
 * with waitid until signals finish; after reap, only observe group absence.
 * This does not cover descendants that leave the session. */
static bool aj_kill_group(pid_t pgid)
{
    if (pgid <= 1) return true;
    int observed = aj_observe_child(pgid, WNOHANG);
    if (observed < 0) return false;
    bool signaled = aj_group_signal(pgid, SIGTERM);
    observed = aj_group_wait_leader(pgid);
    if (observed < 0) return false;
    signaled = aj_group_signal(pgid, SIGKILL) && signaled;
    if (!observed) observed = aj_group_wait_leader(pgid);
    if (observed <= 0) return false;
    int status; pid_t got;
    do { got = waitpid(pgid, &status, 0); } while (got < 0 && errno == EINTR);
    if (got != pgid || !signaled) return false;
    for (unsigned i = 0; i < 50; i++) {
        if (kill(-pgid, 0) != 0) return errno == ESRCH;
        aj_sleep_ms(200);
    }
    return false;
}

/* ── node lifecycle ─────────────────────────────────────────────────── */

/* Build one node's argv from its fixed flag shape. Returns false when any
 * flag string does not fit. The buffers are caller-owned so each fork
 * snapshots its own set before the next spawn rewrites them. */
struct aj_node_flags {
    char bin[600], ddf[640], p2pf[32], rpcf[32], fsf[32], httpsf[32],
        cons[128], pkg[24], home_pair[700], path_pair[64];
};
static bool aj_node_flags_build(struct aj_node_flags *f, const char *home,
                                const char *datadir, int p2p, int rpc, int fs,
                                int https, const char *connect, bool hosting)
{
    return snprintf(f->bin, sizeof(f->bin), "%s/build/bin/zclassic23", g_repo) < (int)sizeof(f->bin) &&
        snprintf(f->ddf, sizeof(f->ddf), "-datadir=%s", datadir) < (int)sizeof(f->ddf) &&
        snprintf(f->p2pf, sizeof(f->p2pf), "-port=%d", p2p) < (int)sizeof(f->p2pf) &&
        snprintf(f->rpcf, sizeof(f->rpcf), "-rpcport=%d", rpc) < (int)sizeof(f->rpcf) &&
        snprintf(f->fsf, sizeof(f->fsf), "-fsport=%d", fs) < (int)sizeof(f->fsf) &&
        snprintf(f->httpsf, sizeof(f->httpsf), "-httpsport=%d", https) < (int)sizeof(f->httpsf) &&
        snprintf(f->cons, sizeof(f->cons), "-connect=%s", connect) < (int)sizeof(f->cons) &&
        snprintf(f->pkg, sizeof(f->pkg), "-packagehost=%d", hosting ? 1 : 0) < (int)sizeof(f->pkg) &&
        snprintf(f->home_pair, sizeof(f->home_pair), "HOME=%s", home) < (int)sizeof(f->home_pair) &&
        snprintf(f->path_pair, sizeof(f->path_pair), "PATH=/usr/bin:/bin") < (int)sizeof(f->path_pair);
}

static void aj_node_argv(struct aj_node_flags *f, char **argv)
{
    char *items[] = {f->bin, f->ddf, (char *)"-regtest", f->p2pf, f->rpcf, f->fsf,
        f->httpsf, f->cons, (char *)"-onion-persist", f->pkg,
        (char *)"-regtestshielded", (char *)"-operator-lane=dev",
        (char *)"-wallet-no-phrase-backup", (char *)"-nobgvalidation",
        (char *)"-nolegacyimport", (char *)"-showmetrics=0", NULL};
    memcpy(argv, items, sizeof(items));
}

static pid_t aj_node_spawn(const char *home, const char *datadir, const char *log,
                           int p2p, int rpc, int fs, int https,
                           const char *connect, bool hosting)
{
    static struct aj_node_flags f;
    if (!aj_node_flags_build(&f, home, datadir, p2p, rpc, fs, https, connect, hosting))
        return 0;
    char *argv[17]; aj_node_argv(&f, argv);
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) {
        if (setsid() == (pid_t)-1) _exit(127);
        int out = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (out < 0) _exit(127);
        if (dup2(out, STDOUT_FILENO) < 0 || dup2(out, STDERR_FILENO) < 0)
            _exit(127);
        int in = open("/dev/null", O_RDONLY);
        if (in < 0 || dup2(in, STDIN_FILENO) < 0) _exit(127);
        char *env[] = {f.home_pair, f.path_pair, NULL};
        extern char **environ;
        environ = env;
        execv(f.bin, argv);
        _exit(127);
    }
    return pid > 0 ? pid : 0;
}

/* One z23 CLI call against a node's RPC (flags in argv, no env needed). */
static int aj_cli(const char *datadir, int rpc, char *const tail[],
                  char *out, size_t cap, int timeout_s, const char *home)
{
    static char ddf[640], rpcf[32];
    char bin[600];
    if (snprintf(bin, sizeof(bin), "%s/build/bin/z23", g_repo) >= (int)sizeof(bin) ||
        snprintf(ddf, sizeof(ddf), "-datadir=%s", datadir) >= (int)sizeof(ddf) ||
        snprintf(rpcf, sizeof(rpcf), "--rpcport=%d", rpc) >= (int)sizeof(rpcf))
        return -1;
    char *argv[24] = {bin, ddf, rpcf, (char *)"-regtest"};
    size_t n = 4;
    for (size_t i = 0; tail[i] && n < 23; i++) argv[n++] = tail[i];
    argv[n] = NULL;
    return aj_run(home ? home : "/nonexistent", "/", timeout_s, out, cap, argv);
}

/* Parse the onion status JSON once: fills addr/state/ready. */
static bool aj_onion_status(const char *datadir, int rpc, const char *home,
                            char *addr, size_t addr_cap, char *state,
                            size_t state_cap, bool *publish_ready)
{
    char out[16384];
    char *tail[] = {(char *)"core", (char *)"network", (char *)"onion",
                    (char *)"status", NULL};
    if (aj_cli(datadir, rpc, tail, out, sizeof(out), 90, home) != 0)
        return false;
    struct json_value v;
    json_init(&v);
    bool ok = json_read(&v, out, strlen(out));
    if (ok) {
        const struct json_value *d = json_get(&v, "data");
        if (!d) d = &v;
        const struct json_value *a = json_get(d, "onion_address");
        const struct json_value *s = json_get(d, "bootstrap_state");
        const struct json_value *r = json_get(d, "p2p_publish_ready");
        ok = a && a->type == JSON_STR && s && s->type == JSON_STR &&
             r && r->type == JSON_BOOL;
        if (ok) {
            snprintf(addr, addr_cap, "%s", json_get_str(a));
            snprintf(state, state_cap, "%s", json_get_str(s));
            *publish_ready = json_get_bool(r);
        }
    }
    json_free(&v);
    return ok;
}

struct aj_node_ctx { char datadir[640]; int rpc; char home[640]; };

static bool aj_wait_ready_pair(struct aj_node_ctx *ac, struct aj_node_ctx *bc,
                               const char *suffix);

/* RPC liveness: the onion status leaf answers at all (any state). */
static bool aj_probe_rpc(void *p)
{
    struct aj_node_ctx *c = p;
    char addr[128], state[32];
    bool ready = false;
    return aj_onion_status(c->datadir, c->rpc, c->home, addr, sizeof(addr),
                           state, sizeof(state), &ready);
}

static bool aj_probe_onion(void *p)
{
    struct aj_node_ctx *c = p;
    char addr[128], state[32];
    bool ready = false;
    return aj_onion_status(c->datadir, c->rpc, c->home, addr, sizeof(addr),
                           state, sizeof(state), &ready) &&
        ready && !strcmp(state, "ready") && addr[0];
}

static bool aj_wait(bool (*probe)(void *), void *ctx, long budget_s,
                    const char *what)
{
    long deadline = aj_now_s() + budget_s;
    for (;;) {
        if (probe(ctx)) return true;
        if (aj_now_s() >= deadline) {
            aj_fail("%s not ready within %lds", what, budget_s);
            return false;
        }
        aj_sleep_ms(2000);
    }
}

/* ── the journey ────────────────────────────────────────────────────── */

static char g_image_a[80], g_root[80], g_publisher[80], g_post[80], g_name[80];
static char g_host_hex[80], g_carrier[80];

static int aj_app(struct aj_node_ctx *c, const char *verb, const char *target,
                  char *out, size_t cap, int timeout_s)
{
    static char ddf[640], rpcf[32];
    char bin[600];
    if (snprintf(bin, sizeof(bin), "%s/build/bin/z23", g_repo) >= (int)sizeof(bin) ||
        snprintf(ddf, sizeof(ddf), "-datadir=%s", c->datadir) >= (int)sizeof(ddf) ||
        snprintf(rpcf, sizeof(rpcf), "--rpcport=%d", c->rpc) >= (int)sizeof(rpcf))
        return -1;
    char *argv[12] = {bin, ddf, rpcf, (char *)"-regtest", (char *)"app",
                      (char *)verb};
    size_t n = 6;
    if (target) argv[n++] = (char *)target;
    argv[n++] = (char *)"--yes";
    argv[n] = NULL;
    /* App verbs run from the fixture checkout: `app copy` seeds the app
     * from the working directory and `app share` writes the .z23share
     * file beside it. */
    int rc = aj_run(c->home, g_repo_app, timeout_s, out, cap, argv);
    /* Every verb's output lands in the work tree, so a failure names its
     * own evidence without a rerun. */
    static int seq;
    char log[1100];
    if (snprintf(log, sizeof(log), "%s/verb-%02d-%s.log", g_work, ++seq, verb) <
        (int)sizeof(log))
        (void)aj_write_file(log, out);
    return rc;
}

static bool aj_fixture(void)
{
    char p[1024];
    static const char *const dirs[] = {"repo", "repo/engine",
        "repo/engine/composition", "repo/engine/composition/commands",
        "repo/tools", "repo/tools/dev", "repo/apps", "repo/apps/tinyapp",
        "repo/apps/tinyapp/include", "repo/apps/tinyapp/src",
        "a/home", "b/home", "capability"};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        if (!aj_path_join(p, sizeof(p), g_work, dirs[i]) || aj_mkdir_p(p) != 0)
            return false;
    }
    snprintf(g_repo_app, sizeof(g_repo_app), "%s/repo", g_work);
    static const char *const files[][2] = {
        {"repo/Makefile", "# fixture checkout\n"},
        {"repo/engine/composition/commands/root.def", "\n"},
        {"repo/tools/dev/test_group_catalog.def", "\n"},
        {"repo/apps/tinyapp/zcode-package.json",
         "{\n  \"schema\": 1,\n  \"name\": \"stub/tinyapp\",\n"
         "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
         "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
         "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n"},
        {"repo/apps/tinyapp/include/tiny.h", "#define TINY_NAME \"tinyapp\"\n"},
        {"repo/apps/tinyapp/src/main.c",
         "#include <stdio.h>\n#include <unistd.h>\n#include \"tiny.h\"\n"
         "int main(void) { puts(TINY_NAME \" ready boost=1\"); fflush(stdout);\n"
         "    pause(); return 0; }\n"},
        {"repo/apps/tinyapp/Makefile",
         ".PHONY: app print-app-closure\n"
         "print-app-closure:\n\t@printf '%s\\n' Makefile include/tiny.h src/main.c\n"
         "app:\n\tcc -std=c2x -O2 -Iinclude -MD -MF $(APP_OUT)/main.d"
         " -c src/main.c -o $(APP_OUT)/main.o\n"
         "\tcc -o $(APP_OUT)/app $(APP_OUT)/main.o\n"},
        {"capability/upper.c",
         "#include <ctype.h>\n#include <stdio.h>\n"
         "int main(void) { int c;\n"
         "    while ((c = getchar()) != EOF)\n"
         "        if (putchar(toupper((unsigned char)c)) == EOF) return 1;\n"
         "    return 0; }\n"},
        {"capability/cases.json",
         "[{\"name\":\"lower\",\"stdin\":\"abc\",\"expect_stdout\":\"ABC\"},"
         "{\"name\":\"mixed\",\"stdin\":\"Hello, z23\\n\","
         "\"expect_stdout\":\"HELLO, Z23\\n\"}]\n"},
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        if (!aj_path_join(p, sizeof(p), g_work, files[i][0]) ||
            !aj_write_file(p, files[i][1]))
            return false;
    }
    /* The stub carries the same Apache-2.0 text the skycombat package does. */
    char lic[4096];
    if (!aj_path_join(p, sizeof(p), g_repo, "apps/skycombat/LICENSE") ||
        aj_slurp(p, lic, sizeof(lic)) <= 0)
        return false;
    return aj_path_join(p, sizeof(p), g_repo_app, "apps/tinyapp/LICENSE") &&
        aj_write_file(p, lic) &&
        aj_path_join(p, sizeof(p), g_work, "capability/LICENSE") &&
        aj_write_file(p, lic);
}

/* CREATE + MODIFY + local SHARE on A, while A's node is not hosting. */
/* Wait for the app's own log to carry its ready line with the modified
 * marker, then stop the resident pid. Shared by A's local journey and
 * B's received copy. */
static bool aj_wait_ready_kill(const char *home, const char *pid_str,
                               const char *who)
{
    char app_log[1100];
    if (!aj_path_join(app_log, sizeof(app_log), home,
                      ".local/state/z23/apps/tinyapp-1.log"))
        return false;
    bool ran = false;
    for (int i = 0; i < 12 && !ran; i++) {
        aj_sleep_ms(300);
        char body[512];
        if (aj_slurp(app_log, body, sizeof(body)) > 0)
            ran = strstr(body, "tinyapp ready boost=2") != NULL;
    }
    if (!g_role_worker) (void)kill((pid_t)strtol(pid_str, NULL, 10), SIGKILL);
    if (!ran) {
        aj_fail("%s's modified app never printed its ready line", who);
        return false;
    }
    return true;
}

/* Open the copy and prove the modified app really ran: the front door
 * reports the resident pid and the app's own log carries its ready line. */
static bool aj_open_verify(struct aj_node_ctx *c, const char *home,
                           const char *who)
{
    char out[16384];
    if (aj_app(c, "open", "tinyapp-1", out, sizeof(out), 180) != 0) {
        aj_fail("%s app open: %s", who, out);
        return false;
    }
    char pids[32];
    if (!aj_opened_pid(out, pids, sizeof(pids))) {
        aj_fail("%s app open reported no pid", who);
        return false;
    }
    return aj_wait_ready_kill(home, pids, who);
}

static bool aj_phase_a_local(struct aj_node_ctx *ac)
{
    char out[16384];
    if (aj_app(ac, "copy", "tinyapp", out, sizeof(out), 600) != 0) {
        aj_fail("A app copy: %s", out);
        return false;
    }
    char copy_src[1024];
    if (!aj_path_join(copy_src, sizeof(copy_src), g_a_dd,
                      "copies/tinyapp-1/src/main.c"))
        return false;
    char src[4096];
    if (aj_slurp(copy_src, src, sizeof(src)) <= 0 || !strstr(src, "boost=1")) {
        aj_fail("A copy source lacks the editable marker");
        return false;
    }
    memcpy(strstr(src, "boost=1"), "boost=2", 7);
    if (!aj_write_file(copy_src, src)) return false;

    if (aj_app(ac, "save", "tinyapp-1", out, sizeof(out), 600) != 0) {
        aj_fail("A app save: %s", out);
        return false;
    }
    if (aj_app(ac, "build", "tinyapp-1", out, sizeof(out), 600) != 0 ||
        !aj_line_value(out, "image_sha3", g_image_a, sizeof(g_image_a))) {
        aj_fail("A app build gave no image_sha3: %s", out);
        return false;
    }
    if (!aj_open_verify(ac, g_a_home, "A")) return false;

    /* A share file is never overwritten; a rerun's stale file is ours. */
    char share[1024];
    if (!aj_path_join(share, sizeof(share), g_repo_app, "tinyapp-1.z23share"))
        return false;
    (void)remove(share);
    if (aj_app(ac, "share", "tinyapp-1", out, sizeof(out), 600) != 0) {
        aj_fail("A app share: %s", out);
        return false;
    }
    struct stat st;
    if (stat(share, &st) != 0 || st.st_size == 0) {
        aj_fail("A share file missing or empty");
        return false;
    }
    return true;
}

static bool aj_phase_publish(struct aj_node_ctx *ac)
{
    char out[32768];
    if (aj_app(ac, "publish", "tinyapp-1", out, sizeof(out), 900) != 0) {
        aj_fail("A app publish: %s", out);
        return false;
    }
    if (!aj_line_value(out, "post_id", g_post, sizeof(g_post)) ||
        strlen(g_post) != 64 ||
        !aj_line_value(out, "package_root", g_root, sizeof(g_root)) ||
        strlen(g_root) != 64 ||
        !aj_line_value(out, "publisher_fingerprint", g_publisher,
                       sizeof(g_publisher)) ||
        strlen(g_publisher) != 66 ||
        !aj_line_value(out, "publishes_as", g_name, sizeof(g_name)) ||
        !strchr(g_name, '/')) {
        aj_fail("A publish output lacks exact identities: %s", out);
        return false;
    }
    return true;
}

/* B types ONE name. Every hex identity arrives from the network and must
 * equal A's; the rebuilt image must equal A's local build byte for byte. */
static bool aj_catalog_has_name(const char *text, const char *name)
{
    size_t len = strlen(name);
    if (!len) return false;
    for (const char *line = text; *line;) {
        if (!strncmp(line, name, len) && line[len] == ' ') return true;
        const char *end = strchr(line, '\n');
        if (!end) break;
        line = end + 1;
    }
    return false;
}

static bool aj_catalog_deadline(int64_t *start, int64_t *deadline)
{
    *start = clock_now_monotonic_ns();
    if (*start <= 0 || g_board_wait_s <= 0 || g_board_wait_s > 86400) return false;
    int64_t budget = (int64_t)g_board_wait_s * 1000000000LL;
    if (*start > INT64_MAX - budget) return false;
    *deadline = *start + budget;
    return true;
}

static bool aj_wait_catalog(struct aj_node_ctx *bc, char *out, size_t cap)
{
    if (!out || !cap) return false;
    out[0] = '\0';
    int64_t start, deadline;
    if (!aj_catalog_deadline(&start, &deadline)) return false;
    char *tail[] = {(char *)"app", (char *)"get", NULL};
    for (;;) {
        int64_t now = clock_now_monotonic_ns();
        if (now < start || now >= deadline) break;
        /* aj_run's alarm has whole-second resolution, so this may run for
         * less than one extra second; never accept a result past deadline. */
        int remaining = (int)((deadline - now + 999999999LL) / 1000000000LL);
        int rc = aj_cli(bc->datadir, bc->rpc, tail, out, cap, remaining, bc->home);
        now = clock_now_monotonic_ns();
        if (now < start || now >= deadline) break;
        if (rc == 0 && aj_catalog_has_name(out, g_name)) return true;
        int64_t ms = (deadline - now) / 1000000LL;
        if (ms > 5000) ms = 5000;
        if (ms > 0) aj_sleep_ms((long)ms);
    }
    aj_fail("B catalog did not expose the app within %lds: %s", g_board_wait_s, out);
    return false;
}

static bool aj_b_get_once(struct aj_node_ctx *bc, char *out, size_t cap)
{
    if (!aj_wait_catalog(bc, out, cap)) return false;
    if (aj_app(bc, "get", g_name, out, cap, 900) == 0) return true;
    aj_fail("B app get failed: %s", out);
    return false;
}

static bool aj_received_matches(const char *out)
{
    char got[160];
    return aj_line_value(out, "package_root", got, sizeof(got)) && !strcmp(got, g_root) &&
        aj_line_value(out, "publisher_fingerprint", got, sizeof(got)) && !strcmp(got, g_publisher) &&
        aj_line_value(out, "image_sha3", got, sizeof(got)) && !strcmp(got, g_image_a);
}

static bool aj_phase_b_get(struct aj_node_ctx *bc)
{
    char out[65536];
    if (!aj_b_get_once(bc, out, sizeof(out))) return false;
    char got[160];
    if (!aj_received_matches(out)) {
        aj_fail("B's root, publisher or rebuilt image differs from A's");
        return false;
    }
    if (!aj_line_value(out, "rebuild_report", got, sizeof(got)) ||
        strcmp(got, "published")) {
        aj_fail("B did not publish a signed rebuild report");
        return false;
    }
    if (!aj_line_value(out, "hosting_host", g_host_hex, sizeof(g_host_hex)) ||
        strlen(g_host_hex) != 64 ||
        !aj_line_value(out, "hosting_carrier", g_carrier, sizeof(g_carrier)) ||
        strlen(g_carrier) != 64) {
        aj_fail("B's get output lacks its exact hosting identity");
        return false;
    }
    if (!aj_opened_pid(out, got, sizeof(got))) {
        aj_fail("B's get output reported no opened pid");
        return false;
    }
    return aj_wait_ready_kill(g_b_home, got, "B");
}

static bool aj_phase_outlives(struct aj_node_ctx *bc)
{
    if (!aj_kill_group(g_a_pgid)) {
        aj_fail("could not stop publisher A and reap its process group");
        return false;
    }
    g_a_pgid = 0;
    aj_sleep_ms(2000);
    static char hostf[128], carrierf[128];
    if (snprintf(hostf, sizeof(hostf), "--host=%s", g_host_hex) >= (int)sizeof(hostf) ||
        snprintf(carrierf, sizeof(carrierf), "--carrier=%s", g_carrier) >= (int)sizeof(carrierf))
        return false;
    char *tail[] = {(char *)"app", (char *)"host", (char *)"status",
                    hostf, carrierf, NULL};
    char out[8192];
    if (aj_cli(bc->datadir, bc->rpc, tail, out, sizeof(out), 180, bc->home) != 0) {
        aj_fail("B app host status after A died: %s", out);
        return false;
    }
    if (!strstr(out, "\"enabled\":true")) {
        aj_fail("B stopped hosting when A died (the app must outlive its author)");
        return false;
    }
    return true;
}

/* ── C23 plugin reproduction over the live package swarm ────────────── */

static char g_plugin_root[2][65], g_plugin_gen[2][129];
static char g_plugin_image[2][129], g_plugin_publisher[65];
static char g_c_home[640], g_c_dd[640], g_c_log[640];
static pid_t g_c_pgid;
#define APPJ_C_RPC 39751
#define APPJ_C_FS 39752
#define APPJ_C_HTTPS 39753
#define APPJ_CONNECT_B "127.0.0.1:20025"

static int aj_plugin_run(struct aj_node_ctx *c, const char *label,
                         char *const tail[], char *out, size_t cap, int timeout_s)
{
    if (cap) out[0] = '\0';
    int rc = aj_cli(c->datadir, c->rpc, tail, out, cap, timeout_s, c->home);
    static unsigned seq;
    char log[1100];
    if (snprintf(log, sizeof(log), "%s/plugin-%02u-%s.log", g_work, ++seq, label) <
        (int)sizeof(log))
        (void)aj_write_file(log, out);
    return rc;
}

static bool aj_json_bool_is(const struct json_value *object, const char *key,
                            bool expected)
{
    const struct json_value *value = json_get(object, key);
    return value && value->type == JSON_BOOL && json_get_bool(value) == expected;
}

static bool aj_json_ok(const char *wire, struct json_value *doc)
{
    json_init(doc);
    return json_read(doc, wire, strlen(wire)) && doc->type == JSON_OBJ &&
           aj_json_bool_is(doc, "ok", true);
}

static const struct json_value *aj_json_data(const struct json_value *doc)
{
    const struct json_value *data = json_get(doc, "data");
    return data ? data : doc;
}

static bool aj_json_refusal(const char *wire, const char *expected)
{
    struct json_value doc = {0};
    json_init(&doc);
    bool ok = json_read(&doc, wire, strlen(wire));
    const struct json_value *error = ok ? json_get(&doc, "error") : NULL;
    const char *code = error ? json_get_str(json_get(error, "code"))
                             : json_get_str(json_get(&doc, "code"));
    ok = ok && !aj_json_bool_is(&doc, "ok", true) && !strcmp(code, expected);
    json_free(&doc);
    return ok;
}

static bool aj_plugin_key(struct aj_node_ctx *c, const char *relative,
                          char public_key[65])
{
    char path[1100], out[8192];
    if (!aj_path_join(path, sizeof(path), g_work, relative)) return false;
    char *tail[] = {(char *)"plugin", (char *)"keygen", path, NULL};
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, "keygen", tail, out, sizeof(out), 60) == 0 &&
              aj_json_ok(out, &doc);
    if (ok) {
        const char *key = json_get_str(json_get(aj_json_data(&doc), "public_key"));
        ok = strlen(key) == 64 && snprintf(public_key, 65, "%s", key) == 64;
    }
    json_free(&doc);
    if (!ok) aj_fail("%s plugin keygen: %s", relative, out);
    return ok;
}

static bool aj_plugin_promote(struct aj_node_ctx *c, const char *version,
                              const char *dist, char generation[129], char image[129])
{
    char source[1100], cases[1200], key[1200], dir[1200], version_arg[32];
    if (!aj_path_join(source, sizeof(source), g_work, "capability/upper.c") ||
        snprintf(cases, sizeof(cases), "--cases=%s/capability/cases.json", g_work) >= (int)sizeof(cases) ||
        snprintf(key, sizeof(key), "--key=%s/a/publisher.key", g_work) >= (int)sizeof(key) ||
        snprintf(dir, sizeof(dir), "--dir=%s", dist) >= (int)sizeof(dir) ||
        snprintf(version_arg, sizeof(version_arg), "--version=%s", version) >= (int)sizeof(version_arg))
        return false;
    char *tail[] = {(char *)"lab", (char *)"promote", source, cases,
        (char *)"--name=upper", version_arg, key, dir, (char *)"--include-source", NULL};
    char out[16384];
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, version, tail, out, sizeof(out), 180) == 0 &&
              aj_json_ok(out, &doc);
    if (ok) {
        const struct json_value *data = aj_json_data(&doc);
        const char *gen = json_get_str(json_get(data, "generation"));
        const char *sha = json_get_str(json_get(data, "release_sha3_512"));
        ok = strlen(gen) == 128 && strlen(sha) == 128 &&
             json_get_int(json_get(data, "cases_passed")) == 2 &&
             snprintf(generation, 129, "%s", gen) == 128 &&
             snprintf(image, 129, "%s", sha) == 128;
    }
    json_free(&doc);
    if (!ok) aj_fail("lab promote %s: %s", version, out);
    return ok;
}

static bool aj_plugin_publish_root(struct aj_node_ctx *c, const char *dist, size_t index)
{
    char dir_arg[1200];
    if (snprintf(dir_arg, sizeof(dir_arg), "--dir=%s", dist) >= (int)sizeof(dir_arg))
        return false;
    char *tail[] = {(char *)"plugin", (char *)"publish", dir_arg, NULL};
    char out[16384];
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, index == 0 ? "1.0.0" : "2.0.0", tail,
                            out, sizeof(out), 120) == 0 && aj_json_ok(out, &doc);
    if (ok) {
        const struct json_value *data = aj_json_data(&doc);
        const char *root = json_get_str(json_get(data, "package_root"));
        const char *publisher = json_get_str(json_get(data, "publisher"));
        const char *generation = json_get_str(json_get(data, "generation"));
        ok = strlen(root) == 64 && !strcmp(publisher, g_plugin_publisher) &&
             !strcmp(generation, g_plugin_gen[index]) &&
             snprintf(g_plugin_root[index], 65, "%s", root) == 64;
    }
    json_free(&doc);
    if (!ok) aj_fail("plugin publish generation %zu: %s", index + 1, out);
    return ok;
}

static bool aj_plugin_publish_one(struct aj_node_ctx *c, size_t index)
{
    char dist[1100], license[1100], license_dst[1100];
    const char *version = index == 0 ? "1.0.0" : "2.0.0";
    return snprintf(dist, sizeof(dist), "%s/a/dist-v%zu", g_work, index + 1) < (int)sizeof(dist) &&
           aj_plugin_promote(c, version, dist, g_plugin_gen[index], g_plugin_image[index]) &&
           aj_path_join(license, sizeof(license), g_work, "capability/LICENSE") &&
           snprintf(license_dst, sizeof(license_dst), "%s/LICENSE", dist) < (int)sizeof(license_dst) &&
           aj_copy_file(license, license_dst) && aj_plugin_publish_root(c, dist, index);
}

static bool aj_plugin_publish(struct aj_node_ctx *c)
{
    if (!aj_plugin_key(c, "a/publisher.key", g_plugin_publisher)) return false;
    for (size_t i = 0; i < 2; i++)
        if (!aj_plugin_publish_one(c, i)) return false;
    return !strcmp(g_plugin_image[0], g_plugin_image[1]) &&
           strcmp(g_plugin_root[0], g_plugin_root[1]) != 0 &&
           strcmp(g_plugin_gen[0], g_plugin_gen[1]) != 0;
}

struct aj_fetch_record_paths {
    char zcode[1100], downloads[1100], record[1200], checkout[1200];
    char root_arg[96], dir_arg[1200];
};

static bool aj_fetch_record_prepare(struct aj_node_ctx *c, size_t index,
                                    struct aj_fetch_record_paths *p)
{
    return snprintf(p->zcode, sizeof(p->zcode), "%s/zcode", c->datadir) < (int)sizeof(p->zcode) &&
           snprintf(p->downloads, sizeof(p->downloads), "%s/downloads", p->zcode) < (int)sizeof(p->downloads) &&
           snprintf(p->record, sizeof(p->record), "%s/%s", p->downloads, g_plugin_root[index]) < (int)sizeof(p->record) &&
           snprintf(p->checkout, sizeof(p->checkout), "%s/received-v%zu", c->datadir, index + 1) < (int)sizeof(p->checkout) &&
           snprintf(p->root_arg, sizeof(p->root_arg), "--root=%s", g_plugin_root[index]) < (int)sizeof(p->root_arg) &&
           snprintf(p->dir_arg, sizeof(p->dir_arg), "--dir=%s", p->checkout) < (int)sizeof(p->dir_arg) &&
           aj_mkdir_p(p->zcode) == 0 &&
           aj_write_file(p->downloads, "not-a-directory\n");
}

static bool aj_plugin_fetch_record_refusal(struct aj_node_ctx *c, size_t index)
{
    struct aj_fetch_record_paths p;
    if (!aj_fetch_record_prepare(c, index, &p)) {
        aj_fail("could not prepare the download-record refusal");
        return false;
    }
    char *tail[] = {(char *)"plugin", (char *)"fetch", p.root_arg, p.dir_arg, NULL};
    char out[32768];
    int rc = aj_plugin_run(c, "fetch-record-refused", tail, out, sizeof(out), 120);
    bool ok = rc != 0 && aj_json_refusal(out, "PLUGIN_FETCH_RECORD_IO");
    if (access(p.record, F_OK) == 0 || (errno != ENOENT && errno != ENOTDIR))
        ok = false;
    if (access(p.checkout, F_OK) == 0 || errno != ENOENT)
        ok = false;
    if (remove(p.downloads) != 0) ok = false;
    if (!ok) aj_fail("download-record persistence refusal failed: %s", out);
    return ok;
}

static bool aj_plugin_request(struct aj_node_ctx *c, size_t index)
{
    char root_arg[96], dir_arg[1200];
    if (aj_mkdir_p(c->datadir) != 0 ||
        snprintf(root_arg, sizeof(root_arg), "--root=%s", g_plugin_root[index]) >= (int)sizeof(root_arg) ||
        snprintf(dir_arg, sizeof(dir_arg), "--dir=%s/received-v%zu", c->datadir, index + 1) >= (int)sizeof(dir_arg))
        return false;
    char *tail[] = {(char *)"plugin", (char *)"fetch", root_arg, dir_arg, NULL};
    char out[32768];
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, "fetch-record", tail, out, sizeof(out), 120) == 0 &&
              aj_json_ok(out, &doc);
    if (ok) {
        const struct json_value *data = aj_json_data(&doc);
        ok = aj_json_bool_is(data, "complete", false) && aj_json_bool_is(data, "live", false);
    }
    json_free(&doc);
    if (!ok) aj_fail("persisting inert plugin fetch: %s", out);
    return ok;
}

static bool aj_plugin_pin(struct aj_node_ctx *c)
{
    char *tail[] = {(char *)"plugin", (char *)"publisher", g_plugin_publisher, NULL};
    char out[8192];
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, "publisher-pin", tail, out, sizeof(out), 60) == 0 &&
              aj_json_ok(out, &doc);
    json_free(&doc);
    if (!ok) aj_fail("owner publisher pin: %s", out);
    return ok;
}

static bool aj_plugin_call_refusal(struct aj_node_ctx *c, const char *expected)
{
    char *tail[] = {(char *)"plugin", (char *)"call", (char *)"upper",
                    (char *)"--stdin=abc", NULL};
    char out[8192];
    bool ok = aj_plugin_run(c, "not-active", tail, out, sizeof(out), 60) != 0 &&
              aj_json_refusal(out, expected);
    if (!ok) aj_fail("%s check failed: %s", expected, out);
    return ok;
}

struct aj_package_wait { struct aj_node_ctx *node; const char *root; };

static bool aj_package_complete(void *p)
{
    struct aj_package_wait *w = p;
    char *tail[] = {(char *)"dumpstate", (char *)"zcode_store", (char *)w->root, NULL};
    char out[32768];
    int rc = aj_plugin_run(w->node, "package-status", tail, out, sizeof(out), 60);
    struct json_value doc = {0};
    json_init(&doc);
    bool parsed = json_read(&doc, out, strlen(out));
    const struct json_value *state = json_get(&doc, "state");
    bool ok = rc == 0 && parsed && aj_json_bool_is(state, "enabled", true) &&
              aj_json_bool_is(state, "tracked", true) && aj_json_bool_is(state, "complete", true);
    json_free(&doc);
    return ok;
}

static bool aj_plugin_wait_complete(struct aj_node_ctx *c, size_t index)
{
    struct aj_package_wait w = {.node = c, .root = g_plugin_root[index]};
    return aj_wait(aj_package_complete, &w, g_board_wait_s,
                   "source-bearing plugin package transfer");
}

static bool aj_package_counts(const struct json_value *package, bool pinned)
{
    const char *pool = package ? json_get_str(json_get(package, "pool")) : NULL;
    int64_t present = package ? json_get_int(json_get(package, "present_bytes")) : 0;
    int64_t total = package ? json_get_int(json_get(package, "total_bytes")) : 0;
    return package && aj_json_bool_is(package, "tracked", true) &&
           aj_json_bool_is(package, "complete", true) &&
           aj_json_bool_is(package, "pinned", pinned) && present > 0 &&
           present == total && (!pinned || (pool && !strcmp(pool, "pins")));
}

static bool aj_package_pin_identity(const struct json_value *data, bool commit,
                                    const char *planned)
{
    const char *root = json_get_str(json_get(data, "package_root"));
    const char *mode = json_get_str(json_get(data, "mode"));
    const char *result = json_get_str(json_get(data, "result"));
    return root && mode && planned && result &&
           !strcmp(root, g_plugin_root[0]) &&
           !strcmp(mode, commit ? "commit" : "plan") &&
           !strcmp(result, "ok") && strlen(planned) == 64;
}

static bool aj_package_pin_reply(const char *out, bool commit, char token[65])
{
    struct json_value doc = {0};
    bool ok = aj_json_ok(out, &doc);
    if (ok) {
        const struct json_value *data = aj_json_data(&doc);
        const char *planned = json_get_str(json_get(data, "plan_token"));
        ok = aj_package_pin_identity(data, commit, planned) &&
             aj_json_bool_is(data, "committed", commit) &&
             aj_json_bool_is(data, "pinned", commit) &&
             aj_package_counts(json_get(data, "package"), commit) &&
             (commit ? !strcmp(planned, token)
                     : snprintf(token, 65, "%s", planned) == 64);
    }
    json_free(&doc);
    return ok;
}

static bool aj_package_operator_pin(struct aj_node_ctx *c)
{
    char root_arg[96], token[65] = {0};
    if (snprintf(root_arg, sizeof(root_arg), "--root=%s", g_plugin_root[0]) >=
        (int)sizeof(root_arg)) return false;
    for (unsigned step = 0; step < 2; step++) {
        bool commit = step != 0;
        char token_arg[96];
        if (commit && snprintf(token_arg, sizeof(token_arg),
                               "--plan_token=%s", token) >=
                          (int)sizeof(token_arg)) return false;
        char *tail[] = {(char *)"zcode", (char *)"package", (char *)"pin",
                        root_arg, commit ? (char *)"--mode=commit" :
                        (char *)"--mode=plan", token_arg, NULL};
        if (!commit) tail[5] = NULL;
        char out[32768];
        int rc = aj_plugin_run(c, commit ? "package-pin-commit" :
                               "package-pin-plan", tail, out, sizeof(out), 60);
        if (rc != 0 || !aj_package_pin_reply(out, commit, token)) {
            aj_fail("operator package pin: %s", out);
            return false;
        }
    }
    return true;
}

struct aj_retention_observation {
    int64_t captured, chunks, total_chunks, bytes, total_bytes;
};

static bool aj_retention_observe(const char *out,
                                 struct aj_retention_observation *observation)
{
    struct json_value doc = {0};
    json_init(&doc);
    bool parsed = json_read(&doc, out, strlen(out));
    const struct json_value *state = json_get(&doc, "state");
    if (!parsed || !state) {
        json_free(&doc);
        return false;
    }
    observation->captured = json_get_int(json_get(&doc, "captured_at"));
    observation->chunks = json_get_int(json_get(state, "present_chunks"));
    observation->total_chunks = json_get_int(json_get(state, "total_chunks"));
    observation->bytes = json_get_int(json_get(state, "present_bytes"));
    observation->total_bytes = json_get_int(json_get(state, "total_bytes"));
    bool ok = observation->captured > 0 &&
              aj_json_bool_is(state, "enabled", true) &&
              aj_package_counts(state, true) && observation->chunks > 0 &&
              observation->chunks == observation->total_chunks;
    json_free(&doc);
    return ok;
}

static bool aj_replica_retention(struct aj_node_ctx *c, pid_t previous_pgid)
{
    char *tail[] = {(char *)"dumpstate", (char *)"zcode_store",
                    g_plugin_root[0], NULL};
    char out[32768];
    int rc = aj_plugin_run(c, "replica-retention", tail, out, sizeof(out), 60);
    struct aj_retention_observation observation = {0};
    bool ok = rc == 0 && aj_retention_observe(out, &observation);
    char evidence[1500], path[1100];
    int n = snprintf(evidence, sizeof(evidence),
        "publisher_running=false\nreplica_before_pgid=%d\n"
        "replica_after_pgid=%d\nold_process_group_absent=true\n"
        "store_reopened=true\npackage_root=%s\ncaptured_at=%lld\n"
        "complete=true\npinned=true\npool=pins\npresent_bytes=%lld\n"
        "total_bytes=%lld\npresent_chunks=%lld\ntotal_chunks=%lld\n"
        "retention_policy=owner-pin-no-expiry\n"
        "continuous_availability_attested=false\n"
        "sudden_power_loss_attested=false\n",
        previous_pgid, g_b_pgid, g_plugin_root[0],
        (long long)observation.captured, (long long)observation.bytes,
        (long long)observation.total_bytes, (long long)observation.chunks,
        (long long)observation.total_chunks);
    if (ok && (n < 0 || (size_t)n >= sizeof(evidence) ||
        !aj_path_join(path, sizeof(path), g_work, "b/replica-restart.txt") ||
        !aj_write_file(path, evidence))) ok = false;
    if (!ok) aj_fail("restarted replica did not recover its complete pin: %s", out);
    return ok;
}

static bool aj_plugin_wait_onion(struct aj_node_ctx *c, const char *who)
{
    char what[128];
    return snprintf(what, sizeof(what), "%s onion", who) < (int)sizeof(what) &&
           aj_wait(aj_probe_onion, c, g_tor_wait_s, what);
}

static bool aj_plugin_checkout(struct aj_node_ctx *c, size_t index)
{
    char root_arg[96], dir_arg[1200];
    if (snprintf(root_arg, sizeof(root_arg), "--root=%s", g_plugin_root[index]) >= (int)sizeof(root_arg) ||
        snprintf(dir_arg, sizeof(dir_arg), "--dir=%s/received-v%zu", c->datadir, index + 1) >= (int)sizeof(dir_arg))
        return false;
    char *fetch[] = {(char *)"plugin", (char *)"fetch", root_arg, dir_arg, NULL};
    char out[32768];
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, "fetch-checkout", fetch, out, sizeof(out), 120) == 0 &&
              aj_json_ok(out, &doc);
    if (ok) {
        const struct json_value *data = aj_json_data(&doc);
        ok = aj_json_bool_is(data, "complete", true) && aj_json_bool_is(data, "live", false) &&
             !strcmp(json_get_str(json_get(data, "root")), g_plugin_root[index]) &&
             !strcmp(json_get_str(json_get(data, "generation")), g_plugin_gen[index]);
    }
    json_free(&doc);
    if (!ok) aj_fail("local verified checkout: %s", out);
    return ok;
}

static bool aj_plugin_install(struct aj_node_ctx *c, size_t index, bool authorized)
{
    char manifest[1200];
    if (snprintf(manifest, sizeof(manifest), "--manifest=%s/received-v%zu/upper.plugin.json",
                 c->datadir, index + 1) >= (int)sizeof(manifest)) return false;
    char *tail[] = {(char *)"plugin", (char *)"install", manifest, NULL};
    char out[16384];
    int rc = aj_plugin_run(c, authorized ? "install" : "install-refused",
                           tail, out, sizeof(out), 60);
    if (!authorized) {
        bool refused = rc != 0 && aj_json_refusal(out, "PLUGIN_NO_KEYS");
        if (!refused) aj_fail("unpinned install was not refused: %s", out);
        return refused;
    }
    struct json_value doc = {0};
    bool ok = rc == 0 && aj_json_ok(out, &doc) &&
              !strcmp(json_get_str(json_get(aj_json_data(&doc), "generation")),
                      g_plugin_gen[index]);
    json_free(&doc);
    if (!ok) aj_fail("owner install: %s", out);
    return ok;
}

static bool aj_plugin_rebuild_data(const struct json_value *data, const char *builder)
{
    return aj_json_bool_is(data, "reproduced", true) &&
           aj_json_bool_is(data, "installed", false) &&
           aj_json_bool_is(data, "activated", false) &&
           aj_json_bool_is(data, "physical_independence_attested", false) &&
           !strcmp(json_get_str(json_get(data, "generation")), g_plugin_gen[0]) &&
           !strcmp(json_get_str(json_get(data, "image_sha3_512")), g_plugin_image[0]) &&
           !strcmp(json_get_str(json_get(data, "source_root")), g_plugin_root[0]) &&
           !strcmp(json_get_str(json_get(data, "builder_key")), builder) &&
           json_get_int(json_get(data, "cases_passed")) == 2;
}

static bool aj_plugin_rebuild(struct aj_node_ctx *c, const char *received,
                              const char *builder)
{
    char dir_arg[1200], key_arg[1200], out_arg[1200], source_arg[96];
    if (snprintf(dir_arg, sizeof(dir_arg), "--dir=%s", received) >= (int)sizeof(dir_arg) ||
        snprintf(key_arg, sizeof(key_arg), "--key=%s/b/builder.key", g_work) >= (int)sizeof(key_arg) ||
        snprintf(out_arg, sizeof(out_arg), "--out=%s/b/reproduced", g_work) >= (int)sizeof(out_arg) ||
        snprintf(source_arg, sizeof(source_arg), "--source-root=%s", g_plugin_root[0]) >= (int)sizeof(source_arg))
        return false;
    char *reproduce[] = {(char *)"plugin", (char *)"reproduce", dir_arg,
        source_arg, key_arg, out_arg, (char *)"--toolchain=live-gcc-linux-x86_64", NULL};
    char out[32768];
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, "reproduce", reproduce, out, sizeof(out), 240) == 0 &&
              aj_json_ok(out, &doc);
    if (ok) ok = aj_plugin_rebuild_data(aj_json_data(&doc), builder);
    json_free(&doc);
    if (!ok) aj_fail("receiver reproduction: %s", out);
    return ok;
}

static bool aj_plugin_attest(struct aj_node_ctx *c, const char *received,
                             const char *builder)
{
    char pin_path[1100], pin[80], manifest[1200], attestations[1200], builders[1200];
    if (!aj_path_join(pin_path, sizeof(pin_path), g_work, "b/builders.pin") ||
        snprintf(pin, sizeof(pin), "%s\n", builder) >= (int)sizeof(pin) ||
        !aj_write_file(pin_path, pin) || chmod(pin_path, 0600) != 0 ||
        snprintf(manifest, sizeof(manifest), "--manifest=%s/upper.plugin.json", received) >= (int)sizeof(manifest) ||
        snprintf(attestations, sizeof(attestations), "--attestations=%s/b/reproduced", g_work) >= (int)sizeof(attestations) ||
        snprintf(builders, sizeof(builders), "--builders=%s", pin_path) >= (int)sizeof(builders))
        return false;
    char root_arg[96];
    if (snprintf(root_arg, sizeof(root_arg), "--source-root=%s", g_plugin_root[0]) >= (int)sizeof(root_arg))
        return false;
    char *verify[] = {(char *)"plugin", (char *)"attest_verify", manifest,
        attestations, builders, (char *)"--threshold=1", root_arg, NULL};
    char out[32768];
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, "attest-verify", verify, out, sizeof(out), 60) == 0 &&
              aj_json_ok(out, &doc);
    if (ok) {
        const struct json_value *data = aj_json_data(&doc);
        ok = aj_json_bool_is(data, "accepted", true) &&
             json_get_int(json_get(data, "attested")) == 1 &&
             json_get_int(json_get(data, "threshold")) == 1;
    }
    json_free(&doc);
    if (!ok) aj_fail("receiver attestation: %s", out);
    return ok;
}

static bool aj_plugin_owner_install(struct aj_node_ctx *c, bool two_generations)
{
    if (!aj_plugin_checkout(c, 0) ||
        (two_generations && !aj_plugin_checkout(c, 1)) ||
        !aj_plugin_install(c, 0, false) || !aj_plugin_pin(c) ||
        !aj_plugin_install(c, 0, true) ||
        (two_generations && !aj_plugin_install(c, 1, true))) return false;
    return aj_plugin_call_refusal(c, "PLUGIN_NO_GENERATION");
}

static bool aj_plugin_reproduce_attested(struct aj_node_ctx *c)
{
    char received[1100];
    if (snprintf(received, sizeof(received), "%s/received-v1", c->datadir) >= (int)sizeof(received))
        return false;
    char builder[65];
    return aj_plugin_key(c, "b/builder.key", builder) &&
           strcmp(builder, g_plugin_publisher) != 0 &&
           aj_plugin_rebuild(c, received, builder) &&
           aj_plugin_attest(c, received, builder);
}

static bool aj_plugin_reproduce_refusal(struct aj_node_ctx *c, const char *dir,
                                        const char *root, const char *out_dir,
                                        const char *expected)
{
    char dir_arg[1200], source_arg[96], key_arg[1200], out_arg[1200];
    if (snprintf(dir_arg, sizeof(dir_arg), "--dir=%s", dir) >= (int)sizeof(dir_arg) ||
        snprintf(source_arg, sizeof(source_arg), "--source-root=%s", root) >= (int)sizeof(source_arg) ||
        snprintf(key_arg, sizeof(key_arg), "--key=%s/b/builder.key", g_work) >= (int)sizeof(key_arg) ||
        snprintf(out_arg, sizeof(out_arg), "--out=%s", out_dir) >= (int)sizeof(out_arg))
        return false;
    char *tail[] = {(char *)"plugin", (char *)"reproduce", dir_arg, source_arg,
        key_arg, out_arg, (char *)"--toolchain=live-gcc-linux-x86_64", NULL};
    char out[16384];
    bool ok = aj_plugin_run(c, "refusal", tail, out, sizeof(out), 60) != 0 &&
              aj_json_refusal(out, expected) &&
              access(out_dir, F_OK) != 0 && errno == ENOENT;
    if (!ok) aj_fail("%s was not refused without output: %s", expected, out);
    return ok;
}

static bool aj_plugin_wrong_root(struct aj_node_ctx *c)
{
    char bad_root[65], out_dir[1100], dir[1100];
    if (snprintf(bad_root, sizeof(bad_root), "%s", g_plugin_root[0]) != 64)
        return false;
    bad_root[0] = bad_root[0] == '0' ? '1' : '0';
    return aj_path_join(out_dir, sizeof(out_dir), g_work, "b/wrong-root-out") &&
           snprintf(dir, sizeof(dir), "%s/received-v1", c->datadir) < (int)sizeof(dir) &&
           aj_plugin_reproduce_refusal(c, dir, bad_root, out_dir,
                                       "PLUGIN_REPRODUCE_ROOT_MISMATCH");
}

static bool aj_flip_image(const char *path)
{
    FILE *f = fopen(path, "r+b");
    if (!f) return false;
    int byte = fseek(f, 32, SEEK_SET) == 0 ? fgetc(f) : EOF;
    bool ok = byte != EOF && fseek(f, 32, SEEK_SET) == 0 &&
              fputc(byte == 'X' ? 'Y' : 'X', f) != EOF;
    return fclose(f) == 0 && ok;
}

static bool aj_plugin_corrupt_image(struct aj_node_ctx *c)
{
    char from[1100], corrupt[1100], image[1200], out_dir[1100];
    if (snprintf(from, sizeof(from), "%s/received-v1", c->datadir) >= (int)sizeof(from) ||
        !aj_path_join(corrupt, sizeof(corrupt), g_work, "b/corrupt") ||
        !aj_path_join(out_dir, sizeof(out_dir), g_work, "b/corrupt-out") ||
        !aj_copy_flat(from, corrupt) ||
        snprintf(image, sizeof(image), "%s/upper", corrupt) >= (int)sizeof(image) ||
        !aj_flip_image(image)) {
        aj_fail("could not prepare a corrupt image copy");
        return false;
    }
    return aj_plugin_reproduce_refusal(c, corrupt, g_plugin_root[0], out_dir,
                                       "PLUGIN_EXE_HASH");
}

static bool aj_plugin_corruption(struct aj_node_ctx *c)
{
    return aj_plugin_wrong_root(c) && aj_plugin_corrupt_image(c);
}

static bool aj_plugin_call(struct aj_node_ctx *c, size_t generation)
{
    char out[16384];
    char *tail[] = {(char *)"plugin", (char *)"call", (char *)"upper",
                    (char *)"--stdin=abc", NULL};
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, "call", tail, out, sizeof(out), 60) == 0 &&
              aj_json_ok(out, &doc);
    if (ok) {
        const struct json_value *data = aj_json_data(&doc);
        const struct json_value *run = json_get(data, "run");
        const char *version = generation == 0 ? "1.0.0" : "2.0.0";
        ok = !strcmp(json_get_str(json_get(data, "version")), version) &&
             !strcmp(json_get_str(json_get(data, "generation")), g_plugin_gen[generation]) &&
             run && !strcmp(json_get_str(json_get(run, "stdout")), "ABC") &&
             json_get_int(json_get(run, "exit_code")) == 0;
    }
    json_free(&doc);
    if (!ok) aj_fail("plugin call generation %zu: %s", generation + 1, out);
    return ok;
}

static bool aj_plugin_switch(struct aj_node_ctx *c, size_t generation, bool rollback)
{
    char *tail[] = {(char *)"plugin", rollback ? (char *)"rollback" : (char *)"switch",
        (char *)"upper", rollback ? NULL : g_plugin_gen[generation], NULL};
    char out[16384];
    struct json_value doc = {0};
    bool ok = aj_plugin_run(c, rollback ? "rollback" : "switch", tail,
                            out, sizeof(out), 60) == 0 && aj_json_ok(out, &doc);
    if (ok)
        ok = !strcmp(json_get_str(json_get(aj_json_data(&doc), "current")),
                     g_plugin_gen[generation]);
    json_free(&doc);
    if (!ok) aj_fail("plugin selection: %s", out);
    return ok;
}

static bool aj_plugin_activate_rollback(struct aj_node_ctx *c)
{
    if (!aj_plugin_switch(c, 0, false) || !aj_plugin_call(c, 0)) return false;
    char data_dir[1100], state[1200];
    if (!aj_path_join(data_dir, sizeof(data_dir), c->home, ".z23/plugins/upper/data") ||
        aj_mkdir_p(data_dir) != 0 ||
        !aj_path_join(state, sizeof(state), data_dir, "state.txt") ||
        !aj_write_file(state, "owner-state-survives\n") ||
        !aj_plugin_switch(c, 1, false) || !aj_plugin_call(c, 1) ||
        !aj_plugin_switch(c, 0, true) || !aj_plugin_call(c, 0)) return false;
    char kept[64];
    if (aj_slurp(state, kept, sizeof(kept)) <= 0 || strcmp(kept, "owner-state-survives\n")) {
        aj_fail("plugin rollback changed owner state");
        return false;
    }
    return true;
}

static bool aj_plugin_receive(struct aj_node_ctx *bc)
{
    return aj_plugin_wait_complete(bc, 0) && aj_plugin_wait_complete(bc, 1) &&
           aj_plugin_call_refusal(bc, "PLUGIN_NOT_INSTALLED");
}

static bool aj_plugin_reproduce_rollback(struct aj_node_ctx *bc)
{
    if (!aj_kill_group(g_b_pgid)) {
        aj_fail("could not stop receiver B before its CLI store handoff");
        return false;
    }
    g_b_pgid = 0;
    aj_sleep_ms(2000);
    return aj_plugin_owner_install(bc, true) && aj_plugin_reproduce_attested(bc) &&
           aj_plugin_corruption(bc) && aj_plugin_activate_rollback(bc);
}

static bool aj_replica_restart(struct aj_node_ctx *bc, pid_t previous_b_pgid)
{
    g_b_pgid = aj_node_spawn(bc->home, bc->datadir, g_b_log, APPJ_B_P2P,
        APPJ_B_RPC, APPJ_B_FS, APPJ_B_HTTPS, APPJ_CONNECT_A, true);
    errno = 0;
    int old_probe = kill(-previous_b_pgid, 0);
    int old_error = errno;
    if (g_b_pgid <= 1 || g_b_pgid == previous_b_pgid ||
        old_probe != -1 || old_error != ESRCH) {
        aj_fail("restart identity failed: before=%d after=%d "
                "old_probe=%d old_errno=%d", previous_b_pgid, g_b_pgid,
                old_probe, old_error);
        return false;
    }
    if (!aj_plugin_wait_onion(bc, "restarted replica B")) return false;
    pid_t actual_pgid = getpgid(g_b_pgid);
    if (actual_pgid != g_b_pgid) {
        aj_fail("restarted receiver is not its session leader: pid=%d pgid=%d",
                g_b_pgid, actual_pgid);
        return false;
    }
    return aj_replica_retention(bc, previous_b_pgid);
}

static bool aj_joiner_prepare(struct aj_node_ctx *cc)
{
    return snprintf(g_c_home, sizeof(g_c_home), "%s/c/home", g_work) < (int)sizeof(g_c_home) &&
           snprintf(g_c_dd, sizeof(g_c_dd), "%s/c/datadir", g_work) < (int)sizeof(g_c_dd) &&
           snprintf(g_c_log, sizeof(g_c_log), "%s/c/node.log", g_work) < (int)sizeof(g_c_log) &&
           snprintf(cc->home, sizeof(cc->home), "%s", g_c_home) < (int)sizeof(cc->home) &&
           snprintf(cc->datadir, sizeof(cc->datadir), "%s", g_c_dd) < (int)sizeof(cc->datadir) &&
           aj_mkdir_p(g_c_home) == 0;
}

static bool aj_joiner_request(struct aj_node_ctx *cc)
{
    if (!aj_plugin_fetch_record_refusal(cc, 0) || !aj_plugin_request(cc, 0))
        return false;
    char record[1200];
    struct stat st;
    if (snprintf(record, sizeof(record), "%s/zcode/downloads/%s", cc->datadir,
                 g_plugin_root[0]) >= (int)sizeof(record) ||
        stat(record, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size == 0) {
        aj_fail("fresh recipient did not retain a resumable fetch record");
        return false;
    }
    return true;
}

static bool aj_plugin_replica(struct aj_node_ctx *bc, pid_t previous_b_pgid)
{
    if (g_a_pgid || g_b_pgid || previous_b_pgid <= 1) {
        aj_fail("publisher or receiver is still live before the replica restart");
        return false;
    }
    if (!aj_replica_restart(bc, previous_b_pgid)) return false;
    struct aj_node_ctx cc = {.rpc = APPJ_C_RPC};
    if (!aj_joiner_prepare(&cc) || !aj_joiner_request(&cc)) return false;
    g_c_pgid = aj_node_spawn(g_c_home, g_c_dd, g_c_log, APPJ_A_P2P,
        APPJ_C_RPC, APPJ_C_FS, APPJ_C_HTTPS, APPJ_CONNECT_B, true);
    if (!g_c_pgid || !aj_plugin_wait_onion(&cc, "joiner C") ||
        !aj_plugin_wait_complete(&cc, 0)) return false;
    if (!aj_kill_group(g_c_pgid)) {
        aj_fail("could not stop joiner C before its CLI store handoff");
        return false;
    }
    g_c_pgid = 0;
    return aj_plugin_owner_install(&cc, false);
}

/* ── reporting ──────────────────────────────────────────────────────── */

static void aj_note(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("app-journey-live: ", stdout);
    vprintf(fmt, ap);
    putchar('\n');
    va_end(ap);
    fflush(stdout);
}

static void aj_fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("app-journey-live: FAIL: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    if (!g_fail_first) {
        va_start(ap, fmt);
        char path[1024];
        if (aj_path_join(path, sizeof(path), g_work, "FAILURE")) {
            FILE *f = fopen(path, "w");
            if (f) {
                vfprintf(f, fmt, ap);
                fputc('\n', f);
                fclose(f);
                g_fail_first = path;
            }
        }
        va_end(ap);
    }
}

/* Wait for one or both nodes to answer RPC and publish a ready onion.
 * `suffix` decorates the wait labels (the hosting restart reuses this). */
static bool aj_wait_ready_pair(struct aj_node_ctx *ac, struct aj_node_ctx *bc,
                               const char *suffix)
{
    char what[96];
    if (snprintf(what, sizeof(what), "node A RPC%s", suffix) >= (int)sizeof(what) ||
        !aj_wait(aj_probe_rpc, ac, g_wait_s, what))
        return false;
    if (bc &&
        snprintf(what, sizeof(what), "node B RPC%s", suffix) < (int)sizeof(what) &&
        !aj_wait(aj_probe_rpc, bc, g_wait_s, what))
        return false;
    if (snprintf(what, sizeof(what),
                 "node A onion (public Tor reachability is required)%s", suffix) >= (int)sizeof(what) ||
        !aj_wait(aj_probe_onion, ac, g_tor_wait_s, what))
        return false;
    if (!bc) return true;
    if (snprintf(what, sizeof(what), "node B onion%s", suffix) >= (int)sizeof(what))
        return false;
    return aj_wait(aj_probe_onion, bc, g_tor_wait_s, what);
}

static bool aj_app_journey(struct aj_node_ctx *ac, struct aj_node_ctx *bc)
{
    /* A boots WITHOUT hosting (the CLI owns <datadir>/zcode for the local
     * verbs); B boots hosting and dials A over the allowlisted port. */
    g_a_pgid = aj_node_spawn(g_a_home, g_a_dd, g_a_log, APPJ_A_P2P, APPJ_A_RPC,
                             APPJ_A_FS, APPJ_A_HTTPS, APPJ_DEAD_SINK, false);
    g_b_pgid = aj_node_spawn(g_b_home, g_b_dd, g_b_log, APPJ_B_P2P, APPJ_B_RPC,
                             APPJ_B_FS, APPJ_B_HTTPS, APPJ_CONNECT_A, true);
    if (!aj_wait_ready_pair(ac, bc, "")) return false;
    char a_addr[128], a_state[32];
    bool a_r = false;
    (void)aj_onion_status(g_a_dd, APPJ_A_RPC, g_a_home, a_addr, sizeof(a_addr),
                          a_state, sizeof(a_state), &a_r);
    aj_note("phase 1 nodes up, A onion %s", a_addr);

    if (!aj_phase_a_local(ac)) return false;
    aj_note("phase 2 A journey: create, modify, build %.16s, open, share file",
            g_image_a);

    /* A restarts WITH hosting: the single package-store writer handoff. */
    if (!aj_kill_group(g_a_pgid)) {
        aj_fail("node A did not exit before its hosting restart");
        return false;
    }
    g_a_pgid = 0;
    aj_sleep_ms(2000);
    g_a_pgid = aj_node_spawn(g_a_home, g_a_dd, g_a_log, APPJ_A_P2P, APPJ_A_RPC,
                             APPJ_A_FS, APPJ_A_HTTPS, APPJ_DEAD_SINK, true);
    if (!g_a_pgid) {
        aj_fail("node A hosting restart failed");
        return false;
    }
    if (!aj_wait_ready_pair(ac, NULL, " (hosting)")) return false;
    if (!aj_phase_publish(ac)) return false;
    aj_note("phase 3 A published offer %.16s root %.16s", g_post, g_root);

    if (!aj_phase_b_get(bc)) return false;
    aj_note("phase 4 B received A's exact offer, rebuilt the same image and "
            "now hosts the carrier");

    if (!aj_plugin_receive(bc) || !aj_package_operator_pin(bc) ||
        !aj_phase_outlives(bc)) return false;
    aj_note("phase 5 outlives: A dead, B still serves the app");
    return true;
}

/* The whole journey after argument parsing: fixture, nodes, A's local
 * verbs, A's hosting restart, publish, B's get, the outlives leg. Returns
 * 0 PASS / 2 FAIL, with nodes always stopped and evidence kept on FAIL. */
static int aj_journey(void)
{
    aj_note("work tree %s", g_work);
    if (!aj_fixture()) {
        aj_fail("fixture checkout could not be written");
        return 2;
    }
    aj_note("phase 0 fixture: ok");

    struct aj_node_ctx ac = {.rpc = APPJ_A_RPC}, bc = {.rpc = APPJ_B_RPC};
    snprintf(ac.datadir, sizeof(ac.datadir), "%s", g_a_dd);
    snprintf(bc.datadir, sizeof(bc.datadir), "%s", g_b_dd);
    snprintf(ac.home, sizeof(ac.home), "%s", g_a_home);
    snprintf(bc.home, sizeof(bc.home), "%s", g_b_home);

    if (!aj_plugin_publish(&ac) || !aj_plugin_request(&bc, 0) ||
        !aj_plugin_request(&bc, 1)) goto fail;
    aj_note("phase 0 C23 plugin: signed two generations and persisted inert fetches");

    if (!aj_app_journey(&ac, &bc)) goto fail;
    pid_t previous_b_pgid = g_b_pgid;
    if (!aj_plugin_reproduce_rollback(&bc) ||
        !aj_plugin_replica(&bc, previous_b_pgid)) goto fail;
    aj_note("phase 6 plugin: owner-pinned replica restarted after A exits; "
            "reproduction, refused authority, state-preserving rollback and "
            "fresh-peer recovery passed");

    bool stopped = aj_kill_group(g_a_pgid);
    stopped = aj_kill_group(g_b_pgid) && stopped;
    stopped = aj_kill_group(g_c_pgid) && stopped;
    if (!stopped) {
        aj_fail("could not stop every test node");
        goto fail;
    }
    if (!g_keep) (void)aj_rm_rf(g_work, 0);
    aj_note("PASS: stranger-to-stranger app journeys proven live between "
            "two isolated nodes: 1");
    return 0;

fail:
    (void)aj_kill_group(g_a_pgid);
    (void)aj_kill_group(g_b_pgid);
    (void)aj_kill_group(g_c_pgid);
    aj_note("FAIL preserved evidence under %s", g_work);
    return 2;
}

/* One --work=DIR / --keep argument set. Returns 0 ok, 3 usage. */
static int aj_parse_args(int argc, char **argv, const char **work_override)
{
    *work_override = NULL;
    const char *keep = getenv("APPJ_KEEP");
    g_keep = keep && strcmp(keep, "1") == 0;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--work=", 7)) *work_override = argv[i] + 7;
        else if (!strcmp(argv[i], "--keep")) g_keep = true;
        else return 3;
    }
    return 0;
}

/* Named failure instead of a silent timeout when the binaries this
 * journey drives were never built in this checkout. */
static bool aj_binaries_present(void)
{
    struct stat st;
    char need[600];
    static const char *const needed[] = {"build/bin/z23",
                                         "build/bin/zclassic23"};
    for (size_t i = 0; i < sizeof(needed) / sizeof(needed[0]); i++) {
        if (snprintf(need, sizeof(need), "%s/%s", g_repo, needed[i]) >= (int)sizeof(need) ||
            stat(need, &st) != 0) {
            fprintf(stderr, "app-journey-live: FAIL: %s is missing in %s "
                            "(run make z23 first)\n", needed[i], g_repo);
            return false;
        }
    }
    return true;
}

/* The scratch tree and per-persona paths. Returns false when the binaries
 * this journey drives were never built or a path does not fit. */
static bool aj_prepare(const char *work_override)
{
    if (!aj_binaries_present()) return false;
    const char *home = getenv("HOME");
    if (work_override) {
        if (snprintf(g_work, sizeof(g_work), "%s", work_override) >= (int)sizeof(g_work))
            return false;
    } else if (!home ||
        snprintf(g_work, sizeof(g_work),
                 "%s/.cache/development-scratch/z23/appjourney-live-%ld",
                 home, (long)getpid()) >= (int)sizeof(g_work)) {
        return false;
    }
    return aj_mkdir_p(g_work) == 0 &&
        aj_path_join(g_a_home, sizeof(g_a_home), g_work, "a/home") &&
        aj_path_join(g_a_dd, sizeof(g_a_dd), g_work, "a/datadir") &&
        aj_path_join(g_b_home, sizeof(g_b_home), g_work, "b/home") &&
        aj_path_join(g_b_dd, sizeof(g_b_dd), g_work, "b/datadir") &&
        aj_path_join(g_a_log, sizeof(g_a_log), g_work, "a/node.log") &&
        aj_path_join(g_b_log, sizeof(g_b_log), g_work, "b/node.log") &&
        aj_mkdir_p(g_a_home) == 0 && aj_mkdir_p(g_b_home) == 0;
}

/* Split roles exchange only these public identities; the receiver checks them
 * after name-only discovery and never turns them into retrieval selectors. */
static bool aj_role_hex(const char *s, size_t len)
{
    uint8_t bytes[33];
    return len <= 2 * sizeof(bytes) && !(len % 2) && zcl_hex_decode_lower(s, bytes, len / 2);
}

static bool aj_role_name_part(const char *s, size_t len)
{
    if (!len || len > 63 || s[0] == '-' || s[len - 1] == '-') return false;
    for (size_t i = 0; i < len; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '-')) return false;
    return true;
}

static bool aj_role_name(const char *s)
{
    if (!s || strlen(s) >= sizeof(g_name)) return false;
    const char *slash = strchr(s, '/');
    return slash && aj_role_name_part(s, (size_t)(slash - s)) &&
        aj_role_name_part(slash + 1, strlen(slash + 1));
}

static bool aj_role_read_public(const char *path, char *body, size_t cap)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size < (off_t)cap;
    size_t used = 0;
    while (ok && used < (size_t)st.st_size) {
        ssize_t n = read(fd, body + used, (size_t)st.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        used += (size_t)n;
    }
    char extra;
    if (ok && read(fd, &extra, 1) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    body[used] = 0;
    return ok && strlen(body) == used && !strstr(body, "\\u0000");
}

static bool aj_role_expected_values(const struct json_value *v)
{
    const struct json_value *name = json_get(v, "name"), *root = json_get(v, "root");
    const struct json_value *pub = json_get(v, "publisher"), *image = json_get(v, "image");
    bool ok = name && name->type == JSON_STR && root && root->type == JSON_STR &&
        pub && pub->type == JSON_STR && image && image->type == JSON_STR &&
        aj_role_name(json_get_str(name)) && aj_role_hex(json_get_str(root), 64) &&
        aj_role_hex(json_get_str(pub), 66) && aj_role_hex(json_get_str(image), 64);
    if (ok) {
        snprintf(g_name, sizeof(g_name), "%s", json_get_str(name));
        snprintf(g_root, sizeof(g_root), "%s", json_get_str(root));
        snprintf(g_publisher, sizeof(g_publisher), "%s", json_get_str(pub));
        snprintf(g_image_a, sizeof(g_image_a), "%s", json_get_str(image));
    }
    return ok;
}

static bool aj_role_expected(const char *path)
{
    char body[4097];
    if (!aj_role_read_public(path, body, sizeof(body))) return false;
    struct json_value v; json_init(&v);
    bool ok = json_read(&v, body, strlen(body)) && aj_role_expected_values(&v);
    json_free(&v); return ok;
}

struct aj_route_observation { char onion[63]; int port; };

static bool aj_route_identity(const struct json_value *data, char onion[63])
{
    const struct json_value *address = json_get(data, "onion_address");
    const struct json_value *ready = json_get(data, "p2p_publish_ready");
    if (!address || address->type != JSON_STR || !ready || ready->type != JSON_BOOL || !json_get_bool(ready)) return false;
    const char *value = json_get_str(address); char endpoint[80];
    int n = snprintf(endpoint, sizeof(endpoint), "%s:1", value);
    if (n < 0 || (size_t)n >= sizeof(endpoint) || !aj_role_peer(endpoint)) return false;
    memcpy(onion, value, 63); return true;
}

static bool aj_route_mapping_ready(const struct json_value *mapping)
{
    const struct json_value *complete = json_get(mapping, "complete"), *persistent = json_get(mapping, "persistent_identity");
    const struct json_value *routes = json_get(mapping, "routes");
    return mapping && mapping->type == JSON_OBJ && complete && complete->type == JSON_BOOL && json_get_bool(complete) &&
        persistent && persistent->type == JSON_BOOL && json_get_bool(persistent) && routes && routes->type == JSON_ARR;
}

static int aj_route_entry(const struct json_value *route, int *port)
{
    const struct json_value *name = json_get(route, "name");
    if (!name || name->type != JSON_STR || strcmp(json_get_str(name), "p2p_tcp")) return 0;
    const struct json_value *installed = json_get(route, "installed"), *value = json_get(route, "virtual_port");
    if (!installed || installed->type != JSON_BOOL || !json_get_bool(installed) ||
        !value || value->type != JSON_INT || json_get_int(value) < 1 || json_get_int(value) > 65535) return -1;
    *port = (int)json_get_int(value); return 1;
}

static bool aj_route_mapping(const struct json_value *mapping, int *port)
{
    if (!aj_route_mapping_ready(mapping)) return false;
    const struct json_value *routes = json_get(mapping, "routes");
    int found = 0;
    for (size_t i = 0; i < json_size(routes); i++) {
        int result = aj_route_entry(json_at(routes, i), port);
        if (result < 0 || (result && ++found > 1)) return false;
    }
    return found == 1;
}

static bool aj_route_skip_ok(const struct json_value *skip)
{
    if (!skip) return true;
    return skip->type == JSON_STR && strcmp(json_get_str(skip), "onion_address") &&
        strcmp(json_get_str(skip), "p2p_publish_ready") && strcmp(json_get_str(skip), "port_mapping");
}

static bool aj_route_page_control(const struct json_value *data, int64_t cursor,
                                  int64_t *next, bool *more)
{
    const struct json_value *page = json_get(data, "_page"), *truncated = json_get(page, "truncated");
    const struct json_value *skip = json_get(page, "skipped_oversize");
    if (!page || page->type != JSON_OBJ || !truncated || truncated->type != JSON_BOOL) return false;
    if (!aj_route_skip_ok(skip)) return false;
    *more = json_get_bool(truncated);
    if (!*more) return true;
    const struct json_value *n = json_get(page, "next_cursor"), *total = json_get(page, "total_fields");
    if (!n || n->type != JSON_INT || !total || total->type != JSON_INT ||
        json_get_int(n) <= cursor || json_get_int(n) > json_get_int(total)) return false;
    *next = json_get_int(n); return true;
}

static bool aj_route_fetch(struct aj_node_ctx *a, int64_t cursor, char *out, size_t cap)
{
    char arg[64];
    if (snprintf(arg, sizeof(arg), "--cursor=%lld", (long long)cursor) >= (int)sizeof(arg)) return false;
    char *tail[] = {(char *)"core", (char *)"network", (char *)"onion", (char *)"status", arg, NULL};
    return aj_cli(a->datadir, a->rpc, tail, out, cap, 90, a->home) == 0;
}

static bool aj_route_save(const char *name, const char *out)
{
    char path[1024];
    return aj_path_join(path, sizeof(path), g_work, name) && aj_write_file(path, out);
}

static bool aj_route_envelope(const char *out, struct json_value *v)
{
    if (!aj_json_ok(out, v)) return false;
    const struct json_value *schema = json_get(v, "data_schema"), *command = json_get(v, "command");
    return schema && schema->type == JSON_STR && !strcmp(json_get_str(schema), "zcl.onion_status.v1") &&
        command && command->type == JSON_STR && !strcmp(json_get_str(command), "core.network.onion.status");
}

static bool aj_route_read_pages(struct aj_node_ctx *a, struct aj_route_observation *route)
{
    int64_t cursor = 0;
    for (int page = 0; page < 16; page++) {
        char out[16384] = {0}, name[64]; struct json_value v = {0};
        if (page == 0) snprintf(name, sizeof(name), "onion-status.json");
        else snprintf(name, sizeof(name), "onion-status-page-%d.json", page + 1);
        bool fetched = aj_route_fetch(a, cursor, out, sizeof(out));
        bool saved = aj_route_save(name, out);
        if (!fetched || !saved || !aj_route_envelope(out, &v)) { json_free(&v); return false; }
        const struct json_value *data = aj_json_data(&v), *mapping = json_get(data, "port_mapping");
        int64_t next = 0; bool more = false;
        bool ok = data && data->type == JSON_OBJ && aj_route_page_control(data, cursor, &next, &more);
        if (ok && page == 0) ok = aj_route_identity(data, route->onion);
        if (ok && mapping) ok = aj_route_mapping(mapping, &route->port);
        json_free(&v);
        if (!ok) return false;
        if (route->port) return true;
        if (!more) return false;
        cursor = next;
    }
    return false;
}

static bool aj_route_recheck_mapping(const struct json_value *data, int expected)
{
    const struct json_value *mapping = json_get(data, "port_mapping");
    if (!mapping) return true;
    int port = 0;
    return aj_route_mapping(mapping, &port) && port == expected;
}

static bool aj_role_status_file(struct aj_node_ctx *a)
{
    struct aj_route_observation route = {0};
    if (!aj_route_read_pages(a, &route)) return false;
    char out[16384] = {0}, onion[63]; struct json_value v = {0};
    bool fetched = aj_route_fetch(a, 0, out, sizeof(out));
    bool saved = aj_route_save("onion-status-recheck.json", out);
    if (!fetched || !saved || !aj_route_envelope(out, &v)) { json_free(&v); return false; }
    int64_t next = 0; bool more = false;
    bool ok = aj_route_page_control(aj_json_data(&v), 0, &next, &more) &&
        aj_route_identity(aj_json_data(&v), onion) && !strcmp(onion, route.onion) &&
        aj_route_recheck_mapping(aj_json_data(&v), route.port);
    json_free(&v);
    char body[256];
    int n = snprintf(body, sizeof(body), "{\"endpoint\":\"%s:%d\",\"observation\":\"separate_status_reads_not_atomic\"}\n", route.onion, route.port);
    return ok && n > 0 && (size_t)n < sizeof(body) && aj_route_save("peer.json", body);
}

static bool aj_role_public_files(struct aj_node_ctx *a)
{
    if (!aj_role_name(g_name) || !aj_role_hex(g_root, 64) ||
        !aj_role_hex(g_publisher, 66) || !aj_role_hex(g_image_a, 64)) return false;
    char path[1024], body[1024];
    int n = snprintf(body, sizeof(body),
        "{\"name\":\"%s\",\"root\":\"%s\",\"publisher\":\"%s\",\"image\":\"%s\"}\n",
        g_name, g_root, g_publisher, g_image_a);
    if (n < 0 || (size_t)n >= sizeof(body) || !aj_path_join(path, sizeof(path), g_work, "expected.json") ||
        !aj_write_file(path, body)) return false;
    return aj_role_status_file(a);
}

static bool aj_role_node_start(const char *home, const char *datadir, const char *log,
                               int p2p, int rpc, int fs, int https, const char *peer, bool hosting);
static bool aj_role_node_stop(void);

static bool aj_role_hold(long seconds)
{
    char path[1024];
    if (!aj_path_join(path, sizeof(path), g_work, "finish")) return false;
    long start = aj_now_s();
    if (start <= 0) return false;
    for (;;) {
        if (platform_supervised_poll(&g_role_node) != PLATFORM_SUPERVISED_RUNNING ||
            g_role_node.supervisor_pid < 0) return false;
        struct stat st;
        if (lstat(path, &st) == 0) return S_ISREG(st.st_mode) && st.st_uid == getuid();
        if (errno != ENOENT) return false;
        long now = aj_now_s();
        if (now < start || now - start >= seconds) return false;
        aj_sleep_ms(200);
    }
}

static bool aj_role_sender(long seconds)
{
    struct aj_node_ctx a = {.rpc = APPJ_A_RPC};
    snprintf(a.home, sizeof(a.home), "%s", g_a_home);
    snprintf(a.datadir, sizeof(a.datadir), "%s", g_a_dd);
    if (!aj_fixture()) return false;
    if (!aj_role_node_start(a.home, a.datadir, g_a_log, APPJ_A_P2P, APPJ_A_RPC,
                            APPJ_A_FS, APPJ_A_HTTPS, APPJ_DEAD_SINK, false) ||
        !aj_wait_ready_pair(&a, NULL, "") || !aj_phase_a_local(&a)) return false;
    if (!aj_role_node_stop()) return false;
    return aj_role_node_start(a.home, a.datadir, g_a_log, APPJ_A_P2P, APPJ_A_RPC,
                              APPJ_A_FS, APPJ_A_HTTPS, APPJ_DEAD_SINK, true) &&
        aj_wait_ready_pair(&a, NULL, " (hosting)") && aj_phase_publish(&a) &&
        aj_role_public_files(&a) && aj_role_hold(seconds);
}

static bool aj_role_host_data(const struct json_value *d, int64_t *generation)
{
    const struct json_value *h = json_get(d, "host"), *c = json_get(d, "carrier");
    const struct json_value *e = json_get(d, "enabled"), *g = json_get(d, "generation");
    bool ok = h && h->type == JSON_STR && c && c->type == JSON_STR &&
        e && e->type == JSON_BOOL && json_get_bool(e) && g && g->type == JSON_INT &&
        json_get_int(g) > 0 && !strcmp(json_get_str(h), g_host_hex) && !strcmp(json_get_str(c), g_carrier);
    if (ok) *generation = json_get_int(g);
    return ok;
}

static bool aj_role_host_status(struct aj_node_ctx *b, int64_t *generation)
{
    char host[96], carrier[96], out[8192];
    if (snprintf(host, sizeof(host), "--host=%s", g_host_hex) >= (int)sizeof(host) ||
        snprintf(carrier, sizeof(carrier), "--carrier=%s", g_carrier) >= (int)sizeof(carrier)) return false;
    char *tail[] = {(char *)"app", (char *)"host", (char *)"status", host, carrier, NULL};
    if (aj_cli(b->datadir, b->rpc, tail, out, sizeof(out), 180, b->home) != 0) return false;
    struct json_value v;
    bool ok = aj_json_ok(out, &v) && aj_role_host_data(aj_json_data(&v), generation);
    json_free(&v); return ok;
}

static bool aj_role_serve(struct aj_node_ctx *b, long seconds)
{
    int64_t generation = 0;
    if (!aj_role_hex(g_host_hex, 64) || !aj_role_hex(g_carrier, 64) ||
        !aj_role_host_status(b, &generation) || !aj_role_status_file(b)) return false;
    char path[1024], body[512];
    int n = snprintf(body, sizeof(body),
        "{\"hosting_intent_enabled\":true,\"host\":\"%s\",\"carrier\":\"%s\",\"generation\":%lld}\n",
        g_host_hex, g_carrier, (long long)generation);
    if (n < 0 || (size_t)n >= sizeof(body) || !aj_path_join(path, sizeof(path), g_work, "receiver-ready.json") ||
        !aj_write_file(path, body)) return false;
    return aj_role_hold(seconds);
}

static bool aj_role_receiver(const char *peer, bool serve, long seconds)
{
    struct aj_node_ctx b = {.rpc = APPJ_B_RPC};
    snprintf(b.home, sizeof(b.home), "%s", g_b_home);
    snprintf(b.datadir, sizeof(b.datadir), "%s", g_b_dd);
    return aj_role_node_start(b.home, b.datadir, g_b_log, APPJ_B_P2P, APPJ_B_RPC,
                              APPJ_B_FS, APPJ_B_HTTPS, peer, true) &&
        aj_wait(aj_probe_rpc, &b, g_wait_s, "receiver RPC") &&
        aj_wait(aj_probe_onion, &b, g_tor_wait_s, "receiver onion") && aj_phase_b_get(&b) &&
        (!serve || aj_role_serve(&b, seconds));
}

static bool aj_role_prepare(const struct aj_role_args *r)
{
    if (!r->sender && !aj_role_expected(r->expected)) { aj_fail("invalid public expectation"); return false; }
    if (mkdir(r->work, 0700) != 0) { aj_fail("split work directory must be fresh and creatable"); return false; }
    if (!aj_prepare(r->work)) { aj_fail("cannot prepare split work directory or runtime"); return false; }
    return r->sender || (aj_path_join(g_repo_app, sizeof(g_repo_app), g_work, "empty") && mkdir(g_repo_app, 0700) == 0);
}

static int aj_role_work(const struct aj_role_args *r)
{
    struct stat st; char token;
    struct pollfd control = {.fd = 3, .events = POLLIN};
    if (fstat(3, &st) != 0 || !S_ISFIFO(st.st_mode) || poll(&control, 1, 1000) <= 0 ||
        !(control.revents & POLLIN) || read(3, &token, 1) != 1 || token != 'R') {
        aj_fail("split worker requires its owner control descriptor"); return 2;
    }
    close(3); g_role_worker = true; g_keep = true; platform_supervised_init(&g_role_node);
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 2;
    if (!aj_role_prepare(r)) return 2;
    bool ok = r->sender ? aj_role_sender(r->seconds) : aj_role_receiver(r->peer, r->serve, r->seconds);
    bool stopped = aj_role_node_stop();
    if (!ok || !stopped) { aj_fail("split worker failed or node cleanup was incomplete"); return 2; }
    return 0;
}

#if defined(__linux__)
static volatile sig_atomic_t g_role_stop;
static void aj_role_signal(int sig) { (void)sig; g_role_stop = 1; }

static int aj_role_image_fd(int fd)
{
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > PLATFORM_SUPERVISED_IMAGE_MAX) { close(fd); return -1; }
    size_t len = (size_t)st.st_size, used = 0;
    unsigned char *bytes = zcl_malloc(len, "app_journey_role_image");
    if (!bytes) { close(fd); return -1; }
    while (used < len) {
        ssize_t n = read(fd, bytes + used, len - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
    }
    bool ok = close(fd) == 0 && used == len;
    uint8_t digest[32]; int image = -1;
    if (ok) {
        zcl_sha3_256(bytes, len, digest);
        if (platform_supervised_image_capture(bytes, len, digest, &image) != PLATFORM_SUPERVISED_IMAGE_OK) image = -1;
    }
    free(bytes); return image;
}

static int aj_role_self_image(void)
{
    FILE *self = os_proc_open_self_exe();
    if (!self) return -1;
    int fd = dup(fileno(self));
    if (fclose(self) != 0) { if (fd >= 0) close(fd); return -1; }
    return aj_role_image_fd(fd);
}

static enum platform_supervised_state aj_role_drain(struct platform_supervised_process *p)
{
    enum platform_supervised_state state = p->observation.state;
    while (p->supervisor_pid >= 0) {
        int64_t now = clock_now_monotonic_ns();
        if (now > 0 && now <= INT64_MAX - 10000000000LL)
            state = platform_supervised_stop(p, now + 10000000000LL);
        else state = platform_supervised_poll(p);
        if (p->supervisor_pid >= 0) (void)poll(NULL, 0, 100);
    }
    return state;
}

static bool aj_role_node_stop(void)
{
    if (g_role_node.supervisor_pid < 0 && g_role_node.observation.state == PLATFORM_SUPERVISED_INVALID) return true;
    enum platform_supervised_state state = platform_supervised_poll(&g_role_node);
    bool prior_exit = g_role_node.observation.engine_exit_observed;
    if (g_role_node.supervisor_pid >= 0) state = aj_role_drain(&g_role_node);
    int status = g_role_node.observation.engine_wait_status;
    bool exit_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    bool stopped = !prior_exit && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    return state == PLATFORM_SUPERVISED_CLEAN && g_role_node.supervisor_pid < 0 &&
        g_role_node.observation.engine_exit_observed && g_role_node.observation.no_children && (exit_ok || stopped);
}

static void aj_role_close_start(int image, int input, int output, const int fds[2], bool writer)
{
    if (image >= 0) close(image);
    if (input >= 0) close(input);
    if (output >= 0) close(output);
    if (fds[0] >= 0) close(fds[0]);
    if (writer && fds[1] >= 0) close(fds[1]);
}

static bool aj_role_node_start(const char *home, const char *datadir, const char *log,
                               int p2p, int rpc, int fs, int https, const char *peer, bool hosting)
{
    struct aj_node_flags f;
    if (!aj_node_flags_build(&f, home, datadir, p2p, rpc, fs, https, peer, hosting)) return false;
    int image = aj_role_self_image();
    int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int output = open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    int fds[2] = {-1, -1};
    if (image < 0 || input < 0 || output < 0 || pipe(fds) != 0) goto fail;
    char *argv[19] = {(char *)"app_journey_live", (char *)"--node-worker"};
    aj_node_argv(&f, argv + 2);
    const char *env[] = {f.home_pair, f.path_pair, NULL};
    struct platform_supervised_fd_map maps[] = {{input, 0}, {output, 1}, {output, 2}, {fds[0], 3}};
    int64_t now = clock_now_monotonic_ns();
    if (now <= 0 || now > INT64_MAX - 10000000000LL) goto fail;
    struct platform_supervised_spec spec = {.executable_fd = image, .argv = (const char *const *)argv,
        .env = env, .env_count = 2, .env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE,
        .maps = maps, .map_count = 4, .launch_deadline_ns = now + 10000000000LL, .cleanup_timeout_ms = 10000};
    enum platform_supervised_state state = platform_supervised_start(&g_role_node, &spec);
    aj_role_close_start(image, input, output, fds, false);
    bool ok = state == PLATFORM_SUPERVISED_RUNNING && write(fds[1], "R", 1) == 1;
    close(fds[1]);
    if (!ok && g_role_node.supervisor_pid >= 0) (void)aj_role_drain(&g_role_node);
    return ok;
fail:
    aj_role_close_start(image, input, output, fds, true);
    return false;
}

static int aj_role_node_worker(int argc, char **argv)
{
    char root[PATH_MAX], target[1024], token; struct stat st;
    struct pollfd control = {.fd = 3, .events = POLLIN};
    if (argc != 18 || !getcwd(root, sizeof(root)) ||
        snprintf(target, sizeof(target), "%s/build/bin/zclassic23", root) >= (int)sizeof(target) ||
        strcmp(argv[2], target) || fstat(3, &st) != 0 || !S_ISFIFO(st.st_mode) ||
        poll(&control, 1, 1000) <= 0 || !(control.revents & POLLIN) ||
        read(3, &token, 1) != 1 || token != 'R') return 2;
    close(3); execv(argv[2], &argv[2]); return 2;
}

static bool aj_role_clean(const struct platform_supervised_process *p,
                          enum platform_supervised_state state)
{
    return state == PLATFORM_SUPERVISED_CLEAN && p->supervisor_pid < 0 &&
        p->observation.no_children && p->observation.engine_exit_observed &&
        WIFEXITED(p->observation.engine_wait_status) && WEXITSTATUS(p->observation.engine_wait_status) == 0;
}

static int aj_role_monitor(struct platform_supervised_process *p, int control, int64_t start, int64_t deadline)
{
    enum platform_supervised_state state = PLATFORM_SUPERVISED_RUNNING;
    bool failure = write(control, "R", 1) != 1;
    while (!failure && !g_role_stop && p->supervisor_pid >= 0) {
        int64_t now = clock_now_monotonic_ns();
        if (now < start || now >= deadline) { aj_fail("split role deadline expired or clock failed"); failure = true; break; }
        state = platform_supervised_poll(p);
        if (p->supervisor_pid < 0) {
            now = clock_now_monotonic_ns();
            if (now < start || now >= deadline) failure = true;
            break;
        }
        if (state != PLATFORM_SUPERVISED_RUNNING) { failure = true; break; }
        (void)poll(NULL, 0, 100);
    }
    if (g_role_stop) { aj_fail("split role canceled"); failure = true; }
    close(control);
    if (p->supervisor_pid >= 0) state = aj_role_drain(p);
    if (failure || !aj_role_clean(p, state)) { aj_fail("split worker failed or supervised cleanup was incomplete"); return 2; }
    return 0;
}

static bool aj_role_handlers(struct sigaction old[3])
{
    const int sigs[] = {SIGPIPE, SIGINT, SIGTERM};
    struct sigaction action = {0}; sigemptyset(&action.sa_mask);
    for (int i = 0; i < 3; i++) {
        action.sa_handler = i == 0 ? SIG_IGN : aj_role_signal;
        if (sigaction(sigs[i], &action, &old[i]) != 0) {
            while (i-- > 0) (void)sigaction(sigs[i], &old[i], NULL);
            return false;
        }
    }
    return true;
}

static bool aj_role_handlers_restore(const struct sigaction old[3])
{
    const int sigs[] = {SIGPIPE, SIGINT, SIGTERM}; bool ok = true;
    for (int i = 0; i < 3; i++) if (sigaction(sigs[i], &old[i], NULL) != 0) ok = false;
    return ok;
}

static int aj_role_owner(int argc, char **argv, const struct aj_role_args *r)
{
    if (argc + 1 >= (int)PLATFORM_SUPERVISED_ARGV_DEFAULT_MAX) return 2;
    int64_t start = clock_now_monotonic_ns(), budget = (int64_t)r->seconds * 1000000000LL;
    if (start <= 0 || start > INT64_MAX - budget) return 2;
    int image = aj_role_self_image(), pipefd[2] = {-1, -1};
    int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (image < 0 || input < 0 || pipe(pipefd) != 0) goto fail;
    char *args[PLATFORM_SUPERVISED_ARGV_DEFAULT_MAX + 1];
    for (int i = 0; i < argc; i++) args[i] = argv[i];
    args[argc] = (char *)"--role-worker"; args[argc + 1] = NULL;
    const char *env[] = {"PATH=/usr/bin:/bin", NULL};
    struct platform_supervised_fd_map maps[] = {{input, 0}, {1, 1}, {2, 2}, {pipefd[0], 3}};
    struct platform_supervised_spec spec = {.executable_fd = image, .argv = (const char *const *)args,
        .env = env, .env_count = 1, .env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE,
        .maps = maps, .map_count = 4, .launch_deadline_ns = start + budget, .cleanup_timeout_ms = 10000};
    struct sigaction old[3]; g_role_stop = 0;
    if (!aj_role_handlers(old)) goto fail;
    struct platform_supervised_process p; platform_supervised_init(&p);
    enum platform_supervised_state state = platform_supervised_start(&p, &spec);
    aj_role_close_start(image, input, -1, pipefd, false);
    if (state != PLATFORM_SUPERVISED_RUNNING) {
        aj_fail("cannot launch supervised split worker");
        close(pipefd[1]); if (p.supervisor_pid >= 0) (void)aj_role_drain(&p);
        (void)aj_role_handlers_restore(old); return 2;
    }
    int rc = aj_role_monitor(&p, pipefd[1], start, start + budget);
    if (!aj_role_handlers_restore(old)) rc = 2;
    return rc;
fail:
    aj_role_close_start(image, input, -1, pipefd, true);
    return 2;
}
#else
static bool aj_role_node_stop(void) { return false; }
static bool aj_role_node_start(const char *home, const char *datadir, const char *log,
                               int p2p, int rpc, int fs, int https, const char *peer, bool hosting)
{ (void)home; (void)datadir; (void)log; (void)p2p; (void)rpc; (void)fs; (void)https; (void)peer; (void)hosting; return false; }
static int aj_role_node_worker(int argc, char **argv) { (void)argc; (void)argv; return 2; }
static int aj_role_owner(int argc, char **argv, const struct aj_role_args *r)
{ (void)argc; (void)argv; (void)r; aj_fail("split role supervision is unavailable on this platform"); return 2; }
#endif

static bool aj_is_role(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--sender") || !strcmp(argv[i], "--receiver") || !strcmp(argv[i], "--role-worker")) return true;
    return false;
}

static int aj_role_entry(int argc, char **argv)
{
    struct aj_role_args args;
    if (!aj_role_parse(argc, argv, &args) || !getcwd(g_repo, sizeof(g_repo))) {
            fprintf(stderr, "usage: app_journey_live --sender|--receiver --work=/fresh/path --seconds=N [--peer=onion:port --expected=/file --serve]\n"); return 3;
    }
    if (args.worker) return aj_role_work(&args);
    int rc = aj_role_owner(argc, argv, &args);
    if (rc == 0) printf("%s: PASS; evidence %s\n", args.sender ? "sender" : "receiver", args.work);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--node-worker")) return aj_role_node_worker(argc, argv);
    if (aj_is_role(argc, argv)) return aj_role_entry(argc, argv);
    const char *work_override = NULL;
    int usage = aj_parse_args(argc, argv, &work_override);
    if (usage) {
        fprintf(stderr, "usage: app-journey-live [--work=DIR] [--keep]\n");
        return usage;
    }
    g_wait_s = aj_env_long("APPJ_WAIT", g_wait_s);
    g_tor_wait_s = aj_env_long("APPJ_TOR_WAIT", g_tor_wait_s);
    g_board_wait_s = aj_env_long("APPJ_BOARD_WAIT", g_board_wait_s);

    if (!getcwd(g_repo, sizeof(g_repo)) || !aj_prepare(work_override)) {
        aj_fail("cannot prepare the work tree (are the node binaries built?)");
        return 2;
    }

    return aj_journey();
}
