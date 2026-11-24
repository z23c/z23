/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * regtest_node_fixture.h: one isolated regtest z23 node and the commands that
 * drive it, for tests that need a real node process.
 *
 * The node runs on 127.0.0.1 only (-private-listeners, -bind=127.0.0.1, no
 * Tor, a dead -connect sink), in a private 0700 directory under the runner's
 * test temporary root. It never outlives the test process: the child sets
 * PR_SET_PDEATHSIG(SIGKILL) before exec (Linux), and rnf_cleanup() stops it
 * and removes the directory on every normal return, on exit() through the
 * atexit reaper, and, for the node only, on SIGINT and SIGTERM. A fixture
 * left by a signalled run stays under the temporary root.
 *
 * The launch line and the command runner are the ones wallet_e2e_regtest
 * uses, so a test built on this header drives a node exactly as an operator
 * or a phone does: the built z23 binary, one argv per command.
 *
 * Header-only and static: include it from one test source file. */

#ifndef ZCL_TEST_REGTEST_NODE_FIXTURE_H
#define ZCL_TEST_REGTEST_NODE_FIXTURE_H

#include "test/test_core.h"
#include "json/json.h"
#include "platform/socket_compat.h"
#include "util/spawn.h"

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define RNF_BIN "build/bin/z23"
#define RNF_RAW (256 * 1024)
#define RNF_CMD_MS 900000
#define RNF_RECONCILE_MS 120000
#define RNF_MAX_WORDS 14

struct rnf {
    char work[PATH_MAX];
    char cred[PATH_MAX + 16];
    char dd_flag[PATH_MAX + 16];
    char rpc_flag[32];
    uint16_t port[2]; /* p2p, rpc */
    pid_t node;
    int tip;
    char tip_hash[80];
};

static struct rnf *rnf_live;           /* reaped by atexit if a path forgets */
static volatile pid_t rnf_node_pid;    /* read by the signal handler */
static struct sigaction rnf_old_int, rnf_old_term;
static bool rnf_signals_armed;

static inline long rnf_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;  // platform-ok:elapsed-evidence-printed-never-asserted
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static inline void rnf_sleep_ms(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static inline uint16_t rnf_reserve_port(void)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID) return 0;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    uint16_t port = 0;
    if (platform_socket_bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
        size_t len = sizeof(a);
        if (platform_socket_local_address(fd, (struct sockaddr *)&a,
                                          &len) == 0)
            port = ntohs(a.sin_port);
    }
    platform_socket_close(fd);
    return port;
}

/* ── node process ─────────────────────────────────────────────────── */

static inline void rnf_node_stop(struct rnf *e)
{
    if (e->node <= 0) return;
    kill(-e->node, SIGTERM);
    int status = 0;
    for (int i = 0; i < 600; i++) {
        if (waitpid(e->node, &status, WNOHANG) == e->node) {
            e->node = 0;
            return;
        }
        rnf_sleep_ms(100);
    }
    kill(-e->node, SIGKILL);
    (void)waitpid(e->node, &status, 0);
    e->node = 0;
}

static inline void rnf_signals_disarm(void)
{
    rnf_node_pid = 0;
    if (!rnf_signals_armed) return;
    rnf_signals_armed = false;
    sigaction(SIGINT, &rnf_old_int, NULL);
    sigaction(SIGTERM, &rnf_old_term, NULL);
}

/* Stop the node and remove the fixture; safe to call twice. */
static inline void rnf_cleanup(struct rnf *e)
{
    rnf_node_stop(e);
    rnf_signals_disarm();
    if (e->work[0]) test_rm_rf(e->work);
    e->work[0] = '\0';
}

static inline void rnf_atexit_reap(void)
{
    if (rnf_live) rnf_cleanup(rnf_live);
}

/* The last bytes of the node log, printed before a failed run's fixture is
 * removed. */
static inline void rnf_log_tail(const struct rnf *e)
{
    char path[PATH_MAX + 16], buf[2049];
    snprintf(path, sizeof(path), "%s/node.log", e->work);
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (fseek(f, -2048L, SEEK_END) != 0) rewind(f);
    size_t n = fread(buf, 1, 2048, f);
    buf[n] = '\0';
    fclose(f);
    printf("  node.log tail:\n%s\n", buf);
}

/* SIGINT or SIGTERM to the test: kill the node's process group, then take the
 * default action. Only async-signal-safe calls. */
static inline void rnf_on_signal(int sig)
{
    pid_t p = rnf_node_pid;
    if (p > 0) kill(-p, SIGKILL);
    signal(sig, SIG_DFL);
    raise(sig);
}

static inline void rnf_signals_arm(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = rnf_on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, &rnf_old_int);
    sigaction(SIGTERM, &sa, &rnf_old_term);
    rnf_signals_armed = true;
}

/* In the node child before exec: die with the test process, however it dies.
 * getppid() against the saved parent closes the race where the parent exited
 * before the request took effect. */
static inline bool rnf_child_die_with_parent(pid_t parent)
{
#ifdef __linux__
    return prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == parent;
#else
    (void)parent;
    return true;
#endif
}

/* A private fixture directory, a credentials directory and two loopback
 * ports. `tag` names the directory under the temporary root. */
static inline bool rnf_setup(struct rnf *e, const char *tag)
{
    memset(e, 0, sizeof(*e));
    if (!test_mkdtemp(e->work, sizeof(e->work), tag)) return false;
    char dd[PATH_MAX + 16];
    snprintf(dd, sizeof(dd), "%s/datadir", e->work);
    snprintf(e->cred, sizeof(e->cred), "%s/cred", e->work);
    if (mkdir(dd, 0700) != 0 || mkdir(e->cred, 0700) != 0) return false;
    for (int i = 0; i < 2; i++) e->port[i] = rnf_reserve_port();
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < i; j++)
            if (e->port[i] == 0 || e->port[i] == e->port[j]) return false;
    snprintf(e->dd_flag, sizeof(e->dd_flag), "-datadir=%s", dd);
    snprintf(e->rpc_flag, sizeof(e->rpc_flag), "-rpcport=%u", e->port[1]);
    return true;
}

static inline bool rnf_node_start(struct rnf *e)
{
    char p2p[32], log[PATH_MAX + 16];
    snprintf(p2p, sizeof(p2p), "-port=%u", e->port[0]);
    snprintf(log, sizeof(log), "%s/node.log", e->work);
    pid_t parent = getpid();
    rnf_signals_arm();
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (!rnf_child_die_with_parent(parent)) _exit(127);
        setpgid(0, 0);
        int fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        setenv("CREDENTIALS_DIRECTORY", e->cred, 1);
        execl(RNF_BIN, RNF_BIN, e->dd_flag, e->rpc_flag, "-regtest",
              "-regtestshielded", "-operator-lane=dev",
              "-private-listeners", "-bind=127.0.0.1", "-no-tor", p2p,
              "-connect=127.0.0.1:1", "-packagehost=0",
              "-wallet-no-phrase-backup", "-nobgvalidation",
              "-nolegacyimport", "-showmetrics=0", (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    e->node = pid;
    rnf_node_pid = pid;
    return true;
}

/* ── command runner ───────────────────────────────────────────────── */

/* A command that fails prints its error to stderr and nothing to stdout. Put
 * the first line there that starts "Error" or "error" (the legacy RPC client's
 * `Error: "..."`, the command client's `error=CODE detail=...`), else the
 * first stderr line, into raw. Only called when stdout was empty. */
static inline void rnf_error_line(const struct zcl_spawn_evidence *ev,
                                  char *raw, size_t cap)
{
    char tail[ZCL_SPAWN_EVIDENCE_TAIL + 1];
    memcpy(tail, ev->stderr_tail, ev->stderr_len);
    tail[ev->stderr_len] = '\0';
    const char *pick = tail;
    for (const char *line = tail; line && *line;) {
        if (strncmp(line, "Error", 5) == 0 || strncmp(line, "error", 5) == 0) {
            pick = line;
            break;
        }
        line = strchr(line, '\n');
        if (line) line++;
    }
    size_t n = strcspn(pick, "\n");
    if (n >= cap) n = cap - 1;
    memcpy(raw, pick, n);
    raw[n] = '\0';
}

/* Run one node command: `words` is the NULL-terminated list after the
 * binary, datadir and port (a command path and its arguments, or a legacy
 * RPC method and its positional parameters). Captures stdout into raw;
 * returns the exit status, -1 on spawn failure or timeout. */
static inline int rnf_exec(const struct rnf *e, const char *const *words,
                           char *raw, size_t cap)
{
    const char *argv[RNF_MAX_WORDS + 4];
    size_t n = 0;
    argv[n++] = RNF_BIN;
    argv[n++] = e->dd_flag;
    argv[n++] = e->rpc_flag;
    for (size_t i = 0; words[i] && n < RNF_MAX_WORDS + 3; i++)
        argv[n++] = words[i];
    argv[n] = NULL;
    struct zcl_spawn_evidence ev;
    memset(&ev, 0, sizeof(ev));
    int rc = zcl_spawn_capture_evidence(argv, raw, cap, RNF_CMD_MS, &ev);
    if (rc < 0 || ev.timed_out) return -1;
    if (raw[0] == '\0' && ev.stderr_len > 0)
        rnf_error_line(&ev, raw, cap);
    return rc;
}

/* Like rnf_exec with `input` on the command's stdin: the way a passphrase
 * reaches `core wallet security unlock|encrypt` (never argv). Waits at most
 * RNF_STDIN_MS for the command; returns its exit status, -1 on failure. */
#define RNF_STDIN_MS 120000
static inline int rnf_exec_stdin(const struct rnf *e, const char *const *words,
                                 const char *input, char *raw, size_t cap)
{
    const char *argv[RNF_MAX_WORDS + 4];
    size_t n = 0;
    argv[n++] = RNF_BIN;
    argv[n++] = e->dd_flag;
    argv[n++] = e->rpc_flag;
    for (size_t i = 0; words[i] && n < RNF_MAX_WORDS + 3; i++)
        argv[n++] = words[i];
    argv[n] = NULL;
    int in[2], out[2];
    if (pipe(in) != 0) return -1;
    if (pipe(out) != 0) {
        close(in[0]);
        close(in[1]);
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        dup2(in[0], STDIN_FILENO);
        dup2(out[1], STDOUT_FILENO);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) dup2(dn, STDERR_FILENO);
        close(in[0]); close(in[1]); close(out[0]); close(out[1]);
        execv(RNF_BIN, (char *const *)argv);
        _exit(127);
    }
    close(in[0]);
    close(out[1]);
    size_t len = strlen(input);
    bool wrote = write(in[1], input, len) == (ssize_t)len;
    close(in[1]);
    size_t got = 0;
    long deadline = rnf_now_ms() + RNF_STDIN_MS;
    while (wrote && got + 1 < cap && rnf_now_ms() < deadline) {
        ssize_t r = read(out[0], raw + got, cap - 1 - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    raw[got] = '\0';
    close(out[0]);
    int status = 0;
    if (rnf_now_ms() >= deadline) kill(pid, SIGKILL);
    if (waitpid(pid, &status, 0) != pid) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Poll until the node answers `core chain tip`; false if it exits or stays
 * silent. */
static inline bool rnf_wait_up(struct rnf *e)
{
    static char raw[RNF_RAW];
    const char *const words[] = { "core", "chain", "tip", NULL };
    for (int i = 0; i < 240; i++) {
        int st = 0;
        if (waitpid(e->node, &st, WNOHANG) == e->node) {
            e->node = 0;
            return false;
        }
        if (rnf_exec(e, words, raw, sizeof(raw)) == 0 &&
            strstr(raw, "\"ok\":true") != NULL)
            return true;
        rnf_sleep_ms(500);
    }
    return false;
}

/* Parse the first JSON document in raw. */
static inline bool rnf_parse(const char *raw, struct json_value *out)
{
    json_init(out);
    const char *start = raw;
    while (*start && *start != '{' && *start != '[') start++;
    return *start && json_read(out, start, strlen(start));
}

/* Dotted-path accessor over a parsed document: "data.txid". */
static inline const struct json_value *rnf_at(const struct json_value *v,
                                              const char *path)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", path);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ".", &save); tok && v;
         tok = strtok_r(NULL, ".", &save))
        v = json_get(v, tok);
    return v;
}

static inline const char *rnf_str(const struct json_value *v, const char *path)
{
    const char *s = json_get_str(rnf_at(v, path));
    return s ? s : "";
}

/* Decimal ZCL text "0.00400000" (optionally with a trailing newline) -> zats;
 * -1 when malformed. */
static inline int64_t rnf_zats(const char *s)
{
    int64_t whole = 0, frac = 0;
    int digits = 0;
    if (!*s || *s < '0' || *s > '9') return -1;
    for (; *s >= '0' && *s <= '9'; s++) whole = whole * 10 + (*s - '0');
    if (*s == '.')
        for (s++; *s >= '0' && *s <= '9' && digits < 8; s++, digits++)
            frac = frac * 10 + (*s - '0');
    if (*s && *s != '\n') return -1;
    while (digits++ < 8) frac *= 10;
    return whole * 100000000LL + frac;
}

/* ── chain ────────────────────────────────────────────────────────── */

static inline bool rnf_chain_now(const struct rnf *e, int *height, char *hash,
                                 size_t cap)
{
    static char raw[RNF_RAW];
    const char *const words[] = { "getblockchaininfo", NULL };
    struct json_value r;
    bool ok = rnf_exec(e, words, raw, sizeof(raw)) == 0 && rnf_parse(raw, &r);
    if (ok) {
        *height = (int)json_get_int(json_get(&r, "blocks"));
        snprintf(hash, cap, "%s", rnf_str(&r, "bestblockhash"));
        json_free(&r);
    }
    return ok;
}

/* A mining call whose reply was lost has an unknown outcome. Inspect the
 * chain and never retry: poll until the height reaches exactly the
 * requested blocks; fail if it passes them or the deadline expires. */
static inline bool rnf_mine_reconcile(struct rnf *e, int blocks)
{
    int want = e->tip + blocks, height = -1;
    char hash[80] = "";
    long deadline = rnf_now_ms() + RNF_RECONCILE_MS;
    while (rnf_now_ms() < deadline) {
        if (!rnf_chain_now(e, &height, hash, sizeof(hash)) || height > want)
            return false;
        if (height == want) {
            e->tip = height;
            snprintf(e->tip_hash, sizeof(e->tip_hash), "%s", hash);
            return true;
        }
        rnf_sleep_ms(500);
    }
    return false;
}

/* Mine `blocks` (1..101) to a transparent regtest `address`. */
static inline bool rnf_mine_to(struct rnf *e, const char *address, int blocks)
{
    static char raw[RNF_RAW];
    char input[512];
    snprintf(input, sizeof(input),
             "--input={\"address\":\"%s\",\"blocks\":%d,\"confirm\":true}",
             address, blocks);
    const char *const words[] = { "core", "mining", "regtest-mine", input,
                                  NULL };
    struct json_value r;
    bool ok = rnf_exec(e, words, raw, sizeof(raw)) == 0 && rnf_parse(raw, &r);
    if (ok) {
        const struct json_value *h = rnf_at(&r, "data.block_hashes");
        ok = json_get_bool(json_get(&r, "ok")) && h &&
             h->num_children == (size_t)blocks;
        if (ok) {
            snprintf(e->tip_hash, sizeof(e->tip_hash), "%s",
                     json_get_str(&h->children[h->num_children - 1]));
            e->tip += blocks;
        }
        json_free(&r);
    }
    return ok || rnf_mine_reconcile(e, blocks);
}

#endif /* ZCL_TEST_REGTEST_NODE_FIXTURE_H */
