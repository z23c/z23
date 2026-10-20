/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Live acceptance for the terminal hub (session/mesh_terminal_hub.h): a
 * confined fbsh served over one byte stream, admitted by the keyed hello.
 * The wire and key-file cases are pure. The session cases fork a real server
 * on a socket pair or a loopback listener and drive it with hand-built frames
 * or with the production client loop, so exit status, resize, close, limits,
 * wrong-key refusal, the session cap, the audit line and the keystroke round
 * trip are all observed on the real worker. Marker discipline as in
 * test_mesh_terminal_worker: command markers are quote-split so the pty echo
 * of the typed line can never satisfy the match. The device-host hop is
 * covered by the group that owns it (device_host_runtime); this group runs
 * the hub without it and reports the round trip it measured.
 *
 * fbsh cases FAIL when build/bin/fbsh is absent: a hub group that cannot run
 * its shell has proven nothing, and the proof builds fbsh. */

#define _GNU_SOURCE

#include "test/test_core.h"
#include "session/mesh_terminal_hub.h"
#include "session/mesh_terminal_worker.h"
#include "command/native_command.h"
#include "command/native_mesh_terminal_hub.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32) /* the POSIX portable-helper cases: no fcntl/sockets/pipes on Windows */
#include "session/mesh_terminal_hub_portable.h"
#include "../../../cognition/modules/session/src/mesh_terminal_hub_io.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── portable descriptor helpers and the confinement refusal ──────────────
 * Run on every host: the helpers are what keeps accepted sockets, pipes and
 * socket pairs close-on-exec (and the signal pipe non-blocking) where there
 * is no accept4/pipe2/SOCK_CLOEXEC, and what makes a dead peer an EPIPE and
 * not a SIGPIPE where there is no MSG_NOSIGNAL. */

static int pcheck(int failures, bool ok, const char *label)
{
    printf("  %s... %s\n", label, ok ? "OK" : "FAIL");
    return failures + (ok ? 0 : 1);
}

static bool p_cloexec(int fd)
{
    int f = fcntl(fd, F_GETFD);
    return f >= 0 && (f & FD_CLOEXEC);
}

static bool p_nonblock(int fd)
{
    int f = fcntl(fd, F_GETFL);
    return f >= 0 && (f & O_NONBLOCK);
}

static volatile sig_atomic_t g_sigpipes;

static void p_on_sigpipe(int sig)
{
    (void)sig;
    g_sigpipes++;
}

static int portable_flag_cases(void)
{
    int failures = 0, p[2] = { -1, -1 }, sv[2] = { -1, -1 };
    failures = pcheck(failures, hub_pipe_cloexec_nonblock(p) == 0 && p_cloexec(p[0]) && p_cloexec(p[1]) &&
                      p_nonblock(p[0]) && p_nonblock(p[1]),
                      "portable: a hub pipe has both ends close-on-exec and non-blocking");
    if (p[0] >= 0) { close(p[0]); close(p[1]); }
    failures = pcheck(failures, hub_socketpair_cloexec(sv) == 0 && p_cloexec(sv[0]) && p_cloexec(sv[1]),
                      "portable: a hub socket pair is close-on-exec on both ends");
    if (sv[0] >= 0) { close(sv[0]); close(sv[1]); }
    int tcp = hub_tcp_socket_cloexec();
    failures = pcheck(failures, tcp >= 0 && p_cloexec(tcp), "portable: a hub TCP socket is close-on-exec");
    if (tcp >= 0) close(tcp);
#if defined(__linux__)
    int pfd = hub_pidfd_open(getpid());
    failures = pcheck(failures, pfd >= 0 || errno == ENOSYS || errno == EPERM,
                      "portable: pidfd helper answers with a pidfd or a plain kernel refusal");
    if (pfd >= 0)
        close(pfd);
#else
    failures = pcheck(failures, hub_pidfd_open(getpid()) == -1,
                      "portable: no pidfd off Linux; callers use their bounded-poll fallback");
#endif
    return failures;
}

/* A dead peer is EPIPE, never SIGPIPE: MSG_NOSIGNAL on Linux, the
 * per-socket option elsewhere. */
static bool dead_peer_is_epipe(int acc, int peer)
{
    struct sigaction act = { .sa_handler = p_on_sigpipe }, old;
    uint8_t frame[8] = { 0 };
    bool epipe = false;
    sigemptyset(&act.sa_mask);
    sigaction(SIGPIPE, &act, &old);
    g_sigpipes = 0;
    hub_socket_nosigpipe(acc); /* while connected: Darwin refuses the option on a dead socket */
    close(peer);
    for (int i = 0; i < 4 && !epipe; i++) /* a unix peer closed: EPIPE at once */
        epipe = !hub_io_send(acc, frame, sizeof frame);
    sigaction(SIGPIPE, &old, NULL);
    return epipe && g_sigpipes == 0;
}

static int portable_accept_cases(void)
{
    int failures = 0;
    uint16_t port = 0;
    int ls = mesh_terminal_hub_listen(0, &port);
    int cl = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bool linked = ls >= 0 && cl >= 0 && connect(cl, (struct sockaddr *)&a, sizeof a) == 0;
    int acc = linked ? hub_accept_cloexec(ls) : -1;
    failures = pcheck(failures, acc >= 0 && p_cloexec(acc) && !p_nonblock(acc),
                      "portable: an accepted hub socket is close-on-exec and keeps the listener's blocking mode");
    failures = pcheck(failures, ls >= 0 && p_cloexec(ls), "portable: the hub listener is close-on-exec");
    if (cl >= 0)
        close(cl);
    int sv[2] = { -1, -1 };
    bool paired = hub_socketpair_cloexec(sv) == 0;
    failures = pcheck(failures, paired && dead_peer_is_epipe(sv[0], sv[1]),
                      "portable: sending to a dead peer fails without raising SIGPIPE");
    if (paired)
        close(sv[0]);
    if (acc >= 0)
        close(acc);
    if (ls >= 0)
        close(ls);
    return failures;
}

#if !defined(__linux__)
static bool p_frame(int fd, uint8_t *type, uint8_t *payload, size_t *len)
{
    uint8_t head[3];
    size_t got = 0;
    while (got < 3) {
        ssize_t r = read(fd, head + got, 3 - got);
        if (r <= 0)
            return false;
        got += (size_t)r;
    }
    if (!mesh_terminal_hub_frame_header(head, 3, type, len))
        return false;
    for (got = 0; got < *len;) {
        ssize_t r = read(fd, payload + got, *len - got);
        if (r <= 0)
            return false;
        got += (size_t)r;
    }
    return true;
}

static void p_serve_cfg(struct mesh_terminal_hub_serve_cfg *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    for (int i = 0; i < 32; i++)
        cfg->key[i] = (uint8_t)(3 + i * 5);
    cfg->shell_path = "/bin/sh";
    static char workdir[256];
    if (!workdir[0])
        (void)test_mkdtemp(workdir, sizeof workdir, "hub_serve_cfg");
    cfg->workdir = workdir;
    cfg->max_bytes_in = cfg->max_bytes_out = 1u << 16;
    cfg->lifetime_seconds = 10;
    cfg->idle_seconds = 5;
    cfg->stop_fd = -1;
}

/* CHALLENGE, a correct HELLO, then the terminating frame: true when it is a
 * one-byte REFUSE whose code lands in *code. */
static bool p_hello_refused(int fd, const uint8_t key[32], int *code)
{
    uint8_t type = 0, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], frame[MESH_TERMINAL_HUB_FRAME_MAX];
    size_t len = 0;
    struct mesh_terminal_hub_request rq = { .cols = 80, .rows = 24, .name = "refuse" };
    if (!p_frame(fd, &type, payload, &len) || type != MESH_TERMINAL_HUB_CHALLENGE || len != 33)
        return false;
    size_t n = mesh_terminal_hub_hello_build(frame + 3, key, payload + 1, &rq);
    size_t total = n ? mesh_terminal_hub_frame_seal(frame, MESH_TERMINAL_HUB_HELLO, n) : 0;
    if (!total || write(fd, frame, total) != (ssize_t)total)
        return false;
    if (!p_frame(fd, &type, payload, &len) || type != MESH_TERMINAL_HUB_REFUSE || len != 1)
        return false;
    *code = payload[0];
    return true;
}

/* No cage on this host: a correct hello is still answered with the typed
 * confinement refusal, the session is not admitted, and no shell runs. */
static int portable_refusal_case(void)
{
    int failures = 0, sv[2], rp[2], code = 0;
    struct mesh_terminal_hub_serve_cfg cfg;
    p_serve_cfg(&cfg);
    if (hub_socketpair_cloexec(sv) != 0 || hub_pipe_cloexec_nonblock(rp) != 0)
        return pcheck(failures, false, "portable: refusal fixture sockets");
    pid_t pid = fork();
    if (pid == 0) {
        struct mesh_terminal_hub_report r;
        close(sv[0]);
        mesh_terminal_hub_serve_fd(sv[1], &cfg, &r);
        ssize_t w = write(rp[1], &r, sizeof r);
        _exit(w == (ssize_t)sizeof r ? 0 : 1);
    }
    close(sv[1]);
    close(rp[1]);
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    bool refused = p_hello_refused(sv[0], cfg.key, &code);
    struct mesh_terminal_hub_report r;
    memset(&r, 0, sizeof r);
    int status = 0;
    close(sv[0]);
    /* the report pipe is non-blocking: wait for the child before reading it */
    bool reaped = waitpid(pid, &status, 0) == pid && WIFEXITED(status);
    bool rep = read(rp[0], &r, sizeof r) == (ssize_t)sizeof r;
    close(rp[0]);
    failures = pcheck(failures, refused && code == MESH_TERMINAL_HUB_REFUSE_CONFINEMENT,
                      "portable: serve on a host without a cage sends the typed confinement refusal");
    failures = pcheck(failures, rep && reaped && !r.admitted && r.refusal == MESH_TERMINAL_HUB_REFUSE_CONFINEMENT &&
                      r.bytes_out == 0, "portable: the session is not admitted and the report names confinement");
    return failures;
}
#endif

int test_mesh_terminal_hub_fifo_bounds(void);

static int portable_cases(void)
{
    int failures = portable_flag_cases() + portable_accept_cases() + test_mesh_terminal_hub_fifo_bounds();
#if defined(__linux__)
    failures = pcheck(failures, hub_confinement_supported(),
                      "portable: Linux has the Landlock+seccomp cage, so serve is allowed to start a shell");
#else
    failures = pcheck(failures, !hub_confinement_supported(),
                      "portable: this host has no cage, so serve must refuse every session");
    failures += portable_refusal_case();
#endif
    return failures;
}

#endif /* !_WIN32 */

#if defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FBSH_BIN "build/bin/fbsh"

int test_mesh_terminal_hub_bounds(const char *fbsh, const char *dir);

static char g_dir[160];
static char g_fbsh[600];

static int check(int failures, bool ok, const char *label)
{
    printf("  %s... %s\n", label, ok ? "OK" : "FAIL");
    return failures + (ok ? 0 : 1);
}

static int64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static void test_key(uint8_t key[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)(seed + i * 7);
}

static void serve_cfg(struct mesh_terminal_hub_serve_cfg *cfg, uint8_t seed)
{
    memset(cfg, 0, sizeof(*cfg));
    test_key(cfg->key, seed);
    cfg->shell_path = g_fbsh;
    cfg->workdir = g_dir;
    cfg->max_bytes_in = 1u << 20;
    cfg->max_bytes_out = 1u << 24;
    cfg->lifetime_seconds = 60;
    cfg->idle_seconds = 30;
    cfg->stop_fd = -1;
}

static size_t hello_make(uint8_t *payload, const uint8_t key[32], const uint8_t nonce[32],
                         uint16_t cols, uint16_t rows, const char *name)
{
    struct mesh_terminal_hub_request rq = { .cols = cols, .rows = rows, .name = name };
    return mesh_terminal_hub_hello_build(payload, key, nonce, &rq);
}

/* ── wire and key file (pure) ─────────────────────────────────────────── */

static int wire_cases(void)
{
    int failures = 0;
    uint8_t frame[MESH_TERMINAL_HUB_FRAME_MAX], type = 0;
    size_t len = 0;
    failures = check(failures, mesh_terminal_hub_frame_seal(frame, MESH_TERMINAL_HUB_DATA, 5) == 8 &&
                     mesh_terminal_hub_frame_header(frame, 8, &type, &len) &&
                     type == MESH_TERMINAL_HUB_DATA && len == 5, "frame header round trip, 3-byte header");
    failures = check(failures, mesh_terminal_hub_frame_seal(frame, MESH_TERMINAL_HUB_DATA, 3073) == 0,
                     "oversize payload refused at seal");
    frame[0] = MESH_TERMINAL_HUB_DATA; frame[1] = 0x0c; frame[2] = 0x01; /* 3073 */
    failures = check(failures, !mesh_terminal_hub_frame_header(frame, 3, &type, &len),
                     "oversize length refused at decode");
    frame[0] = 0x77; frame[1] = frame[2] = 0;
    failures = check(failures, !mesh_terminal_hub_frame_header(frame, 3, &type, &len),
                     "unknown frame type refused");
    failures = check(failures, !mesh_terminal_hub_frame_header(frame, 2, &type, &len),
                     "short header refused");

    uint8_t key[32], other[32], nonce[32], hello[200];
    struct mesh_terminal_hub_hello h;
    test_key(key, 1); test_key(other, 2);
    memset(nonce, 0x5a, sizeof nonce);
    size_t n = hello_make(hello, key, nonce, 100, 30, "lead.one");
    failures = check(failures, mesh_terminal_hub_hello_verify(&h, hello, n, key, nonce) == MESH_TERMINAL_HUB_HELLO_OK &&
                     h.cols == 100 && h.rows == 30 && !strcmp(h.name, "lead.one"), "hello verifies");
    failures = check(failures, mesh_terminal_hub_hello_verify(&h, hello, n, other, nonce) == MESH_TERMINAL_HUB_HELLO_MAC,
                     "wrong key -> mac");
    uint8_t nonce2[32];
    memcpy(nonce2, nonce, 32); nonce2[0] ^= 1;
    failures = check(failures, mesh_terminal_hub_hello_verify(&h, hello, n, key, nonce2) == MESH_TERMINAL_HUB_HELLO_MAC,
                     "replay against another nonce -> mac");
    for (size_t at = 0; at < n; at++) {
        uint8_t copy[200];
        memcpy(copy, hello, n);
        copy[at] ^= 0x01;
        enum mesh_terminal_hub_hello_status s = mesh_terminal_hub_hello_verify(&h, copy, n, key, nonce);
        if (s == MESH_TERMINAL_HUB_HELLO_OK) {
            failures = check(failures, false, "any single flipped hello bit is refused");
            break;
        }
        if (at == n - 1)
            failures = check(failures, true, "any single flipped hello bit is refused");
    }
    failures = check(failures, mesh_terminal_hub_hello_verify(&h, hello, n - 1, key, nonce) == MESH_TERMINAL_HUB_HELLO_MALFORMED,
                     "truncated hello malformed");
    n = hello_make(hello, key, nonce, 0, 24, "x");
    failures = check(failures, mesh_terminal_hub_hello_verify(&h, hello, n, key, nonce) == MESH_TERMINAL_HUB_HELLO_GEOMETRY,
                     "zero columns with a valid mac -> geometry");
    n = hello_make(hello, key, nonce, 80, 24, "a b/c\n; rm -rf");
    failures = check(failures, mesh_terminal_hub_hello_verify(&h, hello, n, key, nonce) == MESH_TERMINAL_HUB_HELLO_OK &&
                     !strpbrk(h.name, " /\n;") && strlen(h.name) <= MESH_TERMINAL_HUB_NAME_MAX,
                     "name sanitised to a log-safe token");
    return failures;
}

static void file_put(const char *path, const void *bytes, size_t n, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd >= 0) {
        ssize_t w = write(fd, bytes, n);
        (void)w;
        fchmod(fd, mode);
        close(fd);
    }
}

static int key_cases(void)
{
    int failures = 0;
    char path[300], fp[32], fp2[32], why[96];
    uint8_t key[32], zero[32] = { 0 };
    snprintf(path, sizeof path, "%s/hub.key", g_dir);
    unlink(path);
    failures = check(failures, mesh_terminal_hub_key_init(path, fp, why, sizeof why) && strlen(fp) == 16,
                     "init-key creates the key and returns a 16-hex fingerprint");
    struct stat st;
    failures = check(failures, stat(path, &st) == 0 && (st.st_mode & 07777) == 0600 && st.st_size == 32,
                     "key file is 0600 and 32 bytes");
    failures = check(failures, mesh_terminal_hub_key_load(path, key, why, sizeof why) &&
                     memcmp(key, zero, 32) != 0, "load accepts it");
    mesh_terminal_hub_key_fingerprint(key, fp2);
    failures = check(failures, !strcmp(fp, fp2), "fingerprint matches the stored key");
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", key[i]);
    failures = check(failures, !strstr(fp, hex) && strlen(fp) < 32, "fingerprint is a short prefix, never the key");
    uint8_t before[32];
    memcpy(before, key, 32);
    failures = check(failures, !mesh_terminal_hub_key_init(path, fp2, why, sizeof why) && strstr(why, "exists"),
                     "init-key never overwrites");
    failures = check(failures, mesh_terminal_hub_key_load(path, key, why, sizeof why) && !memcmp(key, before, 32),
                     "the key survives a refused overwrite");
    chmod(path, 0644);
    failures = check(failures, !mesh_terminal_hub_key_load(path, key, why, sizeof why) && strstr(why, "0600"),
                     "mode 0644 refused");
    chmod(path, 0640);
    failures = check(failures, !mesh_terminal_hub_key_load(path, key, why, sizeof why), "mode 0640 refused");
    chmod(path, 0400);
    failures = check(failures, !mesh_terminal_hub_key_load(path, key, why, sizeof why), "mode 0400 refused (exactly 0600)");
    chmod(path, 0600);
    char short_path[300];
    snprintf(short_path, sizeof short_path, "%s/short.key", g_dir);
    file_put(short_path, "tooshort", 8, 0600);
    failures = check(failures, !mesh_terminal_hub_key_load(short_path, key, why, sizeof why) && strstr(why, "32"),
                     "wrong-size key file refused");
    char link_path[300];
    snprintf(link_path, sizeof link_path, "%s/link.key", g_dir);
    unlink(link_path);
    failures = check(failures, symlink(path, link_path) == 0 &&
                     !mesh_terminal_hub_key_load(link_path, key, why, sizeof why), "symlinked key file refused");
    failures = check(failures, !mesh_terminal_hub_key_load(g_dir, key, why, sizeof why), "a directory is refused");
    failures = check(failures, !mesh_terminal_hub_key_load("/nonexistent/hub.key", key, why, sizeof why), "missing file refused");
    return failures;
}

/* ── a real server on a socket pair ───────────────────────────────────── */

struct srv {
    pid_t pid;
    int fd, report_fd;
};

static bool srv_start(struct srv *s, const struct mesh_terminal_hub_serve_cfg *cfg)
{
    int sv[2], rp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0 || pipe2(rp, O_CLOEXEC) != 0)
        return false;
    s->pid = fork();
    if (s->pid == 0) {
        struct mesh_terminal_hub_report r;
        close(sv[0]);
        mesh_terminal_hub_serve_fd(sv[1], cfg, &r);
        ssize_t w = write(rp[1], &r, sizeof r);
        _exit(w == (ssize_t)sizeof r ? 0 : 1);
    }
    close(sv[1]);
    close(rp[1]);
    s->fd = sv[0];
    s->report_fd = rp[0];
    return s->pid > 0;
}

static bool srv_finish(struct srv *s, struct mesh_terminal_hub_report *r)
{
    ssize_t n = read(s->report_fd, r, sizeof *r);
    int status = 0;
    close(s->fd);
    close(s->report_fd);
    return waitpid(s->pid, &status, 0) == s->pid && n == (ssize_t)sizeof *r && WIFEXITED(status);
}

static bool drv_send(int fd, uint8_t type, const void *payload, size_t len)
{
    uint8_t f[MESH_TERMINAL_HUB_FRAME_MAX];
    if (len)
        memcpy(f + 3, payload, len);
    size_t total = mesh_terminal_hub_frame_seal(f, type, len);
    return total && send(fd, f, total, MSG_NOSIGNAL) == (ssize_t)total;
}

/* Reads one frame within timeout_ms. false on timeout or a closed stream. */
static bool drv_frame(int fd, uint8_t *type, uint8_t *payload, size_t *len, int timeout_ms)
{
    uint8_t head[3];
    size_t have = 0, want = 3;
    int64_t deadline = now_us() + (int64_t)timeout_ms * 1000;
    uint8_t buf[MESH_TERMINAL_HUB_FRAME_MAX];
    while (have < want) {
        int64_t left = (deadline - now_us()) / 1000;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (left < 0 || poll(&p, 1, (int)left) <= 0)
            return false;
        ssize_t r = read(fd, buf + have, want - have);
        if (r <= 0)
            return false;
        have += (size_t)r;
        if (have == 3 && want == 3) {
            memcpy(head, buf, 3);
            if (!mesh_terminal_hub_frame_header(head, 3, type, len))
                return false;
            want = 3 + *len;
        }
    }
    memcpy(payload, buf + 3, *len);
    return true;
}

/* CHALLENGE, HELLO with `key`, then READY/REFUSE. Returns the terminating
 * frame type (READY, REFUSE) and, for REFUSE, the code in *refusal. */
static int drv_handshake_rq(int fd, const uint8_t key[32], struct mesh_terminal_hub_request *rq, int *refusal)
{
    uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], hello[MESH_TERMINAL_HUB_PAYLOAD_MAX];
    size_t len;
    if (!drv_frame(fd, &type, payload, &len, 3000) || type != MESH_TERMINAL_HUB_CHALLENGE || len != 33)
        return -1;
    size_t n = mesh_terminal_hub_hello_build(hello, key, payload + 1, rq);
    if (!n || !drv_send(fd, MESH_TERMINAL_HUB_HELLO, hello, n))
        return -2;
    if (!drv_frame(fd, &type, payload, &len, 3000))
        return -3;
    if (type == MESH_TERMINAL_HUB_REFUSE && len == 1 && refusal)
        *refusal = payload[0];
    return type;
}

static int drv_handshake(int fd, const uint8_t key[32], const char *name, uint16_t cols,
                         uint16_t rows, int *refusal)
{
    uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], hello[200];
    size_t len;
    if (!drv_frame(fd, &type, payload, &len, 3000) || type != MESH_TERMINAL_HUB_CHALLENGE || len != 33)
        return -1;
    size_t n = hello_make(hello, key, payload + 1, cols, rows, name);
    if (!drv_send(fd, MESH_TERMINAL_HUB_HELLO, hello, n))
        return -2;
    if (!drv_frame(fd, &type, payload, &len, 3000))
        return -3;
    if (type == MESH_TERMINAL_HUB_REFUSE && len == 1 && refusal)
        *refusal = payload[0];
    return type;
}

struct exit_info {
    bool seen;
    uint8_t reason, flags, code, sig;
};

/* Collects DATA until `needle` shows up (if given) or EXIT arrives. */
static bool drv_until(int fd, const char *needle, struct exit_info *ex, int timeout_ms, char *seen, size_t cap)
{
    size_t fill = 0;
    int64_t deadline = now_us() + (int64_t)timeout_ms * 1000;
    memset(ex, 0, sizeof *ex);
    if (seen && cap)
        seen[0] = '\0';
    for (;;) {
        uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX];
        size_t len;
        int left = (int)((deadline - now_us()) / 1000);
        if (left <= 0 || !drv_frame(fd, &type, payload, &len, left))
            return false;
        if (type == MESH_TERMINAL_HUB_EXIT && len == 4) {
            ex->seen = true; ex->reason = payload[0]; ex->flags = payload[1];
            ex->code = payload[2]; ex->sig = payload[3];
            return needle == NULL;
        }
        if (type != MESH_TERMINAL_HUB_DATA || !seen)
            continue;
        for (size_t i = 0; i < len && fill + 1 < cap; i++)
            seen[fill++] = (char)payload[i];
        seen[fill] = '\0';
        if (needle && strstr(seen, needle))
            return true;
    }
}

static void say(int fd, const char *line)
{
    drv_send(fd, MESH_TERMINAL_HUB_DATA, line, strlen(line));
}

static bool exit_is(const struct exit_info *ex, bool has_code, int code, int sig)
{
    if (!ex->seen || ex->reason != MESH_TERMINAL_CLOSE_WORKER_EXITED)
        return false;
    if (has_code)
        return (ex->flags & MESH_TERMINAL_HUB_EXIT_HAS_CODE) && ex->code == code;
    return !(ex->flags & MESH_TERMINAL_HUB_EXIT_HAS_CODE) &&
           (ex->flags & MESH_TERMINAL_HUB_EXIT_HAS_SIGNAL) && ex->sig == sig;
}

struct status_case { const char *line; bool has_code; int code; int sig; const char *label; };

static int status_one(const struct status_case *c)
{
    int failures = 0;
    struct mesh_terminal_hub_serve_cfg cfg;
    struct srv s;
    struct mesh_terminal_hub_report r;
    struct exit_info ex;
    char seen[4096];
    serve_cfg(&cfg, 3);
    bool up = srv_start(&s, &cfg);
    int hs = up ? drv_handshake(s.fd, cfg.key, "tester", 80, 24, NULL) : -9;
    say(s.fd, c->line);
    bool got = hs == MESH_TERMINAL_HUB_READY && drv_until(s.fd, NULL, &ex, 8000, seen, sizeof seen);
    bool fin = up && srv_finish(&s, &r);
    failures = check(failures, got && exit_is(&ex, c->has_code, c->code, c->sig), c->label);
    return check(failures, fin && r.admitted && r.reason == MESH_TERMINAL_CLOSE_WORKER_EXITED &&
                 !strcmp(r.name, "tester") && r.bytes_in == strlen(c->line),
                 "report: admitted, worker-exited, name, bytes_in");
}

static int status_cases(void)
{
    static const struct status_case cases[] = {
        { "exit 7\n", true, 7, 0, "exit 7 -> EXIT code 7" },
        { "exit 0\n", true, 0, 0, "exit 0 -> EXIT code 0" },
        { "kill -KILL $$\n", false, 0, 9, "SIGKILL death -> EXIT signal 9, no code" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        failures += status_one(&cases[i]);
    return failures;
}

static int echo_and_resize_cases(void)
{
    int failures = 0;
    struct mesh_terminal_hub_serve_cfg cfg;
    struct srv s;
    struct mesh_terminal_hub_report r;
    struct exit_info ex;
    char seen[4096];
    serve_cfg(&cfg, 4);
    bool up = srv_start(&s, &cfg);
    int hs = up ? drv_handshake(s.fd, cfg.key, "echo", 80, 24, NULL) : -9;
    failures = check(failures, hs == MESH_TERMINAL_HUB_READY, "admitted with the right key");
    say(s.fd, "echo Z23HU\"B\"_OK\n");
    failures = check(failures, drv_until(s.fd, "Z23HUB_OK", &ex, 8000, seen, sizeof seen),
                     "command output comes back through DATA frames");
    /* The kernel raises SIGWINCH on the shell's group when the size changes. */
    say(s.fd, "trap 'echo WIN\"CH\"_SEEN' WINCH\n");
    /* The echoed "trap ..." line comes back before the shell has run it, so
     * wait for output the shell prints only after the trap is installed. */
    say(s.fd, "echo TRAP\"_\"ARMED\n");
    failures = check(failures, drv_until(s.fd, "TRAP_ARMED", &ex, 8000, seen, sizeof seen),
                     "the WINCH trap is installed before RESIZE is sent");
    uint8_t dim[4] = { 0, 120, 0, 40 };
    drv_send(s.fd, MESH_TERMINAL_HUB_RESIZE, dim, 4);
    say(s.fd, "echo\n");
    failures = check(failures, drv_until(s.fd, "WINCH_SEEN", &ex, 8000, seen, sizeof seen),
                     "RESIZE reaches the pty (shell saw SIGWINCH)");
    uint8_t reason = MESH_TERMINAL_CLOSE_REQUESTED;
    drv_send(s.fd, MESH_TERMINAL_HUB_CLOSE, &reason, 1);
    failures = check(failures, drv_until(s.fd, NULL, &ex, 8000, seen, sizeof seen) &&
                     ex.reason == MESH_TERMINAL_CLOSE_REQUESTED && !(ex.flags & 3),
                     "CLOSE -> EXIT requested, no status claimed");
    failures = check(failures, srv_finish(&s, &r) && r.reason == MESH_TERMINAL_CLOSE_REQUESTED && r.exit_code == -1,
                     "server returns after CLOSE; report says requested");
    return failures;
}

static int refuse_wrong_key(void)
{
    int failures = 0, refusal = 0;
    struct mesh_terminal_hub_serve_cfg cfg;
    struct srv s;
    struct mesh_terminal_hub_report r;
    uint8_t wrong[32];
    serve_cfg(&cfg, 5);
    test_key(wrong, 6);
    bool up = srv_start(&s, &cfg);
    int hs = up ? drv_handshake(s.fd, wrong, "intruder", 80, 24, &refusal) : -9;
    bool fin = srv_finish(&s, &r);
    failures = check(failures, hs == MESH_TERMINAL_HUB_REFUSE && refusal == MESH_TERMINAL_HUB_REFUSE_AUTH,
                     "wrong key -> REFUSE auth");
    return check(failures, fin && !r.admitted && r.refusal == MESH_TERMINAL_HUB_REFUSE_AUTH &&
                 r.bytes_in == 0 && r.bytes_out == 0 && r.name[0] == '\0',
                 "wrong key: no shell started, nothing logged as admitted, name not trusted");
}

static int refuse_silent_peer(void)
{
    struct mesh_terminal_hub_serve_cfg cfg;
    struct srv s;
    struct mesh_terminal_hub_report r;
    uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX];
    size_t len;
    serve_cfg(&cfg, 5);
    cfg.handshake_ms = 300;
    bool up = srv_start(&s, &cfg);
    int64_t t0 = now_us();
    bool challenge = up && drv_frame(s.fd, &type, payload, &len, 3000) && type == MESH_TERMINAL_HUB_CHALLENGE;
    bool refused = drv_frame(s.fd, &type, payload, &len, 3000) && type == MESH_TERMINAL_HUB_REFUSE;
    bool fin = srv_finish(&s, &r);
    return check(0, challenge && refused && fin && !r.admitted &&
                 r.refusal == MESH_TERMINAL_HUB_REFUSE_REQUEST && now_us() - t0 < 2500000,
                 "a silent peer is cut at the handshake deadline");
}

static int refuse_garbage(void)
{
    struct mesh_terminal_hub_serve_cfg cfg;
    struct srv s;
    struct mesh_terminal_hub_report r;
    uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], junk[3] = { 0x77, 0, 0 };
    size_t len;
    serve_cfg(&cfg, 5);
    cfg.handshake_ms = 300;
    bool up = srv_start(&s, &cfg);
    drv_frame(s.fd, &type, payload, &len, 3000);
    send(s.fd, junk, 3, MSG_NOSIGNAL);
    bool refused = up && drv_frame(s.fd, &type, payload, &len, 3000) && type == MESH_TERMINAL_HUB_REFUSE;
    bool fin = srv_finish(&s, &r);
    return check(0, refused && fin && !r.admitted, "garbage instead of HELLO is refused");
}

/* A correct hello whose MAC covers the wrong nonce (a replay). */
static int refuse_replay(void)
{
    struct mesh_terminal_hub_serve_cfg cfg;
    struct srv s;
    struct mesh_terminal_hub_report r;
    uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], stale_nonce[32] = { 0 }, hello[200];
    size_t len;
    serve_cfg(&cfg, 5);
    cfg.handshake_ms = 1000;
    bool up = srv_start(&s, &cfg);
    drv_frame(s.fd, &type, payload, &len, 3000);
    size_t n = hello_make(hello, cfg.key, stale_nonce, 80, 24, "replay");
    drv_send(s.fd, MESH_TERMINAL_HUB_HELLO, hello, n);
    bool refused = up && drv_frame(s.fd, &type, payload, &len, 3000) && type == MESH_TERMINAL_HUB_REFUSE &&
                   payload[0] == MESH_TERMINAL_HUB_REFUSE_AUTH;
    bool fin = srv_finish(&s, &r);
    return check(0, refused && fin && !r.admitted, "a hello recorded for another nonce is refused");
}

static int refusal_cases(void)
{
    return refuse_wrong_key() + refuse_silent_peer() + refuse_garbage() + refuse_replay();
}

static int limit_cases(void)
{
    int failures = 0;
    static const struct { bool lifetime; int reason; const char *label; } cases[] = {
        { true, MESH_TERMINAL_CLOSE_LIFETIME_LIMIT, "lifetime limit ends the session by name" },
        { false, MESH_TERMINAL_CLOSE_IDLE_TIMEOUT, "idle timeout ends the session by name" },
    };
    for (size_t i = 0; i < 2; i++) {
        struct mesh_terminal_hub_serve_cfg cfg;
        struct srv s;
        struct mesh_terminal_hub_report r;
        struct exit_info ex;
        char seen[512];
        serve_cfg(&cfg, 7);
        cfg.lifetime_seconds = cases[i].lifetime ? 1 : 60;
        cfg.idle_seconds = cases[i].lifetime ? 0 : 1;
        bool up = srv_start(&s, &cfg);
        int64_t t0 = now_us();
        int hs = up ? drv_handshake(s.fd, cfg.key, "limit", 80, 24, NULL) : -9;
        bool got = hs == MESH_TERMINAL_HUB_READY && drv_until(s.fd, NULL, &ex, 8000, seen, sizeof seen);
        bool fin = up && srv_finish(&s, &r);
        int64_t took = now_us() - t0;
        failures = check(failures, got && ex.reason == cases[i].reason && !(ex.flags & 3) && fin &&
                         (int)r.reason == cases[i].reason, cases[i].label);
        printf("  deadline timing diagnostic: case=%s elapsed_us=%lld "
               "required_us=(900000,4000000) handshake=%d exit_received=%d reaped=%d\n",
               cases[i].label, (long long)took, hs, got, fin);
        failures = check(failures, took > 900000 && took < 4000000, "and it fires at the deadline, not before or long after");
    }
    return failures;
}

/* ── the production client loop against a real server ─────────────────── */

struct cl_run {
    pid_t pid;
    int keys_w, screen_r, res_r, ev_w;
};

static bool test_window(void *ctx, uint16_t *cols, uint16_t *rows)
{
    (void)ctx;
    *cols = 132;
    *rows = 43;
    return true;
}

static bool cl_start(struct cl_run *c, int net_fd, const uint8_t key[32], const char *name, int drop_fd)
{
    int keys[2], screen[2], res[2], ev[2];
    if (pipe2(keys, O_CLOEXEC) || pipe2(screen, O_CLOEXEC) || pipe2(res, O_CLOEXEC) || pipe2(ev, O_CLOEXEC))
        return false;
    c->pid = fork();
    if (c->pid == 0) {
        struct mesh_terminal_hub_client_cfg cfg;
        close(keys[1]); close(screen[0]); close(res[0]); close(ev[1]);
        if (drop_fd >= 0)
            close(drop_fd);
        struct mesh_terminal_hub_client_result r;
        memset(&cfg, 0, sizeof cfg);
        memcpy(cfg.key, key, 32);
        cfg.name = name;
        cfg.net_fd = net_fd;
        cfg.in_fd = keys[0];
        cfg.out_fd = screen[1];
        cfg.event_fd = ev[0];
        cfg.handshake_ms = 5000;
        cfg.window = test_window;
        mesh_terminal_hub_client_run(&cfg, &r);
        ssize_t w = write(res[1], &r, sizeof r);
        (void)w;
        _exit(0);
    }
    close(keys[0]); close(screen[1]); close(res[1]); close(ev[0]);
    c->keys_w = keys[1];
    c->screen_r = screen[0];
    c->res_r = res[0];
    c->ev_w = ev[1];
    return c->pid > 0;
}

static bool cl_finish(struct cl_run *c, struct mesh_terminal_hub_client_result *r, char *screen, size_t cap)
{
    size_t fill = 0;
    ssize_t n;
    if (c->keys_w >= 0)
        close(c->keys_w);
    while (fill + 1 < cap && (n = read(c->screen_r, screen + fill, cap - fill - 1)) > 0)
        fill += (size_t)n;
    screen[fill] = '\0';
    n = read(c->res_r, r, sizeof *r);
    close(c->screen_r); close(c->res_r); close(c->ev_w);
    int st;
    return waitpid(c->pid, &st, 0) == c->pid && n == (ssize_t)sizeof *r;
}

/* The production client against a real server: exit status and refusal. */
static int client_cases(void)
{
    int failures = 0;
    struct mesh_terminal_hub_serve_cfg cfg;
    serve_cfg(&cfg, 8);
    for (int variant = 0; variant < 2; variant++) {
        struct srv s;
        struct cl_run c;
        struct mesh_terminal_hub_client_result r;
        struct mesh_terminal_hub_report rep;
        char screen[8192];
        uint8_t wrong[32];
        test_key(wrong, 99);
        bool up = srv_start(&s, &cfg);
        bool cl = up && cl_start(&c, s.fd, variant == 1 ? wrong : cfg.key, "cli", -1);
        if (variant == 0) {
            const char *script = "echo Z23HU\"B\"_OK\nexit 5\n";
            ssize_t w = write(c.keys_w, script, strlen(script));
            (void)w;
        }
        bool fin = cl && cl_finish(&c, &r, screen, sizeof screen);
        srv_finish(&s, &rep);
        if (variant == 0)
            failures = check(failures, fin && r.exit_code == 5 && !r.code[0] && strstr(screen, "Z23HUB_OK"),
                             "client: remote exit 5 is the process exit code; output reaches the screen");
        else
            failures = check(failures, fin && r.exit_code == 4 && !strcmp(r.code, "AUTH_REFUSED") && r.message[0],
                             "client: refused key -> exit 4, typed code and one human line");
    }
    return failures;
}
/* The next frame is exactly (type, bytes). */
static bool frame_is(int fd, uint8_t want_type, const void *want, size_t want_len)
{
    uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX];
    size_t len;
    if (!drv_frame(fd, &type, payload, &len, 3000))
        return false;
    return type == want_type && len == want_len && (!want_len || !memcmp(payload, want, want_len));
}

/* The client side of a handshake against a scripted server, on a fresh pair. */
static bool script_open(struct cl_run *c, int sv[2], const uint8_t key[32], const char *name,
                        struct mesh_terminal_hub_hello *h)
{
    uint8_t type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], body[33] = { MESH_TERMINAL_HUB_VERSION };
    size_t len;
    memset(body + 1, 0x42, 32);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0 || !cl_start(c, sv[1], key, name, sv[0]))
        return false;
    close(sv[1]);
    drv_send(sv[0], MESH_TERMINAL_HUB_CHALLENGE, body, sizeof body);
    if (!drv_frame(sv[0], &type, payload, &len, 3000) || type != MESH_TERMINAL_HUB_HELLO)
        return false;
    return mesh_terminal_hub_hello_verify(h, payload, len, key, body + 1) == MESH_TERMINAL_HUB_HELLO_OK;
}

/* Window in the hello, SIGWINCH as RESIZE, a key as one DATA frame, end of
 * input as ^D, a stop request as CLOSE and exit 130. */
static int script_live(void)
{
    int failures = 0, sv[2];
    struct cl_run c;
    struct mesh_terminal_hub_client_result r;
    struct mesh_terminal_hub_hello h;
    uint8_t key[32];
    char screen[256], first[2] = { 0, 0 };
    test_key(key, 21);
    bool open = script_open(&c, sv, key, "scripted", &h);
    failures = check(failures, open && h.cols == 132 && h.rows == 43 && !strcmp(h.name, "scripted"),
                     "client hello carries the real window size and its name");
    if (!open)
        return failures;
    drv_send(sv[0], MESH_TERMINAL_HUB_READY, NULL, 0);
    drv_send(sv[0], MESH_TERMINAL_HUB_DATA, "hi", 2);
    ssize_t got_hi = read(c.screen_r, first, 2); /* drawn before anything else happens */
    failures = check(failures, got_hi == 2 && !memcmp(first, "hi", 2), "server bytes reach the screen as they arrive");
    ssize_t w = write(c.ev_w, "W", 1);
    static const uint8_t window[4] = { 0, 132, 0, 43 };
    failures = check(failures, frame_is(sv[0], MESH_TERMINAL_HUB_RESIZE, window, 4),
                     "SIGWINCH event becomes a RESIZE frame with the new size");
    w = write(c.keys_w, "k", 1);
    failures = check(failures, frame_is(sv[0], MESH_TERMINAL_HUB_DATA, "k", 1), "a keystroke is one DATA frame of one byte");
    close(c.keys_w);
    c.keys_w = -1;
    failures = check(failures, frame_is(sv[0], MESH_TERMINAL_HUB_DATA, "\x04", 1), "end of input sends one ^D");
    w = write(c.ev_w, "S", 1);
    (void)w;
    failures = check(failures, frame_is(sv[0], MESH_TERMINAL_HUB_CLOSE, "\0", 1), "a stop request sends CLOSE");
    bool fin = cl_finish(&c, &r, screen, sizeof screen);
    failures = check(failures, fin && r.exit_code == 130 && !strcmp(r.code, "INTERRUPTED") && !strcmp(screen, "\r\n"),
                     "stop -> exit 130, screen got the server's bytes and a fresh line");
    close(sv[0]);
    return failures;
}

/* A server that disappears mid-session. */
static int script_dropped(void)
{
    int sv[2];
    struct cl_run c;
    struct mesh_terminal_hub_client_result r;
    struct mesh_terminal_hub_hello h;
    uint8_t key[32];
    char screen[64];
    test_key(key, 22);
    if (!script_open(&c, sv, key, "dropped", &h))
        return check(0, false, "dropped client setup");
    drv_send(sv[0], MESH_TERMINAL_HUB_READY, NULL, 0);
    close(sv[0]);
    bool fin = cl_finish(&c, &r, screen, sizeof screen);
    return check(0, fin && r.exit_code == 5 && !strcmp(r.code, "CONNECTION_LOST") && r.message[0],
                 "lost connection -> exit 5 CONNECTION_LOST with a human line");
}

/* A server that never answers. */
static int script_silent(void)
{
    int sv[2];
    struct mesh_terminal_hub_client_cfg cfg;
    struct mesh_terminal_hub_client_result r;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return check(0, false, "silent client setup");
    memset(&cfg, 0, sizeof cfg);
    cfg.net_fd = sv[1];
    cfg.in_fd = cfg.out_fd = cfg.event_fd = -1;
    cfg.handshake_ms = 200;
    mesh_terminal_hub_client_run(&cfg, &r);
    close(sv[0]);
    close(sv[1]);
    return check(0, r.exit_code == 5 && !strcmp(r.code, "NO_ANSWER"), "no challenge -> exit 5 NO_ANSWER");
}

static int client_script_cases(void)
{
    return script_live() + script_dropped() + script_silent();
}

/* ── the loopback listener ────────────────────────────────────────────── */

struct lsn {
    pid_t pid;
    uint16_t port;
    char audit[300];
};

static bool lsn_start(struct lsn *l, unsigned max_active, unsigned max_sessions, uint8_t seed)
{
    struct mesh_terminal_hub_listen_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    serve_cfg(&cfg.serve, seed);
    cfg.max_active = max_active;
    cfg.max_sessions = max_sessions;
    snprintf(l->audit, sizeof l->audit, "%s/audit-%u-%u-%u.log", g_dir, max_active, max_sessions, seed);
    unlink(l->audit);
    cfg.audit_fd = open(l->audit, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    int listener = cfg.audit_fd < 0 ? -1 : mesh_terminal_hub_listen(0, &l->port);
    if (listener < 0)
        return false;
    l->pid = fork();
    if (l->pid == 0)
        _exit(mesh_terminal_hub_listen_run(listener, &cfg));
    close(listener);
    close(cfg.audit_fd);
    return l->pid > 0;
}

static int tcp_connect(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), one = 1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    if (fd >= 0)
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

static bool lsn_stop(struct lsn *l)
{
    int st = 0;
    kill(l->pid, SIGTERM);
    return waitpid(l->pid, &st, 0) == l->pid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static size_t file_read(const char *path, char *out, size_t cap)
{
    int fd = open(path, O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, out, cap - 1);
    if (fd >= 0)
        close(fd);
    out[n > 0 ? n : 0] = '\0';
    return n > 0 ? (size_t)n : 0;
}

/* Connects and handshakes, retrying while the supervisor frees the slot of a
 * finished session (the cap counts the child until it is reaped). Returns the
 * connected fd, with *outcome the final frame type (READY or REFUSE) and
 * *refusal its code. */
static int lsn_connect_retry(const struct lsn *l, const uint8_t key[32], const char *name,
                             int want, int *outcome, int *refusal)
{
    int fd = -1;
    for (int tries = 0; tries < 100; tries++) {
        *refusal = 0;
        fd = tcp_connect(l->port);
        *outcome = fd < 0 ? -9 : drv_handshake(fd, key, name, 80, 24, refusal);
        bool done = want == MESH_TERMINAL_HUB_READY ? *outcome == MESH_TERMINAL_HUB_READY
                                                    : *refusal == MESH_TERMINAL_HUB_REFUSE_AUTH;
        if (done)
            return fd;
        if (fd >= 0)
            close(fd);
        usleep(20000); /* real-clock: waits on another process (the supervisor reaping a child); there is no seam to inject */
    }
    return -1;
}

static int audit_checks(const char *audit)
{
    int failures = 0, lines = 0;
    failures = check(failures, strstr(audit, "event=TERMINAL_HUB_SESSION admitted=1 refusal=none") &&
                     strstr(audit, "exit_code=3 signal=-") && strstr(audit, "name=lead name_verified=0 exec=\"-\""),
                     "audit: admitted session line carries exit code, an unverified name and exec");
    failures = check(failures, strstr(audit, "admitted=0 refusal=auth") && strstr(audit, "name=- name_verified=0") &&
                     !strstr(audit, "local-intruder"),
                     "audit: the refused key line names no unverified label");
    for (const char *p = audit; (p = strchr(p, '\n')); p++)
        lines++;
    return check(failures, lines == 3, "audit: exactly one line per session");
}

static bool listener_refuses_busy(const struct lsn *l)
{
    uint8_t type, payload[64];
    size_t len;
    int b = tcp_connect(l->port);
    bool busy = b >= 0 && drv_frame(b, &type, payload, &len, 3000) && type == MESH_TERMINAL_HUB_REFUSE &&
                payload[0] == MESH_TERMINAL_HUB_REFUSE_BUSY;
    if (b >= 0)
        close(b);
    return busy;
}

static int listener_cases(void)
{
    int failures = 0, outcome, refusal;
    struct lsn l;
    struct exit_info ex;
    char seen[2048], audit[4096];
    uint8_t key[32], wrong[32];
    test_key(key, 11); test_key(wrong, 12);

    /* Admission and the cap: one slot, the right key, a second client. */
    bool up = lsn_start(&l, 1, 64, 11); /* busy refusals and retries count toward the cap */
    failures = check(failures, up && l.port != 0, "listener binds 127.0.0.1 on an ephemeral port");
    int a = up ? tcp_connect(l.port) : -1;
    failures = check(failures, a >= 0 && drv_handshake(a, key, "lead", 80, 24, NULL) == MESH_TERMINAL_HUB_READY,
                     "first client admitted with the key");
    failures = check(failures, up && listener_refuses_busy(&l),
                     "a second client at the cap is refused busy before any challenge");
    say(a, "exit 3\n");
    failures = check(failures, drv_until(a, NULL, &ex, 8000, seen, sizeof seen) && (ex.flags & 1) && ex.code == 3,
                     "session ends with its exit status over TCP");
    close(a);

    int d = lsn_connect_retry(&l, wrong, "local-intruder", MESH_TERMINAL_HUB_REFUSE, &outcome, &refusal);
    failures = check(failures, d >= 0 && refusal == MESH_TERMINAL_HUB_REFUSE_AUTH,
                     "a local client without the key is refused (auth)");
    if (d >= 0)
        close(d);
    /* The third slot lets the supervisor finish by itself. */
    int e = lsn_connect_retry(&l, key, "lead", MESH_TERMINAL_HUB_READY, &outcome, &refusal);
    if (e >= 0) {
        say(e, "exit 0\n");
        drv_until(e, NULL, &ex, 8000, seen, sizeof seen);
        close(e);
    }
    failures = check(failures, lsn_stop(&l), "supervisor stops on SIGTERM and reaps every child");
    file_read(l.audit, audit, sizeof audit);
    return failures + audit_checks(audit);
}

static int cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* Keystroke round trip: one byte in, the pty echo of that byte back out. */
static int latency_case(void)
{
    enum { SAMPLES = 300 };
    int failures = 0;
    struct lsn l;
    int64_t us[SAMPLES];
    struct exit_info ex;
    char seen[256];
    uint8_t key[32];
    test_key(key, 13);
    bool up = lsn_start(&l, 2, 1, 13);
    int fd = up ? tcp_connect(l.port) : -1;
    failures = check(failures, fd >= 0 && drv_handshake(fd, key, "latency", 80, 24, NULL) == MESH_TERMINAL_HUB_READY,
                     "latency session admitted");
    int got = 0;
    for (int i = 0; fd >= 0 && i < SAMPLES; i++) {
        char probe[2] = { (char)('a' + i % 26), '\0' };
        int64_t t0 = now_us();
        say(fd, probe);
        if (!drv_until(fd, probe, &ex, 3000, seen, sizeof seen))
            break;
        us[got++] = now_us() - t0;
    }
    failures = check(failures, got == SAMPLES, "every keystroke was echoed back");
    if (got == SAMPLES) {
        qsort(us, SAMPLES, sizeof us[0], cmp_i64);
        printf("  keystroke round trip over loopback TCP, no tunnel (n=%d): min=%lld us median=%lld us p99=%lld us max=%lld us\n",
               SAMPLES, (long long)us[0], (long long)us[SAMPLES / 2], (long long)us[SAMPLES * 99 / 100],
               (long long)us[SAMPLES - 1]);
        failures = check(failures, us[SAMPLES / 2] < 5000, "median keystroke round trip under 5 ms");
    }
    if (fd >= 0) {
        say(fd, "\nexit\n");
        close(fd);
    }
    lsn_stop(&l);
    return failures;
}

/* ── explicit argv inside the cage ────────────────────────────────────── */

static int exec_wire_cases(void)
{
    int failures = 0;
    uint8_t key[32], nonce[32], hello[MESH_TERMINAL_HUB_PAYLOAD_MAX];
    struct mesh_terminal_hub_hello h;
    test_key(key, 31);
    memset(nonce, 0x33, sizeof nonce);
    const char *argv[] = { "/bin/prog", "a b", "c\"d", NULL };
    struct mesh_terminal_hub_request rq = { .cols = 80, .rows = 24, .name = "x", .argv = argv };
    size_t n = mesh_terminal_hub_hello_build(hello, key, nonce, &rq);
    failures = check(failures, n && mesh_terminal_hub_hello_verify(&h, hello, n, key, nonce) == MESH_TERMINAL_HUB_HELLO_OK &&
                     h.argc == 3 && !strcmp(h.argv[0], "/bin/prog") && !strcmp(h.argv[1], "a b") &&
                     !strcmp(h.argv[2], "c\"d") && h.argv[3] == NULL, "hello carries an argv and verifies it");
    bool every = true;
    for (size_t at = 0; at < n; at++) {
        uint8_t copy[MESH_TERMINAL_HUB_PAYLOAD_MAX];
        memcpy(copy, hello, n);
        copy[at] ^= 0x01;
        every = every && mesh_terminal_hub_hello_verify(&h, copy, n, key, nonce) != MESH_TERMINAL_HUB_HELLO_OK;
    }
    failures = check(failures, every, "any single flipped bit of a hello with an argv is refused (argv is under the mac)");
    const char *many[18];
    for (int i = 0; i < 17; i++) many[i] = "/x";
    many[17] = NULL;
    rq.argv = many;
    failures = check(failures, mesh_terminal_hub_hello_build(hello, key, nonce, &rq) == 0, "17 arguments cannot be sent");
    char big[2100];
    memset(big, 'a', sizeof big - 1); big[sizeof big - 1] = '\0';
    const char *huge[] = { "/x", big, NULL };
    rq.argv = huge;
    failures = check(failures, mesh_terminal_hub_hello_build(hello, key, nonce, &rq) == 0, "an argv past 2000 bytes cannot be sent");

    char label[MESH_TERMINAL_HUB_EXEC_LABEL_MAX + 8];
    const char *odd[] = { "/p", "a b", "\"q\"\n", "back\\slash", NULL };
    mesh_terminal_hub_exec_label(label, sizeof label, odd, 4);
    failures = check(failures, !strcmp(label, "/p a\\x20b \\x22q\\x22\\x0a back\\x5cslash"),
                     "audit label escapes space, quote, backslash and control bytes");
    const char *longv[] = { "/x", big, NULL };
    mesh_terminal_hub_exec_label(label, sizeof label, longv, 2);
    failures = check(failures, strlen(label) == MESH_TERMINAL_HUB_EXEC_LABEL_MAX + 3 &&
                     !strcmp(label + MESH_TERMINAL_HUB_EXEC_LABEL_MAX, "..."), "audit label is cut at 256 bytes and says so");
    mesh_terminal_hub_exec_label(label, sizeof label, NULL, 0);
    failures = check(failures, !strcmp(label, "-"), "no argv -> \"-\"");

    struct mesh_terminal_hub_report rep;
    memset(&rep, 0, sizeof rep);
    rep.admitted = true; rep.exit_code = 9; rep.reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
    snprintf(rep.name, sizeof rep.name, "lead");
    mesh_terminal_hub_exec_label(rep.exec, sizeof rep.exec, odd, 4);
    char line[768];
    mesh_terminal_hub_audit_line(line, sizeof line, &rep);
    failures = check(failures, strstr(line, "exit_code=9") && strstr(line, "exec=\"/p a\\x20b") && !strchr(line, '\n'),
                     "audit line carries the escaped argv on one line");
    return failures;
}

/* One exec session: runs `argv`, returns the EXIT frame and the report. */
static bool exec_run(const char *const *argv, struct exit_info *ex, struct mesh_terminal_hub_report *r)
{
    struct mesh_terminal_hub_serve_cfg cfg;
    struct srv s;
    char seen[512];
    struct mesh_terminal_hub_request rq = { .cols = 80, .rows = 24, .name = "exec", .argv = argv };
    serve_cfg(&cfg, 41);
    bool up = srv_start(&s, &cfg);
    int hs = up ? drv_handshake_rq(s.fd, cfg.key, &rq, NULL) : -9;
    bool got = hs == MESH_TERMINAL_HUB_READY && drv_until(s.fd, NULL, ex, 8000, seen, sizeof seen);
    return up && srv_finish(&s, r) && got;
}

/* An argv runs and its exit code propagates; a write outside the cage is denied. */
static int exec_run_cases(void)
{
    int failures = 0;
    struct exit_info ex;
    struct mesh_terminal_hub_report r;
    char outside[200], script[300];
    char outside_dir[160];
    test_make_tmpdir(outside_dir, sizeof outside_dir, "mesh_terminal_hub", "outside");
    snprintf(outside, sizeof outside, "%s/leak", outside_dir);
    snprintf(script, sizeof script, "echo leaked > %s; exit 4", outside);
    const char *const nine[] = { g_fbsh, "-c", "exit 9", NULL };
    const char *const four[] = { g_fbsh, "-c", script, NULL };
    unlink(outside);
    bool ok = exec_run(nine, &ex, &r);
    failures = check(failures, ok && exit_is(&ex, true, 9, 0), "exec: an argv runs and its exit code 9 propagates");
    failures = check(failures, r.admitted && strstr(r.exec, "-c") && r.exit_code == 9, "exec: the report carries the argv");
    ok = exec_run(four, &ex, &r);
    failures = check(failures, ok && exit_is(&ex, true, 4, 0), "exec: the program ran and its exit code 4 propagates");
    struct stat st;
    failures = check(failures, stat(outside, &st) != 0, "exec: a write outside the grants is denied by the cage");
    unlink(outside);
    return failures;
}

/* Programs the server cannot run are refused by name, before any shell. */
static int exec_refusal_cases(void)
{
    int failures = 0;
    struct mesh_terminal_hub_serve_cfg cfg;
    const char *relative[] = { "fbsh", NULL };
    const char *missing[] = { "/nonexistent/z23-prog", NULL };
    const char *not_exec[] = { "/etc/passwd", NULL };
    const char *dir[] = { g_dir, NULL };
    const char *const *cases[] = { relative, missing, not_exec, dir };
    static const char *const labels[] = { "exec: a relative program is refused with the typed exec refusal",
        "exec: a missing program is refused with the typed exec refusal",
        "exec: a file that is not executable is refused with the typed exec refusal",
        "exec: a directory is refused with the typed exec refusal" };
    serve_cfg(&cfg, 41);
    for (int i = 0; i < 4; i++) {
        struct srv s;
        struct mesh_terminal_hub_report r;
        struct mesh_terminal_hub_request rq = { .cols = 80, .rows = 24, .name = "bad", .argv = cases[i] };
        int refusal = 0;
        bool up = srv_start(&s, &cfg);
        int hs = up ? drv_handshake_rq(s.fd, cfg.key, &rq, &refusal) : -9;
        bool fin = srv_finish(&s, &r);
        failures = check(failures, hs == MESH_TERMINAL_HUB_REFUSE && refusal == MESH_TERMINAL_HUB_REFUSE_EXEC &&
                         fin && !r.admitted && r.refusal == MESH_TERMINAL_HUB_REFUSE_EXEC && r.bytes_out == 0,
                         labels[i]);
    }
    struct mesh_terminal_hub_report r;
    char line[768];
    memset(&r, 0, sizeof r);
    r.refusal = MESH_TERMINAL_HUB_REFUSE_EXEC;
    mesh_terminal_hub_audit_line(line, sizeof line, &r);
    return check(failures, strstr(line, "admitted=0 refusal=exec") != NULL, "exec: the audit line names the exec refusal");
}

/* A quiet client does not get its own input echoed back. */
static int quiet_case(void)
{
    struct mesh_terminal_hub_serve_cfg cfg;
    struct srv s;
    struct mesh_terminal_hub_report r;
    struct exit_info ex;
    char seen[1024];
    struct mesh_terminal_hub_request rq = { .cols = 80, .rows = 24, .name = "quiet",
                                            .flags = MESH_TERMINAL_HUB_HELLO_QUIET };
    serve_cfg(&cfg, 41);
    bool up = srv_start(&s, &cfg);
    int hs = up ? drv_handshake_rq(s.fd, cfg.key, &rq, NULL) : -9;
    say(s.fd, "echo Z23HU\"B\"_Q\n");
    bool got = hs == MESH_TERMINAL_HUB_READY && drv_until(s.fd, "Z23HUB_Q", &ex, 8000, seen, sizeof seen);
    int failures = check(0, got && !strstr(seen, "HU\"B\"_Q"), "quiet: the typed line is not echoed back, only its output");
    say(s.fd, "exit\n");
    drv_until(s.fd, NULL, &ex, 8000, seen, sizeof seen);
    srv_finish(&s, &r);
    return failures;
}

static int exec_session_cases(void)
{
    return exec_run_cases() + exec_refusal_cases() + quiet_case();
}

/* The screen ends on a fresh line even when the remote's last bytes were a prompt. */
static int tidy_end_case(void)
{
    int failures = 0, sv[2];
    struct cl_run c;
    struct mesh_terminal_hub_client_result r;
    uint8_t key[32], type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], body[33] = { MESH_TERMINAL_HUB_VERSION };
    size_t len;
    char screen[64];
    test_key(key, 51);
    memset(body + 1, 0x24, 32);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0 || !cl_start(&c, sv[1], key, "tidy", sv[0]))
        return check(failures, false, "tidy client setup");
    close(sv[1]);
    drv_send(sv[0], MESH_TERMINAL_HUB_CHALLENGE, body, sizeof body);
    drv_frame(sv[0], &type, payload, &len, 3000);
    drv_send(sv[0], MESH_TERMINAL_HUB_READY, NULL, 0);
    drv_send(sv[0], MESH_TERMINAL_HUB_DATA, "out\n$ ", 6);
    uint8_t ex[4] = { MESH_TERMINAL_CLOSE_WORKER_EXITED, 1, 0, 0 };
    drv_send(sv[0], MESH_TERMINAL_HUB_EXIT, ex, 4);
    bool fin = cl_finish(&c, &r, screen, sizeof screen);
    failures = check(failures, fin && r.exit_code == 0 && !strcmp(screen, "out\n$ \r\n"),
                     "the screen ends on a fresh line after a dangling prompt");
    close(sv[0]);
    return failures;
}

/* Exactly 2000 argv content bytes over several arguments round-trips; one more cannot be sent. */
static int argv_max_cases(void)
{
    int failures = 0;
    uint8_t key[32], nonce[32], hello[MESH_TERMINAL_HUB_PAYLOAD_MAX];
    struct mesh_terminal_hub_hello h;
    char a[1001], b[998];
    test_key(key, 61);
    memset(nonce, 0x44, sizeof nonce);
    memset(a, 'a', 1000); a[1000] = '\0';
    memset(b, 'b', 997);  b[997] = '\0';
    const char *max3[] = { "/x", a, b, NULL };                 /* 2 + 1000 + 997 = 1999 */
    const char *max4[] = { "/x", a, b, "c", NULL };            /* exactly 2000 */
    const char *over[] = { "/x", a, b, "cc", NULL };           /* 2001 */
    struct mesh_terminal_hub_request rq = { .cols = 80, .rows = 24, .name = "m", .argv = max4 };
    size_t n = mesh_terminal_hub_hello_build(hello, key, nonce, &rq);
    failures = check(failures, n && mesh_terminal_hub_hello_verify(&h, hello, n, key, nonce) == MESH_TERMINAL_HUB_HELLO_OK &&
                     h.argc == 4 && !strcmp(h.argv[1], a) && !strcmp(h.argv[2], b) && !strcmp(h.argv[3], "c"),
                     "a multi-argument hello of exactly 2000 content bytes round-trips");
    rq.argv = max3;
    n = mesh_terminal_hub_hello_build(hello, key, nonce, &rq);
    failures = check(failures, n && mesh_terminal_hub_hello_verify(&h, hello, n, key, nonce) == MESH_TERMINAL_HUB_HELLO_OK,
                     "a hello just under the maximum round-trips");
    rq.argv = over;
    failures = check(failures, mesh_terminal_hub_hello_build(hello, key, nonce, &rq) == 0,
                     "2001 content bytes cannot be sent");
    const char *sixteen[17];
    char many[125];
    memset(many, 'm', 124); many[124] = '\0';
    sixteen[0] = "/";
    for (int i = 1; i < 16; i++) sixteen[i] = many;
    sixteen[16] = NULL;                              /* 1 + 15 x 124 = 1861 content bytes */
    rq.argv = sixteen;
    n = mesh_terminal_hub_hello_build(hello, key, nonce, &rq);
    failures = check(failures, n && mesh_terminal_hub_hello_verify(&h, hello, n, key, nonce) == MESH_TERMINAL_HUB_HELLO_OK &&
                     h.argc == 16, "sixteen arguments round-trip");
    return failures;
}

/* The client against a scripted server that sends one EXIT body. */
static bool client_exit_run(const uint8_t body[4], struct mesh_terminal_hub_client_result *r)
{
    int sv[2];
    struct cl_run c;
    uint8_t key[32], type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], ch[33] = { MESH_TERMINAL_HUB_VERSION };
    size_t len;
    char screen[64];
    test_key(key, 51);
    memset(ch + 1, 0x24, 32);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0 || !cl_start(&c, sv[1], key, "exit", sv[0]))
        return false;
    close(sv[1]);
    drv_send(sv[0], MESH_TERMINAL_HUB_CHALLENGE, ch, sizeof ch);
    drv_frame(sv[0], &type, payload, &len, 3000);
    drv_send(sv[0], MESH_TERMINAL_HUB_READY, NULL, 0);
    drv_send(sv[0], MESH_TERMINAL_HUB_EXIT, body, 4);
    bool fin = cl_finish(&c, r, screen, sizeof screen);
    close(sv[0]);
    return fin;
}

/* An EXIT frame is trusted only in a shape the server can send. Anything else
 * is a typed protocol refusal, never an exit 0. */
static int exit_frame_cases(void)
{
    static const struct {
        uint8_t body[4];
        int exit_code;
        const char *code;
        const char *label;
    } rows[] = {
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 1, 7, 0 }, 7, "", "exit: a code exit carries its code" },
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 1, 0, 0 }, 0, "", "exit: a clean exit is the only exit 0" },
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 2, 0, 15 }, 143, "", "exit: a signal exit is 128 + the signal" },
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 0, 0, 0 }, 1, "PROTOCOL", "exit: worker-exited with neither flag is refused" },
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 3, 4, 9 }, 1, "PROTOCOL", "exit: worker-exited with both flags is refused" },
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 2, 0, 0 }, 1, "PROTOCOL", "exit: signal flag with signal 0 is refused" },
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 2, 0, 65 }, 1, "PROTOCOL", "exit: signal 65 is out of range" },
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 2, 3, 9 }, 1, "PROTOCOL", "exit: a signal exit with a stray code byte is refused" },
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 1, 3, 9 }, 1, "PROTOCOL", "exit: a code exit with a stray signal byte is refused" },
        { { MESH_TERMINAL_CLOSE_WORKER_EXITED, 4, 0, 0 }, 1, "PROTOCOL", "exit: an unknown flag bit is refused" },
        { { 42, 0, 0, 0 }, 1, "PROTOCOL", "exit: an unknown reason is refused, not read as success" },
        { { MESH_TERMINAL_CLOSE_REVOKED, 0, 0, 0 }, 1, "PROTOCOL", "exit: a reason the hub never sends is refused" },
        { { MESH_TERMINAL_CLOSE_REQUESTED, 0, 0, 0 }, 1, "PROTOCOL", "exit: an unsolicited requested ending is refused" },
        { { MESH_TERMINAL_CLOSE_IDLE_TIMEOUT, 1, 3, 0 }, 1, "PROTOCOL", "exit: a limit ending that claims a status is refused" },
        { { MESH_TERMINAL_CLOSE_IDLE_TIMEOUT, 0, 0, 0 }, 5, "IDLE_TIMEOUT", "exit: a limit ending keeps its class" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        struct mesh_terminal_hub_client_result r;
        memset(&r, 0xee, sizeof r);
        bool ok = client_exit_run(rows[i].body, &r);
        failures = check(failures, ok && r.exit_code == rows[i].exit_code && !strcmp(r.code, rows[i].code),
                         rows[i].label);
    }
    return failures;
}

/* Output nobody drains must not keep a termination request from being served. */
static int backpressure_case(void)
{
    int failures = 0, sv[2];
    struct cl_run c;
    struct mesh_terminal_hub_client_result r;
    uint8_t key[32], type, payload[MESH_TERMINAL_HUB_PAYLOAD_MAX], ch[33] = { MESH_TERMINAL_HUB_VERSION };
    uint8_t block[MESH_TERMINAL_HUB_PAYLOAD_MAX];
    size_t len, sent = 0;
    char screen[4096];
    struct timeval tv = { .tv_usec = 300000 };
    test_key(key, 51);
    memset(ch + 1, 0x24, 32);
    memset(block, 'x', sizeof block);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0 || !cl_start(&c, sv[1], key, "bp", sv[0]))
        return check(failures, false, "backpressure setup");
    close(sv[1]);
    drv_send(sv[0], MESH_TERMINAL_HUB_CHALLENGE, ch, sizeof ch);
    drv_frame(sv[0], &type, payload, &len, 3000);
    drv_send(sv[0], MESH_TERMINAL_HUB_READY, NULL, 0);
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    /* Nothing reads the screen pipe: the client wedges, the socket fills, a send times out. */
    while (sent < (8u << 20) && drv_send(sv[0], MESH_TERMINAL_HUB_DATA, block, sizeof block))
        sent += sizeof block;
    failures = check(failures, sent > 0 && sent < (8u << 20), "the unread screen backs the stream up");
    int64_t t0 = now_us();
    ssize_t sw = write(c.ev_w, "S", 1);
    (void)sw;
    struct pollfd p = { .fd = c.res_r, .events = POLLIN };
    bool prompt = poll(&p, 1, 4000) > 0;
    int64_t took = now_us() - t0;
    if (!prompt)
        kill(c.pid, SIGKILL);
    bool fin = cl_finish(&c, &r, screen, sizeof screen);
    failures = check(failures, prompt && took < 4000000, "a stop request is served while the output is backed up");
    failures = check(failures, fin && prompt && r.exit_code == 130 && !strcmp(r.code, "INTERRUPTED"),
                     "the backed-up client ends interrupted (130), not wedged");
    close(sv[0]);
    return failures;
}

/* A SIGHUP-ignoring tunnel child is reaped within a bound (in a helper, so a regression times out). */
static void reap_victim(int ready_fd)
{
    signal(SIGHUP, SIG_IGN);
    if (write(ready_fd, "r", 1) != 1)
        _exit(2);
    for (;;)
        pause();
}

/* In the helper process: reap a HUP-ignoring child, report whether it was
 * reaped, really gone, and quick. */
static bool reap_helper(int ready[2], bool pidfd_unavailable)
{
    char r;
    zcl_native_hub_testing_pidfd_unavailable(pidfd_unavailable);
    pid_t victim = fork();
    if (victim == 0)
        reap_victim(ready[1]);
    bool armed = victim > 0 && read(ready[0], &r, 1) == 1;
    int64_t t0 = now_us();
    bool reaped = armed && zcl_native_hub_tunnel_reap(victim, 200);
    bool gone = waitpid(victim, NULL, WNOHANG) < 0 && errno == ECHILD;
    bool ok = reaped && gone && now_us() - t0 < 5000000;
    if (!ok && victim > 0)
        kill(victim, SIGKILL);
    return ok;
}

static bool reap_bounded_run(bool pidfd_unavailable)
{
    int done[2], ready[2];
    if (pipe2(done, O_CLOEXEC) || pipe2(ready, O_CLOEXEC))
        return false;
    pid_t helper = fork();
    if (helper == 0)
        _exit(write(done[1], reap_helper(ready, pidfd_unavailable) ? "y" : "n", 1) == 1 ? 0 : 2);
    struct pollfd p = { .fd = done[0], .events = POLLIN };
    char verdict = 'n';
    bool in_time = helper > 0 && poll(&p, 1, 8000) > 0 && read(done[0], &verdict, 1) == 1;
    if (!in_time && helper > 0)
        kill(helper, SIGKILL);
    if (helper > 0)
        waitpid(helper, NULL, 0);
    close(done[0]); close(done[1]); close(ready[0]); close(ready[1]);
    return in_time && verdict == 'y';
}

static int edge_cases(void)
{
    int failures = 0;
    failures = check(failures, reap_bounded_run(false),
                     "tunnel reap: a child that ignores SIGHUP is escalated and reaped within a bound");
    failures = check(failures, reap_bounded_run(true),
                     "tunnel reap: with pidfd_open unavailable the child is still reaped within a bound");

    char arg[40], route[2100], keyp[300], fp[32], why[96];
    failures = check(failures, zcl_native_hub_route_arg("/r.json", arg, sizeof arg) && !strcmp(arg, "--input-file=/r.json"),
                     "route argument: a short path is built whole");
    memset(route, 'r', sizeof route - 1); route[sizeof route - 1] = '\0';
    route[0] = '/';
    failures = check(failures, !zcl_native_hub_route_arg(route, arg, sizeof arg),
                     "route argument: a path that does not fit is refused, never cut");
    failures = check(failures, zcl_native_hub_route_arg("/12345678901234567890123", arg, 38) &&
                     !zcl_native_hub_route_arg("/12345678901234567890123", arg, 37),
                     "route argument: the exact boundary fits and one more byte does not");
    snprintf(keyp, sizeof keyp, "%s/route.key", g_dir);
    unlink(keyp);
    struct hub_args a;
    memset(&a, 0, sizeof a);
    a.key_file = keyp;
    a.route_input = route;
    failures = check(failures, mesh_terminal_hub_key_init(keyp, fp, why, sizeof why) &&
                     zcl_native_hub_connect(&a) == ZCL_COMMAND_EXIT_INVALID,
                     "connect: an over-long --route_input is refused as invalid before any spawn");

    const char *const big[] = { "--max_sessions=4294967297" };
    const char *const edge[] = { "--max_sessions=4294967295" };
    const char *const huge[] = { "--max_sessions=18446744073709551615" };
    failures = check(failures, !zcl_native_hub_args_parse(big, 1, 0, &a) &&
                     !zcl_native_hub_args_parse(huge, 1, 0, &a) &&
                     zcl_native_hub_args_parse(edge, 1, 0, &a) && a.max_sessions == UINT32_MAX,
                     "serve: --max_sessions past 32 bits is refused, never wrapped");
    return failures;
}

static bool wait_child_within(pid_t pid, int ms, int *status)
{
    for (int waited = 0; waited <= ms; waited += 20) {
        if (waitpid(pid, status, WNOHANG) == pid)
            return true;
        usleep(20000); /* real-clock: waits on another process; there is no seam to inject */
    }
    kill(pid, SIGKILL);
    waitpid(pid, status, 0);
    return false;
}

static void fill_pipe(int wfd)
{
    char chunk[4096];
    memset(chunk, 'f', sizeof chunk);
    int fl = fcntl(wfd, F_GETFL);
    fcntl(wfd, F_SETFL, fl | O_NONBLOCK);
    while (write(wfd, chunk, sizeof chunk) > 0) {}
    fcntl(wfd, F_SETFL, fl);
}

/* A session whose audit sink never drains must not hold the supervisor: the
 * line is dropped after a bound and the drop is counted. */
static int audit_wedge_case(void)
{
    int failures = 0, status = 0, sink[2];
    struct mesh_terminal_hub_listen_cfg cfg;
    struct exit_info ex;
    char seen[256], errpath[300], errtext[512];
    uint16_t port = 0;
    uint8_t key[32];
    test_key(key, 71);
    memset(&cfg, 0, sizeof cfg);
    serve_cfg(&cfg.serve, 71);
    cfg.max_active = 1;
    cfg.max_sessions = 1;
    cfg.audit_wait_ms = 300;
    snprintf(errpath, sizeof errpath, "%s/wedge-stderr.log", g_dir);
    if (pipe2(sink, O_CLOEXEC) != 0)
        return check(failures, false, "audit wedge setup");
    fill_pipe(sink[1]);
    cfg.audit_fd = sink[1];
    int listener = mesh_terminal_hub_listen(0, &port);
    pid_t sup = listener < 0 ? -1 : fork();
    if (sup == 0) {
        int e = open(errpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (e >= 0)
            dup2(e, STDERR_FILENO);
        _exit(mesh_terminal_hub_listen_run(listener, &cfg));
    }
    close(listener);
    int fd = sup > 0 ? tcp_connect(port) : -1;
    failures = check(failures, fd >= 0 && drv_handshake(fd, key, "wedge", 80, 24, NULL) == MESH_TERMINAL_HUB_READY,
                     "audit wedge: the session is admitted");
    if (fd >= 0) {
        say(fd, "exit 0\n");
        drv_until(fd, NULL, &ex, 8000, seen, sizeof seen);
        close(fd);
    }
    bool stopped = sup > 0 && wait_child_within(sup, 6000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "audit wedge: the supervisor still stops by itself after its last session");
    file_read(errpath, errtext, sizeof errtext);
    failures = check(failures, strstr(errtext, "event=TERMINAL_HUB_AUDIT_DROPPED count=1") != NULL,
                     "audit wedge: the dropped line is counted, not silent");
    close(sink[0]);
    close(sink[1]);
    return failures;
}

/* A session that ignores SIGTERM is killed after the grace, not waited for. */
static int stop_deadline_case(void)
{
    int failures = 0, status = 0;
    struct mesh_terminal_hub_listen_cfg cfg;
    uint16_t port = 0;
    uint8_t key[32];
    test_key(key, 72);
    memset(&cfg, 0, sizeof cfg);
    serve_cfg(&cfg.serve, 72);
    cfg.max_active = 1;
    cfg.stop_grace_ms = 300;
    cfg.audit_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int listener = cfg.audit_fd < 0 ? -1 : mesh_terminal_hub_listen(0, &port);
    pid_t sup = listener < 0 ? -1 : fork();
    if (sup == 0) {
        mesh_terminal_hub_testing_children_ignore_term(true); /* in the supervisor only */
        _exit(mesh_terminal_hub_listen_run(listener, &cfg));
    }
    close(listener);
    int fd = sup > 0 ? tcp_connect(port) : -1;
    failures = check(failures, fd >= 0 && drv_handshake(fd, key, "wedged", 80, 24, NULL) == MESH_TERMINAL_HUB_READY,
                     "stop deadline: a session is open");
    int64_t t0 = now_us();
    if (sup > 0)
        kill(sup, SIGTERM);
    bool stopped = sup > 0 && wait_child_within(sup, 5000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0 && now_us() - t0 < 4000000,
                     "stop deadline: SIGTERM ends the supervisor within a bound although the session ignores it");
    if (fd >= 0)
        close(fd);
    close(cfg.audit_fd);
    return failures;
}

static int bound_cases(void)
{
    return argv_max_cases() + exit_frame_cases() + backpressure_case() + edge_cases() +
           audit_wedge_case() + stop_deadline_case();
}

int test_mesh_terminal_hub(void)
{
    int failures = 0;
    printf("\n=== mesh terminal hub tests ===\n");
    test_make_tmpdir(g_dir, sizeof g_dir, "mesh_terminal_hub", "live");
    struct stat st;
    if (!test_abs_path(FBSH_BIN, g_fbsh, sizeof g_fbsh) || stat(FBSH_BIN, &st) != 0 || !(st.st_mode & S_IXUSR)) {
        printf("  build/bin/fbsh is absent: the hub cannot run its shell\n");
        failures++;
    }
    failures += portable_cases();
    failures += wire_cases();
    failures += key_cases();
    failures += exec_wire_cases();
    if (g_fbsh[0]) {
        failures += status_cases();
        failures += echo_and_resize_cases();
        failures += refusal_cases();
        failures += limit_cases();
        failures += client_cases();
        failures += client_script_cases();
        failures += tidy_end_case();
        failures += exec_session_cases();
        failures += listener_cases();
        failures += latency_case();
        failures += bound_cases();
        failures += test_mesh_terminal_hub_bounds(g_fbsh, g_dir);
    }
    printf("mesh terminal hub: %d failures\n", failures);
    return failures;
}

#else /* __linux__ */

int test_mesh_terminal_hub(void)
{
    printf("\n=== mesh terminal hub tests ===\n  live shell cases are Linux-only: the confined worker needs the Linux cage\n");
    int failures = 0;
#if !defined(_WIN32)
    failures += portable_cases();
#endif
    printf("mesh terminal hub: %d failures\n", failures);
    return failures;
}

#endif
