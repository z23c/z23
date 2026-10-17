/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the terminal hub session loop. One connected stream, one confined
 * worker (mesh_terminal_worker, unchanged), one poll over the socket, the
 * pty master and the shell's pidfd. The loop blocks in poll until bytes or a
 * real deadline arrive; there are no sleeps and no tick. Output is read from
 * the pty straight into the frame buffer behind its 3-byte header and sent
 * with one send(); keystrokes are written to the pty from the receive buffer
 * with no intermediate copy. */

#define _GNU_SOURCE /* accept4 and pidfd on Linux — must precede every include */

#include "session/mesh_terminal_hub.h"

#include <stdio.h>
#include <string.h>

size_t mesh_terminal_hub_audit_line(
    char *out, size_t cap, const struct mesh_terminal_hub_report *r)
{
    static const char *const refusals[] = { "none", "auth", "busy", "request",
                                            "confinement", "shutdown", "exec" };
    char status[48] = "exit_code=- signal=-";
    if (r->exit_code >= 0)
        snprintf(status, sizeof status, "exit_code=%d signal=-", r->exit_code);
    else if (r->signal > 0)
        snprintf(status, sizeof status, "exit_code=- signal=%d", r->signal);
    int refusal = r->refusal >= 0 && r->refusal <= MESH_TERMINAL_HUB_REFUSE_EXEC
                      ? r->refusal : 0;
    int n = snprintf(out, cap,
        "event=TERMINAL_HUB_SESSION admitted=%u refusal=%s start=%lld end=%lld "
        "duration_s=%lld reason=%s %s bytes_in=%llu bytes_out=%llu name=%s "
        "name_verified=0 exec=\"%s\"",
        r->admitted ? 1u : 0u, refusals[refusal], (long long)r->start_unix,
        (long long)r->end_unix, (long long)(r->end_unix - r->start_unix),
        r->admitted ? mesh_terminal_close_reason_string(r->reason) : "-", status,
        (unsigned long long)r->bytes_in, (unsigned long long)r->bytes_out,
        r->name[0] ? r->name : "-", r->exec[0] ? r->exec : "-");
    return n < 0 ? 0 : ((size_t)n < cap ? (size_t)n : cap - 1u);
}

#if defined(_WIN32)

static void hub_serve_fd_arm(int fd,
                                const struct mesh_terminal_hub_serve_cfg *cfg,
                                struct mesh_terminal_hub_report *report)
{
    (void)fd; (void)cfg;
    memset(report, 0, sizeof(*report));
    report->refusal = MESH_TERMINAL_HUB_REFUSE_CONFINEMENT;
    report->exit_code = -1;
}

static int hub_listen_arm(uint16_t port, uint16_t *bound_port)
{
    (void)port; (void)bound_port;
    return -1;
}

static int hub_listen_run_arm(int listener,
                                 const struct mesh_terminal_hub_listen_cfg *cfg)
{
    (void)listener; (void)cfg;
    return -1;
}

#else

#include "mesh_terminal_hub_io.h"
#include "session/mesh_terminal_hub_portable.h"

#include "platform/resident_launch.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "session/mesh_terminal_worker.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define HUB_SEND_TIMEOUT_S 10
#define HUB_PUMP_CHUNKS 8u
#define HUB_FALLBACK_POLL_MS 1000

struct hub_sess {
    int fd;
    int pidfd;                   /* -1 when the kernel has none */
    bool pty_eof;
    int64_t last_check;
    bool forced;                /* ended by us, not by the shell */
    enum mesh_terminal_close_reason forced_reason;
    struct mesh_terminal_worker w;
    struct hub_rx rx;
    uint8_t out[MESH_TERMINAL_HUB_FRAME_MAX];
};

static int64_t hub_now(void)
{
    return (int64_t)platform_time_wall_time_t();
}

static void hub_force(struct hub_sess *s, enum mesh_terminal_close_reason why)
{
    if (!s->forced) {
        s->forced = true;
        s->forced_reason = why;
    }
}

static void hub_socket_prepare(int fd)
{
    int one = 1;
    struct timeval tv = { .tv_sec = HUB_SEND_TIMEOUT_S };
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    hub_socket_nosigpipe(fd);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

static void hub_refuse(int fd, struct mesh_terminal_hub_report *r, int code)
{
    uint8_t c = (uint8_t)code;
    r->refusal = code;
    (void)hub_io_send_frame(fd, MESH_TERMINAL_HUB_REFUSE, &c, 1);
}

/* CHALLENGE, then one HELLO inside the handshake deadline. */
static bool hub_admit(struct hub_sess *s,
                      const struct mesh_terminal_hub_serve_cfg *cfg,
                      struct mesh_terminal_hub_report *r,
                      struct mesh_terminal_hub_hello *hello)
{
    uint8_t body[1 + MESH_TERMINAL_HUB_NONCE_BYTES];
    body[0] = MESH_TERMINAL_HUB_VERSION;
    if (!rng_fill(body + 1, MESH_TERMINAL_HUB_NONCE_BYTES) ||
        !hub_io_send_frame(s->fd, MESH_TERMINAL_HUB_CHALLENGE, body, sizeof body))
        return false;
    uint8_t type;
    const uint8_t *payload;
    size_t len;
    int wait_ms = cfg->handshake_ms ? cfg->handshake_ms : MESH_TERMINAL_HUB_HANDSHAKE_MS;
    if (hub_rx_wait(&s->rx, s->fd, wait_ms, &type, &payload, &len) != HUB_WAIT_FRAME ||
        type != MESH_TERMINAL_HUB_HELLO) {
        hub_refuse(s->fd, r, MESH_TERMINAL_HUB_REFUSE_REQUEST);
        return false;
    }
    enum mesh_terminal_hub_hello_status v = mesh_terminal_hub_hello_verify(
        hello, payload, len, cfg->key, body + 1);
    hub_rx_consume(&s->rx, len);
    if (v != MESH_TERMINAL_HUB_HELLO_OK) {
        hub_refuse(s->fd, r, v == MESH_TERMINAL_HUB_HELLO_MAC
                                 ? MESH_TERMINAL_HUB_REFUSE_AUTH
                                 : MESH_TERMINAL_HUB_REFUSE_REQUEST);
        return false;
    }
    return true;
}

static bool hub_exec_runnable(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0;
}

/* A quiet (non-tty) client has no use for the pty echoing back what it sent. */
static void hub_echo_off(struct hub_sess *s)
{
    struct termios t;
    if (tcgetattr(s->w.master_fd, &t) != 0)
        return;
    t.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
    (void)tcsetattr(s->w.master_fd, TCSANOW, &t);
}

/* 0 when the worker runs, otherwise the refusal code to send. */
static int hub_start_worker(struct hub_sess *s,
                            const struct mesh_terminal_hub_serve_cfg *cfg,
                            const struct mesh_terminal_hub_hello *hello)
{
    bool exec = hello->argc != 0;
    if (!hub_confinement_supported())
        return MESH_TERMINAL_HUB_REFUSE_CONFINEMENT; /* no cage on this host: never an unconfined shell */
    struct mesh_terminal_worker_config wc = {
        .shell_path = exec ? hello->argv[0] : cfg->shell_path, .workdir = cfg->workdir,
        .cols = hello->cols, .rows = hello->rows,
        .max_bytes_in = cfg->max_bytes_in, .max_bytes_out = cfg->max_bytes_out,
        .lifetime_seconds = cfg->lifetime_seconds, .idle_seconds = cfg->idle_seconds,
        .argv = exec ? hello->argv : NULL,
        .pgid_slot = cfg->worker_pgid,
    };
    if (exec && (!mesh_terminal_shell_path_valid(MESH_TERMINAL_PLATFORM_POSIX, wc.shell_path) ||
                 !hub_exec_runnable(wc.shell_path)))
        return MESH_TERMINAL_HUB_REFUSE_EXEC;
    struct zcl_result r = mesh_terminal_worker_spawn(&wc, hub_now(), &s->w);
    if (!r.ok)
        return exec && (r.code == MESH_TERMINAL_WORKER_ERR_EXEC || r.code == MESH_TERMINAL_WORKER_ERR_CONFIG)
                   ? MESH_TERMINAL_HUB_REFUSE_EXEC : MESH_TERMINAL_HUB_REFUSE_CONFINEMENT;
    s->pidfd = hub_pidfd_open(s->w.pid);
    if (hello->flags & MESH_TERMINAL_HUB_HELLO_QUIET)
        hub_echo_off(s);
    return 0;
}

/* poll() timeout: the nearest lifetime/idle deadline, never earlier than a
 * real one (worker clocks are whole seconds, now_unix truncates down). */
static int hub_timeout_ms(const struct hub_sess *s)
{
    const struct mesh_terminal_worker *w = &s->w;
    int64_t now = hub_now(), next = INT64_MAX;
    if (w->lifetime_seconds)
        next = w->started_unix + (int64_t)w->lifetime_seconds;
    if (w->idle_seconds && w->last_activity_unix + (int64_t)w->idle_seconds < next)
        next = w->last_activity_unix + (int64_t)w->idle_seconds;
    int64_t ms = next == INT64_MAX ? -1 : (next - now) * 1000;
    if (ms < 0 && next != INT64_MAX)
        ms = 0;
    if (s->pidfd < 0 && (ms < 0 || ms > HUB_FALLBACK_POLL_MS))
        ms = HUB_FALLBACK_POLL_MS;
    return ms > INT32_MAX ? INT32_MAX : (int)ms;
}

/* Keystrokes and control frames from the client. false = session over. */
static bool hub_frame_in(struct hub_sess *s, uint8_t type, const uint8_t *p, size_t len)
{
    switch (type) {
    case MESH_TERMINAL_HUB_DATA: {
        struct zcl_result r = mesh_terminal_worker_input(&s->w, p, len, hub_now());
        return r.ok || r.code != MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT;
    }
    case MESH_TERMINAL_HUB_RESIZE:
        if (len == 4)
            (void)mesh_terminal_worker_resize(
                &s->w, (uint16_t)((unsigned)p[0] << 8 | p[1]),
                (uint16_t)((unsigned)p[2] << 8 | p[3]));
        return len == 4 || (hub_force(s, MESH_TERMINAL_CLOSE_INTERNAL), false);
    case MESH_TERMINAL_HUB_CLOSE:
        hub_force(s, MESH_TERMINAL_CLOSE_REQUESTED);
        return false;
    default:
        hub_force(s, MESH_TERMINAL_CLOSE_INTERNAL);
        return false;
    }
}

static bool hub_drain_frames(struct hub_sess *s)
{
    for (;;) {
        uint8_t type;
        const uint8_t *payload;
        size_t len;
        enum hub_rx_status st = hub_rx_next(&s->rx, &type, &payload, &len);
        if (st == HUB_RX_NEED_MORE)
            return true;
        if (st == HUB_RX_BAD) {
            hub_force(s, MESH_TERMINAL_CLOSE_INTERNAL);
            return false;
        }
        bool more = hub_frame_in(s, type, payload, len);
        hub_rx_consume(&s->rx, len);
        if (!more)
            return false;
    }
}

static bool hub_socket_ready(struct hub_sess *s)
{
    long got = hub_rx_read(&s->rx, s->fd);
    if (got == 0 || got == -1) {
        hub_force(s, MESH_TERMINAL_CLOSE_SESSION_LOST);
        return false;
    }
    return got == -2 || hub_drain_frames(s);
}

/* Shell output to the client: read behind the header, seal, one send. */
static bool hub_pty_ready(struct hub_sess *s, bool hung_up)
{
    for (unsigned i = 0; i < HUB_PUMP_CHUNKS; i++) {
        size_t n = 0;
        struct zcl_result r = mesh_terminal_worker_output(
            &s->w, s->out + MESH_TERMINAL_HUB_HEADER_BYTES,
            MESH_TERMINAL_HUB_PAYLOAD_MAX, &n, hub_now());
        if (n) {
            size_t total = mesh_terminal_hub_frame_seal(s->out, MESH_TERMINAL_HUB_DATA, n);
            if (!hub_io_send(s->fd, s->out, total)) {
                hub_force(s, MESH_TERMINAL_CLOSE_SESSION_LOST);
                return false;
            }
        }
        if (!r.ok)
            return false; /* byte limit: the worker named the reason */
        if (n < MESH_TERMINAL_HUB_PAYLOAD_MAX) {
            s->pty_eof = n == 0 && hung_up;
            return true;
        }
    }
    return true;
}

/* The worker's budget check reads the process census, so a keystroke must
 * not pay for it: run it on a timeout, when the shell's pidfd fires, and at
 * most once per second while the session is busy. */
static bool hub_budget_due(struct hub_sess *s, bool must)
{
    int64_t now = hub_now();
    if (!must && now == s->last_check)
        return false;
    s->last_check = now;
    return mesh_terminal_worker_budget_exceeded(&s->w, now);
}

static void hub_run(struct hub_sess *s, int stop_fd)
{
    while (!s->forced) {
        struct pollfd pfd[4] = {
            { .fd = s->fd, .events = POLLIN },
            { .fd = s->pty_eof ? -1 : s->w.master_fd, .events = POLLIN },
            { .fd = s->pidfd, .events = POLLIN },
            { .fd = stop_fd, .events = POLLIN },
        };
        int ready = poll(pfd, 4, hub_timeout_ms(s));
        if (ready < 0 && errno != EINTR) {
            hub_force(s, MESH_TERMINAL_CLOSE_INTERNAL);
        } else if (pfd[3].revents) {
            hub_force(s, MESH_TERMINAL_CLOSE_SHUTDOWN);
        } else if ((pfd[0].revents && !hub_socket_ready(s)) ||
                   (pfd[1].revents &&
                    !hub_pty_ready(s, pfd[1].revents & (POLLHUP | POLLERR))) ||
                   hub_budget_due(s, ready == 0 || pfd[2].revents)) {
            return;
        }
    }
}

static void hub_finish(struct hub_sess *s, struct mesh_terminal_hub_report *r)
{
    bool natural = !s->forced;
    if (natural || s->forced_reason == MESH_TERMINAL_CLOSE_REQUESTED) {
        s->pty_eof = false;
        (void)hub_pty_ready(s, false); /* last words of a shell that just exited */
    }
    enum mesh_terminal_close_reason why = s->forced ? s->forced_reason : s->w.close_reason;
    int code = -1, sig = 0;
    if (natural && why == MESH_TERMINAL_CLOSE_WORKER_EXITED) {
        sig = s->w.term_signal;
        code = sig ? -1 : s->w.exit_code;
    }
    mesh_terminal_worker_kill(&s->w);
    r->reason = why;
    r->exit_code = code;
    r->signal = sig;
    r->bytes_in = s->w.bytes_in;
    r->bytes_out = s->w.bytes_out;
    uint8_t body[4] = { (uint8_t)why,
        (uint8_t)((code >= 0 ? MESH_TERMINAL_HUB_EXIT_HAS_CODE : 0) |
                  (sig > 0 ? MESH_TERMINAL_HUB_EXIT_HAS_SIGNAL : 0)),
        (uint8_t)(code >= 0 ? code : 0), (uint8_t)sig };
    (void)hub_io_send_frame(s->fd, MESH_TERMINAL_HUB_EXIT, body, sizeof body);
}

static void hub_serve_fd_arm(int fd,
                                const struct mesh_terminal_hub_serve_cfg *cfg,
                                struct mesh_terminal_hub_report *report)
{
    struct hub_sess s = { .fd = fd, .pidfd = -1 };
    struct mesh_terminal_hub_hello hello;
    memset(report, 0, sizeof(*report));
    report->exit_code = -1;
    report->start_unix = hub_now();
    report->reason = MESH_TERMINAL_CLOSE_INTERNAL;
    snprintf(report->exec, sizeof report->exec, "-");
    hub_socket_prepare(fd);
    if (hub_admit(&s, cfg, report, &hello)) {
        snprintf(report->name, sizeof report->name, "%s", hello.name);
        mesh_terminal_hub_exec_label(report->exec, sizeof report->exec, hello.argv, hello.argc);
        int refusal = hub_start_worker(&s, cfg, &hello);
        if (refusal) {
            hub_refuse(fd, report, refusal);
        } else if (hub_io_send_frame(fd, MESH_TERMINAL_HUB_READY, NULL, 0)) {
            report->admitted = true;
            if (hub_drain_frames(&s))
                hub_run(&s, cfg->stop_fd);
            hub_finish(&s, report);
        } else {
            mesh_terminal_worker_kill(&s.w);
        }
    }
    if (s.pidfd >= 0)
        close(s.pidfd);
    report->end_unix = hub_now();
}

static int hub_listen_arm(uint16_t port, uint16_t *bound_port)
{
    int fd = hub_tcp_socket_cloexec();
    int one = 1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t alen = sizeof a;
    if (fd < 0)
        return -1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 16) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        close(fd);
        return -1;
    }
    if (bound_port)
        *bound_port = ntohs(a.sin_port);
    return fd;
}

/* ── Supervisor ───────────────────────────────────────────────────────── */

static int g_hub_signal_pipe[2] = { -1, -1 };

static void hub_on_signal(int sig)
{
    int saved = errno;
    char c = sig == SIGCHLD ? 'C' : 'T';
    if (g_hub_signal_pipe[1] >= 0)
        (void)!write(g_hub_signal_pipe[1], &c, 1);
    errno = saved;
}

/* The supervisor also wants SIGCHLD; a session child must not (the shell's
 * exit is its own business and a stray byte would read as a stop). */
static bool hub_signals_install(bool watch_children)
{
    struct sigaction act = { .sa_handler = hub_on_signal, .sa_flags = SA_NOCLDSTOP };
    sigemptyset(&act.sa_mask);
    if (hub_pipe_cloexec_nonblock(g_hub_signal_pipe) != 0)
        return false;
    if (watch_children)
        sigaction(SIGCHLD, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    signal(SIGPIPE, SIG_IGN);
    return true;
}

static void hub_signals_reset(void)
{
    signal(SIGCHLD, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    close(g_hub_signal_pipe[0]);
    close(g_hub_signal_pipe[1]);
    g_hub_signal_pipe[0] = g_hub_signal_pipe[1] = -1;
}

#define HUB_AUDIT_WAIT_MS 2000
#define HUB_STOP_GRACE_MS 5000
#define HUB_EXIT_AUDIT_DROPPED 3 /* a session child whose audit line was dropped */

#if defined(ZCL_TESTING)
static bool g_children_ignore_term;

void mesh_terminal_hub_testing_children_ignore_term(bool ignore)
{
    g_children_ignore_term = ignore;
}

static void (*g_before_freeze)(const pid_t *kids, unsigned n);

void mesh_terminal_hub_testing_before_freeze(void (*hook)(const pid_t *kids, unsigned n))
{
    g_before_freeze = hook;
}
#endif

static int64_t hub_mono_ms(void)
{
    return platform_time_monotonic_ms();
}

/* One audit line, bounded. The sink is shared (a pipe nobody drains, or one
 * other sessions are also filling), so readiness proves nothing: the line is
 * tried without blocking (the descriptor keeps its flags) and, on EAGAIN,
 * waited for with poll
 * against one absolute deadline. Dropped, and false, when wait_ms passes. Audit
 * lines are far below PIPE_BUF, so a pipe write is atomic: lines of concurrent
 * sessions never interleave. */
static bool hub_audit_write(int fd, const char *line, size_t n, int wait_ms)
{
    struct hub_wfd w;
    int64_t deadline = hub_mono_ms() + (wait_ms > 0 ? wait_ms : HUB_AUDIT_WAIT_MS);
    hub_wfd_open(&w, fd);
    return hub_wfd_write(&w, line, n, deadline);
}

/* A session child: its own stop pipe, so SIGTERM from the supervisor ends
 * the session through the normal path and the worker's group is killed. */
static void hub_child(int fd, int listener, volatile pid_t *worker_pgid,
                      const struct mesh_terminal_hub_listen_cfg *cfg)
{
    struct mesh_terminal_hub_serve_cfg serve = cfg->serve;
    struct mesh_terminal_hub_report report;
    char line[768];
    close(listener);
    hub_signals_reset();
    serve.worker_pgid = worker_pgid;
    if (hub_signals_install(false))
        serve.stop_fd = g_hub_signal_pipe[0];
#if defined(ZCL_TESTING)
    if (g_children_ignore_term) {
        signal(SIGTERM, SIG_IGN);
        serve.stop_fd = -1;
    }
#endif
    mesh_terminal_hub_serve_fd(fd, &serve, &report);
    size_t n = mesh_terminal_hub_audit_line(line, sizeof line - 1u, &report);
    line[n++] = '\n';
    _exit(hub_audit_write(cfg->audit_fd, line, n, cfg->audit_wait_ms) ? 0 : HUB_EXIT_AUDIT_DROPPED);
}

static void hub_busy(int fd)
{
    uint8_t c = MESH_TERMINAL_HUB_REFUSE_BUSY;
    hub_socket_nosigpipe(fd); /* never reaches hub_socket_prepare */
    (void)hub_io_send_frame(fd, MESH_TERMINAL_HUB_REFUSE, &c, 1);
}

struct hub_sup {
    unsigned active, started, done, audit_dropped;
    bool stopping;
    pid_t kids[MESH_TERMINAL_HUB_ACTIVE_MAX];
    /* Shared with the children: each child's worker group id (see
     * mesh_terminal_hub_serve_cfg.worker_pgid), index-matched to kids. */
    volatile pid_t *pgids;
};

static void hub_sup_gone(struct hub_sup *sup, pid_t pid, int status)
{
    for (unsigned i = 0; i < MESH_TERMINAL_HUB_ACTIVE_MAX; i++)
        if (sup->kids[i] == pid) {
            sup->kids[i] = 0;
            sup->pgids[i] = 0;
            sup->active--;
            sup->done++;
            if (WIFEXITED(status) && WEXITSTATUS(status) == HUB_EXIT_AUDIT_DROPPED)
                sup->audit_dropped++;
        }
}

static void hub_sup_reap(struct hub_sup *sup)
{
    pid_t pid;
    int status = 0;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        hub_sup_gone(sup, pid, status);
}

/* Every accepted connection counts toward max_sessions, a busy refusal and a
 * failed fork included: the limit bounds attempts, not authenticated users.
 * Residual: a connection counts and holds an active slot before it has
 * authenticated, so up to max_active unauthenticated peers can hold every
 * slot for the handshake time (MESH_TERMINAL_HUB_HANDSHAKE_MS, 2 s each) and
 * can spend max_sessions. The tunnel in front is the access control. */
static void hub_sup_accept(struct hub_sup *sup, int listener,
                           const struct mesh_terminal_hub_listen_cfg *cfg)
{
    int fd = hub_accept_cloexec(listener);
    unsigned limit = cfg->max_active < MESH_TERMINAL_HUB_ACTIVE_MAX
                         ? cfg->max_active : MESH_TERMINAL_HUB_ACTIVE_MAX;
    if (fd < 0)
        return;
    sup->started++;
    if (sup->active >= limit) {
        hub_busy(fd);
        close(fd);
        return;
    }
    unsigned slot = 0;
    while (slot + 1 < MESH_TERMINAL_HUB_ACTIVE_MAX && sup->kids[slot])
        slot++;
    pid_t pid = fork();
    if (pid == 0)
        hub_child(fd, listener, &sup->pgids[slot], cfg);
    close(fd);
    if (pid < 0)
        return;
    sup->kids[slot] = pid;
    sup->active++;
}

/* A stop request and finished children arrive as bytes on the signal pipe. */
static void hub_sup_signals(struct hub_sup *sup)
{
    char sig[16];
    ssize_t n = read(g_hub_signal_pipe[0], sig, sizeof sig);
    for (ssize_t i = 0; i < n; i++)
        sup->stopping = sup->stopping || sig[i] == 'T';
    hub_sup_reap(sup);
}

/* A session that outlived its grace owns a worker group of its own (the
 * worker leads a separate group), which killing the session would orphan.
 * All live sessions are frozen first (SIGSTOP), then confirmed stopped
 * against ONE shared deadline, so N wedged sessions cost one deadline and
 * not N. A frozen session cannot reap its worker leader (the thing that
 * releases the group id) between the read of its slot and the kill, so a
 * non-zero slot names a group whose leader still holds the id. The one case
 * that breaks that is a session already dead (killed from outside): its
 * worker leader may have been reparented and reaped by init and the id
 * recycled, so a session that has exited (still our unreaped zombie, so its
 * own pid is safe) has its slot skipped.
 *
 * Residual window: the worker publishes its slot right after fork() (see
 * mesh_terminal_worker.c), with no syscall between the two. A stop landing in
 * that window sees 0 and skips the killpg; the session's SIGKILL then closes
 * its pty master, which hangs up the worker's controlling terminal (SIGHUP to
 * its foreground group). Only a worker that ignores HUP could survive, and only
 * if the stop landed inside those few instructions.
 *
 * Residual window: the freeze is bounded (HUB_FREEZE_MS). A session that has
 * not stopped by then is killed on its slot anyway; if it was still running it
 * could reap its worker leader between our read of the slot and the kill, and
 * the group id could in principle be recycled to an unrelated group. That needs
 * a wedged session and a pid wrap inside the same few milliseconds. */
#define HUB_FREEZE_MS 200
#define HUB_FREEZE_STEP_MS 10

/* True once the session is stopped or gone: it reports stopped or exited, or
 * is no longer ours to wait on. */
static bool hub_sup_settled(pid_t pid)
{
    siginfo_t si = { 0 };
    return waitid(P_PID, (id_t)pid, &si, WEXITED | WSTOPPED | WNOHANG | WNOWAIT) != 0 ||
           si.si_pid != 0;
}

static bool hub_sup_exited(pid_t pid)
{
    siginfo_t si = { 0 };
    return waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT) != 0 || si.si_pid != 0;
}

static void hub_sup_freeze_all(const struct hub_sup *sup)
{
    int64_t until = hub_mono_ms() + HUB_FREEZE_MS;
    bool all = false;
    for (unsigned i = 0; i < MESH_TERMINAL_HUB_ACTIVE_MAX; i++)
        if (sup->kids[i])
            (void)kill(sup->kids[i], SIGSTOP);
    while (!all && hub_mono_ms() < until) {
        all = true;
        for (unsigned i = 0; i < MESH_TERMINAL_HUB_ACTIVE_MAX; i++)
            all = all && (!sup->kids[i] || hub_sup_settled(sup->kids[i]));
        if (!all)
            (void)poll(NULL, 0, HUB_FREEZE_STEP_MS); /* real-clock: a stop is a kernel event with no fd */
    }
}

static void hub_sup_kill_worker(const struct hub_sup *sup, unsigned i)
{
    pid_t pgid = sup->pgids[i];
    if (pgid > 1 && !hub_sup_exited(sup->kids[i]))
        (void)kill(-pgid, SIGKILL);
}

/* Ends the sessions: SIGTERM lets each close through its normal path, and a
 * session still running when the grace is up is frozen, its worker group
 * killed, then itself killed and reaped with the bounded reap, so a wedged
 * session cannot hold the supervisor forever. */
static void hub_sup_stop(struct hub_sup *sup, int grace_ms)
{
    int64_t deadline = hub_mono_ms() + (grace_ms > 0 ? grace_ms : HUB_STOP_GRACE_MS);
    for (unsigned i = 0; i < MESH_TERMINAL_HUB_ACTIVE_MAX; i++)
        if (sup->kids[i])
            (void)kill(sup->kids[i], SIGTERM);
    hub_sup_reap(sup);
    while (sup->active && hub_mono_ms() < deadline) {
        struct pollfd pfd = { .fd = g_hub_signal_pipe[0], .events = POLLIN };
        int64_t left = deadline - hub_mono_ms();
        if (poll(&pfd, 1, (int)(left > 0 ? left : 0)) > 0)
            hub_sup_signals(sup);
        else
            hub_sup_reap(sup);
    }
#if defined(ZCL_TESTING)
    if (g_before_freeze)
        g_before_freeze(sup->kids, MESH_TERMINAL_HUB_ACTIVE_MAX);
#endif
    hub_sup_freeze_all(sup);
    for (unsigned i = 0; i < MESH_TERMINAL_HUB_ACTIVE_MAX; i++) {
        pid_t pid = sup->kids[i];
        int status = 0;
        if (pid)
            hub_sup_kill_worker(sup, i);
        if (pid && resident_launch_kill_reap((uint64_t)pid, RESIDENT_REAP_GRACE_MS, &status))
            hub_sup_gone(sup, pid, status);
    }
}

/* One blocking wait: a signal byte or a connection. false on a poll failure. */
static bool hub_sup_step(struct hub_sup *sup, int listener,
                         const struct mesh_terminal_hub_listen_cfg *cfg, bool full)
{
    struct pollfd pfd[2] = { { .fd = g_hub_signal_pipe[0], .events = POLLIN },
                             { .fd = full ? -1 : listener, .events = POLLIN } };
    if (poll(pfd, 2, -1) < 0 && errno != EINTR)
        return false;
    if (pfd[0].revents)
        hub_sup_signals(sup);
    if (pfd[1].revents && !sup->stopping)
        hub_sup_accept(sup, listener, cfg);
    return true;
}

/* Audit lines that were dropped for want of a sink are counted, and the count
 * is the one thing said about them, on stderr and itself time-bounded. */
static void hub_sup_report_dropped(const struct hub_sup *sup)
{
    char line[96];
    if (!sup->audit_dropped || !hub_wfd_sink_bounded(STDERR_FILENO))
        return;
    int n = snprintf(line, sizeof line, "event=TERMINAL_HUB_AUDIT_DROPPED count=%u\n",
                     sup->audit_dropped);
    if (n > 0)
        (void)hub_audit_write(STDERR_FILENO, line, (size_t)n, 200);
}

static int hub_listen_run_arm(int listener,
                                 const struct mesh_terminal_hub_listen_cfg *cfg)
{
    struct hub_sup sup = { 0 };
    size_t map_len = sizeof(pid_t) * MESH_TERMINAL_HUB_ACTIVE_MAX;
    void *map = listener < 0 || !cfg ? MAP_FAILED
                    : mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED || !hub_wfd_sink_bounded(cfg->audit_fd) || !hub_signals_install(true)) {
        if (map != MAP_FAILED)
            munmap(map, map_len);
        if (listener >= 0)
            close(listener);
        return 1;
    }
    sup.pgids = map;
    while (!sup.stopping) {
        bool full = cfg->max_sessions && sup.started >= cfg->max_sessions;
        if ((full && sup.active == 0) || !hub_sup_step(&sup, listener, cfg, full))
            break;
    }
    hub_sup_stop(&sup, cfg->stop_grace_ms);
    hub_sup_report_dropped(&sup);
    hub_signals_reset();
    munmap(map, map_len);
    close(listener);
    return 0;
}

#endif /* !_WIN32 */

void mesh_terminal_hub_serve_fd(int fd,
                                const struct mesh_terminal_hub_serve_cfg *cfg,
                                struct mesh_terminal_hub_report *report)
{
    hub_serve_fd_arm(fd, cfg, report);
}

int mesh_terminal_hub_listen(uint16_t port, uint16_t *bound_port)
{
    return hub_listen_arm(port, bound_port);
}

int mesh_terminal_hub_listen_run(int listener,
                                 const struct mesh_terminal_hub_listen_cfg *cfg)
{
    return hub_listen_run_arm(listener, cfg);
}
