/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Residual bounds for the terminal hub, run from test_mesh_terminal_hub: a
 * stopped supervisor leaves no worker group behind, every hub write is
 * bounded by its deadline even when another writer wins the readiness, and
 * max_sessions counts every accepted connection (a busy refusal included).
 * The write races are made exact with the before-write seam: the hook fills
 * the pipe between "ready" and "write", which is what a second writer does. */

#define _GNU_SOURCE

#include "test/test_core.h"
#include "session/mesh_terminal_hub.h"
#include "../../../cognition/modules/session/src/mesh_terminal_hub_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *g_fbsh;
static const char *g_dir;
static int g_note_fd = -1;

static int check(int failures, bool ok, const char *label)
{
    printf("  %s... %s\n", label, ok ? "OK" : "FAIL");
    return failures + (ok ? 0 : 1);
}

static void base_cfg(struct mesh_terminal_hub_serve_cfg *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    for (int i = 0; i < 32; i++)
        cfg->key[i] = (uint8_t)(0x5a + i * 3);
    cfg->shell_path = g_fbsh;
    cfg->workdir = g_dir;
    cfg->max_bytes_in = 1u << 20;
    cfg->max_bytes_out = 1u << 24;
    cfg->lifetime_seconds = 60;
    cfg->idle_seconds = 30;
    cfg->stop_fd = -1;
}

static int tcp_connect(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Waits for a child to exit on its own; kills it when it does not. */
static bool exits_within(pid_t pid, int ms, int *status)
{
    if (pid <= 1)
        return false;
    for (int waited = 0; waited <= ms; waited += 20) {
        if (waitpid(pid, status, WNOHANG) == pid)
            return true;
        poll(NULL, 0, 20); /* real-clock: waits on another process; there is no seam to inject */
    }
    kill(pid, SIGKILL);
    waitpid(pid, status, 0);
    return false;
}

static bool readable_within(int fd, int ms)
{
    struct pollfd p = { .fd = fd, .events = POLLIN };
    return poll(&p, 1, ms) > 0;
}

/* Reads until `needle` appears in buf, within ms. */
static bool read_until(int fd, const char *needle, char *buf, size_t cap, int ms)
{
    size_t fill = 0;
    buf[0] = '\0';
    for (int waited = 0; waited < ms && fill + 1 < cap; waited += 20) {
        ssize_t n = readable_within(fd, 20) ? read(fd, buf + fill, cap - fill - 1) : 0;
        if (n > 0) {
            fill += (size_t)n;
            buf[fill] = '\0';
        }
        if (strstr(buf, needle))
            return true;
    }
    return false;
}

/* Members of a process group that are running (a zombie is already dead). */
static unsigned group_running(pid_t pgid)
{
    unsigned live = 0;
    DIR *proc = opendir("/proc");
    struct dirent *ent;
    while (proc && (ent = readdir(proc)) != NULL) {
        char path[64], buf[512];
        long pid = strtol(ent->d_name, NULL, 10);
        if (pid <= 0)
            continue;
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        int fd = open(path, O_RDONLY);
        ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
        if (fd >= 0)
            close(fd);
        const char *after = n > 0 ? (buf[n] = '\0', strrchr(buf, ')')) : NULL;
        char state = 0;
        long ppid = 0, pgrp = 0;
        if (after && sscanf(after + 1, " %c %ld %ld", &state, &ppid, &pgrp) == 3 && pgrp == pgid && state != 'Z')
            live++;
    }
    if (proc)
        closedir(proc);
    return live;
}

/* The production client in a child, on pipes. */
struct cl {
    pid_t pid;
    int keys_w, screen_r, res_r, ev_w;
};

static bool cl_start(struct cl *c, int net_fd, int drop_fd, const char *const *argv)
{
    int keys[2], screen[2], res[2], ev[2];
    if (pipe2(keys, O_CLOEXEC) || pipe2(screen, O_CLOEXEC) || pipe2(res, O_CLOEXEC) || pipe2(ev, O_CLOEXEC))
        return false;
    c->pid = fork();
    if (c->pid == 0) {
        struct mesh_terminal_hub_client_cfg cfg;
        struct mesh_terminal_hub_client_result r;
        struct mesh_terminal_hub_serve_cfg sc;
        if (drop_fd >= 0)
            close(drop_fd);
        base_cfg(&sc);
        memset(&cfg, 0, sizeof cfg);
        memcpy(cfg.key, sc.key, sizeof cfg.key);
        cfg.name = "bounds";
        cfg.argv = argv;
        cfg.net_fd = net_fd;
        cfg.in_fd = keys[0];
        cfg.out_fd = screen[1];
        cfg.event_fd = ev[0];
        cfg.handshake_ms = 5000;
        mesh_terminal_hub_client_run(&cfg, &r);
        ssize_t w = write(res[1], &r, sizeof r);
        _exit(w == (ssize_t)sizeof r ? 0 : 1);
    }
    close(keys[0]); close(screen[1]); close(res[1]); close(ev[0]);
    c->keys_w = keys[1];
    c->screen_r = screen[0];
    c->res_r = res[0];
    c->ev_w = ev[1];
    return c->pid > 0;
}

static void cl_end(struct cl *c)
{
    int st;
    if (c->pid > 1) {
        kill(c->pid, SIGKILL);
        waitpid(c->pid, &st, 0);
    }
    close(c->keys_w); close(c->screen_r); close(c->res_r); close(c->ev_w);
}

/* ── the hook: a second writer wins the readiness ─────────────────────── */

static void fill_pipe_fd(int fd)
{
    char chunk[4096];
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode))
        return;
    memset(chunk, 'f', sizeof chunk);
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    while (write(fd, chunk, sizeof chunk) > 0) {}
    fcntl(fd, F_SETFL, fl);
}

static void note(void)
{
    ssize_t w = g_note_fd >= 0 ? write(g_note_fd, "!", 1) : 0;
    (void)w;
}

static void hook_fill(int fd)
{
    fill_pipe_fd(fd);
    note();
}

static void hook_fill_second(int fd)
{
    static int calls;
    if (++calls == 2)
        hook_fill(fd);
}

/* ── supervisor rigs shared by the stop and count cases ───────────────── */

/* Forks a supervisor on a fresh loopback listener; `prep` runs in the child
 * first (test seams). -1 when there is no listener or no fork. */
static pid_t sup_start(const struct mesh_terminal_hub_listen_cfg *cfg, uint16_t *port, void (*prep)(void))
{
    int listener = mesh_terminal_hub_listen(0, port);
    pid_t sup = listener < 0 ? -1 : fork();
    if (sup == 0) {
        if (prep)
            prep();
        _exit(mesh_terminal_hub_listen_run(listener, cfg));
    }
    if (listener >= 0)
        close(listener);
    return sup;
}

static void prep_wedged(void)
{
    mesh_terminal_hub_testing_children_ignore_term(true); /* a wedged session */
}

static unsigned children_of(pid_t parent, pid_t *out, unsigned cap);

/* The worker leader's group id as the host sees it. The shell runs in its own
 * PID namespace, so the PGID=<n> it announces is namespace-local and is only
 * the readiness signal; the real group is the setsid leader that is a child of
 * one of the supervisor's session processes. */
static bool read_pgid(struct cl *c, pid_t sup, int *leader)
{
    char screen[256];
    pid_t sessions[8], workers[8];
    if (!read_until(c->screen_r, "\n", screen, sizeof screen, 8000) || !strstr(screen, "PGID="))
        return false;
    unsigned ns = children_of(sup, sessions, 8);
    for (unsigned i = 0; i < ns; i++) {
        unsigned nw = children_of(sessions[i], workers, 8);
        for (unsigned j = 0; j < nw; j++)
            if (getpgid(workers[j]) == workers[j]) {
                *leader = workers[j];
                return true;
            }
    }
    return false;
}
#define HUP_TRAP_RUN "trap '' HUP; echo PGID=$$; (while :; do :; done)"

static void rig_end(struct cl *c, bool up, int net, int audit_fd)
{
    if (up)
        cl_end(c);
    if (net >= 0)
        close(net);
    close(audit_fd);
}

/* True once the group has no running member (the kernel finishes a kill
 * asynchronously, so it is polled). */
static bool group_gone(pid_t pgid)
{
    for (int i = 0; i < 150 && group_running(pgid); i++)
        poll(NULL, 0, 20); /* real-clock: no seam */
    return group_running(pgid) == 0;
}

/* ── a stopped supervisor leaves no worker group ──────────────────────── */

static int stop_orphan_case(void)
{
    int failures = 0, status = 0, leader = 0;
    struct mesh_terminal_hub_listen_cfg cfg;
    struct cl c;
    uint16_t port = 0;
    const char *const run[] = { "/bin/sh", "-c", HUP_TRAP_RUN, NULL };
    memset(&cfg, 0, sizeof cfg);
    base_cfg(&cfg.serve);
    cfg.max_active = 1;
    cfg.stop_grace_ms = 300;
    cfg.audit_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    pid_t sup = cfg.audit_fd < 0 ? -1 : sup_start(&cfg, &port, prep_wedged);
    int net = sup > 0 ? tcp_connect(port) : -1;
    bool up = net >= 0 && cl_start(&c, net, -1, run);
    bool said = up && read_pgid(&c, sup, &leader);
    failures = check(failures, said && group_running(leader) >= 2,
                     "worker stop: the worker group (a HUP-ignoring leader and its child) is running");
    if (sup > 0)
        kill(sup, SIGTERM);
    bool stopped = sup > 0 && exits_within(sup, 5000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "worker stop: SIGTERM ends the supervisor although the session ignores it");
    bool gone = said && group_gone(leader);
    failures = check(failures, gone, "worker stop: the WORKER group is gone, not only the supervisor");
    if (said && !gone && leader > 1)
        kill(-leader, SIGKILL);
    rig_end(&c, up, net, cfg.audit_fd);
    return failures;
}

/* ── the audit write is bounded when another writer takes the room ────── */

static int audit_race_case(void)
{
    int failures = 0, status = 0, sink[2];
    struct mesh_terminal_hub_listen_cfg cfg;
    struct cl c;
    char errpath[300], errtext[512] = "";
    uint16_t port = 0;
    const char *const run[] = { "/bin/true", NULL };
    memset(&cfg, 0, sizeof cfg);
    base_cfg(&cfg.serve);
    cfg.max_active = 1;
    cfg.max_sessions = 1;
    cfg.audit_wait_ms = 300;
    snprintf(errpath, sizeof errpath, "%s/race-stderr.log", g_dir);
    if (pipe2(sink, O_CLOEXEC) != 0)
        return check(failures, false, "audit race setup");
    cfg.audit_fd = sink[1];
    int listener = mesh_terminal_hub_listen(0, &port);
    pid_t sup = listener < 0 ? -1 : fork();
    if (sup == 0) {
        int e = open(errpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (e >= 0)
            dup2(e, STDERR_FILENO);
        mesh_terminal_hub_testing_before_write(hook_fill); /* children inherit it */
        _exit(mesh_terminal_hub_listen_run(listener, &cfg));
    }
    close(listener);
    int net = sup > 0 ? tcp_connect(port) : -1;
    bool up = net >= 0 && cl_start(&c, net, -1, run);
    bool stopped = up && exits_within(sup, 6000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "audit race: a line whose room another writer took is dropped at its deadline");
    close(sink[0]);
    close(sink[1]);
    int fd = open(errpath, O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, errtext, sizeof errtext - 1);
    errtext[n > 0 ? n : 0] = '\0';
    if (fd >= 0)
        close(fd);
    failures = check(failures, strstr(errtext, "event=TERMINAL_HUB_AUDIT_DROPPED count=1") != NULL,
                     "audit race: the dropped line is counted");
    if (up)
        cl_end(&c);
    if (net >= 0)
        close(net);
    return failures;
}

/* ── the client's output is bounded and a stop is still served ────────── */

static void frame_out(int fd, uint8_t type, const void *payload, size_t len)
{
    uint8_t f[MESH_TERMINAL_HUB_FRAME_MAX];
    if (len)
        memcpy(f + MESH_TERMINAL_HUB_HEADER_BYTES, payload, len);
    size_t n = mesh_terminal_hub_frame_seal(f, type, len);
    ssize_t w = write(fd, f, n);
    (void)w;
}

/* A scripted server: challenge, ready, one DATA, and optionally an EXIT. */
static bool script_client(struct cl *c, int *server, void (*hook)(int), const void *exit_body)
{
    int sv[2], note_p[2];
    uint8_t ch[33] = { MESH_TERMINAL_HUB_VERSION };
    memset(ch + 1, 0x42, 32);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0 || pipe2(note_p, O_CLOEXEC) != 0)
        return false;
    g_note_fd = note_p[1];
    mesh_terminal_hub_testing_before_write(hook);
    bool ok = cl_start(c, sv[1], sv[0], NULL);
    mesh_terminal_hub_testing_before_write(NULL);
    close(sv[1]);
    close(note_p[1]);
    g_note_fd = note_p[0]; /* the parent waits on the read end */
    *server = sv[0];
    frame_out(sv[0], MESH_TERMINAL_HUB_CHALLENGE, ch, sizeof ch);
    frame_out(sv[0], MESH_TERMINAL_HUB_READY, NULL, 0);
    frame_out(sv[0], MESH_TERMINAL_HUB_DATA, "x", 1);
    if (exit_body)
        frame_out(sv[0], MESH_TERMINAL_HUB_EXIT, exit_body, 4);
    return ok;
}

static int client_stop_case(void)
{
    int failures = 0, server;
    struct cl c;
    struct mesh_terminal_hub_client_result r;
    memset(&r, 0, sizeof r);
    bool up = script_client(&c, &server, hook_fill, NULL);
    bool wedged = up && readable_within(g_note_fd, 3000);
    ssize_t w = wedged ? write(c.ev_w, "S", 1) : 0;
    (void)w;
    bool prompt = wedged && readable_within(c.res_r, 3000) && read(c.res_r, &r, sizeof r) == (ssize_t)sizeof r;
    failures = check(failures, prompt && r.exit_code == 130 && !strcmp(r.code, "INTERRUPTED"),
                     "client output: a stop is served although another writer filled the screen pipe");
    if (up)
        cl_end(&c);
    close(server);
    close(g_note_fd);
    return failures;
}

static int client_tail_case(void)
{
    static const uint8_t done[4] = { MESH_TERMINAL_CLOSE_WORKER_EXITED, 1, 0, 0 };
    int failures = 0, server;
    struct cl c;
    struct mesh_terminal_hub_client_result r;
    memset(&r, 0, sizeof r);
    bool up = script_client(&c, &server, hook_fill_second, done);
    bool filled = up && readable_within(g_note_fd, 3000);
    bool fin = filled && readable_within(c.res_r, 3000) && read(c.res_r, &r, sizeof r) == (ssize_t)sizeof r;
    failures = check(failures, fin && r.exit_code == 0 && r.output_dropped == 1,
                     "client output: the closing newline is dropped at its deadline and counted");
    if (up)
        cl_end(&c);
    close(server);
    close(g_note_fd);
    return failures;
}

/* ── max_sessions counts every accepted connection ────────────────────── */

static int busy_count_case(void)
{
    int failures = 0, status = 0;
    struct mesh_terminal_hub_listen_cfg cfg;
    struct cl c;
    char screen[64];
    uint8_t refuse[16] = { 0 };
    uint16_t port = 0;
    const char *const run[] = { "/bin/sh", "-c", "echo UP; read x", NULL };
    memset(&cfg, 0, sizeof cfg);
    base_cfg(&cfg.serve);
    cfg.max_active = 1;
    cfg.max_sessions = 2;
    cfg.audit_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    pid_t sup = cfg.audit_fd < 0 ? -1 : sup_start(&cfg, &port, NULL);
    int a = sup > 0 ? tcp_connect(port) : -1;
    bool up = a >= 0 && cl_start(&c, a, -1, run) && read_until(c.screen_r, "UP", screen, sizeof screen, 8000);
    int b = up ? tcp_connect(port) : -1;
    ssize_t got = b >= 0 && readable_within(b, 3000) ? read(b, refuse, sizeof refuse) : -1;
    failures = check(failures, got >= 4 && refuse[0] == MESH_TERMINAL_HUB_REFUSE &&
                     refuse[3] == MESH_TERMINAL_HUB_REFUSE_BUSY,
                     "max_sessions: the second connection is refused busy");
    ssize_t w = up ? write(c.keys_w, "\n", 1) : 0;
    (void)w;
    bool stopped = sup > 0 && exits_within(sup, 8000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "max_sessions: a busy refusal counts, so the supervisor stops by itself after two connections");
    if (b >= 0)
        close(b);
    rig_end(&c, up, a, cfg.audit_fd);
    return failures;
}

/* ── a session ended from outside leaves no stale-slot kill ───────────── */

/* Runs in the supervisor right after the stop grace: ends every session from
 * outside and waits until each is a zombie, so the slot of its worker group
 * is stale (the group id may by now belong to someone else). */
static void hook_end_sessions(const pid_t *kids, unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        siginfo_t si = { 0 };
        if (kids[i] <= 0)
            continue;
        kill(kids[i], SIGKILL);
        waitid(P_PID, (id_t)kids[i], &si, WEXITED | WNOWAIT);
    }
}

static void prep_stale(void)
{
    mesh_terminal_hub_testing_children_ignore_term(true);
    mesh_terminal_hub_testing_before_freeze(hook_end_sessions);
}

static int stale_slot_case(void)
{
    int failures = 0, status = 0, leader = 0;
    struct mesh_terminal_hub_listen_cfg cfg;
    struct cl c;
    uint16_t port = 0;
    const char *const run[] = { "/bin/sh", "-c", HUP_TRAP_RUN, NULL };
    memset(&cfg, 0, sizeof cfg);
    base_cfg(&cfg.serve);
    cfg.max_active = 1;
    cfg.stop_grace_ms = 200;
    cfg.audit_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    pid_t sup = cfg.audit_fd < 0 ? -1 : sup_start(&cfg, &port, prep_stale);
    int net = sup > 0 ? tcp_connect(port) : -1;
    bool up = net >= 0 && cl_start(&c, net, -1, run);
    bool said = up && read_pgid(&c, sup, &leader);
    if (sup > 0)
        kill(sup, SIGTERM);
    bool stopped = sup > 0 && exits_within(sup, 5000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "stale slot: the supervisor still stops when a session died from outside");
    failures = check(failures, said && group_running(leader) >= 1,
                     "stale slot: a group named only by a dead session's slot is not killed");
    if (said && leader > 1)
        kill(-leader, SIGKILL);
    rig_end(&c, up, net, cfg.audit_fd);
    return failures;
}

/* ── N wedged sessions cost one freeze deadline, not N ────────────────── */

#define WEDGED_N 4

/* Direct children of `parent`, from /proc. */
static unsigned children_of(pid_t parent, pid_t *out, unsigned cap)
{
    unsigned n = 0;
    DIR *proc = opendir("/proc");
    struct dirent *ent;
    while (proc && (ent = readdir(proc)) != NULL && n < cap) {
        char path[64], buf[512];
        long pid = strtol(ent->d_name, NULL, 10);
        if (pid <= 0)
            continue;
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        int fd = open(path, O_RDONLY);
        ssize_t r = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
        if (fd >= 0)
            close(fd);
        const char *after = r > 0 ? (buf[r] = '\0', strrchr(buf, ')')) : NULL;
        char state = 0;
        long ppid = 0;
        if (after && sscanf(after + 1, " %c %ld", &state, &ppid) == 2 && ppid == parent)
            out[n++] = (pid_t)pid;
    }
    if (proc)
        closedir(proc);
    return n;
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* A session that is traced and never resumed does not report SIGSTOP to its
 * parent (the stop goes to the tracer), which is how a session that cannot be
 * frozen in time looks to the supervisor. */
struct wedged {
    pid_t sup;
    struct cl c[WEDGED_N];
    int net[WEDGED_N];
    pid_t kids[WEDGED_N + 2];
    unsigned nk, seized;
    int started;
};

static void wedged_up(struct wedged *w, uint16_t port)
{
    char screen[64];
    const char *const run[] = { "/bin/sh", "-c", "echo UP; read x", NULL };
    for (int i = 0; w->sup > 0 && i < WEDGED_N; i++) {
        w->net[i] = tcp_connect(port);
        if (w->net[i] >= 0 && cl_start(&w->c[i], w->net[i], -1, run) &&
            read_until(w->c[i].screen_r, "UP", screen, sizeof screen, 8000))
            w->started++;
    }
    w->nk = w->started == WEDGED_N ? children_of(w->sup, w->kids, WEDGED_N + 2) : 0;
    for (unsigned i = 0; i < w->nk; i++)
        w->seized += ptrace(PTRACE_SEIZE, w->kids[i], 0, 0) == 0;
}

/* SIGTERM to the supervisor, then the tracer drains the tracees' events
 * without resuming them (so the killed ones can still be reaped) until the
 * supervisor exits. Returns the elapsed ms, -1 if it never did. */
static int64_t wedged_stop(const struct wedged *w, int *status)
{
    int64_t t0 = now_ms();
    kill(w->sup, SIGTERM);
    while (now_ms() - t0 < 6000) {
        for (unsigned i = 0; i < w->nk; i++)
            waitpid(w->kids[i], status, WNOHANG | __WALL);
        if (waitpid(w->sup, status, WNOHANG) == w->sup)
            return now_ms() - t0;
        poll(NULL, 0, 5); /* real-clock: the supervisor is another process; there is no seam */
    }
    return -1;
}

static int wedged_stop_case(void)
{
    int failures = 0, status = 0;
    struct mesh_terminal_hub_listen_cfg cfg;
    struct wedged w = { 0 };
    uint16_t port = 0;
    memset(&cfg, 0, sizeof cfg);
    base_cfg(&cfg.serve);
    cfg.max_active = WEDGED_N;
    cfg.stop_grace_ms = 300;
    cfg.audit_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    w.sup = cfg.audit_fd < 0 ? -1 : sup_start(&cfg, &port, prep_wedged);
    wedged_up(&w, port);
    failures = check(failures, w.nk == WEDGED_N && w.seized == WEDGED_N,
                     "wedged stop: four sessions are up and held by a tracer");
    int64_t took = w.sup > 0 ? wedged_stop(&w, &status) : -1;
    failures = check(failures, took >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "wedged stop: the supervisor ends although no session can be frozen");
    /* grace 300 + ONE 200 ms freeze deadline + the kills; N serial freezes
     * would add at least 3 x 200 ms more. */
    failures = check(failures, took >= 0 && took < 800,
                     "wedged stop: four unfreezable sessions cost one freeze deadline, not four");
    if (took < 0 && w.sup > 0) {
        kill(w.sup, SIGKILL);
        waitpid(w.sup, &status, 0);
    }
    for (int i = 0; i < w.started; i++)
        cl_end(&w.c[i]);
    for (int i = 0; i < WEDGED_N; i++)
        if (w.net[i] >= 0)
            close(w.net[i]);
    close(cfg.audit_fd);
    return failures;
}

/* ── a natural stop at max_sessions=1, and the sink's flags untouched ─── */

static int natural_stop_case(void)
{
    int failures = 0, status = 0, sink[2];
    struct mesh_terminal_hub_listen_cfg cfg;
    struct cl c;
    char screen[64], audit[512] = "";
    uint16_t port = 0;
    const char *const run[] = { "/bin/sh", "-c", "echo UP; read x", NULL };
    memset(&cfg, 0, sizeof cfg);
    base_cfg(&cfg.serve);
    cfg.max_active = 1;
    cfg.max_sessions = 1;
    if (pipe2(sink, O_CLOEXEC) != 0)
        return check(failures, false, "natural stop setup");
    cfg.audit_fd = sink[1];
    int listener = mesh_terminal_hub_listen(0, &port);
    pid_t sup = listener < 0 ? -1 : fork();
    if (sup == 0)
        _exit(mesh_terminal_hub_listen_run(listener, &cfg));
    close(listener);
    int net = sup > 0 ? tcp_connect(port) : -1;
    bool up = net >= 0 && cl_start(&c, net, -1, run) && read_until(c.screen_r, "UP", screen, sizeof screen, 8000);
    ssize_t w = up ? write(c.keys_w, "\n", 1) : 0;
    (void)w;
    bool stopped = sup > 0 && exits_within(sup, 8000, &status);
    failures = check(failures, stopped && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "max_sessions=1: one admitted session ends and the supervisor exits by itself");
    ssize_t n = read(sink[0], audit, sizeof audit - 1);
    failures = check(failures, n > 0, "max_sessions=1: the session's audit line reached the sink");
    /* the sink's open file description is shared with whoever else holds it:
     * a hub that flipped it to O_NONBLOCK must not leave it so */
    failures = check(failures, n > 0 && !(fcntl(sink[1], F_GETFL) & O_NONBLOCK),
                     "max_sessions=1: the shared audit sink is left with its own flags");
    if (up)
        cl_end(&c);
    if (net >= 0)
        close(net);
    close(sink[0]);
    close(sink[1]);
    return failures;
}

/* hub_wfd on a tty: POLLOUT can mean one free byte, so a pty whose reader has
 * stopped must not hold a write past its deadline. The writer runs in a child
 * so a regression (a PIPE_BUF write blocking in the tty) fails by timeout
 * instead of hanging the group. Also pins the mode choice: a pipe keeps the
 * RWF_NOWAIT path, a pty is polled one byte at a time. */
static int pty_write_case(void)
{
    int failures = 0;
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    int slave = -1;
    if (master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0) {
        char *name = ptsname(master);
        slave = name ? open(name, O_RDWR | O_NOCTTY) : -1;
    }
    failures = check(failures, slave >= 0, "pty write: open a pty pair");
    if (slave < 0)
        return failures;
    int pp[2];
    struct hub_wfd wp, wt;
    failures = check(failures, pipe(pp) == 0, "pty write: pipe");
    hub_wfd_open(&wp, pp[1]);
    hub_wfd_open(&wt, slave);
    failures = check(failures, wp.mode == HUB_WFD_NOWAIT && wp.fifo,
                     "pty write: a pipe keeps the RWF_NOWAIT path");
    failures = check(failures, wt.mode == HUB_WFD_POLLED && !wt.fifo,
                     "pty write: a pty is polled, not trusted with PIPE_BUF");
    close(pp[0]);
    close(pp[1]);
    pid_t pid = fork();
    if (pid == 0) {
        static uint8_t big[1u << 20];
        memset(big, 'x', sizeof big);
        /* nobody reads the master: this must give up at the deadline */
        _exit(hub_wfd_write(&wt, big, sizeof big, now_ms() + 300) ? 1 : 0);
    }
    int status = 0;
    bool done = pid > 0 && exits_within(pid, 3000, &status);
    failures = check(failures, done && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "pty write: a stopped pty reader cannot hold the write past its deadline");
    close(slave);
    close(master);
    return failures;
}

int test_mesh_terminal_hub_bounds(const char *fbsh, const char *dir)
{
    g_fbsh = fbsh;
    g_dir = dir;
    signal(SIGPIPE, SIG_IGN);
    return stop_orphan_case() + audit_race_case() + client_stop_case() +
           client_tail_case() + busy_count_case() +
           stale_slot_case() + wedged_stop_case() + natural_stop_case() +
           pty_write_case();
}

#else /* __linux__ */

int test_mesh_terminal_hub_bounds(const char *fbsh, const char *dir)
{
    (void)fbsh; (void)dir;
    return 0;
}

#endif

/* ── the non-Linux pipe write path, on every POSIX host ───────────────────
 * Off Linux there is no RWF_NOWAIT, so a hub write to a pipe is bounded only
 * if the descriptor is ALREADY O_NONBLOCK; the hub never sets or clears a flag
 * on a descriptor it does not own (the open file description is shared with
 * every other holder). A blocking shared pipe is refused up front. The
 * ZCL_TESTING selector makes Linux take this same branch, so the cases run
 * here as they run on Darwin. Writers run in a child under alarm(): a write
 * that blocks past its deadline dies of SIGALRM instead of hanging the group. */
#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fcheck(int failures, bool ok, const char *label)
{
    printf("  %s... %s\n", label, ok ? "OK" : "FAIL");
    return failures + (ok ? 0 : 1);
}

static int64_t fifo_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* A second writer takes every free byte between "ready" and the write. The
 * pipe is non-blocking here, so this never touches a flag. */
static void fifo_steal(int fd)
{
    char chunk[4096];
    memset(chunk, 's', sizeof chunk);
    while (write(fd, chunk, sizeof chunk) > 0) {}
}

static int fifo_waitstatus(pid_t pid)
{
    int status = 0;
    for (int i = 0; i < 400; i++) {
        if (waitpid(pid, &status, WNOHANG) == pid)
            return status;
        poll(NULL, 0, 20); /* real-clock: waits on another process; there is no seam to inject */
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return status;
}

/* exit 0: gave up at the deadline, flags untouched. 1: the write claimed
 * success into a full pipe. 2: the descriptor's flags changed. 3: it gave up
 * late. SIGALRM: it blocked. */
static int fifo_race_child(int wfd)
{
    struct hub_wfd w;
    int before = fcntl(wfd, F_GETFL);
    alarm(5);
    hub_wfd_open(&w, wfd);
    int64_t start = fifo_now_ms();
    bool ok = hub_wfd_write(&w, "audit line\n", 11, start + 300);
    int64_t took = fifo_now_ms() - start;
    if (ok)
        return 1;
    if (fcntl(wfd, F_GETFL) != before)
        return 2;
    return took >= 250 && took <= 1500 ? 0 : 3;
}

static int fifo_race_case(void)
{
    int p[2], failures = 0;
    mesh_terminal_hub_testing_force_polled_fifo(true);
    failures = fcheck(failures, pipe(p) == 0, "fifo race: pipe");
    if (failures)
        return failures;
    fcntl(p[1], F_SETFL, fcntl(p[1], F_GETFL) | O_NONBLOCK); /* the inherited, already non-blocking sink */
    struct hub_wfd probe;
    hub_wfd_open(&probe, p[1]);
    failures = fcheck(failures, probe.mode == HUB_WFD_PLAIN && probe.fifo,
                      "fifo race: an already non-blocking pipe is written without waiting");
    mesh_terminal_hub_testing_after_ready(fifo_steal);
    pid_t pid = fork();
    if (pid == 0)
        _exit(fifo_race_child(p[1]));
    int status = pid > 0 ? fifo_waitstatus(pid) : -1;
    mesh_terminal_hub_testing_after_ready(NULL);
    failures = fcheck(failures, WIFEXITED(status) && WEXITSTATUS(status) == 0,
                      "fifo race: a second writer takes the room, the write ends at its deadline, flags unchanged");
    close(p[0]);
    close(p[1]);
    mesh_terminal_hub_testing_force_polled_fifo(false);
    return failures;
}

/* A blocking pipe shared with other holders cannot be bounded without a flag
 * change the hub will not make: it is refused and its flags are left alone. */
static int fifo_refuse_case(void)
{
    int p[2], failures = 0;
    mesh_terminal_hub_testing_force_polled_fifo(true);
    failures = fcheck(failures, pipe(p) == 0, "fifo refuse: pipe");
    if (failures)
        return failures;
    int before = fcntl(p[1], F_GETFL);
    failures = fcheck(failures, !hub_wfd_sink_bounded(p[1]) && fcntl(p[1], F_GETFL) == before,
                      "fifo refuse: a blocking shared pipe is refused and its flags are untouched");
    fcntl(p[1], F_SETFL, before | O_NONBLOCK);
    failures = fcheck(failures, hub_wfd_sink_bounded(p[1]),
                      "fifo refuse: the same pipe made non-blocking by its owner is accepted");
    mesh_terminal_hub_testing_force_polled_fifo(false);
    failures = fcheck(failures, hub_wfd_sink_bounded(p[1]), "fifo refuse: Linux keeps RWF_NOWAIT and accepts any pipe");
    close(p[0]);
    close(p[1]);
    return failures;
}

/* Fills a pipe to the brim without changing the flags it is left with. */
static void fifo_fill_full(int wfd)
{
    int fl = fcntl(wfd, F_GETFL);
    fcntl(wfd, F_SETFL, fl | O_NONBLOCK);
    fifo_steal(wfd);
    fcntl(wfd, F_SETFL, fl);
}

/* The server on a blocking audit pipe must refuse to start with the typed
 * outcome, not run and block. With audit_to_stderr the rejected sink IS
 * stderr, and stderr is a FULL blocking pipe nobody reads: the refusal must
 * not write (log) through it, or it would hang refusing itself. */
static int fifo_serve_one(bool audit_to_stderr, const char *label)
{
    int p[2], q[2], failures = 0;
    uint16_t port = 0;
    mesh_terminal_hub_testing_force_polled_fifo(true);
    failures = fcheck(failures, pipe(p) == 0 && pipe(q) == 0, "fifo serve: pipes");
    int listener = failures ? -1 : mesh_terminal_hub_listen(0, &port);
    if (listener < 0)
        return failures + fcheck(0, false, "fifo serve: listener");
    fifo_fill_full(audit_to_stderr ? q[1] : p[1]);
    pid_t pid = fork();
    if (pid == 0) {
        struct mesh_terminal_hub_listen_cfg cfg;
        memset(&cfg, 0, sizeof cfg);
        if (audit_to_stderr)
            dup2(q[1], STDERR_FILENO);
        cfg.audit_fd = audit_to_stderr ? STDERR_FILENO : p[1];
        alarm(5);
        _exit(mesh_terminal_hub_listen_run(listener, &cfg) == MESH_TERMINAL_HUB_LISTEN_SINK_UNBOUNDED ? 0 : 1);
    }
    int status = pid > 0 ? fifo_waitstatus(pid) : -1;
    failures = fcheck(failures, WIFEXITED(status) && WEXITSTATUS(status) == 0, label);
    close(listener);
    close(p[0]); close(p[1]); close(q[0]); close(q[1]);
    mesh_terminal_hub_testing_force_polled_fifo(false);
    return failures;
}

/* The client never writes to, or flips, a blocking pipe it did not open: it
 * refuses before the session starts (typed OUTPUT_UNBOUNDED, exit 2). A pipe
 * that is already non-blocking is accepted (the run then fails later, at the
 * unanswered handshake, with a different code). */
static int fifo_client_case(void)
{
    int p[2], sv[2], failures = 0;
    mesh_terminal_hub_testing_force_polled_fifo(true);
    failures = fcheck(failures, pipe(p) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "fifo client: pipe");
    if (failures)
        return failures;
    int before = fcntl(p[1], F_GETFL);
    pid_t pid = fork();
    if (pid == 0) {
        struct mesh_terminal_hub_client_cfg cfg;
        struct mesh_terminal_hub_client_result res;
        memset(&cfg, 0, sizeof cfg);
        cfg.net_fd = sv[0];
        cfg.in_fd = -1;
        cfg.out_fd = p[1];
        cfg.event_fd = -1;
        cfg.handshake_ms = 200;
        alarm(5);
        mesh_terminal_hub_client_run(&cfg, &res);
        char c;
        bool blocked_ok = !strcmp(res.code, "OUTPUT_UNBOUNDED") && res.exit_code == 2 &&
                          fcntl(p[1], F_GETFL) == before;
        fcntl(p[0], F_SETFL, O_NONBLOCK);
        _exit(blocked_ok && read(p[0], &c, 1) < 0 ? 0 : 1);
    }
    int status = pid > 0 ? fifo_waitstatus(pid) : -1;
    failures = fcheck(failures, WIFEXITED(status) && WEXITSTATUS(status) == 0,
                      "fifo client: a blocking stdout pipe is refused (OUTPUT_UNBOUNDED, exit 2), untouched and unwritten");
    fcntl(p[1], F_SETFL, before | O_NONBLOCK);
    pid = fork();
    if (pid == 0) {
        struct mesh_terminal_hub_client_cfg cfg;
        struct mesh_terminal_hub_client_result res;
        memset(&cfg, 0, sizeof cfg);
        cfg.net_fd = sv[0];
        cfg.in_fd = -1;
        cfg.out_fd = p[1];
        cfg.event_fd = -1;
        cfg.handshake_ms = 200;
        alarm(5);
        mesh_terminal_hub_client_run(&cfg, &res);
        _exit(strcmp(res.code, "OUTPUT_UNBOUNDED") != 0 ? 0 : 1);
    }
    status = pid > 0 ? fifo_waitstatus(pid) : -1;
    failures = fcheck(failures, WIFEXITED(status) && WEXITSTATUS(status) == 0,
                      "fifo client: an already non-blocking stdout pipe is accepted");
    close(p[0]); close(p[1]); close(sv[0]); close(sv[1]);
    mesh_terminal_hub_testing_force_polled_fifo(false);
    return failures;
}

int test_mesh_terminal_hub_fifo_bounds(void)
{
    signal(SIGPIPE, SIG_IGN);
    return fifo_race_case() + fifo_refuse_case() + fifo_client_case() +
           fifo_serve_one(false, "fifo serve: a blocking audit pipe makes the supervisor refuse to start (typed exit 2)") +
           fifo_serve_one(true, "fifo serve: stderr as a FULL blocking audit sink is refused without writing to it");
}

#endif /* !_WIN32 */
