/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: `z23 ops mesh terminal connect` — the lead's side of the terminal
 * hub. This file owns the process edge only: the transport (a direct loopback
 * socket, or the device-host client run as a child on a socket pair), termios
 * raw mode, SIGWINCH and the termination signals turned into bytes on a pipe,
 * and the one-line error. The session loop is mesh_terminal_hub_client.c. */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#define _GNU_SOURCE

#include "command/native_command.h"
#include "native_mesh_terminal_hub.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/resident_launch.h"
#include "session/mesh_terminal_hub.h"
#include "session/mesh_terminal_hub_portable.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>

#define CONNECT_REAP_MS 3000
#define CONNECT_ARG_MAX 1100
#define CONNECT_POLL_STEP_MS 10
#define CONNECT_NOPIDFD_GRACE_MS 200 /* the graceful wait when no pidfd can watch the child */

static int g_event_write = -1;

static void connect_on_winch(int sig)
{
    int saved = errno;
    char c = sig == SIGWINCH ? 'W' : 'S';
    if (g_event_write >= 0)
        (void)!write(g_event_write, &c, 1);
    errno = saved;
}

static bool connect_window(void *ctx, uint16_t *cols, uint16_t *rows)
{
    struct winsize ws;
    (void)ctx;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) != 0 || !ws.ws_col || !ws.ws_row)
        return false;
    *cols = ws.ws_col > MESH_TERMINAL_MAX_COLS ? MESH_TERMINAL_MAX_COLS : ws.ws_col;
    *rows = ws.ws_row > MESH_TERMINAL_MAX_ROWS ? MESH_TERMINAL_MAX_ROWS : ws.ws_row;
    return true;
}

struct connect_edge {
    struct termios saved;
    bool raw;
    struct sigaction winch, term, hup, intr, pipe;
    int events[2];
};

static void connect_raw(struct connect_edge *e)
{
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &e->saved) != 0)
        return;
    struct termios t = e->saved;
    t.c_iflag &= ~(tcflag_t)(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    t.c_oflag &= ~(tcflag_t)OPOST;
    t.c_lflag &= ~(tcflag_t)(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t.c_cflag &= ~(tcflag_t)(CSIZE | PARENB);
    t.c_cflag |= CS8;
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    e->raw = tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) == 0;
}

static bool connect_edge_open(struct connect_edge *e)
{
    struct sigaction act = { .sa_handler = connect_on_winch };
    sigemptyset(&act.sa_mask);
    if (hub_pipe_cloexec_nonblock(e->events) != 0)
        return false;
    g_event_write = e->events[1];
    sigaction(SIGWINCH, &act, &e->winch);
    sigaction(SIGTERM, &act, &e->term);
    sigaction(SIGHUP, &act, &e->hup);
    sigaction(SIGINT, &act, &e->intr);
    signal(SIGPIPE, SIG_IGN);
    connect_raw(e);
    return true;
}

static void connect_edge_close(struct connect_edge *e)
{
    if (e->raw)
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &e->saved);
    sigaction(SIGWINCH, &e->winch, NULL);
    sigaction(SIGTERM, &e->term, NULL);
    sigaction(SIGHUP, &e->hup, NULL);
    sigaction(SIGINT, &e->intr, NULL);
    g_event_write = -1;
    close(e->events[0]);
    close(e->events[1]);
}

static int connect_direct(uint16_t port)
{
    int fd = hub_tcp_socket_cloexec(), one = 1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    if (fd >= 0)
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

struct tunnel {
    pid_t pid;
    int net_fd, err_fd;
};

/* "--input-file=<route>" for the device-host client; false (nothing written
 * past cap) when it does not fit, so a cut path is never handed to a spawn. */
bool zcl_native_hub_route_arg(const char *route, char *out, size_t cap)
{
    int n = snprintf(out, cap, "--input-file=%s", route);
    return n > 0 && (size_t)n < cap;
}

/* The existing device-host client, byte for byte as ProxyCommand runs it, on
 * one end of a socket pair; this process speaks the hub protocol on the other. */
static bool tunnel_open(const char *route_input, struct tunnel *t)
{
    char self[1024], arg[CONNECT_ARG_MAX];
    int sv[2], errp[2];
    bool have_self = os_proc_exe_path(self, sizeof self);
    struct stat st;
    if (!have_self || !zcl_native_hub_route_arg(route_input, arg, sizeof arg) ||
        stat(route_input, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    if (hub_socketpair_cloexec(sv) != 0)
        return false;
    if (hub_pipe_cloexec_nonblock(errp) != 0) {
        close(sv[0]);
        close(sv[1]);
        return false;
    }
    t->pid = fork();
    if (t->pid < 0) {
        int saved = errno;
        close(sv[0]);
        close(sv[1]);
        close(errp[0]);
        close(errp[1]);
        errno = saved;
        return false;
    }
    if (t->pid == 0) {
        char *const argv[] = { (char *)"z23", (char *)"ops", (char *)"mesh", (char *)"device",
                               (char *)"host", (char *)"client", arg, NULL };
        if (dup2(sv[1], 0) < 0 || dup2(sv[1], 1) < 0 || dup2(errp[1], 2) < 0)
            _exit(127);
        execv(self, argv);
        _exit(127);
    }
    close(sv[1]);
    close(errp[1]);
    t->net_fd = sv[0];
    t->err_fd = errp[0];
    return t->pid > 0;
}

/* The last "error=" line the tunnel wrote, for the one human line. */
static void tunnel_said(const struct tunnel *t, char *out, size_t cap)
{
    char buf[512];
    ssize_t n = read(t->err_fd, buf, sizeof buf - 1u);
    out[0] = '\0';
    if (n <= 0)
        return;
    buf[n] = '\0';
    char *line = strstr(buf, "error=");
    if (!line)
        return;
    line[strcspn(line, "\r\n")] = '\0';
    snprintf(out, cap, " (tunnel: %s)", line);
}

#if defined(ZCL_TESTING)
static bool g_pidfd_unavailable;

void zcl_native_hub_testing_pidfd_unavailable(bool unavailable)
{
    g_pidfd_unavailable = unavailable;
}
#endif

static int tunnel_pidfd(pid_t pid)
{
#if defined(ZCL_TESTING)
    if (g_pidfd_unavailable)
        return -1;
#endif
    return hub_pidfd_open(pid);
}

/* Without pidfd_open the graceful wait polls waitpid(WNOHANG) in short steps;
 * the child stays a zombie until the reap below, so its pid cannot be reused. */
static void tunnel_wait_exit(pid_t pid, int grace_ms)
{
    int waited = 0;
    for (; waited < grace_ms; waited += CONNECT_POLL_STEP_MS) {
        siginfo_t si = { 0 };
        if (waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == pid)
            return;
        struct timespec nap = { 0, CONNECT_POLL_STEP_MS * 1000000L };
        nanosleep(&nap, NULL);
    }
}

/* The existing bounded reap (resident_launch_kill_reap: SIGKILL, then a
 * deadline-bound waitpid) ends every path, so no kernel feature is needed
 * for the bound: SIGHUP is the client's graceful close and gets `grace_ms`
 * to land when a pidfd can watch for it, and a child that ignores it, or a
 * host without pidfd_open (a 200 ms wait by waitid), is killed and reaped. */
bool zcl_native_hub_tunnel_reap(pid_t pid, int grace_ms)
{
    (void)kill(pid, SIGHUP);
    int pidfd = tunnel_pidfd(pid);
    if (pidfd >= 0) {
        struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
        (void)poll(&pfd, 1, grace_ms);
        close(pidfd);
    } else {
        tunnel_wait_exit(pid, grace_ms < CONNECT_NOPIDFD_GRACE_MS ? grace_ms : CONNECT_NOPIDFD_GRACE_MS);
    }
    return resident_launch_kill_reap((uint64_t)pid, RESIDENT_REAP_GRACE_MS, NULL);
}

static void tunnel_close(struct tunnel *t)
{
    close(t->net_fd);
    if (t->pid > 0)
        (void)zcl_native_hub_tunnel_reap(t->pid, CONNECT_REAP_MS);
    close(t->err_fd);
}

static int connect_report(const struct mesh_terminal_hub_client_result *r, const char *extra)
{
    if (r->code[0])
        fprintf(stderr, "z23: %s: %s: %s%s\n",
                (r->exit_code >= 2 && r->exit_code <= 4) ? "refused" : "ended",
                r->code, r->message, extra);
    return r->exit_code;
}

static int connect_fail(int rc, const char *code, const char *why)
{
    fprintf(stderr, "z23: refused: %s: %s\n", code, why);
    return rc;
}

static int connect_run(struct mesh_terminal_hub_client_cfg *cfg, struct tunnel *t)
{
    struct mesh_terminal_hub_client_result res;
    struct connect_edge edge;
    char said[200] = "";
    memset(&edge, 0, sizeof edge);
    if (!connect_edge_open(&edge))
        return connect_fail(ZCL_COMMAND_EXIT_INTERNAL, "INTERNAL", "cannot set up the terminal");
    cfg->event_fd = edge.events[0];
    mesh_terminal_hub_client_run(cfg, &res);
    connect_edge_close(&edge);
    if (t && res.code[0])
        tunnel_said(t, said, sizeof said);
    return connect_report(&res, said);
}

/* --exec is a JSON array of 1..16 strings; argv[0] is an absolute path. The
 * strings live in `doc`, which the caller keeps until the session ends. */
static bool connect_exec_parse(const char *text, struct json_value *doc,
                               const char *argv[MESH_TERMINAL_HUB_ARGV_MAX + 1])
{
    json_init(doc);
    if (!json_read(doc, text, strlen(text)) || doc->type != JSON_ARR ||
        doc->num_children == 0 || doc->num_children > MESH_TERMINAL_HUB_ARGV_MAX)
        return false;
    for (size_t i = 0; i < doc->num_children; i++) {
        argv[i] = doc->children[i].type == JSON_STR ? json_get_str(&doc->children[i]) : NULL;
        if (!argv[i])
            return false;
    }
    argv[doc->num_children] = NULL;
    return argv[0][0] == '/';
}

/* Validates the arguments, loads the key and parses --exec into cfg. */
static int connect_prepare(const struct hub_args *a, struct mesh_terminal_hub_client_cfg *cfg,
                           struct json_value *doc, const char **argv)
{
    char why[96];
    if (!a->key_file || (!a->route_input == !a->have_direct_port) || a->direct_port > UINT16_MAX)
        return connect_fail(ZCL_COMMAND_EXIT_INVALID, "INVALID_ARGUMENTS",
            "usage: z23 ops mesh terminal connect --key_file=<path> (--route_input=<file> | --direct_port=N) [--name=<label>] [--exec='[\"/abs/program\",\"arg\"]']");
    char probe[CONNECT_ARG_MAX];
    if (a->route_input && !zcl_native_hub_route_arg(a->route_input, probe, sizeof probe))
        return connect_fail(ZCL_COMMAND_EXIT_INVALID, "ROUTE_TOO_LONG",
                            "the --route_input path is too long to hand to the tunnel client");
    if (a->exec && !connect_exec_parse(a->exec, doc, argv))
        return connect_fail(ZCL_COMMAND_EXIT_INVALID, "EXEC_REFUSED",
                            "--exec must be a JSON array of 1 to 16 strings starting with an absolute program path");
    if (!mesh_terminal_hub_key_load(a->key_file, cfg->key, why, sizeof why))
        return connect_fail(ZCL_COMMAND_EXIT_INVALID, "KEY_FILE_REFUSED", why);
    cfg->name = a->name ? a->name : "z23-connect";
    cfg->argv = a->exec ? argv : NULL;
    cfg->quiet = isatty(STDIN_FILENO) == 0;
    cfg->in_fd = STDIN_FILENO;
    cfg->out_fd = STDOUT_FILENO;
    cfg->window = connect_window;
    return ZCL_COMMAND_EXIT_OK;
}

static int hub_connect_arm(const struct hub_args *a)
{
    struct mesh_terminal_hub_client_cfg cfg;
    struct tunnel t = { .pid = -1, .net_fd = -1, .err_fd = -1 };
    struct json_value doc;
    const char *argv[MESH_TERMINAL_HUB_ARGV_MAX + 1];
    int rc;
    memset(&cfg, 0, sizeof cfg);
    json_init(&doc);
    rc = connect_prepare(a, &cfg, &doc, argv);
    if (rc == ZCL_COMMAND_EXIT_OK &&
        (a->route_input ? !tunnel_open(a->route_input, &t)
                        : (t.net_fd = connect_direct((uint16_t)a->direct_port)) < 0))
        rc = connect_fail(ZCL_COMMAND_EXIT_TRANSIENT, "CONNECT_FAILED",
                          "cannot reach the terminal server (route input unreadable or nothing listening)");
    else if (rc == ZCL_COMMAND_EXIT_OK) {
        cfg.net_fd = t.net_fd;
        rc = connect_run(&cfg, t.pid > 0 ? &t : NULL);
        tunnel_close(&t);
    }
    json_free(&doc);
    return rc;
}

#else

static int hub_connect_arm(const struct hub_args *a)
{
    (void)a;
    fprintf(stderr, "z23: refused: PLATFORM_UNSUPPORTED: the terminal hub client needs Linux\n");
    return ZCL_COMMAND_EXIT_BLOCKED;
}

#endif

int zcl_native_hub_connect(const struct hub_args *a)
{
    return hub_connect_arm(a);
}
