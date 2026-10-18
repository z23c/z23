/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: `z23 ops mesh terminal` — the interactive attach command for the
 * mesh terminal lane. This file owns only the process edge: argv, the local
 * node RPC transport, termios raw mode, SIGWINCH and termination signals.
 * The bridge loop is mesh_terminal_attach.c. */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "command/mesh_terminal_attach.h"
#include "command/native_command.h"
#include "native_mesh_terminal_hub.h"

#include "session/mesh_terminal_proto.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32

static int terminal_run(const char *pairing)
{
    (void)pairing;
    fprintf(stderr, "z23: refused: PLATFORM_UNSUPPORTED: the terminal client "
                    "needs a POSIX terminal\n");
    return ZCL_COMMAND_EXIT_BLOCKED;
}

#else

#include "controllers/rpc_client.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#define TERMINAL_WRITE_STALL_LIMIT 50
#define TERMINAL_WRITE_STALL_MS 100

struct terminal_edge {
    struct termios saved;
    bool raw_on;
};

static volatile sig_atomic_t g_resize_pending;
static volatile sig_atomic_t g_stop_pending;

static void terminal_on_winch(int sig)
{
    (void)sig;
    g_resize_pending = 1;
}

static void terminal_on_stop(int sig)
{
    (void)sig;
    g_stop_pending = 1;
}

static char *terminal_rpc(void *ctx, const char *method, const char *params)
{
    (void)ctx;
    return node_rpc_call(method, params);
}

static long terminal_read_input(void *ctx, uint8_t *buf, size_t cap,
                                int timeout_ms)
{
    (void)ctx;
    struct pollfd pfd = {.fd = STDIN_FILENO, .events = POLLIN};
    int ready = poll(&pfd, 1, timeout_ms);
    if (ready < 0)
        return errno == EINTR ? 0 : -1;
    if (ready == 0)
        return 0;
    ssize_t n = read(STDIN_FILENO, buf, cap);
    if (n > 0)
        return (long)n;
    if (n < 0 && (errno == EINTR || errno == EAGAIN))
        return 0;
    return -1;
}

/* Writes all of buf to fd. A pending stop request abandons the write, so a
 * stalled or blocked reader cannot keep the terminal raw past SIGTERM. */
bool zcl_native_mesh_terminal_write_all(int fd, const uint8_t *buf, size_t len)
{
    int stalls = 0;
    while (len) {
        if (g_stop_pending)
            return false;
        ssize_t n = write(fd, buf, len);
        if (n > 0) {
            buf += n;
            len -= (size_t)n;
            stalls = 0;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && errno == EAGAIN && ++stalls < TERMINAL_WRITE_STALL_LIMIT) {
            struct pollfd pfd = {.fd = fd, .events = POLLOUT};
            (void)poll(&pfd, 1, TERMINAL_WRITE_STALL_MS);
        } else {
            return false;
        }
    }
    return true;
}

static bool terminal_write_output(void *ctx, const uint8_t *buf, size_t len)
{
    (void)ctx;
    return zcl_native_mesh_terminal_write_all(STDOUT_FILENO, buf, len);
}

#ifdef ZCL_TESTING
void zcl_native_mesh_terminal_test_set_stop(bool stop)
{
    g_stop_pending = stop ? 1 : 0;
}
#endif

static bool terminal_window(void *ctx, uint16_t *cols, uint16_t *rows)
{
    (void)ctx;
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) != 0 || !ws.ws_col || !ws.ws_row)
        return false;
    *cols = ws.ws_col > MESH_TERMINAL_MAX_COLS ? MESH_TERMINAL_MAX_COLS
                                               : ws.ws_col;
    *rows = ws.ws_row > MESH_TERMINAL_MAX_ROWS ? MESH_TERMINAL_MAX_ROWS
                                               : ws.ws_row;
    return true;
}

static bool terminal_take_resize(void *ctx)
{
    (void)ctx;
    bool pending = g_resize_pending != 0;
    g_resize_pending = 0;
    return pending;
}

static bool terminal_stop_requested(void *ctx)
{
    (void)ctx;
    return g_stop_pending != 0;
}

static void terminal_make_raw(struct termios *t)
{
    t->c_iflag &= ~(tcflag_t)(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR |
                              IGNCR | ICRNL | IXON);
    t->c_oflag &= ~(tcflag_t)OPOST;
    t->c_lflag &= ~(tcflag_t)(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t->c_cflag &= ~(tcflag_t)(CSIZE | PARENB);
    t->c_cflag |= CS8;
    t->c_cc[VMIN] = 1;
    t->c_cc[VTIME] = 0;
}

#ifdef ZCL_TESTING
bool zcl_native_mesh_terminal_test_raw_is_transparent(void)
{
    struct termios t;
    memset(&t, 0xff, sizeof(t));
    terminal_make_raw(&t);
    const tcflag_t in_bad = IGNBRK | BRKINT | ISTRIP | INLCR | IGNCR | ICRNL |
                            IXON;
    const tcflag_t local_bad = ECHO | ECHONL | ICANON | ISIG | IEXTEN;
    return (t.c_iflag & in_bad) == 0 && (t.c_oflag & OPOST) == 0 &&
           (t.c_lflag & local_bad) == 0 && (t.c_cflag & CSIZE) == CS8 &&
           t.c_cc[VMIN] == 1 && t.c_cc[VTIME] == 0;
}
#endif

/* Restores the saved line discipline only. Modes the remote program set by
 * escape sequence (alternate screen, mouse reporting, bracketed paste) are
 * not reset: the remote owns them. */
static void terminal_raw(void *ctx, bool on)
{
    struct terminal_edge *edge = ctx;
    if (on && !edge->raw_on && tcgetattr(STDIN_FILENO, &edge->saved) == 0) {
        struct termios raw = edge->saved;
        terminal_make_raw(&raw);
        edge->raw_on = tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0;
    } else if (!on && edge->raw_on) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &edge->saved);
        edge->raw_on = false;
    }
}

static void terminal_pause_ms(void *ctx, int ms)
{
    (void)ctx;
    platform_sleep_ms(ms);
}

static int64_t terminal_now_ms(void *ctx)
{
    (void)ctx;
    return platform_time_monotonic_ms();
}

static void terminal_diagnostic(void *ctx, const char *line)
{
    (void)ctx;
    fprintf(stderr, "%s\n", line);
}

struct terminal_signals {
    struct sigaction winch, intr, term, hup, quit, pipe;
};

static void terminal_signals_install(struct terminal_signals *old)
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = terminal_on_winch;
    sigaction(SIGWINCH, &act, &old->winch);
    act.sa_handler = terminal_on_stop;
    sigaction(SIGINT, &act, &old->intr);
    sigaction(SIGTERM, &act, &old->term);
    sigaction(SIGHUP, &act, &old->hup);
    sigaction(SIGQUIT, &act, &old->quit);
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, &old->pipe);
}

static void terminal_signals_restore(const struct terminal_signals *old)
{
    sigaction(SIGWINCH, &old->winch, NULL);
    sigaction(SIGINT, &old->intr, NULL);
    sigaction(SIGTERM, &old->term, NULL);
    sigaction(SIGHUP, &old->hup, NULL);
    sigaction(SIGQUIT, &old->quit, NULL);
    sigaction(SIGPIPE, &old->pipe, NULL);
}

static int terminal_run(const char *pairing)
{
    struct terminal_edge edge;
    memset(&edge, 0, sizeof(edge));
    const struct mesh_terminal_attach_tty tty = {
        .ctx = &edge,
        .read_input = terminal_read_input,
        .write_output = terminal_write_output,
        .window = terminal_window,
        .take_resize = terminal_take_resize,
        .stop_requested = terminal_stop_requested,
        .raw = terminal_raw,
        .pause_ms = terminal_pause_ms,
        .now_ms = terminal_now_ms,
        .diagnostic = terminal_diagnostic,
    };
    const struct mesh_terminal_attach_config config = {
        .pairing_id = pairing,
        .interactive = isatty(STDIN_FILENO) != 0,
    };
    struct terminal_signals old;
    zcl_native_bridge_ensure_rpc();
    terminal_signals_install(&old);
    int rc = mesh_terminal_attach_run(&config, terminal_rpc, NULL, &tty);
    terminal_raw(&edge, false);
    terminal_signals_restore(&old);
    return rc;
}

#endif

static const char *terminal_pairing_arg(const char *const *words, size_t count,
                                        size_t consumed)
{
    const char *pairing = NULL;
    for (size_t i = consumed; i < count; i++) {
        const char *w = words[i];
        if (!w || pairing)
            return NULL;
        pairing = strncmp(w, "--pairing_id=", 13) == 0 ? w + 13 : w;
        if (pairing[0] == '-')
            return NULL;
    }
    return pairing;
}

bool zcl_native_mesh_terminal_try_attach(const char *const *words,
                                         size_t count, size_t consumed,
                                         int *rc)
{
    if (zcl_native_mesh_terminal_hub_try(words, count, consumed, rc))
        return true;
    const char *pairing = terminal_pairing_arg(words, count, consumed);
    if (!pairing || !pairing[0])
        return false;
    *rc = terminal_run(pairing);
    return true;
}

void zcl_native_handle_ops_mesh_terminal(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "TERMINAL_CLI_ONLY", "dispatch", false, false,
        "the terminal bridge needs the caller's terminal; run it as "
        "z23 ops mesh terminal --pairing_id=<64hex>",
        "ops.mesh.terminal");
}
