/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the terminal hub client loop. It owns no terminal modes and no
 * signals — the command edge puts the tty in raw mode and turns SIGWINCH and
 * the termination signals into bytes on event_fd — so the same loop runs
 * under a test with pipes. It blocks in poll over the stream, the keyboard
 * and the event pipe; a keystroke is read straight behind its 3-byte header
 * and sent with one send(), and screen bytes are written from the receive
 * buffer with no copy. */

#define _GNU_SOURCE

#include "session/mesh_terminal_hub.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)

static void hub_client_run_arm(
    const struct mesh_terminal_hub_client_cfg *cfg,
    struct mesh_terminal_hub_client_result *result)
{
    (void)cfg;
    memset(result, 0, sizeof(*result));
    result->exit_code = 3;
    snprintf(result->code, sizeof result->code, "PLATFORM_UNSUPPORTED");
    snprintf(result->message, sizeof result->message,
             "the terminal hub client needs Linux");
}

#else

#include "mesh_terminal_hub_io.h"
#include "session/mesh_terminal_hub_portable.h"

#include "platform/time_compat.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>

#define HUB_CLIENT_HANDSHAKE_MS 20000
#define HUB_EOT 0x04
#define HUB_CLIENT_TAIL_MS 500 /* the closing newline never waits longer */

struct hub_cl {
    const struct mesh_terminal_hub_client_cfg *cfg;
    struct mesh_terminal_hub_client_result *res;
    struct hub_rx rx;
    struct hub_wfd wfd;           /* the screen; every write attempt is non-blocking */
    uint8_t in[MESH_TERMINAL_HUB_FRAME_MAX];
    bool in_eof;
    bool wrote;
    uint8_t last_out;
    bool done;
};

static void hub_cl_fail(struct hub_cl *c, int exit_code, const char *code,
                        const char *message)
{
    c->res->exit_code = exit_code;
    snprintf(c->res->code, sizeof c->res->code, "%s", code);
    snprintf(c->res->message, sizeof c->res->message, "%s", message);
    c->done = true;
}

static void hub_cl_event(struct hub_cl *c);

/* One wait for the screen: 1 writable, 0 keep waiting (an event was served),
 * -1 give up (the output failed, the session ended, or the closing newline
 * hit its deadline, which is counted). `watch` is false for that newline. */
static int hub_cl_wait_out(struct hub_cl *c, bool watch, int64_t deadline)
{
    struct pollfd pfd[2] = {
        { .fd = c->wfd.fd, .events = POLLOUT },
        { .fd = watch ? c->cfg->event_fd : -1, .events = POLLIN },
    };
    int64_t left = deadline - platform_time_monotonic_ms();
    int ready = left <= 0 && !watch ? 0 : poll(pfd, 2, watch ? -1 : (int)left);
    if ((ready < 0 && errno != EINTR) || (ready == 0 && !watch)) {
        c->res->output_dropped += watch ? 0u : 1u;
        return -1;
    }
    if (pfd[1].revents) {
        hub_cl_event(c);
        return c->done ? -1 : 0;
    }
    return pfd[0].revents ? 1 : 0;
}

/* Screen bytes out. The write is tried first; only on EAGAIN (another writer
 * took the room, or the reader stopped draining) does it go to the wait,
 * which also watches the event pipe, so a termination signal is always
 * served. The closing newline has one absolute deadline, taken at its first
 * wait. False when the output failed or the session ended while waiting
 * (c->done tells which). */
static bool hub_cl_write_out(struct hub_cl *c, const uint8_t *p, size_t n, bool watch)
{
    int64_t deadline = 0;
    while (n) {
        ssize_t w = hub_wfd_try(&c->wfd, p, n);
        if (w > 0) {
            p += w;
            n -= (size_t)w;
            continue;
        }
        if (w < 0 && errno != EINTR && errno != EAGAIN)
            return false;
        if (w < 0 && errno == EAGAIN) {
            if (!deadline)
                deadline = platform_time_monotonic_ms() + HUB_CLIENT_TAIL_MS;
            if (hub_cl_wait_out(c, watch, deadline) < 0)
                return false;
        }
    }
    return true;
}

/* Names the likely cause when the server host refuses user namespaces. */
#define HUB_MSG_CONFINEMENT                                                     \
    "the terminal server could not start its confined shell (Ubuntu: see " \
    "kernel.apparmor_restrict_unprivileged_userns, platform/packaging/linux/apparmor)"
_Static_assert(sizeof HUB_MSG_CONFINEMENT <= sizeof((struct mesh_terminal_hub_client_result *)0)->message,
               "confinement refusal text must fit the result message");

static const struct {
    int refusal, exit_code;
    const char *code, *message;
} hub_refusals[] = {
    { MESH_TERMINAL_HUB_REFUSE_AUTH, 4, "AUTH_REFUSED",
      "the terminal server refused the key (wrong or stale key file)" },
    { MESH_TERMINAL_HUB_REFUSE_BUSY, 5, "BUSY",
      "the terminal server is at its session limit; try again shortly" },
    { MESH_TERMINAL_HUB_REFUSE_REQUEST, 2, "REQUEST_REFUSED",
      "the terminal server rejected the request" },
    { MESH_TERMINAL_HUB_REFUSE_CONFINEMENT, 3, "CONFINEMENT_UNAVAILABLE",
      HUB_MSG_CONFINEMENT },
    { MESH_TERMINAL_HUB_REFUSE_EXEC, 2, "EXEC_REFUSED",
      "the terminal server cannot run that program (not an absolute path to an executable file)" },
    { MESH_TERMINAL_HUB_REFUSE_SHUTDOWN, 5, "SERVER_STOPPING",
      "the terminal server is shutting down" },
};

static void hub_cl_refused(struct hub_cl *c, int refusal)
{
    for (size_t i = 0; i < sizeof hub_refusals / sizeof hub_refusals[0]; i++)
        if (hub_refusals[i].refusal == refusal)
            { hub_cl_fail(c, hub_refusals[i].exit_code, hub_refusals[i].code,
                               hub_refusals[i].message); return; }
    hub_cl_fail(c, 1, "REFUSED", "the terminal server refused the session");
}

static void hub_cl_wait_failed(struct hub_cl *c, enum hub_wait w)
{
    if (w == HUB_WAIT_TIMEOUT)
        hub_cl_fail(c, 5, "NO_ANSWER",
                    "no answer from the terminal server (tunnel down, or nothing listening)");
    else if (w == HUB_WAIT_BAD)
        hub_cl_fail(c, 1, "PROTOCOL", "the terminal server sent a malformed frame");
    else
        hub_cl_fail(c, 5, "CONNECTION_LOST", "the connection closed during the handshake");
}

/* The next frame during the handshake; a REFUSE ends the run. */
static bool hub_cl_expect(struct hub_cl *c, uint8_t want, int timeout_ms,
                          const uint8_t **payload, size_t *len)
{
    uint8_t type;
    enum hub_wait w = hub_rx_wait(&c->rx, c->cfg->net_fd, timeout_ms, &type, payload, len);
    if (w != HUB_WAIT_FRAME) {
        hub_cl_wait_failed(c, w);
        return false;
    }
    if (type == MESH_TERMINAL_HUB_REFUSE && *len == 1) {
        hub_cl_refused(c, (*payload)[0]);
        return false;
    }
    if (type != want) {
        hub_cl_fail(c, 1, "PROTOCOL", "the terminal server sent an unexpected frame");
        return false;
    }
    return true;
}

static void hub_cl_handshake(struct hub_cl *c)
{
    const uint8_t *p;
    size_t len;
    int wait_ms = c->cfg->handshake_ms ? c->cfg->handshake_ms : HUB_CLIENT_HANDSHAKE_MS;
    struct mesh_terminal_hub_request rq = { .cols = 80, .rows = 24, .name = c->cfg->name,
        .argv = c->cfg->argv, .flags = c->cfg->quiet ? MESH_TERMINAL_HUB_HELLO_QUIET : 0 };
    uint8_t hello[MESH_TERMINAL_HUB_PAYLOAD_MAX];
    if (!hub_cl_expect(c, MESH_TERMINAL_HUB_CHALLENGE, wait_ms, &p, &len))
        return;
    if (len != 1u + MESH_TERMINAL_HUB_NONCE_BYTES || p[0] != MESH_TERMINAL_HUB_VERSION)
        { hub_cl_fail(c, 1, "PROTOCOL", "the terminal server speaks another version"); return; }
    if (c->cfg->window)
        (void)c->cfg->window(c->cfg->window_ctx, &rq.cols, &rq.rows);
    size_t n = mesh_terminal_hub_hello_build(hello, c->cfg->key, p + 1, &rq);
    if (n == 0)
        { hub_cl_fail(c, 2, "INVALID_ARGUMENTS", "the program and its arguments are too long to send"); return; }
    hub_rx_consume(&c->rx, len);
    if (!hub_io_send_frame(c->cfg->net_fd, MESH_TERMINAL_HUB_HELLO, hello, n))
        { hub_cl_fail(c, 5, "CONNECTION_LOST", "the connection closed during the handshake"); return; }
    if (hub_cl_expect(c, MESH_TERMINAL_HUB_READY, wait_ms, &p, &len))
        hub_rx_consume(&c->rx, len);
}

static const struct {
    int reason, exit_code;
    const char *code, *message;
} hub_ends[] = {
    { MESH_TERMINAL_CLOSE_IDLE_TIMEOUT, 5, "IDLE_TIMEOUT", "the session was idle too long and was closed" },
    { MESH_TERMINAL_CLOSE_LIFETIME_LIMIT, 5, "LIFETIME_LIMIT", "the session reached its lifetime limit" },
    { MESH_TERMINAL_CLOSE_BYTE_LIMIT, 1, "BYTE_LIMIT", "the session reached its byte budget" },
    { MESH_TERMINAL_CLOSE_SESSION_LOST, 5, "SESSION_LOST", "the server lost the session" },
    { MESH_TERMINAL_CLOSE_SHUTDOWN, 5, "SERVER_STOPPING", "the terminal server is shutting down" },
    { MESH_TERMINAL_CLOSE_INTERNAL, 6, "SERVER_ERROR", "the terminal server hit an internal error" },
};

/* The EXIT body is reason, flags, exit code, signal. Only these shapes are
 * meaningful, anything else is a protocol error and never a success:
 *   worker-exited: HAS_CODE alone (signal byte 0), or HAS_SIGNAL alone
 *                  (code byte 0, signal 1..64);
 *   a limit or error ending in hub_ends: no flags, both bytes 0. */
#define HUB_SIGNAL_MAX 64u

static bool hub_cl_exit_shape(const uint8_t *p)
{
    uint8_t flags = p[1];
    if (p[0] == MESH_TERMINAL_CLOSE_WORKER_EXITED) {
        if (flags == MESH_TERMINAL_HUB_EXIT_HAS_CODE)
            return p[3] == 0;
        return flags == MESH_TERMINAL_HUB_EXIT_HAS_SIGNAL && p[2] == 0 &&
               p[3] >= 1 && p[3] <= HUB_SIGNAL_MAX;
    }
    return flags == 0 && p[2] == 0 && p[3] == 0;
}

static void hub_cl_exit_frame(struct hub_cl *c, const uint8_t *p, size_t len)
{
    c->done = true;
    if (len != 4 || !hub_cl_exit_shape(p)) {
        hub_cl_fail(c, 1, "PROTOCOL", "malformed exit frame");
        return;
    }
    if (p[0] == MESH_TERMINAL_CLOSE_WORKER_EXITED) {
        c->res->exit_code = (p[1] & MESH_TERMINAL_HUB_EXIT_HAS_CODE) ? p[2] : 128 + p[3];
        return;
    }
    for (size_t i = 0; i < sizeof hub_ends / sizeof hub_ends[0]; i++)
        if (hub_ends[i].reason == p[0])
            { hub_cl_fail(c, hub_ends[i].exit_code, hub_ends[i].code, hub_ends[i].message); return; }
    hub_cl_fail(c, 1, "PROTOCOL", "the terminal server sent an unknown ending");
}

/* Frames already buffered: the server may send READY and the first screen
 * bytes in one segment, so these are handled before poll is asked again. */
static void hub_cl_frames(struct hub_cl *c)
{
    for (;;) {
        uint8_t type;
        const uint8_t *p;
        size_t len;
        enum hub_rx_status st = hub_rx_next(&c->rx, &type, &p, &len);
        if (st == HUB_RX_NEED_MORE)
            return;
        if (st == HUB_RX_BAD)
            { hub_cl_fail(c, 1, "PROTOCOL", "the terminal server sent a malformed frame"); return; }
        if (type == MESH_TERMINAL_HUB_DATA && len)
            { c->wrote = true; c->last_out = p[len - 1]; }
        if (type == MESH_TERMINAL_HUB_DATA && !hub_cl_write_out(c, p, len, true))
            { if (!c->done) hub_cl_fail(c, 1, "OUTPUT_CLOSED", "cannot write to the terminal"); return; }
        if (type == MESH_TERMINAL_HUB_EXIT)
            { hub_cl_exit_frame(c, p, len); return; }
        hub_rx_consume(&c->rx, len);
    }
}

static void hub_cl_net_ready(struct hub_cl *c)
{
    long got = hub_rx_read(&c->rx, c->cfg->net_fd);
    if (got == 0 || got == -1)
        { hub_cl_fail(c, 5, "CONNECTION_LOST", "the connection to the terminal server was lost"); return; }
    hub_cl_frames(c);
}

static void hub_cl_keys_ready(struct hub_cl *c)
{
    uint8_t *body = c->in + MESH_TERMINAL_HUB_HEADER_BYTES;
    ssize_t n = read(c->cfg->in_fd, body, MESH_TERMINAL_HUB_PAYLOAD_MAX);
    if (n < 0 && (errno == EINTR || errno == EAGAIN))
        return;
    if (n <= 0) { /* end of input: one ^D asks the remote shell to finish */
        c->in_eof = true;
        body[0] = HUB_EOT;
        n = 1;
    }
    size_t total = mesh_terminal_hub_frame_seal(c->in, MESH_TERMINAL_HUB_DATA, (size_t)n);
    if (!hub_io_send(c->cfg->net_fd, c->in, total))
        hub_cl_fail(c, 5, "CONNECTION_LOST", "the connection to the terminal server was lost");
}

static void hub_cl_send_resize(struct hub_cl *c)
{
    uint16_t cols, rows;
    uint8_t body[4];
    if (!c->cfg->window || !c->cfg->window(c->cfg->window_ctx, &cols, &rows))
        return;
    body[0] = (uint8_t)(cols >> 8); body[1] = (uint8_t)cols;
    body[2] = (uint8_t)(rows >> 8); body[3] = (uint8_t)rows;
    (void)hub_io_send_frame(c->cfg->net_fd, MESH_TERMINAL_HUB_RESIZE, body, 4);
}

static void hub_cl_event(struct hub_cl *c)
{
    char ev[8];
    ssize_t n = read(c->cfg->event_fd, ev, sizeof ev);
    for (ssize_t i = 0; i < n; i++) {
        if (ev[i] == 'W') {
            hub_cl_send_resize(c);
        } else if (ev[i] == 'S') {
            uint8_t reason = MESH_TERMINAL_CLOSE_REQUESTED;
            (void)hub_io_send_frame(c->cfg->net_fd, MESH_TERMINAL_HUB_CLOSE, &reason, 1);
            { hub_cl_fail(c, 130, "INTERRUPTED", "interrupted; the remote session was closed"); return; }
        }
    }
}

static void hub_cl_run(struct hub_cl *c)
{
    hub_cl_frames(c);
    while (!c->done) {
        struct pollfd pfd[3] = {
            { .fd = c->cfg->net_fd, .events = POLLIN },
            { .fd = c->in_eof ? -1 : c->cfg->in_fd, .events = POLLIN },
            { .fd = c->cfg->event_fd, .events = POLLIN },
        };
        if (poll(pfd, 3, -1) < 0 && errno != EINTR)
            { hub_cl_fail(c, 6, "INTERNAL", "poll failed"); return; }
        if (pfd[2].revents)
            hub_cl_event(c);
        else if (pfd[0].revents)
            hub_cl_net_ready(c);
        else if (pfd[1].revents)
            hub_cl_keys_ready(c);
    }
}

static void hub_client_run_arm(
    const struct mesh_terminal_hub_client_cfg *cfg,
    struct mesh_terminal_hub_client_result *result)
{
    struct hub_cl c = { .cfg = cfg, .res = result };
    memset(result, 0, sizeof(*result));
    hub_socket_nosigpipe(cfg->net_fd); /* once per socket; no-op on Linux */
    if (!hub_wfd_sink_bounded(cfg->out_fd)) {
        /* Off Linux a blocking pipe cannot be bounded without setting
         * O_NONBLOCK on a description the hub did not open. A tty, a regular
         * file and a socket classify exactly as on Linux. Nothing is written
         * to out_fd, and the session never starts. */
        hub_cl_fail(&c, 2, "OUTPUT_UNBOUNDED",
                    "stdout is a blocking pipe; on this host the hub client needs a terminal, a regular file, or a non-blocking pipe");
        return;
    }
    hub_wfd_open(&c.wfd, cfg->out_fd);
    hub_cl_handshake(&c);
    if (!c.done)
        hub_cl_run(&c);
    /* End the screen on a fresh line: the remote's last bytes are usually a
     * prompt. A raw tty needs the carriage return; a pipe does not. */
    if (c.wrote && c.last_out != '\n')
        (void)hub_cl_write_out(&c, (const uint8_t *)"\r\n" + (cfg->quiet ? 1 : 0),
                               cfg->quiet ? 1u : 2u, false);
}

#endif /* !_WIN32 */

void mesh_terminal_hub_client_run(
    const struct mesh_terminal_hub_client_cfg *cfg,
    struct mesh_terminal_hub_client_result *result)
{
    hub_client_run_arm(cfg, result);
}
