/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: serve the control socket of one confined plugin. Two kinds of frame
 * come from the child and are told apart by their first byte: a result frame
 * (the ping reply, resident_result_header) starts with the magic "z23-res-run-v1"
 * so its first byte is 'z', and a host-call frame starts with a big-endian u32
 * length that is below 2^24, so its first byte is always 0. Supervisor frames
 * (ping, stop) keep their 81-byte format; host-call replies reach the child with
 * the same leading zero byte. Old plugins never send a zero byte first.
 *
 * Bytes are accumulated and decoded in a loop. Host calls are answered here, on
 * the thread that calls plugin_run_poll, so the node handlers need no lock of
 * their own: the caller serves them from the thread that owns node_db. */

#include "plugin_run_internal.h"

#if defined(__linux__)
#include "base/safe_alloc.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PRS_RESULT_MAGIC "z23-res-run-v1"
#define PRS_HOSTCALL_RATE_DEFAULT 200u
#define PRS_RATE_WINDOW_NS UINT64_C(1000000000)
#define PRS_PUMP_BUDGET_MS 200
#define PRS_RX_CAP PLUGIN_HOSTCALL_MAX_FRAME
#define PRS_RESULT_PAYLOAD PRS_TOKEN_HEX

/* The leading byte tells the frame kinds apart only while a host-call length
 * prefix cannot start with 'z' or any other magic byte. */
static_assert(PLUGIN_HOSTCALL_MAX_FRAME < (1u << 24),
              "a host-call frame must start with a zero length byte");

bool prs_control_start(struct plugin_run *run)
{
    prs_control_stop(run);
    run->ctl_rx = zcl_malloc(PRS_RX_CAP, "plugin-ctl-rx");
    run->ctl_reply = zcl_malloc(PLUGIN_HOSTCALL_MAX_FRAME, "plugin-ctl-reply");
    if (!run->ctl_rx || !run->ctl_reply) {
        prs_control_stop(run);
        return false;
    }
    /* wallet.request is PLANNED: never granted, whatever the manifest declares. */
    run->grants = plugin_hostcall_grants_from_manifest(run->capabilities) &
                  ~(uint32_t)PLUGIN_HOSTCALL_CAP_WALLET;
    run->window_start_ns = 0;
    run->window_calls = 0;
    return true;
}

void prs_control_stop(struct plugin_run *run)
{
    free(run->ctl_rx);
    free(run->ctl_reply);
    run->ctl_rx = NULL;
    run->ctl_reply = NULL;
    run->ctl_rx_len = 0;
    run->grants = 0;
}

/* Close the control socket: a framing violation ends the stream, and it counts
 * as a missed ping. The descriptor is forgotten so the launch never closes it
 * a second time. */
static enum prs_ping prs_control_close(struct plugin_run *run)
{
    if (run->launch.ipc_native != (uintptr_t)-1) {
        close((int)run->launch.ipc_native);
        run->launch.ipc_native = (uintptr_t)-1;
    }
    run->ctl_rx_len = 0;
    return PRS_PING_MISS;
}

static void prs_rx_consume(struct plugin_run *run, size_t n)
{
    memmove(run->ctl_rx, run->ctl_rx + n, run->ctl_rx_len - n);
    run->ctl_rx_len -= n;
}

/* Pull whatever the child has written, up to the buffer. EOF and errors are
 * left to the reaper: the child's exit is observed there. */
static void prs_rx_fill(struct plugin_run *run)
{
    int fd = (int)run->launch.ipc_native;
    while (run->ctl_rx_len < PRS_RX_CAP) {
        ssize_t n = recv(fd, run->ctl_rx + run->ctl_rx_len, PRS_RX_CAP - run->ctl_rx_len,
                         MSG_DONTWAIT);
        if (n > 0)
            run->ctl_rx_len += (size_t)n;
        else if (n < 0 && errno == EINTR)
            continue;
        else
            return;
    }
}

/* Write one whole reply before `end`, the deadline of the whole pump, so a slow
 * reader is not waited on afresh for every reply; false when the child does
 * not take it in time. */
static bool prs_reply_send(const struct plugin_run *run, const uint8_t *frame, size_t len,
                           uint64_t end)
{
    int fd = (int)run->launch.ipc_native;
    for (size_t done = 0; done < len;) {
        ssize_t n = send(fd, frame + done, len - done, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) {
            done += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        uint64_t now = prs_now_ns();
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK) || now >= end)
            return false;
        struct pollfd waiter = {.fd = fd, .events = POLLOUT};
        (void)poll(&waiter, 1, (int)((end - now) / UINT64_C(1000000)) + 1);
    }
    return true;
}

/* True while the rate window still has room; false defers the call to a later tick. */
static bool prs_rate_ok(struct plugin_run *run, uint64_t now)
{
    uint32_t limit = run->opt.hostcall_per_second ? run->opt.hostcall_per_second
                                                  : PRS_HOSTCALL_RATE_DEFAULT;
    if (run->window_start_ns == 0 || now - run->window_start_ns >= PRS_RATE_WINDOW_NS) {
        run->window_start_ns = now;
        run->window_calls = 0;
    }
    if (run->window_calls >= limit)
        return false;
    run->window_calls++;
    return true;
}

/* One result frame at the head of the buffer. NONE means more bytes are
 * needed or the frame was a stale reply; BAD means it is not ours. */
static enum prs_ping prs_take_result(struct plugin_run *run)
{
    struct resident_result_header header;
    size_t total = sizeof(header) + PRS_RESULT_PAYLOAD;
    if (run->ctl_rx_len < sizeof(header))
        return PRS_PING_NONE;
    memcpy(&header, run->ctl_rx, sizeof(header));
    if (strncmp(header.magic, PRS_RESULT_MAGIC, sizeof(header.magic)) != 0 ||
        strncmp(header.nonce, run->launch.nonce, sizeof(header.nonce)) != 0 ||
        header.payload_len != PRS_RESULT_PAYLOAD)
        return PRS_PING_BAD;
    if (run->ctl_rx_len < total)
        return PRS_PING_NONE;
    bool match = run->ping_pending &&
                 memcmp(run->ctl_rx + sizeof(header), run->ping_token, PRS_RESULT_PAYLOAD) == 0;
    prs_rx_consume(run, total);
    return match ? PRS_PING_OK : PRS_PING_NONE;
}

enum prs_step { PRS_STEP_MORE, PRS_STEP_DONE, PRS_STEP_CLOSE };

/* One host-call frame at the head of the buffer. */
static enum prs_step prs_take_hostcall(struct plugin_run *run, uint64_t now, uint64_t end)
{
    struct plugin_hostcall_frame request;
    size_t used = 0, reply_len = 0;
    enum plugin_hostcall_status st =
        plugin_hostcall_decode(run->ctl_rx, run->ctl_rx_len, &request, &used);
    if (st == PLUGIN_HOSTCALL_ERR_TRUNCATED)
        return PRS_STEP_MORE;
    if (st != PLUGIN_HOSTCALL_OK)
        return PRS_STEP_CLOSE;
    if (!prs_rate_ok(run, now))
        return PRS_STEP_MORE; /* backpressure: the call waits for the next window */
    static const struct plugin_hostcall_handlers none = {0};
    (void)plugin_hostcall_dispatch(&request, run->grants,
                                   run->opt.hostcall ? run->opt.hostcall : &none,
                                   run->ctl_reply, PLUGIN_HOSTCALL_MAX_FRAME, &reply_len);
    /* No reply means the frame was not a request (a child must not send replies). */
    if (reply_len == 0 || !prs_reply_send(run, run->ctl_reply, reply_len, end))
        return PRS_STEP_CLOSE;
    prs_rx_consume(run, used);
    return PRS_STEP_DONE;
}

/* One pump call is bounded: PRS_PUMP_BUDGET_MS of wall clock for everything it
 * serves. A reply that cannot be written inside the budget ends the stream as a
 * protocol violation; frames still buffered when the budget is spent wait for
 * the next tick. The rate window is judged against the clock at each frame, not
 * against the tick's start, so it rolls correctly inside a long pump. */
enum prs_ping prs_control_pump(struct plugin_run *run, uint64_t now)
{
    if (!run->ctl_rx || run->launch.ipc_native == (uintptr_t)-1)
        return PRS_PING_NONE;
    prs_rx_fill(run);
    uint64_t end = prs_now_ns() + (uint64_t)PRS_PUMP_BUDGET_MS * UINT64_C(1000000);
    enum prs_ping seen = PRS_PING_NONE;
    while (run->ctl_rx_len > 0) {
        if (run->ctl_rx[0] == 0) {
            now = prs_now_ns();
            if (now >= end)
                break;
            enum prs_step step = prs_take_hostcall(run, now, end);
            if (step == PRS_STEP_CLOSE)
                return prs_control_close(run);
            if (step == PRS_STEP_MORE)
                break;
        } else if (run->ctl_rx[0] == (uint8_t)PRS_RESULT_MAGIC[0]) {
            size_t before = run->ctl_rx_len;
            enum prs_ping got = prs_take_result(run);
            if (got == PRS_PING_BAD)
                return PRS_PING_BAD;
            if (got == PRS_PING_OK)
                seen = PRS_PING_OK;
            if (run->ctl_rx_len == before)
                break;
        } else {
            return PRS_PING_BAD;
        }
    }
    return seen;
}
#endif
