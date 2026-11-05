/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The responder's keyboard path to a confined shell. The stream lane runs
 * its callbacks under one lock, so a write here must never wait for a shell
 * that is not reading. Bytes the pty cannot take right now stay in a bounded
 * tail owned by the session, behind everything already queued, and are
 * retried from the stream tick. The caller returns stream credit only for
 * bytes that reached the pty, so the peer's window bounds the tail.
 */

#include "config/boot_mesh_terminal.h"
#include "config/mesh_stream.h"

#include <string.h>

_Static_assert(MESH_TERMINAL_INPUT_TAIL_MAX == MESH_STREAM_INITIAL_WINDOW,
               "the tail is bounded by the credit window the peer holds");

/* One nonblocking write of the whole tail. Returns the bytes the pty took. */
static size_t tail_write(struct mesh_terminal_input_tail *t,
                         struct mesh_terminal_worker *w, int64_t now_unix,
                         struct zcl_result *r)
{
    w->input_nowait = true; /* never wait while the lane lock is held */
    uint64_t before = w->bytes_in;
    *r = mesh_terminal_worker_input(w, t->buf, t->len, now_unix);
    size_t wrote = (size_t)(w->bytes_in - before);
    if (wrote > t->len)
        wrote = t->len;
    if (wrote > 0) {
        memmove(t->buf, t->buf + wrote, t->len - wrote);
        t->len -= wrote;
    }
    return wrote;
}

enum mesh_terminal_input_flow mesh_terminal_input_tail_push(
    struct mesh_terminal_input_tail *t, struct mesh_terminal_worker *w,
    const uint8_t *bytes, size_t n, int64_t now_unix, uint64_t now_mono_ms)
{
    if (n > MESH_TERMINAL_INPUT_TAIL_MAX - t->len) {
        w->close_reason = MESH_TERMINAL_CLOSE_SESSION_LOST;
        return MESH_TERMINAL_INPUT_END;
    }
    if (n > 0) {
        if (t->len == 0)
            t->since_mono_ms = now_mono_ms;
        memcpy(t->buf + t->len, bytes, n);
        t->len += n;
    }
    if (t->len == 0)
        return MESH_TERMINAL_INPUT_CLEAR;
    struct zcl_result r;
    if (tail_write(t, w, now_unix, &r) > 0)
        t->since_mono_ms = now_mono_ms;
    if (r.ok)
        return MESH_TERMINAL_INPUT_CLEAR;
    if (r.code == MESH_TERMINAL_WORKER_ERR_STALLED) {
        /* Only a tail that has made no progress for the whole deadline ends
         * the session; a shell that drains slowly keeps it. */
        if (now_mono_ms < t->since_mono_ms ||
            now_mono_ms - t->since_mono_ms < MESH_TERMINAL_INPUT_STALL_MS)
            return MESH_TERMINAL_INPUT_PENDING;
        w->close_reason = MESH_TERMINAL_CLOSE_SESSION_LOST;
        return MESH_TERMINAL_INPUT_END;
    }
    /* Any other failure (the shell exited, the budget ran out) is the
     * stream tick's to name from the worker's own state: the queued bytes
     * have nowhere to go. */
    t->len = 0;
    return MESH_TERMINAL_INPUT_CLEAR;
}
