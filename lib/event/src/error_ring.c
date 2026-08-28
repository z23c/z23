/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the error accumulator — a small fixed ring that keeps the most
 * recent error events so status callers can say what went wrong without
 * walking the whole event log. Split out of event.c, which owns the log
 * itself; the two share only the observer signature. */

#include "platform/time_compat.h"
#include "event/event.h"
#include <stdio.h>
#include <string.h>

static struct error_ring g_error_ring;

void error_ring_init(struct error_ring *r)
{
    memset(r, 0, sizeof(*r));
    atomic_store(&r->write_pos, 0);
    atomic_store(&r->total_count, 0);
}

void error_ring_observer(enum event_type type, uint32_t peer_id,
                         const void *payload, uint32_t payload_len, void *ctx)
{
    (void)peer_id;
    struct error_ring *r = (struct error_ring *)ctx;
    int pos = atomic_fetch_add(&r->write_pos, 1) % ERROR_RING_SIZE;
    struct error_entry *e = &r->entries[pos];

    e->timestamp_us = platform_time_realtime_us();
    e->type = type;
    if (payload && payload_len > 0) {
        size_t copy = payload_len < sizeof(e->message) - 1
                      ? payload_len : sizeof(e->message) - 1;
        memcpy(e->message, payload, copy);
        e->message[copy] = '\0';
    } else {
        e->message[0] = '\0';
    }
    atomic_fetch_add(&r->total_count, 1);
}

int error_ring_total(const struct error_ring *r)
{
    return atomic_load(&r->total_count);
}

const struct error_entry *error_ring_last(const struct error_ring *r)
{
    int total = atomic_load(&r->total_count);
    if (total == 0) return NULL;
    int pos = (atomic_load(&r->write_pos) - 1 + ERROR_RING_SIZE) % ERROR_RING_SIZE;
    return &r->entries[pos];
}

size_t error_ring_dump_json(const struct error_ring *r, char *buf, size_t sz)
{
    /* Every write below assumes at least the three bytes an empty result
     * needs ("[", "]", NUL). Below that, sz - 2 and sz - 3 wrap as size_t
     * and the clamps become huge values, so refuse outright. */
    if (!r || !buf || sz < 3) return 0;

    int total = atomic_load(&r->total_count);
    int count = total < ERROR_RING_SIZE ? total : ERROR_RING_SIZE;
    int wp = atomic_load(&r->write_pos);

    /* snprintf returns the WOULD-BE length, not the truncated length.
     * Accumulating that into `off` without clamping lets `off` run past
     * `sz`, and the next `sz - off` becomes a huge unsigned value — a
     * buffer overrun on every subsequent write. Clamp after every call. */
    size_t off = 0;
    int wr = snprintf(buf, sz, "{\"total\":%d,\"errors\":[", total);
    if (wr < 0) return 0;
    off = (size_t)wr < sz ? (size_t)wr : sz - 1;

    for (int i = 0; i < count && off < sz - 2; i++) {
        int idx = (wp - count + i + ERROR_RING_SIZE) % ERROR_RING_SIZE;
        const struct error_entry *e = &r->entries[idx];
        /* Separator only BETWEEN entries: an unconditional comma here
         * emits {"errors":[,{...}]}, which is not JSON, and the one
         * consumer (api_json_push_recent_errors) silently falls back to
         * an empty array on a parse failure -- so the field would read
         * as "no recent errors" in exactly the case it exists for. */
        if (i > 0) {
            wr = snprintf(buf + off, sz - off, ",");
            if (wr < 0) break;
            off += (size_t)wr < sz - off ? (size_t)wr : sz - off - 1;
        }

        wr = snprintf(buf + off, sz - off,
            "{\"type\":\"%s\",\"time\":%lld,\"msg\":\"%s\"}",
            event_type_name(e->type),
            (long long)(e->timestamp_us / 1000000),
            e->message);
        if (wr < 0) break;
        off += (size_t)wr < sz - off ? (size_t)wr : sz - off - 1;
    }

    if (off >= sz - 2) off = sz - 3 > 0 ? sz - 3 : 0;
    wr = snprintf(buf + off, sz - off, "]}");
    if (wr > 0) off += (size_t)wr < sz - off ? (size_t)wr : sz - off - 1;
    return off;
}

struct error_ring *error_ring_global(void)
{
    return &g_error_ring;
}
