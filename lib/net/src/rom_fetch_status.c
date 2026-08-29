/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM artifact fetching — status/observability side, split out of
 * rom_fetch.c. See net/rom_fetch.h for the contract and
 * rom_fetch_internal.h for the one seam that crosses the split: the three
 * rf_note_* narrators every download driver in rom_fetch.c calls into. */
#include "rom_fetch_internal.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "base/text_fit.h"
#include <pthread.h>
#include <stdio.h>

#define RF_SUBSYS "rom_fetch"

/* ── Fetch status (observability) ───────────────────────────────────── */

static struct rom_fetch_status g_status;
static pthread_mutex_t g_status_mutex = PTHREAD_MUTEX_INITIALIZER;

void rf_note_begin(const char *peer_addr, uint16_t port,
                   const struct rom_fetch_manifest *m)
{
    pthread_mutex_lock(&g_status_mutex);
    g_status.ever_attempted = true;
    g_status.in_progress = true;
    g_status.last_ok = false;
    char peer[160];
    snprintf(peer, sizeof(peer), "%s:%u", peer_addr, (unsigned)port);
    (void)zcl_text_fit(g_status.peer, sizeof(g_status.peer), peer,
                       RF_SUBSYS, "status.peer");
    snprintf(g_status.filename, sizeof(g_status.filename), "%s", m->filename);
    g_status.detail[0] = '\0';
    g_status.size_bytes = m->size_bytes;
    g_status.num_chunks = m->num_chunks;
    g_status.chunks_done = 0;
    g_status.bytes_done = 0;
    g_status.started_unix = (int64_t)platform_time_wall_time_t();
    g_status.finished_unix = 0;
    g_status.attempts++;
    pthread_mutex_unlock(&g_status_mutex);
}

void rf_note_progress(uint32_t chunks_done, uint64_t bytes_done)
{
    pthread_mutex_lock(&g_status_mutex);
    g_status.chunks_done = chunks_done;
    g_status.bytes_done = bytes_done;
    pthread_mutex_unlock(&g_status_mutex);
}

void rf_note_end(bool ok, const char *detail)
{
    pthread_mutex_lock(&g_status_mutex);
    g_status.in_progress = false;
    g_status.last_ok = ok;
    g_status.finished_unix = (int64_t)platform_time_wall_time_t();
    (void)zcl_text_fit(g_status.detail, sizeof(g_status.detail), detail,
                       RF_SUBSYS, "status.detail");
    if (ok) {
        g_status.successes++;
        g_status.bytes_total += g_status.bytes_done;
    } else {
        g_status.failures++;
    }
    pthread_mutex_unlock(&g_status_mutex);
}

void rom_fetch_status_snapshot(struct rom_fetch_status *out)
{
    if (!out)
        return;
    pthread_mutex_lock(&g_status_mutex);
    *out = g_status;
    pthread_mutex_unlock(&g_status_mutex);
}

/* ── Introspection ──────────────────────────────────────────────────── */

bool rom_fetch_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct rom_fetch_status s;
    rom_fetch_status_snapshot(&s);

    json_push_kv_bool(out, "ever_attempted", s.ever_attempted);
    json_push_kv_bool(out, "in_progress", s.in_progress);
    json_push_kv_bool(out, "last_ok", s.last_ok);
    json_push_kv_int(out, "attempts", (int64_t)s.attempts);
    json_push_kv_int(out, "successes", (int64_t)s.successes);
    json_push_kv_int(out, "failures", (int64_t)s.failures);
    json_push_kv_int(out, "bytes_installed_total", (int64_t)s.bytes_total);

    if (s.ever_attempted) {
        struct json_value last = {0};
        json_set_object(&last);
        json_push_kv_str(&last, "peer", s.peer);
        json_push_kv_str(&last, "filename", s.filename);
        json_push_kv_int(&last, "size_bytes", (int64_t)s.size_bytes);
        json_push_kv_int(&last, "num_chunks", (int64_t)s.num_chunks);
        json_push_kv_int(&last, "chunks_done", (int64_t)s.chunks_done);
        json_push_kv_int(&last, "bytes_done", (int64_t)s.bytes_done);
        json_push_kv_int(&last, "started_unix", s.started_unix);
        json_push_kv_int(&last, "finished_unix", s.finished_unix);
        if (s.detail[0])
            json_push_kv_str(&last, "detail", s.detail);
        json_push_kv(out, "last", &last);
        json_free(&last);
    }

    diag_push_health(out, true,
                     s.in_progress ? "fetch in progress"
                                   : "fetch engine idle");
    return true;
}
