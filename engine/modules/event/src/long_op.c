/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Implementation of util/long_op.h — see header for rationale.
 *
 * A fixed-size table of up to LONG_OP_TABLE_SIZE scopes is protected
 * by a single pthread mutex. begin/end/tick walk the table; the table
 * is small (8 entries) so the linear scan is negligible compared to
 * the work each long_op represents.
 *
 * Event emission:
 *   - long_op_begin() emits EV_LONG_OP_BEGIN once
 *   - long_op_tick() updates last_tick_us every call, but rate-limits
 *     EV_LONG_OP_TICK emission to once per LONG_OP_TICK_EMIT_SECS
 *   - long_op_end() emits EV_LONG_OP_END once
 *
 * Activity gate:
 *   long_op_is_active() returns true iff any scope has had a tick
 *   (or begin) within the last LONG_OP_ACTIVE_WINDOW_SECS.
 */

#include "platform/time_compat.h"
#include "event/long_op.h"

#include "event/event.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define LONG_OP_TABLE_SIZE          8
#define LONG_OP_TICK_EMIT_SECS     30
#define LONG_OP_ACTIVE_WINDOW_SECS 60

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct long_op_scope *g_table[LONG_OP_TABLE_SIZE];

void long_op_begin(struct long_op_scope *s, const char *label)
{
    if (!s) {
        fprintf(stderr,
                "[long_op] %s:%d %s(): NULL scope pointer\n",
                __FILE__, __LINE__, __func__);
        return;
    }

    int64_t now = platform_time_monotonic_us();
    s->label         = label ? label : "(unnamed)";
    s->begin_us      = now;
    s->last_tick_us  = now;
    s->tick_count    = 0;
    s->registered    = false;

    pthread_mutex_lock(&g_mu);
    for (size_t i = 0; i < LONG_OP_TABLE_SIZE; i++) {
        if (g_table[i] == NULL) {
            g_table[i] = s;
            s->registered = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);

    if (!s->registered) {
        /* Table full — still log/emit, but the scope won't gate the
         * watchdog. Better than silent drop. */
        fprintf(stderr,
                "[long_op] %s:%d %s(): table full, '%s' not registered\n",
                __FILE__, __LINE__, __func__, s->label);
    }

    event_emitf(EV_LONG_OP_BEGIN, 0,
                "label=%s begin_us=%lld",
                s->label, (long long)now);
}

void long_op_tick(struct long_op_scope *s)
{
    if (!s) return;

    int64_t now = platform_time_monotonic_us();
    int64_t prev = s->last_tick_us;
    s->last_tick_us = now;
    s->tick_count++;

    /* Rate-limit emit. Always update last_tick_us above so the
     * watchdog-suppression window stays fresh even when we don't
     * emit. */
    int64_t since_prev_us = now - prev;
    if (since_prev_us >= (int64_t)LONG_OP_TICK_EMIT_SECS * 1000000) {
        event_emitf(EV_LONG_OP_TICK, 0,
                    "label=%s age_us=%lld tick=%lld",
                    s->label ? s->label : "(unnamed)",
                    (long long)(now - s->begin_us),
                    (long long)s->tick_count);
    }
}

void long_op_end(struct long_op_scope *s)
{
    if (!s) return;

    int64_t now = platform_time_monotonic_us();
    int64_t duration_us = now - s->begin_us;

    if (s->registered) {
        pthread_mutex_lock(&g_mu);
        for (size_t i = 0; i < LONG_OP_TABLE_SIZE; i++) {
            if (g_table[i] == s) {
                g_table[i] = NULL;
                break;
            }
        }
        pthread_mutex_unlock(&g_mu);
        s->registered = false;
    }

    event_emitf(EV_LONG_OP_END, 0,
                "label=%s duration_us=%lld ticks=%lld ok=true",
                s->label ? s->label : "(unnamed)",
                (long long)duration_us,
                (long long)s->tick_count);
}

bool long_op_is_active(int64_t *last_tick_age_secs)
{
    int64_t now = platform_time_monotonic_us();
    int64_t window_us = (int64_t)LONG_OP_ACTIVE_WINDOW_SECS * 1000000;
    int64_t newest_tick_us = 0;
    bool active = false;

    pthread_mutex_lock(&g_mu);
    for (size_t i = 0; i < LONG_OP_TABLE_SIZE; i++) {
        struct long_op_scope *s = g_table[i];
        if (!s) continue;
        if ((now - s->last_tick_us) <= window_us) {
            active = true;
            if (s->last_tick_us > newest_tick_us)
                newest_tick_us = s->last_tick_us;
        }
    }
    pthread_mutex_unlock(&g_mu);

    if (last_tick_age_secs) {
        if (active && newest_tick_us > 0)
            *last_tick_age_secs = (now - newest_tick_us) / 1000000;
        else
            *last_tick_age_secs = 0;
    }
    return active;
}

const char *long_op_recent_label(void)
{
    const char *label = NULL;
    int64_t newest_tick_us = 0;

    pthread_mutex_lock(&g_mu);
    for (size_t i = 0; i < LONG_OP_TABLE_SIZE; i++) {
        struct long_op_scope *s = g_table[i];
        if (!s) continue;
        if (s->last_tick_us > newest_tick_us) {
            newest_tick_us = s->last_tick_us;
            label = s->label;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return label;
}

bool long_op_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;

    json_set_object(out);
    int64_t now = platform_time_monotonic_us();

    struct json_value arr = {0};
    json_set_array(&arr);

    int active_count = 0;
    int64_t newest_tick_us = 0;
    const char *newest_label = NULL;

    pthread_mutex_lock(&g_mu);
    for (size_t i = 0; i < LONG_OP_TABLE_SIZE; i++) {
        struct long_op_scope *s = g_table[i];
        if (!s) continue;
        active_count++;
        if (s->last_tick_us > newest_tick_us) {
            newest_tick_us = s->last_tick_us;
            newest_label = s->label;
        }

        struct json_value entry = {0};
        json_set_object(&entry);
        json_push_kv_str(&entry, "label", s->label ? s->label : "(unnamed)");
        json_push_kv_int(&entry, "age_us",
                         (int64_t)(now - s->begin_us));
        json_push_kv_int(&entry, "last_tick_age_us",
                         (int64_t)(now - s->last_tick_us));
        json_push_kv_int(&entry, "tick_count", s->tick_count);
        json_push_back(&arr, &entry);
        json_free(&entry);
    }
    pthread_mutex_unlock(&g_mu);

    json_push_kv(out, "scopes", &arr);
    json_free(&arr);
    json_push_kv_int(out, "active_count", (int64_t)active_count);
    json_push_kv_int(out, "table_size", (int64_t)LONG_OP_TABLE_SIZE);
    json_push_kv_int(out, "tick_emit_secs",
                     (int64_t)LONG_OP_TICK_EMIT_SECS);
    json_push_kv_int(out, "active_window_secs",
                     (int64_t)LONG_OP_ACTIVE_WINDOW_SECS);
    if (active_count > 0 && newest_label) {
        json_push_kv_str(out, "recent_label", newest_label);
        json_push_kv_int(out, "recent_tick_age_secs",
                         (newest_tick_us > 0)
                            ? (int64_t)((now - newest_tick_us) / 1000000)
                            : (int64_t)0);
    } else {
        json_push_kv_str(out, "recent_label", "");
        json_push_kv_int(out, "recent_tick_age_secs", 0);
    }
    return true;
}
