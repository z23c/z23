/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Event-log route handlers for the REST API controller. */
#include "api_controller_internal.h"
#include "event/event.h"
#include "json/json.h"
#include "sync/sync_state.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Event log - lock-free atomic reads, safe from any handler thread. */
size_t api_serve_events(const char *path, uint8_t *response,
                        size_t response_max)
{
    enum { EVENT_JSON_BUF_SIZE = 524288 };
    size_t count = 200;
    const char *q = strchr(path, '?');

    if (q) {
        const char *cp = strstr(q, "limit=");
        if (!cp)
            cp = strstr(q, "count=");
        if (cp) {
            const char *value = strchr(cp, '=');
            long v = value ? strtol(value + 1, NULL, 10) : 0;
            if (v > 0 && v <= 65536)
                count = (size_t)v;
        }
    }

    char *buf = zcl_malloc(EVENT_JSON_BUF_SIZE, "api_events_buf");
    if (!buf)
        return api_json_error(response, response_max, JSON_500_HEADERS,
                              "Out of memory");

    const char *type_filter = NULL;
    char type_buf[64];
    if (q) {
        const char *tp = strstr(q, "type=");
        if (tp) {
            size_t tlen = 0;
            for (const char *c = tp + 5; *c && *c != '&' && tlen < 63; c++)
                type_buf[tlen++] = *c;
            type_buf[tlen] = '\0';
            type_filter = type_buf;
        }
    }

    size_t w;
    if (type_filter)
        w = event_dump_json_filtered(buf, EVENT_JSON_BUF_SIZE, count,
                                     type_filter);
    else
        w = event_dump_json(buf, EVENT_JSON_BUF_SIZE, count);

    if (w >= EVENT_JSON_BUF_SIZE) {
        free(buf);
        return api_json_error(response, response_max, JSON_500_HEADERS,
                              "Event response too large");
    }
    buf[w] = '\0';

    struct json_value events;
    json_init(&events);
    if (w == 0) {
        json_set_array(&events);
    } else if (!json_read(&events, buf, w)) {
        free(buf);
        return api_json_error(response, response_max, JSON_500_HEADERS,
                              "Event log response invalid");
    }
    free(buf);

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.events.index.v1");
    api_json_add_freshness(&body, "event_projection", -1);
    json_push_kv_str(&body, "sync_state", sync_state_name(sync_get_state()));
    json_push_kv_int(&body, "limit", (int64_t)count);
    json_push_kv_str(&body, "type", type_filter ? type_filter : "");
    json_push_kv(&body, "events", &events);
    json_free(&events);

    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}
