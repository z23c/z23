/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * The best block of each connected fleet machine. See controllers/fleet_tip.h. */

#include "controllers/fleet_tip.h"

#include "controllers/blockchain_controller.h"
#include "controllers/fleet_status_controller.h"
#include "jobs/node_pace.h"
#include "json/json.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── the route ───────────────────────────────────────────────────────── */

size_t fleet_tip_render(int64_t height, const char *hash, uint8_t *response,
                        size_t response_max)
{
    char body[160];
    int n, blen;
    if (!response || !hash || strlen(hash) != FLEET_TIP_HASH_HEX)
        return 0;
    for (size_t i = 0; i < FLEET_TIP_HASH_HEX; i++)
        if (!isxdigit((unsigned char)hash[i]))
            return 0;
    blen = snprintf(body, sizeof body,
                    "{\"schema\":\"zcl.tip.v1\",\"height\":%lld,"
                    "\"hash\":\"%s\"}", (long long)height, hash);
    if (blen <= 0 || (size_t)blen >= sizeof body)
        return 0;
    n = snprintf((char *)response, response_max,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/json\r\n"
                 "Cache-Control: no-store\r\n"
                 "Content-Length: %d\r\n"
                 "Connection: close\r\n\r\n%s", blen, body);
    if (n <= 0 || (size_t)n >= response_max)
        return 0;
    return (size_t)n;
}

size_t fleet_tip_serve(uint8_t *response, size_t response_max)
{
    char hash[FLEET_TIP_HASH_HEX + 1];
    int64_t height = 0;
    if (!rpc_blockchain_provable_tip(&height, hash))
        return 0;
    return fleet_tip_render(height, hash, response, response_max);
}

/* The tip object of a reply: height >= 0 and a 64-digit hex hash. */
static bool tip_fields(const struct json_value *root, int64_t *height,
                       char hash[FLEET_TIP_HASH_HEX + 1])
{
    const struct json_value *h = json_get(root, "height");
    const struct json_value *x = json_get(root, "hash");
    const char *s = x && x->type == JSON_STR ? json_get_str(x) : NULL;
    if (root->type != JSON_OBJ || !h || h->type != JSON_INT ||
        json_get_int(h) < 0 || !s || strlen(s) != FLEET_TIP_HASH_HEX)
        return false;
    for (size_t i = 0; i < FLEET_TIP_HASH_HEX; i++) {
        if (!isxdigit((unsigned char)s[i]))
            return false; // raw-return-ok:not a tip reply
        hash[i] = (char)tolower((unsigned char)s[i]);
    }
    hash[FLEET_TIP_HASH_HEX] = '\0';
    *height = json_get_int(h);
    return true;
}

bool fleet_tip_parse(const uint8_t *body, size_t len, int64_t *height,
                     char hash[FLEET_TIP_HASH_HEX + 1])
{
    struct json_value root;
    bool ok;
    if (!body || !len || len > FLEET_TIP_BODY_MAX || !height || !hash)
        return false;
    json_init(&root);
    ok = json_read(&root, (const char *)body, len) &&
         tip_fields(&root, height, hash);
    json_free(&root);
    return ok;
}

/* ── the cache ───────────────────────────────────────────────────────── */

struct tip_entry {
    char key[BOOT_FLEET_ROSTER_ONION_MAX];
    bool used;
    bool has_tip;
    int64_t last_try;
    struct fleet_tip tip;
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct tip_entry g_entries[BOOT_FLEET_ROSTER_MAX];

/* The entry for `key`; else a free one; else the least recently asked,
 * reset for `key`. Locked. */
static struct tip_entry *entry_for(const char *key)
{
    struct tip_entry *spare = &g_entries[0];
    for (size_t i = 0; i < BOOT_FLEET_ROSTER_MAX; i++)
        if (g_entries[i].used && strcmp(g_entries[i].key, key) == 0)
            return &g_entries[i];
    for (size_t i = 0; i < BOOT_FLEET_ROSTER_MAX; i++) {
        if (!g_entries[i].used) {
            spare = &g_entries[i];
            break;
        }
        if (g_entries[i].last_try < spare->last_try)
            spare = &g_entries[i];
    }
    memset(spare, 0, sizeof *spare);
    (void)snprintf(spare->key, sizeof spare->key, "%s", key);
    spare->used = true;
    return spare;
}

static const struct tip_entry *entry_find(const char *key)
{
    for (size_t i = 0; i < BOOT_FLEET_ROSTER_MAX; i++)
        if (g_entries[i].used && strcmp(g_entries[i].key, key) == 0)
            return &g_entries[i];
    return NULL;
}

void fleet_tip_cache_put(const char *key, int64_t height, const char *hash,
                         int64_t now)
{
    struct tip_entry *e;
    if (!key || !hash || strlen(hash) != FLEET_TIP_HASH_HEX)
        return;
    pthread_mutex_lock(&g_lock);
    e = entry_for(key);
    e->has_tip = true;
    e->tip.height = height;
    e->tip.fetched_at = now;
    memcpy(e->tip.hash, hash, FLEET_TIP_HASH_HEX + 1);
    pthread_mutex_unlock(&g_lock);
}

bool fleet_tip_cache_get(const char *key, struct fleet_tip *out)
{
    const struct tip_entry *e;
    bool ok = false;
    if (!key || !out)
        return false;
    pthread_mutex_lock(&g_lock);
    e = entry_find(key);
    if (e && e->has_tip) {
        *out = e->tip;
        ok = true;
    }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

bool fleet_tip_cache_due(const char *key, int64_t now)
{
    const struct tip_entry *e;
    bool due;
    if (!key)
        return false;
    pthread_mutex_lock(&g_lock);
    e = entry_find(key);
    due = !e || e->last_try == 0 || now - e->last_try >= FLEET_TIP_REFRESH_SECS;
    pthread_mutex_unlock(&g_lock);
    return due;
}

void fleet_tip_cache_note_try(const char *key, int64_t now)
{
    if (!key)
        return;
    pthread_mutex_lock(&g_lock);
    entry_for(key)->last_try = now;
    pthread_mutex_unlock(&g_lock);
}

void fleet_tip_cache_reset(void)
{
    pthread_mutex_lock(&g_lock);
    memset(g_entries, 0, sizeof g_entries);
    pthread_mutex_unlock(&g_lock);
}

/* ── the schedule ────────────────────────────────────────────────────── */

bool fleet_tip_poll_step(const struct fleet_status *s, int64_t now,
                         bool paused, fleet_tip_fetch_fn fetch)
{
    if (paused || !s || !s->member || !fetch)
        return false;
    for (size_t i = 0; i < s->machine_count; i++) {
        const struct fleet_status_machine *m = &s->machines[i];
        char key[BOOT_FLEET_ROSTER_ONION_MAX];
        char hash[FLEET_TIP_HASH_HEX + 1];
        int64_t height = 0;
        if (!m->connected || !fleet_status_onion_key(m->onion, key, sizeof key) ||
            !fleet_tip_cache_due(key, now))
            continue;
        fleet_tip_cache_note_try(key, now);
        if (fetch(key, &height, hash))
            fleet_tip_cache_put(key, height, hash, now);
        return true;
    }
    return false;
}

/* One fetch of a machine's tip over Tor, bounded and never retried here. */
static bool fetch_tip_over_tor(const char *onion, int64_t *height,
                               char hash[FLEET_TIP_HASH_HEX + 1])
{
    struct onion_fetch_result res;
    bool ok;
    memset(&res, 0, sizeof res);
    ok = tor_integration_fetch_onion_blocking(onion, FLEET_TIP_PATH, &res,
                                              FLEET_TIP_FETCH_TIMEOUT_SECS) ==
             0 &&
         res.status == 200 &&
         fleet_tip_parse(res.body, res.body_len, height, hash);
    free(res.body);
    return ok;
}

void fleet_tip_poll_tick(void)
{
    static int64_t next_at;
    struct fleet_status *s;
    int64_t now = platform_time_monotonic_ms() / 1000;
    if (now < next_at)
        return;
    next_at = now + FLEET_TIP_TICK_SECS;
    node_pace_poll();
    if (node_pace_get() == NODE_PACE_PAUSE || !tor_integration_is_ready())
        return;
    s = zcl_calloc(1, sizeof *s, "fleet_tip_status");
    if (!s)
        return;
    if (fleet_status_current(s))
        (void)fleet_tip_poll_step(s, now, false, fetch_tip_over_tor);
    free(s);
}
