/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * The best block of each connected fleet machine. See controllers/fleet_tip.h. */

#include "controllers/fleet_tip.h"

#include "controllers/blockchain_controller.h"
#include "config/runtime.h"
#include "controllers/fleet_status_controller.h"
#include "jobs/node_pace.h"
#include "json/json.h"
#include "net/tor_integration.h"
#include "platform/clock.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int64_t fleet_tip_now_secs(void)
{
    return clock_now_boottime_ms() / 1000;
}

/* ── the route ───────────────────────────────────────────────────────── */

static bool hash_is_hex(const char *hash)
{
    if (!hash || strlen(hash) != FLEET_TIP_HASH_HEX)
        return false; // raw-return-ok:not a hash
    for (size_t i = 0; i < FLEET_TIP_HASH_HEX; i++)
        if (!isxdigit((unsigned char)hash[i]))
            return false; // raw-return-ok:not a hash
    return true;
}

/* A decimal height of 1 to 10 digits. */
static bool height_from_arg(const char *arg, int64_t *out)
{
    size_t n = arg ? strlen(arg) : 0;
    int64_t v = 0;
    if (n == 0 || n > 10)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (arg[i] < '0' || arg[i] > '9')
            return false;
        v = v * 10 + (arg[i] - '0');
    }
    *out = v;
    return true;
}

static size_t wrap_ok(const char *body, int blen, uint8_t *response,
                      size_t response_max)
{
    int n = snprintf((char *)response, response_max,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/json\r\n"
                     "Cache-Control: no-store\r\n"
                     "Content-Length: %d\r\n"
                     "Connection: close\r\n\r\n%s", blen, body);
    return n > 0 && (size_t)n < response_max ? (size_t)n : 0;
}

/* The JSON body of a tip reply into `body`; its length, or 0. */
static int tip_body(const struct fleet_status_local *chain, bool has_at,
                    int64_t at, const char *at_hash, const char *hash,
                    char *body, size_t cap)
{
    int blen = snprintf(body, cap,
                        "{\"schema\":\"zcl.tip.v1\",\"height\":%lld,"
                        "\"hash\":\"%s\"", (long long)chain->tip, hash);
    if (blen > 0 && (size_t)blen < cap && has_at)
        blen += snprintf(body + blen, cap - (size_t)blen,
                         ",\"at\":{\"height\":%lld,\"hash\":\"%s\"}",
                         (long long)at, at_hash);
    if (blen > 0 && (size_t)blen < cap)
        blen += snprintf(body + blen, cap - (size_t)blen, "}");
    return blen > 0 && (size_t)blen < cap ? blen : 0;
}

/* This node's block hash at `height`, 64 hex digits, or false. */
static bool chain_hash(const struct fleet_status_local *chain, int64_t height,
                       char hash[FLEET_TIP_HASH_HEX + 1])
{
    return chain->hash_at(height, hash, chain->ctx) && hash_is_hex(hash);
}

size_t fleet_tip_respond(const struct fleet_status_local *chain,
                         const char *height_arg, uint8_t *response,
                         size_t response_max)
{
    char hash[FLEET_TIP_HASH_HEX + 1], at_hash[FLEET_TIP_HASH_HEX + 1];
    char body[FLEET_TIP_BODY_MAX];
    int64_t at = 0;
    bool has_at;
    int blen;
    if (!chain || !chain->hash_at || !response || chain->tip < 0 ||
        !chain_hash(chain, chain->tip, hash))
        return 0;
    if (height_arg && !height_from_arg(height_arg, &at))
        return 0;
    has_at = height_arg && at <= chain->tip && chain_hash(chain, at, at_hash);
    blen = tip_body(chain, has_at, at, at_hash, hash, body, sizeof body);
    return blen > 0 ? wrap_ok(body, blen, response, response_max) : 0;
}

static bool node_hash_at(int64_t height, char hex[65], void *ctx)
{
    (void)ctx;
    return rpc_blockchain_provable_hash_at(height, hex);
}

size_t fleet_tip_serve_at(const char *height_arg, uint8_t *response,
                          size_t response_max)
{
    struct fleet_status_local chain = { .hash_at = node_hash_at };
    char hex[65];
    if (!rpc_blockchain_provable_tip(&chain.tip, hex))
        return 0;
    return fleet_tip_respond(&chain, height_arg, response, response_max);
}

size_t fleet_tip_serve(uint8_t *response, size_t response_max)
{
    return fleet_tip_serve_at(NULL, response, response_max);
}

/* A {height, hash} object: height >= 0 and a 64-digit hex hash, lowercased
 * into `hash`. */
static bool pair_fields(const struct json_value *o, int64_t *height,
                        char hash[FLEET_TIP_HASH_HEX + 1])
{
    const struct json_value *h = o ? json_get(o, "height") : NULL;
    const struct json_value *x = o ? json_get(o, "hash") : NULL;
    const char *s = x && x->type == JSON_STR ? json_get_str(x) : NULL;
    if (!o || o->type != JSON_OBJ || !h || h->type != JSON_INT ||
        json_get_int(h) < 0 || !hash_is_hex(s))
        return false; // raw-return-ok:not a tip reply
    for (size_t i = 0; i < FLEET_TIP_HASH_HEX; i++)
        hash[i] = (char)tolower((unsigned char)s[i]);
    hash[FLEET_TIP_HASH_HEX] = '\0';
    *height = json_get_int(h);
    return true;
}

/* The optional `at` object. It counts only when it answers the height that
 * was asked; a malformed one fails the whole reply. */
static bool at_fields(const struct json_value *root, int64_t ask_height,
                      struct fleet_tip *out)
{
    const struct json_value *at = json_get(root, "at");
    out->has_at = false;
    if (!at)
        return true;
    if (!pair_fields(at, &out->at_height, out->at_hash))
        return false; // raw-return-ok:malformed reply, the caller refuses it
    out->has_at = ask_height > 0 && out->at_height == ask_height;
    return true;
}

bool fleet_tip_parse(const uint8_t *body, size_t len, int64_t ask_height,
                     struct fleet_tip *out)
{
    struct json_value root;
    bool ok;
    if (!body || !len || len > FLEET_TIP_BODY_MAX || !out)
        return false;
    memset(out, 0, sizeof *out);
    json_init(&root);
    ok = json_read(&root, (const char *)body, len) &&
         pair_fields(&root, &out->height, out->hash) &&
         at_fields(&root, ask_height, out);
    json_free(&root);
    return ok;
}

/* ── the cache ───────────────────────────────────────────────────────── */

struct tip_entry {
    char key[BOOT_FLEET_ROSTER_ONION_MAX];
    bool used;
    bool has_tip;
    int64_t refusal_height; /* 0: no standing refusal */
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

void fleet_tip_cache_put(const char *key, const struct fleet_tip *tip)
{
    struct tip_entry *e;
    if (!key || !tip || !hash_is_hex(tip->hash))
        return;
    pthread_mutex_lock(&g_lock);
    e = entry_for(key);
    e->tip = *tip;
    e->has_tip = true;
    pthread_mutex_unlock(&g_lock);
}

void fleet_tip_cache_raise_refusal(const char *key, int64_t height)
{
    struct tip_entry *e;
    if (!key || height <= 0)
        return;
    pthread_mutex_lock(&g_lock);
    e = entry_for(key);
    if (e->refusal_height == 0 || height < e->refusal_height)
        e->refusal_height = height;
    pthread_mutex_unlock(&g_lock);
}

void fleet_tip_cache_clear_refusal(const char *key)
{
    struct tip_entry *e;
    if (!key)
        return;
    pthread_mutex_lock(&g_lock);
    e = entry_for(key);
    e->refusal_height = 0;
    pthread_mutex_unlock(&g_lock);
}

int64_t fleet_tip_cache_refusal(const char *key)
{
    const struct tip_entry *e;
    int64_t height = 0;
    if (!key)
        return 0;
    pthread_mutex_lock(&g_lock);
    e = entry_find(key);
    if (e)
        height = e->refusal_height;
    pthread_mutex_unlock(&g_lock);
    return height;
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

int64_t fleet_tip_cache_last_try(const char *key)
{
    const struct tip_entry *e;
    int64_t at = 0;
    if (!key)
        return 0;
    pthread_mutex_lock(&g_lock);
    e = entry_find(key);
    if (e)
        at = e->last_try;
    pthread_mutex_unlock(&g_lock);
    return at;
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

/* The connected machine asked longest ago that is due, as its cache key in
 * `key`; false when none. */
static bool pick_due(const struct fleet_status *s, int64_t now,
                     char key[BOOT_FLEET_ROSTER_ONION_MAX])
{
    int64_t oldest = 0;
    bool found = false;
    for (size_t i = 0; i < s->machine_count; i++) {
        char k[BOOT_FLEET_ROSTER_ONION_MAX];
        int64_t tried;
        if (!s->machines[i].connected ||
            !fleet_status_onion_key(s->machines[i].onion, k, sizeof k))
            continue;
        tried = fleet_tip_cache_last_try(k);
        if (tried != 0 && now - tried < FLEET_TIP_REFRESH_SECS)
            continue;
        if (!found || tried < oldest) {
            memcpy(key, k, sizeof k);
            oldest = tried;
            found = true;
        }
    }
    return found;
}

bool fleet_tip_poll_step(const struct fleet_status *s,
                         const struct fleet_status_local *local,
                         struct node_db *ndb, int64_t now, bool paused,
                         fleet_tip_fetch_fn fetch)
{
    char key[BOOT_FLEET_ROSTER_ONION_MAX];
    struct fleet_tip t;
    if (paused || !s || !s->member || !fetch || !pick_due(s, now, key))
        return false;
    fleet_tip_cache_note_try(key, now);
    memset(&t, 0, sizeof t);
    if (fetch(key, local ? local->tip : 0, &t)) {
        t.fetched_at = now;
        fleet_tip_cache_put(key, &t);
        fleet_status_note_check(ndb, key, &t, local);
    }
    return true;
}

static fleet_tip_transport_fn g_transport;

void fleet_tip_set_transport(fleet_tip_transport_fn fn)
{
    g_transport = fn;
}

bool fleet_tip_fetch(const char *onion, int64_t ask_height,
                     struct fleet_tip *out)
{
    char path[sizeof FLEET_TIP_PATH + 24];
    struct onion_fetch_result res;
    fleet_tip_transport_fn send =
        g_transport ? g_transport : tor_integration_fetch_onion_blocking;
    bool ok;
    if (!onion || !out)
        return false;
    if (ask_height > 0)
        (void)snprintf(path, sizeof path, FLEET_TIP_PATH "/%lld",
                       (long long)ask_height);
    else
        (void)snprintf(path, sizeof path, "%s", FLEET_TIP_PATH);
    memset(&res, 0, sizeof res);
    ok = send(onion, path, &res, FLEET_TIP_FETCH_TIMEOUT_SECS) == 0 &&
         res.status == 200 &&
         fleet_tip_parse(res.body, res.body_len, ask_height, out);
    free(res.body);
    return ok;
}

void fleet_tip_poll_tick(void)
{
    static int64_t next_at;
    struct fleet_status *s;
    struct fleet_status_local local;
    int64_t now = fleet_tip_now_secs();
    if (now < next_at)
        return;
    next_at = now + FLEET_TIP_TICK_SECS;
    node_pace_poll();
    if (node_pace_get() == NODE_PACE_PAUSE || !tor_integration_is_ready())
        return;
    s = zcl_calloc(1, sizeof *s, "fleet_tip_status");
    if (!s)
        return;
    fleet_status_node_local(&local);
    if (fleet_status_current(s))
        (void)fleet_tip_poll_step(s, &local, app_runtime_node_db(), now, false,
                                   fleet_tip_fetch);
    free(s);
}
