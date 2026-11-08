/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Parse and format canonical app offers and consent bindings. */
#include "vcs/app_offer.h"
#include "base/hex.h"
#include "json/json.h"
#include "sha3/sha3.h"
#include <stdio.h>
#include <string.h>
#define ZAO_FIELDS 8u
void vcs_app_plan_hash(const char *domain, const char *const *parts,
                       size_t count, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, strlen(domain) + 1u);
    for (size_t i = 0; i < count; i++) {
        const char *p = parts[i] ? parts[i] : "";
        sha3_256_write(&ctx, (const uint8_t *)p, strlen(p) + 1u);
    }
    sha3_256_finalize(&ctx, out);
}
bool vcs_app_offer_hex_valid(const char *s, size_t bytes)
{
    uint8_t buf[64];
    return s && bytes <= sizeof(buf) && strlen(s) == 2u * bytes &&
           zcl_hex_decode_lower(s, buf, bytes);
}

static bool zao_name_half(const char *s, size_t len)
{
    if (len == 0 || len > VCS_PACKAGE_RELEASE_NAME_HALF_MAX || s[0] == '-' ||
        s[len - 1u] == '-')
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

/* publisher/package, each half [a-z0-9-], as a release name. */
static bool zao_name(const char *s)
{
    const char *slash = s ? strchr(s, '/') : NULL;
    size_t len = s ? strlen(s) : 0;
    if (!slash || len > VCS_PACKAGE_RELEASE_NAME_MAX)
        return false;
    size_t head = (size_t)(slash - s);
    return zao_name_half(s, head) &&
           zao_name_half(slash + 1, len - head - 1u);
}

bool zcl_app_offer_valid(const struct zcl_app_offer *o)
{
    return o && zao_name(o->name) && vcs_app_offer_hex_valid(o->root, 32) &&
           vcs_app_offer_hex_valid(o->publisher, 33) && vcs_app_offer_hex_valid(o->carrier, 32) &&
           vcs_app_offer_hex_valid(o->sha256, 32) && o->size >= 1 &&
           o->size <= (int64_t)ZCL_APP_OFFER_SIZE_MAX &&
           strlen(o->onion) <= ZCL_APP_OFFER_ONION_MAX &&
           vcs_app_offer_peer_is_onion(o->onion);
}

bool vcs_app_get_recurring_plan(const struct zcl_app_offer *o,
                                const char *post_id, const char *post_host,
                                const char *receive_plan, const char *datadir,
                                const char *token, uint8_t out[32])
{
    if (!zcl_app_offer_valid(o) || !vcs_app_offer_hex_valid(post_id, 32) ||
        !vcs_app_offer_hex_valid(post_host, 32) || !vcs_app_offer_hex_valid(receive_plan, 32) ||
        !datadir || !datadir[0] || !vcs_app_offer_hex_valid(token, 16) || !out) return false;
    char size[32];
    int n = snprintf(size, sizeof(size), "%lld", (long long)o->size);
    if (n <= 0 || (size_t)n >= sizeof(size)) return false;
    const char *parts[] = {post_id, post_host, o->name, o->root, o->publisher,
        o->carrier, o->sha256, size, o->onion, receive_plan, datadir, token,
        "public-rebuild-report-v1", "pin-and-recurring-public-host-v2"};
    vcs_app_plan_hash("zcl.app_get.plan.v2", parts, sizeof(parts) / sizeof(parts[0]), out);
    return true;
}

bool zcl_app_offer_format(const struct zcl_app_offer *o, char *out,
                          size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    if (!zcl_app_offer_valid(o))
        return false;
    int n = snprintf(out, cap,
                     "{\"schema\":\"" ZCL_APP_OFFER_SCHEMA "\",\"name\":\"%s\","
                     "\"root\":\"%s\",\"publisher\":\"%s\",\"carrier\":\"%s\","
                     "\"sha256\":\"%s\",\"size\":%lld,\"onion\":\"%s\"}",
                     o->name, o->root, o->publisher, o->carrier, o->sha256,
                     (long long)o->size, o->onion);
    bool ok = n > 0 && (size_t)n < cap && (size_t)n <= ZCL_APP_OFFER_TEXT_MAX;
    if (!ok)
        out[0] = '\0';
    return ok;
}

/* ── strict parse ────────────────────────────────────────────────────── */

static bool zao_copy(char *dst, size_t cap, const struct json_value *v)
{
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    if (!s || strlen(s) >= cap)
        return false;
    (void)snprintf(dst, cap, "%s", s);
    return true;
}

/* One key of the entry into its field; false for an unknown key, a wrong
 * type or an over-long value. */
static bool zao_field(struct zcl_app_offer *o, const char *key,
                      const struct json_value *v, unsigned *seen)
{
    static const char *const keys[ZAO_FIELDS] = {
        "schema", "name", "root", "publisher", "carrier", "sha256", "size",
        "onion"};
    char schema[32];
    char *dst[ZAO_FIELDS] = {schema, o->name, o->root, o->publisher,
                             o->carrier, o->sha256, NULL, o->onion};
    size_t cap[ZAO_FIELDS] = {sizeof(schema), sizeof(o->name),
                              sizeof(o->root), sizeof(o->publisher),
                              sizeof(o->carrier), sizeof(o->sha256), 0,
                              sizeof(o->onion)};
    for (unsigned i = 0; key && i < ZAO_FIELDS; i++) {
        if (strcmp(key, keys[i]) != 0)
            continue;
        if (*seen & (1u << i))
            return false;
        *seen |= 1u << i;
        if (!dst[i]) {
            o->size = v->type == JSON_INT ? json_get_int(v) : 0;
            return v->type == JSON_INT;
        }
        return zao_copy(dst[i], cap[i], v) &&
               (i != 0 || strcmp(schema, ZCL_APP_OFFER_SCHEMA) == 0);
    }
    return false;
}

bool zcl_app_offer_parse(const char *text, size_t len,
                         struct zcl_app_offer *o)
{
    struct json_value doc;
    unsigned seen = 0;
    if (!o)
        return false;
    memset(o, 0, sizeof(*o));
    if (!text || len == 0 || len > ZCL_APP_OFFER_TEXT_MAX ||
        memchr(text, '\0', len))
        return false;
    json_init(&doc);
    bool ok = json_read(&doc, text, len) && doc.type == JSON_OBJ &&
              doc.num_children == ZAO_FIELDS && doc.keys;
    for (size_t i = 0; ok && i < doc.num_children; i++)
        ok = zao_field(o, doc.keys[i], &doc.children[i], &seen);
    json_free(&doc);
    ok = ok && seen == (1u << ZAO_FIELDS) - 1u && zcl_app_offer_valid(o);
    if (!ok)
        memset(o, 0, sizeof(*o));
    return ok;
}
static bool zfb_onion_label(const char *peer)
{
    for (size_t i = 0; i < 56u; i++) {
        char c = peer[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')))
            return false;
    }
    return strncmp(peer + 56u, ".onion", 6) == 0;
}

static bool zfb_onion_port(const char *port)
{
    if (*port == '\0')
        return true;
    if (*port != ':' || port[1] == '\0' || strlen(port + 1) > 5u)
        return false;
    uint32_t value = 0;
    for (const char *p = port + 1; *p; p++) {
        if (*p < '0' || *p > '9')
            return false;
        value = value * 10u + (uint32_t)(*p - '0');
    }
    return value >= 1u && value <= 65535u;
}

bool vcs_app_offer_peer_is_onion(const char *peer)
{
    if (!peer || strlen(peer) < 56u + 6u)
        return false;
    return zfb_onion_label(peer) &&
           zfb_onion_port(peer + 56u + 6);
}

static bool offer_true(const struct json_value *data, const char *key)
{
    const struct json_value *value = json_get(data, key);
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static int offer_p2p_port(const struct json_value *data)
{
    const struct json_value *routes = json_get(json_get(data, "port_mapping"), "routes");
    if (!routes || routes->type != JSON_ARR) return 0;
    int port = 0;
    for (size_t i = 0; i < json_size(routes); ++i) {
        const struct json_value *route = json_at(routes, i);
        const char *name = json_get_str(json_get(route, "name"));
        if (!name || strcmp(name, "p2p_tcp")) continue;
        const struct json_value *value = json_get(route, "virtual_port");
        if (port || !offer_true(route, "installed") || !value ||
            value->type != JSON_INT || json_get_int(value) < 1 || json_get_int(value) > 65535) return 0;
        port = (int)json_get_int(value);
    }
    return port;
}

bool vcs_app_offer_endpoint(const struct json_value *data, char host[static 63],
                            char endpoint[static ZCL_APP_OFFER_ONION_MAX + 1u])
{
    host[0] = endpoint[0] = '\0';
    const char *address = json_get_str(json_get(data, "onion_address"));
    const char *state = json_get_str(json_get(data, "bootstrap_state"));
    int port = offer_p2p_port(data);
    bool ready = state && !strcmp(state, "ready") &&
        offer_true(data, "tor_ready") &&
        offer_true(data, "onion_service_ready") &&
        offer_true(data, "p2p_publish_ready") && address &&
        strlen(address) == 62 && port && vcs_app_offer_peer_is_onion(address);
    if (ready) {
        (void)snprintf(host, 63, "%s", address);
        int n = snprintf(endpoint, ZCL_APP_OFFER_ONION_MAX + 1u, "%s:%d", address, port);
        ready = n > 0 && (size_t)n <= ZCL_APP_OFFER_ONION_MAX;
    }
    return ready;
}
