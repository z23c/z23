/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Share strict row decoding across the fixed local worker boundary. */
#include "command/native_app_network_row.h"
#include "base/safe_alloc.h"
#include <stdlib.h>
#include <string.h>
static bool anr_keys(const struct json_value *v)
{
    if (!v || v->type != JSON_OBJ || v->num_children != 4 || !v->keys) return false;
    unsigned seen = 0;
    for (size_t i = 0; i < v->num_children; ++i) {
        const char *key = v->keys[i]; unsigned bit = !strcmp(key, "post_id") ? 1u :
            !strcmp(key, "host") ? 2u : !strcmp(key, "created_at") ? 4u : !strcmp(key, "offer") ? 8u : 0u;
        if (!bit || (seen & bit)) return false;
        seen |= bit;
    }
    return seen == 15;
}
const char *app_network_json_string(const struct json_value *v, const char *key)
{
    const struct json_value *item = json_get(v, key);
    return item && item->type == JSON_STR ? json_get_str(item) : NULL;
}
bool app_network_json_canonical(const struct json_value *v, const char *wire, size_t len)
{
    if (json_write(v, NULL, 0) != len) return false;
    char *canonical = zcl_malloc(len + 1, "network.job.canonical");
    if (!canonical) return false;
    bool ok = json_write(v, canonical, len + 1) == len && !memcmp(canonical, wire, len);
    free(canonical); return ok;
}
bool app_network_row_equal(const struct zcl_app_offer_row *a, const struct zcl_app_offer_row *b)
{
    const struct zcl_app_offer *x = &a->offer, *y = &b->offer;
    return !strcmp(a->post_id, b->post_id) && !strcmp(a->host, b->host) &&
        a->created_at == b->created_at && !strcmp(x->name, y->name) &&
        !strcmp(x->root, y->root) && !strcmp(x->publisher, y->publisher) &&
        !strcmp(x->carrier, y->carrier) && !strcmp(x->sha256, y->sha256) &&
        !strcmp(x->onion, y->onion) && x->size == y->size;
}
bool app_network_row_decode(const struct json_value *v, struct zcl_app_offer_row *row)
{
    if (!row || !anr_keys(v)) return false;
    const char *id = app_network_json_string(v, "post_id"), *host = app_network_json_string(v, "host");
    const char *offer = app_network_json_string(v, "offer"); const struct json_value *created = json_get(v, "created_at");
    if (!vcs_app_offer_hex_valid(id, 32) || !vcs_app_offer_hex_valid(host, 32) ||
        !created || created->type != JSON_INT || json_get_int(created) <= 0 || !offer ||
        !zcl_app_offer_parse(offer, strlen(offer), &row->offer)) return false;
    memcpy(row->post_id, id, 65); memcpy(row->host, host, 65); row->created_at = json_get_int(created); return true;
}
