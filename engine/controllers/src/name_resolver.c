/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names resolution + the error taxonomy. See
 * controllers/name_resolver.h for the contract and why the three failure
 * modes must stay distinguishable.
 *
 * Read-only: db_znam_find / db_znam_addr_get / db_znam_text_get /
 * db_tx_find_native_or_reversed. No writes, no chain scan, no allocation. */

#include "controllers/name_resolver.h"
#include "controllers/name_controller.h"   /* znam_type_name */
#include "models/tx_index.h"
#include "json/json.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

/* ── Target-type parsing ────────────────────────────────────────── */

uint8_t znam_type_from_name(const char *s)
{
    if (!s || !s[0]) return 0;
    if (strcmp(s, "onion") == 0) return ZNAM_TYPE_ONION;
    if (strcmp(s, "zaddr") == 0 || strcmp(s, "z-address") == 0)
        return ZNAM_TYPE_ZADDR;
    if (strcmp(s, "taddr") == 0 || strcmp(s, "t-address") == 0)
        return ZNAM_TYPE_TADDR;
    if (strcmp(s, "btc") == 0 || strcmp(s, "bitcoin") == 0)
        return ZNAM_TYPE_BTC;
    if (strcmp(s, "ltc") == 0 || strcmp(s, "litecoin") == 0)
        return ZNAM_TYPE_LTC;
    if (strcmp(s, "doge") == 0 || strcmp(s, "dogecoin") == 0)
        return ZNAM_TYPE_DOGE;
    if (strcmp(s, "content") == 0 || strcmp(s, "content-hash") == 0)
        return ZNAM_TYPE_CONTENT;
    return 0;
}

/* ── Taxonomy vocabulary ────────────────────────────────────────── */

const char *name_resolve_status_code(enum name_resolve_status s)
{
    switch (s) {
    case NAME_RESOLVE_OK:                    return "NAME_OK";
    case NAME_RESOLVE_MALFORMED:             return "NAME_MALFORMED";
    case NAME_RESOLVE_ABSENT:                return "NAME_ABSENT";
    case NAME_RESOLVE_NO_SUCH_TARGET:        return "NAME_NO_SUCH_TARGET";
    case NAME_RESOLVE_TYPE_UNKNOWN:          return "NAME_TYPE_UNKNOWN";
    case NAME_RESOLVE_REGISTRY_UNAVAILABLE:  return "NAME_REGISTRY_UNAVAILABLE";
    }
    return "NAME_UNKNOWN_STATUS";
}

const char *name_resolve_status_message(enum name_resolve_status s)
{
    switch (s) {
    case NAME_RESOLVE_OK:
        return "Resolved.";
    case NAME_RESOLVE_MALFORMED:
        return "That is not a valid ZCL Name. A name is 1-63 characters, "
               "lowercase letters, digits and hyphens only — nothing was "
               "looked up.";
    case NAME_RESOLVE_ABSENT:
        return "That name is well-formed but has never been registered on "
               "chain. It is available: anyone can claim it, "
               "first-come-first-served.";
    case NAME_RESOLVE_NO_SUCH_TARGET:
        return "That name IS registered, but its owner has published no "
               "record of the target type you asked for. The name has an "
               "owner — ask them to add one, or look at the records it "
               "does carry.";
    case NAME_RESOLVE_TYPE_UNKNOWN:
        return "No such ZCL Name target type. Valid types are onion, zaddr, "
               "taddr, btc, ltc, doge, content.";
    case NAME_RESOLVE_REGISTRY_UNAVAILABLE:
        return "This node's name registry is not available right now, so "
               "the name could not be looked up. This says nothing about "
               "whether the name is registered.";
    }
    return "Unknown resolution status.";
}

const char *name_resolve_status_http(enum name_resolve_status s)
{
    switch (s) {
    case NAME_RESOLVE_OK:                    return "200 OK";
    case NAME_RESOLVE_MALFORMED:             return "400 Bad Request";
    case NAME_RESOLVE_TYPE_UNKNOWN:          return "400 Bad Request";
    case NAME_RESOLVE_ABSENT:                return "404 Not Found";
    case NAME_RESOLVE_NO_SUCH_TARGET:        return "404 Not Found";
    case NAME_RESOLVE_REGISTRY_UNAVAILABLE:  return "503 Service Unavailable";
    }
    return "500 Internal Server Error";
}

/* ── Resolution ─────────────────────────────────────────────────── */

enum name_resolve_status name_resolve(struct node_db *ndb, const char *name,
                                      uint8_t want_type,
                                      struct name_resolution *out)
{
    struct name_resolution scratch;
    struct name_resolution *r = out ? out : &scratch;

    memset(r, 0, sizeof(*r));
    r->requested_type = want_type;

    /* 1. Syntax first — a malformed label is answered without touching the
     *    registry at all, which is exactly why it is a distinct verdict. */
    if (!name || !znam_validate_name(name))
        return NAME_RESOLVE_MALFORMED;

    /* 2. The registry has to be there before "absent" can mean anything. */
    if (!ndb) {
        LOG_WARN("name", "resolve '%s': registry not wired", name);
        return NAME_RESOLVE_REGISTRY_UNAVAILABLE;
    }

    if (!db_znam_find(ndb, name, &r->entry))
        return NAME_RESOLVE_ABSENT;
    r->have_entry = true;

    /* 3. No constraint — the primary target is the answer. */
    if (want_type == 0) {
        r->matched_type = r->entry.target_type;
        snprintf(r->value, sizeof(r->value), "%s", r->entry.target_value);
        return NAME_RESOLVE_OK;
    }

    /* 4. Constrained: primary target, then the typed address records,
     *    then — for onion only — the "onion" text record the site
     *    controller has always honoured. */
    if (r->entry.target_type == want_type && r->entry.target_value[0]) {
        r->matched_type = want_type;
        snprintf(r->value, sizeof(r->value), "%s", r->entry.target_value);
        return NAME_RESOLVE_OK;
    }
    if (db_znam_addr_get(ndb, name, want_type, r->value, sizeof(r->value)) &&
        r->value[0]) {
        r->matched_type = want_type;
        return NAME_RESOLVE_OK;
    }
    if (want_type == ZNAM_TYPE_ONION &&
        db_znam_text_get(ndb, name, "onion", r->value, sizeof(r->value)) &&
        r->value[0]) {
        r->matched_type = ZNAM_TYPE_ONION;
        return NAME_RESOLVE_OK;
    }

    r->value[0] = '\0';
    return NAME_RESOLVE_NO_SUCH_TARGET;
}

/* ── Site routing ───────────────────────────────────────────────── */

enum name_route_kind name_resolve_route(struct node_db *ndb,
                                        const struct znam_entry *e,
                                        char *target, size_t target_cap)
{
    if (target && target_cap) target[0] = '\0';
    if (!ndb || !e || !target || target_cap == 0)
        return NAME_ROUTE_PROFILE;

    /* onion: explicit text record wins over the primary target, matching
     * the precedence this site has always served. */
    if (db_znam_text_get(ndb, e->name, "onion", target, target_cap) &&
        target[0])
        return NAME_ROUTE_ONION;

    if (e->target_type == ZNAM_TYPE_ONION && e->target_value[0]) {
        snprintf(target, target_cap, "%s", e->target_value);
        return NAME_ROUTE_ONION;
    }

    if (db_znam_text_get(ndb, e->name, "url", target, target_cap) && target[0])
        return NAME_ROUTE_URL;

    target[0] = '\0';
    return NAME_ROUTE_PROFILE;
}

/* ── Chain history ──────────────────────────────────────────────── */

void name_history_load(struct node_db *ndb, const struct znam_entry *e,
                       struct name_history *out)
{
    struct db_tx_index txrow;
    bool reversed = false;

    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->last_change_height = -1;
    if (!e) return;

    out->reg_height = e->reg_height;
    out->expiry_height = e->expiry_height;
    HexStr(e->reg_txid, 32, false, out->reg_txid_hex, sizeof(out->reg_txid_hex));
    HexStr(e->last_update_txid, 32, false, out->last_change_txid_hex,
           sizeof(out->last_change_txid_hex));
    out->changed = memcmp(e->reg_txid, e->last_update_txid, 32) != 0;

    /* The change height is derived, not stored: look the change tx up in
     * the tx index. A node without -txindex simply reports -1 (unknown) —
     * it never guesses, and it never reports "no change". */
    if (!out->changed) {
        out->last_change_height = e->reg_height;
        return;
    }
    if (ndb && db_tx_find_native_or_reversed(ndb, e->last_update_txid, &txrow,
                                             &reversed))
        out->last_change_height = txrow.block_height;
}

void name_history_append_json(struct node_db *ndb, const struct znam_entry *e,
                              struct json_value *obj)
{
    struct name_history h;
    struct json_value hist = {0};

    if (!obj || !e) return;
    name_history_load(ndb, e, &h);

    json_set_object(&hist);
    json_push_kv_str(&hist, "schema", "zcl.names.history.v1");
    json_push_kv_str(&hist, "authority", "confirmed_chain_history");
    json_push_kv_int(&hist, "registered_height", h.reg_height);
    json_push_kv_str(&hist, "registered_txid", h.reg_txid_hex);
    json_push_kv_bool(&hist, "changed_since_registration", h.changed);
    json_push_kv_int(&hist, "last_change_height", h.last_change_height);
    json_push_kv_str(&hist, "last_change_txid", h.last_change_txid_hex);
    json_push_kv_bool(&hist, "last_change_height_known",
                      h.last_change_height >= 0);
    json_push_kv_int(&hist, "expiry_height", h.expiry_height);
    json_push_kv_str(&hist, "note",
        "Every change to this name is a transaction at a height. A "
        "certificate authority can be quietly coerced into re-issuing; a "
        "chain cannot hide the update.");
    json_push_kv(obj, "history", &hist);
    json_free(&hist);
}

/* ── RPC glue ───────────────────────────────────────────────────── */

bool name_resolve_error_json(struct node_db *ndb, const char *name,
                             const char *type_str,
                             struct name_resolution *out,
                             struct json_value *result)
{
    enum name_resolve_status st;
    uint8_t want = 0;

    if (type_str && type_str[0]) {
        want = znam_type_from_name(type_str);
        if (want == 0) st = NAME_RESOLVE_TYPE_UNKNOWN;
        else           st = name_resolve(ndb, name, want, out);
    } else {
        st = name_resolve(ndb, name, 0, out);
    }
    if (st == NAME_RESOLVE_OK) return false;

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.names.resolve_error.v1");
    json_push_kv_str(result, "name", name ? name : "");
    json_push_kv_bool(result, "resolved", false);
    json_push_kv_str(result, "error_code", name_resolve_status_code(st));
    json_push_kv_str(result, "error", name_resolve_status_message(st));
    json_push_kv_str(result, "http_status", name_resolve_status_http(st));
    json_push_kv_bool(result, "registered",
                      st == NAME_RESOLVE_NO_SUCH_TARGET);
    if (type_str && type_str[0])
        json_push_kv_str(result, "requested_type", type_str);
    /* The name exists but lacks the asked-for record: name its owner and
     * the target it DOES carry, so the caller can act rather than guess. */
    if (st == NAME_RESOLVE_NO_SUCH_TARGET && out && out->have_entry) {
        json_push_kv_str(result, "owner", out->entry.owner_address);
        json_push_kv_str(result, "available_type",
                         znam_type_name(out->entry.target_type));
        name_history_append_json(ndb, &out->entry, result);
    }
    return true;
}
