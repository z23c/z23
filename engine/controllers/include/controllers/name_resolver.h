/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names resolution — THE one resolver every name surface goes through,
 * and the error taxonomy it answers with.
 *
 * docs/spec/power-node-contract.md requires that resolution APIs
 * "distinguish absent names, malformed names, and records that exist but
 * lack the requested target type". Collapsing all three into one "Name not
 * found" is the failure this file exists to stop: the three cases have
 * three different fixes (fix your spelling / register the name / ask the
 * owner to add that record) and a caller that cannot tell them apart
 * cannot act.
 *
 * The taxonomy is decided ONCE here, and every surface renders the same
 * verdict:
 *   - JSON-RPC name_resolve (and therefore the native `app names resolve`
 *     leaf, which proxies it),
 *   - the HTML site /n/<name> and /names/<name> (distinct HTTP status +
 *     an X-ZCL-Name-Error: header carrying the machine code).
 *
 * Read-only throughout: pure projection SELECTs through the model helpers
 * (db_znam_find / db_znam_addr_get / db_znam_text_get), never controller
 * SQL, never a chain scan. */

#ifndef ZCL_CONTROLLERS_NAME_RESOLVER_H
#define ZCL_CONTROLLERS_NAME_RESOLVER_H

#include "models/znam.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

/* The four ways a resolution can end other than success. Ordered so a new
 * case can be appended without renumbering; the wire identity is the code
 * STRING from name_resolve_status_code(), never this integer. */
enum name_resolve_status {
    NAME_RESOLVE_OK = 0,
    /* The label itself violates the ZNAM syntax contract (1-63 chars,
     * lowercase alphanumeric + hyphens). Nothing was looked up. */
    NAME_RESOLVE_MALFORMED = 1,
    /* Well-formed, but no registration for it exists on chain. */
    NAME_RESOLVE_ABSENT = 2,
    /* Registered — but it carries no record of the target type asked for
     * (e.g. asking a payment-only name for an .onion). Distinct from
     * ABSENT: the name has an owner, so there is somebody to ask. */
    NAME_RESOLVE_NO_SUCH_TARGET = 3,
    /* The caller named a target type this protocol has no code for. */
    NAME_RESOLVE_TYPE_UNKNOWN = 4,
    /* The projection is not wired/open. Not the name's fault — this node
     * cannot answer right now, which is a 503, not a 404. */
    NAME_RESOLVE_REGISTRY_UNAVAILABLE = 5,
};

/* One resolution's answer. `entry` is filled whenever the name resolved to
 * a registration at all — that includes NAME_RESOLVE_NO_SUCH_TARGET, so a
 * caller can still show the owner and point at the records that DO exist. */
struct name_resolution {
    struct znam_entry entry;
    bool     have_entry;
    uint8_t  requested_type;                 /* 0 = "any target"            */
    uint8_t  matched_type;                   /* type actually resolved (OK) */
    char     value[ZNAM_VALUE_MAX + 1];      /* resolved target value  (OK) */
};

/* Resolve `name`, optionally constrained to `want_type` (0 = any target).
 * `out` may be NULL when only the verdict is wanted. Never allocates. */
enum name_resolve_status name_resolve(struct node_db *ndb, const char *name,
                                      uint8_t want_type,
                                      struct name_resolution *out);

/* Stable machine code for a verdict — "NAME_OK", "NAME_MALFORMED",
 * "NAME_ABSENT", "NAME_NO_SUCH_TARGET", "NAME_TYPE_UNKNOWN",
 * "NAME_REGISTRY_UNAVAILABLE". This string is the contract; callers switch
 * on it, not on the enum's integer value. */
const char *name_resolve_status_code(enum name_resolve_status s);

/* One-sentence human explanation, distinct per verdict. */
const char *name_resolve_status_message(enum name_resolve_status s);

/* The HTTP status line a verdict maps to ("400 Bad Request",
 * "404 Not Found", "503 Service Unavailable", ...). */
const char *name_resolve_status_http(enum name_resolve_status s);

/* THE canonical target-type parser: accepts both the short protocol tokens
 * ("onion", "zaddr", "taddr", "btc", "ltc", "doge", "content") and the long
 * display aliases znam_type_name() emits ("z-address", "bitcoin", ...).
 * Returns 0 for anything unrecognised — 0 is not a valid ZNAM type. */
uint8_t znam_type_from_name(const char *s);

/* ── Site routing ──────────────────────────────────────────────────
 *
 * Where /n/<name> should send a visitor. Precedence is onion > url >
 * profile, decided once here so the redirect path, the gateway path, and
 * any future surface cannot drift apart. */
enum name_route_kind {
    NAME_ROUTE_ONION = 0,   /* target is a .onion host      */
    NAME_ROUTE_URL = 1,     /* target is a clearnet URL     */
    NAME_ROUTE_PROFILE = 2, /* nothing routable — show the profile page */
};

/* Decide the route for an already-resolved entry. Writes the raw target
 * text (as registered) into `target`; empty for NAME_ROUTE_PROFILE. */
enum name_route_kind name_resolve_route(struct node_db *ndb,
                                        const struct znam_entry *e,
                                        char *target, size_t target_cap);

/* ── Chain history ─────────────────────────────────────────────────
 *
 * The argument that beats a certificate authority: a CA can be quietly
 * coerced into re-issuing, but every change to a ZCL Name is a
 * transaction at a height, and the chain cannot hide it. The data was
 * already stored (reg_height/reg_txid/last_update_txid/expiry_height) —
 * this is the presentation of it. */
struct name_history {
    int32_t reg_height;
    char    reg_txid_hex[65];
    /* Height of the transaction that last changed this name, or -1 when
     * that tx is not in this node's tx index (a node without -txindex, or
     * a change still in the mempool). -1 means "unknown", never "none". */
    int32_t last_change_height;
    char    last_change_txid_hex[65];
    /* false when the name has never been changed since registration —
     * last_update_txid still equals reg_txid. */
    bool    changed;
    int32_t expiry_height;
};

/* Fill `out` from an entry (+ a tx-index lookup for the change height).
 * Always succeeds; unknown heights come back as -1. */
void name_history_load(struct node_db *ndb, const struct znam_entry *e,
                       struct name_history *out);

/* Append the history object (schema zcl.names.history.v1) to a JSON name
 * record. No-op when `obj` is NULL. */
void name_history_append_json(struct node_db *ndb, const struct znam_entry *e,
                              struct json_value *obj);

/* ── RPC glue ──────────────────────────────────────────────────────
 *
 * Resolve for a JSON surface. On any non-OK verdict this writes the full
 * taxonomy error body (schema zcl.names.resolve_error.v1) into `result`
 * and returns true — "the request is already answered". On OK it returns
 * false with `out` filled, leaving `result` untouched for the caller to
 * render the success body. */
bool name_resolve_error_json(struct node_db *ndb, const char *name,
                             const char *type_str,
                             struct name_resolution *out,
                             struct json_value *result);

#define NAME_RESOLVE_RPC_HELP \
    "name_resolve \"name\" ( \"type\" )\n" \
    "\nResolve a ZCL Name to its target and resolver records.\n" \
    "\nArguments:\n" \
    "1. name (string, required) The name to resolve\n" \
    "2. type (string, optional) Constrain to one target type: onion,\n" \
    "   zaddr, taddr, btc, ltc, doge, content\n" \
    "\nResult: the name entry, or a zcl.names.resolve_error.v1 body whose\n" \
    "error_code distinguishes NAME_MALFORMED (bad syntax), NAME_ABSENT\n" \
    "(not registered), NAME_NO_SUCH_TARGET (registered, no record of that\n" \
    "type), NAME_TYPE_UNKNOWN, and NAME_REGISTRY_UNAVAILABLE.\n"

#endif /* ZCL_CONTROLLERS_NAME_RESOLVER_H */
