/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Principal model (multi-user-server identity). One row per authenticated
 * public key. before_validate RECOMPUTES granted_capabilities from role via
 * the authz policy table, so no caller can persist an over-privileged mask;
 * validate then asserts that invariant. All writes go through the AR
 * lifecycle; all reads through AR_QUERY_* helpers. */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "models/principal.h"
#include "models/model_text.h"
#include "models/authz_policy.h"
#include "config/runtime.h"
#include "json/json.h"
#include <string.h>

DEFINE_MODEL_CALLBACKS(principal)

static const char *const k_role_names[] = {
    "guest", "member", "operator", "owner",
};

const char *principal_role_name(enum principal_role role)
{
    if ((int)role < 0 || (int)role > PRINCIPAL_ROLE_OWNER)
        return "guest";
    return k_role_names[role];
}

bool principal_role_from_name(const char *name, enum principal_role *out)
{
    if (!name || !out)
        return false;
    for (int i = 0; i <= PRINCIPAL_ROLE_OWNER; i++) {
        if (strcmp(name, k_role_names[i]) == 0) {
            *out = (enum principal_role)i;
            return true;
        }
    }
    return false;
}

const char *principal_status_name(enum principal_status status)
{
    return status == PRINCIPAL_STATUS_SUSPENDED ? "suspended" : "active";
}

bool principal_status_from_name(const char *name, enum principal_status *out)
{
    if (!name || !out)
        return false;
    if (strcmp(name, "active") == 0) { *out = PRINCIPAL_STATUS_ACTIVE; return true; }
    if (strcmp(name, "suspended") == 0) { *out = PRINCIPAL_STATUS_SUSPENDED; return true; }
    return false;
}

static bool principal_hex_len_ok(size_t n)
{
    /* ed25519 pubkey = 32 bytes (64 hex); secp256k1 compressed = 33 (66);
     * uncompressed = 65 (130). */
    return n == 64 || n == 66 || n == 130;
}

static bool principal_is_hex(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

/* before_validate: normalize, default timestamps, and RECOMPUTE the derived
 * capability cache from role. This is the load-bearing security step — after
 * it runs, granted_capabilities is exactly the role's mask regardless of what
 * the caller supplied, so validate's equality check can never be satisfied by
 * an over-privileged mask. */
static bool principal_before_validate(void *record, void *ctx)
{
    struct db_principal *p = record;
    (void)ctx;
    if (!p)
        return false;
    model_trim_ascii(p->address);
    model_trim_ascii(p->pubkey_hex);
    model_trim_ascii(p->znam_name);
    if (p->created_at == 0)
        p->created_at = (int64_t)platform_time_wall_time_t();
    p->granted_capabilities = authz_caps_for_role(p->role);
    return true;
}

static struct ar_callbacks *principal_callbacks_ready(void)
{
    struct ar_callbacks *cbs = db_principal_callbacks();
    static bool hooks_done = false;
    if (!hooks_done) {
        ar_register_before_validate(cbs, principal_before_validate);
        hooks_done = true;
    }
    return cbs;
}

bool db_principal_validate(const struct db_principal *p, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_string_present(errors, p->address, "address");
    validates_string_present(errors, p->pubkey_hex, "pubkey_hex");
    validates_custom(errors,
        strlen(p->address) <= PRINCIPAL_ADDRESS_MAX,
        "address", "exceeds max length");
    validates_custom(errors,
        model_string_is_printable(p->address),
        "address", "contains non-printable characters");
    size_t hlen = strlen(p->pubkey_hex);
    validates_custom(errors,
        principal_hex_len_ok(hlen) && principal_is_hex(p->pubkey_hex, hlen),
        "pubkey_hex", "is not a valid hex public key");
    validates_custom(errors,
        (int)p->key_kind == PRINCIPAL_KEY_SECP256K1 ||
        (int)p->key_kind == PRINCIPAL_KEY_ED25519,
        "key_kind", "is not a known key scheme");
    validates_custom(errors,
        (int)p->role >= PRINCIPAL_ROLE_GUEST &&
        (int)p->role <= PRINCIPAL_ROLE_OWNER,
        "role", "is not a known role");
    validates_custom(errors,
        (int)p->status == PRINCIPAL_STATUS_ACTIVE ||
        (int)p->status == PRINCIPAL_STATUS_SUSPENDED,
        "status", "is not a known status");
    validates_custom(errors, strlen(p->znam_name) <= PRINCIPAL_ZNAM_MAX,
        "znam_name", "exceeds max length");
    /* The invariant: the persisted mask is EXACTLY the role's authz mask. */
    validates_custom(errors,
        p->granted_capabilities == authz_caps_for_role(p->role),
        "granted_capabilities", "must equal the role's authorized mask");
    return !ar_errors_any(errors);
}

bool db_principal_save(struct node_db *ndb, const struct db_principal *p)
{
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs;

    if (!ndb || !ndb->open || !p) {
        LOG_FAIL("model", "db_principal_save: bad args");
        return false;
    }
    cbs = principal_callbacks_ready();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO principals "
        "(address,pubkey_hex,key_kind,znam_name,role,granted_capabilities,"
        "created_at,last_login,status,sybil_proof_height) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        cbs, "principal", p, db_principal_validate,
        AR_BIND_TEXT(s, 1, p->address);
        AR_BIND_TEXT(s, 2, p->pubkey_hex);
        AR_BIND_INT(s, 3, (int)p->key_kind);
        AR_BIND_TEXT(s, 4, p->znam_name);
        AR_BIND_TEXT(s, 5, principal_role_name(p->role));
        AR_BIND_INT(s, 6, (int64_t)p->granted_capabilities);
        AR_BIND_INT(s, 7, p->created_at);
        AR_BIND_INT(s, 8, p->last_login);
        AR_BIND_TEXT(s, 9, principal_status_name(p->status));
        AR_BIND_INT(s, 10, p->sybil_proof_height));
}

static void principal_read_row(struct db_principal *out, sqlite3_stmt *s)
{
    AR_READ_STR(s, 0, out->address, sizeof(out->address));
    AR_READ_STR(s, 1, out->pubkey_hex, sizeof(out->pubkey_hex));
    out->key_kind = (enum principal_key_kind)AR_COL_INT(s, 2);
    AR_READ_STR(s, 3, out->znam_name, sizeof(out->znam_name));
    enum principal_role role = PRINCIPAL_ROLE_GUEST;
    (void)principal_role_from_name(AR_COL_TEXT(s, 4), &role);
    out->role = role;
    out->granted_capabilities = (uint64_t)AR_COL_INT(s, 5);
    out->created_at = AR_COL_INT(s, 6);
    out->last_login = AR_COL_INT(s, 7);
    enum principal_status status = PRINCIPAL_STATUS_ACTIVE;
    (void)principal_status_from_name(AR_COL_TEXT(s, 8), &status);
    out->status = status;
    out->sybil_proof_height = AR_COL_INT(s, 9);
}

#define PRINCIPAL_COLS \
    "address,pubkey_hex,key_kind,znam_name,role,granted_capabilities," \
    "created_at,last_login,status,sybil_proof_height"

bool db_principal_find(struct node_db *ndb, const char *address,
                       struct db_principal *out)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !address || !out) {
        LOG_FAIL("model", "db_principal_find: bad args");
        return false;
    }
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " PRINCIPAL_COLS " FROM principals WHERE address=?",
        AR_BIND_TEXT(s, 1, address),
        principal_read_row(out, s));
}

bool db_principal_exists_pubkey(struct node_db *ndb, const char *pubkey_hex)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !pubkey_hex) {
        LOG_FAIL("model", "db_principal_exists_pubkey: bad args");
        return false;
    }
    AR_QUERY_EXISTS(ndb, s,
        "SELECT 1 FROM principals WHERE pubkey_hex=? LIMIT 1",
        AR_BIND_TEXT(s, 1, pubkey_hex));
}

int db_principal_list(struct node_db *ndb, struct db_principal *out, size_t max)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, s,
        "SELECT " PRINCIPAL_COLS " FROM principals "
        "ORDER BY created_at ASC LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int64_t)max),
        principal_read_row(&out[count], s));
}

int db_principal_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    AR_QUERY_COUNT_SQL(ndb, "SELECT COUNT(*) FROM principals");
}

bool principal_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    struct node_db *ndb = app_runtime_node_db();
    json_push_kv_bool(out, "db_open", ndb && ndb->open);
    if (!ndb || !ndb->open) {
        json_push_kv_int(out, "count", 0);
        return true;
    }
    json_push_kv_int(out, "count", db_principal_count(ndb));

    struct db_principal rows[50];
    int n = db_principal_list(ndb, rows, 50);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "address", rows[i].address);
        json_push_kv_str(&item, "role", principal_role_name(rows[i].role));
        json_push_kv_str(&item, "status", principal_status_name(rows[i].status));
        json_push_kv_int(&item, "key_kind", (int)rows[i].key_kind);
        json_push_kv_int(&item, "last_login", rows[i].last_login);
        json_push_kv_bool(&item, "has_znam", rows[i].znam_name[0] != '\0');
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(out, "principals", &arr);
    json_free(&arr);
    return true;
}
