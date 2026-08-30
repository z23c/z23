/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model for zid anchor domains (schema v38) — see
 * models/zid_domain.h for the field semantics, the canonical-order
 * contract, and the meaning-change rule. Writes go through the AR
 * lifecycle (AR_ADHOC_SAVE); reads through AR_QUERY_*; the leaf-set
 * replacement is one transaction so a domain never carries a root its
 * stored leaves cannot reproduce. */

#include "models/zid_domain.h"

#include "base/hex.h"
#include "config/runtime.h"
#include "json/json.h"
#include "models/model_text.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <string.h>

#define ZID_DOMAIN_LOG "zid_domain"

DEFINE_MODEL_CALLBACKS(zid_domain)
DEFINE_MODEL_CALLBACKS(zid_domain_leaf)

/* ── Validation ────────────────────────────────────────────────────── */

/* ZNAM name shape: 1..ZID_DOMAIN_NAME_MAX lowercase alphanumerics and
 * hyphens. Keeps a domain name safe to print, to use as a ZANC label
 * prefix, and to compare byte-for-byte across nodes. */
static bool zd_name_ok(const char *name)
{
    if (!name || !name[0])
        return false; /* raw-return-ok:empty-name-is-a-negative-predicate */
    size_t n = strlen(name);
    if (n > ZID_DOMAIN_NAME_MAX)
        return false; /* raw-return-ok:overlong-name-is-a-negative-predicate */
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok)
            return false; /* raw-return-ok:charset-is-a-negative-predicate */
    }
    return true;
}

bool db_zid_domain_validate(const struct zid_domain *d,
                            struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!d) {
        ar_errors_add(errors, "domain", "is NULL");
        return false; /* raw-return-ok:null-record-cannot-be-field-validated */
    }
    validates_string_present(errors, d->domain_name, "domain_name");
    validates_custom(errors, zd_name_ok(d->domain_name), "domain_name",
                     "is not 1..63 lowercase alphanumerics/hyphens");
    validates_non_negative(errors, d, num_leaves);
    validates_max(errors, d, num_leaves, (int64_t)ZID_DOMAIN_LEAVES_MAX);
    validates_non_negative(errors, d, updated_at);
    /* An anchored domain must name the height it was anchored at: a txid
     * with no height cannot be located on the chain later. */
    validates_custom(errors, !d->anchored || d->anchored_height >= 0,
                     "anchored_height", "must be >= 0 when anchored");
    return !ar_errors_any(errors);
}

bool db_zid_domain_leaf_validate(const struct zid_domain_leaf *l,
                                 struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!l) {
        ar_errors_add(errors, "leaf", "is NULL");
        return false; /* raw-return-ok:null-record-cannot-be-field-validated */
    }
    validates_string_present(errors, l->domain_name, "domain_name");
    validates_custom(errors, zd_name_ok(l->domain_name), "domain_name",
                     "is not 1..63 lowercase alphanumerics/hyphens");
    validates_non_negative(errors, l, leaf_index);
    validates_max(errors, l, leaf_index, (int64_t)ZID_DOMAIN_LEAVES_MAX - 1);
    /* An all-zero digest is a caller that forgot to fill the leaf, not a
     * SHA3-256 output. */
    validates_presence_of(errors, l, record_digest);
    validates_custom(errors, strlen(l->label) <= ZID_DOMAIN_LABEL_MAX,
                     "label", "exceeds max length");
    validates_custom(errors, l->label[0] == '\0' ||
                     model_string_is_printable(l->label),
                     "label", "contains non-printable characters");
    return !ar_errors_any(errors);
}

/* ── Saves ─────────────────────────────────────────────────────────── */

bool db_zid_domain_save(struct node_db *ndb, const struct zid_domain *d)
{
    if (!ndb || !ndb->open)
        LOG_FAIL(ZID_DOMAIN_LOG, "db_zid_domain_save: db not open");
    if (!d)
        LOG_FAIL(ZID_DOMAIN_LOG, "db_zid_domain_save: domain is NULL");

    struct ar_callbacks *cbs = db_zid_domain_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO zid_domains"
        "(domain_name,owner_pubkey,num_leaves,root,anchored_txid,"
        "anchored_height,updated_at) VALUES(?,?,?,?,?,?,?)",
        cbs, "zid_domain", d, db_zid_domain_validate,
        AR_BIND_TEXT(s, 1, d->domain_name);
        if (d->has_owner) AR_BIND_BLOB(s, 2, d->owner_pubkey, 32);
        else AR_BIND_NULL(s, 2);
        AR_BIND_INT(s, 3, d->num_leaves);
        AR_BIND_BLOB(s, 4, d->root, 32);
        if (d->anchored) AR_BIND_BLOB(s, 5, d->anchored_txid, 32);
        else AR_BIND_NULL(s, 5);
        if (d->anchored) AR_BIND_INT(s, 6, d->anchored_height);
        else AR_BIND_NULL(s, 6);
        AR_BIND_INT(s, 7, d->updated_at));
}

bool db_zid_domain_leaf_save(struct node_db *ndb,
                             const struct zid_domain_leaf *l)
{
    if (!ndb || !ndb->open)
        LOG_FAIL(ZID_DOMAIN_LOG, "db_zid_domain_leaf_save: db not open");
    if (!l)
        LOG_FAIL(ZID_DOMAIN_LOG, "db_zid_domain_leaf_save: leaf is NULL");

    struct ar_callbacks *cbs = db_zid_domain_leaf_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO zid_domain_leaves"
        "(domain_name,leaf_index,record_digest,label) VALUES(?,?,?,?)",
        cbs, "zid_domain_leaf", l, db_zid_domain_leaf_validate,
        AR_BIND_TEXT(s, 1, l->domain_name);
        AR_BIND_INT(s, 2, l->leaf_index);
        AR_BIND_BLOB(s, 3, l->record_digest, 32);
        if (l->label[0]) AR_BIND_TEXT(s, 4, l->label);
        else AR_BIND_NULL(s, 4));
}

/* ── Reads ─────────────────────────────────────────────────────────── */

#define ZID_DOMAIN_COLS \
    "domain_name,owner_pubkey,num_leaves,root,anchored_txid," \
    "anchored_height,updated_at"

static void zd_read_domain(struct zid_domain *out, sqlite3_stmt *s)
{
    memset(out, 0, sizeof(*out));
    AR_READ_STR(s, 0, out->domain_name, sizeof(out->domain_name));
    out->has_owner = sqlite3_column_type(s, 1) != SQLITE_NULL &&
                     sqlite3_column_bytes(s, 1) == 32;
    if (out->has_owner)
        AR_READ_BLOB(s, 1, out->owner_pubkey, 32);
    out->num_leaves = AR_COL_INT(s, 2);
    AR_READ_BLOB(s, 3, out->root, 32);
    out->anchored = sqlite3_column_type(s, 4) != SQLITE_NULL &&
                    sqlite3_column_bytes(s, 4) == 32;
    if (out->anchored)
        AR_READ_BLOB(s, 4, out->anchored_txid, 32);
    out->anchored_height = (sqlite3_column_type(s, 5) == SQLITE_NULL)
                               ? -1 : AR_COL_INT(s, 5);
    out->updated_at = AR_COL_INT(s, 6);
}

static void zd_read_leaf(struct zid_domain_leaf *out, sqlite3_stmt *s)
{
    memset(out, 0, sizeof(*out));
    AR_READ_STR(s, 0, out->domain_name, sizeof(out->domain_name));
    out->leaf_index = AR_COL_INT(s, 1);
    AR_READ_BLOB(s, 2, out->record_digest, 32);
    AR_READ_STR(s, 3, out->label, sizeof(out->label));
}

bool zid_domain_get(struct node_db *ndb, const char *domain_name,
                    struct zid_domain *out)
{
    if (!ndb || !ndb->open || !domain_name || !out)
        LOG_FAIL(ZID_DOMAIN_LOG, "zid_domain_get: invalid args");
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " ZID_DOMAIN_COLS " FROM zid_domains WHERE domain_name=?",
        AR_BIND_TEXT(s, 1, domain_name),
        zd_read_domain(out, s));
}

int zid_domain_list(struct node_db *ndb, struct zid_domain *out, size_t max)
{
    if (!ndb || !ndb->open || !out || max == 0)
        LOG_RETURN(0, ZID_DOMAIN_LOG, "zid_domain_list: invalid args");
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT " ZID_DOMAIN_COLS " FROM zid_domains"
        " ORDER BY domain_name ASC LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int64_t)max),
        zd_read_domain(&out[count], s));
}

int zid_domain_leaves(struct node_db *ndb, const char *domain_name,
                      struct zid_domain_leaf *out, size_t max)
{
    if (!ndb || !ndb->open || !domain_name || !out || max == 0)
        LOG_RETURN(0, ZID_DOMAIN_LOG, "zid_domain_leaves: invalid args");
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT domain_name,leaf_index,record_digest,label"
        " FROM zid_domain_leaves WHERE domain_name=?"
        " ORDER BY leaf_index ASC LIMIT ?",
        out, max,
        AR_BIND_TEXT(s, 1, domain_name);
        AR_BIND_INT(s, 2, (int64_t)max),
        zd_read_leaf(&out[count], s));
}

bool zid_domain_leaf_index_by_digest(struct node_db *ndb,
                                     const char *domain_name,
                                     const uint8_t record_digest[32],
                                     int64_t *index_out)
{
    if (!ndb || !ndb->open || !domain_name || !record_digest || !index_out)
        LOG_FAIL(ZID_DOMAIN_LOG,
                 "zid_domain_leaf_index_by_digest: invalid args");
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT leaf_index FROM zid_domain_leaves"
        " WHERE record_digest=? AND domain_name=?",
        AR_BIND_BLOB(s, 1, record_digest, 32);
        AR_BIND_TEXT(s, 2, domain_name),
        *index_out = AR_COL_INT(s, 0));
}

int64_t zid_domain_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(0, ZID_DOMAIN_LOG, "zid_domain_count: db not open");
    AR_QUERY_INT64_SQL(ndb, "SELECT COUNT(*) FROM zid_domains");
}

int64_t zid_domain_leaf_count(struct node_db *ndb, const char *domain_name)
{
    if (!ndb || !ndb->open || !domain_name)
        LOG_RETURN(0, ZID_DOMAIN_LOG, "zid_domain_leaf_count: invalid args");
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COUNT(*) FROM zid_domain_leaves WHERE domain_name=?",
        AR_BIND_TEXT(s, 1, domain_name));
}

/* ── Mutations ─────────────────────────────────────────────────────── */

static bool zd_delete_leaves(struct node_db *ndb, const char *domain_name)
{
    sqlite3_stmt *s = NULL;
    AR_EXEC_BOOL(ndb, s,
        "DELETE FROM zid_domain_leaves WHERE domain_name=?",
        AR_BIND_TEXT(s, 1, domain_name));
}

/* Body of the atomic replacement — everything the transaction covers.
 * Split out so the caller owns exactly one begin/commit/rollback. */
static bool zd_replace_body(struct node_db *ndb, const struct zid_domain *next,
                            const struct zid_domain_leaf *leaves, size_t n)
{
    if (!zd_delete_leaves(ndb, next->domain_name))
        LOG_FAIL(ZID_DOMAIN_LOG, "replace_leaves: DELETE failed for '%s'",
                 next->domain_name);
    for (size_t i = 0; i < n; i++) {
        struct zid_domain_leaf leaf = leaves[i];
        snprintf(leaf.domain_name, sizeof(leaf.domain_name), "%s",
                 next->domain_name);
        leaf.leaf_index = (int64_t)i;
        if (!db_zid_domain_leaf_save(ndb, &leaf))
            LOG_FAIL(ZID_DOMAIN_LOG,
                     "replace_leaves: leaf %zu of '%s' failed to save", i,
                     next->domain_name);
    }
    if (!db_zid_domain_save(ndb, next))
        LOG_FAIL(ZID_DOMAIN_LOG, "replace_leaves: domain '%s' failed to save",
                 next->domain_name);
    return true;
}

bool zid_domain_replace_leaves(struct node_db *ndb, const char *domain_name,
                               const struct zid_domain_leaf *leaves, size_t n,
                               const uint8_t root[32],
                               const uint8_t *owner_pubkey, int64_t updated_at)
{
    if (!ndb || !ndb->open || !domain_name || !root)
        LOG_FAIL(ZID_DOMAIN_LOG, "replace_leaves: invalid args");
    if (n > 0 && !leaves)
        LOG_FAIL(ZID_DOMAIN_LOG,
                 "replace_leaves: %zu leaves promised, none given", n);
    if (n > ZID_DOMAIN_LEAVES_MAX)
        LOG_FAIL(ZID_DOMAIN_LOG,
                 "replace_leaves: %zu leaves exceeds the %d cap for '%s'", n,
                 ZID_DOMAIN_LEAVES_MAX, domain_name);

    struct zid_domain prev;
    bool had_prev = zid_domain_get(ndb, domain_name, &prev);

    struct zid_domain next;
    memset(&next, 0, sizeof(next));
    snprintf(next.domain_name, sizeof(next.domain_name), "%s", domain_name);
    next.num_leaves = (int64_t)n;
    memcpy(next.root, root, 32);
    next.updated_at = updated_at > 0 ? updated_at
                                     : (int64_t)platform_time_wall_time_t();
    if (owner_pubkey) {
        memcpy(next.owner_pubkey, owner_pubkey, 32);
        next.has_owner = true;
    } else if (had_prev && prev.has_owner) {
        memcpy(next.owner_pubkey, prev.owner_pubkey, 32);
        next.has_owner = true;
    }
    /* The meaning-change rule: an anchor survives only a same-root
     * rewrite. A new root leaves the domain visibly un-anchored rather
     * than wearing the previous batch's txid. */
    if (had_prev && prev.anchored && memcmp(prev.root, root, 32) == 0) {
        memcpy(next.anchored_txid, prev.anchored_txid, 32);
        next.anchored = true;
        next.anchored_height = prev.anchored_height;
    } else {
        next.anchored_height = -1;
    }

    if (!node_db_begin(ndb))
        LOG_FAIL(ZID_DOMAIN_LOG,
                 "replace_leaves: BEGIN failed for '%s'", domain_name);
    if (!zd_replace_body(ndb, &next, leaves, n)) {
        if (!node_db_rollback(ndb))
            LOG_WARN(ZID_DOMAIN_LOG,
                     "replace_leaves: ROLLBACK failed for '%s' — the "
                     "transaction is still open", domain_name);
        LOG_FAIL(ZID_DOMAIN_LOG,
                 "replace_leaves: rolled back the leaf set of '%s'",
                 domain_name);
    }
    if (!node_db_commit(ndb))
        LOG_FAIL(ZID_DOMAIN_LOG, "replace_leaves: COMMIT failed for '%s'",
                 domain_name);
    return true;
}

bool zid_domain_set_anchor(struct node_db *ndb, const char *domain_name,
                           const uint8_t txid[32], int64_t height)
{
    if (!ndb || !ndb->open || !domain_name || !txid)
        LOG_FAIL(ZID_DOMAIN_LOG, "set_anchor: invalid args");
    if (height < 0)
        LOG_FAIL(ZID_DOMAIN_LOG,
                 "set_anchor: height %lld is negative for '%s'",
                 (long long)height, domain_name);

    struct zid_domain d;
    if (!zid_domain_get(ndb, domain_name, &d))
        LOG_FAIL(ZID_DOMAIN_LOG,
                 "set_anchor: domain '%s' does not exist — fold its leaf set "
                 "first so the txid binds a stored root", domain_name);
    memcpy(d.anchored_txid, txid, 32);
    d.anchored = true;
    d.anchored_height = height;
    return db_zid_domain_save(ndb, &d);
}

/* ── `z23 dumpstate zid_domains` ────────────────────────────── */

static void zd_push_domain(struct json_value *obj, const struct zid_domain *d)
{
    json_set_object(obj);
    json_push_kv_str(obj, "domain_name", d->domain_name);
    json_push_kv_int(obj, "num_leaves", d->num_leaves);
    char hex[65];
    zcl_hex_encode(d->root, 32, hex);
    json_push_kv_str(obj, "root", hex);
    json_push_kv_bool(obj, "anchored", d->anchored);
    if (d->anchored) {
        zcl_hex_encode(d->anchored_txid, 32, hex);
        json_push_kv_str(obj, "anchored_txid", hex);
    }
    json_push_kv_int(obj, "anchored_height", d->anchored_height);
    json_push_kv_int(obj, "updated_at", d->updated_at);
    json_push_kv_bool(obj, "has_owner", d->has_owner);
    if (d->has_owner) {
        zcl_hex_encode(d->owner_pubkey, 32, hex);
        json_push_kv_str(obj, "owner_pubkey", hex);
    }
}

bool zid_domain_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        LOG_FAIL(ZID_DOMAIN_LOG, "dump_state_json: out is NULL");
    struct node_db *ndb = app_runtime_node_db();
    bool db_open = ndb && ndb->open;
    json_push_kv_bool(out, "db_open", db_open);
    if (!db_open) {
        json_push_kv_int(out, "domains", 0);
        return true;
    }

    if (key && key[0]) {
        struct zid_domain d;
        bool found = zid_domain_get(ndb, key, &d);
        json_push_kv_bool(out, "found", found);
        json_push_kv_str(out, "domain_name", key);
        if (found) {
            struct json_value obj;
            json_init(&obj);
            zd_push_domain(&obj, &d);
            json_push_kv_int(&obj, "stored_leaf_rows",
                             zid_domain_leaf_count(ndb, key));
            json_push_kv(out, "domain", &obj);
            json_free(&obj);
        }
        return true;
    }

    json_push_kv_int(out, "domains", zid_domain_count(ndb));
    struct zid_domain rows[16];
    int n = zid_domain_list(ndb, rows, 16);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value obj;
        json_init(&obj);
        zd_push_domain(&obj, &rows[i]);
        json_push_back(&arr, &obj);
        json_free(&obj);
    }
    json_push_kv(out, "roster", &arr);
    json_free(&arr);
    json_push_kv_int(out, "roster_cap", 16);
    return true;
}
