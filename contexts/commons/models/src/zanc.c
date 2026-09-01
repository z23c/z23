/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model for ZCL Anchors (ZANC) — the rebuildable zanc_anchors
 * projection table. Rows are immutable once written (an anchor is a confirmed
 * OP_RETURN); the only write path is db_zanc_save from the explorer index. The
 * OP_RETURN parser/builder lives in contexts/commons/modules/zanc/src/zanc.c. */

#include "models/zanc.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(zanc)

static bool read_zanc_blob(sqlite3_stmt *s, int col, void *dest,
                           int expected_len, const char *column)
{
    int got = sqlite3_column_bytes(s, col);
    const void *blob = sqlite3_column_blob(s, col);
    if (!blob || got != expected_len)
        LOG_FAIL("zanc", "zanc_anchors.%s blob length mismatch: got=%d expected=%d",
                 column, got, expected_len);
    AR_READ_BLOB(s, col, dest, expected_len);
    return true;
}

bool db_zanc_validate(const struct zanc_anchor *a, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!a) {
        ar_errors_add(errors, "anchor", "is NULL");
        return false;
    }

    static const uint8_t zero32[32] = {0};

    validates_custom(errors,
        zanc_hash_type_valid(a->hash_type),
        "hash_type", "is not a supported ZANC hash type");
    validates_custom(errors,
        memcmp(a->txid, zero32, 32) != 0,
        "txid", "can't be all zero");
    validates_non_negative(errors, a, height);
    validates_custom(errors,
        zanc_label_valid(a->label, strnlen(a->label, ZANC_LABEL_MAX + 1)),
        "label", "is not a valid bounded UTF-8 label");

    return !ar_errors_any(errors);
}

bool db_zanc_save(struct node_db *ndb, const struct zanc_anchor *a)
{
    if (!ndb || !ndb->open) LOG_FAIL("zanc", "db_zanc_save: db not open");
    if (!a) LOG_FAIL("zanc", "db_zanc_save: anchor is NULL");

    struct ar_callbacks *cbs = db_zanc_callbacks();
    sqlite3_stmt *s = NULL;
    AR_BEGIN_SAVE(cbs, "zanc_anchor", a, db_zanc_validate);
    AR_PREPARE_BOOL(ndb, s,
        "INSERT OR REPLACE INTO zanc_anchors"
        "(txid,height,hash_type,digest,label) VALUES(?,?,?,?,?)");
    AR_BIND_BLOB(s, 1, a->txid, 32);
    AR_BIND_INT(s, 2, a->height);
    AR_BIND_INT(s, 3, a->hash_type);
    AR_BIND_BLOB(s, 4, a->digest, 32);
    AR_BIND_TEXT(s, 5, a->label);

    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    AR_FINISH_SAVE(cbs, a, ok);
}

static bool row_to_zanc(sqlite3_stmt *s, struct zanc_anchor *out)
{
    memset(out, 0, sizeof(*out));
    if (!read_zanc_blob(s, 0, out->txid, 32, "txid"))
        LOG_FAIL("zanc", "zanc_anchors.txid rejected");
    out->height = (int32_t)sqlite3_column_int(s, 1);
    out->hash_type = (uint8_t)sqlite3_column_int(s, 2);
    if (!read_zanc_blob(s, 3, out->digest, 32, "digest"))
        LOG_FAIL("zanc", "zanc_anchors.digest rejected");
    const char *label = (const char *)sqlite3_column_text(s, 4);
    if (label) snprintf(out->label, sizeof(out->label), "%s", label);
    return true;
}

bool db_zanc_find_by_digest(struct node_db *ndb, uint8_t hash_type,
                            const uint8_t digest[ZANC_DIGEST_LEN],
                            struct zanc_anchor *out)
{
    if (!ndb || !ndb->open) return false;
    if (!digest || !out) return false;

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT txid,height,hash_type,digest,label FROM zanc_anchors"
        " WHERE hash_type=? AND digest=?"
        " ORDER BY height ASC, txid ASC LIMIT 1",
        AR_BIND_INT(s, 1, hash_type);
        AR_BIND_BLOB(s, 2, digest, 32),
        if (!row_to_zanc(s, out)) { AR_FINALIZE(s); return false; });
}

int db_zanc_list(struct node_db *ndb, struct zanc_anchor *out, size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "zanc", "db_zanc_list: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid,height,hash_type,digest,label FROM zanc_anchors"
        " ORDER BY height DESC, txid ASC LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int)max),
        if (!row_to_zanc(s, &out[count])) continue);
}

int db_zanc_list_by_label_prefix(struct node_db *ndb, const char *prefix,
                                 struct zanc_anchor *out, size_t max,
                                 size_t offset)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "zanc", "db_zanc_list_by_label_prefix: out is NULL");
    if (max == 0) return 0;

    const char *pfx = prefix ? prefix : "";
    int pfx_len = (int)strnlen(pfx, ZANC_LABEL_MAX + 1);
    if (pfx_len > ZANC_LABEL_MAX)
        LOG_RETURN(0, "zanc",
                   "db_zanc_list_by_label_prefix: prefix longer than a label");

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid,height,hash_type,digest,label FROM zanc_anchors"
        " WHERE substr(label,1,?)=?"
        " ORDER BY height DESC, txid ASC LIMIT ? OFFSET ?",
        out, max,
        AR_BIND_INT(s, 1, pfx_len);
        AR_BIND_TEXT(s, 2, pfx);
        AR_BIND_INT(s, 3, (int)max);
        AR_BIND_INT(s, 4, (int)offset),
        if (!row_to_zanc(s, &out[count])) continue);
}
