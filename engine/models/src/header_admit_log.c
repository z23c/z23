/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: HeaderAdmitLog — see models/header_admit_log.h.
 *
 * The write travels the canonical validate -> before_save -> SQL ->
 * after_save lifecycle (Law 2: "Models are the only writers of state — one
 * way in, one way out"). */

#include "models/header_admit_log.h"
#include "util/log_macros.h"

#include "event/event.h"
#include <stdio.h>
#include <string.h>

/* ── Callbacks ─────────────────────────────────────────────────── */

DEFINE_MODEL_CALLBACKS(header_admit_log)

/* before_save: reject rows the validator can't catch structurally. A
 * genesis row (height 0) legitimately has no parent; every other height
 * must carry one. */
static bool header_admit_log_before_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_header_admit_log *r = record;
    if (r->height < 0) {
        LOG_WARN("header_admit_log", "[header_admit_log] before_save REJECTED: negative height %lld", (long long)r->height);
        return false;
    }
    if (r->height > 0 && !r->has_parent) {
        LOG_WARN("header_admit_log", "[header_admit_log] before_save REJECTED: height %lld missing parent", (long long)r->height);
        return false;
    }
    return true;
}

static void header_admit_log_after_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_header_admit_log *r = record;
    event_emitf(EV_MODEL_SAVED, 0, "model=header_admit_log height=%lld",
                (long long)r->height);
}

static void header_admit_log_init_hooks(void)
{
    static bool done = false;
    if (done) return;
    struct ar_callbacks *cbs = db_header_admit_log_callbacks();
    ar_register_before_save(cbs, header_admit_log_before_save);
    ar_register_after_save(cbs, header_admit_log_after_save);
    done = true;
}

/* ── Validation ────────────────────────────────────────────────── */

bool db_header_admit_log_validate(const struct db_header_admit_log *r,
                                  struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_non_negative(errors, r, height);
    validates_presence_of(errors, r, hash);
    validates_non_negative(errors, r, admitted_at);
    return !ar_errors_any(errors);
}

/* ── Schema ────────────────────────────────────────────────────── */

bool db_header_admit_log_ensure_schema(sqlite3 *db)
{
    if (!db) return false;
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height      INTEGER PRIMARY KEY,"
        "  hash        BLOB    NOT NULL,"
        "  parent_hash BLOB,"
        "  admitted_at INTEGER NOT NULL"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("header_admit_log", "[header_admit_log] schema ensure failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

/* ── Save ──────────────────────────────────────────────────────── */

bool db_header_admit_log_save(sqlite3 *db,
                              const struct db_header_admit_log *r)
{
    if (!db || !r) return false;

    header_admit_log_init_hooks();
    struct ar_callbacks *cbs = db_header_admit_log_callbacks();
    struct header_admit_log_db ndb = { .db = db };
    sqlite3_stmt *s = NULL;

    AR_ADHOC_SAVE(&ndb, s,
        "INSERT OR REPLACE INTO header_admit_log "
        "(height, hash, parent_hash, admitted_at) VALUES (?,?,?,?)",
        cbs, "header_admit_log", r, db_header_admit_log_validate,
        AR_BIND_INT(s, 1, r->height);
        AR_BIND_BLOB(s, 2, r->hash, 32);
        if (r->has_parent)
            AR_BIND_BLOB(s, 3, r->parent_hash, 32);
        else
            AR_BIND_NULL(s, 3);
        AR_BIND_INT(s, 4, r->admitted_at));
}
