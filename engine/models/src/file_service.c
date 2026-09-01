/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: FileService
 *
 * validates :ip, presence: true
 * validates :port, not_zero: true
 *
 * after_save -> emit EV_MODEL_SAVED */

// suffix-ok:entity-FileService — the entity is a "file service" offer (a
// Model row), not the Service shape; the _service here names the thing,
// not the folder. See tools/lint/check_framework_filename_suffix.sh.

#include "platform/time_compat.h"
#include "models/file_service.h"
#include "event/event.h"
#include <string.h>
#include <time.h>

/* ── Callbacks ─────────────────────────────────────────────────── */

DEFINE_MODEL_CALLBACKS(file_service)

static bool file_service_before_save(void *record, void *ctx)
{
    struct db_file_service *fs = record;

    (void)ctx;
    if (!fs)
        return false;
    if (fs->p2p_port == 0)
        fs->p2p_port = fs->port;
    if (fs->last_seen == 0)
        fs->last_seen = (int64_t)platform_time_wall_time_t();
    return true;
}

DEFINE_MODEL_BEFORE_SAVE_READY(file_service, file_service_before_save)

/* ── Validation ────────────────────────────────────────────────── */

bool db_file_service_validate(const struct db_file_service *fs,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, fs, ip);
    validates_not_zero(errors, fs, port);
    validates_non_negative(errors, fs, last_seen);
    return !ar_errors_any(errors);
}

/* ── Row Deserialization ──────────────────────────────────────── */

static void row_to_file_service(sqlite3_stmt *s,
                                struct db_file_service *out)
{
    AR_READ_BLOB(s, 0, out->ip, 16);
    out->port = (uint16_t)AR_COL_INT(s, 1);
    out->p2p_port = (uint16_t)AR_COL_INT(s, 2);
    out->last_seen = AR_COL_INT(s, 3);
    out->is_zcl23 = AR_COL_INT(s, 4) != 0;
}

/* ── Save (cached stmt) ──────────────────────────────────────── */

bool db_file_service_save(struct node_db *ndb,
                          const struct db_file_service *fs)
{
    if (!ndb->open) return false;

    struct ar_callbacks *cbs = file_service_callbacks_ready();
    AR_BEGIN_SAVE(cbs, "file_service", fs, db_file_service_validate);

    sqlite3_stmt *s = ndb->stmt_file_service_save;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, fs->ip, 16);
    AR_BIND_INT(s, 2, fs->port);
    AR_BIND_INT(s, 3, fs->p2p_port);
    AR_BIND_INT(s, 4, fs->last_seen);
    AR_BIND_INT(s, 5, fs->is_zcl23 ? 1 : 0);

    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, fs, ok);
}

/* ── Find (cached stmt) ──────────────────────────────────────── */

/* ── Recent ────────────────────────────────────────────────────── */

int db_file_service_recent(struct node_db *ndb,
                           struct db_file_service *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    int count = 0;

    AR_PREPARE_RET(ndb, s,
        "SELECT ip, port, p2p_port, last_seen, is_zcl23"
        " FROM file_services ORDER BY last_seen DESC LIMIT ?",
        0);
    AR_BIND_INT(s, 1, (int)max);
    AR_LIST_ROWS(s, out, max, row_to_file_service(s, &out[count]));
    AR_FINALIZE(s);
    return count;
}
