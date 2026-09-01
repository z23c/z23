/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_lcc — Log-Cursor Contiguity write-rule guard. See util/stage_lcc.h.
 *
 * Direct prepared-statement calls carry the `raw-sql-ok:kernel-primitive`
 * marker: like the stage primitive and progress_store, this guard sits below
 * the AR lifecycle because it operates on the stage_cursor / stage-log kernel
 * tables, which are not models. */

#include "sync/stage_lcc.h"

#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "sync/stage.h"

#include <stdio.h>
#include <string.h>

#define LCC_TRUSTED_BASE_KEY "lcc:trusted_base"
#define LCC_ENFORCE_KEY       "lcc:enforce"
/* Longest real stage name is "script_validate" (15) / "proof_validate" (14);
 * cap generously and reject anything longer as "not a stage cursor". */
#define LCC_STAGE_NAME_MAX 48

/* A stage name must be a plain lowercase SQL identifier fragment so the derived
 * "<name>_log" table identifier cannot smuggle SQL. Every real stage name is
 * [a-z0-9_]; anything else is, by construction, not one of the height-keyed
 * stage logs, so the guard skips it (returns "not a stage log"). */
static bool lcc_valid_stage_name(const char *name)
{
    if (!name || !name[0])
        return false;
    size_t n = 0;
    for (const char *p = name; *p; p++, n++) {
        char c = *p;
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok || n >= LCC_STAGE_NAME_MAX)
            return false;
    }
    return n > 0;
}

/* Count log rows in [lo, hi) for the derived "<name>_log" table. On success
 * returns the count (>= 0). Sets *missing = true (and returns -1) when the
 * table does not exist — an arbitrary named cursor with no success-checked log,
 * which the guard treats as exempt. Any other prepare/step error returns -1
 * with *missing = false (the caller fails OPEN + loud, never silently pins the
 * fold on a transient SQL error). `name` MUST be validated first. */
static long long lcc_count_rows(sqlite3 *db, const char *name,
                                uint64_t lo, uint64_t hi, bool *missing)
{
    *missing = false;
    if (hi <= lo)
        return 0;
    char sql[128];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT COUNT(*) FROM \"%s_log\" "
                     "WHERE height >= ?1 AND height < ?2",
                     name);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        /* "no such table" => not a stage log => exempt. Distinguish it from a
         * real error so a genuine fault is not silently swallowed. */
        const char *msg = sqlite3_errmsg(db);
        if (msg && strstr(msg, "no such table"))
            *missing = true;
        else
            LOG_WARN("stage_lcc",
                     "[stage_lcc] count prepare failed for %s_log: %s",
                     name, msg ? msg : "(no message)");
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)lo);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)hi);
    long long cnt = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:kernel-primitive
        cnt = (long long)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return cnt;
}

uint64_t stage_lcc_trusted_base(sqlite3 *db)
{
    if (!db)
        return 0;
    uint64_t base = 0;
    size_t got = 0;
    bool found = false;
    if (!progress_meta_get(db, LCC_TRUSTED_BASE_KEY,
                           &base, sizeof(base), &got, &found) ||
        !found || got != sizeof(base))
        return 0;
    return base;
}

bool stage_lcc_set_trusted_base_in_tx(sqlite3 *db, uint64_t base)
{
    if (!db)
        LOG_FAIL("stage_lcc", "set_trusted_base: null db");
    return progress_meta_set_in_tx(db, LCC_TRUSTED_BASE_KEY,
                                   &base, sizeof(base));
}

bool stage_lcc_enforcement_enabled(sqlite3 *db)
{
    if (!db)
        return false;
    uint8_t on = 0;
    size_t got = 0;
    bool found = false;
    if (!progress_meta_get(db, LCC_ENFORCE_KEY, &on, sizeof(on), &got, &found) ||
        !found || got != sizeof(on))
        return false;
    return on != 0;
}

bool stage_lcc_set_enforcement_in_tx(sqlite3 *db, bool enabled)
{
    if (!db)
        LOG_FAIL("stage_lcc", "set_enforcement: null db");
    uint8_t on = enabled ? 1 : 0;
    return progress_meta_set_in_tx(db, LCC_ENFORCE_KEY, &on, sizeof(on));
}

bool stage_lcc_first_gap(sqlite3 *db, const char *name,
                         uint64_t base, uint64_t cursor, uint64_t *gap)
{
    if (!db || !gap || cursor <= base || !lcc_valid_stage_name(name))
        return false;

    /* The lowest missing height is `base` itself when no row backs it; else it
     * is the successor of the lowest present row whose successor (still < cursor)
     * is absent. Both are single ordered-index probes. */
    char sql[192];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT 1 FROM \"%s_log\" WHERE height = ?1", name);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)base);
    bool base_present = sqlite3_step(st) == SQLITE_ROW;  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(st);
    if (!base_present) {
        *gap = base;
        return true;
    }

    n = snprintf(sql, sizeof(sql),
                 "SELECT h.height + 1 FROM \"%s_log\" h "
                 "WHERE h.height >= ?1 AND h.height + 1 < ?2 "
                 "AND NOT EXISTS (SELECT 1 FROM \"%s_log\" x "
                 "WHERE x.height = h.height + 1) "
                 "ORDER BY h.height LIMIT 1",
                 name, name);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return false;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)base);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)cursor);
    bool have = false;
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:kernel-primitive
        *gap = (uint64_t)sqlite3_column_int64(st, 0);
        have = true;
    }
    sqlite3_finalize(st);
    return have;
}

bool stage_lcc_check_raise(sqlite3 *db, const char *name,
                           uint64_t old_cursor, uint64_t new_cursor,
                           char *err, size_t errcap)
{
    if (err && errcap)
        err[0] = '\0';
    if (!db)
        return true;                 /* no store to check against */
    if (new_cursor <= old_cursor)
        return true;                 /* lowering / no-op: never a hole */
    if (!lcc_valid_stage_name(name))
        return true;                 /* arbitrary named cursor: exempt */

    bool missing = false;
    long long cnt = lcc_count_rows(db, name, old_cursor, new_cursor, &missing);
    if (missing)
        return true;                 /* not a success-checked stage log */
    if (cnt < 0)
        return true;                 /* transient SQL error: fail OPEN (logged) */

    uint64_t span = new_cursor - old_cursor;
    if ((uint64_t)cnt >= span)
        return true;                 /* fully backed: contiguous raise */

    /* A gap exists in the raw covered span. It is tolerated only for heights at
     * or below the durable trusted base (a crypto-vetted install commits
     * complete state up to and including B, so the cursor may sit at B+1). A
     * base of 0 / absent exempts nothing. */
    uint64_t base = stage_lcc_trusted_base(db);
    uint64_t exempt_below = base ? base + 1 : 0; /* heights < this are vetted */
    uint64_t low = old_cursor > exempt_below ? old_cursor : exempt_below;
    if (low >= new_cursor)
        return true;                 /* whole covered span at/below the base */

    long long cnt2 = cnt;
    if (low != old_cursor) {
        bool m2 = false;
        cnt2 = lcc_count_rows(db, name, low, new_cursor, &m2);
        if (m2)
            return true;
        if (cnt2 < 0)
            return true;             /* fail OPEN (logged) */
    }
    if ((uint64_t)cnt2 >= (new_cursor - low))
        return true;                 /* contiguous above the base */

    /* Refuse: name the first rowless height so the caller's rollback is a loud,
     * located blocker rather than a silent pin. */
    uint64_t gap = low;
    (void)stage_lcc_first_gap(db, name, low, new_cursor, &gap);
    if (err && errcap)
        snprintf(err, errcap,
                 "stage=%s rowless hole at height=%llu span=[%llu,%llu) "
                 "rows=%lld/%llu base=%llu",
                 name, (unsigned long long)gap,
                 (unsigned long long)low, (unsigned long long)new_cursor,
                 cnt2, (unsigned long long)(new_cursor - low),
                 (unsigned long long)base);
    return false;
}

bool stage_cursor_clamp_to(sqlite3 *db, const char *name, uint64_t max_height)
{
    if (!db || !name || !name[0])
        LOG_FAIL("stage_lcc", "clamp: invalid arg");

    /* Read the current cursor; only lower it. A pure lower goes through the
     * cursor-write chokepoint, which always permits a non-raise, so this can
     * never itself birth a hole. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = ?1",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_lcc", "clamp: read prepare failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    uint64_t cur = 0;
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:kernel-primitive
        cur = (uint64_t)sqlite3_column_int64(st, 0);
        found = true;
    }
    sqlite3_finalize(st);

    if (!found || cur <= max_height)
        return true;                 /* nothing above the surviving frontier */
    return stage_set_named_cursor(db, name, max_height);
}
