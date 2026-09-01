/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded integrity queries over the connected block projection.
 * ar-validate-skip:read-only-projection-query */

#include "models/block.h"

#include "util/log_macros.h"

bool db_block_first_missing_connected_height(struct node_db *ndb,
                                             int max_height,
                                             int *height_out)
{
    if (height_out)
        *height_out = -1;
    if (!ndb || !ndb->open || !height_out)
        LOG_FAIL("block", "first_missing_connected_height: invalid args");
    if (max_height < 0)
        return true;

    /* The connected-height index is UNIQUE and partial on status>=3. When it
     * contains exactly max_height+1 entries in [0,max_height], every height in
     * that interval is present and the expensive self-join below is
     * unnecessary. On a full mainnet projection this turns the overwhelmingly
     * common no-hole case from millions of point lookups into one sequential
     * covering-index count. A mismatch is only a suspicion: retain the exact
     * first-hole query so recovery still rewinds to the right height. */
    sqlite3_stmt *count = NULL;
    AR_PREPARE_BOOL(ndb, count,
        "SELECT COUNT(*) FROM blocks "
        "WHERE status>=3 AND height BETWEEN 0 AND ?");
    AR_BIND_INT(count, 1, max_height);
    int count_rc = sqlite3_step(count);  // raw-sql-ok:read-only-introspection
    int64_t connected = count_rc == SQLITE_ROW ? AR_COL_INT(count, 0) : -1;
    AR_FINALIZE(count);
    if (count_rc != SQLITE_ROW)
        LOG_FAIL("block", "first_missing_connected_height: count failed: %s",
                 sqlite3_errmsg(ndb->db));
    if (connected == (int64_t)max_height + 1)
        return true;

    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "WITH first_missing(h) AS ("
        "SELECT 0 WHERE NOT EXISTS ("
        "SELECT 1 FROM blocks WHERE height=0 AND status>=3)"
        " UNION ALL "
        "SELECT b.height+1 FROM blocks b "
        "LEFT JOIN blocks n ON n.height=b.height+1 AND n.status>=3 "
        "WHERE b.status>=3 AND b.height>=0 AND b.height < ? "
        "AND n.height IS NULL)"
        "SELECT MIN(h) FROM first_missing WHERE h <= ?");
    AR_BIND_INT(s, 1, max_height);
    AR_BIND_INT(s, 2, max_height);
    int step_rc = sqlite3_step(s);  // raw-sql-ok:read-only-introspection
    if (step_rc == SQLITE_ROW && sqlite3_column_type(s, 0) != SQLITE_NULL)
        *height_out = (int)AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    if (step_rc != SQLITE_ROW)
        LOG_FAIL("block", "first_missing_connected_height: scan failed: %s",
                 sqlite3_errmsg(ndb->db));
    return true;
}
