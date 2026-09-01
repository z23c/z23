/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Exact canonical SQLite TEXT comparison for consensus-state artifacts. */

#ifndef ZCL_CONSENSUS_STATE_SQLITE_TEXT_H
#define ZCL_CONSENSUS_STATE_SQLITE_TEXT_H

#include <limits.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <string.h>

static inline bool consensus_state_sqlite_text_equal(
    sqlite3_stmt *statement, int column, const char *expected)
{
    if (!statement || !expected ||
        sqlite3_column_type(statement, column) != SQLITE_TEXT)
        return false;
    const unsigned char *actual = sqlite3_column_text(statement, column);
    size_t expected_size = strlen(expected);
    return actual && expected_size <= INT_MAX &&
           sqlite3_column_bytes(statement, column) == (int)expected_size &&
           memcmp(actual, expected, expected_size) == 0;
}

#endif /* ZCL_CONSENSUS_STATE_SQLITE_TEXT_H */
