/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused native acceptance for Windows SQLite lifetime path recognition. */

#include "models/database_lifetime.h" // lib-layer-ok:windows-db-lifetime-acceptance

#include <sqlite3.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>

static int fail(const char *message)
{
    fprintf(stderr, "database_lifetime_acceptance: %s (win32=%lu)\n",
            message, (unsigned long)GetLastError());
    return 1;
}

int main(void)
{
    wchar_t temp[MAX_PATH], directory[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        !GetTempFileNameW(temp, L"zdl", 0, directory) ||
        !DeleteFileW(directory) || !CreateDirectoryW(directory, NULL))
        return fail("temporary directory creation failed");

    wchar_t database_wide[MAX_PATH];
    if (swprintf(database_wide, MAX_PATH, L"%ls\\node.db", directory) <= 0)
        return fail("database path construction failed");
    char database[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                             database_wide, -1, database,
                             sizeof(database), NULL, NULL))
        return fail("database path conversion failed");

    if (!db_lifetime_install())
        return fail("lifetime VFS installation failed");
    struct db_lifetime_scope owner_scope;
    db_lifetime_scope_enter(&owner_scope, "node_db.canonical",
                            DB_LIFETIME_BACKING_OWNER, 0);
    sqlite3 *db = NULL;
    int rc = sqlite3_open(database, &db);
    uint64_t generation = db_lifetime_scope_generation();
    db_lifetime_scope_leave(&owner_scope);
    if (rc != SQLITE_OK || !db || generation == 0)
        return fail("tracked backing-owner open failed");

    uint64_t before = db_lifetime_unauthorized_count();
    struct db_lifetime_scope borrowed_scope;
    db_lifetime_scope_enter(&borrowed_scope, "windows.acceptance.borrower",
                            DB_LIFETIME_BORROWED, generation);
    sqlite3_vfs *vfs = sqlite3_vfs_find(NULL);
    rc = vfs ? vfs->xDelete(vfs, database, 0) : SQLITE_ERROR;
    db_lifetime_scope_leave(&borrowed_scope);
    if (rc != SQLITE_IOERR_DELETE ||
        db_lifetime_unauthorized_count() != before + 1)
        return fail("backslash node.db retirement was not refused");

    db_lifetime_scope_enter(&owner_scope, "node_db.canonical",
                            DB_LIFETIME_BACKING_OWNER, generation);
    rc = sqlite3_close(db);
    db_lifetime_scope_leave(&owner_scope);
    if (rc != SQLITE_OK || !DeleteFileW(database_wide) ||
        !RemoveDirectoryW(directory))
        return fail("fixture cleanup failed");

    puts("database_lifetime_acceptance: PASS");
    return 0;
}
