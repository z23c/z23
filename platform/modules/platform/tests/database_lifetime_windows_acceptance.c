/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused native acceptance for Windows SQLite lifetime path recognition. */

/* struct db_lifetime_scope is stack-allocated by value below (its address is
 * taken across two enter/leave pairs), so a true opaque forward declaration
 * cannot work here — the compiler needs the complete type at the declaration
 * site. Re-declaring a byte-for-byte mirror of the struct in a lib/-owned
 * header would silently desync from models/database_lifetime.h on the next
 * field change, trading a visible layering violation for an invisible ABI
 * one. This acceptance test also exists specifically to exercise the real
 * production db_lifetime_* implementation end-to-end on Windows (the same
 * reasoning already applied one file over, see
 * rpc_client_transport_windows_acceptance.c's controllers/rpc_client.h
 * include), so a reimplementation would defeat its purpose. */
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

/* Creates a fresh empty fixture directory and stores its path in directory. */
static int create_fixture_directory(wchar_t directory[MAX_PATH])
{
    wchar_t temp[MAX_PATH];
    return GetTempPathW(MAX_PATH, temp) &&
           GetTempFileNameW(temp, L"zdl", 0, directory) &&
           DeleteFileW(directory) && CreateDirectoryW(directory, NULL);
}

/* Builds the wide node.db path inside directory. */
static int format_database_path(const wchar_t *directory,
                                wchar_t database_wide[MAX_PATH])
{
    return swprintf(database_wide, MAX_PATH, L"%ls\\node.db", directory) > 0;
}

/* Converts the wide database path to the UTF-8 form SQLite consumes. */
static int convert_database_path(const wchar_t *database_wide,
                                 char database[MAX_PATH * 3])
{
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                               database_wide, -1, database,
                               MAX_PATH * 3, NULL, NULL) != 0;
}

/* Opens the canonical database as the tracked backing owner and reports
 * the lifetime generation it was opened under. */
static int open_tracked_owner(const char *database, sqlite3 **db,
                              uint64_t *generation)
{
    struct db_lifetime_scope owner_scope;
    db_lifetime_scope_enter(&owner_scope, "node_db.canonical",
                            DB_LIFETIME_BACKING_OWNER, 0);
    int rc = sqlite3_open(database, db);
    *generation = db_lifetime_scope_generation();
    db_lifetime_scope_leave(&owner_scope);
    return rc == SQLITE_OK && *db != NULL && *generation != 0;
}

/* Attempts to delete the tracked database through a borrowed scope and
 * returns the raw SQLite result. */
static int attempt_borrowed_delete(const char *database, uint64_t generation)
{
    struct db_lifetime_scope borrowed_scope;
    db_lifetime_scope_enter(&borrowed_scope, "windows.acceptance.borrower",
                            DB_LIFETIME_BORROWED, generation);
    sqlite3_vfs *vfs = sqlite3_vfs_find(NULL);
    int rc = vfs ? vfs->xDelete(vfs, database, 0) : SQLITE_ERROR;
    db_lifetime_scope_leave(&borrowed_scope);
    return rc;
}

/* Closes the tracked owner handle under its owner scope and returns the
 * raw SQLite result. */
static int close_tracked_owner(sqlite3 *db, uint64_t generation)
{
    struct db_lifetime_scope owner_scope;
    db_lifetime_scope_enter(&owner_scope, "node_db.canonical",
                            DB_LIFETIME_BACKING_OWNER, generation);
    int rc = sqlite3_close(db);
    db_lifetime_scope_leave(&owner_scope);
    return rc;
}

int main(void)
{
    wchar_t directory[MAX_PATH];
    if (!create_fixture_directory(directory))
        return fail("temporary directory creation failed");

    wchar_t database_wide[MAX_PATH];
    if (!format_database_path(directory, database_wide))
        return fail("database path construction failed");
    char database[MAX_PATH * 3];
    if (!convert_database_path(database_wide, database))
        return fail("database path conversion failed");

    if (!db_lifetime_install())
        return fail("lifetime VFS installation failed");
    sqlite3 *db = NULL;
    uint64_t generation = 0;
    if (!open_tracked_owner(database, &db, &generation))
        return fail("tracked backing-owner open failed");

    uint64_t before = db_lifetime_unauthorized_count();
    int rc = attempt_borrowed_delete(database, generation);
    if (rc != SQLITE_IOERR_DELETE ||
        db_lifetime_unauthorized_count() != before + 1)
        return fail("backslash node.db retirement was not refused");

    rc = close_tracked_owner(db, generation);
    if (rc != SQLITE_OK || !DeleteFileW(database_wide) ||
        !RemoveDirectoryW(directory))
        return fail("fixture cleanup failed");

    puts("database_lifetime_acceptance: PASS");
    return 0;
}
