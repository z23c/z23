/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless proof that normal Windows boot admits a retained empty datadir while
 * the offline mint producer remains unavailable without mutation. */
#if defined(_WIN32)

#include "config/boot.h"
#include "platform/directory_transaction.h"
#include "platform/private_directory.h"

#include <sqlite3.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

bool mint_anchor_normal_boot_allowed(sqlite3 *db, char *reason,
                                     size_t reason_size)
{
    (void)db;
    if (reason && reason_size) reason[0] = 0;
    return true;
}

static bool create_private_sqlite(struct platform_directory_transaction *dir,
                                  const char *datadir, const char *leaf,
                                  const char *schema)
{
    struct platform_directory_child child;
    platform_directory_child_init(&child);
    if (!platform_directory_child_create(dir, leaf, &child))
        return false;
    platform_directory_child_close(&child);
    char path[MAX_PATH * 3];
    int n = snprintf(path, sizeof(path), "%s/%s", datadir, leaf);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    sqlite3 *db = NULL;
    bool ok = sqlite3_open_v2(path, &db,
                              SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX,
                              NULL) == SQLITE_OK &&
              sqlite3_exec(db, schema, NULL, NULL, NULL) == SQLITE_OK;
    if (db && sqlite3_close(db) != SQLITE_OK)
        ok = false;
    return ok;
}

static void remove_family(struct platform_directory_transaction *dir,
                          const char *base)
{
    static const char *const suffixes[] = {"", "-wal", "-shm", "-journal"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
        char leaf[80];
        int n = snprintf(leaf, sizeof(leaf), "%s%s", base, suffixes[i]);
        if (n > 0 && (size_t)n < sizeof(leaf))
            (void)platform_directory_child_unlink_result(dir, leaf);
    }
}

int main(void)
{
    wchar_t temp[MAX_PATH], dir[MAX_PATH], marker[MAX_PATH];
    char utf8[MAX_PATH * 3];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(dir, MAX_PATH, L"%lsz23-mint-refuse-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, dir, -1,
                             utf8, sizeof(utf8), NULL, NULL) ||
        !platform_private_directory_create(utf8))
        return 1;
    (void)swprintf(marker, MAX_PATH, L"%ls\\sentinel", dir);
    HANDLE file = CreateFileW(marker, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    const char expected[] = "unchanged";
    DWORD written = 0;
    if (file == INVALID_HANDLE_VALUE ||
        !WriteFile(file, expected, sizeof(expected), &written, NULL) ||
        written != sizeof(expected) || !CloseHandle(file))
        return 1;
    if (!boot_mint_anchor_normal_boot_preflight(utf8) ||
        boot_mint_anchor_preflight_run_all(utf8, NULL))
        return 1;

    struct platform_directory_transaction transaction;
    platform_directory_transaction_init(&transaction);
    const char *projection_schema =
        "CREATE TABLE address_index(key BLOB PRIMARY KEY,value BLOB);"
        "CREATE INDEX address_index_value ON address_index(value);"
        "CREATE TABLE address_index_state(id INTEGER PRIMARY KEY);"
        "CREATE TABLE txindex(key BLOB PRIMARY KEY,value BLOB);"
        "CREATE TABLE txindex_state(id INTEGER PRIMARY KEY);";
    if (!platform_directory_transaction_open(&transaction, utf8) ||
        !create_private_sqlite(&transaction, utf8, "consensus.db", "") ||
        !create_private_sqlite(&transaction, utf8, "progress.kv",
                               projection_schema) ||
        !boot_mint_anchor_normal_boot_preflight(utf8))
        return 1;

    char projection_path[MAX_PATH * 3];
    if (snprintf(projection_path, sizeof(projection_path), "%s/progress.kv",
                 utf8) <= 0)
        return 1;
    sqlite3 *projection = NULL;
    bool opened = sqlite3_open_v2(
        projection_path, &projection,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL) == SQLITE_OK;
    bool wrote_kernel = opened &&
        sqlite3_exec(projection, "CREATE TABLE coins(k BLOB PRIMARY KEY)",
                     NULL, NULL, NULL) == SQLITE_OK;
    if (projection && sqlite3_close(projection) != SQLITE_OK)
        wrote_kernel = false;
    if (!wrote_kernel || boot_mint_anchor_normal_boot_preflight(utf8))
        return 1;

    remove_family(&transaction, "consensus.db");
    remove_family(&transaction, "progress.kv");
    platform_directory_transaction_close(&transaction);
    char actual[sizeof(expected)] = {0};
    file = CreateFileW(marker, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD read = 0;
    bool unchanged = file != INVALID_HANDLE_VALUE &&
                     ReadFile(file, actual, sizeof(actual), &read, NULL) &&
                     read == sizeof(actual) &&
                     memcmp(actual, expected, sizeof(expected)) == 0;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    DeleteFileW(marker);
    platform_private_directory_remove_empty(utf8);
    if (!unchanged)
        return 1;
    puts("mint_anchor_preflight_windows_acceptance: PASS");
    return 0;
}

#else
typedef int mint_anchor_preflight_windows_refusal_not_built;
#endif
