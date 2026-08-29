/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves native wallet restore refuses before mutation on Windows --
 * the datadir query, the datadir hold and the restore run all fail, the
 * backup sentinel is byte-unchanged, and neither node.db nor the recovery
 * lock is created.
 *
 * Adopted from tools/tests/test_wallet_restore_windows_refusal.c, which the
 * deleted tools/scripts/winacceptance.sh only ever compiled — and compiled
 * NATIVELY, so the arm below (the whole assertion) was never read by a
 * compiler at all. The catalog cross-links it for Windows, which is the first
 * time these lines are checked. The body is the original verbatim; only the
 * non-Windows arm changed, from a `return 77` main() to the not-built typedef
 * its catalog siblings use. */
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "base/log_level.h"
#include "services/wallet_restore_service.h"

#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

enum zcl_log_level zcl_log_level_get(void) { return ZCL_LOG_OFF; }
void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
}

static bool write_sentinel(const char *path, const char *bytes)
{
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    bool ok = file != INVALID_HANDLE_VALUE &&
              WriteFile(file, bytes, (DWORD)strlen(bytes), &written, NULL) &&
              written == strlen(bytes);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return ok;
}

static bool format_path(char *out, size_t capacity, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int written = vsnprintf(out, capacity, format, args);
    va_end(args);
    return written >= 0 && (size_t)written < capacity;
}

int main(void)
{
    char temp[MAX_PATH], dir[MAX_PATH + 64];
    char sentinel[MAX_PATH + 96], node_db[MAX_PATH + 80];
    char lock_path[MAX_PATH + 96];
    DWORD n = GetTempPathA(sizeof(temp), temp);
    if (!n || n >= sizeof(temp)) return 2;
    if (!format_path(dir, sizeof(dir), "%sz23-wr-refusal-%lu-%llu", temp,
                     (unsigned long)GetCurrentProcessId(),
                     (unsigned long long)GetTickCount64()))
        return 2;
    if (!CreateDirectoryA(dir, NULL)) return 3;
    if (!format_path(sentinel, sizeof(sentinel), "%s/sentinel.sqlite", dir) ||
        !format_path(node_db, sizeof(node_db), "%s/node.db", dir) ||
        !format_path(lock_path, sizeof(lock_path),
                     "%s/wallet-recovery.lock", dir)) {
        RemoveDirectoryA(dir);
        return 2;
    }
    const char expected[] = "synthetic-wallet-restore-sentinel";
    if (!write_sentinel(sentinel, expected)) return 4;

    struct wallet_restore_datadir_lock lock = {0};
    struct wallet_restore_report report;
    struct wallet_restore_request request = {
        .backup_path = sentinel,
        .datadir = dir,
        .password = NULL,
        .dry_run = false,
    };
    struct zcl_result queried = wallet_restore_datadir_free(dir);
    struct zcl_result held = wallet_restore_datadir_hold(dir, &lock);
    struct zcl_result restored = wallet_restore_run(&request, &report);
    wallet_restore_datadir_release(&lock);

    char actual[sizeof(expected)] = {0};
    HANDLE file = CreateFileA(sentinel, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD read = 0;
    bool unchanged = file != INVALID_HANDLE_VALUE &&
        ReadFile(file, actual, sizeof(expected) - 1, &read, NULL) &&
        read == sizeof(expected) - 1 &&
        memcmp(actual, expected, sizeof(expected) - 1) == 0;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    bool no_mutation = GetFileAttributesA(node_db) == INVALID_FILE_ATTRIBUTES &&
                       GetFileAttributesA(lock_path) == INVALID_FILE_ATTRIBUTES;

    DeleteFileA(sentinel);
    RemoveDirectoryA(dir);
    if (queried.ok || held.ok || restored.ok || !unchanged || !no_mutation)
        return 1;
    puts("wallet_restore_windows_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int wallet_restore_windows_refusal_not_built;
#endif
