/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless acceptance: native wallet restore refuses before mutation. */

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "base/log_level.h"
#include "services/wallet_restore_service.h"

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

int main(void)
{
    char temp[MAX_PATH], dir[MAX_PATH], sentinel[MAX_PATH];
    char node_db[MAX_PATH], lock_path[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(temp), temp);
    if (!n || n >= sizeof(temp)) return 2;
    snprintf(dir, sizeof(dir), "%sz23-wr-refusal-%lu-%llu", temp,
             (unsigned long)GetCurrentProcessId(),
             (unsigned long long)GetTickCount64());
    if (!CreateDirectoryA(dir, NULL)) return 3;
    snprintf(sentinel, sizeof(sentinel), "%s/sentinel.sqlite", dir);
    snprintf(node_db, sizeof(node_db), "%s/node.db", dir);
    snprintf(lock_path, sizeof(lock_path), "%s/wallet-recovery.lock", dir);
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
    return !queried.ok && !held.ok && !restored.ok && unchanged && no_mutation
               ? 0 : 1;
}
#else
/* Not Windows: this program asserts a Windows-only refusal, so there is
 * nothing to observe here. Exit 77 (the convention its siblings use) so a
 * non-run can never be mistaken for a passing assertion. */
int main(void) { return 77; }
#endif
