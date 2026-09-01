/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verify retained private-directory transactions on Windows. */
#include "platform/directory_transaction.h"
#include "platform/private_directory.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static int fail(const char *phase)
{
    fprintf(stderr, "directory_transaction_acceptance: FAIL: %s (%lu)\n",
            phase, (unsigned long)GetLastError());
    return 1;
}

static bool names_are(const struct platform_directory_names *names,
                      const char *first, const char *second)
{
    return names && names->count == 2 &&
           strcmp(names->items[0], first) == 0 &&
           strcmp(names->items[1], second) == 0;
}

static bool same_identity(const struct platform_directory_child_info *left,
                          const struct platform_directory_child_info *right)
{
    return left && right && left->volume == right->volume &&
           left->file_low == right->file_low &&
           left->file_high == right->file_high;
}

struct io_task {
    struct platform_directory_child *child;
    uint64_t offset;
    char byte;
    int failed;
};

static DWORD WINAPI io_worker(void *opaque)
{
    struct io_task *task = opaque;
    char block[64], observed[64];
    memset(block, task->byte, sizeof(block));
    for (unsigned i = 0; i < 250; i++) {
        if (!platform_directory_child_write(task->child, block, sizeof(block),
                                            task->offset) ||
            platform_directory_child_read(task->child, observed,
                                           sizeof(observed), task->offset) !=
                (int64_t)sizeof(observed) ||
            memcmp(block, observed, sizeof(block)) != 0) {
            task->failed = 1;
            break;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--lock-child") == 0) {
        struct platform_directory_transaction child_directory;
        struct platform_directory_lock child_lock;
        platform_directory_transaction_init(&child_directory);
        platform_directory_lock_init(&child_lock);
        if (!platform_directory_transaction_open(&child_directory, argv[2]))
            return 4;
        enum platform_directory_result acquired =
            platform_directory_lock_acquire(&child_directory, "state.lock", false,
                PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &child_lock);
        platform_directory_lock_release(&child_lock);
        platform_directory_transaction_close(&child_directory);
        return acquired == PLATFORM_DIRECTORY_OK ? 0 : 10 + (int)acquired;
    }
    wchar_t temp[MAX_PATH], root_wide[MAX_PATH];
    char root[MAX_PATH * 3];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(root_wide, MAX_PATH, L"%lsz23-dtxn-%lu-%llu", temp,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)GetTickCount64()) <= 0 ||
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root_wide, -1,
                            root, sizeof(root), NULL, NULL) <= 0)
        return fail("private root create");
    if (!platform_private_directory_create(root)) {
        fputs("directory_transaction_acceptance: REFUSE: runtime cannot prove "
              "native SID/DACL semantics\n", stderr);
        return 77;
    }

    int result = 1;
    const char *phase = "open";
    const char *detail = "";
    struct platform_directory_transaction directory;
    struct platform_directory_transaction move_destination;
    struct platform_directory_child stage, opened, occupied, replacement;
    struct platform_directory_child moved, move_probe, collision_source;
    struct platform_directory_child collision_destination, unknown_move;
    platform_directory_transaction_init(&directory);
    platform_directory_transaction_init(&move_destination);
    platform_directory_child_init(&stage);
    platform_directory_child_init(&opened);
    platform_directory_child_init(&occupied);
    platform_directory_child_init(&replacement);
    platform_directory_child_init(&moved);
    platform_directory_child_init(&move_probe);
    platform_directory_child_init(&collision_source);
    platform_directory_child_init(&collision_destination);
    platform_directory_child_init(&unknown_move);
    if (!platform_directory_transaction_open(&directory, root))
        goto cleanup;

    phase = "result/open-or-create/exact I/O";
    struct platform_directory_child opened_or_created;
    platform_directory_child_init(&opened_or_created);
    bool created = false;
    if (platform_directory_child_open_result(
            &directory, "missing", false, false, &opened_or_created, NULL) !=
            PLATFORM_DIRECTORY_MISSING ||
        platform_directory_child_open_result(
            &directory, "exact", true, true, &opened_or_created, &created) !=
            PLATFORM_DIRECTORY_OK || !created ||
        !platform_directory_child_write_exact(&opened_or_created, "exact", 5, 0) ||
        !platform_directory_child_flush(&opened_or_created))
        goto cleanup;
    char exact[5];
    if (!platform_directory_child_read_exact(&opened_or_created, exact, 5, 0) ||
        memcmp(exact, "exact", 5) != 0)
        goto cleanup;
    platform_directory_child_close(&opened_or_created);
    created = true;
    if (platform_directory_child_open_result(
            &directory, "exact", true, true, &opened_or_created, &created) !=
            PLATFORM_DIRECTORY_OK || created)
        goto cleanup;
    platform_directory_child_close(&opened_or_created);
    if (platform_directory_child_unlink_result(&directory, "exact") !=
            PLATFORM_DIRECTORY_OK ||
        platform_directory_child_unlink_result(&directory, "exact") !=
            PLATFORM_DIRECTORY_MISSING)
        goto cleanup;

    phase = "nested retained transaction";
    detail = "open child directory";
    struct platform_directory_transaction nested;
    platform_directory_transaction_init(&nested);
    if (platform_directory_transaction_open_child(
            &directory, "nested", true, &nested) != PLATFORM_DIRECTORY_OK)
        goto cleanup;
    struct platform_directory_child nested_file;
    platform_directory_child_init(&nested_file);
    detail = "create/write/flush child file";
    if (!platform_directory_child_create(&nested, "child", &nested_file) ||
        !platform_directory_child_write_exact(&nested_file, "nested", 6, 0) ||
        !platform_directory_child_flush(&nested_file)) {
        platform_directory_child_close(&nested_file);
        platform_directory_transaction_close(&nested);
        goto cleanup;
    }
    platform_directory_child_close(&nested_file);
    detail = "unlink child file";
    if (platform_directory_child_unlink_result(&nested, "child") !=
        PLATFORM_DIRECTORY_OK) {
        platform_directory_transaction_close(&nested);
        goto cleanup;
    }
    platform_directory_transaction_close(&nested);
    detail = "remove child directory";
    char nested_path[MAX_PATH];
    if (snprintf(nested_path, sizeof(nested_path), "%s/nested", root) <= 0 ||
        !platform_private_directory_remove_empty(nested_path))
        goto cleanup;

    phase = "retained exclusive lock";
    detail = "acquire parent-relative lock";
    struct platform_directory_lock lock;
    platform_directory_lock_init(&lock);
    if (platform_directory_lock_acquire(&directory, "state.lock", true,
            PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lock) != PLATFORM_DIRECTORY_OK)
        goto cleanup;
    wchar_t executable[MAX_PATH], command[MAX_PATH * 4];
    detail = "construct lock contender command";
    if (!GetModuleFileNameW(NULL, executable, MAX_PATH) ||
        swprintf(command, sizeof(command) / sizeof(command[0]),
                 L"\"%ls\" --lock-child \"%ls\"", executable, root_wide) <= 0)
        goto cleanup;
    STARTUPINFOW startup = {.cb = sizeof(startup)};
    PROCESS_INFORMATION process = {0};
    detail = "start lock contender";
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
        goto cleanup;
    CloseHandle(process.hThread);
    DWORD child_wait = WaitForSingleObject(process.hProcess, 10000);
    DWORD child_exit = UINT32_MAX;
    (void)GetExitCodeProcess(process.hProcess, &child_exit);
    CloseHandle(process.hProcess);
    if (child_wait != WAIT_OBJECT_0 ||
        child_exit != 10 + PLATFORM_DIRECTORY_REFUSED) {
        fprintf(stderr, "lock contender held: wait=%lu exit=%lu\n",
                (unsigned long)child_wait, (unsigned long)child_exit);
        goto cleanup;
    }
    detail = "release lock and start successful contender";
    platform_directory_lock_release(&lock);
    process = (PROCESS_INFORMATION){0};
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
        goto cleanup;
    CloseHandle(process.hThread);
    child_wait = WaitForSingleObject(process.hProcess, 10000);
    child_exit = UINT32_MAX;
    (void)GetExitCodeProcess(process.hProcess, &child_exit);
    CloseHandle(process.hProcess);
    if (child_wait != WAIT_OBJECT_0 || child_exit != 0) {
        fprintf(stderr, "lock contender released: wait=%lu exit=%lu\n",
                (unsigned long)child_wait, (unsigned long)child_exit);
        goto cleanup;
    }
    detail = "unlink released lock file";
    if (platform_directory_child_unlink_result(&directory, "state.lock") !=
        PLATFORM_DIRECTORY_OK)
        goto cleanup;

    static const char payload[] = "hello-directory-transaction";
    phase = "child create";
    if (!platform_directory_child_create(&directory, "alpha.stage", &stage))
        goto cleanup;
    phase = "child write";
    if (!platform_directory_child_write(&stage, payload, sizeof(payload) - 1, 0))
        goto cleanup;
    phase = "child flush";
    if (!platform_directory_child_flush(&stage)) goto cleanup;
    phase = "no-clobber publication";
    if (!platform_directory_child_replace(&directory, &stage, "alpha", true))
        goto cleanup;
    platform_directory_child_close(&stage);

    phase = "read/truncate/flush/info";
    char observed[sizeof(payload)] = {0};
    struct platform_directory_child_info info;
    if (!platform_directory_child_open(&directory, "alpha", &opened) ||
        platform_directory_child_read(&opened, observed, sizeof(payload) - 1, 0) !=
            (int64_t)(sizeof(payload) - 1) ||
        memcmp(observed, payload, sizeof(payload) - 1) != 0 ||
        !platform_directory_child_truncate(&opened, 5) ||
        !platform_directory_child_write(&opened, "!", 1, 5) ||
        !platform_directory_child_flush(&opened) ||
        !platform_directory_child_info(&opened, &info) || info.size != 6)
        goto cleanup;
    platform_directory_child_close(&opened);

    phase = "concurrent positioned I/O";
    struct platform_directory_child concurrent;
    platform_directory_child_init(&concurrent);
    if (!platform_directory_child_create(&directory, "concurrent", &concurrent))
        goto cleanup;
    struct io_task tasks[4] = {
        {&concurrent, 0, 'A', 0}, {&concurrent, 64, 'B', 0},
        {&concurrent, 128, 'C', 0}, {&concurrent, 192, 'D', 0}};
    HANDLE threads[4] = {0};
    for (unsigned i = 0; i < 4; i++)
        threads[i] = CreateThread(NULL, 0, io_worker, &tasks[i], 0, NULL);
    DWORD waited = WaitForMultipleObjects(4, threads, TRUE, 30000);
    bool io_failed = waited != WAIT_OBJECT_0;
    for (unsigned i = 0; i < 4; i++) {
        if (threads[i]) CloseHandle(threads[i]);
        io_failed |= !threads[i] || tasks[i].failed;
    }
    if (io_failed || !platform_directory_child_flush(&concurrent)) {
        platform_directory_child_close(&concurrent);
        goto cleanup;
    }
    platform_directory_child_close(&concurrent);
    if (!platform_directory_child_unlink(&directory, "concurrent", false))
        goto cleanup;

    phase = "no-clobber and replacement";
    if (!platform_directory_child_create(&directory, "occupied", &occupied) ||
        !platform_directory_child_write(&occupied, "old", 3, 0) ||
        !platform_directory_child_flush(&occupied))
        goto cleanup;
    platform_directory_child_close(&occupied);
    if (!platform_directory_child_create(&directory, "beta.stage", &replacement) ||
        !platform_directory_child_write(&replacement, "new", 3, 0) ||
        !platform_directory_child_flush(&replacement) ||
        platform_directory_child_replace(&directory, &replacement,
                                          "occupied", true) ||
        !platform_directory_child_replace(&directory, &replacement,
                                           "occupied", false))
        goto cleanup;
    platform_directory_child_close(&replacement);

    phase = "retained cross-directory move";
    detail = "create retained destination";
    if (platform_directory_transaction_open_child(
            &directory, "move-target", true, &move_destination) !=
        PLATFORM_DIRECTORY_OK)
        goto cleanup;
    platform_directory_transaction_close(&move_destination);
    char move_target_path[MAX_PATH];
    if (snprintf(move_target_path, sizeof(move_target_path),
                 "%s/move-target", root) <= 0)
        goto cleanup;
    detail = "reopen top-level retained destination";
    if (!platform_directory_transaction_open(&move_destination,
                                             move_target_path))
        goto cleanup;
    detail = "create retained source";
    if (!platform_directory_child_create(&directory, "move.stage", &moved) ||
        !platform_directory_child_write_exact(&moved, "move-payload", 12, 0) ||
        !platform_directory_child_flush(&moved))
        goto cleanup;
    struct platform_directory_child_info moved_before, moved_after;
    if (!platform_directory_child_info(&moved, &moved_before))
        goto cleanup;
    detail = "invalid destination leaf refusal";
    if (platform_directory_child_move_between(
            &directory, &moved, &move_destination, "name:stream", true) !=
            PLATFORM_DIRECTORY_INVALID ||
        strcmp(moved.leaf, "move.stage") != 0)
        goto cleanup;
    detail = "no-clobber move";
    if (platform_directory_child_move_between(
            &directory, &moved, &move_destination, "move.final", true) !=
            PLATFORM_DIRECTORY_OK ||
        strcmp(moved.leaf, "move.final") != 0)
        goto cleanup;
    if (platform_directory_child_open_result(
            &directory, "move.stage", false, false, &move_probe, NULL) !=
            PLATFORM_DIRECTORY_MISSING ||
        !platform_directory_child_open(&move_destination, "move.final",
                                       &move_probe) ||
        !platform_directory_child_info(&move_probe, &moved_after) ||
        !same_identity(&moved_before, &moved_after))
        goto cleanup;
    platform_directory_child_close(&move_probe);

    detail = "cross-directory no-clobber collision";
    if (!platform_directory_child_create(
            &move_destination, "collision.final", &collision_destination) ||
        !platform_directory_child_write_exact(
            &collision_destination, "old", 3, 0) ||
        !platform_directory_child_flush(&collision_destination))
        goto cleanup;
    platform_directory_child_close(&collision_destination);
    if (!platform_directory_child_create(
            &directory, "collision.stage", &collision_source) ||
        !platform_directory_child_write_exact(&collision_source, "new", 3, 0) ||
        !platform_directory_child_flush(&collision_source))
        goto cleanup;
    struct platform_directory_child_info collision_before, collision_after;
    if (!platform_directory_child_info(&collision_source, &collision_before) ||
        platform_directory_child_move_between(
            &directory, &collision_source, &move_destination,
            "collision.final", true) != PLATFORM_DIRECTORY_EXISTS ||
        strcmp(collision_source.leaf, "collision.stage") != 0)
        goto cleanup;
    detail = "cross-directory replacement";
    if (platform_directory_child_move_between(
            &directory, &collision_source, &move_destination,
            "collision.final", false) != PLATFORM_DIRECTORY_OK ||
        !platform_directory_child_open(
            &move_destination, "collision.final", &collision_destination) ||
        !platform_directory_child_info(
            &collision_destination, &collision_after) ||
        !same_identity(&collision_before, &collision_after))
        goto cleanup;
    platform_directory_child_close(&collision_destination);

    detail = "post-rename durability ambiguity";
    if (!platform_directory_child_create(
            &directory, "unknown.stage", &unknown_move) ||
        !platform_directory_child_write_exact(&unknown_move, "unknown", 7, 0) ||
        !platform_directory_child_flush(&unknown_move))
        goto cleanup;
    struct platform_directory_child_info unknown_before, unknown_after;
    if (!platform_directory_child_info(&unknown_move, &unknown_before))
        goto cleanup;
    platform_directory_child_move_test_fail_durability_once();
    if (platform_directory_child_move_between(
            &directory, &unknown_move, &move_destination,
            "unknown.final", true) != PLATFORM_DIRECTORY_OUTCOME_UNKNOWN ||
        strcmp(unknown_move.leaf, "unknown.final") != 0 ||
        platform_directory_child_open_result(
            &directory, "unknown.stage", false, false, &move_probe, NULL) !=
            PLATFORM_DIRECTORY_MISSING ||
        !platform_directory_child_open(
            &move_destination, "unknown.final", &move_probe) ||
        !platform_directory_child_info(&move_probe, &unknown_after) ||
        !same_identity(&unknown_before, &unknown_after))
        goto cleanup;
    platform_directory_child_close(&move_probe);
    if (!platform_directory_transaction_flush(&move_destination) ||
        !platform_directory_transaction_flush(&directory))
        goto cleanup;

    platform_directory_child_close(&moved);
    platform_directory_child_close(&collision_source);
    platform_directory_child_close(&unknown_move);
    if (!platform_directory_child_unlink(
            &move_destination, "move.final", false) ||
        !platform_directory_child_unlink(
            &move_destination, "collision.final", false) ||
        !platform_directory_child_unlink(
            &move_destination, "unknown.final", false))
        goto cleanup;
    platform_directory_transaction_close(&move_destination);
    if (!platform_private_directory_remove_empty(move_target_path))
        goto cleanup;

    phase = "sorted regular listing";
    struct platform_directory_names names;
    if (!platform_directory_transaction_list_regular(&directory, &names))
        goto cleanup;
    bool sorted = names_are(&names, "alpha", "occupied");
    platform_directory_names_free(&names);
    if (!sorted) goto cleanup;

    phase = "invalid leaf rejection";
    char overlong[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 2u];
    memset(overlong, 'x', sizeof(overlong) - 1u);
    overlong[sizeof(overlong) - 1u] = 0;
    static const char *const fixed_invalid[] = {
        "", ".", "..", "../x", "x/y", "x\\y", "name:stream",
        "trailing.", "trailing ", "CON", "NUL.txt", "COM1"};
    const size_t invalid_count =
        sizeof(fixed_invalid) / sizeof(fixed_invalid[0]) + 1u;
    for (size_t i = 0; i < invalid_count; i++) {
        const char *leaf = i < invalid_count - 1u ? fixed_invalid[i] : overlong;
        struct platform_directory_child bad;
        platform_directory_child_init(&bad);
        if (platform_directory_child_create(&directory, leaf, &bad)) {
            platform_directory_child_close(&bad);
            goto cleanup;
        }
    }

    phase = "reparse child refusal";
    wchar_t alpha_path[MAX_PATH], link_path[MAX_PATH];
    if (swprintf(alpha_path, MAX_PATH, L"%ls\\alpha", root_wide) <= 0 ||
        swprintf(link_path, MAX_PATH, L"%ls\\alpha-link", root_wide) <= 0)
        goto cleanup;
    if (CreateSymbolicLinkW(link_path, alpha_path,
                            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        struct platform_directory_child link;
        platform_directory_child_init(&link);
        bool followed = platform_directory_child_open(&directory, "alpha-link",
                                                       &link);
        platform_directory_child_close(&link);
        DeleteFileW(link_path);
        if (followed) goto cleanup;
    }

    phase = "missing versus non-file refusal";
    wchar_t blocked[MAX_PATH];
    if (swprintf(blocked, MAX_PATH, L"%ls\\blocked", root_wide) <= 0 ||
        !CreateDirectoryW(blocked, NULL) ||
        platform_directory_child_unlink_result(&directory, "blocked") !=
            PLATFORM_DIRECTORY_REFUSED)
        goto cleanup;
    RemoveDirectoryW(blocked);

    phase = "multi-page sorted listing restart";
    enum { MANY_COUNT = 900 };
    for (unsigned i = 0; i < MANY_COUNT; i++) {
        char leaf[96];
        snprintf(leaf, sizeof(leaf),
                 "entry-%04u-abcdefghijklmnopqrstuvwxyz0123456789", i);
        struct platform_directory_child many;
        platform_directory_child_init(&many);
        if (!platform_directory_child_create(&directory, leaf, &many))
            goto cleanup;
        platform_directory_child_close(&many);
    }
    struct platform_directory_names first, second;
    if (!platform_directory_transaction_list_regular(&directory, &first) ||
        !platform_directory_transaction_list_regular(&directory, &second))
        goto cleanup;
    bool complete = first.count == MANY_COUNT + 2u &&
                    second.count == first.count;
    for (size_t i = 0; complete && i < first.count; i++) {
        complete = strcmp(first.items[i], second.items[i]) == 0 &&
                   (i == 0 || strcmp(first.items[i - 1], first.items[i]) < 0);
    }
    platform_directory_names_free(&second);
    platform_directory_names_free(&first);
    if (!complete) goto cleanup;
    for (unsigned i = 0; i < MANY_COUNT; i++) {
        char leaf[96];
        snprintf(leaf, sizeof(leaf),
                 "entry-%04u-abcdefghijklmnopqrstuvwxyz0123456789", i);
        if (!platform_directory_child_unlink(&directory, leaf, false))
            goto cleanup;
    }
    phase = "flush and unlink";
    if (!platform_directory_transaction_flush(&directory) ||
        !platform_directory_child_unlink(&directory, "alpha", false) ||
        !platform_directory_child_unlink(&directory, "occupied", false) ||
        !platform_directory_child_unlink(&directory, "already-missing", true))
        goto cleanup;
    result = 0;

cleanup:
    platform_directory_child_close(&unknown_move);
    platform_directory_child_close(&collision_destination);
    platform_directory_child_close(&collision_source);
    platform_directory_child_close(&move_probe);
    platform_directory_child_close(&moved);
    platform_directory_child_close(&replacement);
    platform_directory_child_close(&occupied);
    platform_directory_child_close(&opened);
    platform_directory_child_close(&stage);
    if (move_destination.native != UINTPTR_MAX) {
        (void)platform_directory_child_unlink(
            &move_destination, "move.final", true);
        (void)platform_directory_child_unlink(
            &move_destination, "collision.final", true);
        (void)platform_directory_child_unlink(
            &move_destination, "unknown.final", true);
    }
    platform_directory_transaction_close(&move_destination);
    if (directory.native != UINTPTR_MAX) {
        (void)platform_directory_child_unlink(&directory, "alpha.stage", true);
        (void)platform_directory_child_unlink(&directory, "alpha", true);
        (void)platform_directory_child_unlink(&directory, "beta.stage", true);
        (void)platform_directory_child_unlink(&directory, "occupied", true);
        (void)platform_directory_child_unlink(&directory, "concurrent", true);
        (void)platform_directory_child_unlink(&directory, "exact", true);
        (void)platform_directory_child_unlink(&directory, "state.lock", true);
        (void)platform_directory_child_unlink(&directory, "move.stage", true);
        (void)platform_directory_child_unlink(
            &directory, "collision.stage", true);
        (void)platform_directory_child_unlink(
            &directory, "unknown.stage", true);
        for (unsigned i = 0; i < 900; i++) {
            char leaf[96];
            snprintf(leaf, sizeof(leaf),
                     "entry-%04u-abcdefghijklmnopqrstuvwxyz0123456789", i);
            (void)platform_directory_child_unlink(&directory, leaf, true);
        }
    }
    platform_directory_transaction_close(&directory);
    wchar_t blocked_cleanup[MAX_PATH];
    if (swprintf(blocked_cleanup, MAX_PATH, L"%ls\\blocked", root_wide) > 0)
        (void)RemoveDirectoryW(blocked_cleanup);
    wchar_t nested_cleanup[MAX_PATH];
    if (swprintf(nested_cleanup, MAX_PATH, L"%ls\\nested", root_wide) > 0)
        (void)RemoveDirectoryW(nested_cleanup);
    wchar_t move_target_cleanup[MAX_PATH];
    if (swprintf(move_target_cleanup, MAX_PATH, L"%ls\\move-target",
                 root_wide) > 0)
        (void)RemoveDirectoryW(move_target_cleanup);
    if (!platform_private_directory_remove_empty(root)) result = 1;
    if (result) {
        fprintf(stderr, "directory_transaction_acceptance detail: %s "
                        "winerr=%lu\n", detail,
                (unsigned long)GetLastError());
        return fail(phase);
    }
    puts("directory_transaction_acceptance: PASS");
    return 0;
}
#else
int main(void) { return 77; }
#endif
