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

/* Shared fixture capabilities remain live through the final cleanup.
 * In particular, I/O workers borrow tasks and concurrent from this storage. */
struct directory_fixture {
    wchar_t root_wide[MAX_PATH];
    char root[MAX_PATH * 3];
    const char *phase, *detail;
    struct platform_directory_transaction directory, move_destination;
    struct platform_directory_child stage, opened, occupied, replacement;
    struct platform_directory_child moved, move_probe, collision_source;
    struct platform_directory_child collision_destination, unknown_move;
    struct platform_directory_child concurrent;
    struct io_task tasks[4];
    char move_target_path[MAX_PATH];
    struct platform_directory_child_info moved_before;
};

static bool fixture_exact_io(struct directory_fixture *f)
{
    f->phase = "result/open-or-create/exact I/O";
    struct platform_directory_child opened_or_created;
    platform_directory_child_init(&opened_or_created);
    bool created = false;
    if (platform_directory_child_open_result(
            &f->directory, "missing", false, false, &opened_or_created, NULL) !=
            PLATFORM_DIRECTORY_MISSING ||
        platform_directory_child_open_result(
            &f->directory, "exact", true, true, &opened_or_created, &created) !=
            PLATFORM_DIRECTORY_OK || !created ||
        !platform_directory_child_write_exact(&opened_or_created, "exact", 5, 0) ||
        !platform_directory_child_flush(&opened_or_created))
        return false;
    char exact[5];
    if (!platform_directory_child_read_exact(&opened_or_created, exact, 5, 0) ||
        memcmp(exact, "exact", 5) != 0)
        return false;
    platform_directory_child_close(&opened_or_created);
    created = true;
    if (platform_directory_child_open_result(
            &f->directory, "exact", true, true, &opened_or_created, &created) !=
            PLATFORM_DIRECTORY_OK || created)
        return false;
    platform_directory_child_close(&opened_or_created);
    if (platform_directory_child_unlink_result(&f->directory, "exact") !=
            PLATFORM_DIRECTORY_OK ||
        platform_directory_child_unlink_result(&f->directory, "exact") !=
            PLATFORM_DIRECTORY_MISSING)
        return false;
    return true;
}

static bool fixture_nested(struct directory_fixture *f)
{
    f->phase = "nested retained transaction";
    f->detail = "open child directory";
    struct platform_directory_transaction nested;
    platform_directory_transaction_init(&nested);
    if (platform_directory_transaction_open_child(
            &f->directory, "nested", true, &nested) != PLATFORM_DIRECTORY_OK)
        return false;
    struct platform_directory_child nested_file;
    platform_directory_child_init(&nested_file);
    f->detail = "create/write/flush child file";
    if (!platform_directory_child_create(&nested, "child", &nested_file) ||
        !platform_directory_child_write_exact(&nested_file, "nested", 6, 0) ||
        !platform_directory_child_flush(&nested_file)) {
        platform_directory_child_close(&nested_file);
        platform_directory_transaction_close(&nested);
        return false;
    }
    platform_directory_child_close(&nested_file);
    f->detail = "unlink child file";
    if (platform_directory_child_unlink_result(&nested, "child") !=
        PLATFORM_DIRECTORY_OK) {
        platform_directory_transaction_close(&nested);
        return false;
    }
    platform_directory_transaction_close(&nested);
    f->detail = "remove child directory";
    char nested_path[MAX_PATH];
    if (snprintf(nested_path, sizeof(nested_path), "%s/nested", f->root) <= 0 ||
        !platform_private_directory_remove_empty(nested_path))
        return false;
    return true;
}

static bool fixture_locking(struct directory_fixture *f)
{
    f->phase = "retained exclusive lock";
    f->detail = "acquire parent-relative lock";
    struct platform_directory_lock lock;
    platform_directory_lock_init(&lock);
    if (platform_directory_lock_acquire(&f->directory, "state.lock", true,
            PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lock) != PLATFORM_DIRECTORY_OK)
        return false;
    wchar_t executable[MAX_PATH], command[MAX_PATH * 4];
    f->detail = "construct lock contender command";
    if (!GetModuleFileNameW(NULL, executable, MAX_PATH) ||
        swprintf(command, sizeof(command) / sizeof(command[0]),
                 L"\"%ls\" --lock-child \"%ls\"", executable, f->root_wide) <= 0)
        return false;
    STARTUPINFOW startup = {.cb = sizeof(startup)};
    PROCESS_INFORMATION process = {0};
    f->detail = "start lock contender";
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
        return false;
    CloseHandle(process.hThread);
    DWORD child_wait = WaitForSingleObject(process.hProcess, 10000);
    DWORD child_exit = UINT32_MAX;
    (void)GetExitCodeProcess(process.hProcess, &child_exit);
    CloseHandle(process.hProcess);
    if (child_wait != WAIT_OBJECT_0 ||
        child_exit != 10 + PLATFORM_DIRECTORY_REFUSED) {
        fprintf(stderr, "lock contender held: wait=%lu exit=%lu\n",
                (unsigned long)child_wait, (unsigned long)child_exit);
        return false;
    }
    f->detail = "release lock and start successful contender";
    platform_directory_lock_release(&lock);
    process = (PROCESS_INFORMATION){0};
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
        return false;
    CloseHandle(process.hThread);
    child_wait = WaitForSingleObject(process.hProcess, 10000);
    child_exit = UINT32_MAX;
    (void)GetExitCodeProcess(process.hProcess, &child_exit);
    CloseHandle(process.hProcess);
    if (child_wait != WAIT_OBJECT_0 || child_exit != 0) {
        fprintf(stderr, "lock contender released: wait=%lu exit=%lu\n",
                (unsigned long)child_wait, (unsigned long)child_exit);
        return false;
    }
    f->detail = "unlink released lock file";
    if (platform_directory_child_unlink_result(&f->directory, "state.lock") !=
        PLATFORM_DIRECTORY_OK)
        return false;
    return true;
}

static bool fixture_publish_read(struct directory_fixture *f)
{
    static const char payload[] = "hello-directory-transaction";
    f->phase = "child create";
    if (!platform_directory_child_create(&f->directory, "alpha.stage", &f->stage))
        return false;
    f->phase = "child write";
    if (!platform_directory_child_write(&f->stage, payload, sizeof(payload) - 1, 0))
        return false;
    f->phase = "child flush";
    if (!platform_directory_child_flush(&f->stage)) return false;
    f->phase = "no-clobber publication";
    if (!platform_directory_child_replace(&f->directory, &f->stage, "alpha", true))
        return false;
    platform_directory_child_close(&f->stage);

    f->phase = "read/truncate/flush/info";
    char observed[sizeof(payload)] = {0};
    struct platform_directory_child_info info;
    if (!platform_directory_child_open(&f->directory, "alpha", &f->opened) ||
        platform_directory_child_read(&f->opened, observed, sizeof(payload) - 1, 0) !=
            (int64_t)(sizeof(payload) - 1) ||
        memcmp(observed, payload, sizeof(payload) - 1) != 0 ||
        !platform_directory_child_truncate(&f->opened, 5) ||
        !platform_directory_child_write(&f->opened, "!", 1, 5) ||
        !platform_directory_child_flush(&f->opened) ||
        !platform_directory_child_info(&f->opened, &info) || info.size != 6)
        return false;
    platform_directory_child_close(&f->opened);
    return true;
}

static bool fixture_concurrent_io(struct directory_fixture *f)
{
    f->phase = "concurrent positioned I/O";
    platform_directory_child_init(&f->concurrent);
    if (!platform_directory_child_create(&f->directory, "concurrent", &f->concurrent))
        return false;
    struct io_task initial_tasks[4] = {
        {&f->concurrent, 0, 'A', 0}, {&f->concurrent, 64, 'B', 0},
        {&f->concurrent, 128, 'C', 0}, {&f->concurrent, 192, 'D', 0}};
    memcpy(f->tasks, initial_tasks, sizeof(f->tasks));
    HANDLE threads[4] = {0};
    for (unsigned i = 0; i < 4; i++)
        threads[i] = CreateThread(NULL, 0, io_worker, &f->tasks[i], 0, NULL);
    DWORD waited = WaitForMultipleObjects(4, threads, TRUE, 30000);
    bool io_failed = waited != WAIT_OBJECT_0;
    for (unsigned i = 0; i < 4; i++) {
        if (threads[i]) CloseHandle(threads[i]);
        io_failed |= !threads[i] || f->tasks[i].failed;
    }
    if (io_failed || !platform_directory_child_flush(&f->concurrent)) {
        platform_directory_child_close(&f->concurrent);
        return false;
    }
    platform_directory_child_close(&f->concurrent);
    if (!platform_directory_child_unlink(&f->directory, "concurrent", false))
        return false;
    return true;
}

static bool fixture_replace(struct directory_fixture *f)
{
    f->phase = "no-clobber and replacement";
    if (!platform_directory_child_create(&f->directory, "occupied", &f->occupied) ||
        !platform_directory_child_write(&f->occupied, "old", 3, 0) ||
        !platform_directory_child_flush(&f->occupied))
        return false;
    platform_directory_child_close(&f->occupied);
    if (!platform_directory_child_create(&f->directory, "beta.stage", &f->replacement) ||
        !platform_directory_child_write(&f->replacement, "new", 3, 0) ||
        !platform_directory_child_flush(&f->replacement) ||
        platform_directory_child_replace(&f->directory, &f->replacement,
                                          "occupied", true) ||
        !platform_directory_child_replace(&f->directory, &f->replacement,
                                           "occupied", false))
        return false;
    platform_directory_child_close(&f->replacement);
    return true;
}

static bool fixture_move_setup(struct directory_fixture *f)
{
    f->phase = "retained cross-directory move";
    f->detail = "create retained destination";
    if (platform_directory_transaction_open_child(
            &f->directory, "move-target", true, &f->move_destination) !=
        PLATFORM_DIRECTORY_OK)
        return false;
    platform_directory_transaction_close(&f->move_destination);
    if (snprintf(f->move_target_path, sizeof(f->move_target_path),
                 "%s/move-target", f->root) <= 0)
        return false;
    f->detail = "reopen top-level retained destination";
    if (!platform_directory_transaction_open(&f->move_destination,
                                             f->move_target_path))
        return false;
    f->detail = "create retained source";
    if (!platform_directory_child_create(&f->directory, "move.stage", &f->moved) ||
        !platform_directory_child_write_exact(&f->moved, "move-payload", 12, 0) ||
        !platform_directory_child_flush(&f->moved))
        return false;
    if (!platform_directory_child_info(&f->moved, &f->moved_before))
        return false;
    return true;
}

static bool fixture_move_verify(struct directory_fixture *f)
{
    struct platform_directory_child_info moved_after;
    f->detail = "invalid destination leaf refusal";
    if (platform_directory_child_move_between(
            &f->directory, &f->moved, &f->move_destination, "name:stream", true) !=
            PLATFORM_DIRECTORY_INVALID ||
        strcmp(f->moved.leaf, "move.stage") != 0)
        return false;
    f->detail = "no-clobber move";
    if (platform_directory_child_move_between(
            &f->directory, &f->moved, &f->move_destination, "move.final", true) !=
            PLATFORM_DIRECTORY_OK ||
        strcmp(f->moved.leaf, "move.final") != 0)
        return false;
    if (platform_directory_child_open_result(
            &f->directory, "move.stage", false, false, &f->move_probe, NULL) !=
            PLATFORM_DIRECTORY_MISSING ||
        !platform_directory_child_open(&f->move_destination, "move.final",
                                       &f->move_probe) ||
        !platform_directory_child_info(&f->move_probe, &moved_after) ||
        !same_identity(&f->moved_before, &moved_after))
        return false;
    platform_directory_child_close(&f->move_probe);
    return true;
}

static bool fixture_collision(struct directory_fixture *f)
{
    f->detail = "cross-directory no-clobber collision";
    if (!platform_directory_child_create(
            &f->move_destination, "collision.final", &f->collision_destination) ||
        !platform_directory_child_write_exact(
            &f->collision_destination, "old", 3, 0) ||
        !platform_directory_child_flush(&f->collision_destination))
        return false;
    platform_directory_child_close(&f->collision_destination);
    if (!platform_directory_child_create(
            &f->directory, "collision.stage", &f->collision_source) ||
        !platform_directory_child_write_exact(&f->collision_source, "new", 3, 0) ||
        !platform_directory_child_flush(&f->collision_source))
        return false;
    struct platform_directory_child_info collision_before, collision_after;
    if (!platform_directory_child_info(&f->collision_source, &collision_before) ||
        platform_directory_child_move_between(
            &f->directory, &f->collision_source, &f->move_destination,
            "collision.final", true) != PLATFORM_DIRECTORY_EXISTS ||
        strcmp(f->collision_source.leaf, "collision.stage") != 0)
        return false;
    f->detail = "cross-directory replacement";
    if (platform_directory_child_move_between(
            &f->directory, &f->collision_source, &f->move_destination,
            "collision.final", false) != PLATFORM_DIRECTORY_OK ||
        !platform_directory_child_open(
            &f->move_destination, "collision.final", &f->collision_destination) ||
        !platform_directory_child_info(
            &f->collision_destination, &collision_after) ||
        !same_identity(&collision_before, &collision_after))
        return false;
    platform_directory_child_close(&f->collision_destination);
    return true;
}

static bool fixture_durability(struct directory_fixture *f)
{
    f->detail = "post-rename durability ambiguity";
    if (!platform_directory_child_create(
            &f->directory, "unknown.stage", &f->unknown_move) ||
        !platform_directory_child_write_exact(&f->unknown_move, "unknown", 7, 0) ||
        !platform_directory_child_flush(&f->unknown_move))
        return false;
    struct platform_directory_child_info unknown_before, unknown_after;
    if (!platform_directory_child_info(&f->unknown_move, &unknown_before))
        return false;
    platform_directory_child_move_test_fail_durability_once();
    if (platform_directory_child_move_between(
            &f->directory, &f->unknown_move, &f->move_destination,
            "unknown.final", true) != PLATFORM_DIRECTORY_OUTCOME_UNKNOWN ||
        strcmp(f->unknown_move.leaf, "unknown.final") != 0 ||
        platform_directory_child_open_result(
            &f->directory, "unknown.stage", false, false, &f->move_probe, NULL) !=
            PLATFORM_DIRECTORY_MISSING ||
        !platform_directory_child_open(
            &f->move_destination, "unknown.final", &f->move_probe) ||
        !platform_directory_child_info(&f->move_probe, &unknown_after) ||
        !same_identity(&unknown_before, &unknown_after))
        return false;
    platform_directory_child_close(&f->move_probe);
    if (!platform_directory_transaction_flush(&f->move_destination) ||
        !platform_directory_transaction_flush(&f->directory))
        return false;
    return true;
}

static bool fixture_move_cleanup(struct directory_fixture *f)
{
    platform_directory_child_close(&f->moved);
    platform_directory_child_close(&f->collision_source);
    platform_directory_child_close(&f->unknown_move);
    if (!platform_directory_child_unlink(
            &f->move_destination, "move.final", false) ||
        !platform_directory_child_unlink(
            &f->move_destination, "collision.final", false) ||
        !platform_directory_child_unlink(
            &f->move_destination, "unknown.final", false))
        return false;
    platform_directory_transaction_close(&f->move_destination);
    if (!platform_private_directory_remove_empty(f->move_target_path))
        return false;
    return true;
}

static bool fixture_listing(struct directory_fixture *f)
{
    f->phase = "sorted regular listing";
    struct platform_directory_names names;
    if (!platform_directory_transaction_list_regular(&f->directory, &names))
        return false;
    bool sorted = names_are(&names, "alpha", "occupied");
    platform_directory_names_free(&names);
    if (!sorted) return false;
    return true;
}

static bool fixture_invalid_leaf(struct directory_fixture *f)
{
    f->phase = "invalid leaf rejection";
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
        if (platform_directory_child_create(&f->directory, leaf, &bad)) {
            platform_directory_child_close(&bad);
            return false;
        }
    }
    return true;
}

static bool fixture_reparse(struct directory_fixture *f)
{
    f->phase = "reparse child refusal";
    wchar_t alpha_path[MAX_PATH], link_path[MAX_PATH];
    if (swprintf(alpha_path, MAX_PATH, L"%ls\\alpha", f->root_wide) <= 0 ||
        swprintf(link_path, MAX_PATH, L"%ls\\alpha-link", f->root_wide) <= 0)
        return false;
    if (CreateSymbolicLinkW(link_path, alpha_path,
                            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        struct platform_directory_child link;
        platform_directory_child_init(&link);
        bool followed = platform_directory_child_open(&f->directory, "alpha-link",
                                                       &link);
        platform_directory_child_close(&link);
        DeleteFileW(link_path);
        if (followed) return false;
    }
    return true;
}

static bool fixture_non_file(struct directory_fixture *f)
{
    f->phase = "missing versus non-file refusal";
    wchar_t blocked[MAX_PATH];
    if (swprintf(blocked, MAX_PATH, L"%ls\\blocked", f->root_wide) <= 0 ||
        !CreateDirectoryW(blocked, NULL) ||
        platform_directory_child_unlink_result(&f->directory, "blocked") !=
            PLATFORM_DIRECTORY_REFUSED)
        return false;
    RemoveDirectoryW(blocked);
    return true;
}

static bool fixture_many(struct directory_fixture *f)
{
    f->phase = "multi-page sorted listing restart";
    enum { MANY_COUNT = 900 };
    for (unsigned i = 0; i < MANY_COUNT; i++) {
        char leaf[96];
        snprintf(leaf, sizeof(leaf),
                 "entry-%04u-abcdefghijklmnopqrstuvwxyz0123456789", i);
        struct platform_directory_child many;
        platform_directory_child_init(&many);
        if (!platform_directory_child_create(&f->directory, leaf, &many))
            return false;
        platform_directory_child_close(&many);
    }
    struct platform_directory_names first, second;
    if (!platform_directory_transaction_list_regular(&f->directory, &first) ||
        !platform_directory_transaction_list_regular(&f->directory, &second))
        return false;
    bool complete = first.count == MANY_COUNT + 2u &&
                    second.count == first.count;
    for (size_t i = 0; complete && i < first.count; i++) {
        complete = strcmp(first.items[i], second.items[i]) == 0 &&
                   (i == 0 || strcmp(first.items[i - 1], first.items[i]) < 0);
    }
    platform_directory_names_free(&second);
    platform_directory_names_free(&first);
    if (!complete) return false;
    for (unsigned i = 0; i < MANY_COUNT; i++) {
        char leaf[96];
        snprintf(leaf, sizeof(leaf),
                 "entry-%04u-abcdefghijklmnopqrstuvwxyz0123456789", i);
        if (!platform_directory_child_unlink(&f->directory, leaf, false))
            return false;
    }
    return true;
}

static bool fixture_flush(struct directory_fixture *f)
{
    f->phase = "flush and unlink";
    if (!platform_directory_transaction_flush(&f->directory) ||
        !platform_directory_child_unlink(&f->directory, "alpha", false) ||
        !platform_directory_child_unlink(&f->directory, "occupied", false) ||
        !platform_directory_child_unlink(&f->directory, "already-missing", true))
        return false;
    return true;
}

static int fixture_cleanup(struct directory_fixture *f, int result)
{
    platform_directory_child_close(&f->unknown_move);
    platform_directory_child_close(&f->collision_destination);
    platform_directory_child_close(&f->collision_source);
    platform_directory_child_close(&f->move_probe);
    platform_directory_child_close(&f->moved);
    platform_directory_child_close(&f->replacement);
    platform_directory_child_close(&f->occupied);
    platform_directory_child_close(&f->opened);
    platform_directory_child_close(&f->stage);
    if (f->move_destination.native != UINTPTR_MAX) {
        (void)platform_directory_child_unlink(
            &f->move_destination, "move.final", true);
        (void)platform_directory_child_unlink(
            &f->move_destination, "collision.final", true);
        (void)platform_directory_child_unlink(
            &f->move_destination, "unknown.final", true);
    }
    platform_directory_transaction_close(&f->move_destination);
    if (f->directory.native != UINTPTR_MAX) {
        (void)platform_directory_child_unlink(&f->directory, "alpha.stage", true);
        (void)platform_directory_child_unlink(&f->directory, "alpha", true);
        (void)platform_directory_child_unlink(&f->directory, "beta.stage", true);
        (void)platform_directory_child_unlink(&f->directory, "occupied", true);
        (void)platform_directory_child_unlink(&f->directory, "concurrent", true);
        (void)platform_directory_child_unlink(&f->directory, "exact", true);
        (void)platform_directory_child_unlink(&f->directory, "state.lock", true);
        (void)platform_directory_child_unlink(&f->directory, "move.stage", true);
        (void)platform_directory_child_unlink(
            &f->directory, "collision.stage", true);
        (void)platform_directory_child_unlink(
            &f->directory, "unknown.stage", true);
        for (unsigned i = 0; i < 900; i++) {
            char leaf[96];
            snprintf(leaf, sizeof(leaf),
                     "entry-%04u-abcdefghijklmnopqrstuvwxyz0123456789", i);
            (void)platform_directory_child_unlink(&f->directory, leaf, true);
        }
    }
    platform_directory_transaction_close(&f->directory);
    wchar_t blocked_cleanup[MAX_PATH];
    if (swprintf(blocked_cleanup, MAX_PATH, L"%ls\\blocked", f->root_wide) > 0)
        (void)RemoveDirectoryW(blocked_cleanup);
    wchar_t nested_cleanup[MAX_PATH];
    if (swprintf(nested_cleanup, MAX_PATH, L"%ls\\nested", f->root_wide) > 0)
        (void)RemoveDirectoryW(nested_cleanup);
    wchar_t move_target_cleanup[MAX_PATH];
    if (swprintf(move_target_cleanup, MAX_PATH, L"%ls\\move-target",
                 f->root_wide) > 0)
        (void)RemoveDirectoryW(move_target_cleanup);
    if (!platform_private_directory_remove_empty(f->root)) result = 1;
    if (result) {
        fprintf(stderr, "directory_transaction_acceptance detail: %s "
                        "winerr=%lu\n", f->detail,
                (unsigned long)GetLastError());
        return fail(f->phase);
    }
    puts("directory_transaction_acceptance: PASS");
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
    struct directory_fixture storage = { 0 };
    struct directory_fixture *f = &storage;
    wchar_t temp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(f->root_wide, MAX_PATH, L"%lsz23-dtxn-%lu-%llu", temp,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)GetTickCount64()) <= 0 ||
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, f->root_wide, -1,
                            f->root, sizeof(f->root), NULL, NULL) <= 0)
        return fail("private root create");
    if (!platform_private_directory_create(f->root)) {
        fputs("directory_transaction_acceptance: REFUSE: runtime cannot prove "
              "native SID/DACL semantics\n", stderr);
        return 77;
    }

    int result = 1;
    f->phase = "open";
    f->detail = "";
    platform_directory_transaction_init(&f->directory);
    platform_directory_transaction_init(&f->move_destination);
    platform_directory_child_init(&f->stage);
    platform_directory_child_init(&f->opened);
    platform_directory_child_init(&f->occupied);
    platform_directory_child_init(&f->replacement);
    platform_directory_child_init(&f->moved);
    platform_directory_child_init(&f->move_probe);
    platform_directory_child_init(&f->collision_source);
    platform_directory_child_init(&f->collision_destination);
    platform_directory_child_init(&f->unknown_move);
    if (!platform_directory_transaction_open(&f->directory, f->root))
        goto cleanup;

    static bool (*const phases[])(struct directory_fixture *) = {
        fixture_exact_io,
        fixture_nested,
        fixture_locking,
        fixture_publish_read,
        fixture_concurrent_io,
        fixture_replace,
        fixture_move_setup,
        fixture_move_verify,
        fixture_collision,
        fixture_durability,
        fixture_move_cleanup,
        fixture_listing,
        fixture_invalid_leaf,
        fixture_reparse,
        fixture_non_file,
        fixture_many,
        fixture_flush,
    };
    for (size_t i = 0; i < sizeof(phases) / sizeof(phases[0]); ++i)
        if (!phases[i](f))
            goto cleanup;
    result = 0;

cleanup:
    return fixture_cleanup(f, result);
}
#else
int main(void) { return 77; }
#endif
