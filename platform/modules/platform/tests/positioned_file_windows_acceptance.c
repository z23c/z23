/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless acceptance for concurrent, cursor-free positioned file reads. */
#include "platform/positioned_file.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>

struct read_task {
    const struct platform_positioned_file *file;
    uint64_t offset;
    char expected[9];
    int failed;
};

static DWORD WINAPI read_worker(void *opaque)
{
    struct read_task *task = opaque;
    for (unsigned i = 0; i < 1000; ++i) {
        char data[8];
        if (platform_positioned_file_read(task->file, data, sizeof(data),
                                          task->offset) != sizeof(data) ||
            memcmp(data, task->expected, sizeof(data)) != 0) {
            task->failed = 1;
            break;
        }
    }
    return 0;
}

/* Creates the temporary file and writes the fixed 32-byte pattern into it;
 * returns 0, or the exit code main should return. */
static int create_pattern_temp_file(wchar_t *path)
{
    wchar_t directory[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, directory) ||
        !GetTempFileNameW(directory, L"zpf", 0, path))
        return 1;
    HANDLE output = CreateFileW(path, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    const char bytes[] = "00000000111111112222222233333333";
    DWORD written = 0;
    if (output == INVALID_HANDLE_VALUE ||
        !WriteFile(output, bytes, sizeof(bytes) - 1, &written, NULL) ||
        written != sizeof(bytes) - 1) {
        if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
        DeleteFileW(path);
        return 2;
    }
    CloseHandle(output);
    return 0;
}

/* Opens the pattern file by UTF-8 path and verifies its size is 32 bytes,
 * deleting the file and returning 4 if that fails. */
static int open_pattern_file(struct platform_positioned_file *file,
                             const char *utf8_path, wchar_t *path)
{
    platform_positioned_file_init(file);
    uint64_t size = 0;
    if (!platform_positioned_file_open(file, utf8_path) ||
        !platform_positioned_file_size(file, &size) || size != 32) {
        platform_positioned_file_close(file);
        DeleteFileW(path);
        return 4;
    }
    return 0;
}

/* Runs the four reader threads plus the short and out-of-range reads;
 * returns nonzero when any of them fails. */
static int run_concurrent_reads(struct platform_positioned_file *file,
                                struct read_task *tasks)
{
    HANDLE threads[4];
    for (unsigned i = 0; i < 4; ++i)
        threads[i] = CreateThread(NULL, 0, read_worker, &tasks[i], 0, NULL);
    DWORD wait = WaitForMultipleObjects(4, threads, TRUE, 30000);
    int failed = wait != WAIT_OBJECT_0;
    for (unsigned i = 0; i < 4; ++i) {
        if (threads[i]) CloseHandle(threads[i]);
        failed |= tasks[i].failed;
    }
    char tail[8];
    failed |= platform_positioned_file_read(file, tail, sizeof(tail), 30) != 2;
    failed |= platform_positioned_file_read(file, tail, 1, UINT64_MAX) != -1;
    return failed;
}

/* Reopens the file beneath its directory and checks its snapshot; returns
 * the failed flag, or -1 after deleting the file when utf8_path has no
 * usable leaf. */
static int probe_open_beneath(struct platform_positioned_file *file,
                              const char *utf8_path, wchar_t *path)
{
    char root[MAX_PATH * 3];
    char *leaf = strrchr(utf8_path, '\\');
    if (!leaf) leaf = strrchr(utf8_path, '/');
    if (!leaf || (size_t)(leaf - utf8_path) >= sizeof(root)) {
        DeleteFileW(path);
        return -1;
    }
    memcpy(root, utf8_path, (size_t)(leaf - utf8_path));
    root[leaf - utf8_path] = '\0';
    int failed = !platform_positioned_file_open_beneath(file, root, leaf + 1);
    struct platform_positioned_file_snapshot snapshot;
    failed |= !platform_positioned_file_snapshot(file, &snapshot) ||
              snapshot.size != 32 || snapshot.file_low == 0;
    platform_positioned_file_close(file);
    return failed;
}

/* The same existing file spelled with forward slashes. Callers join
 * paths with '/' and plain Win32 rewrites those for them, but the \\?\
 * prefix the open path prepends turns every path parse OFF -- a
 * surviving '/' reaches the object manager as a filename character and
 * CreateFileW fails with ERROR_INVALID_NAME. UTF-8 is self-synchronising,
 * so no byte of a multi-byte sequence can be a backslash and this
 * byte-wise rewrite is safe. */
static int reopen_with_forward_slashes(const char *utf8_path)
{
    char utf8_forward[MAX_PATH * 3];
    for (size_t i = 0; i < sizeof(utf8_forward); i++) {
        utf8_forward[i] = utf8_path[i] == '\\' ? '/' : utf8_path[i];
        if (!utf8_path[i]) break;
    }
    struct platform_positioned_file forward;
    platform_positioned_file_init(&forward);
    uint64_t forward_size = 0;
    int failed = !platform_positioned_file_open(&forward, utf8_forward) ||
                 !platform_positioned_file_size(&forward, &forward_size) ||
                 forward_size != 32;
    platform_positioned_file_close(&forward);
    return failed;
}

int main(void)
{
    wchar_t path[MAX_PATH];
    char utf8_path[MAX_PATH * 3];
    int created = create_pattern_temp_file(path);
    if (created != 0) return created;
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1,
                             utf8_path, sizeof(utf8_path), NULL, NULL)) {
        DeleteFileW(path);
        return 3;
    }
    struct platform_positioned_file file;
    int opened = open_pattern_file(&file, utf8_path, path);
    if (opened != 0) return opened;
    /* Kept in main's frame so reader threads never outlive the task storage,
     * including after a wait timeout or failure. */
    struct read_task tasks[4] = {
        {&file, 0, "00000000", 0}, {&file, 8, "11111111", 0},
        {&file, 16, "22222222", 0}, {&file, 24, "33333333", 0}};
    int failed = run_concurrent_reads(&file, tasks);
    platform_positioned_file_close(&file);
    int beneath = probe_open_beneath(&file, utf8_path, path);
    if (beneath < 0) return 5;
    failed |= beneath;
    failed |= reopen_with_forward_slashes(utf8_path);
    DeleteFileW(path);
    if (failed) return 5;
    puts("positioned_file_acceptance: PASS");
    return 0;
}
#else
int main(void) { return 77; }
#endif
