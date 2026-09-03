/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verify shell-free hidden process lifecycle on Windows. */
#include "platform/process_lifecycle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static bool utf8(const wchar_t *wide, char *out, size_t out_size)
{
    int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                                     NULL, 0, NULL, NULL);
    return needed > 0 && (size_t)needed <= out_size &&
           WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, out,
                               (int)out_size, NULL, NULL) == needed;
}

static bool runtime_is_wine(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll && GetProcAddress(ntdll, "wine_get_version") != NULL;
}

static int tree_child_mode(void)
{
    Sleep(INFINITE);
    return 99;
}

static int tree_parent_mode(const char *handle_text)
{
    wchar_t image[32768], line[32768];
    if (!handle_text || !GetModuleFileNameW(NULL, image, 32768) ||
        swprintf(line, 32768, L"\"%ls\" --tree-child", image) <= 0)
        return 30;
    STARTUPINFOW startup = {.cb = sizeof(startup)};
    PROCESS_INFORMATION child = {0};
    if (!CreateProcessW(image, line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &child))
        return 31;
    DWORD child_pid = child.dwProcessId, written = 0;
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    HANDLE output = (HANDLE)(uintptr_t)_strtoui64(handle_text, NULL, 10);
    bool reported = WriteFile(output, &child_pid, sizeof(child_pid), &written,
                              NULL) && written == sizeof(child_pid);
    Sleep(250);
    return reported ? 0 : 32;
}

static int capture_child_mode(int argc, char **argv)
{
    BOOL in_job = FALSE;
    if (argc != 4 || !getenv("Z23_PROCESS_TEST") ||
        strcmp(getenv("Z23_PROCESS_TEST"), "controlled") != 0 ||
        getenv("Z23_PROCESS_UNEXPECTED") != NULL || GetConsoleWindow() != NULL ||
        !IsProcessInJob(GetCurrentProcess(), NULL, &in_job) || !in_job ||
        GetPriorityClass(GetCurrentProcess()) != BELOW_NORMAL_PRIORITY_CLASS)
        return 40;
    if (fputs(argv[2], stdout) < 0 || fflush(stdout) != 0) return 41;
    if (fputs(argv[3], stderr) < 0 || fflush(stderr) != 0) return 42;
    return 7;
}

static int capture_large_mode(void)
{
    for (size_t i = 0; i < 128u * 1024u; i++)
        if (fputc((int)('a' + (i % 26u)), stdout) == EOF) return 43;
    return fflush(stdout) == 0 ? 0 : 44;
}

static int capture_tree_mode(void)
{
    wchar_t image[32768], line[32768];
    if (!GetModuleFileNameW(NULL, image, 32768) ||
        swprintf(line, 32768, L"\"%ls\" --tree-child", image) <= 0)
        return 45;
    STARTUPINFOW startup = {.cb = sizeof(startup)};
    PROCESS_INFORMATION child = {0};
    if (!CreateProcessW(image, line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &child))
        return 46;
    DWORD child_pid = child.dwProcessId;
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    if (printf("%lu\n", (unsigned long)child_pid) < 0 || fflush(stdout) != 0)
        return 47;
    Sleep(INFINITE);
    return 48;
}

static int child_mode(int argc, char **argv)
{
    DWORD inherited_error_mode = GetErrorMode();
    BOOL in_job = FALSE;
    platform_process_child_prepare_headless();
    if (argc != 9 || strcmp(argv[2], "space value") != 0 ||
        strcmp(argv[3], "quote\"value") != 0 ||
        strcmp(argv[4], "trailing\\") != 0 ||
        !getenv("Z23_PROCESS_TEST") ||
        strcmp(getenv("Z23_PROCESS_TEST"), "controlled") != 0 ||
        getenv("Z23_PROCESS_UNEXPECTED") != NULL || GetConsoleWindow() != NULL ||
        !IsProcessInJob(GetCurrentProcess(), NULL, &in_job) || !in_job ||
        GetPriorityClass(GetCurrentProcess()) != BELOW_NORMAL_PRIORITY_CLASS ||
        (inherited_error_mode & (SEM_FAILCRITICALERRORS |
                                 SEM_NOGPFAULTERRORBOX |
                                 SEM_NOOPENFILEERRORBOX)) !=
            (SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
             SEM_NOOPENFILEERRORBOX))
        return 20;
    wchar_t image[32768], cwd[32768], expected_image[32768], expected_cwd[32768];
    if (!GetModuleFileNameW(NULL, image, 32768) ||
        !GetCurrentDirectoryW(32768, cwd) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[5], -1,
                             expected_image, 32768) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[6], -1,
                             expected_cwd, 32768) ||
        _wcsicmp(image, expected_image) != 0 ||
        _wcsicmp(cwd, expected_cwd) != 0)
        return 21;
    uintptr_t inherited = (uintptr_t)_strtoui64(argv[7], NULL, 10);
    DWORD flags = 0;
    if (GetHandleInformation((HANDLE)inherited, &flags) ||
        GetLastError() != ERROR_INVALID_HANDLE)
        return 22;
    HANDLE allowed = (HANDLE)(uintptr_t)_strtoui64(argv[8], NULL, 10);
    char capability[8] = {0}; DWORD received = 0;
    if (!GetHandleInformation(allowed, &flags) ||
        !ReadFile(allowed, capability, 7, &received, NULL) || received != 7 ||
        memcmp(capability, "allowed", 7) != 0)
        return 25;
    FILE *proof = fopen("process-lifecycle.proof", "wb");
    if (!proof) return 23;
    bool ok = fputs("ok\n", proof) >= 0 && fclose(proof) == 0;
    return ok ? 0 : 24;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--tree-child") == 0)
        return tree_child_mode();
    if (argc == 3 && strcmp(argv[1], "--tree-parent") == 0)
        return tree_parent_mode(argv[2]);
    if (argc > 1 && strcmp(argv[1], "--capture-child") == 0)
        return capture_child_mode(argc, argv);
    if (argc == 2 && strcmp(argv[1], "--capture-large") == 0)
        return capture_large_mode();
    if (argc == 2 && strcmp(argv[1], "--capture-tree") == 0)
        return capture_tree_mode();
    if (argc > 1 && strcmp(argv[1], "--child") == 0)
        return child_mode(argc, argv);
    wchar_t image_w[32768], temp_w[32768];
    if (!GetModuleFileNameW(NULL, image_w, 32768) ||
        !GetTempPathW(32768, temp_w)) return 1;
    size_t used = wcslen(temp_w);
    int written = swprintf(temp_w + used, 32768 - used,
                           L"z23-process-%lu", (unsigned long)GetCurrentProcessId());
    if (written <= 0 || !CreateDirectoryW(temp_w, NULL)) return 2;
    char image[32768], cwd[32768], handle_text[32], pipe_text[32];
    HANDLE inherited = CreateEventW(NULL, TRUE, FALSE, NULL);
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    HANDLE pipe_read = INVALID_HANDLE_VALUE, pipe_write = INVALID_HANDLE_VALUE;
    DWORD sent = 0;
    if (!CreatePipe(&pipe_read, &pipe_write, &security, 0) ||
        !SetHandleInformation(pipe_write, HANDLE_FLAG_INHERIT, 0) ||
        !WriteFile(pipe_write, "allowed", 7, &sent, NULL) || sent != 7)
        return 3;
    CloseHandle(pipe_write);
    if (!inherited || !SetHandleInformation(inherited, HANDLE_FLAG_INHERIT,
                                            HANDLE_FLAG_INHERIT) ||
        !utf8(image_w, image, sizeof(image)) || !utf8(temp_w, cwd, sizeof(cwd)))
        return 3;
    (void)snprintf(handle_text, sizeof(handle_text), "%llu",
                   (unsigned long long)(uintptr_t)inherited);
    (void)snprintf(pipe_text, sizeof(pipe_text), "%llu",
                   (unsigned long long)(uintptr_t)pipe_read);
    const char *const child_argv[] = {
        image, "--child", "space value", "quote\"value", "trailing\\",
        image, cwd, handle_text, pipe_text, NULL};
    const char *const child_env[] = {"Z23_PROCESS_TEST=controlled", NULL};
    const uintptr_t allowed_handles[] = {(uintptr_t)pipe_read};
    (void)SetEnvironmentVariableW(L"Z23_PROCESS_UNEXPECTED", L"inherited");
    struct platform_process process;
    platform_process_init(&process);
    struct platform_process_options options = {
        .image = image, .argv = child_argv, .cwd = cwd, .env = child_env,
        .inherited = allowed_handles, .inherited_count = 1};
    bool started = platform_process_start_hidden(&process, &options);
    uint32_t code = UINT32_MAX;
    enum platform_process_wait_result waited = started
        ? platform_process_wait(&process, 10000, &code)
        : PLATFORM_PROCESS_WAIT_FAILED;
    platform_process_close(&process);
    CloseHandle(inherited);
    CloseHandle(pipe_read);
    wchar_t proof[32768];
    (void)swprintf(proof, 32768, L"%ls\\process-lifecycle.proof", temp_w);
    DWORD attributes = GetFileAttributesW(proof);
    bool ok = waited == PLATFORM_PROCESS_WAIT_EXITED && code == 0 &&
              attributes != INVALID_FILE_ATTRIBUTES;

    char captured[128];
    struct platform_process_capture_result capture = {0};
    const char *const capture_argv[] = {
        image, "--capture-child", "space \"value\" trailing\\",
        "stderr-must-not-be-captured", NULL};
    struct platform_process_options capture_options = {
        .image = image, .argv = capture_argv, .cwd = cwd, .env = child_env};
    bool captured_ok = platform_process_capture_stdout(
        &capture_options, captured, sizeof(captured), 10000u, &capture) &&
        capture.exit_code == 7u && !capture.timed_out &&
        !capture.output_truncated &&
        strcmp(captured, "space \"value\" trailing\\") == 0 &&
        strstr(captured, "stderr") == NULL;

    const char *const empty_argv[] = {
        image, "--capture-child", "", "ignored", NULL};
    capture_options.argv = empty_argv;
    bool empty_ok = true;
    for (size_t i = 0; i < 64u && empty_ok; i++) {
        struct platform_process_capture_result empty = {0};
        empty_ok = platform_process_capture_stdout(
            &capture_options, captured, sizeof(captured), 10000u, &empty) &&
            empty.exit_code == 7u && !empty.timed_out &&
            !empty.output_truncated && captured[0] == '\0';
    }

    char boundary[8];
    struct platform_process_capture_result exact = {0}, truncated = {0};
    const char *const exact_argv[] = {
        image, "--capture-child", "1234567", "ignored", NULL};
    capture_options.argv = exact_argv;
    bool boundary_ok = platform_process_capture_stdout(
        &capture_options, boundary, sizeof(boundary), 10000u, &exact) &&
        exact.exit_code == 7u && !exact.output_truncated &&
        strcmp(boundary, "1234567") == 0;
    const char *const truncated_argv[] = {
        image, "--capture-child", "12345678", "ignored", NULL};
    capture_options.argv = truncated_argv;
    boundary_ok = boundary_ok && platform_process_capture_stdout(
        &capture_options, boundary, sizeof(boundary), 10000u, &truncated) &&
        truncated.exit_code == 7u && truncated.output_truncated &&
        strcmp(boundary, "1234567") == 0;

    char large[64];
    struct platform_process_capture_result large_result = {0};
    const char *const large_argv[] = {image, "--capture-large", NULL};
    capture_options.argv = large_argv;
    bool large_ok = platform_process_capture_stdout(
        &capture_options, large, sizeof(large), 10000u, &large_result) &&
        large_result.exit_code == 0u && !large_result.timed_out &&
        large_result.output_truncated && strlen(large) == sizeof(large) - 1u;

    char timed_output[64];
    struct platform_process_capture_result timed = {0};
    const char *const timed_argv[] = {image, "--capture-tree", NULL};
    capture_options.argv = timed_argv;
    bool timed_ok = platform_process_capture_stdout(
        &capture_options, timed_output, sizeof(timed_output), 100u, &timed) &&
        timed.timed_out && timed.exit_code == 124u;
    char *pid_end = NULL;
    unsigned long timed_pid = strtoul(timed_output, &pid_end, 10);
    HANDLE timed_child = timed_pid && timed_pid <= UINT32_MAX
        ? OpenProcess(SYNCHRONIZE, FALSE, (DWORD)timed_pid) : NULL;
    bool timed_tree_reaped = timed_ok && pid_end &&
        (*pid_end == '\n' || *pid_end == '\r') &&
        (!timed_child || WaitForSingleObject(timed_child, 2000) == WAIT_OBJECT_0);
    if (timed_child) CloseHandle(timed_child);

    char refused[8] = "dirty";
    struct platform_process_capture_result refused_result = {0};
    struct platform_process_options refused_options = capture_options;
    refused_options.image = "relative.exe";
    bool relative_refused = !platform_process_capture_stdout(
        &refused_options, refused, sizeof(refused), 100u, &refused_result) &&
        refused[0] == 0;
    refused_options.image = image;
    refused_options.cwd = ".";
    bool relative_cwd_refused = !platform_process_capture_stdout(
        &refused_options, refused, sizeof(refused), 100u, &refused_result) &&
        refused[0] == 0;
    ok = ok && captured_ok && empty_ok && boundary_ok && large_ok &&
         timed_tree_reaped && relative_refused && relative_cwd_refused;

    SECURITY_ATTRIBUTES tree_security = {
        .nLength = sizeof(tree_security), .bInheritHandle = TRUE};
    HANDLE tree_read = INVALID_HANDLE_VALUE, tree_write = INVALID_HANDLE_VALUE;
    DWORD tree_pid = 0, tree_bytes = 0;
    bool tree_pipe = CreatePipe(&tree_read, &tree_write, &tree_security, 0) &&
        SetHandleInformation(tree_read, HANDLE_FLAG_INHERIT, 0);
    char tree_handle[32];
    (void)snprintf(tree_handle, sizeof(tree_handle), "%llu",
                   (unsigned long long)(uintptr_t)tree_write);
    const char *const tree_argv[] = {
        image, "--tree-parent", tree_handle, NULL};
    const uintptr_t tree_handles[] = {(uintptr_t)tree_write};
    struct platform_process tree;
    platform_process_init(&tree);
    struct platform_process_options tree_options = {
        .image = image, .argv = tree_argv, .cwd = cwd, .env = child_env,
        .inherited = tree_handles, .inherited_count = 1};
    bool tree_started = tree_pipe &&
        platform_process_start_hidden(&tree, &tree_options);
    uint32_t tree_code = UINT32_MAX;
    enum platform_process_wait_result tree_waited = tree_started
        ? platform_process_wait(&tree, 10000, &tree_code)
        : PLATFORM_PROCESS_WAIT_FAILED;
    if (tree_write != INVALID_HANDLE_VALUE) CloseHandle(tree_write);
    bool tree_reported = tree_waited == PLATFORM_PROCESS_WAIT_EXITED &&
        tree_code == 0 && ReadFile(tree_read, &tree_pid, sizeof(tree_pid),
                                   &tree_bytes, NULL) &&
        tree_bytes == sizeof(tree_pid) && tree_pid != 0;
    HANDLE descendant = tree_reported
        ? OpenProcess(SYNCHRONIZE, FALSE, tree_pid) : NULL;
    platform_process_close(&tree); /* kill-on-close must reap the descendant */
    bool tree_reaped = descendant &&
        WaitForSingleObject(descendant, 2000) == WAIT_OBJECT_0;
    if (descendant) CloseHandle(descendant);
    if (tree_read != INVALID_HANDLE_VALUE) CloseHandle(tree_read);

    HANDLE detached_read = INVALID_HANDLE_VALUE;
    HANDLE detached_write = INVALID_HANDLE_VALUE;
    DWORD detached_pid = 0, detached_bytes = 0;
    bool detached_pipe =
        CreatePipe(&detached_read, &detached_write, &tree_security, 0) &&
        SetHandleInformation(detached_read, HANDLE_FLAG_INHERIT, 0);
    char detached_handle[32];
    (void)snprintf(detached_handle, sizeof(detached_handle), "%llu",
                   (unsigned long long)(uintptr_t)detached_write);
    const char *const detached_argv[] = {
        image, "--tree-parent", detached_handle, NULL};
    const uintptr_t detached_handles[] = {(uintptr_t)detached_write};
    struct platform_process detached;
    platform_process_init(&detached);
    struct platform_process_options detached_options = {
        .image = image, .argv = detached_argv, .cwd = cwd, .env = child_env,
        .inherited = detached_handles, .inherited_count = 1};
    bool detached_started = detached_pipe &&
        platform_process_start_hidden(&detached, &detached_options);
    uint64_t detached_parent_pid = detached.pid;
    if (detached_write != INVALID_HANDLE_VALUE) CloseHandle(detached_write);
    bool detached_reported = detached_started &&
        ReadFile(detached_read, &detached_pid, sizeof(detached_pid),
                 &detached_bytes, NULL) &&
        detached_bytes == sizeof(detached_pid) && detached_pid != 0;
    HANDLE detached_parent = detached_reported
        ? OpenProcess(SYNCHRONIZE, FALSE, (DWORD)detached_parent_pid) : NULL;
    HANDLE detached_descendant = detached_reported
        ? OpenProcess(SYNCHRONIZE, FALSE, detached_pid) : NULL;
    bool detached_released = detached_reported &&
        platform_process_detach(&detached);
    bool detached_parent_exited = detached_parent &&
        WaitForSingleObject(detached_parent, 2000) == WAIT_OBJECT_0;
    bool detached_tree_reaped = detached_descendant &&
        WaitForSingleObject(detached_descendant, 2000) == WAIT_OBJECT_0;
    if (detached_parent) CloseHandle(detached_parent);
    if (detached_descendant) CloseHandle(detached_descendant);
    if (detached_read != INVALID_HANDLE_VALUE) CloseHandle(detached_read);
    platform_process_close(&detached);
    ok = ok && tree_reported && tree_reaped && detached_released &&
        detached_parent_exited && detached_tree_reaped;
    (void)DeleteFileW(proof);
    (void)RemoveDirectoryW(temp_w);
    (void)SetEnvironmentVariableW(L"Z23_PROCESS_UNEXPECTED", NULL);
    if (!ok) {
        if (runtime_is_wine() && code == 22) {
            fputs("process-lifecycle-acceptance: REFUSE: Wine cannot prove "
                  "PROC_THREAD_ATTRIBUTE_HANDLE_LIST isolation\n", stderr);
            return 77;
        }
        fprintf(stderr,  // obs-ok:acceptance-failure-exits-synchronously
                "process lifecycle failed: started=%d wait=%d exit=%lu "
                "tree_started=%d tree_wait=%d tree_exit=%lu tree_reaped=%d "
                "detached_started=%d detached_released=%d "
                "detached_parent_exited=%d detached_tree_reaped=%d "
                "capture=%d empty=%d boundary=%d large=%d timed_tree=%d "
                "relative=%d relative_cwd=%d\n",
                started, (int)waited, (unsigned long)code, tree_started,
                (int)tree_waited, (unsigned long)tree_code, tree_reaped,
                detached_started, detached_released, detached_parent_exited,
                detached_tree_reaped, captured_ok, empty_ok, boundary_ok,
                large_ok, timed_tree_reaped, relative_refused,
                relative_cwd_refused);
        return 4;
    }
    puts("process-lifecycle-acceptance: ok");
    return 0;
}
#else
int main(void)
{
    puts("process-lifecycle-acceptance: skipped (non-Windows)");
    return 0;
}
#endif
