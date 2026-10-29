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

static bool child_mode_args_ok(int argc, char **argv)
{
    return argc == 9 && strcmp(argv[2], "space value") == 0 &&
           strcmp(argv[3], "quote\"value") == 0 &&
           strcmp(argv[4], "trailing\\") == 0;
}

static bool child_mode_env_ok(DWORD inherited_error_mode)
{
    BOOL in_job = FALSE;
    return getenv("Z23_PROCESS_TEST") != NULL &&
           strcmp(getenv("Z23_PROCESS_TEST"), "controlled") == 0 &&
           getenv("Z23_PROCESS_UNEXPECTED") == NULL &&
           GetConsoleWindow() == NULL &&
           IsProcessInJob(GetCurrentProcess(), NULL, &in_job) && in_job &&
           GetPriorityClass(GetCurrentProcess()) == BELOW_NORMAL_PRIORITY_CLASS &&
           (inherited_error_mode & (SEM_FAILCRITICALERRORS |
                                    SEM_NOGPFAULTERRORBOX |
                                    SEM_NOOPENFILEERRORBOX)) ==
               (SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                SEM_NOOPENFILEERRORBOX);
}

static bool child_mode_paths_ok(char **argv)
{
    wchar_t image[32768], cwd[32768], expected_image[32768], expected_cwd[32768];
    return GetModuleFileNameW(NULL, image, 32768) &&
           GetCurrentDirectoryW(32768, cwd) &&
           MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[5], -1,
                               expected_image, 32768) &&
           MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[6], -1,
                               expected_cwd, 32768) &&
           _wcsicmp(image, expected_image) == 0 &&
           _wcsicmp(cwd, expected_cwd) == 0;
}

static bool child_mode_capability_ok(const char *text)
{
    HANDLE allowed = (HANDLE)(uintptr_t)_strtoui64(text, NULL, 10);
    char capability[8] = {0};
    DWORD flags = 0, received = 0;
    return GetHandleInformation(allowed, &flags) &&
           ReadFile(allowed, capability, 7, &received, NULL) && received == 7 &&
           memcmp(capability, "allowed", 7) == 0;
}

static int child_mode(int argc, char **argv)
{
    DWORD inherited_error_mode = GetErrorMode();
    platform_process_child_prepare_headless();
    if (!child_mode_args_ok(argc, argv) ||
        !child_mode_env_ok(inherited_error_mode))
        return 20;
    if (!child_mode_paths_ok(argv)) return 21;
    uintptr_t inherited = (uintptr_t)_strtoui64(argv[7], NULL, 10);
    DWORD flags = 0;
    if (GetHandleInformation((HANDLE)inherited, &flags) ||
        GetLastError() != ERROR_INVALID_HANDLE)
        return 22;
    if (!child_mode_capability_ok(argv[8])) return 25;
    FILE *proof = fopen("process-lifecycle.proof", "wb");
    if (!proof) return 23;
    bool ok = fputs("ok\n", proof) >= 0 && fclose(proof) == 0;
    return ok ? 0 : 24;
}


/* File-input cases use this driver's trusted self image and private fixture. */

static int capture_file_stdin_child(void)
{
    BOOL in_job = FALSE;
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleWindow() != NULL || !getenv("Z23_PROCESS_TEST") ||
        strcmp(getenv("Z23_PROCESS_TEST"), "controlled") != 0 ||
        !IsProcessInJob(GetCurrentProcess(), NULL, &in_job) || !in_job ||
        GetPriorityClass(GetCurrentProcess()) != BELOW_NORMAL_PRIORITY_CLASS ||
        GetFileType(input) != FILE_TYPE_DISK)
        return 60;
    DWORD written = 0;
    /* The child receives no write authority over its input fixture. */
    if (WriteFile(input, "x", 1, &written, NULL)) return 61;
    char bytes[4096];
    for (;;) {
        DWORD received = 0;
        if (!ReadFile(input, bytes, sizeof(bytes), &received, NULL)) return 62;
        if (received == 0) break;
        if (!WriteFile(output, bytes, received, &written, NULL) ||
            written != received) return 63;
    }
    return 7;
}

static bool capture_file_stdin_write(const char *path, const char *bytes,
                                      size_t length)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool written = fwrite(bytes, 1, length, file) == length;
    int closed = fclose(file);
    return written && closed == 0;
}

static bool capture_file_stdin_exact(const struct platform_process_options *options,
                                     const char *path, const char *bytes,
                                     size_t length)
{
    char output[65537];
    struct platform_process_capture_result result = {0};
    return capture_file_stdin_write(path, bytes, length) &&
        platform_process_capture_stdout_file_input(options, path, output,
            sizeof(output), 1000u, &result) && result.exit_code == 7u &&
        !result.timed_out && !result.output_truncated &&
        strlen(output) == length && memcmp(output, bytes, length) == 0;
}

static bool capture_file_stdin_oversized(const struct platform_process_options *options,
                                         const char *path, const char *payload,
                                         size_t length)
{
    char output[65537];
    struct platform_process_capture_result result = {0};
    DWORD handles_before = 0, handles_after = 0;
    bool measured = GetProcessHandleCount(GetCurrentProcess(), &handles_before);
    bool oversized = capture_file_stdin_write(path, payload, length);
    for (size_t i = 0; i < 16u; i++) {
        oversized = oversized && !platform_process_capture_stdout_file_input(
            options, path, output, sizeof(output), 1000u, &result);
    }
    measured = measured && GetProcessHandleCount(GetCurrentProcess(), &handles_after);
    return oversized && measured && handles_before == handles_after;
}

static bool capture_file_stdin_refusals(const struct platform_process_options *options,
                                        const char *input_path, const char *missing_path)
{
    char output[65537];
    struct platform_process_capture_result result = {0};
    bool ok = !platform_process_capture_stdout_file_input(options,
        "relative.in", output, sizeof(output), 1000u, &result);
    ok = ok && !platform_process_capture_stdout_file_input(options,
        missing_path, output, sizeof(output), 1000u, &result);
    ok = ok && !platform_process_capture_stdout_file_input(options,
        options->cwd, output, sizeof(output), 1000u, &result);
    struct platform_process_options bad = *options;
    bad.image = "relative.exe";
    ok = ok && !platform_process_capture_stdout_file_input(&bad,
        input_path, output, sizeof(output), 1000u, &result);
    return ok && !platform_process_capture_stdout_file_input(options,
        input_path, output, sizeof(output), 0u, &result);
}

static bool capture_file_stdin_timeout(const struct platform_process_options *options,
                                       const char *input_path)
{
    char output[65537];
    struct platform_process_capture_result result = {0};
    const char *const sleep_argv[] = {options->image, "--tree-child", NULL};
    struct platform_process_options sleeping = *options;
    sleeping.argv = sleep_argv;
    return platform_process_capture_stdout_file_input(&sleeping,
        input_path, output, sizeof(output), 100u, &result) && result.timed_out;
}

static bool capture_file_stdin_paths(const char *cwd, char input_path[32768],
                                     char missing_path[32768])
{
    int n = snprintf(input_path, 32768, "%s/capture-stdin.in", cwd);
    if (n <= 0 || n >= 32768) return false;
    n = snprintf(missing_path, 32768, "%s/capture-stdin-missing.in", cwd);
    return n > 0 && n < 32768;
}

static bool capture_file_stdin_cases(const char *image, const char *cwd,
                                     const char *const *env)
{
    char input_path[32768], missing_path[32768];
    static char payload[PLATFORM_PROCESS_CAPTURE_STDIN_MAX + 1u];
    if (!capture_file_stdin_paths(cwd, input_path, missing_path)) return false;
    const char *const argv[] = {image, "--capture-file-stdin", NULL};
    struct platform_process_options options = {
        .image = image, .argv = argv, .cwd = cwd, .env = env};
    const char document[] = "{\"a\":1,\"b\":{\"x\":2}}\n";
    memset(payload, 'a', sizeof(payload));
    bool ok = capture_file_stdin_exact(&options, input_path, document, sizeof(document)-1u) &&
        capture_file_stdin_exact(&options, input_path, "", 0) &&
        capture_file_stdin_exact(&options, input_path, payload, PLATFORM_PROCESS_CAPTURE_STDIN_MAX) &&
        capture_file_stdin_oversized(&options, input_path, payload, sizeof(payload)) &&
        capture_file_stdin_write(input_path, document, sizeof(document)-1u) &&
        capture_file_stdin_refusals(&options, input_path, missing_path) &&
        capture_file_stdin_timeout(&options, input_path);
    /* Reopening for exclusive write and removing the file checks that the
     * parent and child have released the read-only stdin handle. */
    FILE *exclusive = fopen(input_path, "wb");
    bool released = exclusive != NULL;
    if (exclusive && fclose(exclusive) != 0) released = false;
    bool removed = remove(input_path) == 0;
    return ok && released && removed;
}

static int capture_mode(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--capture-file-stdin") == 0)
        return capture_file_stdin_child();
    if (argc > 1 && strcmp(argv[1], "--capture-child") == 0)
        return capture_child_mode(argc, argv);
    if (argc == 2 && strcmp(argv[1], "--capture-large") == 0)
        return capture_large_mode();
    if (argc == 2 && strcmp(argv[1], "--capture-tree") == 0)
        return capture_tree_mode();
    return -1;
}

static const char *const child_mode_env[] = {"Z23_PROCESS_TEST=controlled", NULL};

struct child_mode_session {
    wchar_t image_w[32768];
    wchar_t temp_w[32768];
    wchar_t proof[32768];
    char image[32768];
    char cwd[32768];
    char handle_text[32];
    char pipe_text[32];
    char captured[128];
    HANDLE inherited;
    HANDLE pipe_read;
    bool started;
    enum platform_process_wait_result waited;
    uint32_t code;
    bool tree_started;
    enum platform_process_wait_result tree_waited;
    uint32_t tree_code;
    bool tree_reported;
    bool tree_reaped;
    bool detached_started;
    bool detached_released;
    bool detached_parent_exited;
    bool detached_tree_reaped;
    bool captured_ok;
    bool empty_ok;
    bool boundary_ok;
    bool large_ok;
    bool timed_tree_reaped;
    bool relative_refused;
    bool relative_cwd_refused;
    bool ok;
};

static int child_mode_make_temp_dir(struct child_mode_session *s)
{
    if (!GetModuleFileNameW(NULL, s->image_w, 32768) ||
        !GetTempPathW(32768, s->temp_w)) return 1;
    size_t used = wcslen(s->temp_w);
    int written = swprintf(s->temp_w + used, 32768 - used,
                           L"z23-process-%lu", (unsigned long)GetCurrentProcessId());
    if (written <= 0 || !CreateDirectoryW(s->temp_w, NULL)) return 2;
    return 0;
}

static int child_mode_open_handles(struct child_mode_session *s)
{
    s->inherited = CreateEventW(NULL, TRUE, FALSE, NULL);
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    HANDLE pipe_write = INVALID_HANDLE_VALUE;
    DWORD sent = 0;
    s->pipe_read = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&s->pipe_read, &pipe_write, &security, 0) ||
        !SetHandleInformation(pipe_write, HANDLE_FLAG_INHERIT, 0) ||
        !WriteFile(pipe_write, "allowed", 7, &sent, NULL) || sent != 7)
        return 3;
    CloseHandle(pipe_write);
    if (!s->inherited || !SetHandleInformation(s->inherited, HANDLE_FLAG_INHERIT,
                                               HANDLE_FLAG_INHERIT) ||
        !utf8(s->image_w, s->image, sizeof(s->image)) ||
        !utf8(s->temp_w, s->cwd, sizeof(s->cwd)))
        return 3;
    (void)snprintf(s->handle_text, sizeof(s->handle_text), "%llu",
                   (unsigned long long)(uintptr_t)s->inherited);
    (void)snprintf(s->pipe_text, sizeof(s->pipe_text), "%llu",
                   (unsigned long long)(uintptr_t)s->pipe_read);
    return 0;
}

static int child_mode_prepare(struct child_mode_session *s)
{
    int status = child_mode_make_temp_dir(s);
    return status != 0 ? status : child_mode_open_handles(s);
}

static void child_mode_run_hidden(struct child_mode_session *s)
{
    const char *const child_argv[] = {
        s->image, "--child", "space value", "quote\"value", "trailing\\",
        s->image, s->cwd, s->handle_text, s->pipe_text, NULL};
    const uintptr_t allowed_handles[] = {(uintptr_t)s->pipe_read};
    (void)SetEnvironmentVariableW(L"Z23_PROCESS_UNEXPECTED", L"inherited");
    struct platform_process process;
    platform_process_init(&process);
    struct platform_process_options options = {
        .image = s->image, .argv = child_argv, .cwd = s->cwd,
        .env = child_mode_env, .inherited = allowed_handles,
        .inherited_count = 1};
    s->started = platform_process_start_hidden(&process, &options);
    s->code = UINT32_MAX;
    s->waited = s->started
        ? platform_process_wait(&process, 10000, &s->code)
        : PLATFORM_PROCESS_WAIT_FAILED;
    platform_process_close(&process);
    CloseHandle(s->inherited);
    CloseHandle(s->pipe_read);
    (void)swprintf(s->proof, 32768, L"%ls\\process-lifecycle.proof", s->temp_w);
    DWORD attributes = GetFileAttributesW(s->proof);
    s->ok = s->waited == PLATFORM_PROCESS_WAIT_EXITED && s->code == 0 &&
            attributes != INVALID_FILE_ATTRIBUTES;
}

static struct platform_process_options child_mode_capture_options(
    const struct child_mode_session *s, const char *const *argv)
{
    struct platform_process_options options = {
        .image = s->image, .argv = argv, .cwd = s->cwd, .env = child_mode_env};
    return options;
}

static bool child_mode_capture_stdout(struct child_mode_session *s)
{
    const char *const capture_argv[] = {
        s->image, "--capture-child", "space \"value\" trailing\\",
        "stderr-must-not-be-captured", NULL};
    struct platform_process_options options =
        child_mode_capture_options(s, capture_argv);
    struct platform_process_capture_result capture = {0};
    return platform_process_capture_stdout(
        &options, s->captured, sizeof(s->captured), 10000u, &capture) &&
        capture.exit_code == 7u && !capture.timed_out &&
        !capture.output_truncated &&
        strcmp(s->captured, "space \"value\" trailing\\") == 0 &&
        strstr(s->captured, "stderr") == NULL;
}

static bool child_mode_capture_empty(struct child_mode_session *s)
{
    const char *const empty_argv[] = {
        s->image, "--capture-child", "", "ignored", NULL};
    struct platform_process_options options =
        child_mode_capture_options(s, empty_argv);
    bool empty_ok = true;
    for (size_t i = 0; i < 64u && empty_ok; i++) {
        struct platform_process_capture_result empty = {0};
        empty_ok = platform_process_capture_stdout(
            &options, s->captured, sizeof(s->captured), 10000u, &empty) &&
            empty.exit_code == 7u && !empty.timed_out &&
            !empty.output_truncated && s->captured[0] == '\0';
    }
    return empty_ok;
}

static bool child_mode_capture_boundary(struct child_mode_session *s)
{
    char boundary[8];
    struct platform_process_capture_result exact = {0}, truncated = {0};
    const char *const exact_argv[] = {
        s->image, "--capture-child", "1234567", "ignored", NULL};
    struct platform_process_options options =
        child_mode_capture_options(s, exact_argv);
    bool boundary_ok = platform_process_capture_stdout(
        &options, boundary, sizeof(boundary), 10000u, &exact) &&
        exact.exit_code == 7u && !exact.output_truncated &&
        strcmp(boundary, "1234567") == 0;
    const char *const truncated_argv[] = {
        s->image, "--capture-child", "12345678", "ignored", NULL};
    options.argv = truncated_argv;
    boundary_ok = boundary_ok && platform_process_capture_stdout(
        &options, boundary, sizeof(boundary), 10000u, &truncated) &&
        truncated.exit_code == 7u && truncated.output_truncated &&
        strcmp(boundary, "1234567") == 0;
    return boundary_ok;
}

static bool child_mode_capture_large(struct child_mode_session *s)
{
    char large[64];
    struct platform_process_capture_result large_result = {0};
    const char *const large_argv[] = {s->image, "--capture-large", NULL};
    struct platform_process_options options =
        child_mode_capture_options(s, large_argv);
    return platform_process_capture_stdout(
        &options, large, sizeof(large), 10000u, &large_result) &&
        large_result.exit_code == 0u && !large_result.timed_out &&
        large_result.output_truncated && strlen(large) == sizeof(large) - 1u;
}

static bool child_mode_capture_timed(struct child_mode_session *s)
{
    char timed_output[64];
    struct platform_process_capture_result timed = {0};
    const char *const timed_argv[] = {s->image, "--capture-tree", NULL};
    struct platform_process_options options =
        child_mode_capture_options(s, timed_argv);
    bool timed_ok = platform_process_capture_stdout(
        &options, timed_output, sizeof(timed_output), 100u, &timed) &&
        timed.timed_out && timed.exit_code == 124u;
    char *pid_end = NULL;
    unsigned long timed_pid = strtoul(timed_output, &pid_end, 10);
    HANDLE timed_child = timed_pid && timed_pid <= UINT32_MAX
        ? OpenProcess(SYNCHRONIZE, FALSE, (DWORD)timed_pid) : NULL;
    bool timed_tree_reaped = timed_ok && pid_end &&
        (*pid_end == '\n' || *pid_end == '\r') &&
        (!timed_child || WaitForSingleObject(timed_child, 2000) == WAIT_OBJECT_0);
    if (timed_child) CloseHandle(timed_child);
    return timed_tree_reaped;
}

static void child_mode_capture_refused(struct child_mode_session *s)
{
    const char *const timed_argv[] = {s->image, "--capture-tree", NULL};
    char refused[8] = "dirty";
    struct platform_process_capture_result refused_result = {0};
    struct platform_process_options refused_options =
        child_mode_capture_options(s, timed_argv);
    refused_options.image = "relative.exe";
    s->relative_refused = !platform_process_capture_stdout(
        &refused_options, refused, sizeof(refused), 100u, &refused_result) &&
        refused[0] == 0;
    refused_options.image = s->image;
    refused_options.cwd = ".";
    s->relative_cwd_refused = !platform_process_capture_stdout(
        &refused_options, refused, sizeof(refused), 100u, &refused_result) &&
        refused[0] == 0;
}

static void child_mode_capture_checks(struct child_mode_session *s)
{
    s->captured_ok = child_mode_capture_stdout(s);
    s->empty_ok = child_mode_capture_empty(s);
    s->boundary_ok = child_mode_capture_boundary(s);
    s->large_ok = child_mode_capture_large(s);
    s->timed_tree_reaped = child_mode_capture_timed(s);
    child_mode_capture_refused(s);
}

static bool child_mode_capture_ok(const struct child_mode_session *s)
{
    return s->captured_ok && s->empty_ok && s->boundary_ok && s->large_ok &&
           s->timed_tree_reaped && s->relative_refused &&
           s->relative_cwd_refused;
}

static bool child_mode_wait_reaped(HANDLE handle)
{
    return handle && WaitForSingleObject(handle, 2000) == WAIT_OBJECT_0;
}

static void child_mode_tree_reap(struct child_mode_session *s)
{
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
        s->image, "--tree-parent", tree_handle, NULL};
    const uintptr_t tree_handles[] = {(uintptr_t)tree_write};
    struct platform_process tree;
    platform_process_init(&tree);
    struct platform_process_options tree_options = {
        .image = s->image, .argv = tree_argv, .cwd = s->cwd,
        .env = child_mode_env, .inherited = tree_handles, .inherited_count = 1};
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
    bool tree_reaped = child_mode_wait_reaped(descendant);
    if (descendant) CloseHandle(descendant);
    if (tree_read != INVALID_HANDLE_VALUE) CloseHandle(tree_read);
    s->tree_started = tree_started;
    s->tree_waited = tree_waited;
    s->tree_code = tree_code;
    s->tree_reported = tree_reported;
    s->tree_reaped = tree_reaped;
}

static void child_mode_detached_check(struct child_mode_session *s)
{
    SECURITY_ATTRIBUTES detached_security = {
        .nLength = sizeof(detached_security), .bInheritHandle = TRUE};
    HANDLE detached_read = INVALID_HANDLE_VALUE;
    HANDLE detached_write = INVALID_HANDLE_VALUE;
    DWORD detached_pid = 0, detached_bytes = 0;
    bool detached_pipe =
        CreatePipe(&detached_read, &detached_write, &detached_security, 0) &&
        SetHandleInformation(detached_read, HANDLE_FLAG_INHERIT, 0);
    char detached_handle[32];
    (void)snprintf(detached_handle, sizeof(detached_handle), "%llu",
                   (unsigned long long)(uintptr_t)detached_write);
    const char *const detached_argv[] = {
        s->image, "--tree-parent", detached_handle, NULL};
    const uintptr_t detached_handles[] = {(uintptr_t)detached_write};
    struct platform_process detached;
    platform_process_init(&detached);
    struct platform_process_options detached_options = {
        .image = s->image, .argv = detached_argv, .cwd = s->cwd,
        .env = child_mode_env, .inherited = detached_handles,
        .inherited_count = 1};
    s->detached_started = detached_pipe &&
        platform_process_start_hidden(&detached, &detached_options);
    uint64_t detached_parent_pid = detached.pid;
    if (detached_write != INVALID_HANDLE_VALUE) CloseHandle(detached_write);
    bool detached_reported = s->detached_started &&
        ReadFile(detached_read, &detached_pid, sizeof(detached_pid),
                 &detached_bytes, NULL) &&
        detached_bytes == sizeof(detached_pid) && detached_pid != 0;
    HANDLE detached_parent = detached_reported
        ? OpenProcess(SYNCHRONIZE, FALSE, (DWORD)detached_parent_pid) : NULL;
    HANDLE detached_descendant = detached_reported
        ? OpenProcess(SYNCHRONIZE, FALSE, detached_pid) : NULL;
    s->detached_released = detached_reported && platform_process_detach(&detached);
    s->detached_parent_exited = child_mode_wait_reaped(detached_parent);
    s->detached_tree_reaped = child_mode_wait_reaped(detached_descendant);
    if (detached_parent) CloseHandle(detached_parent);
    if (detached_descendant) CloseHandle(detached_descendant);
    if (detached_read != INVALID_HANDLE_VALUE) CloseHandle(detached_read);
    platform_process_close(&detached);
}

static bool child_mode_tree_ok(const struct child_mode_session *s)
{
    return s->tree_reported && s->tree_reaped && s->detached_released &&
           s->detached_parent_exited && s->detached_tree_reaped;
}

static void child_mode_run_checks(struct child_mode_session *s)
{
    child_mode_run_hidden(s);
    child_mode_capture_checks(s);
    s->ok = s->ok && child_mode_capture_ok(s);
    child_mode_tree_reap(s);
    child_mode_detached_check(s);
    s->ok = s->ok && child_mode_tree_ok(s);
    s->ok = s->ok && capture_file_stdin_cases(s->image, s->cwd, child_mode_env);
    (void)DeleteFileW(s->proof);
    (void)RemoveDirectoryW(s->temp_w);
    (void)SetEnvironmentVariableW(L"Z23_PROCESS_UNEXPECTED", NULL);
}

int main(int argc, char **argv)
{
    int capture_code = capture_mode(argc, argv);
    if (capture_code >= 0) return capture_code;
    if (argc == 2 && strcmp(argv[1], "--tree-child") == 0)
        return tree_child_mode();
    if (argc == 3 && strcmp(argv[1], "--tree-parent") == 0)
        return tree_parent_mode(argv[2]);
    if (argc > 1 && strcmp(argv[1], "--child") == 0)
        return child_mode(argc, argv);
    struct child_mode_session s = {0};
    int setup = child_mode_prepare(&s);
    if (setup != 0) return setup;
    child_mode_run_checks(&s);
    if (!s.ok) {
        if (runtime_is_wine() && s.code == 22) {
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
                s.started, (int)s.waited, (unsigned long)s.code,
                s.tree_started, (int)s.tree_waited, (unsigned long)s.tree_code,
                s.tree_reaped, s.detached_started, s.detached_released,
                s.detached_parent_exited, s.detached_tree_reaped,
                s.captured_ok, s.empty_ok, s.boundary_ok, s.large_ok,
                s.timed_tree_reaped, s.relative_refused, s.relative_cwd_refused);
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
