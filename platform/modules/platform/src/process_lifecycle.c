/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Implement shell-free hidden process lifecycle operations. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/process_lifecycle.h"
#include "platform/os_proc.h"
#include "process_lifecycle_internal.h"
#include "base/safe_alloc.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

void platform_process_init(struct platform_process *process)
{
    if (process)
        *process = (struct platform_process){UINTPTR_MAX, UINTPTR_MAX, 0};
}

/* A non-empty inherited list needs its pointer, and at most 64 entries. */
static bool process_inherited_shape_ok(
    const struct platform_process_options *options)
{
    return (!options->inherited_count || options->inherited) &&
           options->inherited_count <= 64u;
}

/* The request shape both launch arms refuse before touching any handle. */
static bool process_start_shape_ok(const struct platform_process *process,
                                   const struct platform_process_options *options)
{
    return process && process->native == UINTPTR_MAX && options &&
           options->image && options->argv && options->argv[0] &&
           options->env && process_inherited_shape_ok(options);
}

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

void platform_process_child_prepare_headless(void)
{
    (void)SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                       SEM_NOOPENFILEERRORBOX);
}

static bool utf16(const char *text, wchar_t **out)
{
    if (!text || !out) return false;
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1,
                                    NULL, 0);
    wchar_t *wide = count > 0
        ? zcl_malloc((size_t)count * sizeof(*wide), "process-utf16") : NULL;
    if (!wide || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1,
                                     wide, count) != count) {
        free(wide); return false;
    }
    *out = wide; return true;
}

static bool absolute_image(const wchar_t *path)
{
    if (!path || !path[0]) return false;
    return (path[0] && path[1] == L':' &&
            (path[2] == L'\\' || path[2] == L'/')) ||
           (path[0] == L'\\' && path[1] == L'\\');
}

static bool append_char(wchar_t **buffer, size_t *used, size_t *capacity,
                        wchar_t value)
{
    if (*used == *capacity) {
        size_t next = *capacity ? *capacity * 2u : 256u;
        if (next < *capacity || next > 32768u) return false;
        wchar_t *grown = zcl_realloc(
            *buffer, next * sizeof(**buffer), "process-command-line");
        if (!grown) return false;
        *buffer = grown; *capacity = next;
    }
    (*buffer)[(*used)++] = value; return true;
}

static bool append_backslashes(wchar_t **line, size_t *used, size_t *capacity,
                               size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (!append_char(line, used, capacity, L'\\')) return false;
    return true;
}

static bool append_arg_open(wchar_t **line, size_t *used, size_t *capacity,
                            const wchar_t *arg, bool *quote)
{
    if (*used && !append_char(line, used, capacity, L' ')) return false;
    *quote = !arg[0] || wcspbrk(arg, L" \t\n\v\"") != NULL;
    return !*quote || append_char(line, used, capacity, L'\"');
}

static bool append_arg_close(wchar_t **line, size_t *used, size_t *capacity,
                             bool quote)
{
    return (!quote || append_char(line, used, capacity, L'\"')) &&
           append_char(line, used, capacity, 0);
}

/* Implements CommandLineToArgvW's backslash-before-quote grammar. */
static bool append_arg(wchar_t **line, size_t *used, size_t *capacity,
                       const wchar_t *arg)
{
    bool quote = false;
    if (!append_arg_open(line, used, capacity, arg, &quote)) return false;
    size_t slashes = 0;
    for (const wchar_t *p = arg;; p++) {
        if (*p == L'\\') { slashes++; continue; }
        if (*p == L'\"') {
            if (!append_backslashes(line, used, capacity, slashes * 2u + 1u) ||
                !append_char(line, used, capacity, L'\"')) return false;
        } else {
            if (*p == 0 && quote) slashes *= 2u;
            if (!append_backslashes(line, used, capacity, slashes)) return false;
            if (*p == 0) break;
            if (!append_char(line, used, capacity, *p)) return false;
        }
        slashes = 0;
    }
    return append_arg_close(line, used, capacity, quote);
}

static wchar_t *command_line(const char *const *argv)
{
    if (!argv || !argv[0]) return NULL;
    wchar_t *line = NULL; size_t used = 0, capacity = 0;
    for (size_t i = 0; argv[i]; i++) {
        wchar_t *arg = NULL;
        if (!utf16(argv[i], &arg)) { free(line); return NULL; }
        if (used) used--; /* replace the preceding terminator */
        bool ok = append_arg(&line, &used, &capacity, arg);
        free(arg);
        if (!ok) { free(line); return NULL; }
    }
    return line;
}

static int env_compare(const void *a, const void *b)
{
    const wchar_t *const *left = a, *const *right = b;
    return _wcsicmp(*left, *right);
}

static bool environment_add_item(const char *entry, wchar_t **item,
                                 size_t *total)
{
    const char *equal = strchr(entry, '=');
    if (!equal || equal == entry || !utf16(entry, item)) return false;
    size_t length = wcslen(*item);
    if (length > 32766u || *total > 32767u - length - 1u) return false;
    *total += length + 1u;
    return true;
}

static void environment_free_items(wchar_t **items, size_t count)
{
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
}

static wchar_t *environment_block(const char *const *env)
{
    size_t count = 0;
    if (env) while (env[count]) count++;
    wchar_t **items = count
        ? zcl_calloc(count, sizeof(*items), "process-environment-items") : NULL;
    if (count && !items) return NULL;
    size_t total = 1;
    for (size_t i = 0; i < count; i++)
        if (!environment_add_item(env[i], &items[i], &total)) goto fail;
    qsort(items, count, sizeof(*items), env_compare);
    wchar_t *block = zcl_calloc(total + (count == 0), sizeof(*block),
                                "process-environment-block");
    if (!block) goto fail;
    size_t offset = 0;
    for (size_t i = 0; i < count; i++) {
        size_t length = wcslen(items[i]) + 1u;
        memcpy(block + offset, items[i], length * sizeof(*block));
        offset += length;
    }
    environment_free_items(items, count);
    return block;
fail:
    environment_free_items(items, count);
    return NULL;
}

static bool process_inheritable_handle(HANDLE handle)
{
    DWORD flags = 0;
    return GetHandleInformation(handle, &flags) &&
           (flags & HANDLE_FLAG_INHERIT);
}

static bool process_stdio_handles(HANDLE *handles, HANDLE stdout_handle,
                                  HANDLE stdin_handle, bool capture_stdout,
                                  bool file_stdin)
{
    bool ok = true;
    if (capture_stdout) {
        handles[1] = stdout_handle;
        ok = process_inheritable_handle(stdout_handle);
    }
    if (file_stdin) {
        handles[1u + (size_t)capture_stdout] = stdin_handle;
        ok = ok && stdin_handle != stdout_handle &&
             process_inheritable_handle(stdin_handle);
    }
    return ok;
}

static bool process_real_handle(HANDLE handle)
{
    return handle && handle != INVALID_HANDLE_VALUE;
}

static bool process_inherited_handles(HANDLE *handles,
                                      const struct platform_process_options *options,
                                      size_t first, HANDLE stdout_handle,
                                      HANDLE stdin_handle, bool ok)
{
    for (size_t i = 0; i < options->inherited_count; i++) {
        DWORD flags = 0;
        handles[first + i] = (HANDLE)options->inherited[i];
        if (handles[first + i] == stdout_handle ||
            handles[first + i] == stdin_handle ||
            !GetHandleInformation(handles[first + i], &flags) ||
            !(flags & HANDLE_FLAG_INHERIT)) ok = false;
        for (size_t j = 0; j < i; j++)
            if (options->inherited[i] == options->inherited[j]) ok = false;
    }
    return ok;
}

static bool process_startup_attributes(STARTUPINFOEXW *startup,
                                       HANDLE *handles, size_t handle_count,
                                       bool handles_ok)
{
    SIZE_T attribute_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    startup->lpAttributeList = zcl_malloc(attribute_size,
                                          "process-attribute-list");
    return handles_ok && startup->lpAttributeList &&
           InitializeProcThreadAttributeList(startup->lpAttributeList, 1, 0,
                                             &attribute_size) &&
           UpdateProcThreadAttribute(startup->lpAttributeList, 0,
               PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles,
               handle_count * sizeof(*handles), NULL, NULL);
}

static bool process_job_configure(HANDLE job)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PRIORITY_CLASS;
    limits.BasicLimitInformation.PriorityClass = BELOW_NORMAL_PRIORITY_CLASS;
    return job && SetInformationJobObject(
        job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
}

static void process_settle_launch(struct platform_process *process,
                                  HANDLE job,
                                  const PROCESS_INFORMATION *information,
                                  bool started, bool resumed)
{
    if (resumed) {
        CloseHandle(information->hThread);
        process->native = (uintptr_t)information->hProcess;
        process->containment = (uintptr_t)job;
        process->pid = information->dwProcessId;
        return;
    }
    if (started) {
        CloseHandle(information->hThread);
        CloseHandle(information->hProcess);
    }
    if (job) CloseHandle(job);
}

static bool process_start_strings(
    const struct platform_process_options *options, wchar_t **image,
    wchar_t **cwd, wchar_t **line, wchar_t **environment)
{
    *line = command_line(options->argv);
    *environment = environment_block(options->env);
    return utf16(options->image, image) && absolute_image(*image) && *line &&
           (!options->cwd ||
            (utf16(options->cwd, cwd) && absolute_image(*cwd))) &&
           *environment;
}

static bool process_start_hidden_with_stdout(
    struct platform_process *process,
    const struct platform_process_options *options, HANDLE stdout_handle,
    HANDLE stdin_handle)
{
    if (!process_start_shape_ok(process, options)) return false;
    wchar_t *image = NULL, *cwd = NULL, *line = NULL, *environment = NULL;
    if (!process_start_strings(options, &image, &cwd, &line, &environment))
        goto done;
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    HANDLE null_handle = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, NULL);
    if (null_handle == INVALID_HANDLE_VALUE) goto done;
    bool capture_stdout = process_real_handle(stdout_handle);
    bool file_stdin = process_real_handle(stdin_handle);
    size_t handle_count = options->inherited_count + 1u + (size_t)file_stdin +
                          (size_t)capture_stdout;
    HANDLE *handles = zcl_calloc(handle_count, sizeof(*handles),
                                 "process-inherited-handles");
    if (!handles) { CloseHandle(null_handle); goto done; }
    handles[0] = null_handle;
    bool handles_ok = process_stdio_handles(handles, stdout_handle,
                                            stdin_handle, capture_stdout,
                                            file_stdin);
    handles_ok = process_inherited_handles(
        handles, options, 1u + (size_t)capture_stdout + (size_t)file_stdin,
        stdout_handle, stdin_handle, handles_ok);
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.StartupInfo.hStdInput = file_stdin ? stdin_handle : null_handle;
    startup.StartupInfo.hStdOutput = capture_stdout ? stdout_handle : null_handle;
    startup.StartupInfo.hStdError = null_handle;
    if (!process_startup_attributes(&startup, handles, handle_count,
                                    handles_ok)) {
        free(startup.lpAttributeList); free(handles); CloseHandle(null_handle);
        goto done;
    }
    HANDLE job = CreateJobObjectW(NULL, NULL);
    bool job_ok = process_job_configure(job);
    PROCESS_INFORMATION information = {0};
    UINT previous_mode = SetErrorMode(
        SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
        SEM_NOOPENFILEERRORBOX);
    DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED |
                  BELOW_NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT |
                  EXTENDED_STARTUPINFO_PRESENT;
    bool started = job_ok && CreateProcessW(
        image, line, NULL, NULL, TRUE, flags, environment, cwd,
        &startup.StartupInfo, &information) != 0;
    bool assigned = started &&
        AssignProcessToJobObject(job, information.hProcess) != 0;
    bool resumed = assigned &&
        ResumeThread(information.hThread) != (DWORD)-1;
    (void)SetErrorMode(previous_mode);
    if (started && !resumed)
        (void)TerminateProcess(information.hProcess, 125u);
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList); free(handles); CloseHandle(null_handle);
    process_settle_launch(process, job, &information, started, resumed);
done:
    free(image); free(cwd); free(line); free(environment);
    return process->native != UINTPTR_MAX;
}

bool platform_process_start_hidden(struct platform_process *process,
                                   const struct platform_process_options *options)
{
    return process_start_hidden_with_stdout(process, options, NULL, NULL);
}

/* process_lifecycle_internal.h: the confined launch reuses these exact
 * encoders so both launch paths quote and pass environments identically. */
wchar_t *platform_process_windows_utf16(const char *text)
{
    wchar_t *wide = NULL;
    return utf16(text, &wide) ? wide : NULL;
}

wchar_t *platform_process_windows_command_line(const char *const *argv)
{
    return command_line(argv);
}

wchar_t *platform_process_windows_environment(const char *const *env)
{
    return environment_block(env);
}

bool platform_process_windows_absolute(const wchar_t *path)
{
    return absolute_image(path);
}

bool platform_process_open_existing(struct platform_process *process,
                                    uint64_t pid, const char *expected_image)
{
    if (!process || process->native != UINTPTR_MAX || pid == 0 ||
        pid > UINT32_MAX || !expected_image) return false;
    wchar_t *expected = NULL;
    if (!utf16(expected_image, &expected)) return false;
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                SYNCHRONIZE | PROCESS_TERMINATE,
                                FALSE, (DWORD)pid);
    wchar_t actual[32768]; DWORD count = 32768;
    bool ok = handle && QueryFullProcessImageNameW(handle, 0, actual, &count) &&
              _wcsicmp(actual, expected) == 0;
    free(expected);
    if (!ok) { if (handle) CloseHandle(handle); return false; }
    process->native = (uintptr_t)handle; process->pid = pid; return true;
}

enum platform_process_wait_result platform_process_wait(
    struct platform_process *process, uint32_t timeout_ms, uint32_t *exit_code)
{
    if (!process || process->native == UINTPTR_MAX) return PLATFORM_PROCESS_WAIT_FAILED;
    DWORD waited = WaitForSingleObject((HANDLE)process->native, timeout_ms);
    if (waited == WAIT_TIMEOUT) return PLATFORM_PROCESS_WAIT_RUNNING;
    DWORD code = 0;
    if (waited != WAIT_OBJECT_0 || !GetExitCodeProcess((HANDLE)process->native,
                                                       &code))
        return PLATFORM_PROCESS_WAIT_FAILED;
    if (exit_code) *exit_code = code;
    return PLATFORM_PROCESS_WAIT_EXITED;
}

bool platform_process_terminate(struct platform_process *process,
                                uint32_t exit_code)
{
    if (!process || process->native == UINTPTR_MAX) return false;
    if (process->containment != UINTPTR_MAX)
        return TerminateJobObject((HANDLE)process->containment, exit_code) != 0;
    return TerminateProcess((HANDLE)process->native, exit_code) != 0;
}

void platform_process_close(struct platform_process *process)
{
    if (!process || process->native == UINTPTR_MAX) return;
    CloseHandle((HANDLE)process->native);
    if (process->containment != UINTPTR_MAX)
        CloseHandle((HANDLE)process->containment);
    platform_process_init(process);
}

#else
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;

void platform_process_child_prepare_headless(void)
{
    (void)signal(SIGPIPE, SIG_IGN);
}

static bool fd_allowed(int fd, const struct platform_process_options *options)
{
    for (size_t i = 0; i < options->inherited_count; i++)
        if (options->inherited[i] <= INT_MAX &&
            fd == (int)options->inherited[i]) return true;
    return false;
}

static bool process_inherited_fds_ok(
    const struct platform_process_options *options)
{
    for (size_t i = 0; i < options->inherited_count; i++) {
        if (options->inherited[i] > INT_MAX || options->inherited[i] <= 2u ||
            fcntl((int)options->inherited[i], F_GETFD) < 0) return false;
        for (size_t j = 0; j < i; j++)
            if (options->inherited[j] == options->inherited[i]) return false;
    }
    return true;
}

/* Runs in the forked child: detaches stdio onto /dev/null, exiting 126 on
 * any failure. */
static void process_child_null_stdio(void)
{
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 ||
        dup2(null_fd, STDOUT_FILENO) < 0 ||
        dup2(null_fd, STDERR_FILENO) < 0) _exit(126);
    if (null_fd > STDERR_FILENO) close(null_fd);
}

/* Runs in the forked child: only the inherited descriptors stay open. */
static void process_child_prepare_fds(
    const struct platform_process_options *options)
{
    for (size_t i = 0; i < options->inherited_count; i++) {
        int fd = (int)options->inherited[i];
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) != 0)
            _exit(126);
    }
    long limit = sysconf(_SC_OPEN_MAX);
    if (limit < 0) limit = 65536;
    for (int fd = 3; fd < limit; fd++)
        if (!fd_allowed(fd, options)) (void)close(fd);
}

bool platform_process_start_hidden(struct platform_process *process,
                                   const struct platform_process_options *options)
{
    if (!process_start_shape_ok(process, options) || options->image[0] != '/' ||
        !process_inherited_fds_ok(options)) return false;
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (setsid() < 0 || (options->cwd && chdir(options->cwd) != 0))
            _exit(126);
        process_child_null_stdio();
        process_child_prepare_fds(options);
        execve(options->image, (char *const *)options->argv,
               (char *const *)options->env);
        _exit(127);
    }
    process->native = (uintptr_t)pid; process->pid = (uint64_t)pid; return true;
}

bool platform_process_open_existing(struct platform_process *process,
                                    uint64_t pid, const char *expected_image)
{
    char actual[PATH_MAX];
    if (!process || process->native != UINTPTR_MAX || pid <= 1 ||
        !expected_image || !os_proc_pid_exe_path(pid, actual, sizeof(actual)) ||
        strcmp(actual, expected_image) != 0) return false;
    process->native = (uintptr_t)pid; process->pid = pid; return true;
}

enum platform_process_wait_result platform_process_wait(
    struct platform_process *process, uint32_t timeout_ms, uint32_t *exit_code)
{
    if (!process || process->native == UINTPTR_MAX) return PLATFORM_PROCESS_WAIT_FAILED;
    uint32_t elapsed = 0;
    for (;;) {
        int status = 0; pid_t result = waitpid((pid_t)process->native, &status, WNOHANG);
        if (result == (pid_t)process->native) {
            if (exit_code) *exit_code = WIFEXITED(status) ? (uint32_t)WEXITSTATUS(status)
                                                         : 128u + (uint32_t)WTERMSIG(status);
            return PLATFORM_PROCESS_WAIT_EXITED;
        }
        if (result < 0) return PLATFORM_PROCESS_WAIT_FAILED;
        if (elapsed >= timeout_ms) return PLATFORM_PROCESS_WAIT_RUNNING;
        struct timespec delay = {.tv_nsec = 1000000};
        (void)nanosleep(&delay, NULL); elapsed++;
    }
}

bool platform_process_terminate(struct platform_process *process,
                                uint32_t exit_code)
{
    (void)exit_code;
    return process && process->native != UINTPTR_MAX &&
           kill((pid_t)process->native, SIGTERM) == 0;
}

void platform_process_close(struct platform_process *process)
{
    if (process) platform_process_init(process);
}
#endif

/* platform_process_capture_stdout() and platform_process_detach() are
 * declared once in process_lifecycle.h and called from other translation
 * units, so each keeps exactly one non-static definition; the platform
 * difference is folded into the body instead of duplicated per arm. */
/* Clears the caller's buffer and result, then reports whether the capture
 * request has a buffer, a timeout and a result to fill. */
static bool process_capture_begin(
    const struct platform_process_options *options, char *out, size_t out_size,
    uint32_t timeout_ms, struct platform_process_capture_result *result)
{
    if (out && out_size) out[0] = 0;
    if (result)
        *result = (struct platform_process_capture_result){0};
    return options && out && out_size != 0 && timeout_ms != 0 && result;
}

#if defined(_WIN32)
static bool process_capture_pipe(HANDLE *read_handle, HANDLE *write_handle)
{
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    *read_handle = NULL;
    *write_handle = NULL;
    if (CreatePipe(read_handle, write_handle, &security, 0) &&
        SetHandleInformation(*read_handle, HANDLE_FLAG_INHERIT, 0)) return true;
    if (*read_handle) CloseHandle(*read_handle);
    if (*write_handle) CloseHandle(*write_handle);
    return false;
}

/* Reads at most `available` bytes: into the free tail of out while room
 * remains, otherwise into a discard buffer that marks the output truncated. */
static bool process_pipe_read(HANDLE read_handle, char *out, size_t out_size,
                              size_t *used, DWORD available, DWORD *received,
                              struct platform_process_capture_result *result)
{
    char discard[4096];
    size_t room = *used + 1u < out_size ? out_size - *used - 1u : 0u;
    char *destination = room ? out + *used : discard;
    DWORD capacity = room
        ? (room > UINT32_MAX ? UINT32_MAX : (DWORD)room)
        : (DWORD)sizeof(discard);
    DWORD wanted = available < capacity ? available : capacity;
    *received = 0;
    if (!ReadFile(read_handle, destination, wanted, received, NULL) ||
        *received == 0) return false;
    if (room)
        *used += *received;
    else
        result->output_truncated = true;
    return true;
}

static bool process_capture_read_available(
    HANDLE read_handle, char *out, size_t out_size, size_t *used,
    DWORD *available, struct platform_process_capture_result *result)
{
    while (*available > 0) {
        DWORD received = 0;
        if (!process_pipe_read(read_handle, out, out_size, used, *available,
                               &received, result)) return false;
        *available -= received;
    }
    return true;
}

/* A closed pipe is recorded and leaves no bytes to read. */
static bool process_capture_peek(HANDLE read_handle, bool *pipe_closed,
                                 DWORD *available)
{
    *available = 0;
    if (*pipe_closed ||
        PeekNamedPipe(read_handle, NULL, 0, NULL, available, NULL)) return true;
    if (GetLastError() != ERROR_BROKEN_PIPE) return false;
    *pipe_closed = true;
    return true;
}

static void process_capture_stop_containment(struct platform_process *process,
                                             uint32_t exit_code, bool *stopped)
{
    if (*stopped || process->containment == UINTPTR_MAX) return;
    (void)TerminateJobObject((HANDLE)process->containment, exit_code);
    *stopped = true;
}

static bool process_capture_expire(struct platform_process *process,
                                   struct platform_process_capture_result *result)
{
    result->timed_out = true;
    result->exit_code = 124u;
    bool terminated = platform_process_terminate(process, 124u);
    return platform_process_wait(process, 5000u, NULL) ==
               PLATFORM_PROCESS_WAIT_EXITED && terminated;
}

static void process_capture_reap(struct platform_process *process,
                                 bool exited)
{
    if (!exited) (void)platform_process_terminate(process, 125u);
    (void)platform_process_wait(process, 5000u, NULL);
    platform_process_close(process);
}

static bool process_capture_drain(HANDLE read_handle, char *out,
                                  size_t out_size, size_t *used,
                                  struct platform_process_capture_result *result)
{
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_handle, NULL, 0, NULL, &available, NULL) ||
            available == 0) return true;
        DWORD received = 0;
        if (!process_pipe_read(read_handle, out, out_size, used, available,
                               &received, result)) return false;
    }
}
#endif

static bool process_capture_stdout_stdio(
    const struct platform_process_options *options, char *out, size_t out_size,
    uint32_t timeout_ms, struct platform_process_capture_result *result,
    uintptr_t stdin_native)
{
#if defined(_WIN32)
    if (!process_capture_begin(options, out, out_size, timeout_ms, result))
        return false;

    HANDLE read_handle = NULL, write_handle = NULL;
    if (!process_capture_pipe(&read_handle, &write_handle)) return false;

    struct platform_process process;
    platform_process_init(&process);
    bool started = process_start_hidden_with_stdout(
        &process, options, write_handle, (HANDLE)stdin_native);
    CloseHandle(write_handle);
    write_handle = NULL;
    if (!started) {
        CloseHandle(read_handle);
        return false;
    }

    ULONGLONG began = GetTickCount64();
    size_t used = 0;
    bool ok = true, exited = false, containment_stopped = false;
    bool pipe_closed = false;
    for (;;) {
        DWORD available = 0;
        if (!process_capture_peek(read_handle, &pipe_closed, &available) ||
            !process_capture_read_available(read_handle, out, out_size, &used,
                                            &available, result)) {
            ok = false;
            break;
        }

        uint32_t exit_code = 0;
        enum platform_process_wait_result waited =
            platform_process_wait(&process, 0, &exit_code);
        if (waited == PLATFORM_PROCESS_WAIT_FAILED) {
            ok = false;
            break;
        }
        if (waited == PLATFORM_PROCESS_WAIT_EXITED) {
            exited = true;
            result->exit_code = exit_code;
            /* A trusted query has no authority to leave helpers behind. Stop
             * any process that retained the pipe, then drain bytes already
             * committed by the primary process. */
            process_capture_stop_containment(&process, exit_code,
                                             &containment_stopped);
            if (available == 0 && pipe_closed)
                break;
        }

        ULONGLONG now = GetTickCount64();
        if (now - began >= timeout_ms) {
            ok = process_capture_expire(&process, result) && ok;
            exited = true;
            break;
        }
        if (available == 0) Sleep(1u);
    }
    out[used] = 0;

    /* Closing containment is the final fail-closed cleanup even after a pipe
     * or wait failure. Bytes already in the pipe are drained once more so a
     * short-lived child cannot lose its final write between signal and poll. */
    process_capture_reap(&process, exited);
    ok = process_capture_drain(read_handle, out, out_size, &used, result) && ok;
    out[used] = 0;
    CloseHandle(read_handle);
    return ok;
#else
    (void)process_capture_begin(options, out, out_size, timeout_ms, result);
    (void)stdin_native;
    return false;
#endif
}

bool platform_process_capture_stdout(
    const struct platform_process_options *options, char *out, size_t out_size,
    uint32_t timeout_ms, struct platform_process_capture_result *result)
{
    return process_capture_stdout_stdio(options, out, out_size, timeout_ms,
                                         result, 0);
}

#if defined(_WIN32)
static HANDLE process_open_stdin_file(const char *stdin_path)
{
    wchar_t *wide = NULL;
    if (!utf16(stdin_path, &wide)) return INVALID_HANDLE_VALUE;
    bool absolute = absolute_image(wide) && wide[1] == L':';
    if (!absolute) { free(wide); return INVALID_HANDLE_VALUE; }
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    HANDLE input = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ, &security,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wide);
    return input;
}

static bool process_stdin_file_regular(HANDLE input)
{
    BY_HANDLE_FILE_INFORMATION info = {0};
    return GetFileType(input) == FILE_TYPE_DISK &&
        GetFileInformationByHandle(input, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                  FILE_ATTRIBUTE_REPARSE_POINT)) &&
        info.nFileSizeHigh == 0 &&
        info.nFileSizeLow <= PLATFORM_PROCESS_CAPTURE_STDIN_MAX;
}
#endif

bool platform_process_capture_stdout_file_input(
    const struct platform_process_options *options, const char *stdin_path,
    char *out, size_t out_size, uint32_t timeout_ms,
    struct platform_process_capture_result *result)
{
    if (out && out_size) out[0] = 0;
    if (result) *result = (struct platform_process_capture_result){0};
#if defined(_WIN32)
    if (!options || !stdin_path || !out || out_size == 0 ||
        timeout_ms == 0 || !result) return false;
    HANDLE input = process_open_stdin_file(stdin_path);
    if (input == INVALID_HANDLE_VALUE) return false;
    bool ok = process_stdin_file_regular(input) && process_capture_stdout_stdio(options, out, out_size,
        timeout_ms, result, (uintptr_t)input);
    CloseHandle(input);
    return ok;
#else
    (void)options; (void)stdin_path; (void)timeout_ms;
    return false;
#endif
}
bool platform_process_detach(struct platform_process *process)
{
#if defined(_WIN32)
    if (!process || process->native == UINTPTR_MAX) return false;
    if (process->containment != UINTPTR_MAX) {
        HANDLE remote_job = NULL;
        if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)process->containment,
                             (HANDLE)process->native, &remote_job, 0, FALSE,
                             DUPLICATE_SAME_ACCESS))
            return false;
    }
    CloseHandle((HANDLE)process->native);
    if (process->containment != UINTPTR_MAX)
        CloseHandle((HANDLE)process->containment);
    platform_process_init(process);
    return true;
#else
    if (!process || process->native == UINTPTR_MAX) return false;
    platform_process_init(process);
    return true;
#endif
}
