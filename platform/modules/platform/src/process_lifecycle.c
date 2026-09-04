/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Implement shell-free hidden process lifecycle operations. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/process_lifecycle.h"
#include "platform/os_proc.h"
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

/* Implements CommandLineToArgvW's backslash-before-quote grammar. */
static bool append_arg(wchar_t **line, size_t *used, size_t *capacity,
                       const wchar_t *arg)
{
    if (*used && !append_char(line, used, capacity, L' ')) return false;
    bool quote = !arg[0] || wcspbrk(arg, L" \t\n\v\"") != NULL;
    if (quote && !append_char(line, used, capacity, L'\"')) return false;
    size_t slashes = 0;
    for (const wchar_t *p = arg;; p++) {
        if (*p == L'\\') { slashes++; continue; }
        if (*p == L'\"') {
            for (size_t i = 0; i < slashes * 2u + 1u; i++)
                if (!append_char(line, used, capacity, L'\\')) return false;
            if (!append_char(line, used, capacity, L'\"')) return false;
        } else {
            if (*p == 0 && quote) slashes *= 2u;
            for (size_t i = 0; i < slashes; i++)
                if (!append_char(line, used, capacity, L'\\')) return false;
            if (*p == 0) break;
            if (!append_char(line, used, capacity, *p)) return false;
        }
        slashes = 0;
    }
    return (!quote || append_char(line, used, capacity, L'\"')) &&
           append_char(line, used, capacity, 0);
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

static wchar_t *environment_block(const char *const *env)
{
    size_t count = 0;
    if (env) while (env[count]) count++;
    wchar_t **items = count
        ? zcl_calloc(count, sizeof(*items), "process-environment-items") : NULL;
    if (count && !items) return NULL;
    size_t total = 1;
    for (size_t i = 0; i < count; i++) {
        const char *equal = strchr(env[i], '=');
        if (!equal || equal == env[i] || !utf16(env[i], &items[i])) goto fail;
        size_t length = wcslen(items[i]);
        if (length > 32766u || total > 32767u - length - 1u) goto fail;
        total += length + 1u;
    }
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
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items); return block;
fail:
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items); return NULL;
}

static bool process_start_hidden_with_stdout(
    struct platform_process *process,
    const struct platform_process_options *options, HANDLE stdout_handle)
{
    if (!process || process->native != UINTPTR_MAX || !options ||
        !options->image || !options->argv || !options->argv[0] || !options->env ||
        (options->inherited_count && !options->inherited) ||
        options->inherited_count > 64u) return false;
    wchar_t *image = NULL, *cwd = NULL;
    wchar_t *line = command_line(options->argv);
    wchar_t *environment = environment_block(options->env);
    if (!utf16(options->image, &image) || !absolute_image(image) || !line ||
        (options->cwd &&
         (!utf16(options->cwd, &cwd) || !absolute_image(cwd))) ||
        !environment) goto done;
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    HANDLE null_handle = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, NULL);
    if (null_handle == INVALID_HANDLE_VALUE) goto done;
    bool capture_stdout = stdout_handle && stdout_handle != INVALID_HANDLE_VALUE;
    size_t handle_count = options->inherited_count + 1u +
                          (capture_stdout ? 1u : 0u);
    HANDLE *handles = zcl_calloc(handle_count, sizeof(*handles),
                                 "process-inherited-handles");
    if (!handles) { CloseHandle(null_handle); goto done; }
    handles[0] = null_handle;
    bool handles_ok = true;
    if (capture_stdout) {
        DWORD flags = 0;
        handles[1] = stdout_handle;
        if (!GetHandleInformation(stdout_handle, &flags) ||
            !(flags & HANDLE_FLAG_INHERIT))
            handles_ok = false;
    }
    for (size_t i = 0; i < options->inherited_count; i++) {
        DWORD flags = 0;
        size_t at = i + 1u + (capture_stdout ? 1u : 0u);
        handles[at] = (HANDLE)options->inherited[i];
        if (handles[at] == stdout_handle ||
            !GetHandleInformation(handles[at], &flags) ||
            !(flags & HANDLE_FLAG_INHERIT)) handles_ok = false;
        for (size_t j = 0; j < i; j++)
            if (options->inherited[i] == options->inherited[j])
                handles_ok = false;
    }
    SIZE_T attribute_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.StartupInfo.hStdInput = null_handle;
    startup.StartupInfo.hStdOutput = capture_stdout ? stdout_handle : null_handle;
    startup.StartupInfo.hStdError = null_handle;
    startup.lpAttributeList = zcl_malloc(attribute_size,
                                         "process-attribute-list");
    if (!handles_ok || !startup.lpAttributeList ||
        !InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0,
                                           &attribute_size) ||
        !UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles,
            handle_count * sizeof(*handles), NULL, NULL)) {
        free(startup.lpAttributeList); free(handles); CloseHandle(null_handle);
        goto done;
    }
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PRIORITY_CLASS;
    limits.BasicLimitInformation.PriorityClass = BELOW_NORMAL_PRIORITY_CLASS;
    bool job_ok = job && SetInformationJobObject(
        job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
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
    if (resumed) {
        CloseHandle(information.hThread);
        process->native = (uintptr_t)information.hProcess;
        process->containment = (uintptr_t)job;
        process->pid = information.dwProcessId;
    } else {
        if (started) {
            CloseHandle(information.hThread);
            CloseHandle(information.hProcess);
        }
        if (job) CloseHandle(job);
    }
done:
    free(image); free(cwd); free(line); free(environment);
    return process->native != UINTPTR_MAX;
}

bool platform_process_start_hidden(struct platform_process *process,
                                   const struct platform_process_options *options)
{
    return process_start_hidden_with_stdout(process, options, NULL);
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

bool platform_process_start_hidden(struct platform_process *process,
                                   const struct platform_process_options *options)
{
    if (!process || process->native != UINTPTR_MAX || !options ||
        !options->image || options->image[0] != '/' || !options->argv ||
        !options->argv[0] || !options->env ||
        (options->inherited_count && !options->inherited) ||
        options->inherited_count > 64u) return false;
    for (size_t i = 0; i < options->inherited_count; i++) {
        if (options->inherited[i] > INT_MAX || options->inherited[i] <= 2u ||
            fcntl((int)options->inherited[i], F_GETFD) < 0) return false;
        for (size_t j = 0; j < i; j++)
            if (options->inherited[j] == options->inherited[i]) return false;
    }
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (setsid() < 0 || (options->cwd && chdir(options->cwd) != 0))
            _exit(126);
        int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 ||
            dup2(null_fd, STDOUT_FILENO) < 0 ||
            dup2(null_fd, STDERR_FILENO) < 0) _exit(126);
        if (null_fd > STDERR_FILENO) close(null_fd);
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
bool platform_process_capture_stdout(
    const struct platform_process_options *options, char *out, size_t out_size,
    uint32_t timeout_ms, struct platform_process_capture_result *result)
{
#if defined(_WIN32)
    if (out && out_size) out[0] = 0;
    if (result)
        *result = (struct platform_process_capture_result){0};
    if (!options || !out || out_size == 0 || timeout_ms == 0 || !result)
        return false;

    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    HANDLE read_handle = NULL, write_handle = NULL;
    if (!CreatePipe(&read_handle, &write_handle, &security, 0) ||
        !SetHandleInformation(read_handle, HANDLE_FLAG_INHERIT, 0)) {
        if (read_handle) CloseHandle(read_handle);
        if (write_handle) CloseHandle(write_handle);
        return false;
    }

    struct platform_process process;
    platform_process_init(&process);
    bool started = process_start_hidden_with_stdout(
        &process, options, write_handle);
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
        if (!pipe_closed &&
            !PeekNamedPipe(read_handle, NULL, 0, NULL, &available, NULL)) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE)
                pipe_closed = true;
            else {
                ok = false;
                break;
            }
        }
        while (available > 0) {
            char discard[4096];
            size_t room = used + 1u < out_size ? out_size - used - 1u : 0u;
            char *destination = room ? out + used : discard;
            DWORD capacity = room
                ? (room > UINT32_MAX ? UINT32_MAX : (DWORD)room)
                : (DWORD)sizeof(discard);
            DWORD wanted = available < capacity ? available : capacity;
            DWORD received = 0;
            if (!ReadFile(read_handle, destination, wanted, &received, NULL) ||
                received == 0) {
                ok = false;
                break;
            }
            if (room)
                used += received;
            else
                result->output_truncated = true;
            available -= received;
        }
        if (!ok) break;

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
            if (!containment_stopped && process.containment != UINTPTR_MAX) {
                (void)TerminateJobObject((HANDLE)process.containment,
                                         exit_code);
                containment_stopped = true;
            }
            if (available == 0 && pipe_closed)
                break;
        }

        ULONGLONG now = GetTickCount64();
        if (now - began >= timeout_ms) {
            result->timed_out = true;
            result->exit_code = 124u;
            if (!platform_process_terminate(&process, 124u)) ok = false;
            if (platform_process_wait(&process, 5000u, NULL) !=
                PLATFORM_PROCESS_WAIT_EXITED)
                ok = false;
            exited = true;
            break;
        }
        if (available == 0) Sleep(1u);
    }
    out[used] = 0;

    /* Closing containment is the final fail-closed cleanup even after a pipe
     * or wait failure. Bytes already in the pipe are drained once more so a
     * short-lived child cannot lose its final write between signal and poll. */
    if (!exited) (void)platform_process_terminate(&process, 125u);
    (void)platform_process_wait(&process, 5000u, NULL);
    platform_process_close(&process);
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_handle, NULL, 0, NULL, &available, NULL) ||
            available == 0)
            break;
        char discard[4096];
        size_t room = used + 1u < out_size ? out_size - used - 1u : 0u;
        char *destination = room ? out + used : discard;
        DWORD capacity = room
            ? (room > UINT32_MAX ? UINT32_MAX : (DWORD)room)
            : (DWORD)sizeof(discard);
        DWORD wanted = available < capacity ? available : capacity;
        DWORD received = 0;
        if (!ReadFile(read_handle, destination, wanted, &received, NULL) ||
            received == 0) {
            ok = false;
            break;
        }
        if (room)
            used += received;
        else
            result->output_truncated = true;
    }
    out[used] = 0;
    CloseHandle(read_handle);
    return ok;
#else
    (void)options; (void)timeout_ms;
    if (out && out_size) out[0] = 0;
    if (result)
        *result = (struct platform_process_capture_result){0};
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
