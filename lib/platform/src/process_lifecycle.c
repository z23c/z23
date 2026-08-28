/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/process_lifecycle.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

void platform_process_init(struct platform_process *process)
{
    if (process) *process = (struct platform_process){UINTPTR_MAX, 0};
}

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static bool utf16(const char *text, wchar_t **out)
{
    if (!text || !out) return false;
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1,
                                    NULL, 0);
    wchar_t *wide = count > 0 ? malloc((size_t)count * sizeof(*wide)) : NULL;
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
        wchar_t *grown = realloc(*buffer, next * sizeof(**buffer));
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
    wchar_t **items = count ? calloc(count, sizeof(*items)) : NULL;
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
    wchar_t *block = calloc(total + (count == 0), sizeof(*block));
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

bool platform_process_start_hidden(struct platform_process *process,
                                   const struct platform_process_options *options)
{
    if (!process || process->native != UINTPTR_MAX || !options ||
        !options->image || !options->argv || !options->argv[0] ||
        (options->inherit_environment && options->env)) return false;
    wchar_t *image = NULL, *cwd = NULL;
    wchar_t *line = command_line(options->argv);
    wchar_t *environment = options->inherit_environment
                               ? NULL : environment_block(options->env);
    if (!utf16(options->image, &image) || !absolute_image(image) || !line ||
        (options->cwd && !utf16(options->cwd, &cwd)) ||
        (!options->inherit_environment && !environment)) goto done;
    STARTUPINFOW startup = {.cb = sizeof(startup)};
    PROCESS_INFORMATION information = {0};
    DWORD flags = DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT;
    bool ok = CreateProcessW(image, line, NULL, NULL, FALSE, flags,
                             environment, cwd, &startup, &information) != 0;
    if (ok) {
        CloseHandle(information.hThread);
        process->native = (uintptr_t)information.hProcess;
        process->pid = information.dwProcessId;
    }
done:
    free(image); free(cwd); free(line); free(environment);
    return process->native != UINTPTR_MAX;
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
    return process && process->native != UINTPTR_MAX &&
           TerminateProcess((HANDLE)process->native, exit_code) != 0;
}

void platform_process_close(struct platform_process *process)
{
    if (!process || process->native == UINTPTR_MAX) return;
    CloseHandle((HANDLE)process->native); platform_process_init(process);
}

#else
#include <fcntl.h>
#include <signal.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;

bool platform_process_start_hidden(struct platform_process *process,
                                   const struct platform_process_options *options)
{
    if (!process || process->native != UINTPTR_MAX || !options ||
        !options->image || options->image[0] != '/' || !options->argv ||
        !options->argv[0]) return false;
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
#if defined(__linux__)
        if (syscall(SYS_close_range, 3u, UINT_MAX, 0u) != 0) {
            long limit = sysconf(_SC_OPEN_MAX);
            if (limit < 0) limit = 65536;
            for (int fd = 3; fd < limit; fd++) (void)close(fd);
        }
#else
        closefrom(3);
#endif
        char *const empty_environment[] = {NULL};
        execve(options->image, (char *const *)options->argv,
               options->inherit_environment ? environ
                   : options->env ? (char *const *)options->env
                                  : empty_environment);
        _exit(127);
    }
    process->native = (uintptr_t)pid; process->pid = (uint64_t)pid; return true;
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
