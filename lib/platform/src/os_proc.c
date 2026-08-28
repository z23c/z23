/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Provide portable process identity and liveness operations. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_proc — Linux procfs and native Darwin process implementations. */

/* syscall(SYS_gettid) for os_proc_self_tid(): glibc guards it behind
 * __USE_MISC, which an explicit -D_POSIX_C_SOURCE would otherwise switch off. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "platform/os_proc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#include <shellapi.h>
#include <errno.h>
#else
#include <signal.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if !defined(__APPLE__) && !defined(_WIN32)
#include <dirent.h>
#endif

#if defined(__linux__)
#include <sys/syscall.h>   /* SYS_gettid, for os_proc_self_tid() */
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <crt_externs.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#endif

static bool os_proc_ascii_contains_ci(const char *text, const char *needle)
{
    if (!text || !needle || !needle[0])
        return false;
    for (const char *start = text; *start; start++) {
        const char *a = start;
        const char *b = needle;
        while (*a && *b) {
            unsigned char ca = (unsigned char)*a;
            unsigned char cb = (unsigned char)*b;
            if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 'a' - 'A');
            if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 'a' - 'A');
            if (ca != cb) break;
            a++;
            b++;
        }
        if (!*b) return true;
    }
    return false;
}

enum os_proc_environment
os_proc_environment_classify_kernel_release(const char *release)
{
    if (!release || !release[0])
        return OS_PROC_ENVIRONMENT_UNKNOWN;
    if (os_proc_ascii_contains_ci(release, "microsoft") ||
        os_proc_ascii_contains_ci(release, "wsl"))
        return OS_PROC_ENVIRONMENT_WSL;
    return OS_PROC_ENVIRONMENT_NATIVE;
}

enum os_proc_environment os_proc_environment_observe(void)
{
#if defined(_WIN32)
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll && GetProcAddress(ntdll, "wine_get_version"))
        return OS_PROC_ENVIRONMENT_WINE;
    return OS_PROC_ENVIRONMENT_NATIVE;
#elif defined(__linux__)
    FILE *file = fopen("/proc/sys/kernel/osrelease", "r");
    char release[256] = {0};
    if (!file || !fgets(release, sizeof(release), file)) {
        if (file) fclose(file);
        return OS_PROC_ENVIRONMENT_UNKNOWN;
    }
    fclose(file);
    return os_proc_environment_classify_kernel_release(release);
#elif defined(__APPLE__)
    return OS_PROC_ENVIRONMENT_NATIVE;
#else
    return OS_PROC_ENVIRONMENT_UNKNOWN;
#endif
}

const char *os_proc_environment_string(enum os_proc_environment environment)
{
    switch (environment) {
    case OS_PROC_ENVIRONMENT_NATIVE: return "native";
    case OS_PROC_ENVIRONMENT_WSL: return "wsl";
    case OS_PROC_ENVIRONMENT_WINE: return "wine";
    case OS_PROC_ENVIRONMENT_UNKNOWN: return "unknown";
    }
    return "unknown";
}

enum os_proc_liveness os_proc_pid_liveness(uint64_t pid)
{
    if (pid == 0 || pid > UINT32_MAX)
        return OS_PROC_LIVENESS_UNKNOWN;
#if defined(_WIN32)
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                 (DWORD)pid);
    if (!process) {
        DWORD error = GetLastError();
        return error == ERROR_INVALID_PARAMETER ? OS_PROC_LIVENESS_DEAD
                                                : OS_PROC_LIVENESS_UNKNOWN;
    }
    DWORD exit_code = 0;
    bool queried = GetExitCodeProcess(process, &exit_code) != 0;
    CloseHandle(process);
    if (!queried)
        return OS_PROC_LIVENESS_UNKNOWN;
    return exit_code == STILL_ACTIVE ? OS_PROC_LIVENESS_RUNNING
                                     : OS_PROC_LIVENESS_DEAD;
#else
    if (kill((pid_t)pid, 0) == 0)
        return OS_PROC_LIVENESS_RUNNING;
    return errno == ESRCH ? OS_PROC_LIVENESS_DEAD
                          : OS_PROC_LIVENESS_UNKNOWN;
#endif
}

uint64_t os_proc_current_pid(void)
{
#if defined(_WIN32)
    return (uint64_t)GetCurrentProcessId();
#else
    return (uint64_t)getpid();
#endif
}

bool os_proc_pid_start_token(uint64_t pid, uint64_t *token)
{
    if (!token || pid == 0 || pid > UINT32_MAX) return false;
#if defined(_WIN32)
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                 (DWORD)pid);
    FILETIME created, exited, kernel, user;
    bool ok = process && GetProcessTimes(process, &created, &exited,
                                         &kernel, &user) != 0;
    if (process) CloseHandle(process);
    if (!ok) return false;
    *token = ((uint64_t)created.dwHighDateTime << 32) | created.dwLowDateTime;
    return true;
#elif defined(__linux__)
    char path[64], row[4096];
    int n = snprintf(path, sizeof(path), "/proc/%llu/stat",
                     (unsigned long long)pid);
    FILE *file = n > 0 && (size_t)n < sizeof(path) ? fopen(path, "r") : NULL;
    if (!file || !fgets(row, sizeof(row), file)) {
        if (file) fclose(file);
        return false;
    }
    fclose(file);
    char *p = strrchr(row, ')');
    if (!p || p[1] != ' ') return false;
    p += 2;
    for (int field = 3; field < 22; ++field) {
        p = strchr(p, ' '); if (!p) return false; ++p;
    }
    char *end = NULL; unsigned long long value = strtoull(p, &end, 10);
    if (!end || (end == p)) return false;
    *token = (uint64_t)value; return true;
#else
    (void)pid; return false;
#endif
}

bool os_proc_io_bytes(uint64_t *out)
{
    if (!out) return false;
#if defined(_WIN32)
    IO_COUNTERS counters;
    if (!GetProcessIoCounters(GetCurrentProcess(), &counters)) return false;
    if (UINT64_MAX - counters.ReadTransferCount < counters.WriteTransferCount)
        return false;
    *out = counters.ReadTransferCount + counters.WriteTransferCount;
    return true;
#else
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) return false;
    uint64_t input = usage.ru_inblock > 0 ? (uint64_t)usage.ru_inblock : 0;
    uint64_t output = usage.ru_oublock > 0 ? (uint64_t)usage.ru_oublock : 0;
    if (UINT64_MAX / 512u - input < output) return false;
    *out = (input + output) * 512u;
    return true;
#endif
}

int64_t os_proc_uptime_seconds(void)
{
#if defined(_WIN32)
    FILETIME created, exited, kernel, user, now;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel,
                         &user))
        return -1;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER created_ticks;
    ULARGE_INTEGER now_ticks;
    created_ticks.LowPart = created.dwLowDateTime;
    created_ticks.HighPart = created.dwHighDateTime;
    now_ticks.LowPart = now.dwLowDateTime;
    now_ticks.HighPart = now.dwHighDateTime;
    if (now_ticks.QuadPart < created_ticks.QuadPart)
        return 0;
    return (int64_t)((now_ticks.QuadPart - created_ticks.QuadPart) /
                     UINT64_C(10000000));
#elif defined(__APPLE__)
    struct proc_bsdinfo info;
    int read = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &info,
                            (int)sizeof(info));
    if (read != (int)sizeof(info))
        return -1;
    time_t now = time(NULL);
    return now >= (time_t)info.pbi_start_tvsec
        ? (int64_t)(now - (time_t)info.pbi_start_tvsec) : 0;
#else
    /* System uptime */
    double sys_up = 0;
    FILE *f = fopen("/proc/uptime", "r");
    if (!f)
        return -1; // raw-return-ok:optional-uptime-unavailable
    if (fscanf(f, "%lf", &sys_up) != 1) {
        fclose(f);
        return -1; // raw-return-ok:optional-uptime-unavailable
    }
    fclose(f);

    /* Process start time (field 22 of /proc/self/stat) */
    f = fopen("/proc/self/stat", "r");
    if (!f)
        return -1; // raw-return-ok:optional-uptime-unavailable
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0)
        return -1; // raw-return-ok:optional-uptime-unavailable
    buf[n] = '\0';

    /* Skip past the comm field (contains parens, may have embedded
     * spaces). */
    const char *p = strrchr(buf, ')');
    if (!p)
        return -1; // raw-return-ok:optional-uptime-unavailable
    p++;
    /* Fields after ')': state(3)..starttime(22) — skip 19 fields. */
    for (int i = 0; i < 19; i++) {
        while (*p == ' ') p++;
        while (*p && *p != ' ') p++;
    }
    while (*p == ' ') p++;
    long long starttime = 0;
    if (sscanf(p, "%lld", &starttime) != 1)
        return -1; // raw-return-ok:optional-uptime-unavailable

    long clk = sysconf(_SC_CLK_TCK);
    if (clk <= 0) clk = 100;
    double proc_start_sec = (double)starttime / (double)clk;
    double age = sys_up - proc_start_sec;
    return age > 0 ? (int64_t)age : 0;
#endif
}

bool os_proc_exe_path(char *buf, size_t n)
{
    if (!buf || n == 0)
        return false; // raw-return-ok:null-arg

#if defined(_WIN32)
    wchar_t wide[32768];
    DWORD length = GetModuleFileNameW(NULL, wide,
                                     (DWORD)(sizeof(wide) / sizeof(wide[0])));
    if (length == 0 || length >= sizeof(wide) / sizeof(wide[0]))
        return false;
    int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide,
                                       (int)length, NULL, 0, NULL, NULL);
    if (required <= 0 || (size_t)required >= n)
        return false;
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)length,
                            buf, required, NULL, NULL) != required)
        return false;
    buf[required] = '\0';
    return true;
#elif defined(__APPLE__)
    uint32_t size = n > UINT32_MAX ? UINT32_MAX : (uint32_t)n;
    if (_NSGetExecutablePath(buf, &size) != 0)
        return false;
    char resolved[4096];
    if (realpath(buf, resolved)) {
        size_t len = strlen(resolved);
        if (len >= n) return false;
        memcpy(buf, resolved, len + 1u);
    }
    return true;
#else
    ssize_t len = readlink("/proc/self/exe", buf, n - 1);
    if (len <= 0)
        return false; // raw-return-ok:optional-exe-path-unavailable
    buf[len] = '\0';
    return true;
#endif
}

bool os_proc_pid_exe_path(uint64_t pid, char *buf, size_t n)
{
    if (pid == 0 || pid > UINT32_MAX || !buf || n == 0) return false;
#if defined(_WIN32)
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                 (DWORD)pid);
    if (!process) return false;
    wchar_t wide[32768];
    DWORD length = (DWORD)(sizeof(wide) / sizeof(wide[0]));
    bool ok = QueryFullProcessImageNameW(process, 0, wide, &length) != 0 &&
              length > 0 && length < sizeof(wide) / sizeof(wide[0]);
    CloseHandle(process);
    if (!ok) return false;
    int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide,
                                       (int)length, NULL, 0, NULL, NULL);
    if (required <= 0 || (size_t)required >= n) return false;
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)length,
                            buf, required, NULL, NULL) != required)
        return false;
    buf[required] = '\0';
    return true;
#elif defined(__APPLE__)
    if (pid > INT_MAX || n > INT_MAX) return false;
    int length = proc_pidpath((int)pid, buf, (uint32_t)n);
    return length > 0 && (size_t)length < n;
#else
    char link[64];
    int written = snprintf(link, sizeof(link), "/proc/%llu/exe",
                           (unsigned long long)pid);
    if (written <= 0 || (size_t)written >= sizeof(link)) return false;
    ssize_t length = readlink(link, buf, n - 1);
    if (length <= 0 || (size_t)length >= n) return false;
    buf[length] = '\0';
    return true;
#endif
}

FILE *os_proc_open_self_exe(void)
{
#if defined(__APPLE__)
    /* Darwin: _NSGetExecutablePath resolves the running binary's path
     * (the kernel keeps the exec mapping alive even after unlink), then
     * fopen reopens it for hashing. Slightly weaker than Linux's
     * /proc/self/exe inode pin, but the standard darwin approach. */
    char path[4096];
    if (!os_proc_exe_path(path, sizeof(path)))
        return NULL;
    return fopen(path, "rb");
#elif defined(__linux__)
    /* Hold the RUNNING inode, which is what this function promises.
     * Resolving the pathname first and opening that instead would
     * reopen whatever now sits at the name -- after a deploy that
     * replaces the file, a different binary -- and the kernel marks a
     * replaced dentry with a " (deleted)" suffix that does not open
     * at all. Neither is the image this process is executing. */
    return fopen("/proc/self/exe", "rb");
#else
    errno = ENOTSUP;
    return NULL;
#endif
}

bool os_proc_cmdline_has_token(const char *token)
{
    if (!token || !*token)
        return false; // raw-return-ok:null-arg

#if defined(_WIN32)
    wchar_t wide_token[32768];
    int wide_token_len = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, token, -1, wide_token,
        (int)(sizeof(wide_token) / sizeof(wide_token[0])));
    if (wide_token_len <= 0)
        return false;
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool found = false;
    for (int i = 0; argv && i < argc; i++) {
        if (wcscmp(argv[i], wide_token) == 0) {
            found = true;
            break;
        }
    }
    if (argv)
        LocalFree(argv);
    return found;
#elif defined(__APPLE__)
    int argc = *_NSGetArgc();
    char **argv = *_NSGetArgv();
    for (int i = 0; argv && i < argc; i++) {
        if (argv[i] && strcmp(argv[i], token) == 0)
            return true;
    }
    return false;
#else
    FILE *f = fopen("/proc/self/cmdline", "rb");
    if (!f)
        return false; // raw-return-ok:optional-cmdline-unavailable

    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    /* /proc/self/cmdline is NUL-separated argv; match `token` exactly against
     * one whole argument (not a substring of a longer flag/value). */
    size_t tlen = strlen(token);
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || buf[i] == '\0') {
            size_t len = i - start;
            if (len == tlen && memcmp(&buf[start], token, tlen) == 0)
                return true;
            start = i + 1;
        }
    }
    return false;
#endif
}

bool os_proc_open_fd_count(size_t *out)
{
    if (!out)
        return false; // raw-return-ok:null-arg
#if defined(_WIN32)
    DWORD handles = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &handles))
        return false; // raw-return-ok:platform-cannot-answer
    *out = (size_t)handles;
    return true;
#elif defined(__APPLE__)
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (bytes <= 0)
        return false; // raw-return-ok:platform-cannot-answer
    *out = (size_t)bytes / sizeof(struct proc_fdinfo);
    return true;
#else
    /* The shim for this read lives here precisely so no caller outside
     * lib/platform/ opens /proc itself. */
    DIR *d = opendir("/proc/self/fd");
    if (!d)
        return false; // raw-return-ok:platform-cannot-answer
    size_t n = 0;
    for (const struct dirent *e = readdir(d); e; e = readdir(d)) {
        if (e->d_name[0] == '.')
            continue;
        n++;
    }
    closedir(d);
    /* Exclude the directory handle opened just above, so a census taken
     * before an operation and one taken after are directly comparable. */
    *out = n ? n - 1 : 0;
    return true;
#endif
}

/* ── Per-thread kernel work counters ──────────────────────────────────────
 * The shim for these reads lives here precisely so no caller outside
 * lib/platform/ opens /proc itself. */

long os_proc_self_tid(void)
{
#if defined(__linux__)
    return (long)syscall(SYS_gettid);
#else
    return 0; // raw-return-ok:platform-has-no-thread-id
#endif
}

#if defined(__linux__)

/* /proc/<pid>/stat field order is stable, but field 2 (comm) is the thread
 * name in parentheses and may itself contain spaces AND parentheses, so the
 * only safe anchor is the LAST ')' in the line. Field 3 (state) is a letter,
 * not a number, so it is skipped as a token rather than parsed. Numbering the
 * remaining space-separated numeric fields from ppid (field 4) as index 0:
 * majflt is field 12, utime field 14, stime field 15. */
#define OS_PROC_TW_MAJFLT (12 - 4)
#define OS_PROC_TW_UTIME  (14 - 4)
#define OS_PROC_TW_STIME  (15 - 4)

static bool os_proc_tw_parse_stat(const char *line,
                                  struct os_proc_thread_work *out)
{
    const char *p = strrchr(line, ')');
    if (!p)
        return false; // raw-return-ok:platform-cannot-answer
    p++;
    while (*p == ' ')                 /* state: a letter, not a number */
        p++;
    while (*p != '\0' && *p != ' ')
        p++;
    uint64_t majflt = 0, utime = 0, stime = 0;
    for (int idx = 0; idx <= OS_PROC_TW_STIME; idx++) {
        while (*p == ' ')
            p++;
        if (*p == '\0')
            return false; // raw-return-ok:platform-cannot-answer
        char *end = NULL;
        unsigned long long v = strtoull(p, &end, 10);
        if (end == p)
            return false; // raw-return-ok:platform-cannot-answer
        if (idx == OS_PROC_TW_MAJFLT) majflt = (uint64_t)v;
        if (idx == OS_PROC_TW_UTIME)  utime  = (uint64_t)v;
        if (idx == OS_PROC_TW_STIME)  stime  = (uint64_t)v;
        p = end;
    }
    out->major_faults = majflt;
    out->cpu_ticks    = utime + stime;
    return true;
}

/* read_bytes/write_bytes need CONFIG_TASK_IO_ACCOUNTING. When the file is
 * missing the thread is still observable through CPU and major faults, so a
 * failure here leaves io_bytes at zero rather than failing the whole read. */
static void os_proc_tw_read_io(long tid, struct os_proc_thread_work *out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/io", tid);
    FILE *f = fopen(path, "rb");
    if (!f)
        return;
    char line[256];
    uint64_t total = 0;
    while (fgets(line, sizeof(line), f)) {
        const char *v = NULL;
        if (strncmp(line, "read_bytes:", 11) == 0)
            v = line + 11;
        else if (strncmp(line, "write_bytes:", 12) == 0)
            v = line + 12;
        if (v)
            total += strtoull(v, NULL, 10);
    }
    fclose(f);
    out->io_bytes = total;
}

bool os_proc_thread_work_read(long tid, struct os_proc_thread_work *out)
{
    if (!out)
        return false; // raw-return-ok:platform-cannot-answer
    memset(out, 0, sizeof(*out));
    if (tid <= 0)
        return false; // raw-return-ok:platform-cannot-answer
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/stat", tid);
    FILE *f = fopen(path, "rb");
    if (!f)
        return false; // raw-return-ok:platform-cannot-answer
    char line[1024];
    char *got = fgets(line, sizeof(line), f);
    fclose(f);
    if (!got || !os_proc_tw_parse_stat(line, out))
        return false; // raw-return-ok:platform-cannot-answer
    os_proc_tw_read_io(tid, out);
    return true;
}

#else /* !__linux__ */

bool os_proc_thread_work_read(long tid, struct os_proc_thread_work *out)
{
    (void)tid;
    if (!out)
        return false; // raw-return-ok:platform-cannot-answer
    memset(out, 0, sizeof(*out));
    return false; // raw-return-ok:platform-cannot-answer
}

#endif /* __linux__ */
