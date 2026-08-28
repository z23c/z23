/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_proc — Linux procfs and native Darwin process implementations. */

#include "platform/os_proc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#include <shellapi.h>
#include <psapi.h>
#else
#include <unistd.h>
#endif

#if !defined(__APPLE__) && !defined(_WIN32)
#include <dirent.h>
#endif

#if defined(__APPLE__)
#include <crt_externs.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#endif

#define OS_PROC_CGROUP_ROOT "/sys/fs/cgroup"

/* ── Test override seam (mirrors platform/clock.h, platform/rng.h) ──── */

static _Atomic bool g_override_active;
static struct os_proc_mem g_override_value;

void os_proc_mem_set_override(const struct os_proc_mem *forced)
{
    if (!forced) {
        atomic_store(&g_override_active, false);
        return;
    }
    g_override_value = *forced;
    atomic_store(&g_override_active, true);
}

/* ── Small parsing helpers ───────────────────────────────────────── */

#if !defined(_WIN32)
static void os_proc_trim_newline(char *s)
{
    if (!s)
        return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        len--;
    }
}

/* Read a single "Label: NNN kB" style line's value (in kB) from a
 * /proc/self/status-shaped file, returned as bytes. -1 if not found. */
#if !defined(__APPLE__) && !defined(_WIN32)
static int64_t os_proc_status_field_bytes(const char *path, const char *label)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[256];
    size_t label_len = strlen(label);
    int64_t result = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, label, label_len) != 0)
            continue;
        long long kb = 0;
        if (sscanf(line + label_len, " %lld", &kb) == 1 && kb >= 0)
            result = (int64_t)kb * 1024;
        break;
    }
    fclose(f);
    return result;
}
#endif

#endif /* !_WIN32 */

/* ── cgroup v2 dir resolution + limit reads ──────────────────────── */

bool os_proc_cgroup_dir(char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return false; // raw-return-ok:optional-cgroup-unavailable

#if defined(_WIN32)
    return false; // raw-return-ok:platform-has-no-cgroups
#else
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f)
        return false; // raw-return-ok:optional-cgroup-unavailable

    char line[512];
    bool ok = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::", 3) != 0)
            continue;
        char *rel = line + 3;
        os_proc_trim_newline(rel);
        int n = 0;
        if (rel[0] == '\0' || strcmp(rel, "/") == 0) {
            n = snprintf(out, out_len, "%s", OS_PROC_CGROUP_ROOT);
        } else if (rel[0] == '/') {
            n = snprintf(out, out_len, "%s%s", OS_PROC_CGROUP_ROOT, rel);
        } else {
            n = snprintf(out, out_len, "%s/%s", OS_PROC_CGROUP_ROOT, rel);
        }
        if (n < 0 || (size_t)n >= out_len)
            break;
        ok = true;
        break;
    }

    fclose(f);
    return ok;
#endif
}

#if !defined(__APPLE__) && !defined(_WIN32)
static int64_t os_proc_cgroup_limit_bytes(const char *dir, const char *name)
{
    if (!dir || !name)
        return -1; // raw-return-ok:optional-cgroup-unavailable

    char path[768];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path))
        return -1; // raw-return-ok:optional-cgroup-unavailable

    FILE *f = fopen(path, "r");
    if (!f)
        return -1; // raw-return-ok:optional-cgroup-unavailable

    char buf[64];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1; // raw-return-ok:optional-cgroup-unavailable
    }
    fclose(f);
    os_proc_trim_newline(buf);
    if (strcmp(buf, "max") == 0)
        return -1; // raw-return-ok:unlimited-cgroup-value

    long long value = -1;
    if (sscanf(buf, "%lld", &value) != 1 || value < 0)
        return -1; // raw-return-ok:optional-cgroup-unavailable
    return (int64_t)value;
}

/* ── /proc/meminfo (system totals) ───────────────────────────────── */

static void os_proc_meminfo(int64_t *total_bytes, int64_t *avail_bytes)
{
    *total_bytes = -1;
    *avail_bytes = -1;

    FILE *f = fopen("/proc/meminfo", "r");
    if (!f)
        return;

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f) && found < 2) {
        long long kb = 0;
        if (strncmp(line, "MemTotal:", 9) == 0) {
            if (sscanf(line + 9, " %lld", &kb) == 1 && kb >= 0) {
                *total_bytes = (int64_t)kb * 1024;
                found++;
            }
        } else if (strncmp(line, "MemAvailable:", 13) == 0) {
            if (sscanf(line + 13, " %lld", &kb) == 1 && kb >= 0) {
                *avail_bytes = (int64_t)kb * 1024;
                found++;
            }
        }
    }
    fclose(f);
}
#endif

/* ── Public API ───────────────────────────────────────────────────── */

bool os_proc_mem_read(struct os_proc_mem *out)
{
    if (!out)
        return false; // raw-return-ok:null-arg

    if (atomic_load(&g_override_active)) {
        *out = g_override_value;
        return true;
    }

#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS counters;
    memset(&counters, 0, sizeof(counters));
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(), &counters,
                              sizeof(counters)))
        return false;
    out->rss_bytes = (int64_t)counters.WorkingSetSize;
    out->vsize_bytes = (int64_t)counters.PagefileUsage;
    out->cgroup_current = -1;
    out->cgroup_high = -1;
    out->cgroup_max = -1;
    MEMORYSTATUSEX memory;
    memset(&memory, 0, sizeof(memory));
    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory)) {
        out->sys_total_bytes = (int64_t)memory.ullTotalPhys;
        out->sys_avail_bytes = (int64_t)memory.ullAvailPhys;
    } else {
        out->sys_total_bytes = -1;
        out->sys_avail_bytes = -1;
    }
    return true;
#elif defined(__APPLE__)
    struct rusage_info_v2 usage;
    memset(&usage, 0, sizeof(usage));
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V2,
                        (rusage_info_t *)&usage) != 0)
        return false;
    out->rss_bytes = (int64_t)usage.ri_resident_size;
    mach_task_basic_info_data_t basic;
    mach_msg_type_number_t basic_count = MACH_TASK_BASIC_INFO_COUNT;
    out->vsize_bytes = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
        (task_info_t)&basic, &basic_count) == KERN_SUCCESS
        ? (int64_t)basic.virtual_size : -1;
    out->cgroup_current = -1;
    out->cgroup_high = -1;
    out->cgroup_max = -1;
    uint64_t total = 0;
    size_t total_size = sizeof(total);
    out->sys_total_bytes = sysctlbyname("hw.memsize", &total, &total_size,
                                       NULL, 0) == 0 ? (int64_t)total : -1;
    out->sys_avail_bytes = -1;
    return true;
#else
    out->rss_bytes = os_proc_status_field_bytes("/proc/self/status", "VmRSS:");
    out->vsize_bytes = os_proc_status_field_bytes("/proc/self/status", "VmSize:");

    char dir[768];
    if (os_proc_cgroup_dir(dir, sizeof(dir))) {
        out->cgroup_current = os_proc_cgroup_limit_bytes(dir, "memory.current");
        out->cgroup_high = os_proc_cgroup_limit_bytes(dir, "memory.high");
        out->cgroup_max = os_proc_cgroup_limit_bytes(dir, "memory.max");
    } else {
        out->cgroup_current = -1;
        out->cgroup_high = -1;
        out->cgroup_max = -1;
    }

    os_proc_meminfo(&out->sys_total_bytes, &out->sys_avail_bytes);

    return out->rss_bytes >= 0;
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

FILE *os_proc_open_self_exe(void)
{
    char path[4096];
    return os_proc_exe_path(path, sizeof(path)) ? fopen(path, "rb") : NULL;
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
