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
#include "os_proc_fdclose_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#if defined(_WIN32)
#include <windows.h>
#include <shellapi.h>
#include <errno.h>
#include <fcntl.h>   /* _O_RDONLY/_O_BINARY for os_proc_open_self_exe() */
#include <io.h>      /* _open_osfhandle/_close, likewise */
#include <wchar.h>
#else
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if !defined(_WIN32)
#include <dirent.h>
#endif

#if defined(__linux__)
#include <sys/prctl.h>     /* PR_SET_PDEATHSIG, for os_proc_bind_parent_death() */
#include <fcntl.h>         /* O_DIRECTORY, for os_proc_fd_dir_open() */
#include <sys/syscall.h>   /* SYS_gettid, for os_proc_self_tid() */
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <crt_externs.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#endif

#if defined(__linux__)
static bool os_proc_capability_line_zero(const char *line)
{
    const char *value = strchr(line, ':');
    if (!value) return false;
    errno = 0;
    char *end = NULL;
    unsigned long long bits = strtoull(value + 1, &end, 16);
    return errno == 0 && end != value + 1 && bits == 0 &&
           (*end == '\n' || *end == '\0');
}
#endif

bool os_proc_unprivileged_no_capabilities(void)
{
#if defined(__linux__)
    uid_t real, effective, saved;
    if (getresuid(&real, &effective, &saved) != 0 ||
        real == 0 || effective == 0 || saved == 0) return false;
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return false;
    char line[512];
    unsigned found = 0;
    bool clean = true;
    while (fgets(line, sizeof(line), status)) {
        unsigned bit = strncmp(line, "CapPrm:", 7) == 0 ? 1u :
                       strncmp(line, "CapEff:", 7) == 0 ? 2u :
                       strncmp(line, "CapAmb:", 7) == 0 ? 4u : 0u;
        if (!bit) continue;
        found |= bit;
        if (!os_proc_capability_line_zero(line)) { clean = false; break; }
    }
    bool read_failed = ferror(status) != 0;
    bool close_failed = fclose(status) != 0;
    return !read_failed && !close_failed && clean && found == 7u;
#else
    return false;
#endif
}

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
#elif defined(__APPLE__)
    if (pid > INT_MAX) return false;
    struct proc_bsdinfo info = {0};
    int bytes = proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &info,
                             (int)sizeof(info));
    if (bytes != (int)sizeof(info) || info.pbi_pid != (uint32_t)pid ||
        info.pbi_start_tvusec >= UINT64_C(1000000) ||
        info.pbi_start_tvsec >
            (UINT64_MAX - info.pbi_start_tvusec) / UINT64_C(1000000))
        return false;
    *token = info.pbi_start_tvsec * UINT64_C(1000000) +
             info.pbi_start_tvusec;
    return *token != 0;
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
#elif defined(__APPLE__)
    struct rusage_info_v2 usage;
    memset(&usage, 0, sizeof(usage));
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V2,
                        (rusage_info_t *)&usage) != 0 ||
        UINT64_MAX - usage.ri_diskio_bytesread <
            usage.ri_diskio_byteswritten)
        return false;
    *out = usage.ri_diskio_bytesread + usage.ri_diskio_byteswritten;
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

int64_t os_proc_system_uptime_seconds(void)
{
#if defined(__linux__)
    FILE *f = fopen("/proc/uptime", "r");
    double seconds = -1.0;
    if (!f)
        return -1; // raw-return-ok:platform-cannot-answer
    if (fscanf(f, "%lf", &seconds) != 1 || seconds < 0 || seconds > 3.0e9)
        seconds = -1.0;
    fclose(f);
    return seconds < 0 ? -1 : (int64_t)seconds; // raw-return-ok:platform-cannot-answer
#elif defined(__APPLE__)
    struct timeval boot;
    size_t size = sizeof boot;
    time_t now = time(NULL);
    if (sysctlbyname("kern.boottime", &boot, &size, NULL, 0) != 0 ||
        size != sizeof boot || now < boot.tv_sec)
        return -1; // raw-return-ok:platform-cannot-answer
    return (int64_t)(now - boot.tv_sec);
#else
    return -1; // raw-return-ok:platform-cannot-answer
#endif
}

int64_t os_proc_load1_centi(void)
{
#if defined(__linux__)
    FILE *f = fopen("/proc/loadavg", "r");
    char buf[128];
    unsigned whole = 0, frac = 0;
    if (!f || !fgets(buf, sizeof buf, f)) {
        if (f)
            fclose(f);
        return -1; // raw-return-ok:platform-cannot-answer
    }
    fclose(f);
    if (sscanf(buf, "%u.%2u", &whole, &frac) < 1 || whole > 100000)
        return -1; // raw-return-ok:platform-cannot-answer
    return (int64_t)whole * 100 + (int64_t)frac;
#else
    return -1; // raw-return-ok:platform-cannot-answer
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

bool os_proc_self_exe_open_path(char *buf, size_t n)
{
    if (!buf || n == 0)
        return false; // raw-return-ok:null-arg
#if defined(__linux__)
    static const char k_magic[] = "/proc/self/exe";
    if (sizeof(k_magic) > n)
        return false;
    memcpy(buf, k_magic, sizeof(k_magic));
    return true;
#else
    return os_proc_exe_path(buf, n);
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

#if defined(_WIN32)
/* GetModuleFileNameW can hand back more than MAX_PATH characters, and a
 * plain CreateFileW on such a string fails unless the process happens to be
 * long-path aware. The \\?\ prefix turns the Win32 path parse off entirely
 * and lifts the limit. Same three cases as platform_windows_wide_path()
 * (platform/modules/platform/src/windows_path_internal.h) minus its '/'-to-'\' rewrite:
 * that helper takes UTF-8 and this input is already wide and already
 * normalised by the loader, so round-tripping it through UTF-8 just to reuse
 * the helper would add two lossy conversions to buy nothing. */
static bool os_proc_win_extend_path(const wchar_t *in, size_t len,
                                    wchar_t out[32768])
{
    if (len == 0 || len >= 32768)
        return false;
    if (wcsncmp(in, L"\\\\?\\", 4) == 0) {
        wmemcpy(out, in, len + 1u);
        return true;
    }
    if (in[0] == L'\\' && in[1] == L'\\') {          /* \\server\share\... */
        if (len + 7u >= 32768) return false;
        wmemcpy(out, L"\\\\?\\UNC\\", 8);
        wmemcpy(out + 8, in + 2, len - 2u + 1u);
        return true;
    }
    if (in[0] && in[1] == L':' && in[2] == L'\\') {  /* C:\... */
        if (len + 5u >= 32768) return false;
        wmemcpy(out, L"\\\\?\\", 4);
        wmemcpy(out + 4, in, len + 1u);
        return true;
    }
    wmemcpy(out, in, len + 1u);
    return true;
}
#endif

FILE *os_proc_open_self_exe(void)
{
#if defined(_WIN32)
    /* Windows reopens the running image BY PATHNAME. That is rung
     * RESOLVED_PATH, not RUNNING_IMAGE, and the difference is real: no
     * documented Win32 call hands out a handle to the file object the
     * loader mapped. GetModuleFileNameW returns a STRING cached in the PEB
     * at image load, so everything after it is ordinary name resolution.
     *
     * The race is not hypothetical on this platform, it is the platform's
     * own update idiom. A running image cannot be overwritten in place --
     * the loader holds it without FILE_SHARE_WRITE -- so a Windows deploy
     * RENAMES the running exe aside and installs the new one at the old
     * name. Between GetModuleFileNameW and CreateFileW that leaves a new,
     * different file under the name we are about to open.
     *
     * Two things narrow the window and neither closes it, so neither earns
     * a stronger label:
     *   - FILE_SHARE_WRITE denial rules out the in-place-overwrite variant,
     *     so the file at that name cannot have been edited underneath us.
     *   - FILE_SHARE_DELETE in OUR open means that once the handle exists it
     *     keeps naming that one file object across any later rename or
     *     delete, so the bytes a caller reads are self-consistent.
     * GetFileInformationByHandle's volume serial + file index would give an
     * inode-equivalent identity for the handle, but there is nothing
     * trustworthy to compare it against -- the only other identity available
     * is derived from the same pathname -- so it would be a comparison of a
     * value with itself, dressed up as a proof. Left out deliberately. */
    wchar_t wide[32768];
    DWORD length = GetModuleFileNameW(NULL, wide,
                                      (DWORD)(sizeof(wide) / sizeof(wide[0])));
    if (length == 0 || length >= sizeof(wide) / sizeof(wide[0])) {
        errno = ENOENT;
        return NULL;
    }
    wchar_t extended[32768];
    if (!os_proc_win_extend_path(wide, (size_t)length, extended)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    HANDLE handle = CreateFileW(extended, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = EACCES;
        return NULL;
    }
    /* Ownership walks forward one step at a time and each failure arm frees
     * exactly the tier it reached: _open_osfhandle takes the HANDLE (so
     * _close, never CloseHandle, is the undo after it succeeds) and _fdopen
     * takes the fd (so the caller's fclose closes both). Getting this wrong
     * leaks a handle on every boot of a node that cannot read its own
     * image, which is precisely the box an operator is trying to diagnose. */
    int fd = _open_osfhandle((intptr_t)handle, _O_RDONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(handle);
        errno = EBADF;
        return NULL;
    }
    FILE *stream = _fdopen(fd, "rb");
    if (!stream) {
        _close(fd);
        return NULL;
    }
    return stream;
#elif defined(__APPLE__)
    /* Darwin: _NSGetExecutablePath resolves the running binary's path
     * (the kernel keeps the exec mapping alive even after unlink), then
     * fopen reopens it for hashing. Rung RESOLVED_PATH, weaker than
     * Linux's /proc/self/exe inode pin for the same reason the Windows arm
     * above is -- the open is by NAME -- but the standard darwin approach. */
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
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL; // raw-return-ok:platform-cannot-answer
    FILE *stream = fdopen(fd, "rb");
    if (!stream) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
    }
    return stream;
#else
    errno = ENOTSUP;
    return NULL;
#endif
}

/* The rung the arm above actually reached. Deliberately derived from the
 * SAME preprocessor ladder, immediately below it, so a platform cannot
 * acquire an implementation without its label moving with it, and cannot
 * acquire a label without an implementation. A reader that keeps its own
 * copy of this #if is a claim that drifts away from the mechanism. */
enum os_proc_image_identity os_proc_self_exe_identity(void)
{
#if defined(_WIN32) || defined(__APPLE__)
    return OS_PROC_IMAGE_IDENTITY_RESOLVED_PATH;
#elif defined(__linux__)
    return OS_PROC_IMAGE_IDENTITY_RUNNING_IMAGE;
#else
    return OS_PROC_IMAGE_IDENTITY_UNAVAILABLE;
#endif
}

#if defined(_WIN32)
static bool os_proc_windows_cmdline_has_token(const wchar_t *wide_token)
{
    int argc = 0;
    /* Loading Shell32 eagerly prevents a low-integrity, UI-restricted worker
     * from reaching main. Load its parser only when needed, from System32. */
    HMODULE shell = LoadLibraryExW(L"shell32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    typedef LPWSTR *(WINAPI *parse_fn)(LPCWSTR, int *);
    parse_fn parse = NULL;
    FARPROC symbol = shell ? GetProcAddress(shell, "CommandLineToArgvW") : NULL;
    static_assert(sizeof(parse) == sizeof(symbol), "Windows parser symbol width");
    memcpy(&parse, &symbol, sizeof(parse));
    if (!parse) {
        DWORD error = GetLastError();
        if (shell) FreeLibrary(shell);
        fprintf(stderr, "os_proc: command-line parser unavailable win32=%lu\n",
                (unsigned long)error);
        return false;
    }
    wchar_t **argv = parse(GetCommandLineW(), &argc);
    if (!argv)
        fprintf(stderr, "os_proc: command-line parsing failed win32=%lu\n",
                (unsigned long)GetLastError());
    bool found = false;
    for (int i = 0; argv && i < argc; i++) {
        if (wcscmp(argv[i], wide_token) == 0) {
            found = true;
            break;
        }
    }
    if (argv)
        LocalFree(argv);
    FreeLibrary(shell);
    return found;
}
#endif

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
    return os_proc_windows_cmdline_has_token(wide_token);
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

bool os_proc_close_inherited_fds(void)
{
#if defined(_WIN32)
    errno = ENOSYS;
    return false; // raw-return-ok:caller-logs-context
#else
    DIR *directory = opendir("/dev/fd");
    if (!directory) return false; // raw-return-ok:caller-logs-context
    int own = dirfd(directory);
    bool ok = own >= 0;
    while (ok) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) {
            ok = errno == 0;
            break;
        }
        if (entry->d_name[0] == '.') continue;
        char *end = NULL;
        long number = strtol(entry->d_name, &end, 10);
        if (errno || !end || *end || number < 0 || number > INT_MAX) {
            errno = EINVAL;
            ok = false;
            break;
        }
        int fd = (int)number;
        if (fd > STDERR_FILENO && fd != own && close(fd) != 0 &&
            errno != EBADF)
            ok = false;
    }
    int saved = errno;
    if (closedir(directory) != 0)
        return false; // raw-return-ok:caller-logs-context
    if (!ok) errno = saved;
    return ok;
#endif
}

bool os_proc_bind_parent_death(int signal_number, uint64_t expected_parent)
{
#if defined(_WIN32)
    (void)signal_number;
    (void)expected_parent;
    errno = ENOSYS;
    return false; // raw-return-ok:caller-logs-context
#else
#if defined(__linux__)
    if (prctl(PR_SET_PDEATHSIG, signal_number) != 0)
        return false; // raw-return-ok:caller-logs-context
#else
    (void)signal_number;
#endif
    return (uint64_t)getppid() == expected_parent;
#endif
}

#if !defined(_WIN32) && !defined(__linux__)
static bool os_proc_close_fd_except_entry(const struct dirent *entry,
                                          int own, int keep_fd)
{
    if (entry->d_name[0] == '.') return true;
    char *end = NULL;
    errno = 0;
    long number = strtol(entry->d_name, &end, 10);
    if (errno || !end || *end || number < 0 || number > INT_MAX) {
        errno = EINVAL;
        return false;
    }
    int fd = (int)number;
    if (fd <= STDERR_FILENO || fd == own || fd == keep_fd) return true;
    return close(fd) == 0 || errno == EBADF;
}
#endif

#if defined(__linux__)
/* Allocation-free child descriptor census; never trusts RLIMIT_NOFILE. */
static bool op_fd_kept(const int *keep, size_t n, int fd)
{
    for (size_t i = 0; i < n; ++i) if (keep[i] == fd) return true;
    return false;
}

/* Decode only complete numeric proc names, without locale or allocation. */
static bool op_fd_number(const char *name, size_t len, int *fd)
{
    if ((len == 1 && name[0] == '.') ||
        (len == 2 && name[0] == '.' && name[1] == '.')) {
        *fd = -1;
        return true;
    }
    if (!len) return false;
    unsigned value = 0;
    for (size_t i = 0; i < len; ++i) {
        if (name[i] < '0' || name[i] > '9') return false;
        unsigned digit = (unsigned)(name[i] - '0');
        if (value > ((unsigned)INT_MAX - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    *fd = (int)value;
    return true;
}

/* Validate raw Linux dirent64 extents before interpreting their names. */
static bool op_fd_batch(const unsigned char *buf, size_t size, int own,
                         const int *keep, size_t n, bool *unwanted)
{
    size_t off = 0;
    while (off < size) {
        if (size - off < 20u) return false;
        unsigned short len;
        memcpy(&len, buf + off + 16u, sizeof(len));
        if (len < 20u || len > size - off) return false;
        const char *name = (const char *)buf + off + 19u;
        size_t available = (size_t)len - 19u, used = 0;
        while (used < available && name[used]) ++used;
        int fd;
        if (used == available || !op_fd_number(name, used, &fd)) return false;
        if (fd >= 0 && fd != own && !op_fd_kept(keep, n, fd)) {
            *unwanted = true;
            if (close(fd) != 0 && errno != EBADF && errno != EINTR) return false;
        }
        off += len;
    }
    return true;
}

/* A clean full pass is required after closing: errors never imply emptiness. */
static bool op_fd_census(int own, const int *keep, size_t n)
{
    for (unsigned pass = 0; pass < 64u; ++pass) {
        unsigned char buf[2048];
        bool unwanted = false;
        if (lseek(own, 0, SEEK_SET) < 0) return false;
        long got;
        while ((got = syscall(SYS_getdents64, own, buf, sizeof(buf))) > 0) {
            if (!op_fd_batch(buf, (size_t)got, own, keep, n, &unwanted)) return false;
        }
        if (got < 0) return false;
        if (!unwanted) return true;
    }
    errno = EBUSY;
    return false;
}

/* close_range(2) over the gaps between retained descriptors; false means the
 * kernel lacks it (or refused) and the proc census must finish the job. */
static bool op_fd_range_close(const int *keep, size_t n)
{
#if defined(SYS_close_range)
    unsigned next = 0;
    bool swept = true;
    for (size_t i = 0; swept && i < n; ++i) {
        if (keep[i] < 0 || (unsigned)keep[i] < next) continue;
        if ((unsigned)keep[i] > next)
            swept = syscall(SYS_close_range, next, (unsigned)keep[i] - 1u, 0u) == 0;
        next = (unsigned)keep[i] + 1u;
    }
    return swept && syscall(SYS_close_range, next, UINT_MAX, 0u) == 0;
#else
    (void)keep;
    (void)n;
    return false;
#endif
}

/* Sorted retained descriptors permit range closure; proc is the older-kernel
 * fallback. Both paths operate on this child only, without libc streams. */
bool os_proc_linux_close_fds_kept(const int *keep, size_t n, bool try_range)
{
    if (!keep || !n || n > 48u) { errno = EINVAL; return false; }
    for (size_t i = 1; i < n; ++i)
        if (keep[i] < keep[i - 1]) { errno = EINVAL; return false; }
    if (try_range && op_fd_range_close(keep, n)) return true;
    int own = os_proc_fd_dir_open();
    if (own < 0) return false;
    bool ok = op_fd_census(own, keep, n);
    int saved = errno;
    if (close(own) != 0) return false;
    if (!ok) errno = saved;
    return ok;
}
#endif

bool os_proc_close_inherited_fds_except(int keep_fd)
{
#if defined(_WIN32)
    (void)keep_fd;
    errno = ENOSYS;
    return false; // raw-return-ok:caller-logs-context
#else
    if (keep_fd <= STDERR_FILENO) {
        errno = EINVAL;
        return false; // raw-return-ok:caller-logs-context
    }
    struct stat kept;
    if (fstat(keep_fd, &kept) < 0)
        return false; // raw-return-ok:caller-logs-context
#if defined(__linux__)
    const int keep[] = {0, 1, 2, keep_fd};
    return os_proc_linux_close_fds_kept(keep, 4u, true);
#else
    DIR *directory = opendir("/dev/fd");
    if (!directory) return false; // raw-return-ok:caller-logs-context
    int own = dirfd(directory);
    bool ok = own >= 0;
    while (ok) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) {
            ok = errno == 0;
            break;
        }
        ok = os_proc_close_fd_except_entry(entry, own, keep_fd);
    }
    int saved = errno;
    if (closedir(directory) != 0)
        return false; // raw-return-ok:caller-logs-context
    if (!ok) errno = saved;
    return ok;
#endif
#endif
}

int os_proc_fd_dir_open(void)
{
#if defined(__linux__)
    return open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
#else
    errno = ENOSYS;
    return -1; // raw-return-ok:caller-logs-context
#endif
}

#if defined(__linux__)
/* Parses the decimal after "\nSeccomp_filters:\t" in a status text. */
static bool os_proc_parse_seccomp_filters(const char *status, uint32_t *out)
{
    static const char key[] = "\nSeccomp_filters:\t";
    const char *p = strstr(status, key);
    if (!p)
        return false; // raw-return-ok:platform-cannot-answer
    p += sizeof(key) - 1;
    uint64_t value = 0;
    const char *digits = p;
    for (; *p >= '0' && *p <= '9' && value <= UINT32_MAX; p++)
        value = value * 10u + (uint64_t)(*p - '0');
    if (p == digits || value > UINT32_MAX)
        return false; // raw-return-ok:platform-cannot-answer
    if (*p != '\n')
        return false; // raw-return-ok:truncated-read-fails-closed
    *out = (uint32_t)value;
    return true;
}

#ifdef ZCL_TESTING
bool os_proc_parse_seccomp_filters_for_test(const char *status, uint32_t *out)
{
    return os_proc_parse_seccomp_filters(status, out);
}
#endif
#endif

bool os_proc_seccomp_filters(uint64_t pid, uint32_t *out)
{
    if (!out)
        return false; // raw-return-ok:null-arg
#if defined(__linux__)
    char path[48];
    if (pid == 0) (void)snprintf(path, sizeof(path), "/proc/self/status");
    else (void)snprintf(path, sizeof(path), "/proc/%llu/status",
                        (unsigned long long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false; // raw-return-ok:platform-cannot-answer
    char buf[4096];
    size_t have = 0;
    bool read_failed = false;
    for (;;) {
        ssize_t n = read(fd, buf + have, sizeof(buf) - 1 - have);
        if (n > 0 && (have += (size_t)n) < sizeof(buf) - 1) continue;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) read_failed = true;
        break;
    }
    (void)close(fd);
    if (read_failed)
        return false; // raw-return-ok:platform-cannot-answer
    buf[have] = '\0';
    return os_proc_parse_seccomp_filters(buf, out);
#else
    (void)pid;
    return false; // raw-return-ok:platform-cannot-answer
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
    /* A NULL buffer returns fd-table capacity plus slack, not live FDs. */
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (bytes <= 0)
        return false; // raw-return-ok:platform-cannot-answer
    struct proc_fdinfo *fds = malloc((size_t)bytes); // raw-alloc-ok:standalone-platform-package
    if (!fds)
        return false; // raw-return-ok:platform-cannot-answer
    int used = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, bytes);
    free(fds);
    /* A full buffer could have truncated a concurrent fd-table growth. */
    if (used <= 0 || used >= bytes ||
        (size_t)used % sizeof(struct proc_fdinfo) != 0)
        return false; // raw-return-ok:platform-cannot-answer
    *out = (size_t)used / sizeof(struct proc_fdinfo);
    return true;
#else
    /* The shim for this read lives here precisely so no caller outside
     * platform/modules/platform/ opens /proc itself. */
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
 * platform/modules/platform/ opens /proc itself. */

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

char *os_proc_self_maps_read(size_t max, size_t *len_out)
{
#if defined(__linux__)
    FILE *f = fopen("/proc/self/maps", "rb");
    if (!f)
        return NULL; // raw-return-ok:platform-cannot-answer
    char *buf = malloc(max + 1); // raw-alloc-ok:standalone-platform-package
    size_t n = buf ? fread(buf, 1, max + 1, f) : 0;
    bool whole = buf && !ferror(f) && feof(f) && n <= max &&
                 !memchr(buf, 0, n);
    fclose(f);
    if (!whole) {
        free(buf);
        return NULL; // raw-return-ok:platform-cannot-answer
    }
    buf[n] = 0;
    if (len_out)
        *len_out = n;
    return buf;
#else
    (void)max;
    if (len_out)
        *len_out = 0;
    return NULL; // raw-return-ok:platform-cannot-answer
#endif
}

#if defined(__APPLE__)
enum { OS_PROC_PATH_PID_CAP = 65536, OS_PROC_PATH_FD_CAP = 65536 };
#ifdef ZCL_TESTING
static _Atomic unsigned g_path_capacity;
static _Atomic uint64_t g_path_error_pid;
static _Atomic int g_path_error_fd;
static _Atomic int g_path_error;
static _Atomic bool g_path_error_seen;
void os_proc_test_path_vnode_error(uint64_t pid, int fd, int error)
{
    atomic_store(&g_path_error_pid, pid);
    atomic_store(&g_path_error_fd, fd);
    atomic_store(&g_path_error, error);
    atomic_store(&g_path_error_seen, false);
}
bool os_proc_test_path_vnode_error_seen(void)
{
    return atomic_load(&g_path_error_seen);
}
void os_proc_test_path_capacity(unsigned capacity)
{
    atomic_store(&g_path_capacity, capacity);
}
#endif

static unsigned os_proc_path_capacity(unsigned normal)
{
#ifdef ZCL_TESTING
    unsigned cap = atomic_load(&g_path_capacity);
    if (cap > 0 && cap < normal) return cap;
#endif
    return normal;
}

static bool os_proc_visit_path(const char *path, size_t cap,
                               os_proc_path_visitor visitor, void *opaque)
{
    if (!memchr(path, '\0', cap) || path[0] != '/') return false;
    visitor(path, opaque);
    return true;
}

static int os_proc_path_vnode_info(int pid, int fd,
                                   struct vnode_fdinfowithpath *info)
{
#ifdef ZCL_TESTING
    int error = atomic_load(&g_path_error);
    if (error && atomic_load(&g_path_error_pid) == (uint64_t)pid &&
        atomic_load(&g_path_error_fd) == fd) {
        atomic_store(&g_path_error_seen, true);
        errno = error;
        return -1;
    }
#endif
    return proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, info, sizeof(*info));
}

static bool os_proc_visit_vnode(int pid, int fd,
                                os_proc_path_visitor visitor, void *opaque)
{
    struct vnode_fdinfowithpath info;
    memset(&info, 0, sizeof(info));
    errno = 0;
    int n = os_proc_path_vnode_info(pid, fd, &info);
    if (n != (int)sizeof(info)) return n <= 0 && errno == EBADF;
    return os_proc_visit_path(info.pvip.vip_path, sizeof(info.pvip.vip_path),
                              visitor, opaque);
}

static bool os_proc_visit_fds(int pid, os_proc_path_visitor visitor, void *opaque)
{
    size_t bytes = os_proc_path_capacity(OS_PROC_PATH_FD_CAP) * sizeof(struct proc_fdinfo);
    struct proc_fdinfo *fds = malloc(bytes); // raw-alloc-ok:standalone-platform-package
    if (!fds) return false;
    errno = 0;
    int n = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, (int)bytes);
    bool complete = n >= 0 && (n != 0 || errno == 0) && (size_t)n < bytes &&
                    n % (int)sizeof(*fds) == 0;
    size_t count = n > 0 && (size_t)n <= bytes ? (size_t)n / sizeof(*fds) : 0;
    for (size_t i = 0; i < count; i++) {
        if (fds[i].proc_fdtype == PROX_FDTYPE_VNODE &&
            !os_proc_visit_vnode(pid, fds[i].proc_fd, visitor, opaque))
            complete = false;
    }
    free(fds);
    return complete;
}

static bool os_proc_visit_one(int pid, os_proc_path_visitor visitor, void *opaque)
{
    uint64_t before, after;
    if (!os_proc_pid_start_token((uint64_t)pid, &before))
        return os_proc_pid_liveness((uint64_t)pid) == OS_PROC_LIVENESS_DEAD;
    struct proc_vnodepathinfo info;
    memset(&info, 0, sizeof(info));
    int n = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, sizeof(info));
    bool complete = n == (int)sizeof(info) &&
        os_proc_visit_path(info.pvi_cdir.vip_path, sizeof(info.pvi_cdir.vip_path),
                           visitor, opaque);
    if (!os_proc_visit_fds(pid, visitor, opaque)) complete = false;
    if (!os_proc_pid_start_token((uint64_t)pid, &after))
        return os_proc_pid_liveness((uint64_t)pid) == OS_PROC_LIVENESS_DEAD;
    return complete && before == after;
}
#ifdef ZCL_TESTING
bool os_proc_test_visit_pid_paths(uint64_t pid, os_proc_path_visitor visitor,
                                  void *opaque)
{
    return visitor && pid > 0 && pid <= INT_MAX &&
           os_proc_visit_one((int)pid, visitor, opaque);
}
#endif
#endif

bool os_proc_visit_paths(os_proc_path_visitor visitor, void *opaque)
{
#if defined(__APPLE__)
    if (!visitor) return false;
    size_t bytes = os_proc_path_capacity(OS_PROC_PATH_PID_CAP) * sizeof(pid_t);
    pid_t *pids = malloc(bytes); // raw-alloc-ok:standalone-platform-package
    if (!pids) return false;
    int n = proc_listpids(PROC_ALL_PIDS, 0, pids, (int)bytes);
    bool complete = n > 0 && (size_t)n < bytes && n % (int)sizeof(*pids) == 0;
    size_t count = n > 0 && (size_t)n <= bytes ? (size_t)n / sizeof(*pids) : 0;
    for (size_t i = 0; i < count; i++)
        if (pids[i] <= 0 || !os_proc_visit_one(pids[i], visitor, opaque)) complete = false;
    free(pids);
    return complete;
#else
    (void)visitor;
    (void)opaque;
    return false;
#endif
}

#if defined(__linux__)
/* Only these per-thread procfs files may be read through the shim. */
static bool os_proc_task_file_allowed(const char *name)
{
    return name && (strcmp(name, "stat") == 0 || strcmp(name, "wchan") == 0 ||
                    strcmp(name, "syscall") == 0);
}

static size_t os_proc_task_ids_scan(DIR *d, long *out, size_t max,
                                    size_t *total)
{
    size_t n = 0, all = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char *end = NULL;
        if (e->d_name[0] < '0' || e->d_name[0] > '9')
            continue;
        long tid = strtol(e->d_name, &end, 10);
        if (*end != '\0')
            continue;
        all++;
        if (out && n < max)
            out[n++] = tid;
    }
    if (total) *total = all;
    return n;
}
#endif

size_t os_proc_self_task_ids(long *out, size_t max, size_t *total)
{
    if (total) *total = 0;
#if defined(__linux__)
    DIR *d = opendir("/proc/self/task");
    if (!d)
        return 0;
    size_t n = os_proc_task_ids_scan(d, out, max, total);
    closedir(d);
    return n;
#else
    (void)out;
    (void)max;
    return 0;
#endif
}

bool os_proc_self_task_read(long tid, const char *name, char *buf, size_t cap)
{
    if (!buf || cap == 0)
        return false;
    buf[0] = '\0';
#if defined(__linux__)
    if (tid <= 0 || !os_proc_task_file_allowed(name))
        return false;
    char path[96];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/%s", tid, name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    ssize_t n = read(fd, buf, cap - 1);
    (void)close(fd);
    if (n < 0)
        return false;
    buf[n] = '\0';
    return true;
#else
    (void)tid;
    (void)name;
    return false;
#endif
}
