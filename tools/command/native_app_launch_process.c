/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the process side of `z23 app open`: identify a live process by
 * executable and kernel start time, find a copy started by hand, deliver the
 * raise signal to an app that declares it (and, on Linux, handles it), and
 * spawn a detached app
 * with a bounded wait for its ready marker. No shell anywhere. */

#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1 /* posix_spawn_file_actions_addclosefrom_np */
#endif

#include "command/native_app_launch.h"

#include "platform/time_compat.h"
#include "platform/resident_launch.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif
#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc.h> /* SZOMB */
#include <sys/proc_info.h>
#endif

#define APP_LOG_SCAN_MAX (256u * 1024u)
#define APP_POLL_MS 50

/* Each public app_proc_* function is defined ONCE, at the end of this file;
 * the per-platform bodies are static app_os_* helpers. */
#if !defined(_WIN32)

/* Reap pid when it is an exited child of this process (an MCP server keeps
 * its spawned apps as children); true when it is gone. */
[[maybe_unused]] static bool app_proc_reaped(long pid)
{
    int status;
    return waitpid((pid_t)pid, &status, WNOHANG) == (pid_t)pid;
}

#if defined(__linux__)

/* State and start time from /proc/<pid>/stat. Fields are read after the
 * LAST ')' because the command name may itself hold spaces and parens. */
static bool app_proc_stat(long pid, char *state, uint64_t *start_time)
{
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
    FILE *f = fopen(path, "re");
    if (!f)
        return false;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    char *p = strrchr(buf, ')');
    if (!p || p[1] != ' ' || !p[2])
        return false;
    *state = p[2];
    p += 3; /* the space before field 4 */
    /* Each step moves p to the start of field `field`, so the loop must end
     * on starttime, field 22 (field 21, itrealvalue, is always 0). */
    for (int field = 4; field <= 22 && p; field++) {
        p = strchr(p, ' ');
        p = p ? p + 1 : NULL;
    }
    if (!p)
        return false;
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(p, &end, 10);
    if (errno || end == p || v == 0) /* 0 cannot tell one process from another */
        return false;
    *start_time = (uint64_t)v;
    return true;
}

static bool app_proc_exe(long pid, char exe[APP_LAUNCH_PATH_MAX])
{
    static const char deleted[] = " (deleted)";
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/exe", pid);
    ssize_t n = readlink(path, exe, APP_LAUNCH_PATH_MAX - 1);
    if (n <= 0 || (size_t)n >= APP_LAUNCH_PATH_MAX - 1)
        return false;
    exe[n] = '\0';
    size_t dl = sizeof(deleted) - 1;
    if ((size_t)n > dl && strcmp(exe + n - (ssize_t)dl, deleted) == 0)
        exe[n - (ssize_t)dl] = '\0';
    return true;
}

static bool app_os_identity(long pid, char exe[APP_LAUNCH_PATH_MAX],
                            uint64_t *start_time)
{
    char state = 0;
    if (pid <= 1 || app_proc_reaped(pid) ||
        !app_proc_stat(pid, &state, start_time) || state == 'Z' ||
        state == 'X')
        return false;
    return app_proc_exe(pid, exe);
}

static bool app_proc_numeric(const char *name, long *pid)
{
    char *end = NULL;
    if (name[0] < '1' || name[0] > '9')
        return false;
    *pid = strtol(name, &end, 10);
    return end && *end == '\0' && *pid > 1;
}

static long app_os_scan(const char *exe)
{
    DIR *d = opendir("/proc");
    long best = 0;
    if (!d)
        return 0;
    for (struct dirent *de = readdir(d); de; de = readdir(d)) {
        long pid;
        struct stat st;
        char path[64], seen[APP_LAUNCH_PATH_MAX];
        uint64_t start;
        if (!app_proc_numeric(de->d_name, &pid))
            continue;
        snprintf(path, sizeof(path), "/proc/%ld", pid);
        if (stat(path, &st) != 0 || st.st_uid != getuid())
            continue;
        if (app_proc_identity(pid, seen, &start) && strcmp(seen, exe) == 0 &&
            (best == 0 || pid < best))
            best = pid;
    }
    (void)closedir(d);
    return best;
}

/* True when /proc/<pid>/status says the process catches SIGUSR1. */
static bool app_proc_catches_usr1(long pid, bool *known)
{
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%ld/status", pid);
    FILE *f = fopen(path, "re");
    *known = false;
    if (!f)
        return false;
    unsigned long long mask = 0;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "SigCgt:", 7) == 0) {
            *known = sscanf(line + 7, "%llx", &mask) == 1;
            break;
        }
    (void)fclose(f);
    return *known && (mask & (1ULL << (SIGUSR1 - 1))) != 0;
}

#elif defined(__APPLE__)

static bool app_os_identity(long pid, char exe[APP_LAUNCH_PATH_MAX],
                            uint64_t *start_time)
{
    struct proc_bsdinfo info;
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (pid <= 1 || app_proc_reaped(pid) ||
        proc_pidinfo((pid_t)pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) !=
            (int)sizeof(info) ||
        info.pbi_status == SZOMB ||
        proc_pidpath((pid_t)pid, path, sizeof(path)) <= 0 ||
        strlen(path) >= APP_LAUNCH_PATH_MAX)
        return false;
    memcpy(exe, path, strlen(path) + 1);
    *start_time = (uint64_t)info.pbi_start_tvsec * 1000000u +
                  (uint64_t)info.pbi_start_tvusec;
    return true;
}

static long app_os_scan(const char *exe)
{
    (void)exe; /* only the pid record identifies an instance on macOS */
    return 0;
}

#else

static bool app_os_identity(long pid, char exe[APP_LAUNCH_PATH_MAX],
                            uint64_t *start_time)
{
    (void)pid; (void)exe; (void)start_time;
    return false;
}

static long app_os_scan(const char *exe)
{
    (void)exe;
    return 0;
}

#endif

/* Whether text holds needle (text may hold NUL bytes). */
static bool app_text_has(const char *text, size_t len, const char *needle)
{
    size_t n = strlen(needle);
    if (n == 0 || n > len)
        return false;
    for (size_t i = 0; i + n <= len; i++)
        if (text[i] == needle[0] && memcmp(text + i, needle, n) == 0)
            return true;
    return false;
}

/* Whether the first APP_LOG_SCAN_MAX bytes of path hold needle. */
static bool app_log_has(const char *path, const char *needle)
{
    static char buf[APP_LOG_SCAN_MAX];
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    ssize_t n = read(fd, buf, sizeof(buf));
    (void)close(fd);
    return n > 0 && app_text_has(buf, (size_t)n, needle);
}

static bool app_log_fd_has(int fd, const char *needle)
{
    static char buf[APP_LOG_SCAN_MAX];
    ssize_t n = pread(fd, buf, sizeof(buf), 0);
    return n > 0 && app_text_has(buf, (size_t)n, needle);
}

static enum app_raise_outcome app_os_raise(long pid, char *note,
                                           size_t note_size)
{
#if defined(__linux__)
    bool known = false;
    bool handles = app_proc_catches_usr1(pid, &known);
    if (!known) {
        snprintf(note, note_size, "cannot read the process signal mask");
        return APP_RAISE_FAILED;
    }
    if (!handles) {
        snprintf(note, note_size, "the app declares raise support but this "
                 "copy has no SIGUSR1 handler; nothing was sent");
        return APP_RAISE_NO_HANDLER;
    }
#endif
    if (kill((pid_t)pid, SIGUSR1) != 0) {
        snprintf(note, note_size, "SIGUSR1 failed: %s", strerror(errno));
        return APP_RAISE_FAILED;
    }
    snprintf(note, note_size, "sent SIGUSR1");
    return APP_RAISE_DELIVERED;
}

/* ── spawn ────────────────────────────────────────────────────────────── */

static bool app_spawn_actions(posix_spawn_file_actions_t *fa, int logfd)
{
    bool ok =
        posix_spawn_file_actions_addopen(fa, 0, "/dev/null", O_RDONLY, 0) == 0 &&
        posix_spawn_file_actions_adddup2(fa, logfd, 1) == 0 &&
        posix_spawn_file_actions_adddup2(fa, logfd, 2) == 0;
#if defined(__GLIBC__) && (__GLIBC__ > 2 || __GLIBC_MINOR__ >= 34)
    ok = ok && posix_spawn_file_actions_addclosefrom_np(fa, 3) == 0;
#else
    /* Close every descriptor this process holds above 2 (the log fd is
     * O_CLOEXEC; its duplicates on 1 and 2 are not). */
    int fds[256];
    unsigned nfds = 0;
    DIR *d = opendir("/dev/fd");
    if (d) {
        int self = dirfd(d);
        for (struct dirent *de = readdir(d); de && nfds < 256; de = readdir(d)) {
            int fd = atoi(de->d_name);
            if (fd > 2 && fd != self)
                fds[nfds++] = fd;
        }
        (void)closedir(d);
    }
    for (unsigned i = 0; ok && i < nfds; i++)
        ok = posix_spawn_file_actions_addclose(fa, fds[i]) == 0;
#endif
    return ok;
}

static bool app_spawn_attrs(posix_spawnattr_t *at)
{
    sigset_t defaults, empty;
    short flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    (void)sigemptyset(&empty);
    (void)sigemptyset(&defaults);
    (void)sigaddset(&defaults, SIGPIPE);
    (void)sigaddset(&defaults, SIGTERM);
    (void)sigaddset(&defaults, SIGINT);
    (void)sigaddset(&defaults, SIGHUP);
    (void)sigaddset(&defaults, SIGUSR1);
    (void)sigaddset(&defaults, SIGCHLD);
#if defined(POSIX_SPAWN_SETSID)
    flags |= POSIX_SPAWN_SETSID;
#else
    flags |= POSIX_SPAWN_SETPGROUP;
    if (posix_spawnattr_setpgroup(at, 0) != 0)
        return false;
#endif
    return posix_spawnattr_setsigdefault(at, &defaults) == 0 &&
           posix_spawnattr_setsigmask(at, &empty) == 0 &&
           posix_spawnattr_setflags(at, flags) == 0;
}

static int app_spawn(const struct app_launch_entry *entry, int logfd,
                     pid_t *pid)
{
    char *argv[APP_LAUNCH_ARGS_MAX + 2];
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    argv[0] = (char *)entry->executable;
    for (unsigned i = 0; i < entry->arg_count; i++)
        argv[i + 1] = (char *)entry->args[i];
    argv[entry->arg_count + 1] = NULL;
    if (posix_spawn_file_actions_init(&fa) != 0)
        return ENOMEM;
    if (posix_spawnattr_init(&at) != 0) {
        (void)posix_spawn_file_actions_destroy(&fa);
        return ENOMEM;
    }
    int rc = app_spawn_actions(&fa, logfd) && app_spawn_attrs(&at)
                 ? posix_spawn(pid, entry->executable, &fa, &at, argv, environ)
                 : EINVAL;
    (void)posix_spawnattr_destroy(&at);
    (void)posix_spawn_file_actions_destroy(&fa);
    return rc;
}

/* One poll: exited (reaped here), ready, or neither. */
static bool app_wait_step(pid_t pid, const struct app_launch_entry *entry,
                          const char *log_path, int logfd, int64_t elapsed, int settle_ms,
                          struct app_spawn_outcome *out)
{
    int status = 0;
    pid_t waited = waitpid(pid, &status, WNOHANG);
    if (waited < 0 && errno != EINTR && logfd >= 0) {
        out->spawn_errno = errno;
        return true;
    }
    if (waited == pid) {
        out->exited = true;
        out->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        out->term_signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        return true;
    }
    if (entry->ready_marker[0] ? (logfd >= 0 ? app_log_fd_has(logfd, entry->ready_marker) : app_log_has(log_path, entry->ready_marker))
                               : elapsed >= settle_ms) {
        out->ready = true;
        out->ready_ms = elapsed;
        return true;
    }
    return false;
}

static bool app_os_spawn_and_wait(const struct app_launch_entry *entry,
                                  const char *log_path, int timeout_ms,
                                  int settle_ms, struct app_spawn_outcome *out)
{
    pid_t pid = 0;
    memset(out, 0, sizeof(*out));
    int logfd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                                   O_NOFOLLOW, 0600);
    if (logfd < 0) {
        out->spawn_errno = errno;
        LOG_ERROR("app-launch", "cannot open app log %s: %s", log_path,
                  strerror(errno));
        return false;
    }
    int rc = app_spawn(entry, logfd, &pid);
    (void)close(logfd);
    if (rc != 0) {
        out->spawn_errno = rc;
        LOG_ERROR("app-launch", "posix_spawn %s: %s", entry->executable,
                  strerror(rc));
        return false;
    }
    out->pid = (long)pid;
    int64_t start = platform_time_monotonic_ms();
    for (;;) {
        int64_t elapsed = platform_time_monotonic_ms() - start;
        if (app_wait_step(pid, entry, log_path, -1, elapsed, settle_ms, out) ||
            elapsed >= timeout_ms)
            return true;
        platform_sleep_ms(APP_POLL_MS);
    }
}

static bool app_resident_wait(const struct app_launch_entry *entry,
                              int logfd,
                              int timeout_ms, int settle_ms,
                              struct app_spawn_outcome *out)
{
    int64_t start = platform_time_monotonic_ms();
    for (;;) {
        int64_t elapsed = platform_time_monotonic_ms() - start;
        if (app_wait_step((pid_t)out->pid, entry, NULL, logfd, elapsed, settle_ms, out) ||
            elapsed >= timeout_ms) return out->spawn_errno == 0;
        platform_sleep_ms(APP_POLL_MS);
    }
}

/* The last lines of the log, printable ASCII and newlines only. */
static void app_os_log_tail(const char *path, char *out, size_t out_size)
{
    char buf[APP_LAUNCH_TAIL_MAX * 2];
    struct stat st;
    out[0] = '\0';
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return;
    off_t from = 0;
    if (fstat(fd, &st) == 0 && st.st_size > (off_t)sizeof(buf) - 1)
        from = st.st_size - (off_t)(sizeof(buf) - 1);
    ssize_t n = pread(fd, buf, sizeof(buf) - 1, from);
    (void)close(fd);
    if (n <= 0)
        return;
    size_t len = (size_t)n, at = 0;
    if (len >= out_size)
        at = len - (out_size - 1);
    while (at > 0 && at < len && buf[at - 1] != '\n')
        at++;
    size_t w = 0;
    for (; at < len && w + 1 < out_size; at++) {
        unsigned char c = (unsigned char)buf[at];
        out[w++] = (c == '\n' || (c >= 0x20 && c < 0x7f)) ? (char)c : '?';
    }
    out[w] = '\0';
}

#endif /* !_WIN32 */

/* ── public entry points: one definition each ─────────────────────────── */

bool app_proc_identity(long pid, char exe[APP_LAUNCH_PATH_MAX],
                       uint64_t *start_time)
{
#if defined(_WIN32)
    (void)pid; (void)exe; (void)start_time;
    return false;
#else
    return app_os_identity(pid, exe, start_time);
#endif
}

long app_proc_scan(const char *exe)
{
#if defined(_WIN32)
    (void)exe;
    return 0;
#else
    return app_os_scan(exe);
#endif
}

enum app_raise_outcome app_proc_raise(long pid, char *note, size_t note_size)
{
#if defined(_WIN32)
    (void)pid;
    snprintf(note, note_size, "raise is not supported on Windows");
    return APP_RAISE_FAILED;
#else
    return app_os_raise(pid, note, note_size);
#endif
}

bool app_proc_spawn_and_wait(const struct app_launch_entry *entry,
                             const char *log_path, int timeout_ms,
                             int settle_ms, struct app_spawn_outcome *out)
{
#if defined(_WIN32)
    (void)entry; (void)log_path; (void)timeout_ms; (void)settle_ms;
    memset(out, 0, sizeof(*out));
    out->spawn_errno = ENOSYS;
    return false;
#else
    return app_os_spawn_and_wait(entry, log_path, timeout_ms, settle_ms, out);
#endif
}

bool app_proc_resident_spawn_and_wait(const struct app_launch_entry *entry,
                                     struct resident_launch *prepared,
                                     const char *log_path, int timeout_ms,
                                     int settle_ms, struct resident_receipt *receipt,
                                     struct app_spawn_outcome *out,
                                     char *error, size_t error_size)
{
    if (!out) { resident_launch_close(prepared); errno = EINVAL; return false; }
    memset(out, 0, sizeof(*out));
    if (!entry || !prepared || !receipt || !log_path || entry->arg_count > APP_LAUNCH_ARGS_MAX) {
        out->spawn_errno = EINVAL;
        resident_launch_close(prepared);
        return false;
    }
#if defined(_WIN32)
    (void)entry; (void)log_path; (void)timeout_ms; (void)settle_ms;
    (void)receipt; (void)error; (void)error_size;
    out->spawn_errno = ENOSYS;
    resident_launch_close(prepared);
    return false;
#else
    int logfd = open(log_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (logfd < 0) {
        out->spawn_errno = errno;
        resident_launch_close(prepared);
        return false;
    }
    char *argv[APP_LAUNCH_ARGS_MAX + 2];
    argv[0] = (char *)entry->executable;
    for (unsigned i = 0; i < entry->arg_count; ++i) argv[i + 1] = (char *)entry->args[i];
    argv[entry->arg_count + 1] = NULL;
    prepared->desktop_signals = true;
    prepared->log_stdio = true;
    prepared->log_stdio_fd = logfd;
    bool spawned = resident_launch_spawn(prepared, argv, environ, receipt, error, error_size);
    if (spawned) {
        out->pid = receipt->pid;
        if (!app_resident_wait(entry, logfd, timeout_ms, settle_ms, out)) {
            (void)resident_launch_cancel(prepared, 20, error, error_size);
            spawned = false;
        }
    } else out->spawn_errno = errno;
    close(logfd);
    resident_launch_close(prepared);
    return spawned;
#endif
}

void app_proc_log_tail(const char *path, char *out, size_t out_size)
{
#if defined(_WIN32)
    (void)path;
    if (out_size)
        out[0] = '\0';
#else
    app_os_log_tail(path, out, out_size);
#endif
}
