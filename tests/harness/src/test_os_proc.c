/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the platform os_proc introspection shim
 * (platform/modules/platform/src/os_proc.c) — Rung 1, docs/adr/0003-os-substrate-
 * verdict.md.
 *
 * Coverage:
 *   - real os_proc_mem_read() returns a sane VmRSS for this live process
 *   - real os_proc_uptime_seconds() returns a non-negative age
 *   - real os_proc_exe_path() resolves to an existing, absolute path
 *   - os_proc_mem_set_override() forces every subsequent read; NULL clears
 *   - os_proc_cgroup_dir() either resolves a real path or reports
 *     unavailable — never garbage
 *   - os_proc_cgroup_mem_stat_read() parses a memory.stat fixture in one
 *     pass, whole-key ("file" never reads the file_mapped/file_dirty/
 *     file_writeback rows listed before it), and reports -1 — never 0 — for
 *     a row, a file or a cgroup that is not there
 *   - the Seccomp_filters status-text parser requires the trailing '\n'
 *     after the digits, so a status read truncated mid-number fails closed
 *     instead of returning a short-read digit prefix
 *   - os_proc_self_maps_read() returns the whole mapping table or refuses
 *   - platform_allocator_arena_cap() picks the default glibc arena cap of 4
 *     unless the operator set MALLOC_ARENA_MAX or a glibc.malloc.arena_max tunable
 */

#include "test/test_core.h"
#include "platform/allocator_compat.h"
#include "platform/disk_space.h"
#include "platform/os_proc.h"
#include "platform/ram_scratch.h"
#include "platform/temp_directory.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <dirent.h>
#include <sys/file.h>
#endif

#define OSPROC_CHECK(name, expr) do { \
    printf("os_proc: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Write `body` as the memory.stat of a fixture cgroup directory. */
static bool write_cgroup_memory_stat(const char *dir, const char *body)
{
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/memory.stat", dir);
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    fputs(body, f);
    fclose(f);
    return true;
}

/* The whole-key guarantee os_proc.h documents. Its own function so each
 * fixture shape stays well under the complexity cap. */
static int cgroup_stat_whole_key_checks(const char *dir)
{
    int failures = 0;
    /* 12 GiB ceiling, ~10.2 GiB charged, ~7 GiB page cache, RSS 3.68 GiB.
     *
     * file_mapped, file_dirty and file_writeback are listed BEFORE `file` so
     * a matcher that does not require the separating space reads 134217728
     * for `file` and the test fails. */
    if (!write_cgroup_memory_stat(dir, "anon 3951034368\n"
                                       "file_mapped 134217728\n"
                                       "file_dirty 268435456\n"
                                       "file_writeback 134217728\n"
                                       "file 7516192768\n"
                                       "kernel 268435456\n"
                                       "shmem 1073741824\n"
                                       "unevictable 536870912\n"
                                       "slab 201326592\n")) {
        printf("os_proc: cgroup memory.stat fixture write... FAIL\n");
        return 1;
    }

    struct os_proc_cgroup_mem_stat stat;
    OSPROC_CHECK("memory.stat fixture reads in one pass",
                 os_proc_cgroup_mem_stat_read(dir, &stat));
    OSPROC_CHECK("file reads whole-key, not the file_* rows listed first",
                 stat.file == 7516192768);
    OSPROC_CHECK("memory.stat shmem row", stat.shmem == 1073741824);
    OSPROC_CHECK("memory.stat unevictable row", stat.unevictable == 536870912);
    OSPROC_CHECK("memory.stat file_dirty row", stat.file_dirty == 268435456);
    OSPROC_CHECK("memory.stat file_writeback row",
                 stat.file_writeback == 134217728);
    return failures;
}

/* What the parser reports when a row, the file, or the cgroup is missing:
 * always -1 for that row, never a plausible-looking zero. */
static int cgroup_stat_degrade_checks(const char *dir)
{
    int failures = 0;
    if (!write_cgroup_memory_stat(dir, "file 7516192768\n"
                                       "shmem 0\n"
                                       "unevictable 0\n"
                                       "file_dirty 0\n")) {
        printf("os_proc: partial memory.stat fixture write... FAIL\n");
        return 1;
    }

    struct os_proc_cgroup_mem_stat stat;
    OSPROC_CHECK("a memory.stat missing a row still reads",
                 os_proc_cgroup_mem_stat_read(dir, &stat));
    OSPROC_CHECK("the missing row alone reads unavailable",
                 stat.file_writeback == -1 && stat.file == 7516192768);
    OSPROC_CHECK("a NULL dir reads nothing and says so",
                 !os_proc_cgroup_mem_stat_read(NULL, &stat));
    OSPROC_CHECK("a NULL dir leaves every row unavailable",
                 stat.file == -1 && stat.shmem == -1 &&
                 stat.unevictable == -1 && stat.file_dirty == -1 &&
                 stat.file_writeback == -1);

    char missing[PATH_MAX + 16];
    snprintf(missing, sizeof(missing), "%s/gone", dir);
    OSPROC_CHECK("a cgroup dir with no memory.stat says so",
                 !os_proc_cgroup_mem_stat_read(missing, &stat));
    return failures;
}

/* memory.stat parser fixture. Its own function so test_os_proc gains a
 * single zero-branch call and keeps its exact complexity pin. */
static int os_proc_cgroup_stat_fixture_checks(void)
{
    char dir[PATH_MAX];
    if (!test_mkdtemp(dir, sizeof(dir), "os_proc_cgroup")) {
        printf("os_proc: cgroup memory.stat fixture mkdtemp... FAIL\n");
        return 1;
    }
    int failures = cgroup_stat_whole_key_checks(dir);
    failures += cgroup_stat_degrade_checks(dir);
    test_rm_rf_recursive(dir);
    return failures;
}

/* A descriptor above the child's lowered limit is still inherited. The
 * report pipe must survive the scrub while that unrelated descriptor dies. */
#if !defined(_WIN32)
static void os_proc_close_if_open(int fd)
{
    if (fd >= 0) (void)close(fd);
}

static int os_proc_report_limit_prepare(rlim_t want, struct rlimit *saved)
{
    if (getrlimit(RLIMIT_NOFILE, saved) != 0) {
        fprintf(stderr, "os_proc: getrlimit fixture setup: %s\n", strerror(errno));
        return 1;
    }
    if (saved->rlim_max != RLIM_INFINITY && saved->rlim_max <= want) {
        printf("os_proc: high FD scrub... UNOBSERVED (hard limit %llu <= %llu)\n",
               (unsigned long long)saved->rlim_max, (unsigned long long)want);
        return 77;
    }
    struct rlimit raised = *saved;
    if (raised.rlim_cur > want) return 0;
    raised.rlim_cur = want + 1;
    if (setrlimit(RLIMIT_NOFILE, &raised) == 0) return 0;
    fprintf(stderr, "os_proc: raise fixture soft limit: %s\n", strerror(errno));
    return 1;
}

static void os_proc_preserved_report_child(int report[2], int high)
{
    (void)close(report[0]);
    struct rlimit limit;
    bool bounded = getrlimit(RLIMIT_NOFILE, &limit) == 0;
    if (bounded && limit.rlim_cur > 64) {
        limit.rlim_cur = 64;
        bounded = setrlimit(RLIMIT_NOFILE, &limit) == 0;
    }
    bool scrubbed = bounded &&
        os_proc_close_inherited_fds_except(report[1]);
    bool high_closed = fcntl(high, F_GETFD) == -1 && errno == EBADF;
    bool report_open = fcntl(report[1], F_GETFD) >= 0;
    char result = scrubbed && high_closed && report_open ? 'Y' : 'N';
     TEST_DISCARD(write(report[1], &result, 1));
    _exit(result == 'Y' ? 0 : 1);
}

static int os_proc_preserved_report_parent(int report[2], int secret[2],
                                            int high, pid_t child)
{
    int failures = 0;
    os_proc_close_if_open(report[1]);
    os_proc_close_if_open(secret[0]);
    os_proc_close_if_open(secret[1]);
    os_proc_close_if_open(high);
    char result = 0;
    ssize_t got = report[0] >= 0 ? read(report[0], &result, 1) : -1;
    os_proc_close_if_open(report[0]);
    int status = 0;
    pid_t waited = child > 0 ? waitpid(child, &status, 0) : -1;
    if (child <= 0 || waited != child || got != 1 || result != 'Y')
        fprintf(stderr, "os_proc: scrub witness child=%ld waited=%ld bytes=%ld result=%d status=%d\n",
                (long)child, (long)waited, (long)got, (int)result, status);
    OSPROC_CHECK("scrub preserves report and closes inherited high FD",
                 child > 0 && waited == child && got == 1 && result == 'Y' &&
                 WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return failures;
}
#endif

static int os_proc_preserved_report_fd_checks(void)
{
#if defined(_WIN32)
    return 0;
#else
    int failures = 0;
    int report[2] = {-1, -1}, secret[2] = {-1, -1};
    int high = -1;
    pid_t child = -1;
#if defined(__linux__)
    const int want = 70000;
#else
    const int want = 200;
#endif
    struct rlimit saved;
    int setup = os_proc_report_limit_prepare((rlim_t)want, &saved);
    if (setup != 0) return setup == 77 ? 0 : 1;
    bool ready = pipe(report) == 0 && pipe(secret) == 0;
    if (ready) high = fcntl(secret[0], F_DUPFD, want);
    if (!ready || high < 0)
        fprintf(stderr, "os_proc: pipe/high FD fixture setup: %s\n", strerror(errno));
    if (ready && high >= 0) child = fork();
    if (child == 0) os_proc_preserved_report_child(report, high);
    if (ready && high >= 0 && child < 0)
        fprintf(stderr, "os_proc: fork scrub fixture: %s\n", strerror(errno));
    bool restored = setrlimit(RLIMIT_NOFILE, &saved) == 0;
    if (!restored)
        fprintf(stderr, "os_proc: restore fixture soft limit: %s\n", strerror(errno));
    OSPROC_CHECK("restore caller descriptor limit", restored);
    failures += os_proc_preserved_report_parent(report, secret, high, child);
    OSPROC_CHECK("invalid report FD refuses before closing anything",
                 !os_proc_close_inherited_fds_except(-1) && errno == EINVAL);
    return failures;
#endif
}

/* Only async-signal-safe operations occur between fork and exec. */
#if defined(__linux__)
static bool os_proc_image_exec_probe(int image_fd, int control_fd)
{
    char image_arg[32], control_arg[32];
    int a = snprintf(image_arg, sizeof(image_arg), "%d", image_fd);
    int b = snprintf(control_arg, sizeof(control_arg), "%d", control_fd);
    if (a < 0 || (size_t)a >= sizeof(image_arg) ||
        b < 0 || (size_t)b >= sizeof(control_arg))
        return false;
    pid_t child = fork();
    if (child == 0) {
        execl("/bin/sh", "sh", "-c",
              "test ! -e /proc/self/fd/\"$1\" && "
              "test -e /proc/self/fd/\"$2\"", "sh", image_arg,
              control_arg, (char *)NULL);
        _exit(127);
    }
    if (child < 0)
        return false;
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

static int os_proc_image_cloexec_checks(void)
{
    int failures = 0;
#if defined(__linux__)
    /* Keep the image above shell-internal low descriptors, without replacing
     * or duplicating the descriptor returned by the production API. */
    int padding[32];
    size_t count = 0;
    for (; count < sizeof(padding) / sizeof(padding[0]); ++count) {
        padding[count] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (padding[count] < 0) break;
    }
    FILE *image = count == sizeof(padding) / sizeof(padding[0])
        ? os_proc_open_self_exe() : NULL;
    int image_fd = image ? fileno(image) : -1;
    while (count > 0) (void)close(padding[--count]);
    int source = open("/dev/null", O_RDONLY);
    int control = source >= 0 ? fcntl(source, F_DUPFD, 200) : -1;
    if (source >= 0) (void)close(source);
    int flags = image_fd >= 0 ? fcntl(image_fd, F_GETFD) : -1;
    OSPROC_CHECK("self image is close-on-exec before any child starts",
                 flags >= 0 && (flags & FD_CLOEXEC) != 0);
    bool child_ok = image_fd >= 0 && control >= 0 && control != image_fd &&
                    os_proc_image_exec_probe(image_fd, control);
    OSPROC_CHECK("real exec closes self image but preserves control descriptor",
                 child_ok);
    if (control >= 0) (void)close(control);
    if (image) (void)fclose(image);
#endif
    return failures;
}

static int os_proc_open_fd_count_checks(void)
{
    int failures = 0;
#if !defined(_WIN32)
    size_t before = 0, open_count = 0, after = 0;
    bool counted = os_proc_open_fd_count(&before);
    int source = open("/dev/null", O_RDONLY);
    int high = source >= 0 ? fcntl(source, F_DUPFD, 200) : -1;
    if (source >= 0) (void)close(source);
    bool counted_open = high >= 0 && os_proc_open_fd_count(&open_count);
    if (high >= 0) (void)close(high);
    bool counted_after = os_proc_open_fd_count(&after);
    OSPROC_CHECK("high descriptor contributes exactly one live fd",
                 counted && counted_open && open_count == before + 1);
    OSPROC_CHECK("closing high descriptor restores live fd count",
                 counted && counted_after && after == before);
#endif
    return failures;
}

/* Seccomp_filters status-text parser: a truncated read must fail closed,
 * never return the digit prefix it happened to have in the buffer. */
static int os_proc_seccomp_filters_parse_checks(void)
{
    int failures = 0;
#if defined(ZCL_TESTING) && defined(__linux__)
    uint32_t out = 12345;
    /* "Seccomp_filters: 12" cut down to "1": no trailing newline. */
    OSPROC_CHECK("a digit run truncated before '\\n' fails closed",
                 !os_proc_parse_seccomp_filters_for_test(
                     "Name:\tz23\n"
                     "\nSeccomp_filters:\t1", &out));
    OSPROC_CHECK("a failed parse leaves no stale value behind",
                 out == 12345);

    out = 0;
    OSPROC_CHECK("a correctly terminated field parses",
                 os_proc_parse_seccomp_filters_for_test(
                     "Name:\tz23\n"
                     "\nSeccomp_filters:\t2\n"
                     "Cpus_allowed:\tff\n", &out));
    OSPROC_CHECK("the correctly terminated field's value is observed",
                 out == 2);
#endif
    return failures;
}

/* os_proc_self_exe_open_path() hands back "/proc/self/exe" verbatim, which
 * the kernel re-resolves to the CURRENT inode on every traversal. Opening
 * by this path and via os_proc_open_self_exe() must name the same file. */
static int os_proc_self_exe_open_path_checks(void)
{
    int failures = 0;
    char path[4096];
    bool ok = os_proc_self_exe_open_path(path, sizeof(path));
    OSPROC_CHECK("self_exe_open_path resolves", ok);
    OSPROC_CHECK("self_exe_open_path is absolute", ok && path[0] == '/');
    struct stat by_path;
    bool by_path_ok = ok && stat(path, &by_path) == 0;
    OSPROC_CHECK("self_exe_open_path names an existing file", by_path_ok);
    FILE *pinned = os_proc_open_self_exe();
    struct stat by_pinned;
    bool by_pinned_ok = pinned && fstat(fileno(pinned), &by_pinned) == 0;
    if (pinned)
        fclose(pinned);
    OSPROC_CHECK("self_exe_open_path identifies the same running image "
                 "os_proc_open_self_exe() pins (dev/inode/size/mtime)",
                 by_path_ok && by_pinned_ok &&
                 by_path.st_dev == by_pinned.st_dev &&
                 by_path.st_ino == by_pinned.st_ino &&
                 by_path.st_size == by_pinned.st_size &&
                 by_path.st_mtime == by_pinned.st_mtime);
    return failures;
}

/* self maps read: on Linux the whole mapping table comes back NUL-terminated
 * with its exact length and names this process's own image; a cap smaller
 * than the table refuses (NULL) instead of returning a truncated prefix a
 * caller could mistake for the complete library set. Elsewhere the platform
 * keeps no such table and the read reports no evidence. */
static int os_proc_self_maps_read_checks(void)
{
    int failures = 0;
    size_t len = 7;
    char *maps = os_proc_self_maps_read(4u << 20, &len);
#if defined(__linux__)
    OSPROC_CHECK("self_maps_read returns the table", maps != NULL);
    OSPROC_CHECK("self_maps_read length matches the NUL-terminated text",
                 maps && len > 0 && strlen(maps) == len);
    OSPROC_CHECK("self_maps_read lists at least one mapped file",
                 maps && strchr(maps, '/') != NULL);
    char *capped = os_proc_self_maps_read(8, NULL);
    OSPROC_CHECK("self_maps_read refuses a table larger than its cap",
                 capped == NULL);
    free(capped);
#else
    OSPROC_CHECK("self_maps_read reports no evidence off Linux",
                 maps == NULL && len == 0);
#endif
    free(maps);
    return failures;
}

/* Kernel-release classification and a live environment observation. */
static int os_proc_environment_classify_checks(void)
{
    int failures = 0;
    OSPROC_CHECK("native Linux release classification",
                 os_proc_environment_classify_kernel_release(
                     "6.12.8-generic") == OS_PROC_ENVIRONMENT_NATIVE);
    OSPROC_CHECK("WSL2 release classification",
                 os_proc_environment_classify_kernel_release(
                     "5.15.153.1-microsoft-standard-WSL2") ==
                     OS_PROC_ENVIRONMENT_WSL);
    OSPROC_CHECK("WSL classification is case-insensitive",
                 os_proc_environment_classify_kernel_release(
                     "4.4.0-MICROSOFT") == OS_PROC_ENVIRONMENT_WSL);
    OSPROC_CHECK("missing release remains unknown",
                 os_proc_environment_classify_kernel_release(NULL) ==
                     OS_PROC_ENVIRONMENT_UNKNOWN);
    OSPROC_CHECK("live environment is observed",
                 os_proc_environment_observe() !=
                     OS_PROC_ENVIRONMENT_UNKNOWN);
    return failures;
}

/* Real reads against this live process: RSS, cgroup and system totals. */
static int os_proc_live_mem_read_checks(void)
{
    int failures = 0;
    /* ── real reads: this live process ───────────────────────────── */
    os_proc_mem_set_override(NULL);

    struct os_proc_mem mem;
    bool ok = os_proc_mem_read(&mem);
    OSPROC_CHECK("mem_read succeeds for live process", ok);
    OSPROC_CHECK("live RSS is positive and sane (<64GB)",
                 mem.rss_bytes > 0 &&
                 mem.rss_bytes < (int64_t)64 * 1024 * 1024 * 1024);
    /* cgroup fields may legitimately be -1 (no cgroup v2 / no limit
     * configured) — only assert they are never a bogus negative other
     * than the -1 sentinel. */
    OSPROC_CHECK("cgroup_current is -1 or non-negative",
                 mem.cgroup_current == -1 || mem.cgroup_current >= 0);
    OSPROC_CHECK("cgroup_high is -1 or positive",
                 mem.cgroup_high == -1 || mem.cgroup_high > 0);
    OSPROC_CHECK("cgroup_max is -1 or positive",
                 mem.cgroup_max == -1 || mem.cgroup_max > 0);
    OSPROC_CHECK("sys_total_bytes is sane (>0, <can't-exist)",
                 mem.sys_total_bytes > 0);
    OSPROC_CHECK("sys_avail_bytes is -1 or non-negative",
                 mem.sys_avail_bytes >= -1);
    OSPROC_CHECK("sys_avail_bytes <= sys_total_bytes",
                 mem.sys_avail_bytes <= mem.sys_total_bytes);
#if defined(__APPLE__)
    OSPROC_CHECK("Darwin publishes reclaimable host memory",
                 mem.sys_avail_bytes >= 0);
#endif
    return failures;
}

/* Process age sanity. */
static int os_proc_uptime_checks(void)
{
    int failures = 0;
    /* ── uptime ───────────────────────────────────────────────────── */
    int64_t age = os_proc_uptime_seconds();
    OSPROC_CHECK("uptime_seconds is non-negative", age >= 0);
    /* Sanity ceiling of 10 years catches a units bug (ticks vs seconds). */
    OSPROC_CHECK("uptime_seconds is not absurdly large",
                 age < (int64_t)10 * 365 * 24 * 3600);
    return failures;
}

/* Stable process-birth identity tokens for this pid. */
static int os_proc_pid_start_token_checks(void)
{
    int failures = 0;
    /* ── stable process-birth identity ───────────────────────────── */
    uint64_t first = 0, second = 0;
    uint64_t self = os_proc_current_pid();
    OSPROC_CHECK("current pid is nonzero", self != 0);
    OSPROC_CHECK("current process start token resolves",
                 os_proc_pid_start_token(self, &first));
    OSPROC_CHECK("current process start token is nonzero", first != 0);
    OSPROC_CHECK("start token is stable across repeated reads",
                 os_proc_pid_start_token(self, &second) &&
                 second == first);
    OSPROC_CHECK("start token refuses pid zero",
                 !os_proc_pid_start_token(0, &second));
    OSPROC_CHECK("start token refuses a NULL output",
                 !os_proc_pid_start_token(self, NULL));
#if defined(__APPLE__)
    OSPROC_CHECK("Darwin start token refuses a non-pid_t value",
                 !os_proc_pid_start_token(UINT32_MAX, &second));
#endif
    return failures;
}

/* exe_path resolves to an existing absolute path. */
static int os_proc_exe_path_checks(void)
{
    int failures = 0;
    /* ── exe path ─────────────────────────────────────────────────── */
    char path[4096];
    bool ok = os_proc_exe_path(path, sizeof(path));
    OSPROC_CHECK("exe_path resolves", ok);
    OSPROC_CHECK("exe_path is absolute", ok && path[0] == '/');
    struct stat st;
    OSPROC_CHECK("exe_path names an existing file",
                 ok && stat(path, &st) == 0);
    return failures;
}

/* open_self_exe hands back real bytes of the running image. */
static int os_proc_open_self_exe_read_checks(void)
{
    int failures = 0;
    /* ── open self exe ────────────────────────────────────────────── */
    FILE *fp = os_proc_open_self_exe();
    OSPROC_CHECK("open_self_exe returns a non-NULL FILE*", fp != NULL);
    if (fp) {
        unsigned char buf[64];
        size_t n = fread(buf, 1, sizeof(buf), fp);
        /* The running test binary is always well over 64 bytes; a
         * short read here would mean we opened the wrong thing. */
        OSPROC_CHECK("open_self_exe reads real bytes from the running image",
                     n == sizeof(buf));
        fclose(fp);
    }
    return failures;
}

/* The published running-image identity rung matches reality. */
static int os_proc_self_exe_identity_rung_checks(void)
{
    int failures = 0;
    /* ── running-image identity rung ──────────────────────────────── */
    /* The rung is published as diagnostics `binary_identity_scope`: the
     * strong rung requires opening the image without resolving a
     * pathname, and any rung requires the open to work. */
    enum os_proc_image_identity rung = os_proc_self_exe_identity();
#if defined(__linux__)
    /* Linux earns RUNNING_IMAGE and only Linux: /proc/self/exe is the
     * kernel's exe_file reference, no name lookup anywhere in it. */
    OSPROC_CHECK("linux publishes the kernel-pinned running-image rung",
                 rung == OS_PROC_IMAGE_IDENTITY_RUNNING_IMAGE);
#elif defined(_WIN32) || defined(__APPLE__)
    /* Both reopen BY NAME (GetModuleFileNameW / _NSGetExecutablePath),
     * so both are honestly the weaker rung -- never RUNNING_IMAGE. */
    OSPROC_CHECK("pathname reopen publishes the weaker resolved-path rung",
                 rung == OS_PROC_IMAGE_IDENTITY_RESOLVED_PATH);
#else
    OSPROC_CHECK("platform with no running-image read reports unavailable",
                 rung == OS_PROC_IMAGE_IDENTITY_UNAVAILABLE);
#endif
    /* A rung that cannot open the image is an overclaim; an UNAVAILABLE
     * rung on a platform that opens it is stale. */
    FILE *probe = os_proc_open_self_exe();
    bool opened = probe != NULL;
    if (probe)
        fclose(probe);
    OSPROC_CHECK("identity rung agrees with whether the image opens",
                 opened == (rung != OS_PROC_IMAGE_IDENTITY_UNAVAILABLE));
    return failures;
}

/* cgroup_dir resolves cleanly or reports unavailable. */
static int os_proc_cgroup_dir_checks(void)
{
    int failures = 0;
    /* ── cgroup dir ───────────────────────────────────────────────── */
    char dir[768];
    bool ok = os_proc_cgroup_dir(dir, sizeof(dir));
    /* Either resolves to a real, non-empty absolute path, or reports
     * unavailable — never a torn/partial buffer. */
    if (ok) {
        OSPROC_CHECK("cgroup_dir non-empty when resolved", dir[0] != '\0');
        OSPROC_CHECK("cgroup_dir absolute when resolved", dir[0] == '/');
    } else {
        OSPROC_CHECK("cgroup_dir false is a clean 'unavailable'", true);
    }

    /* Undersized buffer must fail cleanly, not overflow/crash. */
    char tiny[1];
    bool tiny_ok = os_proc_cgroup_dir(tiny, sizeof(tiny));
    OSPROC_CHECK("cgroup_dir with a 1-byte buffer never claims success",
                 !tiny_ok);
    return failures;
}

/* The mem override seam: force, replace, clear. */
static int os_proc_mem_override_seam_checks(void)
{
    int failures = 0;
    /* ── override seam ────────────────────────────────────────────── */
    struct os_proc_mem forced = {
        .rss_bytes = 123456789,
        .vsize_bytes = 987654321,
        .cgroup_current = 100,
        .cgroup_high = 200,
        .cgroup_max = 300,
        .sys_total_bytes = 1000,
        .sys_avail_bytes = 500,
    };
    os_proc_mem_set_override(&forced);

    struct os_proc_mem got;
    bool ok = os_proc_mem_read(&got);
    OSPROC_CHECK("override read succeeds", ok);
    OSPROC_CHECK("override rss_bytes observed", got.rss_bytes == 123456789);
    OSPROC_CHECK("override vsize_bytes observed",
                 got.vsize_bytes == 987654321);
    OSPROC_CHECK("override cgroup_current observed",
                 got.cgroup_current == 100);
    OSPROC_CHECK("override cgroup_high observed", got.cgroup_high == 200);
    OSPROC_CHECK("override cgroup_max observed", got.cgroup_max == 300);
    OSPROC_CHECK("override sys_total_bytes observed",
                 got.sys_total_bytes == 1000);
    OSPROC_CHECK("override sys_avail_bytes observed",
                 got.sys_avail_bytes == 500);

    /* Second forced value fully replaces the first (no stale fields). */
    struct os_proc_mem forced2 = {
        .rss_bytes = 1, .vsize_bytes = 1, .cgroup_current = -1,
        .cgroup_high = -1, .cgroup_max = -1,
        .sys_total_bytes = -1, .sys_avail_bytes = -1,
    };
    os_proc_mem_set_override(&forced2);
    (void)os_proc_mem_read(&got);
    OSPROC_CHECK("second override fully replaces the first",
                 got.rss_bytes == 1 && got.cgroup_high == -1);

    /* Clear restores live reads. */
    os_proc_mem_set_override(NULL);
    (void)os_proc_mem_read(&got);
    OSPROC_CHECK("clearing the override restores a live (large, real) RSS",
                 got.rss_bytes != 1 && got.rss_bytes > 0);
    return failures;
}

/* Per-thread work counters advance and fail closed. */
static int os_proc_thread_work_counter_checks(void)
{
    int failures = 0;
    /* ── per-thread work counters ──────────────────────────────────
     * A tid that names no thread must fail rather than return zeros. */
    struct os_proc_thread_work w;
    long self = os_proc_self_tid();
#if defined(__linux__)
    OSPROC_CHECK("self_tid is a real thread id on Linux", self > 0);
    OSPROC_CHECK("thread work counters read for this thread",
                 os_proc_thread_work_read(self, &w));

    struct os_proc_thread_work before, after;
    OSPROC_CHECK("baseline thread work read",
                 os_proc_thread_work_read(self, &before));
    volatile uint64_t spin = 0;
    for (uint64_t i = 0; i < 200000000ULL; i++)
        spin += i;
    (void)spin;
    OSPROC_CHECK("a busy thread's cpu_ticks advance",
                 os_proc_thread_work_read(self, &after) &&
                 after.cpu_ticks > before.cpu_ticks);
#else
    (void)self;
#endif
    /* No such thread: a failed read must be reported as failure, not as
     * a zeroed "reading". */
    w.cpu_ticks = 12345;
    OSPROC_CHECK("a tid naming no thread fails the read",
                 !os_proc_thread_work_read(0, &w));
    OSPROC_CHECK("a failed read leaves no stale value behind",
                 w.cpu_ticks == 0);
    OSPROC_CHECK("a NULL out is refused",
                 !os_proc_thread_work_read(self, NULL));
    return failures;
}

/* Default glibc arena cap decision table. */
static int os_proc_arena_cap_default_checks(void)
{
    int failures = 0;
    /* ── default glibc arena cap: pure decision ───────────────────────── */
    OSPROC_CHECK("arena cap defaults to 4 with nothing set",
                 platform_allocator_arena_cap(NULL, NULL) == 4);
    OSPROC_CHECK("an unrelated GLIBC_TUNABLES keeps the default cap",
                 platform_allocator_arena_cap(NULL,
                                              "glibc.malloc.tcache_count=0") == 4);
    OSPROC_CHECK("MALLOC_ARENA_MAX set is the operator's choice",
                 platform_allocator_arena_cap("8", NULL) == 0);
    OSPROC_CHECK("MALLOC_ARENA_MAX set empty is still the operator's choice",
                 platform_allocator_arena_cap("", NULL) == 0);
    OSPROC_CHECK("GLIBC_TUNABLES arena_max is the operator's choice",
                 platform_allocator_arena_cap(NULL,
                                              "glibc.malloc.arena_max=2") == 0);
    OSPROC_CHECK("arena_max among several tunables is the operator's choice",
                 platform_allocator_arena_cap(
                     NULL, "glibc.malloc.check=0:glibc.malloc.arena_max=16") == 0);
    return failures;
}

#if defined(__linux__)
static bool os_proc_test_control(const char *dir, const char *name, const char *value)
{
    char path[PATH_MAX + 32];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(value, f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool os_proc_test_level(const char *dir, const char *current,
                               const char *high, const char *max)
{
    return os_proc_test_control(dir, "memory.current", current) &&
           os_proc_test_control(dir, "memory.high", high) &&
           os_proc_test_control(dir, "memory.max", max);
}

static int os_proc_cgroup_levels_values(const char *root, const char *parent,
                                         const char *leaf)
{
    int failures = 0;
    uint64_t headroom = 0;
    OSPROC_CHECK("tight parent bounds generous child",
        os_proc_cgroup_memory_levels_read(root, leaf, &headroom) && headroom == 10);
    OSPROC_CHECK("explicit max is unlimited", os_proc_test_level(parent, "90\n", "max\n", "max\n") &&
        os_proc_test_level(leaf, "5\n", "max\n", "max\n") &&
        os_proc_cgroup_memory_levels_read(root, leaf, &headroom) && headroom == UINT64_MAX);
    OSPROC_CHECK("exhausted parent gives zero", os_proc_test_level(parent, "101\n", "max\n", "100\n") &&
        os_proc_cgroup_memory_levels_read(root, leaf, &headroom) && headroom == 0);
    return failures;
}

static int os_proc_cgroup_levels_refusals(const char *root, const char *parent,
                                           const char *leaf)
{
    int failures = 0;
    uint64_t headroom = 0;
    OSPROC_CHECK("malformed limit is unknown", os_proc_test_control(parent, "memory.max", "12oops\n") &&
        !os_proc_cgroup_memory_levels_read(root, leaf, &headroom) && headroom == 0);
    OSPROC_CHECK("overflow limit is unknown", os_proc_test_control(parent, "memory.max", "18446744073709551616\n") &&
        !os_proc_cgroup_memory_levels_read(root, leaf, &headroom) && headroom == 0);
    char missing[PATH_MAX + 48];
    (void)snprintf(missing, sizeof(missing), "%s/memory.high", parent);
    OSPROC_CHECK("missing limit is unknown", os_proc_test_control(parent, "memory.max", "100\n") &&
        unlink(missing) == 0 && !os_proc_cgroup_memory_levels_read(root, leaf, &headroom) && headroom == 0);
    return failures;
}

static int os_proc_cgroup_root_controls_checks(const char *root)
{
    int failures = 0;
    char path[PATH_MAX + 32];
    (void)snprintf(path, sizeof(path), "%s/cgroup.type", root);
    OSPROC_CHECK("root controls prove only root-shaped fixture",
        os_proc_test_control(root, "cgroup.controllers", "cpu memory\n") &&
        os_proc_cgroup_root_controls_match(root));
    OSPROC_CHECK("visible nonroot controls refuse root shape",
        os_proc_test_control(root, "cgroup.type", "domain\n") &&
        !os_proc_cgroup_root_controls_match(root));
    OSPROC_CHECK("missing memory controller refuses root shape",
        unlink(path) == 0 && os_proc_test_control(root, "cgroup.controllers", "cpu\n") &&
        !os_proc_cgroup_root_controls_match(root));
    (void)snprintf(path, sizeof(path), "%s/cgroup.controllers", root);
    OSPROC_CHECK("missing controllers are unknown",
        unlink(path) == 0 && !os_proc_cgroup_root_controls_match(root));
    return failures;
}

static int os_proc_cgroup_membership_checks(const char *root)
{
    int failures = 0;
    OSPROC_CHECK("root shape alone does not establish membership",
        os_proc_test_control(root, "cgroup.controllers", "memory\n") &&
        os_proc_cgroup_root_controls_match(root) &&
        os_proc_test_control(root, "cgroup.procs", "123\n456\n") &&
        !os_proc_cgroup_contains_pid(root, 789));
    OSPROC_CHECK("exact member is found", os_proc_cgroup_contains_pid(root, 456));
    OSPROC_CHECK("malformed membership listing refuses",
        os_proc_test_control(root, "cgroup.procs", "456\n123x\n") &&
        !os_proc_cgroup_contains_pid(root, 456));
    return failures;
}

static int os_proc_cgroup_levels_fixture_checks(void)
{
    int failures = 0;
    char root[PATH_MAX], parent[PATH_MAX + 16], leaf[PATH_MAX + 32];
    if (!test_mkdtemp(root, sizeof(root), "os_proc_levels")) return 1;
    (void)snprintf(parent, sizeof(parent), "%s/parent", root);
    (void)snprintf(leaf, sizeof(leaf), "%s/child", parent);
    if (mkdir(parent, 0700) != 0 || mkdir(leaf, 0700) != 0 ||
        !os_proc_test_level(parent, "90\n", "max\n", "100\n") ||
        !os_proc_test_level(leaf, "5\n", "max\n", "1000\n")) {
        test_rm_rf_recursive(root);
        return 1;
    }
    failures += os_proc_cgroup_root_controls_checks(root);
    failures += os_proc_cgroup_membership_checks(root);
    failures += os_proc_cgroup_levels_values(root, parent, leaf);
    failures += os_proc_cgroup_levels_refusals(root, parent, leaf);
    test_rm_rf_recursive(root);
    return failures;
}
#else
static int os_proc_cgroup_levels_fixture_checks(void) { return 0; }
#endif

static int os_proc_scratch_metadata_checks(void)
{
    int failures = 0;
    struct platform_ram_scratch_root_facts f = {
        .directory = true, .owner = true, .owner_private = true,
        .tmpfs = true, .free_inodes = true
    };
    OSPROC_CHECK("qualified scratch metadata", platform_ram_scratch_root_facts_admit(&f));
    f.noexec = true;
    OSPROC_CHECK("noexec root refused", !platform_ram_scratch_root_facts_admit(&f));
    f.noexec = false; f.tmpfs = false;
    OSPROC_CHECK("non-tmpfs root refused", !platform_ram_scratch_root_facts_admit(&f));
    f.tmpfs = true; f.owner_private = false;
    OSPROC_CHECK("shared root refused", !platform_ram_scratch_root_facts_admit(&f));
    f.owner_private = true; f.owner = false;
    OSPROC_CHECK("foreign owner refused", !platform_ram_scratch_root_facts_admit(&f));
    f.owner = true; f.readonly = true;
    OSPROC_CHECK("readonly root refused", !platform_ram_scratch_root_facts_admit(&f));
    f.readonly = false; f.free_inodes = false;
    OSPROC_CHECK("exhausted root refused", !platform_ram_scratch_root_facts_admit(&f));
    return failures;
}

#if !defined(_WIN32)
static int os_proc_scratch_private_checks(void)
{
    int failures = 0;
    char root[PATH_MAX], path[PATH_MAX + 32], made[PATH_MAX];
    if (!test_mkdtemp(root, sizeof(root), "private_scratch")) return 1;
    int n = snprintf(path, sizeof(path), "%s/.z23-leases", root);
    if (n < 0 || (size_t)n >= sizeof(path) || chmod(root, 0777) != 0) {
        test_rm_rf_recursive(root);
        return 1;
    }
    struct platform_ram_scratch_lease lease = {0};
    OSPROC_CHECK("unsafe root refuses before lease creation",
        !platform_ram_scratch_reserve_private(root, 1, &lease) && !lease.held &&
        access(path, F_OK) != 0);
    OSPROC_CHECK("oversized reservation refuses without overflow",
        !platform_ram_scratch_reserve(root, UINT64_MAX, &lease) && !lease.held);
    OSPROC_CHECK("explicit temp root creates a private child",
        platform_temp_directory_create_under(root, "child-", made, sizeof(made)) &&
        rmdir(made) == 0);
    OSPROC_CHECK("relative temp root refuses", !platform_temp_directory_create_under(
        "relative", "child-", made, sizeof(made)) && made[0] == '\0');
    test_rm_rf_recursive(root);
    return failures;
}
#else
static int os_proc_scratch_private_checks(void) { return 0; }
#endif

#if defined(__linux__)
static bool os_proc_scratch_live_capacity(const char *root)
{
    struct os_proc_mem memory;
    uint64_t cgroup, free_bytes;
    const uint64_t required = PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES + 4096u;
    return os_proc_mem_read(&memory) && memory.sys_avail_bytes >= 0 &&
        (uint64_t)memory.sys_avail_bytes >= required &&
        os_proc_cgroup_memory_headroom(&cgroup) && cgroup >= required &&
        platform_disk_space_available(root, &free_bytes) && free_bytes >= required;
}

static bool os_proc_scratch_only_lease(const char *root, const char *expected)
{
    char path[PATH_MAX + 32];
    int n = snprintf(path, sizeof(path), "%s/.z23-leases", root);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool found = false, ok = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
            !strcmp(entry->d_name, "lock")) continue;
        if (strcmp(entry->d_name, expected) || found) { ok = false; break; }
        found = true;
    }
    if (closedir(dir) != 0) ok = false;
    return ok && found;
}

static int os_proc_scratch_low_memory_check(const char *root, const char *lease_path)
{
    int failures = 0;
    struct os_proc_mem memory;
    if (!os_proc_mem_read(&memory)) return 1;
    memory.sys_avail_bytes = 0;
    os_proc_mem_set_override(&memory);
    struct platform_ram_scratch_lease denied = {0};
    bool refused = !platform_ram_scratch_reserve_private(root, 4096, &denied);
    os_proc_mem_set_override(NULL);
    const char *name = strrchr(lease_path, '/');
    OSPROC_CHECK("low host memory refuses without another lease", refused && !denied.held &&
        name && os_proc_scratch_only_lease(root, name + 1));
    platform_ram_scratch_release(&denied);
    return failures;
}

static int os_proc_scratch_contention_check(const char *root)
{
    int failures = 0;
    char path[PATH_MAX + 32];
    int n = snprintf(path, sizeof(path), "%s/.z23-leases/lock", root);
    if (n < 0 || (size_t)n >= sizeof(path)) return 1;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) { close(fd); return 1; }
    struct platform_ram_scratch_lease denied = {0};
    bool refused = !platform_ram_scratch_reserve_private(root, 4096, &denied);
    bool unlocked = flock(fd, LOCK_UN) == 0;
    bool closed = close(fd) == 0;
    OSPROC_CHECK("contended private lease refuses without waiting",
        refused && !denied.held && unlocked && closed);
    platform_ram_scratch_release(&denied);
    return failures;
}

static int os_proc_scratch_live_lease_checks(void)
{
    int failures = 0;
    char base[PLATFORM_TEMP_PATH_MAX], root[PLATFORM_TEMP_PATH_MAX];
    if (!platform_ram_scratch_private_root(base, sizeof(base))) {
        printf("os_proc: private tmpfs lease not exercised (no qualified runtime root)\n");
        return 0;
    }
    if (!platform_temp_directory_create_under(base, "z23-lease-test-", root, sizeof(root))) return 1;
    struct platform_ram_scratch_lease lease = {0};
    if (!os_proc_scratch_live_capacity(root)) {
        printf("os_proc: private tmpfs lease not exercised (headroom unavailable)\n");
        test_rm_rf_recursive(root);
        return 0;
    }
    if (!platform_ram_scratch_reserve_private(root, 4096, &lease)) {
        printf("os_proc: qualified private lease... FAIL\n");
        test_rm_rf_recursive(root);
        return 1;
    }
    char path[sizeof(lease.path)];
    memcpy(path, lease.path, sizeof(path));
    OSPROC_CHECK("qualified root creates a live private lease", lease.held && access(path, F_OK) == 0);
    failures += os_proc_scratch_low_memory_check(root, path);
    failures += os_proc_scratch_contention_check(root);
    platform_ram_scratch_release(&lease);
    OSPROC_CHECK("private lease release removes its file", !lease.held &&
        access(path, F_OK) != 0 && errno == ENOENT);
    test_rm_rf_recursive(root);
    return failures;
}
#else
static int os_proc_scratch_live_lease_checks(void) { return 0; }
#endif

int test_os_proc(void);
int test_os_proc(void)
{
    printf("\n=== platform os_proc tests ===\n");
    int failures = 0;

    failures += os_proc_open_fd_count_checks();
    failures += os_proc_image_cloexec_checks();
    failures += os_proc_cgroup_stat_fixture_checks();
    failures += os_proc_cgroup_levels_fixture_checks();
    failures += os_proc_scratch_metadata_checks();
    failures += os_proc_scratch_private_checks();
    failures += os_proc_scratch_live_lease_checks();
    failures += os_proc_preserved_report_fd_checks();
    failures += os_proc_seccomp_filters_parse_checks();
    failures += os_proc_self_exe_open_path_checks();
    failures += os_proc_self_maps_read_checks();
    failures += os_proc_environment_classify_checks();
    failures += os_proc_live_mem_read_checks();
    failures += os_proc_uptime_checks();
    failures += os_proc_pid_start_token_checks();
    failures += os_proc_exe_path_checks();
    failures += os_proc_open_self_exe_read_checks();
    failures += os_proc_self_exe_identity_rung_checks();
    failures += os_proc_cgroup_dir_checks();
    failures += os_proc_mem_override_seam_checks();
    failures += os_proc_thread_work_counter_checks();
    failures += os_proc_arena_cap_default_checks();

    /* Final defensive reset so later tests in the same process never see a
     * stuck override. */
    os_proc_mem_set_override(NULL);

    if (failures == 0) {
        printf("=== platform os_proc tests: ALL PASS ===\n\n");
    } else {
        printf("=== platform os_proc tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
