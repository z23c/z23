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
#include "platform/os_proc.h"

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

int test_os_proc(void);
int test_os_proc(void)
{
    printf("\n=== platform os_proc tests ===\n");
    int failures = 0;

    failures += os_proc_open_fd_count_checks();
    failures += os_proc_image_cloexec_checks();
    failures += os_proc_cgroup_stat_fixture_checks();
    failures += os_proc_preserved_report_fd_checks();
    failures += os_proc_seccomp_filters_parse_checks();
    failures += os_proc_self_exe_open_path_checks();
    failures += os_proc_self_maps_read_checks();

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

    /* ── real reads: this live process ───────────────────────────── */
    {
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
    }

    /* ── uptime ───────────────────────────────────────────────────── */
    {
        int64_t age = os_proc_uptime_seconds();
        OSPROC_CHECK("uptime_seconds is non-negative", age >= 0);
        /* Sanity ceiling of 10 years catches a units bug (ticks vs seconds). */
        OSPROC_CHECK("uptime_seconds is not absurdly large",
                     age < (int64_t)10 * 365 * 24 * 3600);
    }

    /* ── stable process-birth identity ───────────────────────────── */
    {
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
    }

    /* ── exe path ─────────────────────────────────────────────────── */
    {
        char path[4096];
        bool ok = os_proc_exe_path(path, sizeof(path));
        OSPROC_CHECK("exe_path resolves", ok);
        OSPROC_CHECK("exe_path is absolute", ok && path[0] == '/');
        struct stat st;
        OSPROC_CHECK("exe_path names an existing file",
                     ok && stat(path, &st) == 0);
    }

    /* ── open self exe ────────────────────────────────────────────── */
    {
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
    }

    /* ── running-image identity rung ──────────────────────────────── */
    {
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
    }

    /* ── cgroup dir ───────────────────────────────────────────────── */
    {
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
    }

    /* ── override seam ────────────────────────────────────────────── */
    {
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
    }

    /* ── per-thread work counters ──────────────────────────────────
     * A tid that names no thread must fail rather than return zeros. */
    {
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
    }

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
