/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the binary A/B fallback module (app/services/src/binary_ab_fallback.c)
 * and the shared native launch primitive used by `zcl-nodectl launch`.
 */

#include "test/test_core.h"
#include "services/binary_ab_fallback.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"
#include "platform/os_binary_slots.h"
#include "platform/os_proc.h"
#include "platform/process_compat.h"
#include "util/blocker.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

#if !defined(_WIN32)
extern char **environ;
#endif

#if defined(__APPLE__)
#define AB_TRUE_PATH "/usr/bin/true"
#else
#define AB_TRUE_PATH "/bin/true"
#endif

#define AB_CHECK(name, expr) do { \
    printf("ab: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#if !defined(_WIN32)

static int ab_write_file(const char *path, const char *contents, mode_t mode)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    size_t len = strlen(contents);
    size_t w = fwrite(contents, 1, len, fp);
    fclose(fp);
    if (w != len) return -1;
    return chmod(path, mode);
}

/* Reads up to sz-1 bytes of `path` into `out` (NUL-terminated). -1 on error. */
static int ab_read_file(const char *path, char *out, size_t sz)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    size_t r = fread(out, 1, sz - 1, fp);
    out[r] = '\0';
    fclose(fp);
    return (int)r;
}

static bool ab_pinned_bytes_equal(int fd, const char *expected)
{
    char buf[128];
    if (lseek(fd, 0, SEEK_SET) < 0)
        return false;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0)
        return false;
    buf[n] = '\0';
    return strcmp(buf, expected) == 0;
}

static bool ab_special_create(const char *path, mode_t mode)
{
#if defined(_WIN32)
    (void)mode;
    return platform_directory_create(path, 0700) == 0;
#else
    return mkfifo(path, mode) == 0;
#endif
}

static bool ab_special_remove(const char *path)
{
#if defined(_WIN32)
    return rmdir(path) == 0;
#else
    return unlink(path) == 0;
#endif
}

/* ── non-regular-path promptness is not stopwatch-graded ──────────────────
 *
 * Section 9 uses a writer-less FIFO on POSIX and a directory on Windows to
 * prove os_binary_slots_prepare_launch() promptly refuses non-regular paths.
 * The FIFO property used to be graded
 * `elapsed < 250 ms`, which flakes on a loaded box: 250 ms of scheduler delay
 * is ordinary on a 32-worker run, and it says nothing whatever about the
 * code. A 7200rpm-disk box measured under 2 MB/s — the honest worst case this
 * project deliberately keeps on the network — would fail it routinely.
 *
 * The bound was also redundant. A blocking open() on a writer-less FIFO
 * blocks FOREVER, so the call never returns and the comparison is never
 * evaluated; every defect the 250 ms could catch is already caught by the
 * OUTCOME assertions (refused / fell back / no descriptor), which are exact
 * and load-independent. So the outcome is what is asserted now, and the
 * elapsed time is REPORTED beside it.
 *
 * What the stopwatch did give — turning an infinite block into a visible
 * failure rather than a hung suite — is kept, but as a real hang detector:
 * an alarm whose handler does NOT set SA_RESTART, so a parked open() returns
 * EINTR and the outcome assertion then fails legibly with a message that says
 * "blocked" rather than the run wedging. The bound is 30 s: the guarded call
 * is a handful of open()/fstat()s on local files, microseconds even on the
 * slowest disk in this fleet, so 30 s is not a budget anybody can approach by
 * being slow — it exists only to convert "never returns" into a sentence. */
static volatile sig_atomic_t g_ab_hang_fired;
static void ab_hang_handler(int sig) { (void)sig; g_ab_hang_fired = 1; }

/* struct sigaction, sigaction(2), SIGALRM, and alarm(2) are POSIX-only —
 * mingw has none of them. The hang guard below is not exercised on
 * Windows, only kept syntactically valid there; the stub arm/disarm pair
 * reports "no hang" unconditionally, which is correct for code that never
 * runs. */
#if !defined(_WIN32)
static struct sigaction g_ab_old_alrm;
static void ab_hang_guard_arm(unsigned secs)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ab_hang_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;              /* NO SA_RESTART: a parked open() gets EINTR */
    g_ab_hang_fired = 0;
    (void)sigaction(SIGALRM, &sa, &g_ab_old_alrm);
    (void)alarm(secs);
}
static bool ab_hang_guard_disarm(void)
{
    (void)alarm(0);
    (void)sigaction(SIGALRM, &g_ab_old_alrm, NULL);
    return g_ab_hang_fired == 0;
}
#else
static void ab_hang_guard_arm(unsigned secs) { (void)secs; }
static bool ab_hang_guard_disarm(void) { return true; }
#endif /* !defined(_WIN32) */

/* Print a measured duration next to a check WITHOUT grading anything on it.
 * The load average is printed too, so a reader looking at a red run can tell
 * a real regression from a busy box in one glance. */
static void ab_report_elapsed(const char *what, int64_t elapsed_ns)
{
    char load[64] = "unknown";
    FILE *fp = fopen("/proc/loadavg", "rb");
    if (fp) {
        if (fgets(load, sizeof(load), fp)) {
            char *nl = strchr(load, '\n');
            if (nl) *nl = '\0';
        }
        fclose(fp);
    }
    printf("ab: [reported, not asserted] %s took %.3f ms (loadavg %s)\n",
           what, (double)elapsed_ns / 1e6, load);
}

static bool ab_fexecve_true(int fd)
{
#if defined(__APPLE__)
    char *const args[] = { (char *)AB_TRUE_PATH, NULL };
    errno = 0;
    return platform_execve_fd(fd, args, environ) == -1 && errno == ENOTSUP;
#elif defined(_WIN32)
    /* fork()/waitpid() have no Windows equivalent; this descriptor-bound
     * exec path is POSIX-only and not exercised there. */
    (void)fd;
    return false;
#else
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        char *const args[] = { (char *)AB_TRUE_PATH, NULL };
        platform_execve_fd(fd, args, environ);
        _exit(111);
    }
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
#endif
}

/* fork()/pipe()/waitpid() have no Windows equivalent; this native-launch
 * adapter is POSIX-only and is not exercised on Windows, only kept
 * syntactically valid there. */
#if !defined(_WIN32)
static bool ab_run_nodectl(const char *slots, const char *threshold,
                           const char *echo_value, const char *node,
                           char *output, size_t output_size,
                           int *exit_status)
{
    if (!slots || !node || !output || output_size == 0 || !exit_status)
        return false;
    int capture[2];
    if (pipe(capture) != 0)
        return false;
    pid_t child = fork();
    if (child < 0) {
        close(capture[0]);
        close(capture[1]);
        return false;
    }
    if (child == 0) {
        close(capture[0]);
        if (dup2(capture[1], STDOUT_FILENO) < 0)
            _exit(120);
        close(capture[1]);
        if (setenv("ZCL_BINARY_SLOTS_DIR", slots, 1) != 0 ||
            unsetenv("HOME") != 0)
            _exit(121);
        if (threshold) {
            if (setenv("ZCL_BINARY_FALLBACK_THRESHOLD", threshold, 1) != 0)
                _exit(122);
        } else {
            unsetenv("ZCL_BINARY_FALLBACK_THRESHOLD");
        }
        if (echo_value) {
            if (setenv("ZCL_LAUNCH_TEST_ECHO", echo_value, 1) != 0)
                _exit(123);
        } else {
            unsetenv("ZCL_LAUNCH_TEST_ECHO");
        }
        execl("build/bin/zcl-nodectl", "zcl-nodectl", "launch", node,
              "-datadir=/forwarded", "--marker=kept", (char *)NULL);
        _exit(124);
    }
    close(capture[1]);
    size_t used = 0;
    for (;;) {
        char discard[256];
        char *dst = used + 1u < output_size ? output + used : discard;
        size_t cap = used + 1u < output_size
            ? output_size - 1u - used : sizeof(discard);
        ssize_t n = read(capture[0], dst, cap);
        if (n > 0) {
            if (dst != discard)
                used += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            close(capture[0]);
            (void)waitpid(child, NULL, 0);
            return false;
        }
        break;
    }
    close(capture[0]);
    output[used] = '\0';
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
        return false;
    *exit_status = WEXITSTATUS(status);
    return true;
}
#else
static bool ab_run_nodectl(const char *slots, const char *threshold,
                           const char *echo_value, const char *node,
                           char *output, size_t output_size,
                           int *exit_status)
{
    (void)slots; (void)threshold; (void)echo_value; (void)node;
    (void)output; (void)output_size; (void)exit_status;
    return false;
}
#endif /* !defined(_WIN32) */

static int test_binary_ab_fallback_platform_arm(void)
{
    printf("\n=== binary_ab_fallback tests ===\n");
    int failures = 0;

    blocker_module_init();

    char tmpl[] = "/tmp/zcl_ab_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) {
        printf("ab: mkdtemp failed — cannot run seam tests\n");
        return 1;
    }
    char resolved_dir[PATH_MAX];
    if (!platform_directory_canonical_real(dir, resolved_dir,
                                           sizeof(resolved_dir))) {
        printf("ab: realpath failed — cannot run seam tests\n");
        return 1;
    }
    dir = resolved_dir;

    char streak[PATH_MAX], cur[PATH_MAX], lastgood[PATH_MAX], buf[256];
    snprintf(streak, sizeof(streak), "%s/%s", dir, BINARY_AB_STREAK_BASENAME);
    snprintf(lastgood, sizeof(lastgood), "%s/%s", dir, BINARY_AB_LASTGOOD_BASENAME);
    snprintf(cur, sizeof(cur), "%s/current-bin", dir);

#if defined(__linux__)
    /* systemd ProtectSystem=strict exposes read-only ancestors as searchable
     * but not readable. The launcher must traverse them without directory
     * enumeration authority. */
    {
        char writable[PATH_MAX], protected_slots[PATH_MAX];
        snprintf(writable, sizeof(writable), "%s/traverse", dir);
        snprintf(protected_slots, sizeof(protected_slots), "%s/slots", writable);
        AB_CHECK("create traversal fixture", mkdir(writable, 0700) == 0);
        AB_CHECK("make traversal parent execute-only", chmod(dir, 0111) == 0);
        AB_CHECK("create slots below execute-only ancestor",
                 os_binary_slots_ensure_directory(protected_slots, NULL, 0));
        AB_CHECK("restore traversal parent permissions", chmod(dir, 0700) == 0);
        AB_CHECK("remove traversed slots fixture", rmdir(protected_slots) == 0);
        AB_CHECK("remove traversal fixture", rmdir(writable) == 0);
    }
#endif

    /* ── 1. reset_streak overwrites any value with "0\n" ─────────────── */
    {
        AB_CHECK("seed streak file with 7", ab_write_file(streak, "7\n", 0644) == 0);
        AB_CHECK("reset_streak succeeds", binary_ab_reset_streak(streak));
        AB_CHECK("streak file now reads 0", ab_read_file(streak, buf, sizeof(buf)) >= 0
                 && strcmp(buf, "0\n") == 0);
        AB_CHECK("reset_streak on empty path fails", !binary_ab_reset_streak(""));
        AB_CHECK("reset_streak on NULL path fails", !binary_ab_reset_streak(NULL));
    }

    /* ── 2. promote copies current bytes into the last-good slot ─────── */
    {
        AB_CHECK("write a fake current binary", ab_write_file(cur, "CURRENT-V1-BYTES", 0755) == 0);
        AB_CHECK("promote succeeds", binary_ab_promote(dir, cur));
        AB_CHECK("last-good exists with the current bytes",
                 ab_read_file(lastgood, buf, sizeof(buf)) >= 0
                 && strcmp(buf, "CURRENT-V1-BYTES") == 0);
        struct stat st;
        AB_CHECK("last-good is executable",
                 stat(lastgood, &st) == 0 && (st.st_mode & S_IXUSR));
        AB_CHECK("promote with empty current_path fails", !binary_ab_promote(dir, ""));
        AB_CHECK("promote with empty slots_dir fails", !binary_ab_promote("", cur));
    }

    /* ── 3. normal ready promotes durably before resetting streak ───── */
    {
        AB_CHECK("re-seed streak to 5", ab_write_file(streak, "5\n", 0644) == 0);
        AB_CHECK("rewrite current to V2", ab_write_file(cur, "CURRENT-V2-BYTES", 0755) == 0);
        AB_CHECK("on_ready(fallback=false) succeeds", binary_ab_on_ready(dir, cur, false));
        AB_CHECK("on_ready reset streak to 0",
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 && strcmp(buf, "0\n") == 0);
        AB_CHECK("on_ready promoted V2 to last-good",
                 ab_read_file(lastgood, buf, sizeof(buf)) >= 0
                 && strcmp(buf, "CURRENT-V2-BYTES") == 0);
    }

    /* ── 4. on_ready (fallback): resets streak but does NOT overwrite the
     *      good slot with the bad current binary ─────────────────────── */
    {
        AB_CHECK("last-good currently holds V2 (the good slot)",
                 ab_read_file(lastgood, buf, sizeof(buf)) >= 0
                 && strcmp(buf, "CURRENT-V2-BYTES") == 0);
        AB_CHECK("current is now a BAD V3 build", ab_write_file(cur, "BAD-V3-BYTES", 0755) == 0);
        AB_CHECK("seed streak to 9", ab_write_file(streak, "9\n", 0644) == 0);
        AB_CHECK("on_ready(fallback=true) succeeds", binary_ab_on_ready(dir, cur, true));
        AB_CHECK("fallback on_ready reset streak to 0",
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 && strcmp(buf, "0\n") == 0);
        AB_CHECK("fallback on_ready LEFT last-good = V2 (never promoted the bad binary)",
                 ab_read_file(lastgood, buf, sizeof(buf)) >= 0
                 && strcmp(buf, "CURRENT-V2-BYTES") == 0);
    }

    /* ── 5. on_ready with no slots dir is a no-op success ────────────── */
    {
        AB_CHECK("seed old last-good before failed ready promotion",
                 ab_write_file(lastgood, "OLD-LAST-GOOD", 0755) == 0);
        AB_CHECK("seed streak 2 before failed ready promotion",
                 ab_write_file(streak, "2\n", 0600) == 0);
        AB_CHECK("seed candidate for failed ready promotion",
                 ab_write_file(cur, "UNCOMMITTED-CANDIDATE", 0755) == 0);
        binary_ab_test_fail_before_promote_rename_once();
        AB_CHECK("injected ready promotion failure is reported",
                 !binary_ab_on_ready(dir, cur, false));
        AB_CHECK("failed promotion preserves streak failure evidence",
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 &&
                 strcmp(buf, "2\n") == 0);
        AB_CHECK("failed promotion preserves committed last-good",
                 ab_read_file(lastgood, buf, sizeof(buf)) >= 0 &&
                 strcmp(buf, "OLD-LAST-GOOD") == 0);
        AB_CHECK("managed normal ready requires current path",
                 !binary_ab_on_ready(dir, NULL, false));
        AB_CHECK("missing ready current path preserves streak",
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 &&
                 strcmp(buf, "2\n") == 0);

        AB_CHECK("on_ready(NULL slots) is a no-op success", binary_ab_on_ready(NULL, cur, false));
        AB_CHECK("on_ready(empty slots) is a no-op success", binary_ab_on_ready("", cur, false));
    }

    /* ── 6. the fallback blocker ─────────────────────────────────────── */
    {
        blocker_clear(BINARY_FALLBACK_BLOCKER_ID);
        binary_ab_raise_fallback_blocker(false);
        AB_CHECK("raise(false) does not raise the blocker",
                 !blocker_exists(BINARY_FALLBACK_BLOCKER_ID));
        binary_ab_raise_fallback_blocker(true);
        AB_CHECK("raise(true) raises binary.fallback_active",
                 blocker_exists(BINARY_FALLBACK_BLOCKER_ID));
        AB_CHECK("blocker is PERMANENT (operator-cleared)",
                 blocker_class_for(BINARY_FALLBACK_BLOCKER_ID) == BLOCKER_PERMANENT);
        blocker_clear(BINARY_FALLBACK_BLOCKER_ID);
    }

    /* ── 7. corrupt launch state fails closed to a pinned last-good ──── */
    {
        uint32_t threshold = 0;
        AB_CHECK("strict threshold accepts 3",
                 os_binary_slots_parse_threshold("3", &threshold) &&
                 threshold == 3);
        AB_CHECK("strict threshold accepts UINT32_MAX",
                 os_binary_slots_parse_threshold("4294967295", &threshold) &&
                 threshold == UINT32_MAX);
        AB_CHECK("strict threshold rejects empty",
                 !os_binary_slots_parse_threshold("", &threshold));
        AB_CHECK("strict threshold rejects zero",
                 !os_binary_slots_parse_threshold("0", &threshold));
        AB_CHECK("strict threshold rejects signs",
                 !os_binary_slots_parse_threshold("+3", &threshold) &&
                 !os_binary_slots_parse_threshold("-3", &threshold));
        AB_CHECK("strict threshold rejects suffix",
                 !os_binary_slots_parse_threshold("3x", &threshold));
        AB_CHECK("strict threshold rejects overflow",
                 !os_binary_slots_parse_threshold("4294967296", &threshold));

        AB_CHECK("write executable current fixture",
                 ab_write_file(cur, "CURRENT-PINNED", 0755) == 0);
        AB_CHECK("write executable last-good fixture",
                 ab_write_file(lastgood, "LAST-GOOD-PINNED", 0755) == 0);
        AB_CHECK("seed malformed streak",
                 ab_write_file(streak, "garbage\n", 0600) == 0);
        struct os_binary_slots_launch launch;
        bool ok = os_binary_slots_prepare_launch(dir, cur, 3, &launch);
        AB_CHECK("malformed streak selects last-good",
                 ok && launch.fallback_active && launch.streak_corrupt &&
                 !launch.streak_written && launch.executable_fd >= 0);
        AB_CHECK("malformed streak evidence is preserved",
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 &&
                 strcmp(buf, "garbage\n") == 0);
        AB_CHECK("selected last-good fd is pinned to expected bytes",
                 ok && ab_pinned_bytes_equal(launch.executable_fd,
                                             "LAST-GOOD-PINNED"));
        os_binary_slots_close_launch(&launch);

        AB_CHECK("seed empty streak", ab_write_file(streak, "", 0600) == 0);
        ok = os_binary_slots_prepare_launch(dir, cur, 3, &launch);
        AB_CHECK("empty streak selects last-good and remains empty",
                 ok && launch.fallback_active && launch.streak_corrupt &&
                 !launch.streak_written &&
                 ab_read_file(streak, buf, sizeof(buf)) == 0);
        os_binary_slots_close_launch(&launch);

        AB_CHECK("seed numeric overflow streak",
                 ab_write_file(streak, "4294967296\n", 0600) == 0);
        ok = os_binary_slots_prepare_launch(dir, cur, 3, &launch);
        AB_CHECK("numeric overflow selects fallback and is preserved",
                 ok && launch.fallback_active && launch.streak_corrupt &&
                 !launch.streak_written &&
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 &&
                 strcmp(buf, "4294967296\n") == 0);
        os_binary_slots_close_launch(&launch);

        AB_CHECK("seed increment-overflow streak",
                 ab_write_file(streak, "4294967295\n", 0600) == 0);
        ok = os_binary_slots_prepare_launch(dir, cur, 3, &launch);
        AB_CHECK("increment overflow selects fallback and is preserved",
                 ok && launch.fallback_active && launch.streak_corrupt &&
                 !launch.streak_written &&
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 &&
                 strcmp(buf, "4294967295\n") == 0);
        os_binary_slots_close_launch(&launch);
    }

    /* ── 8. interrupted durable write preserves old committed bytes ──── */
    {
        AB_CHECK("seed threshold streak",
                 ab_write_file(streak, "3\n", 0600) == 0);
        struct os_binary_slots_launch threshold_launch;
        bool threshold_ok = os_binary_slots_prepare_launch(
            dir, cur, 3, &threshold_launch);
        AB_CHECK("prior equal to threshold selects fallback",
                 threshold_ok && threshold_launch.fallback_active &&
                 threshold_launch.streak_before == 3 &&
                 threshold_launch.streak_after == 4);
        os_binary_slots_close_launch(&threshold_launch);

        AB_CHECK("seed missing-current streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
        AB_CHECK("remove current fixture", unlink(cur) == 0);
        struct os_binary_slots_launch missing_launch;
        bool missing_ok = os_binary_slots_prepare_launch(
            dir, cur, 3, &missing_launch);
        AB_CHECK("missing current selects executable last-good",
                 missing_ok && missing_launch.fallback_active &&
                 missing_launch.executable_fd >= 0 &&
                 missing_launch.streak_after == 1);
        os_binary_slots_close_launch(&missing_launch);
        AB_CHECK("restore current fixture",
                 ab_write_file(cur, "CURRENT-PINNED", 0755) == 0);

        AB_CHECK("seed valid streak 2",
                 ab_write_file(streak, "2\n", 0600) == 0);
        os_binary_slots_test_fail_before_rename_once();
        struct os_binary_slots_launch launch;
        bool ok = os_binary_slots_prepare_launch(dir, cur, 3, &launch);
        AB_CHECK("injected pre-rename failure rejects launch", !ok);
        AB_CHECK("pre-rename failure preserves old streak bytes",
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 &&
                 strcmp(buf, "2\n") == 0);
        os_binary_slots_close_launch(&launch);
    }

    /* ── 9. selected fd survives a pathname replacement ─────────────── */
    {
        /* See the ab_hang_guard_* header above: the VERDICT is the refusal
         * outcome (exact, load-independent); the alarm only converts a
         * hypothetical infinite park in open() into a legible failure; the
         * elapsed time is printed and graded by nobody. */
        const unsigned hang_guard_secs = 30;
        AB_CHECK("replace streak with non-regular object",
                 unlink(streak) == 0 && ab_special_create(streak, 0600));
        int64_t started = clock_now_monotonic_ns();
        struct os_binary_slots_launch fifo_launch;
        ab_hang_guard_arm(hang_guard_secs);
        bool fifo_ok = os_binary_slots_prepare_launch(
            dir, cur, 3, &fifo_launch);
        bool no_hang = ab_hang_guard_disarm();
        int64_t elapsed = clock_now_monotonic_ns() - started;
        ab_report_elapsed("prepare_launch over a FIFO streak", elapsed);
        AB_CHECK("FIFO streak refuses and selects last-good "
                 "(no park in open(): guard did not fire)",
                 no_hang && fifo_ok && fifo_launch.fallback_active &&
                 fifo_launch.streak_corrupt);
        os_binary_slots_close_launch(&fifo_launch);
        AB_CHECK("remove non-regular streak", ab_special_remove(streak));

        AB_CHECK("seed streak before FIFO current",
                 ab_write_file(streak, "0\n", 0600) == 0);
        AB_CHECK("replace current with non-regular object",
                 unlink(cur) == 0 && ab_special_create(cur, 0700));
        started = clock_now_monotonic_ns();
        ab_hang_guard_arm(hang_guard_secs);
        bool promote_refused = !binary_ab_promote(dir, cur);
        no_hang = ab_hang_guard_disarm();
        ab_report_elapsed("binary_ab_promote from a FIFO source",
                          clock_now_monotonic_ns() - started);
        AB_CHECK("FIFO promotion source is refused "
                 "(no park in open(): guard did not fire)",
                 no_hang && promote_refused);
        started = clock_now_monotonic_ns();
        ab_hang_guard_arm(hang_guard_secs);
        fifo_ok = os_binary_slots_prepare_launch(dir, cur, 3, &fifo_launch);
        no_hang = ab_hang_guard_disarm();
        elapsed = clock_now_monotonic_ns() - started;
        ab_report_elapsed("prepare_launch over a FIFO current", elapsed);
        AB_CHECK("FIFO current refuses and selects last-good "
                 "(no park in open(): guard did not fire)",
                 no_hang && fifo_ok && fifo_launch.fallback_active);
        os_binary_slots_close_launch(&fifo_launch);
        AB_CHECK("remove non-regular current", ab_special_remove(cur));
        AB_CHECK("restore regular current",
                 ab_write_file(cur, "CURRENT-AFTER-FIFO", 0755) == 0);

        AB_CHECK("seed threshold before FIFO last-good",
                 ab_write_file(streak, "3\n", 0600) == 0);
        AB_CHECK("replace last-good with non-regular object",
                 unlink(lastgood) == 0 && ab_special_create(lastgood, 0700));
        started = clock_now_monotonic_ns();
        ab_hang_guard_arm(hang_guard_secs);
        fifo_ok = os_binary_slots_prepare_launch(dir, cur, 3, &fifo_launch);
        no_hang = ab_hang_guard_disarm();
        elapsed = clock_now_monotonic_ns() - started;
        ab_report_elapsed("prepare_launch over a FIFO last-good", elapsed);
        AB_CHECK("required FIFO last-good is refused "
                 "(no park in open(): guard did not fire)",
                 no_hang && !fifo_ok && fifo_launch.executable_fd < 0);
        os_binary_slots_close_launch(&fifo_launch);
        AB_CHECK("remove non-regular last-good",
                 ab_special_remove(lastgood));
        AB_CHECK("restore regular last-good",
                 ab_write_file(lastgood, "LAST-GOOD-AFTER-FIFO", 0755) == 0);

        char replacement[PATH_MAX];
        snprintf(replacement, sizeof(replacement), "%s/current-new", dir);
        AB_CHECK("seed fresh launch streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
        AB_CHECK("seed original current bytes",
                 ab_write_file(cur, "ORIGINAL-INODE", 0755) == 0);
        struct os_binary_slots_launch launch;
        bool ok = os_binary_slots_prepare_launch(dir, cur, 3, &launch);
        AB_CHECK("normal launch pins current fd",
                 ok && !launch.fallback_active && launch.executable_fd >= 0 &&
                 launch.streak_written && launch.streak_after == 1);
        AB_CHECK("create replacement current inode",
                 ab_write_file(replacement, "REPLACED-PATH", 0755) == 0);
        AB_CHECK("swap current pathname after decision",
                 rename(replacement, cur) == 0);
        AB_CHECK("pinned fd still reads original inode",
                 ok && ab_pinned_bytes_equal(launch.executable_fd,
                                             "ORIGINAL-INODE"));
        os_binary_slots_close_launch(&launch);
        unlink(replacement);
    }

    /* ── 10. O_CLOEXEC pinned descriptor executes a real host binary ─ */
    {
        AB_CHECK("seed native launch streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
        struct os_binary_slots_launch launch;
        bool ok = os_binary_slots_prepare_launch(dir, AB_TRUE_PATH, 3, &launch);
        AB_CHECK("prepare real native launch succeeds",
                 ok && !launch.fallback_active && launch.executable_fd >= 0);
        AB_CHECK("descriptor-bound launch succeeds or fails closed",
                 ok && ab_fexecve_true(launch.executable_fd));
        os_binary_slots_close_launch(&launch);
    }

    /* ── 11. checked path joins refuse truncation ────────────────────── */
    {
        char too_long[OS_BINARY_SLOTS_PATH_MAX + 32];
        memset(too_long, 'a', sizeof(too_long) - 1u);
        too_long[sizeof(too_long) - 1u] = '\0';
        struct os_binary_slots_launch long_launch;
        AB_CHECK("overlong slots directory is refused",
                 !os_binary_slots_prepare_launch(
                     too_long, AB_TRUE_PATH, 3, &long_launch));
        AB_CHECK("overlong current path is refused",
                 !os_binary_slots_prepare_launch(dir, too_long, 3,
                                                  &long_launch));
        AB_CHECK("overlong promotion destination is refused",
                 !binary_ab_promote(too_long, cur));
    }

    /* ── 12. native zcl-nodectl adapter preserves argv/env contracts ── */
    {
        char output[2048];
        int status = -1;
        AB_CHECK("seed adapter normal streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
#if defined(__APPLE__)
        AB_CHECK("native launcher refuses when descriptor-bound exec is unavailable",
                 ab_run_nodectl(dir, "3", "0", AB_TRUE_PATH,
                                output, sizeof(output), &status) &&
                 status == 126);
        AB_CHECK("seed Darwin adapter threshold streak",
                 ab_write_file(streak, "3\n", 0600) == 0);
        AB_CHECK("Darwin selected last-good also fails closed",
                 ab_run_nodectl(dir, "3", "0", AB_TRUE_PATH,
                                output, sizeof(output), &status) &&
                 status == 126);
#else
        AB_CHECK("native launcher runs with explicit slots and no HOME",
                 ab_run_nodectl(dir, "3", "1", AB_TRUE_PATH,
                                output, sizeof(output), &status) &&
                 status == 0);
        AB_CHECK("native launcher forwards normal environment",
                 strstr(output, "FALLBACK_ACTIVE=\n") &&
                 strstr(output, "CURRENT=" AB_TRUE_PATH "\n") &&
                 strstr(output, "STREAK_WRITTEN=1\n"));
        AB_CHECK("native launcher forwards node argv",
                 strstr(output, "ARGV[0]=-datadir=/forwarded\n") &&
                 strstr(output, "ARGV[1]=--marker=kept\n"));

        AB_CHECK("seed exact-echo control streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
        AB_CHECK("test echo value zero executes rather than echoing",
                 ab_run_nodectl(dir, "3", "0", AB_TRUE_PATH,
                                output, sizeof(output), &status) &&
                 status == 0 && output[0] == '\0');
#endif

        AB_CHECK("seed invalid-threshold control streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
        AB_CHECK("native launcher rejects non-decimal threshold",
                 ab_run_nodectl(dir, "+3", "1", AB_TRUE_PATH,
                                output, sizeof(output), &status) &&
                 status == 64);
        AB_CHECK("invalid threshold leaves streak untouched",
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 &&
                 strcmp(buf, "0\n") == 0);

#if !defined(__APPLE__)
        AB_CHECK("seed adapter threshold streak",
                 ab_write_file(streak, "3\n", 0600) == 0);
        AB_CHECK("native launcher threshold uses fallback",
                 ab_run_nodectl(dir, "3", "1", AB_TRUE_PATH,
                                output, sizeof(output), &status) &&
                 status == 0 && strstr(output, "FALLBACK_ACTIVE=1\n") &&
                 strstr(output, "STREAK_WRITTEN=4\n"));

        AB_CHECK("seed adapter missing-current streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
        AB_CHECK("native launcher missing current uses fallback",
                 ab_run_nodectl(dir, "3", "1", "/does/not/exist/z23",
                                output, sizeof(output), &status) &&
                 status == 0 && strstr(output, "FALLBACK_ACTIVE=1\n") &&
                 strstr(output, "CURRENT=\n"));
#endif
    }

    /* ── 13. cleanup temp dir ────────────────────────────────────────── */
    unlink(streak); unlink(lastgood); unlink(cur);
    char lock_path[PATH_MAX];
    snprintf(lock_path, sizeof(lock_path), "%s/.binary-slots.lock", dir);
    unlink(lock_path);
    rmdir(dir);

    return failures;
}
#else  /* _WIN32 */
/* Windows refuses the whole A/B slot surface by name, errno == ENOTSUP —
 * see SLOT_WIN32_REFUSAL in lib/platform/src/os_binary_slots.c: there is no
 * directory-handle-relative O_NOFOLLOW open and no descriptor-bound exec,
 * and a partial emulation was deliberately rejected. This lane asserts the
 * refusal contract itself; the launch matrix above is the POSIX lane. */
static int test_binary_ab_fallback_platform_arm(void)
{
    printf("\n=== binary_ab_fallback tests (Windows refusal lane) ===\n");
    int failures = 0;

    struct os_binary_slots_launch launch;
    errno = 0;
    bool prepare_refused =
        !os_binary_slots_prepare_launch("/nonexistent-slots",
                                        "/nonexistent-node", 3, &launch) &&
        errno == ENOTSUP;
    AB_CHECK("os_binary_slots_prepare_launch refuses by name (ENOTSUP)",
             prepare_refused);

    errno = 0;
    char *const args[] = { (char *)"/nonexistent-node", NULL };
    AB_CHECK("platform_execve_fd refuses descriptor-bound exec (ENOTSUP)",
             platform_execve_fd(-1, args, NULL) == -1 && errno == ENOTSUP);

    if (!failures)
        printf("binary_ab_fallback: SKIP (Windows): descriptor-bound A/B "
               "launch lane is POSIX-only; refusal contract asserted\n");
    return failures;
}
#endif

int test_binary_ab_fallback(void)
{
    return test_binary_ab_fallback_platform_arm();
}
