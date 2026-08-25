/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the binary A/B fallback module (app/services/src/binary_ab_fallback.c)
 * and the shared native launch primitive used by `zcl-nodectl launch`.
 */

#include "test/test_core.h"
#include "services/binary_ab_fallback.h"
#include "platform/clock.h"
#include "platform/os_binary_slots.h"
#include "platform/os_proc.h"
#include "util/blocker.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define AB_CHECK(name, expr) do { \
    printf("ab: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

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

static bool ab_fexecve_true(int fd)
{
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        char *const args[] = { (char *)"/bin/true", NULL };
        fexecve(fd, args, environ);
        _exit(111);
    }
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
}

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

int test_binary_ab_fallback(void)
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
        const int64_t prompt_ns = 250LL * 1000LL * 1000LL;
        AB_CHECK("replace streak with FIFO", unlink(streak) == 0 &&
                 mkfifo(streak, 0600) == 0);
        int64_t started = clock_now_monotonic_ns();
        struct os_binary_slots_launch fifo_launch;
        bool fifo_ok = os_binary_slots_prepare_launch(
            dir, cur, 3, &fifo_launch);
        int64_t elapsed = clock_now_monotonic_ns() - started;
        AB_CHECK("FIFO streak promptly selects last-good",
                 fifo_ok && fifo_launch.fallback_active &&
                 fifo_launch.streak_corrupt && elapsed >= 0 &&
                 elapsed < prompt_ns);
        os_binary_slots_close_launch(&fifo_launch);
        AB_CHECK("remove FIFO streak", unlink(streak) == 0);

        AB_CHECK("seed streak before FIFO current",
                 ab_write_file(streak, "0\n", 0600) == 0);
        AB_CHECK("replace current with FIFO", unlink(cur) == 0 &&
                 mkfifo(cur, 0700) == 0);
        started = clock_now_monotonic_ns();
        AB_CHECK("FIFO promotion source is promptly refused",
                 !binary_ab_promote(dir, cur) &&
                 clock_now_monotonic_ns() - started < prompt_ns);
        started = clock_now_monotonic_ns();
        fifo_ok = os_binary_slots_prepare_launch(dir, cur, 3, &fifo_launch);
        elapsed = clock_now_monotonic_ns() - started;
        AB_CHECK("FIFO current promptly selects last-good",
                 fifo_ok && fifo_launch.fallback_active && elapsed >= 0 &&
                 elapsed < prompt_ns);
        os_binary_slots_close_launch(&fifo_launch);
        AB_CHECK("remove FIFO current", unlink(cur) == 0);
        AB_CHECK("restore regular current",
                 ab_write_file(cur, "CURRENT-AFTER-FIFO", 0755) == 0);

        AB_CHECK("seed threshold before FIFO last-good",
                 ab_write_file(streak, "3\n", 0600) == 0);
        AB_CHECK("replace last-good with FIFO", unlink(lastgood) == 0 &&
                 mkfifo(lastgood, 0700) == 0);
        started = clock_now_monotonic_ns();
        fifo_ok = os_binary_slots_prepare_launch(dir, cur, 3, &fifo_launch);
        elapsed = clock_now_monotonic_ns() - started;
        AB_CHECK("required FIFO last-good is promptly refused",
                 !fifo_ok && fifo_launch.executable_fd < 0 && elapsed >= 0 &&
                 elapsed < prompt_ns);
        os_binary_slots_close_launch(&fifo_launch);
        AB_CHECK("remove FIFO last-good", unlink(lastgood) == 0);
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

    /* ── 10. O_CLOEXEC pinned descriptor executes a real ELF ────────── */
    {
        AB_CHECK("seed ELF launch streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
        struct os_binary_slots_launch launch;
        bool ok = os_binary_slots_prepare_launch(dir, "/bin/true", 3, &launch);
        AB_CHECK("prepare real ELF launch succeeds",
                 ok && !launch.fallback_active && launch.executable_fd >= 0);
        AB_CHECK("fexecve pinned O_CLOEXEC ELF succeeds",
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
                     too_long, "/bin/true", 3, &long_launch));
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
        AB_CHECK("native launcher runs with explicit slots and no HOME",
                 ab_run_nodectl(dir, "3", "1", "/bin/true",
                                output, sizeof(output), &status) &&
                 status == 0);
        AB_CHECK("native launcher forwards normal environment",
                 strstr(output, "FALLBACK_ACTIVE=\n") &&
                 strstr(output, "CURRENT=/bin/true\n") &&
                 strstr(output, "STREAK_WRITTEN=1\n"));
        AB_CHECK("native launcher forwards node argv",
                 strstr(output, "ARGV[0]=-datadir=/forwarded\n") &&
                 strstr(output, "ARGV[1]=--marker=kept\n"));

        AB_CHECK("seed exact-echo control streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
        AB_CHECK("test echo value zero executes rather than echoing",
                 ab_run_nodectl(dir, "3", "0", "/bin/true",
                                output, sizeof(output), &status) &&
                 status == 0 && output[0] == '\0');

        AB_CHECK("seed invalid-threshold control streak",
                 ab_write_file(streak, "0\n", 0600) == 0);
        AB_CHECK("native launcher rejects non-decimal threshold",
                 ab_run_nodectl(dir, "+3", "1", "/bin/true",
                                output, sizeof(output), &status) &&
                 status == 64);
        AB_CHECK("invalid threshold leaves streak untouched",
                 ab_read_file(streak, buf, sizeof(buf)) >= 0 &&
                 strcmp(buf, "0\n") == 0);

        AB_CHECK("seed adapter threshold streak",
                 ab_write_file(streak, "3\n", 0600) == 0);
        AB_CHECK("native launcher threshold uses fallback",
                 ab_run_nodectl(dir, "3", "1", "/bin/true",
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
    }

    /* ── 13. cleanup temp dir ────────────────────────────────────────── */
    unlink(streak); unlink(lastgood); unlink(cur);
    char lock_path[PATH_MAX];
    snprintf(lock_path, sizeof(lock_path), "%s/.binary-slots.lock", dir);
    unlink(lock_path);
    rmdir(dir);

    return failures;
}
