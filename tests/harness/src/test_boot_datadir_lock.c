/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_datadir_lock.h"
#include "config/boot_error.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>
#if !defined(_WIN32)

#define BDL_CHECK(name, expr) do {                                      \
    printf("boot_datadir_lock: %s... ", (name));                       \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static bool bdl_read_file(const char *path, char *out, size_t out_cap)
{
    if (!path || !out || out_cap == 0)
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(out, 1, out_cap - 1, f);
    fclose(f);
    out[n] = '\0';
    return true;
}

/* Every refusal must reach the operator as the typed pre-registry block
 * (config/boot_error.h): a stable code, the measured evidence, and a next
 * command that runs. These helpers assert on the exact rendered text, since
 * the text is the contract for an agent reading stderr. */
static bool bdl_render_has(const char *needle)
{
    char render[BOOT_ERROR_RENDER_MAX];
    if (boot_error_last_render(render, sizeof(render)) == 0)
        return false;
    return strstr(render, needle) != NULL;
}

static bool bdl_render_is_typed_block(const char *code, const char *phase)
{
    char code_line[BOOT_ERROR_CODE_MAX + 32];
    char phase_line[128];
    snprintf(code_line, sizeof(code_line), "  code:     %s\n", code);
    snprintf(phase_line, sizeof(phase_line), "  phase:    %s\n", phase);
    return bdl_render_has("FATAL boot: ") && bdl_render_has(code_line) &&
           bdl_render_has(phase_line) && bdl_render_has("  evidence: ");
}

static bool bdl_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    if (text && fputs(text, f) < 0) {
        fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

#define BDL_BEACON_CAP (64 * 1024)

/* Reads a whole regular file into out. st receives the stat taken before the
 * read; out_len is the byte count. Fails when the file is missing, empty,
 * 64 KiB or larger, or short-read. */
static bool bdl_read_beacon(const char *path, char *out, size_t *out_len,
                            struct stat *st)
{
    if (stat(path, st) != 0 || !S_ISREG(st->st_mode))
        return false;
    if (st->st_size <= 0 || st->st_size >= BDL_BEACON_CAP)
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t want = (size_t)st->st_size;
    size_t n = fread(out, 1, want, f);
    fclose(f);
    *out_len = n;
    return n == want;
}

/* Owner child: take the lock, report it, hold until released, then exit. */
static void bdl_owner_hold(const char *dir, int ready_w, int release_r)
{
    bool locked = boot_datadir_lock_acquire(dir);
    char ready = locked ? '1' : '0';
    (void)!write(ready_w, &ready, 1);
    close(ready_w);
    if (locked) {
        char release = 0;
        (void)!read(release_r, &release, 1);
        boot_datadir_lock_release();
    }
    close(release_r);
    _exit(locked ? 0 : 1);
}

static void bdl_close_fds(int ready[2], int release[2])
{
    for (int i = 0; i < 2; i++) {
        if (ready[i] >= 0) close(ready[i]);
        if (release[i] >= 0) close(release[i]);
    }
}

struct bdl_beacon_probe {
    bool beacon_read;
    bool parent_refused;
    bool beacon_stable;
};

/* Parent side: snapshot the owner's beacon, make the refused acquire, then
 * prove the beacon is byte-, inode- and mtime-identical afterwards. */
static void bdl_probe_refusal(const char *dir, const char *beacon_path,
                              struct bdl_beacon_probe *out)
{
    static char before[BDL_BEACON_CAP];
    static char after[BDL_BEACON_CAP];
    struct stat probe;
    if (stat(beacon_path, &probe) != 0)
        (void)bdl_write_file(beacon_path,
            "{\"schema\":\"zcl.boot_status.v1\",\"stage_ordinal\":9,"
            "\"serving\":true}\n");
    struct stat before_st;
    size_t before_len = 0;
    out->beacon_read = bdl_read_beacon(beacon_path, before, &before_len,
                                       &before_st);
    out->parent_refused = !boot_datadir_lock_acquire(dir);
    struct stat after_st;
    size_t after_len = 0;
    bool after_read = bdl_read_beacon(beacon_path, after, &after_len,
                                      &after_st);
    out->beacon_stable = out->beacon_read && after_read &&
                         after_len == before_len &&
                         memcmp(before, after, before_len) == 0 &&
                         after_st.st_ino == before_st.st_ino &&
                         after_st.st_mtime == before_st.st_mtime;
}

/* A live owner holds the datadir and has published its beacon. A second
 * process is refused, and the refused attempt must not replace or rewrite the
 * owner's boot_status.json: same bytes, same inode, same mtime. */
static int test_boot_datadir_lock_owner_beacon_stable(void)
{
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_datadir_lock", "owner_beacon");
    char beacon_path[512];
    snprintf(beacon_path, sizeof(beacon_path), "%s/boot_status.json", dir);
    int ready_pipe[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    bool pipes_ok = pipe(ready_pipe) == 0 && pipe(release_pipe) == 0;
    pid_t child = pipes_ok ? fork() : -1;
    if (child == 0) {
        close(ready_pipe[0]);
        close(release_pipe[1]);
        bdl_owner_hold(dir, ready_pipe[1], release_pipe[0]);
    }

    bool owner_ready = false;
    bool child_clean = false;
    struct bdl_beacon_probe probe = {false, false, false};
    if (child > 0) {
        close(ready_pipe[1]);
        close(release_pipe[0]);
        char ready = 0;
        owner_ready = read(ready_pipe[0], &ready, 1) == 1 && ready == '1';
        close(ready_pipe[0]);
        if (owner_ready)
            bdl_probe_refusal(dir, beacon_path, &probe);
        char release = '1';
        if (owner_ready)
            (void)!write(release_pipe[1], &release, 1);
        close(release_pipe[1]);
        int status = 0;
        child_clean = waitpid(child, &status, 0) == child &&
                      WIFEXITED(status) && WEXITSTATUS(status) == 0;
    } else {
        bdl_close_fds(ready_pipe, release_pipe);
    }
    BDL_CHECK("owner beacon is readable, non-empty and under 64 KiB",
              pipes_ok && owner_ready && probe.beacon_read);
    BDL_CHECK("second acquire is refused while the owner holds the datadir",
              probe.parent_refused);
    BDL_CHECK("refused acquire leaves owner beacon byte, inode and mtime intact",
              probe.beacon_stable);
    BDL_CHECK("owner releases cleanly after the refusal", child_clean);
    test_rm_rf_recursive(dir);
    return failures;
}

static int test_boot_datadir_lock_platform_arm(void)
{
    int failures = 0;

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_datadir_lock", "basic");
        char pid_path[512];
        char buf[64];
        snprintf(pid_path, sizeof(pid_path), "%s/zclassic23.pid", dir);

        bool ok = boot_datadir_lock_acquire(dir);
        bool read_ok = bdl_read_file(pid_path, buf, sizeof(buf));
        char want[64];
        snprintf(want, sizeof(want), "%ld\n", (long)getpid());
        BDL_CHECK("acquire writes current pid",
                  ok && read_ok && strcmp(buf, want) == 0);

        boot_datadir_lock_release();
        BDL_CHECK("release retains reusable lock inode",
                  access(pid_path, F_OK) == 0);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_datadir_lock", "concurrent");
        char pid_path[512];
        char buf[64];
        snprintf(pid_path, sizeof(pid_path), "%s/zclassic23.pid", dir);

        int ready_pipe[2] = {-1, -1};
        int release_pipe[2] = {-1, -1};
        bool pipes_ok = pipe(ready_pipe) == 0;
        if (pipes_ok)
            pipes_ok = pipe(release_pipe) == 0;
        pid_t child = pipes_ok ? fork() : -1;
        if (child == 0) {
            close(ready_pipe[0]);
            close(release_pipe[1]);
            bool locked = boot_datadir_lock_acquire(dir);
            char ready = locked ? '1' : '0';
            (void)!write(ready_pipe[1], &ready, 1);
            close(ready_pipe[1]);
            if (locked) {
                char release = 0;
                (void)!read(release_pipe[0], &release, 1);
                boot_datadir_lock_release();
            }
            close(release_pipe[0]);
            _exit(locked ? 0 : 1);
        }

        bool child_ready = false;
        bool parent_refused = false;
        bool child_clean = false;
        bool parent_reacquired = false;
        if (child > 0) {
            close(ready_pipe[1]);
            close(release_pipe[0]);
            char ready = 0;
            child_ready = read(ready_pipe[0], &ready, 1) == 1 && ready == '1';
            close(ready_pipe[0]);
            if (child_ready) {
                parent_refused = !boot_datadir_lock_acquire(dir);
                char release = '1';
                (void)!write(release_pipe[1], &release, 1);
            }
            close(release_pipe[1]);
            int status = 0;
            child_clean = waitpid(child, &status, 0) == child &&
                          WIFEXITED(status) && WEXITSTATUS(status) == 0;
            parent_reacquired = boot_datadir_lock_acquire(dir);
            if (parent_reacquired) {
                parent_reacquired = bdl_read_file(pid_path, buf, sizeof(buf));
                boot_datadir_lock_release();
            }
        } else {
            if (ready_pipe[0] >= 0) close(ready_pipe[0]);
            if (ready_pipe[1] >= 0) close(ready_pipe[1]);
            if (release_pipe[0] >= 0) close(release_pipe[0]);
            if (release_pipe[1] >= 0) close(release_pipe[1]);
        }
        BDL_CHECK("concurrent process excluded then release permits acquire",
                  pipes_ok && child_ready && parent_refused && child_clean &&
                  parent_reacquired);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_datadir_lock", "stale");
        char pid_path[512];
        char buf[64];
        snprintf(pid_path, sizeof(pid_path), "%s/zclassic23.pid", dir);

        bool ok = bdl_write_file(pid_path, "99999999\n");
        ok = ok && boot_datadir_lock_acquire(dir);
        ok = ok && bdl_read_file(pid_path, buf, sizeof(buf));
        char want[64];
        snprintf(want, sizeof(want), "%ld\n", (long)getpid());
        BDL_CHECK("stale lock file is reused", ok && strcmp(buf, want) == 0);

        boot_datadir_lock_release();
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_datadir_lock", "symlink");
        char pid_path[512];
        char target_path[512];
        char buf[64];
        struct stat st;
        snprintf(pid_path, sizeof(pid_path), "%s/zclassic23.pid", dir);
        snprintf(target_path, sizeof(target_path), "%s/not-a-lock", dir);

        bool ok = bdl_write_file(target_path, "do-not-touch\n");
        ok = ok && symlink(target_path, pid_path) == 0;
        ok = ok && !boot_datadir_lock_acquire(dir);
        ok = ok && bdl_read_file(target_path, buf, sizeof(buf));
        ok = ok && strcmp(buf, "do-not-touch\n") == 0;
        ok = ok && lstat(pid_path, &st) == 0 && S_ISLNK(st.st_mode);
        BDL_CHECK("symlink lock path is refused without touching target", ok);
        boot_datadir_lock_release();
        test_rm_rf_recursive(dir);
    }

    {
        char parent[256];
        test_make_tmpdir(parent, sizeof(parent), "boot_datadir_lock",
                         "datadir_symlink");
        char real_dir[512];
        char alias_dir[512];
        snprintf(real_dir, sizeof(real_dir), "%s/real", parent);
        snprintf(alias_dir, sizeof(alias_dir), "%s/alias", parent);
        bool ok = mkdir(real_dir, 0700) == 0 &&
                  symlink(real_dir, alias_dir) == 0 &&
                  !boot_datadir_lock_acquire(alias_dir);
        BDL_CHECK("symlink datadir is refused", ok);
        boot_datadir_lock_release();
        test_rm_rf_recursive(parent);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_datadir_lock", "reacquire");
        bool first = boot_datadir_lock_acquire(dir);
        bool duplicate_refused = first && !boot_datadir_lock_acquire(dir);
        boot_datadir_lock_release();
        bool second = boot_datadir_lock_acquire(dir);
        boot_datadir_lock_release();
        BDL_CHECK("release is idempotent and permits reacquire",
                  first && duplicate_refused && second);
        boot_datadir_lock_release();
        test_rm_rf_recursive(dir);
    }

    {
        BDL_CHECK("null datadir fails closed",
                  !boot_datadir_lock_acquire(NULL));
        BDL_CHECK("empty datadir fails closed",
                  !boot_datadir_lock_acquire(""));
    }

    /* ── the refusal TEXT, not just the refusal ─────────────────────────
     * A pre-registry failure has one channel: stderr. Each case pins the code
     * AND the specific next command, so a remedy that stops naming a runnable
     * step fails here. */
    {
        boot_error_reset_for_testing();
        BDL_CHECK("null datadir refusal is a typed block",
                  !boot_datadir_lock_acquire(NULL) &&
                  bdl_render_is_typed_block("BOOT_DATADIR_UNSET",
                                            "datadir_lock") &&
                  bdl_render_has("  next[1]:  zclassic23 -datadir=") &&
                  bdl_render_has("            why: "));
        BDL_CHECK("first FATAL code latches for the boot call site",
                  boot_error_reported() &&
                  strcmp(boot_error_first_code(),
                         "BOOT_DATADIR_UNSET") == 0);
    }

    {
        char parent[256];
        test_make_tmpdir(parent, sizeof(parent), "boot_datadir_lock",
                         "missing_datadir");
        char absent[512];
        char want_mkdir[600];
        snprintf(absent, sizeof(absent), "%s/never-created", parent);
        snprintf(want_mkdir, sizeof(want_mkdir), "next[1]:  mkdir -p %s",
                 absent);

        boot_error_reset_for_testing();
        bool refused = !boot_datadir_lock_acquire(absent);
        BDL_CHECK("missing datadir names its code, parent and mkdir remedy",
                  refused &&
                  bdl_render_is_typed_block("BOOT_DATADIR_MISSING",
                                            "datadir_lock") &&
                  bdl_render_has(want_mkdir) &&
                  bdl_render_has("parent=") &&
                  bdl_render_has("open_errno=No such file or directory"));
        test_rm_rf_recursive(parent);
    }

    {
        char parent[256];
        test_make_tmpdir(parent, sizeof(parent), "boot_datadir_lock",
                         "symlink_text");
        char real_dir[512];
        char alias_dir[512];
        char want_readlink[600];
        snprintf(real_dir, sizeof(real_dir), "%s/real", parent);
        snprintf(alias_dir, sizeof(alias_dir), "%s/alias", parent);
        snprintf(want_readlink, sizeof(want_readlink),
                 "next[1]:  readlink -f %s", alias_dir);

        boot_error_reset_for_testing();
        bool built = mkdir(real_dir, 0700) == 0 &&
                     symlink(real_dir, alias_dir) == 0;
        bool refused = built && !boot_datadir_lock_acquire(alias_dir);
        /* Linux answers open(O_DIRECTORY|O_NOFOLLOW) over a symlink with
         * ENOTDIR, not ELOOP; the code assertion below keeps the
         * classification honest. */
        BDL_CHECK("symlinked datadir explains O_NOFOLLOW and how to resolve it",
                  refused &&
                  bdl_render_is_typed_block("BOOT_DATADIR_SYMLINK_REFUSED",
                                            "datadir_lock") &&
                  bdl_render_has(want_readlink) &&
                  bdl_render_has("O_NOFOLLOW"));
        boot_datadir_lock_release();
        test_rm_rf_recursive(parent);
    }

    {
        /* ENOTDIR has three causes needing three answers. The symlink case is
         * covered above; a PARENT that is a file must not send the operator to
         * `ls -ld <datadir>`, since the datadir does not exist to list. */
        char parent[256];
        test_make_tmpdir(parent, sizeof(parent), "boot_datadir_lock",
                         "notdir_text");
        char plain[512];
        char under[600];
        char want_ls[600];
        snprintf(plain, sizeof(plain), "%s/plainfile", parent);
        snprintf(under, sizeof(under), "%s/sub", plain);
        /* Both cases must list `plain`: in the first it is the datadir, in the
         * second the datadir's parent. */
        snprintf(want_ls, sizeof(want_ls), "next[1]:  ls -ld %s", plain);

        bool built = bdl_write_file(plain, "not-a-directory\n");

        boot_error_reset_for_testing();
        bool self_ok = built && !boot_datadir_lock_acquire(plain) &&
                       bdl_render_is_typed_block("BOOT_DATADIR_NOT_A_DIRECTORY",
                                                 "datadir_lock") &&
                       bdl_render_has("path_lstat=ok") &&
                       bdl_render_has(want_ls) &&
                       bdl_render_has("path itself is a file");
        BDL_CHECK("a file as -datadir= says the path itself is the file",
                  self_ok);

        boot_error_reset_for_testing();
        bool parent_ok = built && !boot_datadir_lock_acquire(under) &&
                         bdl_render_is_typed_block(
                             "BOOT_DATADIR_NOT_A_DIRECTORY", "datadir_lock") &&
                         bdl_render_has("path_lstat=failed") &&
                         bdl_render_has(want_ls) &&
                         bdl_render_has("PARENT component");
        BDL_CHECK("a file PARENT component points at the parent, not the path",
                  parent_ok);

        test_rm_rf_recursive(parent);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_datadir_lock", "reenter_text");
        boot_error_reset_for_testing();
        bool first = boot_datadir_lock_acquire(dir);
        bool refused = first && !boot_datadir_lock_acquire(dir);
        /* No next[] here on purpose: re-entry is an internal ordering bug,
         * and naming an operator command would be a guess. */
        BDL_CHECK("re-entrant acquire is typed and suggests no false remedy",
                  refused &&
                  bdl_render_is_typed_block("BOOT_DATADIR_LOCK_REENTERED",
                                            "datadir_lock") &&
                  !bdl_render_has("  next[1]:"));
        boot_datadir_lock_release();
        test_rm_rf_recursive(dir);
    }

    {
        /* Cross-process contention: the message must carry the HOLDER's pid,
         * which is the one fact that turns "cannot start" into an action. */
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_datadir_lock", "held_text");

        int ready_pipe[2] = {-1, -1};
        int release_pipe[2] = {-1, -1};
        bool pipes_ok = pipe(ready_pipe) == 0 && pipe(release_pipe) == 0;
        pid_t child = pipes_ok ? fork() : -1;
        if (child == 0) {
            close(ready_pipe[0]);
            close(release_pipe[1]);
            bool locked = boot_datadir_lock_acquire(dir);
            char ready = locked ? '1' : '0';
            (void)!write(ready_pipe[1], &ready, 1);
            close(ready_pipe[1]);
            if (locked) {
                char release = 0;
                (void)!read(release_pipe[0], &release, 1);
                boot_datadir_lock_release();
            }
            close(release_pipe[0]);
            _exit(locked ? 0 : 1);
        }

        bool holder_named = false;
        if (child > 0) {
            close(ready_pipe[1]);
            close(release_pipe[0]);
            char ready = 0;
            bool child_ready =
                read(ready_pipe[0], &ready, 1) == 1 && ready == '1';
            close(ready_pipe[0]);
            if (child_ready) {
                char want_pid[64];
                char want_ps[64];
                snprintf(want_pid, sizeof(want_pid), "holder_pid=%ld",
                         (long)child);
                snprintf(want_ps, sizeof(want_ps),
                         "next[1]:  ps -o pid,lstart,cmd -p %ld", (long)child);
                boot_error_reset_for_testing();
                holder_named =
                    !boot_datadir_lock_acquire(dir) &&
                    bdl_render_is_typed_block("BOOT_DATADIR_LOCKED",
                                              "datadir_lock") &&
                    bdl_render_has(want_pid) && bdl_render_has(want_ps);
                char release = '1';
                (void)!write(release_pipe[1], &release, 1);
            }
            close(release_pipe[1]);
            int status = 0;
            (void)waitpid(child, &status, 0);
        } else {
            if (ready_pipe[0] >= 0) close(ready_pipe[0]);
            if (ready_pipe[1] >= 0) close(ready_pipe[1]);
            if (release_pipe[0] >= 0) close(release_pipe[0]);
            if (release_pipe[1] >= 0) close(release_pipe[1]);
        }
        BDL_CHECK("held datadir names the holding pid and how to inspect it",
                  pipes_ok && holder_named);
        test_rm_rf_recursive(dir);
    }

    failures += test_boot_datadir_lock_owner_beacon_stable();

    boot_error_reset_for_testing();
    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's forked datadir-lock contention child lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_boot_datadir_lock_platform_arm(void)
{
    printf("boot_datadir_lock: SKIP (Windows): forked datadir-lock contention child lane\n");
    return 0;
}
#endif

int test_boot_datadir_lock(void)
{
    return test_boot_datadir_lock_platform_arm();
}
