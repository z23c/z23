/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: cases for the tmpfs scratch root lifecycle (test/test_scratch_reap.h)
 *          and for the runner that uses it. Called from the test_group_selector
 *          group. Every case uses a private parent directory; none touches
 *          the real /dev/shm/z23-scratch.
 */
#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/test_core.h"
#include "test/test_scratch_reap.h"
#include "platform/os_proc.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum { TSC_AGED = 3600, TSC_LEGACY_OLD = 7 * 3600, TSC_ANCIENT = 100 * 86400 };

/* Age a path (symlinks included) by seconds. */
static bool tsc_age(const char *path, int seconds_back)
{
    struct timespec ts[2];
    ts[0].tv_sec = time(NULL) - seconds_back;
    ts[0].tv_nsec = 0;
    ts[1] = ts[0];
    return utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW) == 0;
}

static bool tsc_path(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool tsc_exists(const char *dir, const char *name)
{
    char path[PATH_MAX];
    struct stat st;
    return tsc_path(path, sizeof(path), dir, name) && lstat(path, &st) == 0;
}

static bool tsc_touch(const char *dir, const char *name)
{
    char path[PATH_MAX];
    if (!tsc_path(path, sizeof(path), dir, name)) return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    return close(fd) == 0;
}

/* A file with real data: tmpfs reports no blocks for empty files or directories. */
static bool tsc_fill(const char *dir, const char *name)
{
    char path[PATH_MAX], page[8192];
    if (!tsc_path(path, sizeof(path), dir, name)) return false;
    memset(page, 'e', sizeof(page));
    int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = write(fd, page, sizeof(page)) == (ssize_t)sizeof(page);
    return close(fd) == 0 && ok;
}

/* A root with a nested read-only directory and file, then dated back.
 * with_lock adds the (unheld) runner lock file a dead runner leaves. */
static bool tsc_make_root(const char *parent, const char *name, bool with_lock,
                          int seconds_back)
{
    char root[PATH_MAX], sub[PATH_MAX], file[PATH_MAX];
    if (!tsc_path(root, sizeof(root), parent, name) || mkdir(root, 0700) != 0 ||
        !tsc_path(sub, sizeof(sub), root, "ro") || mkdir(sub, 0700) != 0 ||
        !tsc_path(file, sizeof(file), sub, "evidence") || !tsc_fill(sub, "evidence"))
        return false;
    if (with_lock && !tsc_touch(root, TSR_LOCK_NAME)) return false;
    if (chmod(file, 0400) != 0 || chmod(sub, 0500) != 0) return false;
    return seconds_back == 0 || tsc_age(root, seconds_back);
}

static bool tsc_parent(char *parent, size_t cap, const char *root)
{
    return tsc_path(parent, cap, root, "scratch") && mkdir(parent, 0700) == 0;
}

/* ---- removal -------------------------------------------------------- */

/* A tree deeper than PATH_MAX with read-only directories and a symlink that
 * points out of it. */
static bool tsc_build_deep(int rootfd, int levels, const char *outside)
{
    char name[96];
    memset(name, 'd', sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    int cur = dup(rootfd);
    for (int i = 0; i < levels && cur >= 0; i++) {
        int next = mkdirat(cur, name, 0700) == 0
            ? openat(cur, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
        close(cur);
        cur = next;
    }
    bool ok = cur >= 0 && symlinkat(outside, cur, "escape") == 0;
    if (cur >= 0) close(cur);
    return ok;
}

static int test_tsr_remove_tree(void)
{
    int failures = 0;
    TEST("scratch reap: read-only, over-long and symlinked trees are removed in place") {
        char base[PATH_MAX], parent[PATH_MAX], outside[PATH_MAX];
        test_make_tmpdir(base, sizeof(base), "tsr", "remove");
        ASSERT(tsc_parent(parent, sizeof(parent), base));
        ASSERT(tsc_path(outside, sizeof(outside), base, "outside") && mkdir(outside, 0700) == 0);
        ASSERT(tsc_touch(outside, "survivor"));
        ASSERT(tsc_make_root(parent, "aaaaaaaa.BBBBBB", true, 0));
        char root[PATH_MAX];
        ASSERT(tsc_path(root, sizeof(root), parent, "aaaaaaaa.BBBBBB"));
        int rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        ASSERT(rootfd >= 0);
        ASSERT(tsc_build_deep(rootfd, 60, outside));   /* 60 * 97 > PATH_MAX */
        char none[PATH_MAX];   /* a mode-0 directory with content */
        ASSERT(tsc_path(none, sizeof(none), root, "none") && mkdir(none, 0700) == 0);
        ASSERT(tsc_touch(none, "x") && chmod(none, 0000) == 0);
        close(rootfd);
        int pfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        ASSERT(pfd >= 0);
        uint64_t seen = 0, dry = 0;
        ASSERT(tsr_remove_tree(pfd, "aaaaaaaa.BBBBBB", false, &dry) == 0);
        ASSERT(tsc_exists(parent, "aaaaaaaa.BBBBBB"));
        ASSERT(tsr_remove_tree(pfd, "aaaaaaaa.BBBBBB", true, &seen) == 0);
        close(pfd);
        ASSERT(!tsc_exists(parent, "aaaaaaaa.BBBBBB"));
        ASSERT(seen > 0 && seen >= dry);
        ASSERT(tsc_exists(outside, "survivor"));   /* the link was not followed */
        ASSERT(test_rm_rf_recursive(base) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- classification -------------------------------------------------- */

struct tsc_fixture {
    char base[PATH_MAX], parent[PATH_MAX];
    int live_lock, legacy_lock, busy_fd;
};

static bool tsc_hold_lock_file(const char *parent, const char *name, int *fd)
{
    char root[PATH_MAX];
    if (!tsc_path(root, sizeof(root), parent, name)) return false;
    *fd = tsr_lock_root(root);
    return *fd >= 0 && tsc_age(root, TSC_ANCIENT);
}

static bool tsc_hold_dir_lock(const char *parent, const char *name, int *fd)
{
    char root[PATH_MAX];
    if (!tsc_path(root, sizeof(root), parent, name)) return false;
    *fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return *fd >= 0 && flock(*fd, LOCK_EX | LOCK_NB) == 0;
}

static bool tsc_hold_busy(const char *parent, const char *name, int *fd)
{
    char root[PATH_MAX], file[PATH_MAX];
    if (!tsc_path(root, sizeof(root), parent, name) ||
        !tsc_path(file, sizeof(file), root, "open"))
        return false;
    *fd = open(file, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    return *fd >= 0 && tsc_age(root, TSC_ANCIENT);
}

static bool tsc_keep_roots(const char *parent)
{
    char root[PATH_MAX];
    if (!tsc_make_root(parent, "bbbbbbb1.KEEP00", true, TSC_AGED) ||
        !tsc_make_root(parent, "bbbbbbb2.EXPIRE", true, TSC_AGED))
        return false;
    if (!tsc_path(root, sizeof(root), parent, "bbbbbbb1.KEEP00") || !tsr_keep_mark(root))
        return false;
    if (!tsc_path(root, sizeof(root), parent, "bbbbbbb2.EXPIRE") || !tsr_keep_mark(root))
        return false;
    char marker[PATH_MAX];
    return tsc_path(marker, sizeof(marker), root, TSR_KEEP_NAME) &&
           tsc_age(marker, TSR_KEEP_SECONDS + 3600) && tsc_age(root, TSC_AGED);
}

/* Entries the reaper must not mistake for roots. */
static bool tsc_build_foreign(const struct tsc_fixture *f)
{
    char sym[PATH_MAX];
    if (!tsc_make_root(f->parent, "NOTAROOT", true, TSC_ANCIENT) ||    /* wrong shape */
        !tsc_touch(f->parent, "88888888.FILE00") ||                    /* not a directory */
        !tsc_path(sym, sizeof(sym), f->parent, "99999999.LINK00") ||
        symlink(f->base, sym) != 0)
        return false;
    return tsc_age(sym, TSC_ANCIENT) && tsc_age(f->parent, 0);
}

/* Dead and survivor roots of every shape the reaper must tell apart. */
static bool tsc_build(struct tsc_fixture *f)
{
    if (!tsc_make_root(f->parent, "11111111.DEAD00", true, TSC_AGED) ||     /* dead: lock free */
        !tsc_make_root(f->parent, "22222222.LEGACY", false, TSC_LEGACY_OLD) || /* dead: old, unused */
        !tsc_make_root(f->parent, "33333333.LIVE00", true, TSC_ANCIENT) ||
        !tsc_make_root(f->parent, "44444444.DIRLCK", false, TSC_ANCIENT) ||
        !tsc_make_root(f->parent, "55555555.YOUNG0", false, TSC_AGED) ||
        !tsc_make_root(f->parent, "66666666.FRESH0", true, 0) ||
        !tsc_make_root(f->parent, "77777777.BUSY00", true, TSC_AGED) ||
        !tsc_keep_roots(f->parent) || !tsc_build_foreign(f))
        return false;
    return tsc_hold_lock_file(f->parent, "33333333.LIVE00", &f->live_lock) &&
           tsc_hold_dir_lock(f->parent, "44444444.DIRLCK", &f->legacy_lock) &&
           tsc_hold_busy(f->parent, "77777777.BUSY00", &f->busy_fd);
}

static void tsc_close_holders(struct tsc_fixture *f)
{
    int *fds[] = {&f->live_lock, &f->legacy_lock, &f->busy_fd};
    for (size_t i = 0; i < 3; i++)
        if (*fds[i] >= 0) { close(*fds[i]); *fds[i] = -1; }
}

static bool tsc_survivors(const struct tsc_fixture *f)
{
    static const char *const keep[] = {"33333333.LIVE00", "44444444.DIRLCK",
        "55555555.YOUNG0", "66666666.FRESH0", "77777777.BUSY00", "bbbbbbb1.KEEP00",
        "NOTAROOT", "88888888.FILE00", "99999999.LINK00"};
    for (size_t i = 0; i < sizeof(keep) / sizeof(keep[0]); i++)
        if (!tsc_exists(f->parent, keep[i])) return false;
    return !tsc_exists(f->parent, "11111111.DEAD00") &&
           !tsc_exists(f->parent, "22222222.LEGACY") &&
           !tsc_exists(f->parent, "bbbbbbb2.EXPIRE");
}

static int test_tsr_classify(void)
{
    int failures = 0;
    struct tsc_fixture f = {.live_lock = -1, .legacy_lock = -1, .busy_fd = -1};
    TEST("scratch reap: dead roots of any hash are reaped; live, kept and foreign are not") {
        test_make_tmpdir(f.base, sizeof(f.base), "tsr", "classify");
        ASSERT(tsc_parent(f.parent, sizeof(f.parent), f.base));
        ASSERT(tsc_build(&f));
        struct tsr_report dry, applied;
        int64_t now = (int64_t)time(NULL);
        ASSERT(tsr_reap_parent(f.parent, geteuid(), now, false, &dry) == 0);
        ASSERT(dry.dead == 3 && dry.reaped == 0 && dry.dead_bytes > 0);
        ASSERT(tsc_exists(f.parent, "11111111.DEAD00"));   /* a dry run removes nothing */
        ASSERT(dry.live == 3 && dry.kept == 1 && dry.young == 2 && dry.foreign == 3);
        ASSERT(tsr_reap_parent(f.parent, geteuid(), now, true, &applied) == 0);
        ASSERT(applied.dead == dry.dead && applied.reaped == dry.dead);
        ASSERT(applied.dead_bytes == dry.dead_bytes && applied.reaped_bytes == dry.dead_bytes);
        ASSERT(applied.failed == 0 && tsc_survivors(&f));
        /* Once the holders exit, the next sweep reaps what they protected. */
        tsc_close_holders(&f);
        ASSERT(tsr_reap_parent(f.parent, geteuid(), now, true, &applied) == 0);
        ASSERT(applied.reaped == 3);
        ASSERT(!tsc_exists(f.parent, "33333333.LIVE00") &&
               !tsc_exists(f.parent, "44444444.DIRLCK") &&
               !tsc_exists(f.parent, "77777777.BUSY00"));
        PASS();
    } _test_next:;
    tsc_close_holders(&f);
    if (f.base[0] && test_rm_rf_recursive(f.base) != 0) failures++;
    return failures;
}

static int test_tsr_foreign_owner(void)
{
    int failures = 0;
    TEST("scratch reap: a root owned by another uid is left alone") {
        char base[PATH_MAX], parent[PATH_MAX];
        test_make_tmpdir(base, sizeof(base), "tsr", "owner");
        ASSERT(tsc_parent(parent, sizeof(parent), base));
        ASSERT(tsc_make_root(parent, "aaaaaaaa.DEAD00", true, TSC_AGED));
        struct tsr_report r;
        ASSERT(tsr_reap_parent(parent, geteuid() + 1, (int64_t)time(NULL), true, &r) == 0);
        ASSERT(r.foreign == 1 && r.reaped == 0 && tsc_exists(parent, "aaaaaaaa.DEAD00"));
        ASSERT(chmod(parent, 0777) == 0);   /* an unsafe parent is refused outright */
        ASSERT(tsr_reap_parent(parent, geteuid(), (int64_t)time(NULL), true, &r) != 0);
        ASSERT(tsc_exists(parent, "aaaaaaaa.DEAD00"));
        ASSERT(chmod(parent, 0700) == 0);
        ASSERT(test_rm_rf_recursive(base) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- the runner ------------------------------------------------------ */

static int tsc_run_runner(const char *cwd, const char *parent, char *out, size_t cap)
{
    char exe[PATH_MAX], parent_env[PATH_MAX + 32];
    if (!os_proc_exe_path(exe, sizeof(exe)) ||
        snprintf(parent_env, sizeof(parent_env), "ZCL_TEST_TMPFS_PARENT=%s", parent) <= 0)
        return -1;
    const char *env = access("/usr/bin/env", X_OK) == 0 ? "/usr/bin/env" : "/bin/env";
    const char *args[] = {env, "-u", "ZCL_TEST_TMPROOT", "-u", "ZCL_TEST_TMPFS_ACTIVE",
        "ZCL_TEST_TMPFS=1", "ZCL_TEST_TMPFS_MAX_MB=2048", parent_env, exe,
        "--jobs=1", "--no-cache", "--exact=test_hex_codec", NULL};
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_in_dir_observed(args, cwd, out, cap, 120000, &timed_out);
    return timed_out ? -1 : rc;
}

static bool tsc_shm_parent(char *parent, size_t cap)
{
    snprintf(parent, cap, "/dev/shm/z23-scratch-selftest.XXXXXX");
    return mkdtemp(parent) != NULL;
}

static bool tsc_empty(const char *dir)
{
    struct tsr_report r;
    return tsr_reap_parent(dir, geteuid(), 0, false, &r) == 0 &&
           r.live + r.kept + r.young + r.foreign + r.dead == 0;
}

/* Remove the private parent and whatever a failed assertion left in it. */
static bool tsc_remove_parent(const char *parent)
{
    char dir[PATH_MAX];
    const char *slash = strrchr(parent, '/');
    if (!slash || slash == parent || (size_t)(slash - parent) >= sizeof(dir)) return false;
    memcpy(dir, parent, (size_t)(slash - parent));
    dir[slash - parent] = '\0';
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = tsr_remove_tree(fd, slash + 1, true, NULL) == 0;
    close(fd);
    return ok;
}

static int test_tsr_runner(void)
{
    int failures = 0, live = -1;
    static char out[256 * 1024];
    char parent[PATH_MAX] = "", base[PATH_MAX] = "", cwd[PATH_MAX];
    TEST("scratch reap: a finishing runner leaves nothing and reaps a killed runner's root") {
        if (!tsc_shm_parent(parent, sizeof(parent))) {
            parent[0] = '\0';
            printf("SKIP (no /dev/shm)\n");
            goto _test_next;
        }
        test_make_tmpdir(base, sizeof(base), "tsr", "runner");
        ASSERT(tsc_path(cwd, sizeof(cwd), base, "elsewhere") && mkdir(cwd, 0700) == 0);
        int rc = tsc_run_runner(cwd, parent, out, sizeof(out));
        if (strstr(out, "tmpfs unavailable or disabled")) {
            printf("SKIP (tmpfs unavailable)\n");
            goto _test_next;
        }
        ASSERT(rc == 0 && tsc_empty(parent));            /* a normal exit removes its root */
        /* A killed runner's root (other cwd hash, lock free, read-only subtree)
         * and a live one (lock held, old) side by side. */
        ASSERT(tsc_make_root(parent, "deadbeef.KILLED", true, TSC_AGED));
        ASSERT(tsc_make_root(parent, "cafef00d.ALIVE0", true, TSC_AGED));
        ASSERT(tsc_hold_lock_file(parent, "cafef00d.ALIVE0", &live));
        rc = tsc_run_runner(cwd, parent, out, sizeof(out));
        ASSERT(rc == 0 && strstr(out, "reaped 1 dead tmpfs root") != NULL);
        ASSERT(!tsc_exists(parent, "deadbeef.KILLED") && tsc_exists(parent, "cafef00d.ALIVE0"));
        PASS();
    } _test_next:;
    if (live >= 0) close(live);
    if (base[0] && test_rm_rf_recursive(base) != 0) failures++;
    if (parent[0] && !tsc_remove_parent(parent)) failures++;
    return failures;
}

/* ---- the janitor (tools/scripts/host_gc.sh --only ramscratch) --------- */

static int tsc_run_janitor(const char *base, const char *parent, bool apply,
                           char *out, size_t cap)
{
    char home[PATH_MAX], state[PATH_MAX], h[PATH_MAX + 40], s[PATH_MAX + 40], p[PATH_MAX + 48];
    if (!tsc_path(home, sizeof(home), base, "home") || !tsc_path(state, sizeof(state), base, "state") ||
        snprintf(h, sizeof(h), "ZCL_HOST_GC_HOME=%s", home) <= 0 ||
        snprintf(s, sizeof(s), "ZCL_HOST_GC_STATE=%s", state) <= 0 ||
        snprintf(p, sizeof(p), "ZCL_HOST_GC_RAM_SCRATCH_DIR=%s", parent) <= 0)
        return -1;
    if ((mkdir(home, 0700) != 0 && errno != EEXIST) || (mkdir(state, 0700) != 0 && errno != EEXIST))
        return -1;   /* the sweep refuses a home that does not exist */
    const char *args[] = {"/usr/bin/env", h, s, p, "tools/scripts/host_gc.sh", "--only",
        "ramscratch", apply ? "--apply" : "--dry-run", NULL};
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_in_dir_observed(args, ".", out, cap, 120000, &timed_out);
    return timed_out ? -1 : rc;
}

static unsigned long long tsc_dead_bytes(const char *out)
{
    const char *at = strstr(out, "shm_scratch_dead_bytes=");
    return at ? strtoull(at + strlen("shm_scratch_dead_bytes="), NULL, 10) : ~0ull;
}

static bool tsc_janitor_roots(const char *parent, int *held)
{
    char root[PATH_MAX], marker[PATH_MAX];
    if (!tsc_make_root(parent, "11111111.DEAD00", true, TSC_AGED) ||
        !tsc_make_root(parent, "22222222.LIVE00", true, TSC_AGED) ||
        !tsc_make_root(parent, "33333333.KEEP00", true, TSC_AGED) ||
        !tsc_make_root(parent, "44444444.OLDKP0", true, TSC_AGED) ||
        !tsc_make_root(parent, "55555555.FRESH0", true, 0) ||
        !tsc_path(root, sizeof(root), parent, "33333333.KEEP00") || !tsr_keep_mark(root))
        return false;
    if (!tsc_path(root, sizeof(root), parent, "44444444.OLDKP0") || !tsr_keep_mark(root) ||
        !tsc_path(marker, sizeof(marker), root, TSR_KEEP_NAME) ||
        !tsc_age(marker, TSR_KEEP_SECONDS + 3600) || !tsc_age(root, TSC_AGED))
        return false;
    return tsc_hold_lock_file(parent, "22222222.LIVE00", held);
}

static int test_tsr_janitor(void)
{
    int failures = 0, held = -1;
    static char dry[64 * 1024], applied[64 * 1024];
    char parent[PATH_MAX] = "", base[PATH_MAX] = "";
    TEST("scratch reap: the janitor's dry run and apply agree and honour the lock proof") {
        if (!tsc_shm_parent(parent, sizeof(parent))) {
            parent[0] = '\0';
            printf("SKIP (no /dev/shm)\n");
            goto _test_next;
        }
        test_make_tmpdir(base, sizeof(base), "tsr", "janitor");
        ASSERT(tsc_janitor_roots(parent, &held));
        ASSERT(tsc_run_janitor(base, parent, false, dry, sizeof(dry)) == 0);
        ASSERT(strstr(dry, "ramscratch: REFUSED") == NULL);
        ASSERT(strstr(dry, "KEEP (runner lock held)") != NULL);
        ASSERT(strstr(dry, "KEEP (.z23-keep marker, bounded)") != NULL);
        ASSERT(strstr(dry, "KEEP (inside the 120 s grace)") != NULL);
        ASSERT(tsc_exists(parent, "11111111.DEAD00") && tsc_exists(parent, "44444444.OLDKP0"));
        ASSERT(tsc_run_janitor(base, parent, true, applied, sizeof(applied)) == 0);
        ASSERT(!tsc_exists(parent, "11111111.DEAD00") && !tsc_exists(parent, "44444444.OLDKP0"));
        ASSERT(tsc_exists(parent, "22222222.LIVE00") && tsc_exists(parent, "33333333.KEEP00") &&
               tsc_exists(parent, "55555555.FRESH0"));
        ASSERT(tsc_dead_bytes(dry) > 0 && tsc_dead_bytes(dry) == tsc_dead_bytes(applied));
        PASS();
    } _test_next:;
    if (held >= 0) close(held);
    if (base[0] && test_rm_rf_recursive(base) != 0) failures++;
    if (parent[0] && !tsc_remove_parent(parent)) failures++;
    return failures;
}

int scratch_reap_run_cases(void)
{
    return test_tsr_remove_tree() + test_tsr_classify() + test_tsr_foreign_owner() +
           test_tsr_runner() + test_tsr_janitor();
}

#else
typedef int tsc_not_linux;   /* scratch roots exist only on Linux tmpfs */
#endif
