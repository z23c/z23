/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.lane.new — create an agent worktree and materialise the
 *          proof's vendored dependencies onto independent inodes.
 *
 * WHY THESE FILES ARE PRIMED (cited from tools/command/native_dev_land.c
 * :2468-2503). dev_proof.c's prepare_generation() only ever COPIES the
 * entries in its `dependencies[]` array (vendor/lib, vendor/include, the
 * vendor/tor archives, build/githooks and, on Linux, the two hotswap
 * rollback fixture images) out of paths->root into the proof's private
 * generation; it never builds any of them itself. A bare `git worktree add`
 * inherits none of this: vendored archives are gitignored, the Tor
 * submodule is not checked out into a fresh worktree, and nothing has ever
 * linked a test binary here — so every one of them is missing the first
 * time a fresh worktree reaches a proof, and the proof refuses by name
 * (`proof_generation_dependency_unavailable:<dep> (<fix>)`). This leaf
 * primes those paths once per worktree lifetime, with independent inodes.
 *
 * NEVER call link()/linkat(). Creating another hardlink changes the shared
 * inode's ctime, which refuses every in-flight proof whose seal covered
 * that file. Materialisation uses platform_file_clone_fd() (Linux FICLONE)
 * with a byte-copy fallback, then preserves mode+mtime and rename()s into
 * place. Recursion follows dl_materialize() in native_dev_land.c:2563-2598
 * (plain files and directories only; fail closed on symlinks and devices)
 * and dl_dirs_make()/:219-234 for mkdir of missing parents.
 *
 * PROCESS RULE. `git` and `make` run only through zcl_spawn_capture()
 * (util/spawn.h). No popen(), system(), or shell command string.
 */

/* realpath() is declared by glibc only through the fortify inline unless a
 * feature-test macro asks for it; without this the file compiles today by
 * accident of -O2 and is a hard C23 error at -O0 or on another libc. Must
 * precede the first #include, which is where <features.h> is read. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/file_clone.h"
#include "util/spawn.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DLN_LEAF "dev.lane.new"
#define DLN_PATH_CAP 4096
#define DLN_OUT_CAP 8192
#define DLN_GIT_TIMEOUT_MS 60000
#define DLN_MAKE_TIMEOUT_MS 300000

static void dln_log(const char *what, const char *detail)
{
    fprintf(stderr, "[dev.lane.new] %s: %s\n", what,
            detail && detail[0] ? detail : "");
}

static void dln_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    dln_log(code, message);
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false,
                           false, message, evidence);
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static const char *const DLN_REQUIRED[] = {
    "vendor/tor/libtor.a",
    "vendor/lib",
    "vendor/include",
    "build/githooks",
    "build/hotswap/zcl_rollback_fixture_a.so",
    "build/hotswap/zcl_rollback_fixture_b.so",
};

static void dln_strip(char *s)
{
    size_t n;
    if (!s)
        return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

static bool dln_join(char *out, size_t cap, const char *a, const char *b)
{
    int n;
    if (!out || !a || !b)
        return false;
    n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool dln_is_abs(const char *path)
{
    return path && path[0] == '/';
}

static bool dln_sha_ok(const char *s)
{
    size_t i;
    if (!s || strlen(s) != 40)
        return false;
    for (i = 0; i < 40; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
    }
    return true;
}

static bool dln_ends_with_a(const char *name)
{
    size_t n;
    if (!name)
        return false;
    n = strlen(name);
    return n > 2 && name[n - 2] == '.' && name[n - 1] == 'a';
}

static const char *dln_dep_fix(const char *rel)
{
    if (!rel)
        return "make vendor";
    if (strncmp(rel, "vendor/", 7) == 0)
        return "make vendor";
    if (strncmp(rel, "build/hotswap/", 14) == 0)
        return "make test_parallel";
    return "make install-hooks";
}

/* Run one git command. `dir` is passed as `-C <dir>` (omitted when empty). */
static int dln_git(const char *dir, const char *const args[], char *out,
                   size_t out_cap, int timeout_ms)
{
    const char *argv[24];
    size_t n = 0;
    static char scratch[1];
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i] && n + 1 < sizeof(argv) / sizeof(argv[0]);
         i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    if (out && out_cap)
        out[0] = '\0';
    return zcl_spawn_capture(argv, out ? out : scratch,
                             out ? out_cap : sizeof(scratch), timeout_ms);
}

static bool dln_mkdir_one(const char *path)
{
    struct stat st;
    if (!path || !path[0])
        return false;
    if (mkdir(path, 0700) == 0)
        return true;
    if (errno != EEXIST) {
        dln_log("mkdir", path);
        return false;
    }
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Mirror of dl_dirs_make()'s mkdir-parents shape: create every missing
 * ancestor of `path` (the leaf itself is not created). */
static bool dln_mkdir_parents(const char *path)
{
    char buf[DLN_PATH_CAP];
    char *slash;
    if (!path || snprintf(buf, sizeof(buf), "%s", path) >= (int)sizeof(buf))
        return false;
    slash = strrchr(buf, '/');
    if (!slash || slash == buf)
        return true;
    *slash = '\0';
    for (char *p = buf + 1;; p++) {
        if (*p != '/' && *p != '\0')
            continue;
        char saved = *p;
        *p = '\0';
        if (!dln_mkdir_one(buf))
            return false;
        *p = saved;
        if (!saved)
            break;
    }
    return true;
}

static bool dln_write_all(int fd, const void *data, size_t size)
{
    const unsigned char *p = data;
    while (size > 0) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        p += (size_t)n;
        size -= (size_t)n;
    }
    return true;
}

/* Clone or copy `source` onto a new inode at `target`. NEVER link(). */
static bool dln_clone_file(const char *source, const char *target,
                           const struct stat *source_st)
{
    int input = -1;
    int output = -1;
    char temporary[DLN_PATH_CAP];
    int temporary_len;
    bool ok;
    enum platform_file_clone_result cloned = PLATFORM_FILE_CLONE_UNAVAILABLE;

    input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) {
        dln_log("open_source", source);
        return false;
    }
    temporary_len =
        snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", target);
    ok = temporary_len > 0 && temporary_len < (int)sizeof(temporary);
    if (!ok) {
        dln_log("tmp_path", target);
        (void)close(input);
        return false;
    }
    output = mkstemp(temporary);
    if (output < 0) {
        dln_log("mkstemp", temporary);
        (void)close(input);
        return false;
    }
    cloned = platform_file_clone_fd(input, output);
    if (cloned == PLATFORM_FILE_CLONE_REFUSED) {
        dln_log("file_clone_refused", source);
        errno = EIO;
        ok = false;
    }
    while (ok && cloned == PLATFORM_FILE_CLONE_UNAVAILABLE) {
        unsigned char buffer[65536];
        ssize_t got = read(input, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            dln_log("read", source);
            ok = false;
            break;
        }
        if (got == 0)
            break;
        if (!dln_write_all(output, buffer, (size_t)got)) {
            dln_log("write", temporary);
            ok = false;
            break;
        }
    }
    if (close(input) != 0)
        ok = false;
    input = -1;
    if (output >= 0) {
        if (ok && fchmod(output, source_st->st_mode & 07777) != 0) {
            dln_log("fchmod", temporary);
            ok = false;
        }
        if (ok) {
            const struct timespec times[2] = {
                source_st->st_atim,
                source_st->st_mtim,
            };
            if (futimens(output, times) != 0) {
                dln_log("futimens", temporary);
                ok = false;
            }
        }
        if (close(output) != 0)
            ok = false;
        output = -1;
    }
    if (ok && rename(temporary, target) != 0) {
        dln_log("rename", target);
        ok = false;
    }
    if (!ok)
        (void)unlink(temporary);
    return ok;
}

/* Recursion shape of dl_materialize() (native_dev_land.c:2563-2598) on
 * file_clone: skip an already-present target; copy a regular file onto a
 * new inode; mkdir+recurse a directory; refuse anything else. */
static bool dln_materialize(const char *source, const char *target,
                            int *copied)
{
    struct stat source_st, target_st;
    DIR *dir;
    struct dirent *entry;
    bool ok;

    if (lstat(source, &source_st) != 0) {
        dln_log("lstat_source", source);
        return false;
    }
    if (lstat(target, &target_st) == 0)
        return true;
    if (S_ISREG(source_st.st_mode)) {
        if (!dln_mkdir_parents(target))
            return false;
        if (!dln_clone_file(source, target, &source_st))
            return false;
        if (copied)
            (*copied)++;
        return true;
    }
    if (!S_ISDIR(source_st.st_mode)) {
        /* Regular files only: a symlink or device is not copied. A named
         * directory walk still succeeds after skipping those children. */
        dln_log("skip_non_regular", source);
        return true;
    }
    dir = opendir(source);
    if (!dir) {
        dln_log("opendir", source);
        return false;
    }
    /* Same order as native_dev_land.c's dl_mkdir_parents + dl_materialize:
     * the leaf mkdir cannot create build/githooks when build/ is absent. */
    if (!dln_mkdir_parents(target) || !dln_mkdir_one(target)) {
        (void)closedir(dir);
        return false;
    }
    ok = true;
    while (ok && (entry = readdir(dir)) != NULL) {
        char child_source[DLN_PATH_CAP], child_target[DLN_PATH_CAP];
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (!dln_join(child_source, sizeof(child_source), source,
                      entry->d_name) ||
            !dln_join(child_target, sizeof(child_target), target,
                      entry->d_name) ||
            !dln_materialize(child_source, child_target, copied))
            ok = false;
    }
    return closedir(dir) == 0 && ok;
}

static bool dln_git_common_abs(const char *dir, char *out, size_t cap)
{
    char got[DLN_PATH_CAP], joined[DLN_PATH_CAP], resolved[PATH_MAX];
    static const char *const args[] = { "rev-parse", "--git-common-dir",
                                        NULL };
    const char *src;

    if (dln_git(dir, args, got, sizeof(got), DLN_GIT_TIMEOUT_MS) != 0 ||
        !got[0])
        return false;
    dln_strip(got);
    if (got[0] == '/') {
        src = got;
    } else {
        if (!dln_join(joined, sizeof(joined), dir, got))
            return false;
        src = joined;
    }
    if (realpath(src, resolved)) {
        if (snprintf(out, cap, "%s", resolved) >= (int)cap)
            return false;
        return true;
    }
    if (snprintf(out, cap, "%s", src) >= (int)cap)
        return false;
    return true;
}

static bool dln_is_worktree_of(const char *path, const char *root)
{
    char path_common[DLN_PATH_CAP], root_common[DLN_PATH_CAP];
    if (!dln_git_common_abs(path, path_common, sizeof(path_common)) ||
        !dln_git_common_abs(root, root_common, sizeof(root_common)))
        return false;
    return strcmp(path_common, root_common) == 0;
}

static bool dln_has_git(const char *path)
{
    char marker[DLN_PATH_CAP];
    struct stat st;
    if (!dln_join(marker, sizeof(marker), path, ".git"))
        return false;
    return lstat(marker, &st) == 0;
}

static bool dln_materialize_one(const char *root, const char *dest,
                                const char *rel, int *copied)
{
    char source[DLN_PATH_CAP], target[DLN_PATH_CAP];
    if (!dln_join(source, sizeof(source), root, rel) ||
        !dln_join(target, sizeof(target), dest, rel)) {
        dln_log("path_too_long", rel);
        return false;
    }
    return dln_materialize(source, target, copied);
}

static bool dln_materialize_ext_archives(const char *root, const char *dest,
                                         int *copied, char *failed_rel,
                                         size_t failed_cap)
{
    char ext[DLN_PATH_CAP];
    DIR *d1;
    struct dirent *e1;
    struct stat st;
    bool ok = true;

    if (!dln_join(ext, sizeof(ext), root, "vendor/tor/src/ext"))
        return false;
    if (lstat(ext, &st) != 0)
        return true;
    if (!S_ISDIR(st.st_mode)) {
        if (failed_rel && failed_cap)
            (void)snprintf(failed_rel, failed_cap, "%s",
                           "vendor/tor/src/ext");
        dln_log("ext_not_dir", ext);
        return false;
    }
    d1 = opendir(ext);
    if (!d1) {
        dln_log("opendir", ext);
        if (failed_rel && failed_cap)
            (void)snprintf(failed_rel, failed_cap, "%s",
                           "vendor/tor/src/ext");
        return false;
    }
    while (ok && (e1 = readdir(d1)) != NULL) {
        char l1[DLN_PATH_CAP];
        DIR *d2;
        struct dirent *e2;
        struct stat st1;
        if (strcmp(e1->d_name, ".") == 0 || strcmp(e1->d_name, "..") == 0)
            continue;
        if (!dln_join(l1, sizeof(l1), ext, e1->d_name)) {
            ok = false;
            break;
        }
        if (lstat(l1, &st1) != 0 || !S_ISDIR(st1.st_mode))
            continue;
        d2 = opendir(l1);
        if (!d2) {
            dln_log("opendir", l1);
            ok = false;
            break;
        }
        while (ok && (e2 = readdir(d2)) != NULL) {
            char l2[DLN_PATH_CAP];
            struct stat st2;
            if (strcmp(e2->d_name, ".") == 0 ||
                strcmp(e2->d_name, "..") == 0)
                continue;
            if (!dln_join(l2, sizeof(l2), l1, e2->d_name)) {
                ok = false;
                break;
            }
            if (lstat(l2, &st2) != 0)
                continue;
            if (S_ISREG(st2.st_mode) && dln_ends_with_a(e2->d_name)) {
                char rel[DLN_PATH_CAP];
                int n = snprintf(rel, sizeof(rel),
                                 "vendor/tor/src/ext/%s/%s", e1->d_name,
                                 e2->d_name);
                if (n <= 0 || (size_t)n >= sizeof(rel) ||
                    !dln_materialize_one(root, dest, rel, copied)) {
                    if (failed_rel && failed_cap)
                        (void)snprintf(failed_rel, failed_cap, "%s",
                                       n > 0 ? rel : "vendor/tor/src/ext");
                    ok = false;
                    break;
                }
                continue;
            }
            if (!S_ISDIR(st2.st_mode))
                continue;
            {
                DIR *d3 = opendir(l2);
                struct dirent *e3;
                if (!d3) {
                    dln_log("opendir", l2);
                    ok = false;
                    break;
                }
                while (ok && (e3 = readdir(d3)) != NULL) {
                    char l3[DLN_PATH_CAP];
                    struct stat st3;
                    char rel[DLN_PATH_CAP];
                    int n;
                    if (strcmp(e3->d_name, ".") == 0 ||
                        strcmp(e3->d_name, "..") == 0)
                        continue;
                    if (!dln_join(l3, sizeof(l3), l2, e3->d_name)) {
                        ok = false;
                        break;
                    }
                    if (lstat(l3, &st3) != 0 || !S_ISREG(st3.st_mode) ||
                        !dln_ends_with_a(e3->d_name))
                        continue;
                    n = snprintf(rel, sizeof(rel),
                                 "vendor/tor/src/ext/%s/%s/%s", e1->d_name,
                                 e2->d_name, e3->d_name);
                    if (n <= 0 || (size_t)n >= sizeof(rel) ||
                        !dln_materialize_one(root, dest, rel, copied)) {
                        if (failed_rel && failed_cap)
                            (void)snprintf(failed_rel, failed_cap, "%s",
                                           n > 0 ? rel
                                                 : "vendor/tor/src/ext");
                        ok = false;
                        break;
                    }
                }
                if (closedir(d3) != 0)
                    ok = false;
            }
        }
        if (closedir(d2) != 0)
            ok = false;
    }
    if (closedir(d1) != 0)
        ok = false;
    return ok;
}
#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

void zcl_native_handle_dev_lane_new(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
#if !defined(ZCL_DEV_BUILD) && !defined(ZCL_TESTING)
    (void)request;
    dln_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
             "DEV_BUILD_REQUIRED", "dispatch",
             "agent worktree construction requires a dev build",
             "make dev-bin, or z23-dev dev lane new");
    return;
#else
    const char *path = request && request->input
                           ? json_get_str(json_get(request->input, "path"))
                           : "";
    const char *base = request && request->input
                           ? json_get_str(json_get(request->input, "base"))
                           : "";
    char cwd[DLN_PATH_CAP];
    char root[DLN_PATH_CAP];
    char head[80];
    char why[256];
    char failed_rel[DLN_PATH_CAP];
    int copied = 0;
    struct stat libtor_st;
    char libtor_path[DLN_PATH_CAP];
    const char *make_argv[8];

    if (!getcwd(cwd, sizeof(cwd))) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "lane.root_not_checkout", "root",
                 "cwd is not a git checkout", "");
        return;
    }
    {
        static const char *const top_args[] = { "rev-parse",
                                                "--show-toplevel", NULL };
        if (dln_git(cwd, top_args, root, sizeof(root),
                    DLN_GIT_TIMEOUT_MS) != 0 ||
            !root[0]) {
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INVALID, "lane.root_not_checkout",
                     "root", "cwd is not a git checkout", cwd);
            return;
        }
        dln_strip(root);
    }
    if (!path[0] || !dln_is_abs(path)) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_PATH", "validate",
                 "path must be an absolute worktree path", path);
        return;
    }
    if (!base[0]) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_BASE", "validate", "base is required", "");
        return;
    }
    {
        const char *verify_args[] = { "rev-parse", "--verify", "--quiet",
                                      base, NULL };
        char resolved[80];
        if (dln_git(root, verify_args, resolved, sizeof(resolved),
                    DLN_GIT_TIMEOUT_MS) != 0) {
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INVALID, "lane.base_unresolved",
                     "base", "base does not resolve", base);
            return;
        }
    }

    if (!dln_has_git(path)) {
        const char *add_args[] = { "worktree", "add", "--detach", path,
                                   base, NULL };
        char add_out[DLN_OUT_CAP];
        if (!dln_mkdir_parents(path)) {
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "lane.path_not_worktree",
                     "worktree_add",
                     "could not create the worktree parent directory",
                     path);
            return;
        }
        if (dln_git(root, add_args, add_out, sizeof(add_out),
                    DLN_GIT_TIMEOUT_MS) != 0) {
            dln_log("worktree_add", add_out);
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "lane.path_not_worktree",
                     "worktree_add",
                     "git worktree add --detach failed", path);
            return;
        }
    }
    if (!dln_is_worktree_of(path, root)) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "lane.path_not_worktree", "worktree",
                 "path exists but is not a worktree of this checkout",
                 path);
        return;
    }

    {
        const char *st_args[] = { "submodule", "status", "--",
                                  "vendor/tor", NULL };
        char st_out[DLN_OUT_CAP];
        if (dln_git(path, st_args, st_out, sizeof(st_out),
                    DLN_GIT_TIMEOUT_MS) == 0 &&
            st_out[0] == '-') {
            const char *init_args[] = { "submodule", "update", "--init",
                                        "--", "vendor/tor", NULL };
            char init_out[DLN_OUT_CAP];
            if (dln_git(path, init_args, init_out, sizeof(init_out),
                        DLN_GIT_TIMEOUT_MS) != 0)
                dln_log("submodule_init", init_out);
        }
    }

    /* Preflight every required source that the worktree does not yet hold,
     * so a missing ROOT dependency refuses without copying any sibling. */
    for (size_t i = 0; i < sizeof(DLN_REQUIRED) / sizeof(DLN_REQUIRED[0]);
         i++) {
        char source[DLN_PATH_CAP], target[DLN_PATH_CAP];
        char code[64];
        struct stat source_st, target_st;
        if (!dln_join(source, sizeof(source), root, DLN_REQUIRED[i]) ||
            !dln_join(target, sizeof(target), path, DLN_REQUIRED[i])) {
            (void)snprintf(code, sizeof(code),
                           "lane.dependency_unavailable:%s",
                           DLN_REQUIRED[i]);
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INVALID, code, "deps", code,
                     DLN_REQUIRED[i]);
            return;
        }
        if (lstat(target, &target_st) == 0)
            continue;
        if (lstat(source, &source_st) != 0) {
            (void)snprintf(code, sizeof(code),
                           "lane.dependency_unavailable:%s",
                           DLN_REQUIRED[i]);
            (void)snprintf(why, sizeof(why),
                           "lane.dependency_unavailable:%s (%s)",
                           DLN_REQUIRED[i], dln_dep_fix(DLN_REQUIRED[i]));
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INVALID, code, "deps", why,
                     DLN_REQUIRED[i]);
            return;
        }
    }
    for (size_t i = 0; i < sizeof(DLN_REQUIRED) / sizeof(DLN_REQUIRED[0]);
         i++) {
        char source[DLN_PATH_CAP], target[DLN_PATH_CAP];
        if (!dln_join(source, sizeof(source), root, DLN_REQUIRED[i]) ||
            !dln_join(target, sizeof(target), path, DLN_REQUIRED[i])) {
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "lane.materialize_failed",
                     "materialize", DLN_REQUIRED[i], DLN_REQUIRED[i]);
            return;
        }
        if (!dln_materialize(source, target, &copied)) {
            (void)snprintf(why, sizeof(why), "lane.materialize_failed:%s",
                           DLN_REQUIRED[i]);
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "lane.materialize_failed",
                     "materialize", why, DLN_REQUIRED[i]);
            return;
        }
    }

    failed_rel[0] = '\0';
    if (!dln_materialize_ext_archives(root, path, &copied, failed_rel,
                                      sizeof(failed_rel))) {
        (void)snprintf(why, sizeof(why), "lane.materialize_failed:%s",
                       failed_rel[0] ? failed_rel : "vendor/tor/src/ext");
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INTERNAL, "lane.materialize_failed",
                 "materialize", why, failed_rel);
        return;
    }

    make_argv[0] = "make";
    make_argv[1] = "-C";
    make_argv[2] = path;
    make_argv[3] = "-s";
    make_argv[4] = "install-hooks";
    make_argv[5] = NULL;
    {
        char make_out[DLN_OUT_CAP];
        if (zcl_spawn_capture(make_argv, make_out, sizeof(make_out),
                              DLN_MAKE_TIMEOUT_MS) != 0) {
            dln_log("install_hooks", make_out);
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "lane.hooks_failed",
                     "hooks", "make -s install-hooks failed", path);
            return;
        }
    }

    {
        static const char *const head_args[] = { "rev-parse", "HEAD",
                                                 NULL };
        if (dln_git(path, head_args, head, sizeof(head),
                    DLN_GIT_TIMEOUT_MS) != 0) {
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "GIT_FAILED", "head",
                     "git rev-parse HEAD failed", path);
            return;
        }
        dln_strip(head);
        if (!dln_sha_ok(head)) {
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "GIT_FAILED", "head",
                     "HEAD is not a 40-hex commit", head);
            return;
        }
    }

    if (!dln_join(libtor_path, sizeof(libtor_path), path,
                  "vendor/tor/libtor.a") ||
        lstat(libtor_path, &libtor_st) != 0) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INVALID,
                 "lane.dependency_unavailable:vendor/tor/libtor.a", "deps",
                 "lane.dependency_unavailable:vendor/tor/libtor.a "
                 "(make vendor)",
                 "vendor/tor/libtor.a");
        return;
    }

    (void)json_push_kv_bool(&reply->data, "ok", true);
    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv_str(&reply->data, "head", head);
    (void)json_push_kv_int(&reply->data, "dependencies", copied);
    (void)json_push_kv_int(&reply->data, "libtor_links",
                           (int64_t)libtor_st.st_nlink);
    (void)json_push_kv_bool(&reply->data, "hooks_installed", true);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
#endif
}
