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
#include "util/path_util.h"
#include "util/spawn.h"
#include "proof_dependencies.h"

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
    if (strncmp(rel, "vendor/tor/", 11) == 0)
        return "make tor-full";
    if (strncmp(rel, "vendor/", 7) == 0)
        return "make vendor";
    if (strncmp(rel, "build/bin/", 10) == 0)
        return "make build/bin/z23-lint build/bin/z23-fleet-observe build/bin/gen_capability_inventory";
    if (strncmp(rel, "build/fixtures/", 15) == 0)
        return "make build/fixtures/rlc_child_v1 build/fixtures/rlc_child_broken "
               "build/fixtures/otlp_startup_probe";
    if (strncmp(rel, "build/hotswap/", 14) == 0)
        return "make test_parallel";
    return "make install-hooks";
}

#define DLN_LIST_CAP 256
#define DLN_LIST_RESERVE 32

/* A bounded "; "-joined list. Items that do not fit are counted in hidden
 * and reported by dln_list_close(), never dropped silently. */
struct dln_list {
    char text[DLN_LIST_CAP];
    size_t len;
    int hidden;
};

static void dln_list_add(struct dln_list *l, const char *item)
{
    size_t need = strlen(item) + (l->len ? 2 : 0);
    if (l->len + need + DLN_LIST_RESERVE > sizeof(l->text)) {
        l->hidden++;
        return;
    }
    (void)snprintf(l->text + l->len, sizeof(l->text) - l->len, "%s%s",
                   l->len ? "; " : "", item);
    l->len += need;
}

static void dln_list_close(struct dln_list *l)
{
    if (l->hidden > 0)
        (void)snprintf(l->text + l->len, sizeof(l->text) - l->len,
                       "; +%d more not shown", l->hidden);
}

#define DLN_FIXES_SEEN 8

struct dln_missing {
    struct dln_list paths;
    struct dln_list fixes;
    const char *seen[DLN_FIXES_SEEN];
    size_t seen_n;
    char first[DLN_PATH_CAP];
    int count;
};

/* True the first time a remedy is offered. Remedies come from
 * dln_dep_fix(), which yields fewer than DLN_FIXES_SEEN distinct strings. */
static bool dln_fix_is_new(struct dln_missing *m, const char *fix)
{
    for (size_t i = 0; i < m->seen_n; i++)
        if (strcmp(m->seen[i], fix) == 0)
            return false;
    if (m->seen_n < DLN_FIXES_SEEN)
        m->seen[m->seen_n++] = fix;
    return true;
}

static void dln_missing_add(struct dln_missing *m, const char *rel)
{
    const char *fix = dln_dep_fix(rel);
    if (m->count++ == 0)
        (void)snprintf(m->first, sizeof(m->first), "%s", rel);
    dln_list_add(&m->paths, rel);
    if (dln_fix_is_new(m, fix))
        dln_list_add(&m->fixes, fix);
}

/* Scan every required path. Returns false when a path cannot be composed
 * (the offending relative path is left in m->first and count is -1). */
static bool dln_collect_missing(const char *root, const char *path,
                                struct dln_missing *m)
{
    memset(m, 0, sizeof(*m));
    size_t req_count;
    const struct zcl_dep_row *req_rows = zcl_dep_rows(&req_count);
    for (size_t i = 0; i < req_count; i++) {
        const char *req = req_rows[i].path;
        char source[DLN_PATH_CAP], target[DLN_PATH_CAP];
        struct stat st;
        if (!(req_rows[i].consumers & ZCL_DEP_LANE))
            continue;
        if (!zcl_path_join(source, sizeof(source), root, req) ||
            !zcl_path_join(target, sizeof(target), path, req)) {
            (void)snprintf(m->first, sizeof(m->first), "%s",
                           req);
            m->count = -1;
            return false;
        }
        if (lstat(target, &st) != 0 && lstat(source, &st) != 0)
            dln_missing_add(m, req);
    }
    dln_list_close(&m->paths);
    dln_list_close(&m->fixes);
    return true;
}

/* Refuse once, naming every missing required path and its remedy. Returns
 * true when nothing is missing. Nothing has been created at this point.
 * The reply message holds 192 bytes, so with several missing items the
 * paths go in evidence and the remedies in next_action. */
static bool dln_preflight(struct zcl_command_reply *reply, const char *root,
                          const char *path)
{
    struct dln_missing m;
    char code[DLN_PATH_CAP], why[DLN_PATH_CAP + 128];
    if (dln_collect_missing(root, path, &m) && m.count == 0)
        return true;
    (void)snprintf(code, sizeof(code), "lane.dependency_unavailable:%s",
                   m.first);
    if (m.count < 0)
        (void)snprintf(why, sizeof(why), "%s", code);
    else if (m.count == 1)
        (void)snprintf(why, sizeof(why), "%s (%s)", code,
                       dln_dep_fix(m.first));
    else
        (void)snprintf(why, sizeof(why),
                       "%s and %d more missing; see evidence and "
                       "next_action",
                       code, m.count - 1);
    dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
             code, "deps", why, m.count > 1 ? m.paths.text : m.first);
    if (m.count > 1) {
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s",
                       m.fixes.text);
        dln_log("missing", m.paths.text);
        dln_log("fix", m.fixes.text);
    }
    return false;
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

/* Format the temporary name beside target; false when it does not fit. */
static bool dln_clone_temp_name(char *temporary, size_t cap,
                                const char *target)
{
    int temporary_len = snprintf(temporary, cap, "%s.tmp.XXXXXX", target);
    return temporary_len > 0 && temporary_len < (int)cap;
}

enum dln_copy_result {
    DLN_COPY_OK,
    DLN_COPY_READ_FAILED,
    DLN_COPY_WRITE_FAILED,
};

/* Byte-copy input onto output when the clone was unavailable and ok is still
 * true. A read or write failure is reported for the caller to log. */
static enum dln_copy_result dln_clone_copy_bytes(
    int input, int output, bool ok, enum platform_file_clone_result cloned)
{
    unsigned char buffer[65536];
    if (!ok || cloned != PLATFORM_FILE_CLONE_UNAVAILABLE)
        return DLN_COPY_OK;
    while (true) {
        ssize_t got = read(input, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return DLN_COPY_READ_FAILED;
        if (got == 0)
            return DLN_COPY_OK;
        if (!dln_write_all(output, buffer, (size_t)got))
            return DLN_COPY_WRITE_FAILED;
    }
}

enum dln_meta_result {
    DLN_META_OK,
    DLN_META_CHMOD_FAILED,
    DLN_META_TIMES_FAILED,
};

/* Give the clone the source's mode and times, when ok is still true. */
static enum dln_meta_result dln_clone_set_meta(int output,
                                               const struct stat *source_st,
                                               bool ok)
{
    if (!ok)
        return DLN_META_OK;
    if (fchmod(output, source_st->st_mode & 07777) != 0)
        return DLN_META_CHMOD_FAILED;
    {
        const struct timespec times[2] = {
            source_st->st_atim,
            source_st->st_mtim,
        };
        if (futimens(output, times) != 0)
            return DLN_META_TIMES_FAILED;
    }
    return DLN_META_OK;
}

/* Clone or copy `source` onto a new inode at `target`. NEVER link(). */
static bool dln_clone_file(const char *source, const char *target,
                           const struct stat *source_st)
{
    int input = -1;
    int output = -1;
    char temporary[DLN_PATH_CAP];
    bool ok;
    enum platform_file_clone_result cloned = PLATFORM_FILE_CLONE_UNAVAILABLE;
    enum dln_copy_result copied_bytes;
    enum dln_meta_result meta;

    input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) {
        dln_log("open_source", source);
        return false;
    }
    ok = dln_clone_temp_name(temporary, sizeof(temporary), target);
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
    copied_bytes = dln_clone_copy_bytes(input, output, ok, cloned);
    if (copied_bytes == DLN_COPY_READ_FAILED) {
        dln_log("read", source);
        ok = false;
    } else if (copied_bytes == DLN_COPY_WRITE_FAILED) {
        dln_log("write", temporary);
        ok = false;
    }
    if (close(input) != 0)
        ok = false;
    input = -1;
    if (output >= 0) {
        meta = dln_clone_set_meta(output, source_st, ok);
        if (meta == DLN_META_CHMOD_FAILED) {
            dln_log("fchmod", temporary);
            ok = false;
        } else if (meta == DLN_META_TIMES_FAILED) {
            dln_log("futimens", temporary);
            ok = false;
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

/* True for the "." and ".." entries that readdir() returns. */
static bool dln_is_dot_entry(const char *name)
{
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

/* Join one directory entry name onto the source and target paths. */
static bool dln_child_paths(char *child_source, char *child_target,
                            const char *source, const char *target,
                            const char *name)
{
    return zcl_path_join(child_source, DLN_PATH_CAP, source, name) &&
           zcl_path_join(child_target, DLN_PATH_CAP, target, name);
}

/* Copy one regular file: make its parents, then clone it onto a new inode. */
static bool dln_materialize_regular(const char *source, const char *target,
                                    const struct stat *source_st, int *copied)
{
    if (!dln_mkdir_parents(target))
        return false;
    if (!dln_clone_file(source, target, source_st))
        return false;
    if (copied)
        (*copied)++;
    return true;
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
    if (S_ISREG(source_st.st_mode))
        return dln_materialize_regular(source, target, &source_st, copied);
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
        if (dln_is_dot_entry(entry->d_name))
            continue;
        if (!dln_child_paths(child_source, child_target, source, target,
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
        if (!zcl_path_join(joined, sizeof(joined), dir, got))
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
    if (!zcl_path_join(marker, sizeof(marker), path, ".git"))
        return false;
    return lstat(marker, &st) == 0;
}

static bool dln_materialize_one(const char *root, const char *dest,
                                const char *rel, int *copied)
{
    char source[DLN_PATH_CAP], target[DLN_PATH_CAP];
    if (!zcl_path_join(source, sizeof(source), root, rel) ||
        !zcl_path_join(target, sizeof(target), dest, rel)) {
        dln_log("path_too_long", rel);
        return false;
    }
    return dln_materialize(source, target, copied);
}

/* Set failed_rel to rel when the caller passed a buffer for it. */
static void dln_set_failed_rel(char *failed_rel, size_t failed_cap,
                               const char *rel)
{
    if (failed_rel && failed_cap)
        (void)snprintf(failed_rel, failed_cap, "%s", rel);
}

/* Close dir; ok is cleared only when closedir() fails. */
static bool dln_closedir_keep(DIR *dir, bool ok)
{
    return closedir(dir) == 0 && ok;
}

enum dln_ext_visit {
    DLN_EXT_SKIP,
    DLN_EXT_FAILED,
    DLN_EXT_DESCEND,
};

/* Classify one entry of vendor/tor/src/ext: a directory is descended into,
 * anything else is skipped, and a path that cannot be joined fails. */
static enum dln_ext_visit dln_ext_group_entry(const char *ext,
                                              const char *name, char *group)
{
    struct stat st;
    if (dln_is_dot_entry(name))
        return DLN_EXT_SKIP;
    if (!zcl_path_join(group, DLN_PATH_CAP, ext, name))
        return DLN_EXT_FAILED;
    if (lstat(group, &st) != 0 || !S_ISDIR(st.st_mode))
        return DLN_EXT_SKIP;
    return DLN_EXT_DESCEND;
}

/* Classify one entry of a group directory: a .a regular file is materialised,
 * a directory is descended into, and anything else is skipped. */
static enum dln_ext_visit dln_ext_member_entry(
    const char *root, const char *dest, const char *group_name,
    const char *group, const char *name, char *member, int *copied,
    char *failed_rel, size_t failed_cap)
{
    struct stat st;
    if (dln_is_dot_entry(name))
        return DLN_EXT_SKIP;
    if (!zcl_path_join(member, DLN_PATH_CAP, group, name))
        return DLN_EXT_FAILED;
    if (lstat(member, &st) != 0)
        return DLN_EXT_SKIP;
    if (S_ISREG(st.st_mode) && dln_ends_with_a(name)) {
        char rel[DLN_PATH_CAP];
        int n = snprintf(rel, sizeof(rel), "vendor/tor/src/ext/%s/%s",
                         group_name, name);
        if (n <= 0 || (size_t)n >= sizeof(rel) ||
            !dln_materialize_one(root, dest, rel, copied)) {
            dln_set_failed_rel(failed_rel, failed_cap,
                               n > 0 ? rel : "vendor/tor/src/ext");
            return DLN_EXT_FAILED;
        }
        return DLN_EXT_SKIP;
    }
    if (!S_ISDIR(st.st_mode))
        return DLN_EXT_SKIP;
    return DLN_EXT_DESCEND;
}

/* Materialise the .a files directly inside member, then close files. */
static bool dln_ext_scan_files(const char *root, const char *dest,
                               const char *group_name,
                               const char *member_name, const char *member,
                               DIR *files, int *copied, char *failed_rel,
                               size_t failed_cap)
{
    struct dirent *entry;
    bool ok = true;
    while (ok && (entry = readdir(files)) != NULL) {
        char file[DLN_PATH_CAP];
        char rel[DLN_PATH_CAP];
        struct stat st;
        int n;
        if (dln_is_dot_entry(entry->d_name))
            continue;
        if (!zcl_path_join(file, sizeof(file), member, entry->d_name)) {
            ok = false;
            break;
        }
        if (lstat(file, &st) != 0 || !S_ISREG(st.st_mode) ||
            !dln_ends_with_a(entry->d_name))
            continue;
        n = snprintf(rel, sizeof(rel), "vendor/tor/src/ext/%s/%s/%s",
                     group_name, member_name, entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(rel) ||
            !dln_materialize_one(root, dest, rel, copied)) {
            dln_set_failed_rel(failed_rel, failed_cap,
                               n > 0 ? rel : "vendor/tor/src/ext");
            ok = false;
            break;
        }
    }
    return dln_closedir_keep(files, ok);
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

    if (!zcl_path_join(ext, sizeof(ext), root, "vendor/tor/src/ext"))
        return false;
    if (lstat(ext, &st) != 0)
        return true;
    if (!S_ISDIR(st.st_mode)) {
        dln_set_failed_rel(failed_rel, failed_cap, "vendor/tor/src/ext");
        dln_log("ext_not_dir", ext);
        return false;
    }
    d1 = opendir(ext);
    if (!d1) {
        dln_log("opendir", ext);
        dln_set_failed_rel(failed_rel, failed_cap, "vendor/tor/src/ext");
        return false;
    }
    while (ok && (e1 = readdir(d1)) != NULL) {
        char l1[DLN_PATH_CAP];
        DIR *d2;
        struct dirent *e2;
        enum dln_ext_visit visit = dln_ext_group_entry(ext, e1->d_name, l1);
        if (visit == DLN_EXT_FAILED) {
            ok = false;
            break;
        }
        if (visit == DLN_EXT_SKIP)
            continue;
        d2 = opendir(l1);
        if (!d2) {
            dln_log("opendir", l1);
            ok = false;
            break;
        }
        while (ok && (e2 = readdir(d2)) != NULL) {
            char l2[DLN_PATH_CAP];
            DIR *d3;
            visit = dln_ext_member_entry(root, dest, e1->d_name, l1,
                                         e2->d_name, l2, copied,
                                         failed_rel, failed_cap);
            if (visit == DLN_EXT_FAILED) {
                ok = false;
                break;
            }
            if (visit == DLN_EXT_SKIP)
                continue;
            d3 = opendir(l2);
            if (!d3) {
                dln_log("opendir", l2);
                ok = false;
                break;
            }
            ok = dln_ext_scan_files(root, dest, e1->d_name, e2->d_name, l2,
                                    d3, copied, failed_rel, failed_cap);
        }
        ok = dln_closedir_keep(d2, ok);
    }
    return dln_closedir_keep(d1, ok);
}
/* Copy every table row the lane consumes by direct copy. Replies and returns
 * false on the first failure. */
static bool dln_materialize_required(struct zcl_command_reply *reply,
                                     const char *root, const char *path,
                                     int *copied)
{
    size_t req_count;
    const struct zcl_dep_row *req_rows = zcl_dep_rows(&req_count);
    for (size_t i = 0; i < req_count; i++) {
        const char *req = req_rows[i].path;
        char source[DLN_PATH_CAP], target[DLN_PATH_CAP], why[256];
        if (!(req_rows[i].consumers & ZCL_DEP_LANE) ||
            req_rows[i].acquire != ZCL_DEP_COPY)
            continue;
        if (!zcl_path_join(source, sizeof(source), root, req) ||
            !zcl_path_join(target, sizeof(target), path, req)) {
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "lane.materialize_failed",
                     "materialize", req, req);
            return false;
        }
        if (!dln_materialize(source, target, copied)) {
            (void)snprintf(why, sizeof(why), "lane.materialize_failed:%s",
                           req);
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INTERNAL, "lane.materialize_failed",
                     "materialize", why, req);
            return false;
        }
    }
    return true;
}

/* Read one request field as a string; "" when the request has no input. */
static const char *dln_input_str(const struct zcl_command_request *request,
                                 const char *key)
{
    return request && request->input
               ? json_get_str(json_get(request->input, key))
               : "";
}

/* Resolve the checkout root from cwd; refuses when cwd is not a checkout. */
static bool dln_lane_find_root(struct zcl_command_reply *reply, char *cwd,
                               char *root)
{
    if (!getcwd(cwd, DLN_PATH_CAP)) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "lane.root_not_checkout", "root",
                 "cwd is not a git checkout", "");
        return false;
    }
    {
        static const char *const top_args[] = { "rev-parse",
                                                "--show-toplevel", NULL };
        if (dln_git(cwd, top_args, root, DLN_PATH_CAP,
                    DLN_GIT_TIMEOUT_MS) != 0 ||
            !root[0]) {
            dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INVALID, "lane.root_not_checkout",
                     "root", "cwd is not a git checkout", cwd);
            return false;
        }
        dln_strip(root);
    }
    return true;
}

/* Check the path and base arguments, and that base resolves in the root. */
static bool dln_lane_validate(struct zcl_command_reply *reply,
                              const char *root, const char *path,
                              const char *base)
{
    if (!path[0] || !dln_is_abs(path)) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_PATH", "validate",
                 "path must be an absolute worktree path", path);
        return false;
    }
    if (!base[0]) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_BASE", "validate", "base is required", "");
        return false;
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
            return false;
        }
    }
    return true;
}

/* Create the parent directories of the worktree; refuse if they fail. */
static bool dln_lane_make_parent(struct zcl_command_reply *reply,
                                 const char *path)
{
    if (!dln_mkdir_parents(path)) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "lane.path_not_worktree", "worktree_add",
                 "could not create the worktree parent directory", path);
        return false;
    }
    return true;
}

/* Refuse when an existing path is not a worktree of the checkout root. */
static bool dln_lane_check_worktree(struct zcl_command_reply *reply,
                                    const char *root, const char *path)
{
    if (dln_is_worktree_of(path, root))
        return true;
    dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
             "lane.path_not_worktree", "worktree",
             "path exists but is not a worktree of this checkout", path);
    return false;
}

/* True when git reports vendor/tor as not initialised (a '-' status). */
static bool dln_lane_submodule_missing(const char *path)
{
    const char *st_args[] = { "submodule", "status", "--", "vendor/tor",
                              NULL };
    char st_out[DLN_OUT_CAP];
    return dln_git(path, st_args, st_out, sizeof(st_out),
                   DLN_GIT_TIMEOUT_MS) == 0 &&
           st_out[0] == '-';
}

/* Materialise the dependencies; refuses on the first one that cannot be. */
static bool dln_lane_materialize_deps(struct zcl_command_reply *reply,
                                      const char *root, const char *path,
                                      int *copied)
{
    char failed_rel[DLN_PATH_CAP];
    char why[256];
    /* Preflight every required source that the worktree does not yet hold,
     * so a missing ROOT dependency refuses without copying any sibling. */
    if (!dln_preflight(reply, root, path))
        return false;
    if (!dln_materialize_required(reply, root, path, copied))
        return false;

    failed_rel[0] = '\0';
    if (!dln_materialize_ext_archives(root, path, copied, failed_rel,
                                      sizeof(failed_rel))) {
        (void)snprintf(why, sizeof(why), "lane.materialize_failed:%s",
                       failed_rel[0] ? failed_rel : "vendor/tor/src/ext");
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INTERNAL, "lane.materialize_failed",
                 "materialize", why, failed_rel);
        return false;
    }
    return true;
}

/* Read the worktree's HEAD; refuses unless it is a 40-hex commit. */
static bool dln_lane_read_head(struct zcl_command_reply *reply,
                               const char *path, char *head, size_t head_cap)
{
    static const char *const head_args[] = { "rev-parse", "HEAD", NULL };
    if (dln_git(path, head_args, head, head_cap, DLN_GIT_TIMEOUT_MS) != 0) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "GIT_FAILED", "head", "git rev-parse HEAD failed", path);
        return false;
    }
    dln_strip(head);
    if (!dln_sha_ok(head)) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "GIT_FAILED", "head", "HEAD is not a 40-hex commit", head);
        return false;
    }
    return true;
}

/* Refuse unless vendor/tor/libtor.a exists; fills libtor_st on success. */
static bool dln_lane_check_libtor(struct zcl_command_reply *reply,
                                  const char *path, struct stat *libtor_st)
{
    char libtor_path[DLN_PATH_CAP];
    if (!zcl_path_join(libtor_path, sizeof(libtor_path), path,
                       "vendor/tor/libtor.a") ||
        lstat(libtor_path, libtor_st) != 0) {
        dln_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "lane.dependency_unavailable:vendor/tor/libtor.a", "deps",
                 "lane.dependency_unavailable:vendor/tor/libtor.a "
                 "(make vendor)",
                 "vendor/tor/libtor.a");
        return false;
    }
    return true;
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
    const char *path = dln_input_str(request, "path");
    const char *base = dln_input_str(request, "base");
    char cwd[DLN_PATH_CAP];
    char root[DLN_PATH_CAP];
    char head[80];
    int copied = 0;
    struct stat libtor_st;
    const char *make_argv[8];

    if (!dln_lane_find_root(reply, cwd, root))
        return;
    if (!dln_lane_validate(reply, root, path, base))
        return;
    if (!dln_has_git(path)) {
        const char *add_args[] = { "worktree", "add", "--detach", path,
                                   base, NULL };
        char add_out[DLN_OUT_CAP];
        if (!dln_lane_make_parent(reply, path))
            return;
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
    if (!dln_lane_check_worktree(reply, root, path))
        return;

    if (dln_lane_submodule_missing(path)) {
        const char *init_args[] = { "submodule", "update", "--init",
                                    "--", "vendor/tor", NULL };
        char init_out[DLN_OUT_CAP];
        if (dln_git(path, init_args, init_out, sizeof(init_out),
                    DLN_GIT_TIMEOUT_MS) != 0)
            dln_log("submodule_init", init_out);
    }

    if (!dln_lane_materialize_deps(reply, root, path, &copied))
        return;

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

    if (!dln_lane_read_head(reply, path, head, sizeof(head)))
        return;
    if (!dln_lane_check_libtor(reply, path, &libtor_st))
        return;

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
