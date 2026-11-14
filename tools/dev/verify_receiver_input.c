/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * The receiver's own measurements in the proof generation: the root-owned
 * pinned profile, a fresh -E with that profile, the prerequisites its
 * depfile names, and the portable source content root over those files.
 * Nothing here trusts a byte the candidate's build produced. */
#define _POSIX_C_SOURCE 200809L
#include "verify_receiver_internal.h"

#include "verify/fixed_result_contract.h"
#include "verify/fixed_result_source.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define VR_PP_DEADLINE_US (30ll * 1000000ll)
#define VR_INPUTS_MAX 4096u

/* ── Bounded files ─────────────────────────────────────────────────────── */

static bool vr_same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size && a->st_mtime == b->st_mtime &&
           a->st_ctime == b->st_ctime;
}

static const char *vr_read_fd(int fd, size_t limit, bool single_link,
                              struct vr_bytes *out)
{
    struct stat before, after;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        (single_link && before.st_nlink != 1))
        return "receiver_file_unsafe";
    if (before.st_size < 0 || (uint64_t)before.st_size > limit)
        return "receiver_file_limit";
    size_t len = (size_t)before.st_size, at = 0;
    uint8_t *p = zcl_malloc(len + 1u, "verify receiver file");
    if (!p) return "receiver_out_of_memory";
    while (at < len) {
        ssize_t n = read(fd, p + at, len - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        at += (size_t)n;
    }
    if (at != len || fstat(fd, &after) != 0 || !vr_same_file(&before, &after)) {
        free(p);
        return "receiver_file_changed";
    }
    p[len] = 0;
    out->p = p;
    out->n = len;
    return NULL;
}

const char *vr_read_at(int dir_fd, const char *name, size_t limit,
                       struct vr_bytes *out)
{
    out->p = NULL;
    out->n = 0;
    int fd = openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
                                      O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? "receiver_file_missing"
                               : "receiver_file_unreadable";
    const char *why = vr_read_fd(fd, limit, true, out);
    (void)close(fd);
    return why;
}

bool vr_write_at(int dir_fd, const char *name, const void *bytes, size_t len)
{
    int fd = openat(dir_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                      O_CLOEXEC, 0600);
    if (fd < 0) return false;
    const uint8_t *p = bytes;
    size_t at = 0;
    while (at < len) {
        ssize_t n = write(fd, p + at, len - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        at += (size_t)n;
    }
    return close(fd) == 0 && at == len;
}

static bool vr_root_dir_ok(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == 0 &&
           (st.st_mode & 0022) == 0;
}

/* Walk `absolute` from "/" one component at a time: every directory
 * root-owned and not group/world writable, no link followed. */
static int vr_root_parent(const char *absolute, const char **leaf)
{
    char path[PATH_MAX];
    if (!absolute || absolute[0] != '/' ||
        snprintf(path, sizeof(path), "%s", absolute) >= (int)sizeof(path))
        return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    char *save = NULL, *part = strtok_r(path + 1, "/", &save);
    while (fd >= 0 && part) {
        char *next = strtok_r(NULL, "/", &save);
        if (!vr_root_dir_ok(fd)) { (void)close(fd); return -1; }
        if (!next) {
            *leaf = absolute + (part - path);
            return fd;
        }
        int child = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                         O_CLOEXEC);
        (void)close(fd);
        fd = child;
        part = next;
    }
    if (fd >= 0) (void)close(fd);
    return -1;
}

const char *vr_read_root_owned(const char *absolute, size_t limit,
                               struct vr_bytes *out)
{
    const char *leaf = NULL;
    out->p = NULL;
    out->n = 0;
    int dir = vr_root_parent(absolute, &leaf);
    if (dir < 0) return "receiver_profile_path_unsafe";
    int fd = openat(dir, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    (void)close(dir);
    if (fd < 0)
        return errno == ENOENT ? "receiver_profile_missing"
                               : "receiver_profile_unsafe";
    struct stat st;
    const char *why = NULL;
    if (fstat(fd, &st) != 0 || st.st_uid != 0 || (st.st_mode & 0022) != 0)
        why = "receiver_profile_unsafe";
    else
        why = vr_read_fd(fd, limit, true, out);
    (void)close(fd);
    return why;
}

/* ── The pinned profile ────────────────────────────────────────────────── */

static const char *vr_profile_expand(struct vr_profile *p, const char *cwd)
{
    static const char tag[] = "@CWD@";
    size_t found = 0;
    for (size_t i = 0; i < VR_PROFILE_TOKENS; i++) {
        char *at = strstr(p->tokens[i], tag);
        if (!at) continue;
        if (found++ != 0 || strstr(at + 5, tag)) return "receiver_profile_shape";
        int n = snprintf(p->expanded, sizeof(p->expanded), "%.*s%s%s",
                         (int)(at - p->tokens[i]), p->tokens[i], cwd, at + 5);
        if (n <= 0 || n >= (int)sizeof(p->expanded))
            return "receiver_cwd_unsupported";
        p->tokens[i] = p->expanded;
    }
    return found == 1 ? NULL : "receiver_profile_shape";
}

/* The fixed profile's LF-terminated tokens, split in place; the first must be "cc". */
static bool vr_profile_split(struct vr_profile *out)
{
    size_t count = 0, start = 0;
    for (size_t i = 0; i < out->len; i++) {
        if (out->text[i] != '\n') continue;
        if (i == start || count == VR_PROFILE_TOKENS) return false;
        out->text[i] = 0;
        out->tokens[count++] = (char *)out->text + start;
        start = i + 1;
    }
    out->tokens[count < VR_PROFILE_TOKENS ? count : VR_PROFILE_TOKENS] = NULL;
    return count == VR_PROFILE_TOKENS && start == out->len &&
           strcmp(out->tokens[0], "cc") == 0;
}

const char *vr_profile_load(const struct vr_bytes *bytes, const char *cwd,
                            struct vr_profile *out)
{
    uint8_t hash[32];
    char hex[65];
    memset(out, 0, sizeof(*out));
    if (!bytes->p || bytes->n == 0 || bytes->n > VR_PROFILE_MAX)
        return "receiver_profile_shape";
    zcl_sha3_256(bytes->p, bytes->n, hash);
    zcl_hex_encode(hash, sizeof(hash), hex);
    if (strcmp(hex, ZCL_FR_PROFILE_SHA3) != 0) return "receiver_profile_mismatch";
    if (!cwd || cwd[0] != '/' || strchr(cwd, '\n') || strchr(cwd, ' '))
        return "receiver_cwd_unsupported";
    memcpy(out->text, bytes->p, bytes->n);
    out->len = bytes->n;
    if (!vr_profile_split(out)) return "receiver_profile_shape";
    return vr_profile_expand(out, cwd);
}

/* ── The receiver's own -E ─────────────────────────────────────────────── */

static char *const vr_env[] = {
    "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", NULL
};

static void vr_child(const char *compiler, const char *cwd,
                     char *const argv[], int err_fd)
{
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0 || chdir(cwd) != 0 || dup2(null_fd, STDIN_FILENO) < 0 ||
        dup2(null_fd, STDOUT_FILENO) < 0 || dup2(err_fd, STDERR_FILENO) < 0)
        _exit(127);
    execve(compiler, argv, vr_env);
    _exit(127);
}

static const char *vr_wait(pid_t pid)
{
    int64_t start = platform_time_monotonic_us();
    int status = 0;
    for (;;) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) break;
        if (done < 0 && errno != EINTR) return "receiver_preprocess_wait_failed";
        if (platform_time_monotonic_us() - start > VR_PP_DEADLINE_US) {
            (void)kill(pid, SIGKILL);
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
            return "receiver_preprocess_deadline";
        }
        struct timespec pause = {0, 1000000};
        (void)nanosleep(&pause, NULL);
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0
               ? NULL : "receiver_preprocess_failed";
}

static const char *vr_spawn(const char *compiler, const char *cwd,
                            char *const argv[], int work_fd)
{
    int err_fd = openat(work_fd, "pp.stderr",
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
    if (err_fd < 0) return "receiver_work_unsafe";
    pid_t pid = fork();
    if (pid == 0) vr_child(compiler, cwd, argv, err_fd);
    (void)close(err_fd);
    return pid < 0 ? "receiver_preprocess_spawn_failed" : vr_wait(pid);
}

const char *vr_preprocess(const char *compiler, const char *cwd,
                          const struct vr_profile *profile, int work_fd,
                          const char *work, uint8_t pp_sha3[32],
                          struct vr_bytes *dep)
{
    char dep_path[PATH_MAX], pp_path[PATH_MAX];
    if (snprintf(dep_path, sizeof(dep_path), "%s/pp.d", work) >=
            (int)sizeof(dep_path) ||
        snprintf(pp_path, sizeof(pp_path), "%s/pp.i", work) >=
            (int)sizeof(pp_path))
        return "receiver_work_unsafe";
    char *argv[VR_PROFILE_TOKENS + 16u];
    size_t n = 0;
    for (size_t i = 0; i < VR_PROFILE_TOKENS; i++) argv[n++] = profile->tokens[i];
    char *tail[] = {"-MMD", "-MP", "-MF", dep_path, "-MT",
                    ZCL_VERIFY_RECEIVER_PLACEHOLDER_TARGET,
                    "-fno-working-directory", "-E", "-o", pp_path,
                    ZCL_FR_SOURCE};
    for (size_t i = 0; i < sizeof(tail) / sizeof(tail[0]); i++)
        argv[n++] = tail[i];
    argv[n] = NULL;
    const char *why = vr_spawn(compiler, cwd, argv, work_fd);
    if (why) return why;
    struct vr_bytes pp = {0};
    why = vr_read_at(work_fd, "pp.i", VR_PP_MAX, &pp);
    if (!why && pp.n == 0) why = "receiver_preprocess_empty";
    if (!why) zcl_sha3_256(pp.p, pp.n, pp_sha3);
    free(pp.p);
    return why ? why : vr_read_at(work_fd, "pp.d", VR_DEP_MAX, dep);
}

/* ── Depfile prerequisites ─────────────────────────────────────────────── */

static int vr_path_order(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void zcl_verify_receiver_paths_free(char **paths, size_t count)
{
    for (size_t i = 0; paths && i < count; i++) free(paths[i]);
    free(paths);
}

static bool vr_relative_ok(const char *p)
{
    if (!p[0] || p[0] == '/' || strstr(p, "//")) return false;
    for (const char *s = p; *s;) {
        size_t n = strcspn(s, "/");
        if ((n == 1 && s[0] == '.') || (n == 2 && s[0] == '.' && s[1] == '.'))
            return false;
        s += n;
        if (*s == '/') s++;
    }
    return p[strlen(p) - 1] != '/';
}

static const char *vr_input_add(char ***paths, size_t *count,
                                const char *start, size_t len)
{
    if (len == 0) return NULL;
    if (len >= PATH_MAX || *count == VR_INPUTS_MAX ||
        memchr(start, '$', len) || memchr(start, '\\', len))
        return "receiver_depfile_unparsed";
    char *copy = zcl_malloc(len + 1u, "verify receiver input");
    char **grown = zcl_realloc(*paths, (*count + 1u) * sizeof(**paths),
                               "verify receiver inputs");
    if (!copy || !grown) {
        free(copy);
        if (grown) *paths = grown;
        return "receiver_out_of_memory";
    }
    memcpy(copy, start, len);
    copy[len] = 0;
    *paths = grown;
    (*paths)[(*count)++] = copy;
    return vr_relative_ok(copy) ? NULL : "receiver_input_path_unsafe";
}

enum vr_dep_char { VR_DEP_TOKEN, VR_DEP_SPACE, VR_DEP_CONT, VR_DEP_END };

static enum vr_dep_char vr_dep_class(const char *s, size_t n, size_t i)
{
    if (i == n || s[i] == '\n') return VR_DEP_END;
    if (i + 1 < n && s[i] == '\\' && s[i + 1] == '\n') return VR_DEP_CONT;
    return s[i] == ' ' || s[i] == '\t' ? VR_DEP_SPACE : VR_DEP_TOKEN;
}

/* Split the first rule's prerequisites. A backslash is allowed only as the
 * line continuation GCC writes; any other escape refuses. */
static const char *vr_depfile_split(const char *s, size_t n, char ***paths,
                                    size_t *count)
{
    size_t i = 0, start = 0;
    bool in_token = false;
    for (;;) {
        enum vr_dep_char c = vr_dep_class(s, n, i);
        if (c == VR_DEP_TOKEN) {
            if (!in_token) start = i;
            in_token = true;
            i++;
            continue;
        }
        const char *why = in_token
                              ? vr_input_add(paths, count, s + start, i - start)
                              : NULL;
        if (why) return why;
        in_token = false;
        if (c == VR_DEP_END) return NULL;
        i += c == VR_DEP_CONT ? 2u : 1u;
    }
}

static bool vr_dedupe(char **paths, size_t *count)
{
    if (*count > 1)
        qsort(paths, *count, sizeof(*paths), vr_path_order);
    size_t w = 0;
    for (size_t i = 0; i < *count; i++) {
        if (w > 0 && strcmp(paths[w - 1], paths[i]) == 0) {
            free(paths[i]);
            continue;
        }
        paths[w++] = paths[i];
    }
    *count = w;
    return w > 0;
}

const char *zcl_verify_receiver_depfile_inputs(const uint8_t *dep,
                                               size_t dep_len,
                                               const char *target,
                                               char ***out, size_t *count)
{
    *out = NULL;
    *count = 0;
    size_t t = target ? strlen(target) : 0;
    if (!dep || dep_len <= t + 1u || memchr(dep, 0, dep_len) ||
        memcmp(dep, target, t) != 0 || dep[t] != ':')
        return ZCL_FR_WHY_DEPFILE_TARGET;
    const char *why = vr_depfile_split((const char *)dep + t + 1u,
                                       dep_len - t - 1u, out, count);
    if (!why && !vr_dedupe(*out, count)) why = "receiver_depfile_unparsed";
    if (why) {
        zcl_verify_receiver_paths_free(*out, *count);
        *out = NULL;
        *count = 0;
    }
    return why;
}

/* ── Portable source content root ──────────────────────────────────────── */

/* The one reader and definition the launcher's pin also uses. */
const char *zcl_verify_receiver_source_content(int root_fd,
                                               char *const *paths,
                                               size_t count,
                                               uint8_t out[32])
{
    if (root_fd < 0 || !paths || count == 0) return "receiver_inputs_missing";
    return zcl_fr_source_content_at(root_fd, (const char *const *)paths, count,
                                    out);
}

const char *vr_read_beneath(int root_fd, const char *rel, size_t limit,
                            struct vr_bytes *out)
{
    out->p = NULL;
    out->n = 0;
    int fd = zcl_fr_open_beneath(root_fd, rel);
    if (fd < 0) return "receiver_file_missing";
    const char *why = vr_read_fd(fd, limit, false, out);
    (void)close(fd);
    return why;
}
