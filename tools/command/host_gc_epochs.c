/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: conservatively collect inactive build epochs in an explicit checkout. */

#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
#include "command/host_gc_sweep.h"
#include "json/json.h"
#include "util/file_tree_ops.h"
#include "util/spawn.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

struct he_profile { const char *objects, *candidate, *session; };
static const struct he_profile he_profiles[] = {
    {"obj", NULL, "build-only-v2"}, {"node-obj", NULL, "node-c23-v1"}, {"dev-obj", "dev", "dev-v2"},
    {"dev-asan-obj", "dev-asan", "dev-asan-v2"}, {"dev-tsan-obj", "dev-tsan", "dev-tsan-v2"},
    {"test-obj", "test-fast", "test-fast-v2"}, {"test-rel-obj", "test-strict", "test-strict-v2"},
    {"test-asan-obj", "test-asan-epochs", "test-asan-v2"}, {"test-tsan-obj", "test-tsan-epochs", "test-tsan-v2"},
    {"cov", "coverage", "coverage-v2"},
};
enum { HE_MAX_EPOCHS = 512, HE_PATH = 4096 };
struct he_epoch { char name[65]; struct timespec mtime; bool retain; };

static bool he_epoch_name(const char *s)
{
    if (strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}
static const struct he_profile *he_selector(const char *s, const char **hash)
{
    if (!s) return NULL;
    const char *colon = strchr(s, ':');
    if (!colon || !he_epoch_name(colon + 1)) return NULL;
    size_t len = (size_t)(colon - s);
    for (size_t i = 0; i < sizeof(he_profiles) / sizeof(he_profiles[0]); ++i)
        if (strlen(he_profiles[i].objects) == len && !memcmp(s, he_profiles[i].objects, len)) {
            *hash = colon + 1;
            return &he_profiles[i];
        }
    return NULL;
}
static bool he_same_mount(int parent, int fd);
static int he_dir(int parent, const char *name)
{
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0 && !he_same_mount(parent, fd)) { close(fd); errno = EXDEV; return -1; }
    return fd;
}
static bool he_current(int root, char out[65])
{
    int fd = openat(root, ".current-epoch", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    struct stat st; char wire[67];
    if (fd < 0) return false;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    ssize_t n = ok ? read(fd, wire, sizeof(wire)) : -1;
    ok = ok && n == 65 && wire[64] == '\n';
    if (close(fd) != 0) ok = false;
    if (!ok) return false;
    memcpy(out, wire, 64); out[64] = 0;
    return he_epoch_name(out);
}
static bool he_hash_line(const char *line, const char *key)
{
    size_t n = strlen(key);
    if (strncmp(line, key, n) || strlen(line + n) != 65 || line[n + 64] != '\n') return false;
    char hash[65]; memcpy(hash, line + n, 64); hash[64] = 0;
    return he_epoch_name(hash);
}
static bool he_session_head(FILE *f)
{
    char line[512];
    return fgets(line, sizeof(line), f) && !strcmp(line, "schema=zcl.build_epoch_session.v1\n") &&
        fgets(line, sizeof(line), f) && he_hash_line(line, "source_id=") &&
        fgets(line, sizeof(line), f) && !strcmp(line, "complete=1\n") &&
        fgets(line, sizeof(line), f) && he_hash_line(line, "mutation=") &&
        fgets(line, sizeof(line), f) && he_hash_line(line, "compiler_id=");
}
static bool he_session_tail(FILE *f, const char *name, const char *profile)
{
    char line[512], expected[128];
    (void)snprintf(expected, sizeof(expected), "epoch=%s\n", name);
    if (!fgets(line, sizeof(line), f) || strcmp(line, expected)) return false;
    (void)snprintf(expected, sizeof(expected), "profile=%s\n", profile);
    return fgets(line, sizeof(line), f) && !strcmp(line, expected) &&
        fgets(line, sizeof(line), f) && he_hash_line(line, "flags_sha256=") &&
        !fgets(line, sizeof(line), f) && !ferror(f);
}
static bool he_session_fd_valid(int fd, const char *name, const char *profile)
{
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > 1024) { close(fd); return false; }
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return false; }
    bool ok = he_session_head(f) && he_session_tail(f, name, profile);
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool he_session_valid(int epoch, const char *name, const char *profile)
{
    return he_session_fd_valid(openat(epoch, ".build-session", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC), name, profile);
}

/* Any lease, unknown marker, or unreadable lease directory is a keep. */
static bool he_idle(int epoch)
{
    struct stat st;
    if (fstatat(epoch, ".unverified", &st, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return false;
    int fd = he_dir(epoch, ".leases");
    if (fd < 0) return false;
    DIR *d = fdopendir(fd);
    if (!d) { close(fd); return false; }
    bool empty = true; errno = 0;
    for (struct dirent *e; (e = readdir(d)); )
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) { empty = false; break; }
    int read_error = errno;
    if (closedir(d) != 0 || read_error) empty = false;
    return empty;
}
static int he_order(const void *a, const void *b)
{
    const struct he_epoch *x = a, *y = b;
    if (x->mtime.tv_sec != y->mtime.tv_sec) return x->mtime.tv_sec > y->mtime.tv_sec ? -1 : 1;
    if (x->mtime.tv_nsec != y->mtime.tv_nsec) return x->mtime.tv_nsec > y->mtime.tv_nsec ? -1 : 1;
    return strcmp(y->name, x->name);
}
static bool he_same_mount(int parent, int fd)
{
#if defined(STATX_MNT_ID)
    struct statx a, b;
    return statx(parent, "", AT_EMPTY_PATH, STATX_MNT_ID, &a) == 0 &&
        statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &b) == 0 &&
        (a.stx_mask & STATX_MNT_ID) && (b.stx_mask & STATX_MNT_ID) && a.stx_mnt_id == b.stx_mnt_id;
#else
    (void)parent; (void)fd; return false;
#endif
}
static bool he_remove(int parent, const char *name)
{
    struct stat named, held, after;
    if (fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(named.st_mode)) return false;
    int fd = he_dir(parent, name);
    if (fd < 0) return false;
    bool ok = fstat(fd, &held) == 0 && held.st_dev == named.st_dev && held.st_ino == named.st_ino &&
        he_same_mount(parent, fd);
    if (ok) ok = zcl_tree_remove_contents_fd_one_mount(fd).ok;
    if (ok) ok = fstatat(parent, name, &after, AT_SYMLINK_NOFOLLOW) == 0 &&
        after.st_dev == held.st_dev && after.st_ino == held.st_ino && S_ISDIR(after.st_mode);
    if (close(fd) != 0) ok = false;
    return ok && unlinkat(parent, name, AT_REMOVEDIR) == 0;
}

/* A hard link to the verified producer session remains outside the renamed
 * epoch until deletion completes, so interrupted removals remain identifiable. */
static bool he_retire_names(const char *name, char stage[80], char marker[88])
{
    return snprintf(stage, 80, ".gc-%s", name) == 68 &&
        snprintf(marker, 88, ".gc-%s.session", name) == 76;
}
static bool he_absent(int dir, const char *name)
{
    struct stat st;
    return fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}
static bool he_same_session(int epoch, int epochs, const char *marker)
{
    struct stat source, saved;
    return fstatat(epoch, ".build-session", &source, AT_SYMLINK_NOFOLLOW) == 0 &&
        fstatat(epochs, marker, &saved, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(source.st_mode) && S_ISREG(saved.st_mode) &&
        source.st_dev == saved.st_dev && source.st_ino == saved.st_ino;
}
static bool he_finish_stage(int epochs, const char *stage, const char *marker)
{
    if (!he_remove(epochs, stage)) return false;
    if (unlinkat(epochs, marker, 0) != 0) return false;
    return fsync(epochs) == 0;
}
static bool he_marker_sync(int epochs, const char *marker)
{
    int fd = openat(epochs, marker, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}
static bool he_start_retire(int epochs, const char *name)
{
    char stage[80], marker[88];
    if (!he_retire_names(name, stage, marker) || !he_absent(epochs, stage)) return false;
    int fd = he_dir(epochs, name);
    if (fd < 0) return false;
    bool ok = he_same_session(fd, epochs, marker);
    if (!ok && he_absent(epochs, marker))
        ok = linkat(fd, ".build-session", epochs, marker, 0) == 0 &&
            he_same_session(fd, epochs, marker) && fsync(epochs) == 0;
    if (ok) ok = he_marker_sync(epochs, marker);
    if (close(fd) != 0) ok = false;
    if (!ok || renameat2(epochs, name, epochs, stage, RENAME_NOREPLACE) != 0 || fsync(epochs) != 0)
        return false;
    return he_finish_stage(epochs, stage, marker);
}
static bool he_remove_optional(int dir, const char *name)
{
    return dir < 0 || he_absent(dir, name) || he_remove(dir, name);
}

static bool he_collect(int epochs, const char *current, struct he_epoch *rows, size_t *count)
{
    int scan = openat(epochs, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan < 0) return false;
    DIR *dir = fdopendir(scan);
    if (!dir) { close(scan); return false; }
    bool ok = true, found = false; errno = 0;
    for (struct dirent *ent; (ent = readdir(dir)); ) {
        if (!he_epoch_name(ent->d_name)) continue;
        struct stat st;
        if (fstatat(epochs, ent->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(st.st_mode)) { ok = false; break; }
        if (*count == HE_MAX_EPOCHS) { ok = false; break; }
        struct he_epoch *row = &rows[(*count)++];
        memcpy(row->name, ent->d_name, 65); row->mtime = st.st_mtim;
        if (!strcmp(row->name, current)) found = true;
    }
    int read_error = errno;
    if (closedir(dir) != 0 || read_error) ok = false;
    return ok && found;
}
static bool he_is_pair(int candidates, const char *name)
{
    if (candidates < 0) return true;
    struct stat st;
    if (fstatat(candidates, name, &st, AT_SYMLINK_NOFOLLOW) == 0) return S_ISDIR(st.st_mode);
    return errno == ENOENT;
}
static bool he_append(struct json_value *rows, const char *profile, const char *name,
    uint64_t bytes, bool removed)
{
    struct json_value row; json_init(&row); json_set_object(&row);
    bool ok = json_push_kv_str(&row, "profile", profile) && json_push_kv_str(&row, "epoch", name) &&
        json_push_kv_int(&row, "logical_bytes", (int64_t)bytes) && json_push_kv_bool(&row, "removed", removed) &&
        json_push_back(rows, &row);
    json_free(&row); return ok;
}
static bool he_stage_idle(int fd)
{
    struct stat st;
    if (fstatat(fd, ".unverified", &st, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return false;
    if (fstatat(fd, ".leases", &st, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT;
    return he_idle(fd);
}
static bool he_recover_original(int epochs, const char *name, const char *marker, bool apply)
{
    int fd = he_dir(epochs, name);
    if (fd < 0) return false;
    bool safe = he_same_session(fd, epochs, marker) && he_idle(fd);
    if (close(fd) != 0) safe = false;
    return safe && (!apply || he_start_retire(epochs, name));
}
static bool he_recover_stage(int epochs, const char *stage, const char *marker, bool apply)
{
    int fd = he_dir(epochs, stage);
    if (fd < 0) return false;
    struct stat st;
    bool session_absent = fstatat(fd, ".build-session", &st, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    bool safe = he_stage_idle(fd) && (session_absent || he_same_session(fd, epochs, marker));
    if (close(fd) != 0) safe = false;
    return safe && (!apply || he_finish_stage(epochs, stage, marker));
}
static bool he_recover_one(int epochs, int candidates, const char *name,
    const char *current, const char *profile, bool apply)
{
    char stage[80], marker[88];
    if (!he_retire_names(name, stage, marker) || !strcmp(name, current) ||
        !he_session_fd_valid(openat(epochs, marker, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC), name, profile) ||
        (candidates >= 0 && !he_absent(candidates, name))) return false;
    bool original_absent = he_absent(epochs, name);
    bool stage_absent = he_absent(epochs, stage);
    if (!original_absent && !stage_absent) return false;
    if (stage_absent && !original_absent) return he_recover_original(epochs, name, marker, apply);
    if (!stage_absent) return he_recover_stage(epochs, stage, marker, apply);
    return !apply || (unlinkat(epochs, marker, 0) == 0 && fsync(epochs) == 0);
}
static bool he_orphan_stage(int epochs, const char *name)
{
    char marker[88];
    memcpy(marker, name, 68); memcpy(marker + 68, ".session", 9);
    return !he_absent(epochs, name) && he_absent(epochs, marker);
}
static bool he_recovery_name(const char *entry, const char *selected, char name[65], bool *stage)
{
    size_t len = strlen(entry);
    if (strncmp(entry, ".gc-", 4) || (len != 68 && len != 76)) return false;
    if (len == 76 && strcmp(entry + 68, ".session")) return false;
    memcpy(name, entry + 4, 64); name[64] = 0;
    if (selected && strcmp(name, selected)) return false;
    *stage = len == 68;
    return true;
}
static bool he_recover(int epochs, int candidates, const char *current,
    const char *profile, const char *selected, bool apply, unsigned *refused, unsigned *pending, unsigned *partial)
{
    int fd = openat(epochs, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    DIR *dir = fdopendir(fd);
    if (!dir) { close(fd); return false; }
    bool ok = true; errno = 0;
    for (struct dirent *ent; (ent = readdir(dir)); ) {
        char name[65]; bool stage;
        if (!he_recovery_name(ent->d_name, selected, name, &stage)) continue;
        if (stage) {
            if (he_orphan_stage(epochs, ent->d_name)) ++*refused;
            errno = 0;
            continue;
        }
        ++*pending;
        if (!he_epoch_name(name) || !he_recover_one(epochs, candidates, name, current, profile, apply)) {
            ++*refused;
            if (apply) ++*partial;
        }
        errno = 0;
    }
    int read_error = errno;
    if (closedir(dir) != 0 || read_error) ok = false;
    return ok;
}

struct he_run {
    const char *checkout;
    const struct he_profile *profile;
    const char *selected;
    int object, candidate, epochs, candidates, lock, keep;
    bool apply;
    char current[65];
    struct json_value *rows;
    uint64_t *bytes;
    unsigned *refused, *pending, *partial;
};
static void he_run_close(struct he_run *run)
{
    if (run->candidates >= 0) close(run->candidates);
    if (run->epochs >= 0) close(run->epochs);
    if (run->candidate >= 0) close(run->candidate);
    if (run->lock >= 0) close(run->lock);
    if (run->object >= 0) close(run->object);
}
static bool he_current_dirs(const struct he_run *run)
{
    int object = he_dir(run->epochs, run->current);
    if (object < 0) return false;
    bool ok = close(object) == 0;
    if (run->candidates >= 0) {
        int candidate = he_dir(run->candidates, run->current);
        if (candidate < 0) return false;
        if (close(candidate) != 0) ok = false;
    }
    return ok;
}
static bool he_run_open(struct he_run *run, int bins)
{
    struct stat st; char other[65];
    run->lock = openat(run->object, ".epoch-gc.lock", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (run->lock < 0 || fstat(run->lock, &st) != 0 || !S_ISREG(st.st_mode) ||
        flock(run->lock, LOCK_EX | LOCK_NB) != 0) return false;
    if (!he_current(run->object, run->current) || (run->epochs = he_dir(run->object, "epochs")) < 0) return false;
    if (run->profile->candidate) {
        if (bins < 0 || (run->candidate = he_dir(bins, run->profile->candidate)) < 0 ||
            !he_current(run->candidate, other) || strcmp(run->current, other) ||
            (run->candidates = he_dir(run->candidate, "epochs")) < 0) return false;
    }
    if (!he_current_dirs(run)) return false;
    return he_recover(run->epochs, run->candidates, run->current, run->profile->session, run->selected,
        run->apply, run->refused, run->pending, run->partial);
}
static bool he_measure_one(int parent, const char *name, bool optional, uint64_t *size)
{
    *size = 0;
    if (parent < 0) return optional;
    int fd = he_dir(parent, name);
    if (fd < 0) return optional && errno == ENOENT;
    bool ok = zcl_tree_measure_contents_fd_one_mount(fd, size).ok;
    if (close(fd) != 0) ok = false;
    return ok;
}
static bool he_measure(const struct he_run *run, const char *name, uint64_t *size)
{
    uint64_t candidate = 0;
    if (!he_measure_one(run->epochs, name, false, size) ||
        !he_measure_one(run->candidates, name, true, &candidate) ||
        *size > INT64_MAX || candidate > (uint64_t)INT64_MAX - *size) return false;
    *size += candidate; return true;
}
static bool he_remove_pair(struct he_run *run, const char *name)
{
    if (!he_remove_optional(run->candidates, name)) return false;
    if (run->candidates >= 0 && fsync(run->candidates) != 0) return false;
    return he_start_retire(run->epochs, name);
}
static bool he_retire_entry(struct he_run *run, const char *name)
{
    uint64_t size;
    if (!he_measure(run, name, &size) || size > (uint64_t)INT64_MAX - *run->bytes) return false;
    if (run->apply && !he_remove_pair(run, name)) { ++*run->partial; return false; }
    if (!he_append(run->rows, run->profile->objects, name, size, run->apply)) {
        if (run->apply) ++*run->partial;
        return false;
    }
    *run->bytes += size; return true;
}
static bool he_entry(struct he_run *run, const struct he_epoch *entry, int *retained)
{
    if (!strcmp(entry->name, run->current)) return true;
    int fd = he_dir(run->epochs, entry->name);
    if (fd < 0) return false;
    bool idle = he_session_valid(fd, entry->name, run->profile->session) && he_idle(fd);
    if (close(fd) != 0) return false;
    if (!idle || !he_is_pair(run->candidates, entry->name)) return true;
    if (*retained < run->keep) { ++*retained; return true; }
    if (run->selected && strcmp(entry->name, run->selected)) return true;
    return he_retire_entry(run, entry->name);
}
static bool he_process(const char *checkout, int build, int bins, const struct he_profile *profile,
    int keep, bool apply, struct json_value *rows, uint64_t *bytes, unsigned *refused,
    unsigned *pending, unsigned *partial, const char *selected)
{
    struct he_run run = { .checkout = checkout, .profile = profile, .object = -1,
        .candidate = -1, .epochs = -1, .candidates = -1, .lock = -1, .keep = keep,
        .apply = apply, .rows = rows, .bytes = bytes, .refused = refused, .pending = pending, .partial = partial,
        .selected = selected };
    run.object = he_dir(build, profile->objects);
    if (run.object < 0) { if (errno != ENOENT) ++*refused; return true; }
    bool ok = he_run_open(&run, bins);
    struct he_epoch entries[HE_MAX_EPOCHS]; size_t count = 0;
    if (ok) ok = he_collect(run.epochs, run.current, entries, &count);
    if (ok) {
        qsort(entries, count, sizeof(entries[0]), he_order);
        int retained = 1;
        for (size_t i = 0; i < count && ok; ++i) ok = he_entry(&run, &entries[i], &retained);
    }
    if (!ok) ++*refused;
    he_run_close(&run); return true;
}
static bool he_checkout_git(const char *checkout)
{
    const char *args[] = { "env", "-u", "GIT_DIR", "-u", "GIT_COMMON_DIR", "-u", "GIT_WORK_TREE",
        "-u", "GIT_INDEX_FILE", "-u", "GIT_OBJECT_DIRECTORY", "-u", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "git", "-C", checkout, "rev-parse", "--show-toplevel", NULL };
    char out[HE_PATH], expected[HE_PATH];
    int n = snprintf(expected, sizeof(expected), "%s\n", checkout);
    if (n <= 0 || (size_t)n >= sizeof(expected) ||
        zcl_spawn_capture(args, out, sizeof(out), 10000) != 0 || strcmp(out, expected)) return false;
    const char *tracked[] = { "env", "-u", "GIT_DIR", "-u", "GIT_COMMON_DIR", "-u", "GIT_WORK_TREE",
        "-u", "GIT_INDEX_FILE", "-u", "GIT_OBJECT_DIRECTORY", "-u", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "git", "-C", checkout, "ls-files", "--", "build", NULL };
    if (zcl_spawn_capture(tracked, out, sizeof(out), 10000) != 0 || out[0]) return false;
    const char *committed[] = { "env", "-u", "GIT_DIR", "-u", "GIT_COMMON_DIR", "-u", "GIT_WORK_TREE",
        "-u", "GIT_INDEX_FILE", "-u", "GIT_OBJECT_DIRECTORY", "-u", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "git", "-C", checkout, "ls-tree", "-r", "--name-only", "HEAD", "--", "build", NULL };
    return zcl_spawn_capture(committed, out, sizeof(out), 10000) == 0 && !out[0];
}

/* This marker describes a cooperating checkout producer; it is not an
 * authentication claim and does not replace the Git, lock or mount checks. */
static bool he_producer_protocol(int root)
{
    int tools = he_dir(root, "tools");
    if (tools < 0) return false;
    int dev = he_dir(tools, "dev"); close(tools);
    if (dev < 0) return false;
    int fd = openat(dev, "build-epoch-session.sh", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    close(dev);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 1 || st.st_size > 262144) {
        close(fd); return false;
    }
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return false; }
    char line[1024]; unsigned found = 0; bool ok = true;
    while (fgets(line, sizeof(line), f)) {
        if (!strchr(line, '\n')) { ok = false; break; }
        if (!strcmp(line, "# z23-epoch-gc-protocol: lock-before-generation, preserve-staged-v1\n")) ++found;
    }
    if (ferror(f)) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok && found == 1;
}
struct he_totals { uint64_t bytes; unsigned refused, pending, partial; };
static int he_checkout_open(const char *checkout, int *bins, bool *compatible)
{
    char resolved[HE_PATH];
    if (!checkout || checkout[0] != '/' || !realpath(checkout, resolved) || strcmp(checkout, resolved) ||
        !strcmp(checkout, "/") || !he_checkout_git(checkout)) return -1;
    int root = open(checkout, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) return -1;
    struct stat st;
    bool valid = fstatat(root, ".git", &st, AT_SYMLINK_NOFOLLOW) == 0 && (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode));
    *compatible = valid && he_producer_protocol(root);
    int build = valid ? he_dir(root, "build") : -1;
    *bins = build >= 0 ? he_dir(build, "bin") : -1;
    close(root); return build;
}
static bool he_report(struct json_value *out, const char *checkout, int keep, bool apply,
    const struct he_totals *totals, struct json_value *rows)
{
    return json_push_kv_bool(out, "apply", apply) && json_push_kv_str(out, "checkout", checkout) &&
        json_push_kv_int(out, "epoch_keep", keep) && json_push_kv_int(out, "estimated_logical_path_bytes", (int64_t)totals->bytes) &&
        json_push_kv_int(out, "profiles_refused", totals->refused) &&
        json_push_kv_int(out, "pending_recovery", totals->pending) &&
        json_push_kv_int(out, "partial_possible", totals->partial) && json_push_kv(out, "epochs", rows);
}
static void he_process_profiles(const char *checkout, int build, int bins, int keep, bool apply,
    const struct he_profile *profile, const char *selected, struct json_value *rows, struct he_totals *totals)
{
    for (size_t i = 0; i < sizeof(he_profiles)/sizeof(he_profiles[0]); ++i) {
        if (profile && profile != &he_profiles[i]) continue;
        (void)he_process(checkout, build, bins, &he_profiles[i], keep, apply, rows,
            &totals->bytes, &totals->refused, &totals->pending, &totals->partial, selected);
    }
}
static bool he_epochs_impl(const char *checkout, int keep, bool apply,
                           const char *selector, struct json_value *out)
{
    const char *selected = NULL;
    const struct he_profile *profile = selector ? he_selector(selector, &selected) : NULL;
    if (selector && !profile) return false;
    bool compatible = false;
    int bins = -1, build = he_checkout_open(checkout, &bins, &compatible);
    if (build < 0) return false;
    if (!json_push_kv_bool(out, "producer_compatible", compatible)) {
        if (bins >= 0) close(bins);
        close(build); return false;
    }
    if (apply && !compatible) { if (bins >= 0) close(bins); close(build); return false; }
    struct json_value rows; json_init(&rows); json_set_array(&rows);
    struct he_totals totals = {0};
    he_process_profiles(checkout, build, bins, keep, apply, profile, selected, &rows, &totals);
    bool ok = he_report(out, checkout, keep, apply, &totals, &rows);
    if (ok && selector) ok = json_push_kv_str(out, "epoch_selector", selector);
    json_free(&rows); if (bins >= 0) close(bins); close(build); return ok;
}
#else
static bool he_epochs_impl(const char *checkout, int keep, bool apply, const char *selector, struct json_value *out)
{ (void)checkout; (void)keep; (void)apply; (void)selector; (void)out; return false; }
#endif

bool host_gc_epochs(const char *checkout, int keep, bool apply, struct json_value *out)
{ return he_epochs_impl(checkout, keep, apply, NULL, out); }
bool host_gc_epoch_selector_valid(const char *selector)
{
#if defined(__linux__)
    const char *hash = NULL;
    return he_selector(selector, &hash) != NULL;
#else
    (void)selector; return false;
#endif
}
bool host_gc_epochs_selected(const char *checkout, int keep, bool apply,
                             const char *selector, struct json_value *out)
{ return selector && he_epochs_impl(checkout, keep, apply, selector, out); }
