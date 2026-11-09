/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Stage untrusted checkpoint bytes without granting acceptance. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include "zcl_nodectl_bundle.h"
#include "platform/positioned_file.h"
#include "sha3/sha3.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct bs_stage {
    int parent, data, bundles, temp;
    char parent_path[PATH_MAX], data_path[PATH_MAX], data_leaf[NAME_MAX + 1];
    char leaf[NAME_MAX + 1], temporary[NAME_MAX + 1];
    struct stat parent_id, data_id, bundles_id, temp_id;
    struct platform_positioned_file source;
    const char *phase; bool published;
};
static bool bs_same(const struct stat *a, const struct stat *b)
{ return a->st_dev == b->st_dev && a->st_ino == b->st_ino; }
static bool bs_owned_dir(const struct stat *s)
{ return S_ISDIR(s->st_mode) && s->st_uid == geteuid() && !(s->st_mode & 0022); }
static bool bs_bound(struct bs_stage *s)
{
    struct stat parent, data, named, held;
    char canonical[PATH_MAX];
    return realpath(s->parent_path, canonical) && !strcmp(canonical, s->parent_path) &&
        lstat(s->parent_path, &parent) == 0 && bs_same(&s->parent_id, &parent) &&
        fstatat(s->parent, s->data_leaf, &data, AT_SYMLINK_NOFOLLOW) == 0 &&
        bs_same(&s->data_id, &data) &&
        lstat(s->data_path, &data) == 0 && bs_same(&s->data_id, &data) &&
        fstatat(s->data, "bundles", &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        fstat(s->bundles, &held) == 0 && bs_owned_dir(&named) &&
        bs_same(&s->bundles_id, &named) && bs_same(&named, &held);
}
/* Return 1 for an existing marker/bundle, 0 when empty, -1 on ambiguity. */
static int bs_existing(int data, int bundles)
{
    struct stat st;
    if (fstatat(data, "consensus-bundle-installed.marker", &st, AT_SYMLINK_NOFOLLOW) == 0)
        return S_ISREG(st.st_mode) ? 1 : -1;
    if (errno != ENOENT) return -1;
    if (bundles < 0) return 0;
    int copy = dup(bundles); if (copy < 0) return -1;
    DIR *dir = fdopendir(copy); if (!dir) { close(copy); return -1; }
    rewinddir(dir);
    int result = 0; struct dirent *entry; errno = 0;
    while ((entry = readdir(dir))) {
        size_t n = strlen(entry->d_name);
        if (n < 7 || strcmp(entry->d_name + n - 7, ".sqlite")) continue;
        if (fstatat(bundles, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) result = -1;
        else result = 1;
        break;
    }
    if (!entry && errno) result = -1;
    if (closedir(dir) != 0) result = -1;
    return result;
}
static bool bs_open_parent(struct bs_stage *s, const char *path)
{
    char canonical[PATH_MAX], parent[PATH_MAX];
    if (!path || path[0] != '/' || strlen(path) >= sizeof(s->data_path)) return false;
    const char *slash = strrchr(path, '/'); size_t name_len = strlen(slash + 1);
    size_t parent_len = (size_t)(slash - path);
    if (!parent_len || !name_len || name_len > NAME_MAX || parent_len >= sizeof(parent) ||
        !strcmp(slash + 1, ".") || !strcmp(slash + 1, "..")) return false;
    memcpy(parent, path, parent_len); parent[parent_len] = 0;
    if (!realpath(parent, canonical) || strcmp(parent, canonical)) return false;
    s->parent = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (s->parent < 0 || fstat(s->parent, &s->parent_id) != 0 || !bs_owned_dir(&s->parent_id)) return false;
    memcpy(s->parent_path, parent, parent_len + 1); memcpy(s->data_leaf, slash + 1, name_len + 1);
    memcpy(s->data_path, path, strlen(path) + 1); return true;
}
static bool bs_open_data(struct bs_stage *s, bool create)
{
    if (create && mkdirat(s->parent, s->data_leaf, 0700) != 0 && errno != EEXIST) return false;
    if (create && fsync(s->parent) != 0) return false;
    s->data = openat(s->parent, s->data_leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (s->data < 0) return false;
    if (fstat(s->data, &s->data_id) == 0 && bs_owned_dir(&s->data_id)) return true;
    close(s->data); s->data = -1; errno = EPERM; return false;
}
static bool bs_open_bundles(struct bs_stage *s, bool create)
{
    if (create && mkdirat(s->data, "bundles", 0700) != 0 && errno != EEXIST) return false;
    if (create && fsync(s->data) != 0) return false;
    s->bundles = openat(s->data, "bundles", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (s->bundles < 0) return false;
    if (fstat(s->bundles, &s->bundles_id) == 0 && bs_owned_dir(&s->bundles_id) && bs_bound(s)) return true;
    close(s->bundles); s->bundles = -1; errno = EPERM; return false;
}
static bool bs_write_all(int fd, const uint8_t *data, size_t size)
{
    while (size) {
        ssize_t n = write(fd, data, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        data += (size_t)n; size -= (size_t)n;
    }
    return true;
}
static bool bs_hash_staged(int fd, uint64_t size, uint8_t out[32])
{
    if (lseek(fd, 0, SEEK_SET) < 0) return false;
    struct sha3_256_ctx hash; uint8_t buf[65536]; uint64_t off = 0;
    sha3_256_init(&hash);
    while (off < size) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || (uint64_t)n > size - off) return false;
        sha3_256_write(&hash, buf, (size_t)n); off += (uint64_t)n;
    }
    sha3_256_finalize(&hash, out); return true;
}
static bool bs_copy(struct bs_stage *s)
{
    struct platform_positioned_file_snapshot before, after;
    if (!platform_positioned_file_snapshot(&s->source, &before) || !before.size) return false;
    struct sha3_256_ctx hash; uint8_t source_hash[32], dest_hash[32], buf[65536];
    sha3_256_init(&hash); uint64_t off = 0;
    while (off < before.size) {
        size_t want = before.size - off > sizeof(buf) ? sizeof(buf) : (size_t)(before.size - off);
        int64_t n = platform_positioned_file_read(&s->source, buf, want, off);
        if (n <= 0 || !bs_write_all(s->temp, buf, (size_t)n)) return false;
        sha3_256_write(&hash, buf, (size_t)n); off += (uint64_t)n;
    }
    sha3_256_finalize(&hash, source_hash);
    if (!platform_positioned_file_snapshot(&s->source, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after) || fchmod(s->temp, 0444) || fsync(s->temp)) return false;
    return bs_hash_staged(s->temp, before.size, dest_hash) && !memcmp(source_hash, dest_hash, sizeof(source_hash));
}
static bool bs_temp(struct bs_stage *s)
{
    for (unsigned i = 0; i < 64; ++i) {
        int n = snprintf(s->temporary, sizeof(s->temporary), ".z23-stage-%ld-%u", (long)getpid(), i);
        if (n <= 0 || (size_t)n >= sizeof(s->temporary)) return false;
        s->temp = openat(s->bundles, s->temporary, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (s->temp >= 0) return fstat(s->temp, &s->temp_id) == 0;
        if (errno != EEXIST) return false;
    }
    return false;
}
static bool bs_cleanup(struct bs_stage *s)
{
    bool ok = true; struct stat named;
    if (s->temp >= 0) {
        if (fstatat(s->bundles, s->temporary, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !bs_same(&s->temp_id, &named) || unlinkat(s->bundles, s->temporary, 0) != 0) ok = false;
        else if (fsync(s->bundles) != 0) ok = false;
        if (close(s->temp) != 0) ok = false;
    }
    if (s->bundles >= 0 && close(s->bundles) != 0) ok = false;
    if (s->data >= 0 && close(s->data) != 0) ok = false;
    if (s->parent >= 0 && close(s->parent) != 0) ok = false;
    platform_positioned_file_close(&s->source); return ok;
}
static int bs_finish(struct bs_stage *s)
{
    if (bs_cleanup(s)) return 0;
    fprintf(stderr, "zcl-nodectl bundle-stage: cleanup incomplete; inspect staging directory before retrying\n");
    return 1;
}
static bool bs_source(struct bs_stage *s, const char *source)
{
    const char *name = strrchr(source, '/'); name = name ? name + 1 : source;
    size_t len = strlen(name);
    if (len < 8 || len > NAME_MAX || strcmp(name + len - 7, ".sqlite") ||
        !platform_positioned_file_open(&s->source, source)) return false;
    struct platform_positioned_file_snapshot info;
    if (!platform_positioned_file_snapshot(&s->source, &info) || !info.size) return false;
    memcpy(s->leaf, name, len + 1); return true;
}
/* -1 refuses, 0 continues, 1 is an already-staged no-op. */
static int bs_prepare(struct bs_stage *s, const char *datadir, const char *source)
{
    s->phase = "validate data directory";
    if (!bs_open_parent(s, datadir)) return -1;
    bool opened = bs_open_data(s, false);
    if (!opened && errno != ENOENT) return -1;
    if (opened && !bs_open_bundles(s, false) && errno != ENOENT) return -1;
    if (opened) { int old = bs_existing(s->data, s->bundles); if (old != 0) return old; }
    s->phase = "validate source";
    if (!bs_source(s, source)) return -1;
    s->phase = "create staging directory";
    if (!opened && !bs_open_data(s, true)) return -1;
    if (s->bundles < 0 && !bs_open_bundles(s, true)) return -1;
    return 0;
}
static int bs_publish(struct bs_stage *s)
{
    s->phase = "acquire staging lock";
    if (flock(s->bundles, LOCK_EX | LOCK_NB) != 0) return -1;
    int existing = bs_existing(s->data, s->bundles);
    if (existing != 0) return existing;
    s->phase = "copy and verify source";
    if (!bs_bound(s) || !bs_temp(s) || !bs_copy(s) || !bs_bound(s) || bs_existing(s->data, s->bundles) != 0) return -1;
    s->phase = "publish without replacement";
    if (linkat(s->bundles, s->temporary, s->bundles, s->leaf, 0) != 0) return -1;
    s->published = true; struct stat final;
    if (fstatat(s->bundles, s->leaf, &final, AT_SYMLINK_NOFOLLOW) != 0 ||
        !bs_same(&s->temp_id, &final) || !bs_bound(s) || fsync(s->bundles) != 0) return -1;
    return 0;
}
static int bs_stage(const char *datadir, const char *source)
{
    struct bs_stage s = {.parent = -1, .data = -1, .bundles = -1, .temp = -1};
    platform_positioned_file_init(&s.source);
    if (!source || !source[0]) return 0;
    int prepared = bs_prepare(&s, datadir, source);
    if (prepared > 0) return bs_finish(&s);
    if (prepared == 0 && bs_publish(&s) >= 0) return bs_finish(&s);
    (void)bs_finish(&s);
    fprintf(stderr, "zcl-nodectl bundle-stage: %s failed%s; inspect %s before retrying\n",
            s.phase, s.published ? " after publication; outcome uncertain" : "", datadir ? datadir : "datadir");
    return 1;
}
int nodectl_bundle_stage(int argc, char **argv)
{
    const char *data = NULL, *source = NULL;
    for (int i = 2; i < argc; ++i) {
        if (!strncmp(argv[i], "--datadir=", 10) && !data) data = argv[i] + 10;
        else if (!strncmp(argv[i], "--source=", 9) && !source) source = argv[i] + 9;
        else { fprintf(stderr, "zcl-nodectl bundle-stage: expected --datadir= and --source=\n"); return 2; }
    }
    if (!data || !source) return 2;
    return bs_stage(data, source);
}
