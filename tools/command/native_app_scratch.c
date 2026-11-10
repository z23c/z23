/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Owned private root; refuse replacement and never follow links during cleanup. */
#define _POSIX_C_SOURCE 200809L
#include "command/native_app_scratch.h"
#if !defined(_WIN32)
#include "util/file_tree_ops.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
bool an_scratch_copy_text(char *out, size_t cap, const char *text, bool allow_empty)
{
    if (!text) return false;
    size_t n = strnlen(text, cap);
    if ((!allow_empty && n == 0) || n >= cap) return false;
    memcpy(out, text, n + 1);
    return true;
}
bool an_scratch_read_exact(int fd, uint8_t *bytes, size_t n)
{
    size_t used = 0;
    while (used < n) {
        ssize_t got = read(fd, bytes + used, n - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        used += (size_t)got;
    }
    return true;
}
bool an_scratch_decimal(const char *s, uint64_t max, uint64_t *out)
{
    uint64_t n = 0;
    if (!s || !*s || (*s == '0' && s[1])) return false;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
        unsigned d = (unsigned)(*s - '0');
        if (d > max || n > (max - d) / 10u) return false;
        n = n * 10u + d;
    }
    *out = n; return true;
}
static bool an_same_dir(const struct stat *a, const struct stat *b)
{ return S_ISDIR(a->st_mode) && S_ISDIR(b->st_mode) && a->st_dev == b->st_dev && a->st_ino == b->st_ino; }
/* Scratch belongs to one worker and is removed only after it is reaped. */
bool an_scratch_bound(const struct an_scratch *s)
{
    struct stat parent, named_parent, held, named, full;
    return s->parent >= 0 && s->root >= 0 && fstat(s->parent, &parent) == 0 &&
        lstat(s->anchor, &named_parent) == 0 && an_same_dir(&parent, &named_parent) &&
        fstat(s->root, &held) == 0 && held.st_dev == s->dev && held.st_ino == s->ino &&
        fstatat(s->parent, s->leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        lstat(s->path, &full) == 0 && an_same_dir(&held, &named) && an_same_dir(&held, &full);
}
static int an_scratch_parent(const char *anchor)
{
    int fd = open(anchor, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || st.st_uid != geteuid() || (st.st_mode & 022)) { close(fd); return -1; }
    return fd;
}
bool an_scratch_create(struct an_scratch *s, const char *anchor, const char *token)
{
    memset(s, 0, sizeof(*s)); s->parent = s->root = -1;
    if (strlen(anchor) >= sizeof(s->anchor)) return false;
    memcpy(s->anchor, anchor, strlen(anchor) + 1);
    int n = snprintf(s->leaf, sizeof(s->leaf), ".app-network-%s", token);
    int p = snprintf(s->path, sizeof(s->path), "%s/%s", anchor, s->leaf);
    if (n <= 0 || (size_t)n >= sizeof(s->leaf) || p <= 0 || (size_t)p >= sizeof(s->path)) return false;
    s->parent = an_scratch_parent(anchor);
    struct stat root;
    if (s->parent < 0) return false;
    if (mkdirat(s->parent, s->leaf, 0700)) return false;
    s->created = true;
    s->root = openat(s->parent, s->leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (s->root < 0 || fstat(s->root, &root) || root.st_uid != geteuid() || (root.st_mode & 077)) return false;
    s->dev = root.st_dev; s->ino = root.st_ino;
    return fsync(s->parent) == 0 && an_scratch_bound(s);
}
bool an_scratch_cleanup(struct an_scratch *s, bool child_reaped)
{
    bool ok = false;
    if (child_reaped && s->created && an_scratch_bound(s)) {
        struct zcl_result result = zcl_tree_remove_contents_fd(s->root);
        ok = result.ok && an_scratch_bound(s) &&
            unlinkat(s->parent, s->leaf, AT_REMOVEDIR) == 0 && fsync(s->parent) == 0;
    }
    if (s->root >= 0) close(s->root);
    if (s->parent >= 0) close(s->parent);
    return ok;
}
#else
typedef int app_scratch_unavailable;
#endif
