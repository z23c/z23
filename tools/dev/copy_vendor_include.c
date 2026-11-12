/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Merge one checkout's generated vendor/include tree into another.
 *          Matches cp -a of the source directory contents: directories merge,
 *          files and symlinks are replaced, unrelated destination files stay. */

#include "copy_vendor_include.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void cvi_msg(int fd, const char *text)
{
    size_t n;
    if (!text)
        return;
    if (fd < 0)
        fd = STDERR_FILENO;
    n = strlen(text);
    while (n > 0) {
        ssize_t w = write(fd, text, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        text += (size_t)w;
        n -= (size_t)w;
    }
}

#if !defined(_WIN32)

static int cvi_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && n < (int)cap ? 0 : -1;
}

static int cvi_copy_bytes(const char *src, const char *dst, mode_t mode)
{
    int in = open(src, O_RDONLY);
    int out;
    char buf[65536];
    if (in < 0)
        return -1;
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) {
        (void)close(in);
        return -1;
    }
    for (;;) {
        ssize_t n = read(in, buf, sizeof buf);
        size_t left;
        char *p;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            (void)close(in);
            (void)close(out);
            return -1;
        }
        if (n == 0)
            break;
        left = (size_t)n;
        p = buf;
        while (left > 0) {
            ssize_t w = write(out, p, left);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                (void)close(in);
                (void)close(out);
                return -1;
            }
            p += w;
            left -= (size_t)w;
        }
    }
    if (fchmod(out, mode & 07777) != 0) {
        (void)close(in);
        (void)close(out);
        return -1;
    }
    (void)close(in);
    return close(out) == 0 ? 0 : -1;
}

static int cvi_unlink_file(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return 0;
    if (S_ISDIR(st.st_mode))
        return -1;
    return unlink(path);
}

static int cvi_copy_tree(const char *src, const char *dst);

static int cvi_copy_entry(const char *src, const char *dst)
{
    struct stat st;
    if (lstat(src, &st) != 0)
        return -1;
    if (S_ISDIR(st.st_mode)) {
        if (mkdir(dst, st.st_mode & 07777) != 0 && errno != EEXIST)
            return -1;
        return cvi_copy_tree(src, dst);
    }
    if (cvi_unlink_file(dst) != 0)
        return -1;
    if (S_ISLNK(st.st_mode)) {
        char link[PATH_MAX];
        ssize_t n = readlink(src, link, sizeof link - 1);
        if (n < 0)
            return -1;
        link[n] = '\0';
        return symlink(link, dst);
    }
    if (!S_ISREG(st.st_mode))
        return 0;
    return cvi_copy_bytes(src, dst, st.st_mode);
}

static int cvi_copy_tree(const char *src, const char *dst)
{
    DIR *dir = opendir(src);
    struct dirent *ent;
    if (!dir)
        return -1;
    while ((ent = readdir(dir)) != NULL) {
        char from[PATH_MAX];
        char to[PATH_MAX];
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        if (cvi_join(from, sizeof from, src, ent->d_name) != 0 ||
            cvi_join(to, sizeof to, dst, ent->d_name) != 0 ||
            cvi_copy_entry(from, to) != 0) {
            (void)closedir(dir);
            return -1;
        }
    }
    return closedir(dir) == 0 ? 0 : -1;
}

static int cvi_missing(const char *source_root, int err_fd)
{
    char line[PATH_MAX + 160];
    (void)snprintf(line, sizeof line,
                   "vendor/include: source %s/vendor/include is missing -- "
                   "openssl/zlib gates will fail until you run make vendor "
                   "there\n",
                   source_root);
    cvi_msg(err_fd, line);
    return 1;
}

#endif /* !_WIN32 */

int zcl_copy_vendor_include(const char *source_root, const char *dest_root,
                            int err_fd)
{
#if defined(_WIN32)
    (void)source_root;
    (void)dest_root;
    cvi_msg(err_fd, "copy-vendor-include: unavailable on Windows\n");
    return 1;
#else
    char src[PATH_MAX];
    char dst[PATH_MAX];
    struct stat st;
    if (!source_root || !source_root[0] || !dest_root || !dest_root[0])
        return 2;
    if (snprintf(src, sizeof src, "%s/vendor/include", source_root) >=
            (int)sizeof src ||
        snprintf(dst, sizeof dst, "%s/vendor/include", dest_root) >=
            (int)sizeof dst)
        return 1;
    if (lstat(src, &st) != 0 || !S_ISDIR(st.st_mode))
        return cvi_missing(source_root, err_fd);
    if (mkdir(dst, 0755) != 0 && errno != EEXIST)
        return 1;
    return cvi_copy_tree(src, dst) == 0 ? 0 : 1;
#endif
}
