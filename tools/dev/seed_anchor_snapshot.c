/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Stage a candidate anchor snapshot at <datadir>/utxo-anchor.snapshot.
 *          Best-effort and idempotent: a missing datadir or source is a skip,
 *          a same nonzero size is left in place, and a copy or rename failure
 *          does not fail the caller. The node SHA3-verifies the body. */

#include "seed_anchor_snapshot.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if !defined(_WIN32)

static int sas_fit(int n, size_t cap)
{
    return n > 0 && (size_t)n < cap;
}

enum { SAS_NONE = 0, SAS_DIR = 1, SAS_REG = 2 };

/* One stat: directory, regular file plus size, or neither. A failed stat
 * and a negative size are neither, which the shell treats as size 0. */
static int sas_kind(const char *path, unsigned long long *sz)
{
    struct stat st;
    if (sz != NULL)
        *sz = 0;
    if (stat(path, &st) != 0)
        return SAS_NONE;
    if (S_ISDIR(st.st_mode))
        return SAS_DIR;
    if (!S_ISREG(st.st_mode) || st.st_size < 0)
        return SAS_NONE;
    if (sz != NULL)
        *sz = (unsigned long long)st.st_size;
    return SAS_REG;
}

static int sas_resolve(char *datadir, size_t dcap, char *src, size_t scap)
{
    const char *datadir_env = getenv("ZCL_DATADIR");
    const char *src_env = getenv("ZCL_ANCHOR_SNAPSHOT_SRC");
    const char *home = getenv("HOME");
    int n;
    if (datadir_env != NULL && datadir_env[0] != '\0')
        n = snprintf(datadir, dcap, "%s", datadir_env);
    else if (home != NULL && home[0] != '\0')
        n = snprintf(datadir, dcap, "%s/.zclassic-c23", home);
    else {
        fprintf(stderr,
                "seed-anchor-snapshot: ZCL_DATADIR and HOME are unset\n");
        return -1;
    }
    if (!sas_fit(n, dcap))
        return -1;
    if (src_env != NULL && src_env[0] != '\0')
        n = snprintf(src, scap, "%s", src_env);
    else
        n = snprintf(src, scap, "/tmp/anchor-ram.snapshot");
    if (!sas_fit(n, scap))
        return -1;
    return 0;
}

static void sas_absent(const char *datadir)
{
    fprintf(stdout,
            "[seed-anchor-snapshot] datadir %s absent — skip "
            "(fresh install mints in-fold)\n",
            datadir);
}

static void sas_no_source(const char *src)
{
    fprintf(stdout,
            "[seed-anchor-snapshot] no source snapshot at %s — skip "
            "(self-mint will produce one on the anchor-crossing fold; "
            "set ZCL_ANCHOR_SNAPSHOT_SRC to override)\n",
            src);
}

static void sas_kept(const char *dst, unsigned long long sz)
{
    fprintf(stdout,
            "[seed-anchor-snapshot] %s already present (size %llu) — "
            "not re-copying\n",
            dst, sz);
}

static void sas_fail(const char *verb, const char *from, const char *to)
{
    fprintf(stdout,
            "[seed-anchor-snapshot] %s %s -> %s failed — skip (non-fatal)\n",
            verb, from, to);
}

static void sas_staged(const char *src, const char *dst)
{
    unsigned long long sz = 0;
    if (sas_kind(dst, &sz) != SAS_REG) {
        fprintf(stdout,
                "[seed-anchor-snapshot] staged %s -> %s (size ?). "
                "The node SHA3-verifies it vs the compiled checkpoint "
                "on boot before any trust.\n",
                src, dst);
        return;
    }
    fprintf(stdout,
            "[seed-anchor-snapshot] staged %s -> %s (size %llu). "
            "The node SHA3-verifies it vs the compiled checkpoint "
            "on boot before any trust.\n",
            src, dst, sz);
}

static int sas_copy(const char *from, const char *to)
{
    int in_fd = open(from, O_RDONLY);
    int out_fd;
    char buf[8192];
    if (in_fd < 0)
        return -1;
    out_fd = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        close(in_fd);
        return -1;
    }
    for (;;) {
        ssize_t n = read(in_fd, buf, sizeof buf);
        ssize_t off = 0;
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(in_fd);
            close(out_fd);
            return -1;
        }
        while (off < n) {
            ssize_t w = write(out_fd, buf + off, (size_t)(n - off));
            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0) {
                close(in_fd);
                close(out_fd);
                return -1;
            }
            off += w;
        }
    }
    if (close(out_fd) != 0) {
        close(in_fd);
        return -1;
    }
    close(in_fd);
    return 0;
}

static int sas_same(const char *src, const char *dst)
{
    unsigned long long src_sz = 0;
    unsigned long long dst_sz = 0;
    if (sas_kind(dst, &dst_sz) != SAS_REG)
        return 0;
    if (sas_kind(src, &src_sz) != SAS_REG)
        return 0;
    if (src_sz == dst_sz && src_sz != 0) {
        sas_kept(dst, dst_sz);
        return 1;
    }
    return 0;
}

static int sas_publish(const char *src, const char *dst, const char *tmp)
{
    if (sas_copy(src, tmp) != 0) {
        sas_fail("copy", src, tmp);
        unlink(tmp);
        return 0;
    }
    if (rename(tmp, dst) != 0) {
        sas_fail("rename", tmp, dst);
        unlink(tmp);
        return 0;
    }
    sas_staged(src, dst);
    return 0;
}

static int sas_run(void)
{
    char datadir[PATH_MAX];
    char src[PATH_MAX];
    char dst[PATH_MAX];
    char tmp[PATH_MAX];
    int n;
    if (sas_resolve(datadir, sizeof datadir, src, sizeof src) != 0)
        return 1;
    if (sas_kind(datadir, NULL) != SAS_DIR) {
        sas_absent(datadir);
        return 0;
    }
    n = snprintf(dst, sizeof dst, "%s/utxo-anchor.snapshot", datadir);
    if (!sas_fit(n, sizeof dst))
        return 1;
    if (sas_kind(src, NULL) != SAS_REG) {
        sas_no_source(src);
        return 0;
    }
    if (sas_same(src, dst))
        return 0;
    n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", dst, (long)getpid());
    if (!sas_fit(n, sizeof tmp)) {
        sas_fail("copy", src, dst);
        return 0;
    }
    return sas_publish(src, dst, tmp);
}

#endif /* !_WIN32 */

int zcl_seed_anchor_snapshot(void)
{
#if defined(_WIN32)
    fprintf(stdout,
            "[seed-anchor-snapshot] datadir staging is unavailable "
            "on Windows — skip\n");
    return 0;
#else
    return sas_run();
#endif
}
