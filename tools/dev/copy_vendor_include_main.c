/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry worktree-prime execs instead of copy_vendor_include.sh. */

#include "copy_vendor_include.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <sys/stat.h>
#endif

static void cvi_usage(const char *argv0)
{
    fprintf(stderr, "usage: %s --selftest | SOURCE_ROOT DESTINATION_ROOT\n",
            argv0 ? argv0 : "copy-vendor-include");
}

#if !defined(_WIN32)
static int cvi_write(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    if (!file)
        return -1;
    if (fputs(text, file) < 0 || fclose(file) != 0)
        return -1;
    return 0;
}

static int cvi_mkdir_p(const char *path)
{
    char buf[512];
    size_t n;
    size_t i;
    if (!path || strlen(path) >= sizeof buf)
        return -1;
    n = strlen(path);
    memcpy(buf, path, n + 1);
    for (i = 1; i < n; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (buf[0] && mkdir(buf, 0755) != 0 && errno != EEXIST)
            return -1;
        buf[i] = '/';
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int cvi_rm_rf(const char *path)
{
    DIR *dir = opendir(path);
    struct dirent *ent;
    if (!dir)
        return unlink(path);
    while ((ent = readdir(dir)) != NULL) {
        char child[512];
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        if (snprintf(child, sizeof child, "%s/%s", path, ent->d_name) >=
            (int)sizeof child) {
            (void)closedir(dir);
            return -1;
        }
        if (cvi_rm_rf(child) != 0) {
            (void)closedir(dir);
            return -1;
        }
    }
    if (closedir(dir) != 0)
        return -1;
    return rmdir(path);
}

static int cvi_expect(const char *path, const char *text)
{
    FILE *file = fopen(path, "r");
    char got[32];
    if (!file)
        return -1;
    if (!fgets(got, sizeof got, file) || strcmp(got, text) != 0) {
        (void)fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int cvi_selftest_prepare(const char *fixture)
{
    char path[512];
    (void)snprintf(path, sizeof path, "%s/source/vendor/include/openssl",
                   fixture);
    if (cvi_mkdir_p(path) != 0)
        return -1;
    (void)snprintf(path, sizeof path, "%s/destination/vendor/include/leveldb",
                   fixture);
    if (cvi_mkdir_p(path) != 0)
        return -1;
    (void)snprintf(path, sizeof path, "%s/source/vendor/include/openssl/evp.h",
                   fixture);
    if (cvi_write(path, "evp-v1\n") != 0)
        return -1;
    (void)snprintf(path, sizeof path, "%s/source/vendor/include/zlib.h",
                   fixture);
    if (cvi_write(path, "zlib-v1\n") != 0)
        return -1;
    (void)snprintf(path, sizeof path,
                   "%s/destination/vendor/include/leveldb/db.h", fixture);
    return cvi_write(path, "tracked\n");
}

static int cvi_selftest_copied(const char *fixture)
{
    char source[512];
    char dest[512];
    char path[512];
    (void)snprintf(source, sizeof source, "%s/source", fixture);
    (void)snprintf(dest, sizeof dest, "%s/destination", fixture);
    if (zcl_copy_vendor_include(source, dest, STDERR_FILENO) != 0)
        return -1;
    (void)snprintf(path, sizeof path,
                   "%s/destination/vendor/include/openssl/evp.h", fixture);
    if (cvi_expect(path, "evp-v1\n") != 0)
        return -1;
    (void)snprintf(path, sizeof path,
                   "%s/destination/vendor/include/leveldb/db.h", fixture);
    return cvi_expect(path, "tracked\n");
}

static int cvi_selftest_missing(void)
{
    int pipefd[2];
    char err[512];
    ssize_t n;
    int status;
    if (pipe(pipefd) != 0)
        return -1;
    status = zcl_copy_vendor_include("/no/such/vendor-src", "/tmp", pipefd[1]);
    (void)close(pipefd[1]);
    n = read(pipefd[0], err, sizeof err - 1);
    (void)close(pipefd[0]);
    if (n < 0)
        n = 0;
    err[n] = '\0';
    if (status != 1 || strstr(err, "vendor/include: source ") == NULL)
        return -1;
    return 0;
}

static int cvi_selftest(void)
{
    char fixture[] = "/tmp/z23-vendor-include.XXXXXX";
    int status = 1;
    if (!mkdtemp(fixture))
        return 1;
    if (cvi_selftest_prepare(fixture) == 0 &&
        cvi_selftest_copied(fixture) == 0 &&
        cvi_selftest_missing() == 0) {
        printf("copy-vendor-include --selftest: PASS\n");
        status = 0;
    }
    (void)cvi_rm_rf(fixture);
    return status;
}
#endif

int main(int argc, char **argv)
{
#if defined(_WIN32)
    (void)argc;
    (void)argv;
    fprintf(stderr, "copy-vendor-include: unavailable on Windows\n");
    return 1;
#else
    const char *argv0 = argc > 0 ? argv[0] : "copy-vendor-include";
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return cvi_selftest();
    if (argc != 3) {
        cvi_usage(argv0);
        return 2;
    }
    return zcl_copy_vendor_include(argv[1], argv[2], STDERR_FILENO);
#endif
}
