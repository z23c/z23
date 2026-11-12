/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_copy_vendor_include, the shipped vendor-header merge. A
 * destination file that the source does not have must stay, a second copy
 * must replace changed bytes, and a missing source must refuse. */

#include "test/test_core.h"

#include "copy_vendor_include.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int cvi_put(const char *path, const char *text)
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
    size_t i;
    size_t n = strlen(path);
    if (n >= sizeof buf)
        return -1;
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

static int cvi_read(const char *path, char *out, size_t cap)
{
    FILE *file = fopen(path, "r");
    if (!file || !fgets(out, (int)cap, file)) {
        if (file)
            (void)fclose(file);
        return -1;
    }
    (void)fclose(file);
    return 0;
}

static int test_copy_vendor_include_cases(const char *root)
{
    int failures = 0;
    char source[512];
    char dest[512];
    char path[512];
    char err[1024];
    char got[64];
    int pipefd[2];
    int status;
    ssize_t n;
    TEST("copy vendor include: merge, keep extras, replace, refuse missing") {
        (void)snprintf(source, sizeof source, "%s/source", root);
        (void)snprintf(dest, sizeof dest, "%s/destination", root);
        (void)snprintf(path, sizeof path, "%s/vendor/include/openssl", source);
        ASSERT(cvi_mkdir_p(path) == 0);
        (void)snprintf(path, sizeof path, "%s/vendor/include/leveldb", dest);
        ASSERT(cvi_mkdir_p(path) == 0);
        (void)snprintf(path, sizeof path, "%s/vendor/include/openssl/evp.h",
                       source);
        ASSERT(cvi_put(path, "evp-v1\n") == 0);
        (void)snprintf(path, sizeof path, "%s/vendor/include/zlib.h", source);
        ASSERT(cvi_put(path, "zlib-v1\n") == 0);
        (void)snprintf(path, sizeof path, "%s/vendor/include/link", source);
        ASSERT(symlink("zlib.h", path) == 0);
        (void)snprintf(path, sizeof path, "%s/vendor/include/leveldb/db.h",
                       dest);
        ASSERT(cvi_put(path, "tracked\n") == 0);
        ASSERT(zcl_copy_vendor_include(source, dest, STDERR_FILENO) == 0);
        (void)snprintf(path, sizeof path,
                       "%s/vendor/include/openssl/evp.h", dest);
        ASSERT(cvi_read(path, got, sizeof got) == 0);
        ASSERT(strcmp(got, "evp-v1\n") == 0);
        (void)snprintf(path, sizeof path, "%s/vendor/include/leveldb/db.h",
                       dest);
        ASSERT(cvi_read(path, got, sizeof got) == 0);
        ASSERT(strcmp(got, "tracked\n") == 0);
        (void)snprintf(path, sizeof path, "%s/vendor/include/link", dest);
        {
            char link[64];
            ssize_t len = readlink(path, link, sizeof link - 1);
            ASSERT(len > 0);
            link[len] = '\0';
            ASSERT(strcmp(link, "zlib.h") == 0);
        }
        (void)snprintf(path, sizeof path, "%s/vendor/include/openssl/evp.h",
                       source);
        ASSERT(cvi_put(path, "evp-v2\n") == 0);
        ASSERT(zcl_copy_vendor_include(source, dest, STDERR_FILENO) == 0);
        (void)snprintf(path, sizeof path,
                       "%s/vendor/include/openssl/evp.h", dest);
        ASSERT(cvi_read(path, got, sizeof got) == 0);
        ASSERT(strcmp(got, "evp-v2\n") == 0);
        ASSERT(pipe(pipefd) == 0);
        status = zcl_copy_vendor_include("/no/such/vendor-src", dest,
                                         pipefd[1]);
        (void)close(pipefd[1]);
        n = read(pipefd[0], err, sizeof err - 1);
        (void)close(pipefd[0]);
        ASSERT(n > 0);
        err[n] = '\0';
        ASSERT(status == 1);
        ASSERT(strstr(err, "vendor/include: source /no/such/vendor-src/"
                           "vendor/include is missing -- ") != NULL);
        ASSERT(zcl_copy_vendor_include(NULL, dest, STDERR_FILENO) == 2);
        PASS();
    } _test_next:;
    return failures;
}

int test_copy_vendor_include(void);
int test_copy_vendor_include(void)
{
    char root[512];
    int failures;
    test_make_tmpdir(root, sizeof root, "copy_vendor_include", "root");
    failures = test_copy_vendor_include_cases(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_copy_vendor_include: all passed\n");
    else
        printf("test_copy_vendor_include: %d FAILED\n", failures);
    return failures;
}
