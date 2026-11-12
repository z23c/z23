/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_binary_size against fixture files of known length. */

#include "test/test_core.h"

#include "binary_size.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int bs_fit(int n, int cap)
{
    return n > 0 && n < cap;
}

static int bs_sized(const char *path, off_t size)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    int closed;
    if (fd < 0)
        return -1;
    if (ftruncate(fd, size) != 0) {
        close(fd);
        return -1;
    }
    closed = close(fd);
    return closed == 0 ? 0 : -1;
}

static int bs_capture(int argc, char **argv, const char *fallback,
                      const char *log, char *got, size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_binary_size(argc, argv, fallback);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd);
    file = fopen(log, "r");
    if (!file)
        return -1;
    used = fread(got, 1, cap - 1, file);
    got[used] = '\0';
    fclose(file);
    return 0;
fail:
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int test_binary_size_cases(const char *dir)
{
    int failures = 0;
    TEST("binary size: bytes, human line, and missing file") {
        char big[1024], small[1024], log[1024], got[2048], want[2048];
        char *argv_human[] = {"binary-size", NULL};
        char *argv_bytes[] = {"binary-size", "--bytes", big, NULL};
        char *argv_order[] = {"binary-size", small, "--bytes", NULL};
        char *argv_last[] = {"binary-size", small, big, NULL};
        char *argv_flag[] = {"binary-size", "-nope", NULL};
        char *argv_dir[] = {"binary-size", (char *)dir, NULL};
        int rc = 0;
        int n;
        n = snprintf(big, sizeof big, "%s/big.bin", dir);
        ASSERT(bs_fit(n, (int)sizeof big));
        n = snprintf(small, sizeof small, "%s/small.bin", dir);
        ASSERT(bs_fit(n, (int)sizeof small));
        n = snprintf(log, sizeof log, "%s/capture.out", dir);
        ASSERT(bs_fit(n, (int)sizeof log));
        ASSERT(bs_sized(big, 1572864) == 0);
        ASSERT(bs_sized(small, 524288) == 0);

        ASSERT(bs_capture(1, argv_human, big, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        n = snprintf(want, sizeof want,
                     "1572864 bytes (~1.5 MB)  %s\n", big);
        ASSERT(bs_fit(n, (int)sizeof want));
        ASSERT_STR_EQ(got, want);

        ASSERT(bs_capture(3, argv_bytes, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, "1572864\n");

        ASSERT(bs_capture(3, argv_order, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, "524288\n");

        ASSERT(bs_capture(3, argv_last, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        n = snprintf(want, sizeof want,
                     "1572864 bytes (~1.5 MB)  %s\n", big);
        ASSERT(bs_fit(n, (int)sizeof want));
        ASSERT_STR_EQ(got, want);

        ASSERT(bs_capture(2, argv_flag, big, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT_STR_EQ(got, "binary_size.sh: unknown flag '-nope'\n");

        ASSERT(bs_capture(2, argv_dir, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        n = snprintf(want, sizeof want,
                     "binary_size.sh: '%s' not built yet — run "
                     "'make -j$(nproc)' (or 'make build-only').\n",
                     dir);
        ASSERT(bs_fit(n, (int)sizeof want));
        ASSERT_STR_EQ(got, want);

        ASSERT(bs_capture(1, argv_human, "/no/such/binary-size-fixture", log,
                          got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "binary_size.sh: '/no/such/binary-size-fixture' "
                           "not built yet") == got);

        PASS();
    } _test_next:;
    return failures;
}

int test_binary_size(void);
int test_binary_size(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "binary_size", "root");
    failures = test_binary_size_cases(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_binary_size: all passed\n");
    else
        printf("test_binary_size: %d FAILED\n", failures);
    return failures;
}
