/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_tor_stamp, zcl_tor_require_full, and
 * zcl_tor_write_stamp_sidecar against fixture executables. */

#include "test/test_core.h"

#include "tor_stamp.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_refusal[] =
    "refusing to package a tor=stub binary: it cannot reach the onion "
    "network; rebuild with make tor-full";

static int tn_fit(int n, size_t cap)
{
    return n > 0 && (size_t)n < cap;
}

static int tn_write(const char *path, const char *text, mode_t mode)
{
    FILE *fp = fopen(path, "w");
    size_t n;
    size_t wrote;
    if (fp == NULL)
        return -1;
    n = strlen(text);
    wrote = fwrite(text, 1, n, fp);
    if (fclose(fp) != 0 || wrote != n)
        return -1;
    if (chmod(path, mode) != 0)
        return -1;
    return 0;
}

static int tn_capture(const char *node, const char *context, const char *log,
                      char *got, size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved = dup(STDERR_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved < 0)
        goto fail;
    fflush(stderr);
    if (dup2(fd, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_tor_require_full(node, context);
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    close(fd);
    file = fopen(log, "r");
    if (file == NULL)
        return -1;
    used = fread(got, 1, cap - 1, file);
    got[used] = '\0';
    fclose(file);
    return 0;
fail:
    if (saved >= 0) {
        dup2(saved, STDERR_FILENO);
        close(saved);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int tn_hash(const char *path, char *hex, size_t cap)
{
    char cmd[1200];
    FILE *fp;
    size_t i = 0;
    int n = snprintf(cmd, sizeof cmd, "sha256sum < \"%s\"", path);
    if (!tn_fit(n, sizeof cmd))
        return -1;
    fp = popen(cmd, "r");
    if (fp == NULL)
        return -1;
    while (i + 1 < cap) {
        int c = fgetc(fp);
        if (c == EOF || c == ' ' || c == '\n')
            break;
        hex[i++] = (char)c;
    }
    hex[i] = '\0';
    pclose(fp);
    return i == 64 ? 0 : -1;
}

static int test_tor_stamp_cases(const char *dir)
{
    int failures = 0;
    TEST("tor stamp: full passes, stub and a missing stamp refuse") {
        char full[1024], stub[1024], noise[1024], plain[1024];
        char side[1100], log[1024], got[2048], want[2048];
        char stamp[8], hex[80], body[256];
        FILE *fp;
        int rc = 0;
        int n;
        n = snprintf(full, sizeof full, "%s/full.sh", dir);
        ASSERT(tn_fit(n, sizeof full));
        n = snprintf(stub, sizeof stub, "%s/stub.sh", dir);
        ASSERT(tn_fit(n, sizeof stub));
        n = snprintf(noise, sizeof noise, "%s/noise.sh", dir);
        ASSERT(tn_fit(n, sizeof noise));
        n = snprintf(plain, sizeof plain, "%s/plain", dir);
        ASSERT(tn_fit(n, sizeof plain));
        n = snprintf(log, sizeof log, "%s/capture.log", dir);
        ASSERT(tn_fit(n, sizeof log));
        ASSERT(tn_write(full, "#!/bin/sh\nprintf 'tor: full\\n'\n", 0755) == 0);
        ASSERT(tn_write(stub, "#!/bin/sh\nprintf 'noise\\ntor: stub\\n'\n",
                        0755) == 0);
        ASSERT(tn_write(noise, "#!/bin/sh\nprintf 'tor: maybe\\n'\n", 0755) == 0);
        ASSERT(tn_write(plain, "not a node\n", 0644) == 0);
        unsetenv("ZCL_TOR_STUB_REFUSAL");

        ASSERT(zcl_tor_stamp(full, stamp, sizeof stamp) == 0);
        ASSERT_STR_EQ(stamp, "full");
        ASSERT(tn_capture(full, "the install node", log, got, sizeof got,
                          &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, "");

        ASSERT(zcl_tor_stamp(stub, stamp, sizeof stamp) == 0);
        ASSERT_STR_EQ(stamp, "stub");
        ASSERT(tn_capture(stub, "the ship candidate", log, got, sizeof got,
                          &rc) == 0);
        ASSERT(rc == 1);
        n = snprintf(want, sizeof want, "%s (the ship candidate reports tor: stub)\n",
                     k_refusal);
        ASSERT(tn_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);

        ASSERT(tn_capture(noise, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        n = snprintf(want, sizeof want,
                     "%s (%s printed no tor: stamp, so nothing proves it "
                     "links real Tor)\n",
                     k_refusal, noise);
        ASSERT(tn_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);

        ASSERT(tn_capture(plain, "plain file", log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "plain file printed no tor: stamp") != NULL);

        ASSERT(zcl_tor_write_stamp_sidecar(full) == 0);
        n = snprintf(side, sizeof side, "%s.tor-stamp", full);
        ASSERT(tn_fit(n, sizeof side));
        ASSERT(tn_hash(full, hex, sizeof hex) == 0);
        fp = fopen(side, "r");
        ASSERT(fp != NULL);
        ASSERT(fgets(body, (int)sizeof body, fp) != NULL);
        ASSERT_STR_EQ(body, "tor: full\n");
        ASSERT(fgets(body, (int)sizeof body, fp) != NULL);
        fclose(fp);
        n = snprintf(want, sizeof want, "binary_sha256: %s\n", hex);
        ASSERT(tn_fit(n, sizeof want));
        ASSERT_STR_EQ(body, want);

        ASSERT(zcl_tor_write_stamp_sidecar(noise) != 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_tor_node_stamp(void);
int test_tor_node_stamp(void)
{
    char dir[1024];
    char old[1024];
    const char *prev = getenv("ZCL_TOR_STUB_REFUSAL");
    int had = 0;
    int failures;
    if (prev != NULL) {
        int n = snprintf(old, sizeof old, "%s", prev);
        had = tn_fit(n, sizeof old) ? 1 : -1;
    }
    test_make_tmpdir(dir, sizeof dir, "tor_node_stamp", "root");
    if (had < 0) {
        printf("test_tor_node_stamp: env does not fit\n");
        failures = 1;
    } else {
        failures = test_tor_stamp_cases(dir);
    }
    if (had == 0)
        unsetenv("ZCL_TOR_STUB_REFUSAL");
    else if (had > 0)
        setenv("ZCL_TOR_STUB_REFUSAL", old, 1);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_tor_node_stamp: all passed\n");
    else
        printf("test_tor_node_stamp: %d FAILED\n", failures);
    return failures;
}
