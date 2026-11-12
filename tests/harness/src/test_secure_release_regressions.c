/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_secure_release_regressions_check against a fixture manifest
 * and against the checkout's canonical manifest. */

#include "test/test_core.h"

#include "secure_release_regressions.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char k_srr_manifest[] =
    "    \"runner=test_parallel:all-groups:uncached\\n\"\n"
    "    \"stale_wal_ownership=test_alpha\\n\"\n"
    "    \"lease_takeover=test_beta\\n\"\n"
    "    \"mempool_generation=test_gamma\\n\"\n"
    "    \"provider_reconnect=test_delta\\n\"\n"
    "    \"utxo_mirror_storm=test_epsilon\\n\"\n"
    "    \"diagnostic_teardown=test_zeta\\n\"\n"
    "    \"rollback=test_eta\\n\"\n";

static const char k_srr_catalog[] =
    "ZCL_TEST_GROUP(alpha)\n"
    "ZCL_TEST_GROUP(beta)\n"
    "ZCL_TEST_GROUP(gamma)\n"
    "ZCL_TEST_GROUP(delta)\n"
    "ZCL_TEST_GROUP(epsilon)\n"
    "ZCL_TEST_GROUP(zeta)\n"
    "ZCL_TEST_GROUP(eta)\n";

static const char k_srr_groups[] =
    "test_alpha,test_beta,test_gamma,test_delta,test_epsilon,test_zeta,test_eta";

static int srr_write(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    if (!file)
        return -1;
    if (fputs(text, file) < 0 || fclose(file) != 0)
        return -1;
    return 0;
}

static int srr_capture(const char *groups, const char *manifest,
                       const char *catalog, const char *log, char *got,
                       size_t cap, int *rc)
{
    int fd, saved_out, saved_err;
    FILE *file;
    size_t used;
    fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    saved_out = dup(STDOUT_FILENO);
    saved_err = dup(STDERR_FILENO);
    if (fd < 0 || saved_out < 0 || saved_err < 0 ||
        dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        return -1;
    *rc = zcl_secure_release_regressions_check(groups, manifest, catalog);
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
}

static int srr_make_groups(char *out, size_t cap)
{
    FILE *file = fopen("Makefile", "r");
    char line[8192];
    const char *prefix = "SECURE_RELEASE_REGRESSION_GROUPS := ";
    size_t prefix_len = strlen(prefix);
    if (!file)
        return -1;
    while (fgets(line, sizeof line, file)) {
        size_t n;
        if (strncmp(line, prefix, prefix_len) != 0)
            continue;
        n = strlen(line + prefix_len);
        while (n > 0 && (line[prefix_len + n - 1] == '\n' ||
                         line[prefix_len + n - 1] == '\r'))
            n--;
        if (n + 1 > cap) {
            fclose(file);
            return -1;
        }
        memcpy(out, line + prefix_len, n);
        out[n] = '\0';
        fclose(file);
        return 0;
    }
    fclose(file);
    return -1;
}

static int test_secure_release_regressions_cases(const char *dir)
{
    int failures = 0;
    char manifest[512];
    char catalog[512];
    char log[512];
    char got[2048];
    char real_groups[8192];
    TEST("secure release regressions: manifest, Makefile list, and catalog agree") {
        int rc = 0;
        int n = snprintf(manifest, sizeof manifest, "%s/manifest.c", dir);
        ASSERT(n > 0 && n < (int)sizeof manifest);
        n = snprintf(catalog, sizeof catalog, "%s/catalog.def", dir);
        ASSERT(n > 0 && n < (int)sizeof catalog);
        n = snprintf(log, sizeof log, "%s/capture.out", dir);
        ASSERT(n > 0 && n < (int)sizeof log);
        ASSERT(srr_write(manifest, k_srr_manifest) == 0);
        ASSERT(srr_write(catalog, k_srr_catalog) == 0);
        ASSERT(srr_capture(k_srr_groups, manifest, catalog, log, got, sizeof got,
                           &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "secure-release-regressions-selftest: PASS "
                           "cases=7 groups=7 exact=true\n") != NULL);
        ASSERT(srr_capture("test_other", manifest, catalog, log, got, sizeof got,
                           &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "Makefile/manifest drift:") != NULL);
        ASSERT(srr_capture("", manifest, catalog, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "expected the Makefile exact group set") != NULL);
        ASSERT(srr_write(catalog, "ZCL_TEST_GROUP(alpha)\n") == 0);
        ASSERT(srr_capture(k_srr_groups, manifest, catalog, log, got, sizeof got,
                           &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "group is absent from the exact test catalog: "
                           "test_beta") != NULL);
        ASSERT(srr_make_groups(real_groups, sizeof real_groups) == 0);
        ASSERT(srr_capture(real_groups,
                           "contexts/commons/modules/vcs/src/"
                           "build_release_regressions.c",
                           "tools/dev/test_group_catalog.def", log, got,
                           sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "secure-release-regressions-selftest: PASS "
                           "cases=7 groups=12 exact=true\n") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_secure_release_regressions(void);
int test_secure_release_regressions(void)
{
    char dir[512];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "secure_release_regressions", "root");
    failures = test_secure_release_regressions_cases(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_secure_release_regressions: all passed\n");
    else
        printf("test_secure_release_regressions: %d FAILED\n", failures);
    return failures;
}
