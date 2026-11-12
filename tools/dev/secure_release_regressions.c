/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact comparison of the secure-release regression group list. */

#define _POSIX_C_SOURCE 200809L

#include "secure_release_regressions.h"

#include "dev_script_dir.h"

#include <stdio.h>
#include <string.h>

static const char k_srr_cases[] =
    "stale_wal_ownership,lease_takeover,mempool_generation,"
    "provider_reconnect,utxo_mirror_storm,diagnostic_teardown,rollback";

static int srr_fail(const char *text)
{
    fprintf(stderr, "secure-release-regressions-selftest: FAIL: %s\n", text);
    return 1;
}

static int srr_fail2(const char *prefix, const char *make_groups,
                     const char *manifest)
{
    fprintf(stderr,
            "secure-release-regressions-selftest: FAIL: %s make=%s manifest=%s\n",
            prefix, make_groups, manifest);
    return 1;
}

static int srr_key(const char *start, const char *eq, char *key, size_t key_cap)
{
    size_t kn = (size_t)(eq - start);
    for (const char *c = start; c < eq; c++)
        if (!((*c >= 'a' && *c <= 'z') || *c == '_'))
            return 0;
    if (kn == 0 || kn + 1 > key_cap)
        return 0;
    memcpy(key, start, kn);
    key[kn] = '\0';
    return 1;
}

static int srr_value(const char *start, char *value, size_t value_cap)
{
    const char *tail;
    size_t vn = 0;
    if (strncmp(start, "test_", 5) != 0)
        return 0;
    while (start[vn] &&
           !(start[vn] == '\\' && start[vn + 1] == 'n' && start[vn + 2] == '"'))
        vn++;
    if (start[vn] != '\\' || vn + 1 > value_cap)
        return 0;
    memcpy(value, start, vn);
    value[vn] = '\0';
    tail = start + vn + 3;
    while (*tail == ',' || *tail == ';')
        tail++;
    return *tail == '\0' || *tail == '\n' || *tail == '\r';
}

/* A manifest source row: four spaces, a quote, key=test_...\\n", optional
 * comma or semicolon. Returns 1 and fills key and value, 0 otherwise. */
static int srr_row(const char *line, char *key, size_t key_cap, char *value,
                   size_t value_cap)
{
    const char *eq;
    if (strncmp(line, "    \"", 5) != 0)
        return 0;
    eq = strchr(line + 5, '=');
    if (!eq || !srr_key(line + 5, eq, key, key_cap))
        return 0;
    return srr_value(eq + 1, value, value_cap);
}

static int srr_append(char *dest, size_t cap, int *any, const char *text)
{
    size_t used = strlen(dest);
    size_t add = strlen(text);
    if (*any) {
        if (used + 1 >= cap)
            return -1;
        dest[used++] = ',';
        dest[used] = '\0';
    }
    if (used + add >= cap)
        return -1;
    memcpy(dest + used, text, add + 1);
    *any = 1;
    return 0;
}

static int srr_manifest(const char *path, char *groups, size_t groups_cap,
                        char *cases, size_t cases_cap)
{
    FILE *file = fopen(path, "r");
    char line[2048];
    int any_group = 0;
    int any_case = 0;
    if (!file)
        return -1;
    groups[0] = '\0';
    cases[0] = '\0';
    while (fgets(line, sizeof line, file)) {
        char key[64];
        char value[1024];
        if (srr_row(line, key, sizeof key, value, sizeof value) != 1)
            continue;
        if (strcmp(key, "runner") == 0)
            continue;
        if (srr_append(groups, groups_cap, &any_group, value) != 0 ||
            srr_append(cases, cases_cap, &any_case, key) != 0) {
            fclose(file);
            return -1;
        }
    }
    fclose(file);
    return 0;
}

static int srr_group_id(const char *group)
{
    const char *p;
    if (strncmp(group, "test_", 5) != 0 || group[5] == '\0')
        return 0;
    for (p = group + 5; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '_'))
            return 0;
    return 1;
}

static int srr_catalog_has(const char *path, const char *symbol)
{
    FILE *file = fopen(path, "r");
    char line[512];
    char want[192];
    if (!file)
        return 0;
    if (snprintf(want, sizeof want, "ZCL_TEST_GROUP(%s)", symbol) >=
        (int)sizeof want) {
        fclose(file);
        return 0;
    }
    while (fgets(line, sizeof line, file)) {
        zcl_dev_chomp(line);
        if (strcmp(line, want) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

static int srr_groups(const char *groups, const char *catalog, int *count)
{
    char copy[8192];
    char *cursor;
    char *save = NULL;
    char *group;
    char seen[64][128];
    int n = 0;
    int i;
    if (strlen(groups) >= sizeof copy)
        return srr_fail("canonical manifest group set is empty");
    memcpy(copy, groups, strlen(groups) + 1);
    cursor = copy;
    while ((group = strtok_r(cursor, ",", &save)) != NULL) {
        char symbol[128];
        cursor = NULL;
        if (!srr_group_id(group)) {
            fprintf(stderr,
                    "secure-release-regressions-selftest: FAIL: noncanonical group id: %s\n",
                    group);
            return 1;
        }
        for (i = 0; i < n; i++)
            if (strcmp(seen[i], group) == 0) {
                fprintf(stderr,
                        "secure-release-regressions-selftest: FAIL: duplicate group id: %s\n",
                        group);
                return 1;
            }
        if (n == 64 || strlen(group) >= sizeof seen[0])
            return srr_fail("canonical manifest group set is empty");
        memcpy(seen[n], group, strlen(group) + 1);
        n++;
        if (snprintf(symbol, sizeof symbol, "%s", group + 5) >= (int)sizeof symbol)
            return srr_fail("canonical manifest group set is empty");
        if (!srr_catalog_has(catalog, symbol)) {
            fprintf(stderr,
                    "secure-release-regressions-selftest: FAIL: group is absent from the exact test catalog: %s\n",
                    group);
            return 1;
        }
    }
    *count = n;
    return 0;
}

int zcl_secure_release_regressions_check(const char *make_groups,
                                        const char *manifest_path,
                                        const char *catalog_path)
{
    char groups[8192];
    char cases[1024];
    int count = 0;
    if (!make_groups || !make_groups[0])
        return srr_fail("expected the Makefile exact group set");
    if (!manifest_path || !catalog_path ||
        srr_manifest(manifest_path, groups, sizeof groups, cases, sizeof cases) !=
            0 ||
        !groups[0])
        return srr_fail("canonical manifest group set is empty");
    if (strcmp(groups, make_groups) != 0)
        return srr_fail2("Makefile/manifest drift:", make_groups, groups);
    if (strcmp(cases, k_srr_cases) != 0) {
        fprintf(stderr,
                "secure-release-regressions-selftest: FAIL: historical case drift: expected=%s actual=%s\n",
                k_srr_cases, cases);
        return 1;
    }
    if (srr_groups(groups, catalog_path, &count) != 0)
        return 1;
    printf("secure-release-regressions-selftest: PASS cases=7 groups=%d exact=true\n",
           count);
    return 0;
}
