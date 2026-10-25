/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exercise the production shadow-directory reader with a refused
 * name duplication, without depending on directory order or memory pressure.
 */
#ifndef ZCL_SEMANTIC_WARM_DIRECTORY_CASES_H
#define ZCL_SEMANTIC_WARM_DIRECTORY_CASES_H

#include "../../../tools/sensors/clang_manifest_core.h"

/* The reader's storage is fixed for this case. Its dependency replacements
 * cannot allocate or grow; only the second name duplication is refused. */
static char smwd_names[2][256];
static unsigned smwd_duplicates;
static bool smwd_sort_null;

static bool smwd_grow(void **items, size_t *cap, size_t n, size_t elem)
{
    (void)items;
    (void)elem;
    return n < *cap;
}

static char *smwd_strdup(const char *name)
{
    size_t len = strlen(name);
    unsigned slot = smwd_duplicates++;
    if (slot >= 2 || len >= sizeof(smwd_names[0])) {
        fprintf(stderr, "shadow-directory fixture: name storage refused\n");
        return NULL;
    }
    if (slot == 1) {
        fprintf(stderr, "shadow-directory fixture: second duplication refused\n");
        return NULL;
    }
    memcpy(smwd_names[slot], name, len + 1);
    return smwd_names[slot];
}

/* File hashing is outside this directory-reader case; refuse if reached. */
static bool smwd_stream_sha3(FILE *fp, uint8_t out[32])
{
    (void)out;
    if (fp != NULL)
        (void)fclose(fp);
    fprintf(stderr, "shadow-directory fixture: unexpected file hashing\n");
    return false;
}

static bool smwd_resource_root(char out[PATH_MAX], size_t *len)
{
    out[0] = '\0';
    *len = 0;
    fprintf(stderr, "shadow-directory fixture: unexpected resource lookup\n");
    return false;
}

/* Observe the actual sorting call without letting the defective version
 * crash in strcmp(NULL, ...). A NULL entry becomes an assertion failure. */
static void smwd_qsort(void *base, size_t count, size_t size,
                       int (*compare)(const void *, const void *))
{
    char **names = base;
    for (size_t i = 0; i < count; i++) {
        if (names[i] == NULL) {
            smwd_sort_null = true;
            return;
        }
    }
    qsort(base, count, size, compare);
}

#define cm_grow smwd_grow
#define cm_strdup smwd_strdup
#define cm_stream_sha3 smwd_stream_sha3
#define cm_host_resource_root smwd_resource_root
#define qsort smwd_qsort
#include "../../../tools/sensors/clang_manifest_warm.c"
#undef qsort
#undef cm_host_resource_root
#undef cm_stream_sha3
#undef cm_strdup
#undef cm_grow

static bool smwd_touch(const char *root, const char *name)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, name);
    FILE *fp;
    if (n < 0 || (size_t)n >= sizeof(path)) {
        fprintf(stderr, "shadow-directory fixture: path too long\n");
        return false;
    }
    fp = fopen(path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "shadow-directory fixture: cannot create %s\n", path);
        return false;
    }
    if (fclose(fp) != 0) {
        fprintf(stderr, "shadow-directory fixture: cannot close %s\n", path);
        return false;
    }
    return true;
}

static int smwd_directory_case(void)
{
    int failures = 0;
    char root[1024] = {0};
    char *names[2] = {NULL, NULL};
    struct cm_sdir dir = {.dir = ".", .len = 1, .names = names, .cap = 2};
    struct cm_host_paths paths = {.root = root};
    struct cm_shadow shadow = {.paths = &paths};
    smwd_duplicates = 0;
    smwd_sort_null = false;
    TEST_CASE("semantic_manifest: refused directory name is excluded from sorting") {
        ASSERT(test_mkdtemp(root, sizeof(root), "semantic_warm_names") != NULL);
        ASSERT(smwd_touch(root, "a.h"));
        ASSERT(smwd_touch(root, "b.h"));
        ASSERT(!cm_sdir_read(&shadow, &dir));
        ASSERT(smwd_duplicates == 2);
        ASSERT(!smwd_sort_null);
        ASSERT(dir.nnames == 1);
        ASSERT(dir.cap == 2);
        ASSERT(dir.names == names);
        ASSERT(dir.names[0] != NULL);
        ASSERT(dir.names[1] == NULL);
    } TEST_END
    if (root[0] != '\0' && test_rm_rf_recursive(root) != 0) {
        fprintf(stderr, "shadow-directory fixture: cleanup failed\n");
        failures++;
    }
    return failures;
}

#endif
