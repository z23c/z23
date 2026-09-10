/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Evaluate declared test-group host needs against an exact tree. */

#include "test_group_host_need.h"
#include "test_group_catalog.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const struct zcl_test_group_host_need g_host_needs[] = {
#define ZCL_TEST_GROUP_NEED(full_id_, kind_, value_) {kind_, full_id_, value_},
#include "test_group_host_needs.def"
#undef ZCL_TEST_GROUP_NEED
};

#define ZCL_HOST_NEED_COUNT \
    (sizeof(g_host_needs) / sizeof(g_host_needs[0]))

const char *
zcl_test_group_host_need_kind_name(enum zcl_test_group_host_need_kind kind)
{
    switch (kind) {
    case ZCL_HOST_NEED_NONE:
        return "none";
    case ZCL_HOST_NEED_FILE:
        return "file";
    case ZCL_HOST_NEED_ENV:
        return "env";
    default:
        return NULL;
    }
}

/* One row's own shape: a known non-NONE kind and a non-empty value naming a
 * registered group. A row that fails this is a table error, not a host fact. */
static bool host_need_row_valid(size_t i)
{
    const struct zcl_test_group_host_need *row = &g_host_needs[i];
    if (!row->group || !row->group[0] || !row->value || !row->value[0] ||
        row->kind == ZCL_HOST_NEED_NONE ||
        !zcl_test_group_host_need_kind_name(row->kind)) {
        fprintf(stderr,
                "test_group_host_need: row %zu declares an unknown kind or an "
                "empty field\n", i);
        return false;
    }
    if (!zcl_test_group_catalog_contains(row->group)) {
        fprintf(stderr,
                "test_group_host_need: row %zu names unregistered group '%s'\n",
                i, row->group);
        return false;
    }
    return true;
}

bool zcl_test_group_host_needs_valid(void)
{
    for (size_t i = 0; i < ZCL_HOST_NEED_COUNT; i++) {
        if (!host_need_row_valid(i))
            return false;
        for (size_t j = 0; j < i; j++) {
            if (strcmp(g_host_needs[i].group, g_host_needs[j].group) != 0)
                continue;
            fprintf(stderr,
                    "test_group_host_need: group '%s' declares two needs\n",
                    g_host_needs[i].group);
            return false;
        }
    }
    return true;
}

bool zcl_test_group_host_need(const char *group,
                              struct zcl_test_group_host_need *out)
{
    if (!out)
        return false;
    out->kind = ZCL_HOST_NEED_NONE;
    out->group = NULL;
    out->value = NULL;
    if (!group || !group[0] || !zcl_test_group_catalog_contains(group)) {
        fprintf(stderr,
                "test_group_host_need: '%s' is not a registered test group\n",
                group ? group : "(null)");
        return false;
    }
    if (!zcl_test_group_host_needs_valid())
        return false;
    for (size_t i = 0; i < ZCL_HOST_NEED_COUNT; i++) {
        if (strcmp(g_host_needs[i].group, group) != 0)
            continue;
        *out = g_host_needs[i];
        return true;
    }
    return true;
}

/* Does `<root>/<value>` exist? Only existence is asked: a proof generation
 * either carries the artifact or it does not, and a deeper probe would make
 * selection depend on the artifact's content. */
static bool host_need_file_present(const char *root, const char *value)
{
    char path[PATH_MAX];
    struct stat st;
    int n = snprintf(path, sizeof(path), "%s/%s", root, value);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        fprintf(stderr,
                "test_group_host_need: file need path too long under '%s'\n",
                root);
        return false;
    }
    return stat(path, &st) == 0;
}

bool zcl_test_group_host_need_met(const char *root,
                                  const struct zcl_test_group_host_need *need)
{
    if (!need)
        return false;
    if (need->kind != ZCL_HOST_NEED_NONE && (!need->value || !need->value[0]))
        return false;
    switch (need->kind) {
    case ZCL_HOST_NEED_NONE:
        return true;
    case ZCL_HOST_NEED_FILE: {
        if (!root || !root[0])
            return false;
        return host_need_file_present(root, need->value);
    }
    case ZCL_HOST_NEED_ENV: {
        const char *set = getenv(need->value);
        return set != NULL && set[0] != '\0';
    }
    default:
        fprintf(stderr,
                "test_group_host_need: unknown need kind %d for '%s'\n",
                (int)need->kind, need->group ? need->group : "(null)");
        return false;
    }
}
