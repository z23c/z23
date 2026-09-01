/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded file loading, cross-App collision checks, and the explicit catalog
 * of statically linked Apps. Parsing remains in app_definition.c. */

#include "framework/app_definition.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

enum app_catalog_error {
    APP_CATALOG_INVALID_ARGUMENT = -3300,
    APP_CATALOG_IO = -3301,
    APP_CATALOG_LIMIT = -3303,
    APP_CATALOG_COLLISION = -3305,
};

static const char *const g_builtin_app_ids[] = {
    "blog",
    "social",
    "yardsale",
};

size_t zcl_app_definition_builtin_count_v1(void)
{
    return sizeof(g_builtin_app_ids) / sizeof(g_builtin_app_ids[0]);
}

const char *zcl_app_definition_builtin_id_v1(size_t index)
{
    return index < zcl_app_definition_builtin_count_v1()
        ? g_builtin_app_ids[index] : NULL;
}

bool zcl_app_definition_builtin_v1(const char *app_id)
{
    if (!zcl_app_definition_id_valid_v1(app_id))
        return false;
    for (size_t i = 0; i < zcl_app_definition_builtin_count_v1(); i++) {
        if (strcmp(g_builtin_app_ids[i], app_id) == 0)
            return true;
    }
    return false;
}

struct zcl_result zcl_app_definition_load_v1(
    const char *repo_root,
    const char *expected_app_id,
    struct zcl_app_definition_v1 *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    const char *root_end = repo_root ? memchr(repo_root, '\0', PATH_MAX) : NULL;
    if (!out || !root_end || root_end == repo_root ||
        !zcl_app_definition_id_valid_v1(expected_app_id))
        return ZCL_ERR(APP_CATALOG_INVALID_ARGUMENT,
                       "invalid app definition file argument or path id");
    char path[PATH_MAX];
    int path_len = snprintf(path, sizeof(path),
                            "%s/contexts/commons/apps/%s/app.def",
                            repo_root, expected_app_id);
    if (path_len <= 0 || (size_t)path_len >= sizeof(path))
        return ZCL_ERR(APP_CATALOG_LIMIT,
                       "app definition path is too long");
    FILE *file = fopen(path, "rb");
    if (!file)
        return ZCL_ERR(APP_CATALOG_IO,
                       "cannot open app definition '%s'", path);
    char source[ZCL_APP_DEFINITION_SOURCE_MAX + 1];
    size_t source_len = fread(source, 1, sizeof(source), file);
    bool read_failed = ferror(file) != 0;
    bool close_failed = fclose(file) != 0;
    if (read_failed || close_failed) {
        memset(out, 0, sizeof(*out));
        return ZCL_ERR(APP_CATALOG_IO,
                       "cannot read app definition '%s'", path);
    }
    if (source_len > ZCL_APP_DEFINITION_SOURCE_MAX) {
        memset(out, 0, sizeof(*out));
        return ZCL_ERR(APP_CATALOG_LIMIT,
                       "app definition '%s' is too large", path);
    }
    struct zcl_result result = zcl_app_definition_parse_v1(
        expected_app_id, source, source_len, out);
    if (!result.ok)
        memset(out, 0, sizeof(*out));
    return result;
}

static struct zcl_result catalog_check_collisions(
    const struct zcl_app_definition_catalog_v1 *catalog,
    size_t candidate_index)
{
    const struct zcl_app_definition_v1 *candidate =
        &catalog->apps[candidate_index];
    for (size_t i = 0; i < candidate_index; i++) {
        const struct zcl_app_definition_v1 *prior = &catalog->apps[i];
        if (strcmp(candidate->app_id, prior->app_id) == 0)
            return ZCL_ERR(APP_CATALOG_COLLISION,
                           "duplicate catalog app id '%s'", candidate->app_id);
        for (size_t mount = 0; mount < candidate->mount_count; mount++) {
            for (size_t other = 0; other < prior->mount_count; other++) {
                if (strcmp(candidate->mounts[mount].path,
                           prior->mounts[other].path) == 0)
                    return ZCL_ERR(APP_CATALOG_COLLISION,
                                   "catalog web mount collision '%s'",
                                   candidate->mounts[mount].path);
            }
        }
        for (size_t topic = 0; topic < candidate->topic_count; topic++) {
            for (size_t other = 0; other < prior->topic_count; other++) {
                if (strcmp(candidate->topics[topic].name,
                           prior->topics[other].name) == 0)
                    return ZCL_ERR(APP_CATALOG_COLLISION,
                                   "catalog topic collision '%s'",
                                   candidate->topics[topic].name);
            }
        }
    }
    return ZCL_OK;
}

struct zcl_result zcl_app_definition_catalog_compile_v1(
    const char *repo_root,
    const char *const *app_ids,
    size_t app_id_count,
    struct zcl_app_definition_catalog_v1 *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!out || !repo_root || !app_ids || app_id_count == 0 ||
        app_id_count > ZCL_APP_DEFINITION_CATALOG_MAX)
        return ZCL_ERR(APP_CATALOG_INVALID_ARGUMENT,
                       "invalid app definition catalog arguments");
    struct zcl_app_definition_catalog_v1 catalog;
    memset(&catalog, 0, sizeof(catalog));
    catalog.struct_size = sizeof(catalog);
    catalog.catalog_version = ZCL_APP_DEFINITION_V1;
    for (size_t i = 0; i < app_id_count; i++) {
        if (!zcl_app_definition_id_valid_v1(app_ids[i]))
            return ZCL_ERR(APP_CATALOG_INVALID_ARGUMENT,
                           "catalog path id at index %zu is invalid", i);
        struct zcl_result result = zcl_app_definition_load_v1(
            repo_root, app_ids[i], &catalog.apps[i]);
        if (!result.ok)
            return ZCL_ERR(result.code, "app '%s': %s",
                           app_ids[i], result.message);
        catalog.app_count = i + 1;
        result = catalog_check_collisions(&catalog, i);
        if (!result.ok)
            return result;
    }
    *out = catalog;
    return ZCL_OK;
}

struct zcl_result zcl_app_definition_builtin_catalog_compile_v1(
    const char *repo_root,
    struct zcl_app_definition_catalog_v1 *out)
{
    return zcl_app_definition_catalog_compile_v1(
        repo_root, g_builtin_app_ids,
        zcl_app_definition_builtin_count_v1(), out);
}
