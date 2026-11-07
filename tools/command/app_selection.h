/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: App selection records and revision-checked local persistence API.
 */
#ifndef ZCL_COMMAND_APP_SELECTION_H
#define ZCL_COMMAND_APP_SELECTION_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define APP_SELECTION_ID_MAX 32u
#define APP_SELECTION_PATH_MAX 1024u
#define APP_SELECTION_ROUTES_MAX 16u
/* Reserved even when malformed: callers must never fall back to a catalog. */
bool app_selection_route_reserved(const char *name);
bool app_selection_route_valid(const char *name);
struct app_selection_routes {
    size_t count;
    char names[APP_SELECTION_ROUTES_MAX][APP_SELECTION_ID_MAX + 1u];
};
/* A local owner choice, not executable authority. Revalidate the copy grant,
 * saved ancestry, package and build record before every execution. */
struct app_selection {
    uint64_t revision;
    char app[APP_SELECTION_ID_MAX + 1];
    char copy[APP_SELECTION_PATH_MAX];
    char datadir[APP_SELECTION_PATH_MAX];
    uint8_t fork[32], parent[32], version[32], package[32];
    uint8_t env[32], dependencies[32], record[32], image[32];
};
enum app_selection_result {
    APP_SELECTION_OK, APP_SELECTION_ABSENT, APP_SELECTION_INVALID,
    APP_SELECTION_IO, APP_SELECTION_STALE
};
/* No creation or recovery. INVALID or IO must not fall back to a default. */
enum app_selection_result app_selection_load(const char *state_dir, const char *app,
                                              struct app_selection *out);
/* Read-only, bounded enumeration of valid kept records. No partial result on
 * error/overflow. This lists choices, not current executable authority. */
enum app_selection_result app_selection_routes_load(const char *state_dir,
    struct app_selection_routes *out);
/* Under an exclusive per-app lock, compare expected revision (0 means absent)
 * and atomically publish the validated pointer with revision expected + 1.
 * On IO the write's durability may be unknown; reload before retrying. */
enum app_selection_result app_selection_save(const char *state_dir,
    uint64_t expected_revision, const struct app_selection *selection,
    struct app_selection *out);
#if defined(ZCL_TESTING)
void app_selection_test_swap_hook(void (*hook)(const char *));
void app_selection_test_fail_directory_sync(bool fail);
#endif
#endif
