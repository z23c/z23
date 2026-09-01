/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Strict, bounded compiler for built-in apps/<id>/app.def declarations.
 * Definitions are data only: parsing them grants no runtime authority. */

#ifndef ZCL_FRAMEWORK_APP_DEFINITION_H
#define ZCL_FRAMEWORK_APP_DEFINITION_H

#include "util/result.h"
#include "zclassic23/app.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_APP_DEFINITION_V1 1u
#define ZCL_APP_DEFINITION_SOURCE_MAX 32768u
#define ZCL_APP_DEFINITION_DIRECTIVE_MAX 128u
#define ZCL_APP_DEFINITION_RESOURCE_MAX 16u
#define ZCL_APP_DEFINITION_TOPIC_MAX 8u
#define ZCL_APP_DEFINITION_MOUNT_MAX 4u
#define ZCL_APP_DEFINITION_SIM_MAX 16u
#define ZCL_APP_DEFINITION_CATALOG_MAX 16u
#define ZCL_APP_DEFINITION_DISPLAY_MAX 95u
#define ZCL_APP_DEFINITION_VERSION_MAX 31u
#define ZCL_APP_DEFINITION_RESOURCE_NAME_MAX 63u
#define ZCL_APP_DEFINITION_SIM_NAME_MAX 95u
#define ZCL_APP_DEFINITION_ZNAM_MAX 63u
#define ZCL_APP_DEFINITION_EVENT_BYTES_MAX 65536u

struct zcl_app_definition_resource_v1 {
    char name[ZCL_APP_DEFINITION_RESOURCE_NAME_MAX + 1];
};

struct zcl_app_definition_topic_v1 {
    char name[ZCL_APP_TOPIC_MAX + 1];
    uint32_t wire_version;
    uint32_t max_event_bytes;
};

struct zcl_app_definition_mount_v1 {
    char path[ZCL_APP_ROUTE_MAX + 1];
};

struct zcl_app_definition_sim_v1 {
    char name[ZCL_APP_DEFINITION_SIM_NAME_MAX + 1];
};

/* Pointer-free so the parsed value is self-contained and safe to copy into a
 * generated catalog. Presence flags distinguish an omitted singleton from a
 * deliberately false/zero value. */
struct zcl_app_definition_v1 {
    uint32_t struct_size;
    uint32_t definition_version;
    char app_id[ZCL_APP_ID_MAX + 1];
    char display_name[ZCL_APP_DEFINITION_DISPLAY_MAX + 1];
    char app_version[ZCL_APP_DEFINITION_VERSION_MAX + 1];
    uint64_t required_capabilities;

    struct zcl_app_definition_resource_v1
        resources[ZCL_APP_DEFINITION_RESOURCE_MAX];
    size_t resource_count;
    struct zcl_app_definition_topic_v1 topics[ZCL_APP_DEFINITION_TOPIC_MAX];
    size_t topic_count;
    struct zcl_app_definition_mount_v1 mounts[ZCL_APP_DEFINITION_MOUNT_MAX];
    size_t mount_count;
    struct zcl_app_definition_sim_v1 simulations[ZCL_APP_DEFINITION_SIM_MAX];
    size_t simulation_count;

    bool onion_declared;
    bool onion_enabled;
    bool znam_declared;
    char znam[ZCL_APP_DEFINITION_ZNAM_MAX + 1];
    bool state_schema_declared;
    uint32_t state_schema_version;
};

struct zcl_app_definition_catalog_v1 {
    uint32_t struct_size;
    uint32_t catalog_version;
    struct zcl_app_definition_v1
        apps[ZCL_APP_DEFINITION_CATALOG_MAX];
    size_t app_count;
};

/* Canonical identifier predicate shared by parser, checkout tools, and the
 * immutable built-in catalog. The input scan is bounded to ZCL_APP_ID_MAX. */
bool zcl_app_definition_id_valid_v1(const char *app_id);

/* Compile one exact byte span. Embedded NUL bytes, unknown syntax, and any
 * bytes after the last complete directive are rejected. `out` is zeroed on
 * every failure. */
struct zcl_result zcl_app_definition_parse_v1(
    const char *expected_app_id,
    const char *source,
    size_t source_len,
    struct zcl_app_definition_v1 *out);

/* Read and compile <repo_root>/apps/<expected_app_id>/app.def. The file and
 * all parser products are bounded by the constants above. */
struct zcl_result zcl_app_definition_load_v1(
    const char *repo_root,
    const char *expected_app_id,
    struct zcl_app_definition_v1 *out);

/* Compile an explicit, deterministic built-in app list. Cross-app app IDs,
 * web mounts, and P2P topics must be unique. No directory enumeration or
 * runtime registration occurs. `out` is zeroed on every failure. */
struct zcl_result zcl_app_definition_catalog_compile_v1(
    const char *repo_root,
    const char *const *app_ids,
    size_t app_id_count,
    struct zcl_app_definition_catalog_v1 *out);

/* One explicit list is the source of truth for statically linked Apps. These
 * accessors do not touch the filesystem or grant runtime authority. */
size_t zcl_app_definition_builtin_count_v1(void);
const char *zcl_app_definition_builtin_id_v1(size_t index);
bool zcl_app_definition_builtin_v1(const char *app_id);
struct zcl_result zcl_app_definition_builtin_catalog_compile_v1(
    const char *repo_root,
    struct zcl_app_definition_catalog_v1 *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_FRAMEWORK_APP_DEFINITION_H */
