/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Development-only ABI between the resident reflex parent and a disposable
 * HOT_FORK child. Candidate code never enters the authoritative process. */

#ifndef ZCL_HOTSWAP_HOTFORK_CAPSULE_H
#define ZCL_HOTSWAP_HOTFORK_CAPSULE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_HOTFORK_CAPSULE_ABI_V1 1u
#define ZCL_HOTFORK_CAPSULE_SYMBOL "zcl_hotfork_capsule_v1"
#define ZCL_HOTFORK_OBSERVATION_MAGIC UINT32_C(0x48464f31)

struct zcl_hotfork_observation_v1 {
    uint32_t magic;
    uint32_t checks_run;
    uint32_t checks_passed;
    char exercised_surface[160];
    char detail[192];
};

struct zcl_hotfork_capsule_v1 {
    uint32_t abi_version;
    size_t descriptor_size;
    const char *owner_id;
    const char *source_tu;
    const char *candidate_object_root;
    const char *story_id;
    const char *story_root;
    const char *story_fixture_root;
    bool (*run_story)(struct zcl_hotfork_observation_v1 *out);
};

typedef bool (*zcl_hotfork_capsule_visit_fn)(
    const struct zcl_hotfork_capsule_v1 *capsule, void *ctx);

/* Pins and hashes the exact module inode, resolves its sole descriptor, and
 * lends that descriptor to `visit` for the lifetime of the mapping. This is
 * development-only; release builds refuse without opening or loading. */
bool zcl_hotswap_hotfork_visit_so(
    const char *so_path, const char *expected_sha256,
    zcl_hotfork_capsule_visit_fn visit, void *ctx,
    char actual_sha256[65]);

#endif /* ZCL_HOTSWAP_HOTFORK_CAPSULE_H */
