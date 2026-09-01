/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Versioned persistent package-swarm download intent records. */

#ifndef ZCL_VCS_PACKAGE_SWARM_RECORD_H
#define ZCL_VCS_PACKAGE_SWARM_RECORD_H

#include <stdbool.h>
#include <stdint.h>

struct vcs_swarm_record {
    uint8_t root[32];
    int64_t created_day;
    bool provider_restricted;
    uint64_t maximum_package_bytes;
};

struct vcs_package_manifest;
bool vcs_swarm_manifest_within_bound(
    const struct vcs_package_manifest *manifest, uint64_t maximum_bytes);

bool vcs_swarm_record_persist(const char *zcode_dir, const char *root_hex,
                              const struct vcs_swarm_record *record);
bool vcs_swarm_record_load(const char *path, struct vcs_swarm_record *out);
void vcs_swarm_record_delete(const char *zcode_dir, const char *root_hex);

#endif /* ZCL_VCS_PACKAGE_SWARM_RECORD_H */
