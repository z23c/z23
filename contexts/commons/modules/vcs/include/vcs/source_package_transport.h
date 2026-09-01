/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: content.v2 carrier for one verified ZVCS source bundle. */

#ifndef ZCL_VCS_SOURCE_PACKAGE_TRANSPORT_H
#define ZCL_VCS_SOURCE_PACKAGE_TRANSPORT_H

#include "vcs/source_bundle.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_SOURCE_PACKAGE_MANIFEST_PATH \
    "zclassic23-source/manifest.zvsm"
#define VCS_SOURCE_PACKAGE_LANE_PATH "zcode-lane-receipt.v1"
#define VCS_SOURCE_PACKAGE_AUTHORITY_PATH \
    "zcode-accepted-work-authority.v1"
#define VCS_SOURCE_PACKAGE_MARKER_PATH "zcode-source-transport.c"
#define VCS_SOURCE_PACKAGE_LICENSE_PATH "LICENSE"
#define VCS_SOURCE_PACKAGE_OFFLINE_INPUT_MAX 8u

struct vcs_source_package_file {
    const char *path;
    uint8_t *bytes;
    size_t len;
};

struct vcs_source_package_transport {
    uint8_t package_root[32];
    uint8_t recipe_root[32];
    uint8_t *manifest_wire;
    size_t manifest_wire_len;
    uint8_t *recipe_wire;
    size_t recipe_wire_len;
    uint8_t *license_bytes;
    size_t license_len;
    uint8_t *lane_wire;
    size_t lane_wire_len;
    uint8_t *authority_wire;
    size_t authority_wire_len;
    uint8_t accepted_work_root[32];
    struct vcs_source_bundle_sharded source;
    struct vcs_source_package_file
        offline_inputs[VCS_SOURCE_PACKAGE_OFFLINE_INPUT_MAX];
    size_t offline_input_count;
    uint64_t source_transport_bytes;
    uint64_t offline_input_bytes;
    struct vcs_source_bundle_metrics bundle_metrics;
};

void vcs_source_package_transport_init(
    struct vcs_source_package_transport *transport);
void vcs_source_package_transport_free(
    struct vcs_source_package_transport *transport);

/* Derive one ordinary content.v2 package from an authoritative ZVCS tree.
 * The package carries the exact top-level LICENSE, verified source bundle,
 * signed lane-receipt wire, and an inert compilable transport marker.
 * transport must first be initialized with
 * vcs_source_package_transport_init(). */
bool vcs_source_package_transport_build(
    const char *workspace, const uint8_t source_root[32],
    const uint8_t expected_signer[32],
    const uint8_t *lane_wire, size_t lane_wire_len,
    struct vcs_source_package_transport *transport);

/* Publication path: derive the expected signer and PROVEN receipt only by
 * resolving the complete accepted-work chain, then carry that closed chain
 * beside the source. */
bool vcs_source_package_transport_build_accepted(
    const char *workspace, const uint8_t source_root[32],
    const uint8_t accepted_work_root[32], int64_t now_unix,
    struct vcs_source_package_transport *transport);

const uint8_t *vcs_source_package_transport_marker(size_t *len_out);

size_t vcs_source_package_transport_file_count(
    const struct vcs_source_package_transport *transport);
bool vcs_source_package_transport_file_at(
    const struct vcs_source_package_transport *transport, size_t index,
    const char **path_out, const uint8_t **bytes_out, size_t *len_out);

size_t vcs_source_package_offline_input_count(void);
const char *vcs_source_package_offline_input_path(size_t index);

#endif /* ZCL_VCS_SOURCE_PACKAGE_TRANSPORT_H */
