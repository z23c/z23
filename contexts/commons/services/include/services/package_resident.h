/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: bind an explicitly selected installed program to resident_launch. */
#ifndef ZCL_SERVICES_PACKAGE_RESIDENT_H
#define ZCL_SERVICES_PACKAGE_RESIDENT_H

#include "base/result.h"
#include "platform/resident_launch.h"
#include "platform/ram_scratch.h"
#include "services/package_lifecycle.h"

/* This is an inert acceptance projection, never an execution grant. The
 * caller must separately authorize the exact package, receipt and output.
 * The digest comes from the verified install receipt, never from whichever
 * bytes happen to occupy the installed pathname today. */
struct package_resident_artifact {
    uint8_t package_root[32];
    uint8_t receipt_id[32];
    uint8_t recipe_root[32];
    char output[VCS_PACKAGE_BUILD_PATH_MAX + 1u];
    char locator[PACKAGE_LIFECYCLE_INSTALL_DIR_MAX +
                 VCS_PACKAGE_BUILD_PATH_MAX + 2u];
    struct resident_launch_accepted accepted;
};

struct zcl_result package_resident_artifact_read(
    const char *datadir, const uint8_t package_root[32],
    const uint8_t receipt_id[32], const char *output,
    struct package_resident_artifact *out);

/* Inert Linux HOST image admission for fixed bin/tunnel. Exact request binds
 * installed root, receipt and digest; retained current-lock reads are copied
 * into a sealed top-level image. Fresh image_fd=-1 output owns the returned FD.
 * No child/socket is created. Caller separately approves host_os execution,
 * trusts mutable system loader/libraries and retains exclusive FD custody. */
struct zcl_result package_resident_host_image_capture(
    const char *datadir, const uint8_t package_root[32], const uint8_t receipt_id[32],
    const uint8_t artifact_sha3[32], int *image_fd);

/* One caller-owned application process. Independent snapshot lifetime ends
 * only after the seam has cancelled/reaped its child. A failed candidate
 * never changes any other instance or a package's active generation. */
struct package_resident {
    struct package_resident_artifact artifact;
    struct resident_launch launch;
    struct resident_receipt receipt;
    struct resident_startup startup;
    struct platform_ram_scratch_lease snapshot_lease;
    char snapshot_directory[128];
    char snapshot_image[160];
};

void package_resident_init(struct package_resident *app);
struct zcl_result package_resident_prepare(struct package_resident *app,
    const struct package_resident_artifact *artifact);
/* Rehash a retained independent snapshot and issue a fresh launch nonce and
 * deadline. The caller must freshly verify the installed artifact first. */
struct zcl_result package_resident_prepare_reuse(struct package_resident *app,
    const struct package_resident_artifact *artifact);
struct zcl_result package_resident_start(struct package_resident *app);
struct zcl_result package_resident_close(struct package_resident *app);


#endif
