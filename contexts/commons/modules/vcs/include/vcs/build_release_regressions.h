/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical requested intent for the secure-release regression lane. */

#ifndef ZCL_VCS_BUILD_RELEASE_REGRESSIONS_H
#define ZCL_VCS_BUILD_RELEASE_REGRESSIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_BUILD_RELEASE_REGRESSION_MANIFEST_VERSION 1u

/* This fixed manifest is requested intent. The test action is the
 * compiler-derived plan, and its work receipt is physical observation. */
void vcs_build_release_regression_manifest_v1_bytes(
    const uint8_t **bytes, size_t *len);
void vcs_build_release_regression_manifest_v1_root(uint8_t out[32]);
bool vcs_build_release_regression_manifest_v1_store(
    const char *workspace, uint8_t out[32]);
bool vcs_build_release_regression_manifest_v1_verify_cas(
    const char *workspace, const uint8_t expected_root[32]);

#endif /* ZCL_VCS_BUILD_RELEASE_REGRESSIONS_H */
