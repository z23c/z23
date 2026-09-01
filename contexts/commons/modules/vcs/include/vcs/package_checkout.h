/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: inert checkout of one verified ordinary ZCODE package tree. */

#ifndef ZCL_VCS_PACKAGE_CHECKOUT_H
#define ZCL_VCS_PACKAGE_CHECKOUT_H

#include "vcs/package_store.h"

#include <stddef.h>
#include <stdint.h>

enum vcs_package_checkout_result {
    VCS_PACKAGE_CHECKOUT_OK = 0,
    VCS_PACKAGE_CHECKOUT_NULL,
    VCS_PACKAGE_CHECKOUT_INCOMPLETE,
    VCS_PACKAGE_CHECKOUT_MANIFEST,
    VCS_PACKAGE_CHECKOUT_CHUNK,
    VCS_PACKAGE_CHECKOUT_DESTINATION,
};

struct vcs_package_checkout_metrics {
    uint32_t files;
    uint32_t chunks;
    uint64_t bytes;
};

const char *vcs_package_checkout_result_string(
    enum vcs_package_checkout_result result);

/* Reconstruct one complete ordinary content.v2 package beneath an absent
 * destination. The package root and every chunk are reverified before the
 * staged tree is renamed into place. Downloaded bytes remain inert: this
 * function never builds, loads, tests, or executes them. */
enum vcs_package_checkout_result vcs_package_checkout(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *destination, struct vcs_package_checkout_metrics *metrics);

#endif /* ZCL_VCS_PACKAGE_CHECKOUT_H */
