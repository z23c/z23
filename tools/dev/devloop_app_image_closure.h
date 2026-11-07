/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the dev-only closure root of an app copy build record. It reads
 *          the compile actions' depfile derivation (devloop_action_root.h),
 *          so it is linked into z23-dev and the tests, never into z23. */

#ifndef ZCL_DEVLOOP_APP_IMAGE_CLOSURE_H
#define ZCL_DEVLOOP_APP_IMAGE_CLOSURE_H

#include <stddef.h>
#include <stdint.h>

#include "base/result.h"

struct zcl_action_root_request;

/* Closure root of the compile actions that built the image. Each request is
 * derived (zcl_action_root_derive) from its own -MD depfile; any miss
 * refuses, naming the action and the miss code. One action gives exactly
 * its vcs_build_input_closure_v1_root(); several fold their roots, in the
 * given order, under APP_IMAGE_BUILD_CLOSURE_SET_DOMAIN with the count. */
struct zcl_result app_image_closure_root(
    const struct zcl_action_root_request *actions, size_t count,
    uint8_t out[32]);

#endif /* ZCL_DEVLOOP_APP_IMAGE_CLOSURE_H */
