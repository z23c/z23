/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded bridge to the land queue's existing cancellation authority. */
#ifndef ZCL_NATIVE_DEV_LAND_CANCEL_H
#define ZCL_NATIVE_DEV_LAND_CANCEL_H
#include <stdbool.h>
enum zcl_land_cancel_observation { ZCL_LAND_CANCEL_UNKNOWN, ZCL_LAND_CANCEL_CURRENT,
                                   ZCL_LAND_CANCEL_SETTLED };
enum zcl_land_cancel_observation zcl_dev_land_cancel_observe(
    const char *binding, const char *root, const char *local, const char *base);
#endif
