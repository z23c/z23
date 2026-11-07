/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Expose read-only exact kept-source resolution to native app callers. */
#ifndef ZCL_APP_CUSTOMIZE_SOURCE_H
#define ZCL_APP_CUSTOMIZE_SOURCE_H
#include "command/app_selection.h"
#include "command/native_zcode_package_copy.h"
/* Snapshot-as-of-read: subsequent Keep does not change this source choice. */
bool app_customize_source(const char *name, uint64_t revision,
    struct app_selection *selection, struct zcl_package_copy *copy,
    struct zcl_command_reply *reply);
#endif
