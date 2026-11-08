/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Declare the explicit desktop reveal operation for a shared app file. */
#ifndef ZCL_NATIVE_APP_SHARE_REVEAL_H
#define ZCL_NATIVE_APP_SHARE_REVEAL_H
#include <stdbool.h>
bool app_share_reveal(const char *path);
#if defined(ZCL_TESTING)
typedef bool (*app_share_reveal_runner)(void *, const char *, const char *const *);
bool zcl_test_app_share_reveal(const char *path, app_share_reveal_runner runner, void *context);
bool zcl_test_app_share_reveal_run(const char *image, const char *const *argv);
#endif
#endif
