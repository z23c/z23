/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * User-owned hosting window; never starts hosting or authorizes a share. */
#ifndef ZCL_NATIVE_APP_HOST_VIEW_H
#define ZCL_NATIVE_APP_HOST_VIEW_H
#include "command/native_app_confirm.h"
struct app_host_owner;
/* Owner was started only after explicit confirmation. On close/failure this
 * requests Stop; caller must join/reap and safely clean its retained scratch. */
bool app_host_view_run(struct app_host_owner *, app_confirm_presenter,
                       void *, char *, size_t);
#if defined(ZCL_TESTING) && !defined(_WIN32)
typedef bool (*app_host_test_copy_fn)(const char *, void *);
bool zcl_test_app_host_view_run(struct app_host_owner *, app_confirm_presenter, void *,
                                app_host_test_copy_fn, void *, char *, size_t);
#endif
#endif
