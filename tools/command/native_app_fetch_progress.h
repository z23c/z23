/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Present a bounded carrier fetch while retaining worker ownership. */
#ifndef ZCL_NATIVE_APP_FETCH_PROGRESS_H
#define ZCL_NATIVE_APP_FETCH_PROGRESS_H
#include "command/native_app_confirm.h"
#include <stdbool.h>
enum app_fetch_progress_result { APP_FETCH_OK, APP_FETCH_FAILED, APP_FETCH_CLOSED, APP_FETCH_UNAVAILABLE };
enum app_fetch_progress_result app_fetch_progress_run(bool (*fetch)(void *), void *work,
    app_confirm_presenter presenter, void *context);
#endif
