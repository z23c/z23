/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SHARE_DIAG_H
#define ZAPP_SHARE_DIAG_H
#ifdef __ANDROID__
#include <android/log.h>
#define SHARE_DIAG(...) __android_log_print(ANDROID_LOG_INFO, "z23", __VA_ARGS__)
#else
#define SHARE_DIAG(...) ((void)0)
#endif
#endif
