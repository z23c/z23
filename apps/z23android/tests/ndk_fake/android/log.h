/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_FAKE_ANDROID_LOG_H
#define ZAPP_FAKE_ANDROID_LOG_H
/* Host fake of the NDK log header, only for tests/thermal_start_test.c. */
enum { ANDROID_LOG_WARN = 5 };
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
#endif
