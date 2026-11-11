/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_LAUNCHER_H
#define ZAPP_LAUNCHER_H
#include "home.h"
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>

#define ZAPP_LAUNCHER_MAX 256u

struct zapp_launcher_app {
    struct zapp_app_entry entry;
};

/* Lists the apps with a launcher entry other than this one, sorted by label, at most max (and
 * ZAPP_LAUNCHER_MAX). The UI uses text labels and does not load app icons. */
size_t zapp_launcher_list(JNIEnv *env, jobject activity, struct zapp_launcher_app *apps, size_t max);
/* Starts one launcher activity class of a package. False when it cannot be started. */
bool zapp_launcher_start(JNIEnv *env, jobject activity, const char *package, const char *activity_class);
/* Opens the system screen that chooses the Home app, or the main Android settings when no app handles it. */
bool zapp_launcher_home_settings(JNIEnv *env, jobject activity);
#endif
