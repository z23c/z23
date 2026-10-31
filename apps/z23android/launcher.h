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
    jobject icon; /* Global reference to the app's Drawable, or NULL. */
};

/* Lists the apps with a launcher entry other than this one, sorted by label, at most max (and
 * ZAPP_LAUNCHER_MAX). With icons set, each icon is a global reference released by zapp_launcher_release. */
size_t zapp_launcher_list(JNIEnv *env, jobject activity, struct zapp_launcher_app *apps, size_t max, bool icons);
void zapp_launcher_release(JNIEnv *env, struct zapp_launcher_app *apps, size_t count);
/* Starts the launch activity of a package. False when it has none. */
bool zapp_launcher_start(JNIEnv *env, jobject activity, const char *package);
/* Opens the system screen that chooses the Home app. */
bool zapp_launcher_home_settings(JNIEnv *env, jobject activity);
#endif
