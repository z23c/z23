/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_NODE_SERVICE_H
#define Z23_ANDROID_NODE_SERVICE_H
#include <jni.h>
#include <stdbool.h>

/* Starts org.z23.nativeapp.NodeService, a foreground service that raises the process priority
 * while the app is hidden. Call from the UI thread while the activity is visible. */
bool zapp_node_service_start(JNIEnv *env, jobject context);
/* Stops that service. */
void zapp_node_service_stop(JNIEnv *env, jobject context);
#endif
