/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_NODE_SERVICE_H
#define Z23_ANDROID_NODE_SERVICE_H
#include <jni.h>
#include <stdbool.h>

/* Starts org.z23.nativeapp.NodeService, a foreground service that raises the process priority
 * while the app is hidden. Call from the UI thread while the activity is visible. */
bool zapp_node_service_start(JNIEnv *env, jobject context);
/* True once the service ended itself because the node exited. Cleared by the next start. */
bool zapp_node_service_ended(void);
/* Posts one notification on the "Payments" channel when a payment ended (an enum zapp_payment_result): private on the
 * lock screen, whose public version reads only "Z23 payment update". Safe from any thread attached to the JVM. */
bool zapp_payment_notify(JNIEnv *env, jobject context, int result);
/* Stops that service. */
void zapp_node_service_stop(JNIEnv *env, jobject context);
#endif
