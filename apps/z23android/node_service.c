/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "node_service.h"
#include <android/log.h>
#include <stdarg.h>
#include <stdio.h>

#define TAG "z23"
#define SERVICE_CLASS "org.z23.nativeapp.NodeService"
enum { NOTIFICATION_ID = 1, IMPORTANCE_LOW = 2, FLAG_IMMUTABLE = 0x04000000,
       SERVICE_TYPE_SPECIAL_USE = 0x40000000, START_NOT_STICKY = 2 };

/* True and cleared when a Java exception is pending. */
static bool failed(JNIEnv *env, const char *what)
{
    if (!(*env)->ExceptionCheck(env)) return false;
    (*env)->ExceptionClear(env);
    __android_log_print(ANDROID_LOG_ERROR, TAG, "node service: %s failed", what);
    return true;
}
static jmethodID method_of(JNIEnv *env, jobject o, const char *name, const char *sig)
{
    jclass cls = (*env)->GetObjectClass(env, o);
    jmethodID m = cls ? (*env)->GetMethodID(env, cls, name, sig) : NULL;
    return failed(env, name) ? NULL : m;
}
static jobject call_object(JNIEnv *env, jobject o, const char *name, const char *sig, ...)
{
    jmethodID m = method_of(env, o, name, sig);
    va_list ap; va_start(ap, sig);
    jobject r = m ? (*env)->CallObjectMethodV(env, o, m, ap) : NULL;
    va_end(ap);
    return failed(env, name) ? NULL : r;
}
static bool call_void(JNIEnv *env, jobject o, const char *name, const char *sig, ...)
{
    jmethodID m = method_of(env, o, name, sig);
    va_list ap; va_start(ap, sig);
    if (m) (*env)->CallVoidMethodV(env, o, m, ap);
    va_end(ap);
    return m && !failed(env, name);
}
static jobject new_object(JNIEnv *env, const char *class_name, const char *sig, ...)
{
    jclass cls = (*env)->FindClass(env, class_name);
    jmethodID ctor = cls ? (*env)->GetMethodID(env, cls, "<init>", sig) : NULL;
    va_list ap; va_start(ap, sig);
    jobject r = ctor && !failed(env, class_name) ? (*env)->NewObjectV(env, cls, ctor, ap) : NULL;
    va_end(ap);
    return failed(env, class_name) ? NULL : r;
}
static jstring jstr(JNIEnv *env, const char *text) { return (*env)->NewStringUTF(env, text); }

static void create_channel(JNIEnv *env, jobject service)
{
    jobject manager = call_object(env, service, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;",
                                  jstr(env, "notification"));
    jobject channel = manager ? new_object(env, "android/app/NotificationChannel",
        "(Ljava/lang/String;Ljava/lang/CharSequence;I)V", jstr(env, "node"), jstr(env, "Node"), IMPORTANCE_LOW) : NULL;
    if (channel) (void)call_void(env, manager, "createNotificationChannel", "(Landroid/app/NotificationChannel;)V", channel);
}
/* A PendingIntent that opens the app. */
static jobject tap_action(JNIEnv *env, jobject service, jstring package)
{
    jobject packages = call_object(env, service, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject launch = packages ? call_object(env, packages, "getLaunchIntentForPackage",
        "(Ljava/lang/String;)Landroid/content/Intent;", package) : NULL;
    jclass cls = launch ? (*env)->FindClass(env, "android/app/PendingIntent") : NULL;
    jmethodID get = cls ? (*env)->GetStaticMethodID(env, cls, "getActivity",
        "(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;") : NULL;
    if (failed(env, "PendingIntent") || !get) return NULL;
    jobject action = (*env)->CallStaticObjectMethod(env, cls, get, service, 0, launch, FLAG_IMMUTABLE);
    return failed(env, "getActivity") ? NULL : action;
}
static jint app_icon(JNIEnv *env, jobject service)
{
    jobject info = call_object(env, service, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jclass cls = info ? (*env)->GetObjectClass(env, info) : NULL;
    jfieldID icon = cls ? (*env)->GetFieldID(env, cls, "icon", "I") : NULL;
    jint id = icon ? (*env)->GetIntField(env, info, icon) : 0;
    return failed(env, "icon") ? 0 : id;
}
static jobject build_notification(JNIEnv *env, jobject service)
{
    jstring package = call_object(env, service, "getPackageName", "()Ljava/lang/String;");
    jobject tap = package ? tap_action(env, service, package) : NULL;
    jobject b = new_object(env, "android/app/Notification$Builder", "(Landroid/content/Context;Ljava/lang/String;)V",
                           service, jstr(env, "node"));
    static const char *const self = "Landroid/app/Notification$Builder;";
    char sig[96];
    if (!b || !tap) return NULL;
    snprintf(sig, sizeof(sig), "(Ljava/lang/CharSequence;)%s", self);
    (void)call_object(env, b, "setContentTitle", sig, jstr(env, "Z23 node"));
    (void)call_object(env, b, "setContentText", sig, jstr(env, "Running and in sync while hidden"));
    snprintf(sig, sizeof(sig), "(I)%s", self);
    (void)call_object(env, b, "setSmallIcon", sig, app_icon(env, service));
    snprintf(sig, sizeof(sig), "(Z)%s", self);
    (void)call_object(env, b, "setOngoing", sig, 1);
    snprintf(sig, sizeof(sig), "(Landroid/app/PendingIntent;)%s", self);
    (void)call_object(env, b, "setContentIntent", sig, tap);
    return call_object(env, b, "build", "()Landroid/app/Notification;");
}

/* Called by NodeService.onStartCommand on the main thread. */
JNIEXPORT jint JNICALL Java_org_z23_nativeapp_NodeService_start(JNIEnv *env, jclass cls, jobject service, jint id);
JNIEXPORT jint JNICALL Java_org_z23_nativeapp_NodeService_start(JNIEnv *env, jclass cls, jobject service, jint id)
{
    (void)cls; (void)id;
    if ((*env)->PushLocalFrame(env, 64) != JNI_OK) { (void)failed(env, "local frame"); return START_NOT_STICKY; }
    create_channel(env, service);
    jobject notification = build_notification(env, service);
    bool ok = notification && call_void(env, service, "startForeground", "(ILandroid/app/Notification;I)V",
                                        NOTIFICATION_ID, notification, SERVICE_TYPE_SPECIAL_USE);
    /* Android ends an app whose started foreground service never calls startForeground. */
    if (!ok) (void)call_void(env, service, "stopSelf", "()V");
    (*env)->PopLocalFrame(env, NULL);
    return START_NOT_STICKY;
}

/* An Intent naming NodeService in this app's package. */
static jobject service_intent(JNIEnv *env, jobject context)
{
    jstring package = call_object(env, context, "getPackageName", "()Ljava/lang/String;");
    jobject intent = package ? new_object(env, "android/content/Intent", "()V") : NULL;
    bool named = intent && call_object(env, intent, "setClassName",
        "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;", package, jstr(env, SERVICE_CLASS));
    return named ? intent : NULL;
}
bool zapp_node_service_start(JNIEnv *env, jobject context)
{
    bool ok = false;
    if ((*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)failed(env, "local frame"); return false; }
    jobject intent = service_intent(env, context);
    ok = intent && call_object(env, context, "startForegroundService",
                               "(Landroid/content/Intent;)Landroid/content/ComponentName;", intent) != NULL;
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
void zapp_node_service_stop(JNIEnv *env, jobject context)
{
    if ((*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)failed(env, "local frame"); return; }
    jobject intent = service_intent(env, context);
    jmethodID stop = intent ? method_of(env, context, "stopService", "(Landroid/content/Intent;)Z") : NULL;
    if (stop) (void)(*env)->CallBooleanMethod(env, context, stop, intent);
    (void)failed(env, "stopService");
    (*env)->PopLocalFrame(env, NULL);
}
