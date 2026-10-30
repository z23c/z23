/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "node_service.h"
#include "controller.h"
#include "node_watch.h"
#include <android/log.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>

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
static jint stock_icon(JNIEnv *env)
{
    jclass cls = (*env)->FindClass(env, "android/R$drawable");
    jfieldID field = cls ? (*env)->GetStaticFieldID(env, cls, "sym_def_app_icon", "I") : NULL;
    jint id = field ? (*env)->GetStaticIntField(env, cls, field) : 0;
    return failed(env, "stock icon") ? 0 : id;
}
/* The app icon, or the stock one when the app has none. */
static jint app_icon(JNIEnv *env, jobject service)
{
    jobject info = call_object(env, service, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jclass cls = info ? (*env)->GetObjectClass(env, info) : NULL;
    jfieldID icon = cls ? (*env)->GetFieldID(env, cls, "icon", "I") : NULL;
    jint id = icon ? (*env)->GetIntField(env, info, icon) : 0;
    return failed(env, "icon") || id == 0 ? stock_icon(env) : id;
}
static const char *const builder_class = "Landroid/app/Notification$Builder;";
static jobject new_builder(JNIEnv *env, jobject service)
{
    return new_object(env, "android/app/Notification$Builder", "(Landroid/content/Context;Ljava/lang/String;)V",
                      service, jstr(env, "node"));
}
/* The full notification; a missing tap action only costs the tap. */
static jobject build_notification(JNIEnv *env, jobject service)
{
    jstring package = call_object(env, service, "getPackageName", "()Ljava/lang/String;");
    jobject tap = package ? tap_action(env, service, package) : NULL;
    jobject b = new_builder(env, service);
    char sig[96];
    if (!b) return NULL;
    snprintf(sig, sizeof(sig), "(Ljava/lang/CharSequence;)%s", builder_class);
    (void)call_object(env, b, "setContentTitle", sig, jstr(env, "Z23 node"));
    (void)call_object(env, b, "setContentText", sig, jstr(env, "Running and in sync while hidden"));
    snprintf(sig, sizeof(sig), "(I)%s", builder_class);
    (void)call_object(env, b, "setSmallIcon", sig, app_icon(env, service));
    snprintf(sig, sizeof(sig), "(Z)%s", builder_class);
    (void)call_object(env, b, "setOngoing", sig, 1);
    if (tap) {
        snprintf(sig, sizeof(sig), "(Landroid/app/PendingIntent;)%s", builder_class);
        (void)call_object(env, b, "setContentIntent", sig, tap);
    }
    return call_object(env, b, "build", "()Landroid/app/Notification;");
}
/* Only what startForeground needs, for when the full notification cannot be built. */
static jobject minimal_notification(JNIEnv *env, jobject service)
{
    jobject b = new_builder(env, service);
    char sig[96];
    if (!b) return NULL;
    snprintf(sig, sizeof(sig), "(I)%s", builder_class);
    (void)call_object(env, b, "setSmallIcon", sig, stock_icon(env));
    return call_object(env, b, "build", "()Landroid/app/Notification;");
}
static bool enter_foreground(JNIEnv *env, jobject service)
{
    jobject n = build_notification(env, service);
    if (!n) n = minimal_notification(env, service);
    return n && call_void(env, service, "startForeground", "(ILandroid/app/Notification;I)V",
                          NOTIFICATION_ID, n, SERVICE_TYPE_SPECIAL_USE);
}

/* generation counts service starts; a watch from an earlier start must not stop a newer one. */
static struct { pthread_mutex_t lock; JavaVM *vm; jobject service; uintptr_t generation; } held = { PTHREAD_MUTEX_INITIALIZER, NULL, NULL, 0 };

static void release_service(JNIEnv *env)
{
    pthread_mutex_lock(&held.lock);
    jobject service = held.service;
    held.service = NULL;
    pthread_mutex_unlock(&held.lock);
    if (service) (*env)->DeleteGlobalRef(env, service);
}
static atomic_bool ended;
static bool node_alive(void *context) { (void)context; return zapp_controller_node_running(); }
/* The node exited with nothing in the app watching: end the service from the watch thread. Returns
 * false when the stop could not be issued, so the watch tries again. */
static bool node_gone(void *context)
{
    JNIEnv *env = NULL;
    pthread_mutex_lock(&held.lock); JavaVM *vm = held.vm; pthread_mutex_unlock(&held.lock);
    if (!vm || (*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) return false;
    pthread_mutex_lock(&held.lock);
    bool current = held.generation == (uintptr_t)context && held.service;
    /* Held across stopSelf so a newer start cannot be delivered before this stop is issued. */
    bool stopped = !current || call_void(env, held.service, "stopSelf", "()V");
    jobject service = stopped && current ? held.service : NULL;
    if (service) held.service = NULL;
    pthread_mutex_unlock(&held.lock);
    if (service) { atomic_store(&ended, true); (*env)->DeleteGlobalRef(env, service); }
    (*vm)->DetachCurrentThread(vm);
    return stopped;
}
static void watch_node(JNIEnv *env, jobject service)
{
    struct node_watch_ops ops = { node_alive, node_gone, NULL, 5000 };
    JavaVM *vm = NULL;
    zapp_node_watch_stop();
    release_service(env);
    if ((*env)->GetJavaVM(env, &vm) != JNI_OK) return;
    jobject ref = (*env)->NewGlobalRef(env, service);
    if (!ref) { (void)failed(env, "global ref"); return; }
    pthread_mutex_lock(&held.lock); held.vm = vm; held.service = ref; ops.context = (void *)held.generation;
    pthread_mutex_unlock(&held.lock);
    if (!zapp_node_watch_start(&ops)) release_service(env);
}

/* Called by NodeService.onStartCommand on the main thread. */
JNIEXPORT jint JNICALL Java_org_z23_nativeapp_NodeService_start(JNIEnv *env, jclass cls, jobject service, jint id);
JNIEXPORT jint JNICALL Java_org_z23_nativeapp_NodeService_start(JNIEnv *env, jclass cls, jobject service, jint id)
{
    (void)cls; (void)id;
    if ((*env)->PushLocalFrame(env, 64) != JNI_OK) { (void)failed(env, "local frame"); return START_NOT_STICKY; }
    create_channel(env, service);
    /* Android ends an app whose started foreground service never calls startForeground. */
    if (enter_foreground(env, service)) watch_node(env, service);
    else (void)call_void(env, service, "stopSelf", "()V");
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
    atomic_store(&ended, false);
    pthread_mutex_lock(&held.lock); held.generation++; pthread_mutex_unlock(&held.lock);
    jobject intent = service_intent(env, context);
    ok = intent && call_object(env, context, "startForegroundService",
                               "(Landroid/content/Intent;)Landroid/content/ComponentName;", intent) != NULL;
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
bool zapp_node_service_ended(void) { return atomic_load(&ended); }
void zapp_node_service_stop(JNIEnv *env, jobject context)
{
    zapp_node_watch_stop();
    release_service(env);
    if ((*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)failed(env, "local frame"); return; }
    jobject intent = service_intent(env, context);
    jmethodID stop = intent ? method_of(env, context, "stopService", "(Landroid/content/Intent;)Z") : NULL;
    if (stop) (void)(*env)->CallBooleanMethod(env, context, stop, intent);
    (void)failed(env, "stopService");
    (*env)->PopLocalFrame(env, NULL);
}
