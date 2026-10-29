/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "app.h"
#include "base/cleanse.h"
#include "camera.h"
#include "controller.h"
#include "native_ui.h"
#include <android/input.h>
#include <android/looper.h>
#include <android/native_activity.h>
#include <fcntl.h>
#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic(JavaVM *) vm;
static jobject active;
static ALooper *looper;
static int signal_pipe[2] = {-1, -1};
static uint64_t permission_ticket;
static bool foreground = true;
static bool microphone_allowed(JNIEnv *env, jobject activity);

static bool clean(JNIEnv *env)
{
    if (!(*env)->ExceptionCheck(env)) return true;
    (*env)->ExceptionClear(env); return false;
}
static void notify(void)
{
    pthread_mutex_lock(&lock);
    if (signal_pipe[1] >= 0) { char byte = 1; (void)write(signal_pipe[1], &byte, 1); }
    pthread_mutex_unlock(&lock);
}
static void refresh(JNIEnv *env)
{
    struct zapp_view *view = calloc(1, sizeof(*view));
    if (!view) return;
    zapp_controller_snapshot(view);
    zapp_native_ui_render(env, view);
    unsigned char *bmp = NULL; size_t size = 0;
    (void)zapp_camera_preview(&bmp, &size);
    zapp_native_ui_preview(env, bmp, size); free(bmp);
    free(view);
}
static void action(const char *name, const char *argument)
{
    if (!strcmp(name, "voice_start")) {
        JNIEnv *env = NULL; JavaVM *current_vm = atomic_load(&vm);
        if (!foreground || !current_vm ||
            (*current_vm)->GetEnv(current_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK ||
            !active || !microphone_allowed(env, active)) return;
    }
    if (!zapp_controller_action(name, argument, "")) {
        JNIEnv *env = NULL; JavaVM *current_vm = atomic_load(&vm);
        if (current_vm && (*current_vm)->GetEnv(current_vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK)
            zapp_native_ui_update(env, NULL, "Unable to start that action.");
    } else notify();
}
static void request_permission(JNIEnv *env, jobject activity, const char *name)
{
    jclass cls = (*env)->GetObjectClass(env, activity);
    jclass string_cls = (*env)->FindClass(env, "java/lang/String");
    jmethodID method = cls ? (*env)->GetMethodID(env, cls, "requestPermissions", "([Ljava/lang/String;I)V") : NULL;
    jobjectArray permissions = string_cls ? (*env)->NewObjectArray(env, 1, string_cls, NULL) : NULL;
    jstring camera = (*env)->NewStringUTF(env, name);
    if (clean(env) && method && permissions && camera) {
        (*env)->SetObjectArrayElement(env, permissions, 0, camera);
        if (clean(env)) (*env)->CallVoidMethod(env, activity, method, permissions, 1);
    }
    (void)clean(env);
    if (camera) (*env)->DeleteLocalRef(env, camera);
    if (permissions) (*env)->DeleteLocalRef(env, permissions);
    if (string_cls) (*env)->DeleteLocalRef(env, string_cls);
    if (cls) (*env)->DeleteLocalRef(env, cls);
}
static bool microphone_allowed(JNIEnv *env, jobject activity)
{
    if ((*env)->PushLocalFrame(env, 4) != JNI_OK) { (void)clean(env); return false; }
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID check = cls ? (*env)->GetMethodID(env, cls, "checkSelfPermission", "(Ljava/lang/String;)I") : NULL;
    jstring permission = (*env)->NewStringUTF(env, "android.permission.RECORD_AUDIO");
    bool granted = false;
    if (clean(env) && check && permission) {
        jint result = (*env)->CallIntMethod(env, activity, check, permission);
        granted = clean(env) && result == 0;
    }
    (*env)->PopLocalFrame(env, NULL);
    if (!granted) {
        request_permission(env, activity, "android.permission.RECORD_AUDIO");
        zapp_native_ui_update(env, "Microphone permission required. After granting access, press Talk again.", NULL);
    }
    return granted;
}
static int signal_ready(int fd, int events, void *context)
{
    (void)context;
    if (!(events & ALOOPER_EVENT_INPUT)) return 1;
    char bytes[64]; while (read(fd, bytes, sizeof(bytes)) > 0) {}
    JNIEnv *env = NULL; JavaVM *current_vm = atomic_load(&vm);
    if (!current_vm || (*current_vm)->GetEnv(current_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return 1;
    pthread_mutex_lock(&lock);
    jobject activity = active ? (*env)->NewLocalRef(env, active) : NULL;
    bool request = permission_ticket && permission_ticket == zapp_camera_ticket();
    permission_ticket = 0;
    pthread_mutex_unlock(&lock);
    if (activity && request) request_permission(env, activity, "android.permission.CAMERA");
    if (activity) { refresh(env); (*env)->DeleteLocalRef(env, activity); }
    return 1;
}
static int input_ready(int fd, int events, void *context)
{
    (void)fd; (void)events;
    AInputQueue *queue = context; AInputEvent *event = NULL; JNIEnv *env = NULL;
    JavaVM *current_vm = atomic_load(&vm);
    if (!current_vm || (*current_vm)->GetEnv(current_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return 1;
    while (AInputQueue_getEvent(queue, &event) >= 0) {
        if (AInputQueue_preDispatchEvent(queue, event)) continue;
        zapp_native_ui_input(env, event);
        AInputQueue_finishEvent(queue, event, 0);
    }
    return 1;
}
static void queue_created(ANativeActivity *activity, AInputQueue *queue)
{
    (void)activity;
    if (looper) AInputQueue_attachLooper(queue, looper, ALOOPER_POLL_CALLBACK, input_ready, queue);
}
static void queue_destroyed(ANativeActivity *activity, AInputQueue *queue)
{ (void)activity; AInputQueue_detachLooper(queue); }
static bool permission_wait(JNIEnv *env, jobject activity, jmethodID check,
                            jstring permission, uint64_t ticket)
{
    pthread_mutex_lock(&lock);
    bool queued = active && ticket == zapp_camera_ticket() && signal_pipe[1] >= 0;
    if (queued) { char byte = 1; permission_ticket = ticket; queued = write(signal_pipe[1], &byte, 1) == 1; if (!queued) permission_ticket = 0; }
    pthread_mutex_unlock(&lock);
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 200000000 };
    for (int i = 0; queued && i < 150; ++i) {
        nanosleep(&pause, NULL);
        pthread_mutex_lock(&lock); bool alive = active && ticket == zapp_camera_ticket(); pthread_mutex_unlock(&lock);
        if (!alive) break;
        bool granted = (*env)->CallIntMethod(env, activity, check, permission) == 0;
        if (!clean(env)) break;
        if (granted) return true;
    }
    return false;
}

static bool permission_attach(JavaVM *current_vm, JNIEnv **env, bool *attached)
{
    if (!current_vm) return false;
    jint rc = (*current_vm)->GetEnv(current_vm, (void **)env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if ((*current_vm)->AttachCurrentThread(current_vm, env, NULL) != JNI_OK) return false;
        *attached = true;
        return true;
    }
    return rc == JNI_OK;
}

bool zapp_camera_permission(uint64_t ticket)
{
    JavaVM *current_vm = atomic_load(&vm); JNIEnv *env = NULL; bool attached = false, granted = false;
    if (!permission_attach(current_vm, &env, &attached)) return false;
    pthread_mutex_lock(&lock);
    jobject activity = active && ticket == zapp_camera_ticket() ? (*env)->NewLocalRef(env, active) : NULL;
    pthread_mutex_unlock(&lock);
    if (!activity) goto out;
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID check = cls ? (*env)->GetMethodID(env, cls, "checkSelfPermission", "(Ljava/lang/String;)I") : NULL;
    jstring permission = (*env)->NewStringUTF(env, "android.permission.CAMERA");
    if (!clean(env) || !check || !permission) goto done;
    jint permission_status = (*env)->CallIntMethod(env, activity, check, permission);
    if (!clean(env)) goto done;
    granted = permission_status == 0;
    if (!granted) granted = permission_wait(env, activity, check, permission, ticket);
done:
    (void)clean(env);
    if (permission) (*env)->DeleteLocalRef(env, permission);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    (*env)->DeleteLocalRef(env, activity);
out:
    if (attached) (*current_vm)->DetachCurrentThread(current_vm);
    return granted;
}

static bool native_directory(JNIEnv *env, jobject activity, char *out, size_t cap)
{
    bool ok = false;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)clean(env); return false; }
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID get = cls ? (*env)->GetMethodID(env, cls, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;") : NULL;
    jobject info = get ? (*env)->CallObjectMethod(env, activity, get) : NULL;
    if (!clean(env) || !info) goto out;
    jclass info_cls = (*env)->GetObjectClass(env, info);
    jfieldID field = info_cls ? (*env)->GetFieldID(env, info_cls, "nativeLibraryDir", "Ljava/lang/String;") : NULL;
    jstring value = field ? (*env)->GetObjectField(env, info, field) : NULL;
    if (!clean(env) || !value) goto out;
    const char *chars = (*env)->GetStringUTFChars(env, value, NULL);
    if (!clean(env) || !chars) goto out;
    size_t length = strlen(chars);
    if (length < cap) { memcpy(out, chars, length + 1); ok = true; }
    (*env)->ReleaseStringUTFChars(env, value, chars);
out:
    (void)clean(env); (*env)->PopLocalFrame(env, NULL); return ok;
}
static jobject launch_intent(JNIEnv *env, jobject activity)
{
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID get = cls ? (*env)->GetMethodID(env, cls, "getIntent", "()Landroid/content/Intent;") : NULL;
    return clean(env) && get ? (*env)->CallObjectMethod(env, activity, get) : NULL;
}
static bool copy_utf(JNIEnv *env, jstring value, char *out, size_t cap)
{
    const char *chars = clean(env) && value ? (*env)->GetStringUTFChars(env, value, NULL) : NULL;
    bool ok = chars && strlen(chars) < cap;
    if (ok) memcpy(out, chars, strlen(chars) + 1);
    if (chars) (*env)->ReleaseStringUTFChars(env, value, chars);
    return ok;
}
/* Reads and removes the pairing descriptor a USB-connected laptop host offered
 * through the launch intent. The owner still accepts it on screen. */
static bool intent_pairing(JNIEnv *env, jobject activity, char *out, size_t cap)
{
    bool ok = false;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)clean(env); return false; }
    jobject intent = launch_intent(env, activity);
    jclass intent_cls = clean(env) && intent ? (*env)->GetObjectClass(env, intent) : NULL;
    jmethodID extra = intent_cls ? (*env)->GetMethodID(env, intent_cls, "getStringExtra", "(Ljava/lang/String;)Ljava/lang/String;") : NULL;
    jmethodID remove = intent_cls ? (*env)->GetMethodID(env, intent_cls, "removeExtra", "(Ljava/lang/String;)V") : NULL;
    jstring key = clean(env) ? (*env)->NewStringUTF(env, "org.z23.pair") : NULL;
    jstring value = clean(env) && extra && remove && key ? (*env)->CallObjectMethod(env, intent, extra, key) : NULL;
    ok = copy_utf(env, value, out, cap);
    if (value) (*env)->CallVoidMethod(env, intent, remove, key);
    (void)clean(env); (*env)->PopLocalFrame(env, NULL); return ok;
}
static bool release_surface(JNIEnv *env, jobject activity)
{
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)clean(env); return false; }
    bool ok = false;
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID get = cls ? (*env)->GetMethodID(env, cls, "getWindow", "()Landroid/view/Window;") : NULL;
    jobject window = get ? (*env)->CallObjectMethod(env, activity, get) : NULL;
    jclass win_class = window ? (*env)->GetObjectClass(env, window) : NULL;
    jmethodID take = win_class ? (*env)->GetMethodID(env, win_class, "takeSurface", "(Landroid/view/SurfaceHolder$Callback2;)V") : NULL;
    jmethodID flags = win_class ? (*env)->GetMethodID(env, win_class, "setFlags", "(II)V") : NULL;
    if (!clean(env) || !take || !flags) goto out;
    (*env)->CallVoidMethod(env, window, take, NULL);
    if (!clean(env)) goto out;
    (*env)->CallVoidMethod(env, window, flags, 0x01000000, 0x01000000);
    ok = clean(env);
out:
    (void)clean(env); (*env)->PopLocalFrame(env, NULL); return ok;
}
/* Releases activity-bound state. A relaunch creates the new activity before the old one is
 * destroyed, so the newest activity takes this state over and the old one skips it. */
static void detach_activity(JNIEnv *env)
{
    zapp_controller_detach();
    zapp_camera_set_frame_notify(NULL);
    zapp_camera_stop();
    pthread_mutex_lock(&lock);
    jobject retained = active; active = NULL; permission_ticket = 0;
    if (looper && signal_pipe[0] >= 0) ALooper_removeFd(looper, signal_pipe[0]);
    for (int i = 0; i < 2; ++i) { if (signal_pipe[i] >= 0) close(signal_pipe[i]); signal_pipe[i] = -1; }
    if (looper) ALooper_release(looper);
    looper = NULL;
    pthread_mutex_unlock(&lock);
    zapp_native_ui_destroy(env);
    if (retained) (*env)->DeleteGlobalRef(env, retained);
}
static void destroy(ANativeActivity *activity)
{
    JNIEnv *env = activity->env;
    pthread_mutex_lock(&lock);
    bool owner = active && (*env)->IsSameObject(env, active, activity->clazz);
    pthread_mutex_unlock(&lock);
    if (owner) detach_activity(env);
}
static void pause_activity(ANativeActivity *activity)
{
    (void)activity; foreground = false;
    zapp_controller_pause();
    zapp_camera_stop();
}
static void resume_activity(ANativeActivity *activity)
{
    foreground = true;
    refresh(activity->env);
}
JNIEXPORT void ANativeActivity_onCreate(ANativeActivity *activity, void *state, size_t state_size);
JNIEXPORT void ANativeActivity_onCreate(ANativeActivity *activity, void *state, size_t state_size)
{
    (void)state; (void)state_size;
    atomic_store(&vm, activity->vm);
    activity->callbacks->onDestroy = destroy;
    activity->callbacks->onPause = pause_activity;
    activity->callbacks->onResume = resume_activity;
    activity->callbacks->onInputQueueCreated = queue_created;
    activity->callbacks->onInputQueueDestroyed = queue_destroyed;
    JNIEnv *env = activity->env; char native_dir[4096]; bool preview = false;
    pthread_mutex_lock(&lock); bool previous = active != NULL; pthread_mutex_unlock(&lock);
    if (previous) detach_activity(env);
    if (!activity->internalDataPath || !native_directory(env, activity->clazz, native_dir, sizeof(native_dir))) goto fail;
    looper = ALooper_forThread();
    if (!looper) goto fail;
    ALooper_acquire(looper);
    if (pipe2(signal_pipe, O_CLOEXEC | O_NONBLOCK) ||
        ALooper_addFd(looper, signal_pipe[0], ALOOPER_POLL_CALLBACK, ALOOPER_EVENT_INPUT, signal_ready, NULL) != 1) goto fail;
    pthread_mutex_lock(&lock); active = (*env)->NewGlobalRef(env, activity->clazz); pthread_mutex_unlock(&lock);
    if (!clean(env) || !active || !release_surface(env, activity->clazz) ||
        !zapp_native_ui_package_preview(env, activity->clazz, &preview) ||
        !zapp_controller_start(activity->internalDataPath, native_dir, preview, notify) ||
        !zapp_native_ui_create(env, activity->clazz, action)) goto fail;
    zapp_camera_set_frame_notify(notify);
    char offer[256];
    if (intent_pairing(env, activity->clazz, offer, sizeof(offer))) {
        (void)zapp_controller_action("pair_offer", offer, "");
        memory_cleanse(offer, sizeof(offer));
    }
    refresh(env); return;
fail:
    (void)clean(env); ANativeActivity_finish(activity);
}
