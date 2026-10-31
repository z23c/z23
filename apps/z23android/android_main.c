/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "app.h"
#include "base/cleanse.h"
#include "camera.h"
#include "clip_screen.h"
#include "controller.h"
#ifdef ZAPP_DEVKEY_PROBE
#include "device_key_probe.h"
#endif
#include "native_ui.h"
#include "node_service.h"
#include "secure_window.h"
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
/* The saved Start node choice has been put to the background-network dialog. */
static bool background_asked;
/* The camera permission dialog is up: the pause it causes must not cancel the scan waiting on it. */
static atomic_bool camera_dialog;
/* The dialog closed without the permission. */
static atomic_bool camera_denied;
/* The foreground service that keeps the node's process above hidden-app priority is running. */
static bool node_service_on;
/* Notifications were requested once; the service works without them. */
static bool notifications_asked;
/* A failed service start is not retried before this CLOCK_MONOTONIC second. */
static time_t service_retry_at;
static bool microphone_allowed(JNIEnv *env, jobject activity);
static void request_permission(JNIEnv *env, jobject activity, const char *name);

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
/* True when the app is already exempt from battery optimization, or when that cannot be read. */
static bool background_exempt(JNIEnv *env, jobject activity, jstring package)
{
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID service = cls ? (*env)->GetMethodID(env, cls, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;") : NULL;
    jstring power_name = clean(env) ? (*env)->NewStringUTF(env, "power") : NULL;
    jobject power = clean(env) && service && power_name ? (*env)->CallObjectMethod(env, activity, service, power_name) : NULL;
    jclass power_cls = clean(env) && power ? (*env)->GetObjectClass(env, power) : NULL;
    jmethodID ignoring = power_cls ? (*env)->GetMethodID(env, power_cls, "isIgnoringBatteryOptimizations", "(Ljava/lang/String;)Z") : NULL;
    bool exempt = !clean(env) || !ignoring || (*env)->CallBooleanMethod(env, power, ignoring, package);
    return !clean(env) || exempt;
}
/* package:<name> as an android.net.Uri, or NULL. */
static jobject package_uri(JNIEnv *env, jstring package)
{
    jclass cls = (*env)->FindClass(env, "android/net/Uri");
    jmethodID parts = clean(env) && cls ? (*env)->GetStaticMethodID(env, cls, "fromParts",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;") : NULL;
    jstring scheme = clean(env) ? (*env)->NewStringUTF(env, "package") : NULL;
    jobject uri = clean(env) && parts && scheme ? (*env)->CallStaticObjectMethod(env, cls, parts, scheme, package, NULL) : NULL;
    return clean(env) ? uri : NULL;
}
/* The system dialog that exempts package from battery optimization, as an Intent, or NULL. */
static jobject background_request(JNIEnv *env, jstring package)
{
    jobject uri = package_uri(env, package);
    jclass cls = uri ? (*env)->FindClass(env, "android/content/Intent") : NULL;
    jmethodID ctor = clean(env) && cls ? (*env)->GetMethodID(env, cls, "<init>", "(Ljava/lang/String;Landroid/net/Uri;)V") : NULL;
    jstring action = clean(env) ? (*env)->NewStringUTF(env, "android.settings.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS") : NULL;
    jobject intent = clean(env) && ctor && action ? (*env)->NewObject(env, cls, ctor, action, uri) : NULL;
    return clean(env) ? intent : NULL;
}
/* Android withholds the network from a hidden app and from the node it started,
 * unless the owner lets the app run in the background; ask through the system dialog. */
static void allow_background_network(JNIEnv *env, jobject activity)
{
    if ((*env)->PushLocalFrame(env, 16) != JNI_OK) { (void)clean(env); return; }
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID name = cls ? (*env)->GetMethodID(env, cls, "getPackageName", "()Ljava/lang/String;") : NULL;
    jmethodID start = clean(env) && cls ? (*env)->GetMethodID(env, cls, "startActivity", "(Landroid/content/Intent;)V") : NULL;
    jstring package = clean(env) && name ? (*env)->CallObjectMethod(env, activity, name) : NULL;
    jobject intent = clean(env) && package && start && !background_exempt(env, activity, package) ?
        background_request(env, package) : NULL;
    if (intent) (*env)->CallVoidMethod(env, activity, start, intent);
    (void)clean(env); (*env)->PopLocalFrame(env, NULL);
}
static bool permission_held(JNIEnv *env, jobject activity, const char *name)
{
    if ((*env)->PushLocalFrame(env, 4) != JNI_OK) { (void)clean(env); return false; }
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID check = cls ? (*env)->GetMethodID(env, cls, "checkSelfPermission", "(Ljava/lang/String;)I") : NULL;
    jstring permission = (*env)->NewStringUTF(env, name);
    bool granted = clean(env) && check && permission && (*env)->CallIntMethod(env, activity, check, permission) == 0;
    (void)clean(env); (*env)->PopLocalFrame(env, NULL);
    return granted;
}
/* While the node process runs and the app is visible, run the foreground service that keeps the
 * process out of the hidden-app kill class; stop it once the node has exited. */
static void sync_node_service(JNIEnv *env, const struct zapp_view *view)
{
    struct timespec now;
    if (!active) return;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (node_service_on && zapp_node_service_ended()) node_service_on = false;
    if (!node_service_on && foreground && view->node_process_running && now.tv_sec >= service_retry_at) {
        if (!notifications_asked && !permission_held(env, active, "android.permission.POST_NOTIFICATIONS")) {
            notifications_asked = true; request_permission(env, active, "android.permission.POST_NOTIFICATIONS");
        }
        node_service_on = zapp_node_service_start(env, active);
        if (!node_service_on) service_retry_at = now.tv_sec + 60;
    } else if (node_service_on && !view->node_process_running) {
        zapp_node_service_stop(env, active); node_service_on = false;
    }
}
static void refresh(JNIEnv *env)
{
    struct zapp_view *view = calloc(1, sizeof(*view));
    if (!view) return;
    zapp_controller_snapshot(view);
    zapp_native_ui_render(env, view);
    sync_node_service(env, view);
    if (!view->node_wanted) background_asked = false;
    else if (foreground && active && !background_asked) {
        background_asked = true; allow_background_network(env, active);
    }
    unsigned char *bmp = NULL; size_t size = 0;
    (void)zapp_camera_preview(&bmp, &size);
    zapp_native_ui_preview(env, bmp, size); free(bmp);
    free(view);
}
static void action(const char *name, const char *argument)
{
    JNIEnv *env = NULL; JavaVM *current_vm = atomic_load(&vm);
    if (!current_vm || (*current_vm)->GetEnv(current_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) env = NULL;
    if (!strcmp(name, "voice_start") && (!foreground || !env || !active || !microphone_allowed(env, active))) return;
    if (!zapp_controller_action(name, argument, "")) {
        if (env) zapp_native_ui_update(env, NULL, "Unable to start that action.");
        return;
    }
    notify();
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
    if (activity && request) { atomic_store(&camera_dialog, true); request_permission(env, activity, "android.permission.CAMERA"); }
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
        if (zapp_secure_window_drops(event)) { AInputQueue_finishEvent(queue, event, true); continue; }
        bool taken = zapp_clip_screen_input(env, event) || zapp_native_ui_input(env, event);
        AInputQueue_finishEvent(queue, event, taken);
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
        if (!alive || atomic_load(&camera_denied)) break;
        bool granted = (*env)->CallIntMethod(env, activity, check, permission) == 0;
        if (!clean(env)) break;
        if (granted && !atomic_load(&camera_dialog)) return true;
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
    atomic_store(&camera_denied, false);
    atomic_store(&camera_dialog, false);
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
/* Reads the org.z23.clips launch extra and removes it from the in-process intent, so a later resume or
 * configuration change does not see it. After the process is killed the system can deliver the original
 * intent again; the screen then returns with the camera closed. False when the extra is absent. */
static bool take_clips_extra(JNIEnv *env, jobject intent, char *out, size_t cap)
{
    jclass intent_cls = clean(env) && intent ? (*env)->GetObjectClass(env, intent) : NULL;
    jmethodID extra = intent_cls ? (*env)->GetMethodID(env, intent_cls, "getStringExtra", "(Ljava/lang/String;)Ljava/lang/String;") : NULL;
    jmethodID remove = intent_cls ? (*env)->GetMethodID(env, intent_cls, "removeExtra", "(Ljava/lang/String;)V") : NULL;
    jstring key = clean(env) ? (*env)->NewStringUTF(env, "org.z23.clips") : NULL;
    jstring value = clean(env) && extra && remove && key ? (*env)->CallObjectMethod(env, intent, extra, key) : NULL;
    bool ok = copy_utf(env, value, out, cap);
    if (value) (*env)->CallVoidMethod(env, intent, remove, key);
    return ok;
}
/* Opens the clips screen named by the org.z23.clips launch extra: record or watch. */
static void intent_clips(JNIEnv *env, jobject activity, const char *files)
{
    char word[16];
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)clean(env); return; }
    if (take_clips_extra(env, launch_intent(env, activity), word, sizeof(word)) && (!strcmp(word, "record") || !strcmp(word, "watch")))
        (void)zapp_clip_screen_open(env, activity, files, strcmp(word, "record") ? ZAPP_CLIP_WATCH : ZAPP_CLIP_RECORD);
    (void)clean(env); (*env)->PopLocalFrame(env, NULL);
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
/* Asks the activity that still owns the state to close; the newest activity takes over. */
static void finish_previous(JNIEnv *env)
{
    pthread_mutex_lock(&lock); jobject old = active ? (*env)->NewLocalRef(env, active) : NULL; pthread_mutex_unlock(&lock);
    if (!old) return;
    jclass cls = (*env)->GetObjectClass(env, old);
    jmethodID finish = cls ? (*env)->GetMethodID(env, cls, "finish", "()V") : NULL;
    if (finish) (*env)->CallVoidMethod(env, old, finish);
    (void)clean(env);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    (*env)->DeleteLocalRef(env, old);
}
/* Releases activity-bound state. A relaunch creates the new activity before the old one is
 * destroyed, so the newest activity takes this state over and the old one skips it. */
static void detach_activity(JNIEnv *env)
{
    zapp_clip_screen_close(env);
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
    zapp_secure_window_release();
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
#ifdef ZAPP_DEVKEY_PROBE
    zapp_devkey_probe(activity, ZAPP_DEVKEY_PROBE_PAUSE);
#endif
    foreground = false;
    zapp_clip_screen_pause(activity->env);
    zapp_controller_visible(false);
    if (!atomic_load(&camera_dialog)) zapp_camera_stop();
}
static void focus_changed(ANativeActivity *activity, int focused)
{
    if (focused) zapp_native_ui_focus(activity->env);
}
static void resume_activity(ANativeActivity *activity)
{
    if (atomic_exchange(&camera_dialog, false) && !permission_held(activity->env, activity->clazz, "android.permission.CAMERA"))
        atomic_store(&camera_denied, true);
    pthread_mutex_lock(&lock);
    bool owner = active && (*activity->env)->IsSameObject(activity->env, active, activity->clazz);
    pthread_mutex_unlock(&lock);
    if (!owner) { ANativeActivity_finish(activity); return; }
    foreground = true;
    zapp_clip_screen_resume(activity->env);
    zapp_controller_visible(true);
    zapp_native_ui_resume(activity->env);
    refresh(activity->env);
#ifdef ZAPP_DEVKEY_PROBE
    zapp_devkey_probe(activity, ZAPP_DEVKEY_PROBE_RESUME);
#endif
}
JNIEXPORT void ANativeActivity_onCreate(ANativeActivity *activity, void *state, size_t state_size);
JNIEXPORT void ANativeActivity_onCreate(ANativeActivity *activity, void *state, size_t state_size)
{
    (void)state; (void)state_size;
    atomic_store(&vm, activity->vm);
    activity->callbacks->onDestroy = destroy;
    activity->callbacks->onPause = pause_activity;
    activity->callbacks->onResume = resume_activity;
    activity->callbacks->onWindowFocusChanged = focus_changed;
    activity->callbacks->onInputQueueCreated = queue_created;
    activity->callbacks->onInputQueueDestroyed = queue_destroyed;
    JNIEnv *env = activity->env; char native_dir[4096]; bool preview = false;
    pthread_mutex_lock(&lock); bool previous = active != NULL; pthread_mutex_unlock(&lock);
    if (previous) { finish_previous(env); detach_activity(env); }
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
    intent_clips(env, activity->clazz, activity->internalDataPath);
    refresh(env); return;
fail:
    (void)clean(env); ANativeActivity_finish(activity);
}
