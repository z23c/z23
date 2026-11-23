/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "review.h"
#include "share.h"
#include "jni_util.h"
#include "controller.h"
#include "operations.h"
#include "review_stage.h"
#include "review_result.h"
#include "review_event.h"
#include <android/looper.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <unistd.h>

enum review_phase { REVIEW_IDLE, REVIEW_PREPARED, REVIEW_PICKING, REVIEW_WORKING };
static pthread_mutex_t review_lock = PTHREAD_MUTEX_INITIALIZER;
static enum review_phase review_phase;
static bool review_return, review_alias_known;
static char review_status[512] = "Review a signed file without starting the node.";

struct review_job {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    JavaVM *vm;
    jobject activity, uri, cancellation;
    ALooper *looper;
    int wake[2], timer;
    pthread_t thread;
    uintptr_t generation;
    bool decided, proceed, opened, attach_failed, wake_failed, timeout_reported, wake_active, timer_active;
    atomic_bool cancel;
};
static struct review_job *review_job;
static uintptr_t review_generation;
static void review_job_free(JNIEnv *env, struct review_job *job);

static void review_message(const char *text, bool finished)
{
    pthread_mutex_lock(&review_lock);
    snprintf(review_status, sizeof(review_status), "%s", text);
    if (finished) review_phase = REVIEW_IDLE;
    pthread_mutex_unlock(&review_lock);
}

bool zapp_review_prepare(void)
{
    pthread_mutex_lock(&review_lock);
    bool ok = review_phase == REVIEW_IDLE && !zapp_share_busy();
    if (ok) {
        review_phase = REVIEW_PREPARED;
        review_alias_known = true;
        review_return = false;
        snprintf(review_status, sizeof(review_status), "Choose a signed app file. The node is not needed.");
    }
    pthread_mutex_unlock(&review_lock);
    return ok;
}
void zapp_review_abandon(void)
{
    pthread_mutex_lock(&review_lock);
    review_phase = REVIEW_IDLE;
    review_return = true;
    snprintf(review_status, sizeof(review_status), "Could not open the file picker. Try again.");
    pthread_mutex_unlock(&review_lock);
}
bool zapp_review_is_pending(void)
{
    pthread_mutex_lock(&review_lock);
    bool pending = review_phase != REVIEW_IDLE;
    pthread_mutex_unlock(&review_lock);
    return pending;
}
void zapp_review_snapshot(char *out, size_t cap)
{
    if (!out || !cap) return;
    pthread_mutex_lock(&review_lock);
    snprintf(out, cap, "%s", review_status);
    pthread_mutex_unlock(&review_lock);
}
bool zapp_review_take_return(void)
{
    pthread_mutex_lock(&review_lock);
    bool result = review_return;
    review_return = false;
    pthread_mutex_unlock(&review_lock);
    return result;
}

bool zapp_review_is_activity(JNIEnv *env, jobject activity)
{
    jobject intent = zj_object_property(env, activity, "getIntent", "()Landroid/content/Intent;");
    jobject component = intent ? zj_object_property(env, intent, "getComponent", "()Landroid/content/ComponentName;") : NULL;
    jstring name = component ? zj_object_property(env, component, "getClassName", "()Ljava/lang/String;") : NULL;
    char text[128];
    bool result = name && zj_copy_utf(env, name, text, sizeof(text)) && !strcmp(text, "org.z23.nativeapp.ReviewActivity");
    if (name) (*env)->DeleteLocalRef(env, name);
    if (component) (*env)->DeleteLocalRef(env, component);
    if (intent) (*env)->DeleteLocalRef(env, intent);
    return result;
}

static bool review_waiting_view(JNIEnv *env, jobject activity)
{
    jobject text = zj_widget(env, "android/widget/TextView", activity);
    bool ok = text && zj_typography(env, text, 18.0f, (jint)0xffffffffu) &&
        zj_padding(env, text, 24, 24) && zj_text(env, text, "Opening the file… Press Back to cancel.");
    jmethodID set = ok ? zj_method(env, activity, "setContentView", "(Landroid/view/View;)V") : NULL;
    if (set) (*env)->CallVoidMethod(env, activity, set, text);
    bool clean = zj_clean(env);
    if (text) (*env)->DeleteLocalRef(env, text);
    return ok && set && clean;
}

bool zapp_review_begin(JNIEnv *env, jobject activity)
{
    pthread_mutex_lock(&review_lock);
    bool start = review_phase == REVIEW_PREPARED;
    bool active = review_phase != REVIEW_IDLE;
    bool working = review_phase == REVIEW_WORKING;
    bool decided = false;
    if (review_job) {
        jobject next = (*env)->NewGlobalRef(env, activity);
        bool clean = zj_clean(env);
        if (!next || !clean) {
            if (next) (*env)->DeleteGlobalRef(env, next);
            active = false;
        }
        else {
            pthread_mutex_lock(&review_job->lock);
            decided = review_job->decided;
            jobject previous = review_job->activity;
            review_job->activity = next;
            pthread_mutex_unlock(&review_job->lock);
            if (previous) (*env)->DeleteGlobalRef(env, previous);
        }
    }
    if (start) review_phase = REVIEW_PICKING;
    pthread_mutex_unlock(&review_lock);
    if (!start) {
        if (!active) {
            pthread_mutex_lock(&review_lock);
            review_return = true;
            if (!review_alias_known) snprintf(review_status, sizeof(review_status), "Review was interrupted. Choose the file again.");
            pthread_mutex_unlock(&review_lock);
        }
        return active && !decided && (!working || review_waiting_view(env, activity));
    }
    if ((*env)->PushLocalFrame(env, 12) != JNI_OK) { zapp_review_abandon(); return false; }
    jclass cls = (*env)->FindClass(env, "android/content/Intent");
    jmethodID ctor = cls ? (*env)->GetMethodID(env, cls, "<init>", "(Ljava/lang/String;)V") : NULL;
    jstring action = ctor ? zj_string(env, "android.intent.action.OPEN_DOCUMENT") : NULL;
    jobject intent = action ? (*env)->NewObject(env, cls, ctor, action) : NULL;
    jmethodID category = intent ? zj_method(env, intent, "addCategory", "(Ljava/lang/String;)Landroid/content/Intent;") : NULL;
    jstring openable = category ? zj_string(env, "android.intent.category.OPENABLE") : NULL;
    if (openable) (*env)->CallObjectMethod(env, intent, category, openable);
    jmethodID type = intent ? zj_method(env, intent, "setType", "(Ljava/lang/String;)Landroid/content/Intent;") : NULL;
    jstring mime = type ? zj_string(env, "*/*") : NULL;
    if (mime) (*env)->CallObjectMethod(env, intent, type, mime);
    jmethodID start_method = intent ? zj_method(env, activity, "startActivityForResult", "(Landroid/content/Intent;I)V") : NULL;
    if (start_method && openable && mime) (*env)->CallVoidMethod(env, activity, start_method, intent, ZAPP_REVIEW_PICK_REQUEST);
    bool clean = zj_clean(env);
    bool ok = start_method && openable && mime && clean;
    (*env)->PopLocalFrame(env, NULL);
    if (!ok) zapp_review_abandon();
    return ok;
}

static JNIEnv *review_env(struct review_job *job)
{
    JNIEnv *env = NULL;
    return (*job->vm)->GetEnv(job->vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK ? env : NULL;
}
static void review_finish(JNIEnv *env, struct review_job *job)
{
    pthread_mutex_lock(&job->lock);
    jobject activity = job->activity ? (*env)->NewLocalRef(env, job->activity) : NULL;
    pthread_mutex_unlock(&job->lock);
    jmethodID method = activity ? zj_method(env, activity, "finish", "()V") : NULL;
    if (method) (*env)->CallVoidMethod(env, activity, method);
    (void)zj_clean(env);
    if (activity) (*env)->DeleteLocalRef(env, activity);
}
static bool review_still_open(JNIEnv *env, struct review_job *job)
{
    pthread_mutex_lock(&job->lock);
    jobject activity = job->activity ? (*env)->NewLocalRef(env, job->activity) : NULL;
    pthread_mutex_unlock(&job->lock);
    jmethodID method = activity ? zj_method(env, activity, "isFinishing", "()Z") : NULL;
    jboolean finishing = method ? (*env)->CallBooleanMethod(env, activity, method) : JNI_TRUE;
    bool ok = zj_clean(env) && method && !finishing;
    if (activity) (*env)->DeleteLocalRef(env, activity);
    return ok;
}
static int review_ready(int fd, int events, void *opaque)
{
    (void)events;
    pthread_mutex_lock(&review_lock);
    struct review_job *job = review_job;
    if (!job || !zapp_review_event_matches(job->generation, job->wake_active, job->wake[0], (uintptr_t)opaque, fd)) {
        pthread_mutex_unlock(&review_lock);
        return 1;
    }
    job->wake_active = false;
    ALooper_removeFd(job->looper, fd);
    char byte;
    (void)read(fd, &byte, 1);
    JNIEnv *env = review_env(job);
    pthread_mutex_lock(&job->lock);
    bool opened = job->opened;
    bool attach_failed = job->attach_failed;
    pthread_mutex_unlock(&job->lock);
    bool canceled = atomic_load(&job->cancel);
    bool proceed = opened && env && !canceled && review_still_open(env, job);
    if (!proceed) atomic_store(&job->cancel, true);
    if (job->timer_active) {
        job->timer_active = false;
        ALooper_removeFd(job->looper, job->timer);
        close(job->timer);
        job->timer = -1;
    }
    review_return = true;
    if (proceed) snprintf(review_status, sizeof(review_status), "Checking the signed file. The node is not needed.");
    else if (!canceled) snprintf(review_status, sizeof(review_status), "Review canceled or the file could not be opened.");
    if (env) review_finish(env, job);
    if (attach_failed && env) {
        pthread_mutex_unlock(&review_lock);
        (void)pthread_join(job->thread, NULL);
        review_job_free(env, job);
        return 1;
    }
    pthread_mutex_lock(&job->lock);
    job->proceed = proceed;
    job->decided = true;
    pthread_cond_signal(&job->changed);
    pthread_mutex_unlock(&job->lock);
    pthread_mutex_unlock(&review_lock);
    return 1;
}
static int review_timeout(int fd, int events, void *opaque)
{
    (void)events;
    pthread_mutex_lock(&review_lock);
    struct review_job *job = review_job;
    if (!job || !zapp_review_event_matches(job->generation, job->timer_active, job->timer, (uintptr_t)opaque, fd)) {
        pthread_mutex_unlock(&review_lock);
        return 1;
    }
    uint64_t elapsed;
    (void)read(fd, &elapsed, sizeof(elapsed));
    bool first = !job->timeout_reported;
    job->timeout_reported = true;
    atomic_store(&job->cancel, true);
    JNIEnv *env = review_env(job);
    if (env && first) {
        jmethodID cancel = zj_method(env, job->cancellation, "cancel", "()V");
        if (cancel) (*env)->CallVoidMethod(env, job->cancellation, cancel);
        (void)zj_clean(env);
        review_finish(env, job);
    }
    if (first) {
        review_return = true;
        snprintf(review_status, sizeof(review_status), "Opening the file timed out. Try again after the file provider responds.");
    }
    pthread_mutex_lock(&job->lock);
    bool wake_failed = job->wake_failed, attach_failed = job->attach_failed;
    pthread_mutex_unlock(&job->lock);
    if (!wake_failed || (attach_failed && !env)) { pthread_mutex_unlock(&review_lock); return 1; }
    job->wake_active = false;
    ALooper_removeFd(job->looper, job->wake[0]);
    job->timer_active = false;
    ALooper_removeFd(job->looper, job->timer);
    close(job->timer);
    job->timer = -1;
    if (attach_failed) {
        pthread_mutex_unlock(&review_lock);
        (void)pthread_join(job->thread, NULL);
        review_job_free(env, job);
        return 1;
    }
    pthread_mutex_lock(&job->lock);
    job->decided = true;
    job->proceed = false;
    pthread_cond_signal(&job->changed);
    pthread_mutex_unlock(&job->lock);
    pthread_mutex_unlock(&review_lock);
    return 1;
}

static void review_wake(struct review_job *job)
{
    char byte = 1;
    ssize_t n;
    do n = write(job->wake[1], &byte, 1); while (n < 0 && errno == EINTR);
    if (n == 1) return;
    pthread_mutex_lock(&job->lock);
    job->wake_failed = true;
    pthread_mutex_unlock(&job->lock);
}

static int review_open(JNIEnv *env, struct review_job *job)
{
    pthread_mutex_lock(&job->lock);
    jobject activity = job->activity ? (*env)->NewLocalRef(env, job->activity) : NULL;
    pthread_mutex_unlock(&job->lock);
    jobject resolver = activity ? zj_object_property(env, activity, "getContentResolver", "()Landroid/content/ContentResolver;") : NULL;
    jmethodID open_method = resolver ? zj_method(env, resolver, "openFileDescriptor",
        "(Landroid/net/Uri;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/os/ParcelFileDescriptor;") : NULL;
    jstring mode = open_method ? zj_string(env, "r") : NULL;
    jobject parcel = mode ? (*env)->CallObjectMethod(env, resolver, open_method, job->uri, mode, job->cancellation) : NULL;
    bool clean = zj_clean(env);
    jmethodID detach = clean && parcel ? zj_method(env, parcel, "detachFd", "()I") : NULL;
    jint fd = detach ? (*env)->CallIntMethod(env, parcel, detach) : -1;
    if (!zj_clean(env)) fd = -1;
    if (parcel) (*env)->DeleteLocalRef(env, parcel);
    if (mode) (*env)->DeleteLocalRef(env, mode);
    if (resolver) (*env)->DeleteLocalRef(env, resolver);
    if (activity) (*env)->DeleteLocalRef(env, activity);
    return fd;
}
static void review_job_free(JNIEnv *env, struct review_job *job)
{
    pthread_mutex_lock(&review_lock);
    review_job = NULL;
    review_phase = REVIEW_IDLE;
    pthread_mutex_unlock(&review_lock);
    if (job->activity) (*env)->DeleteGlobalRef(env, job->activity);
    if (job->uri) (*env)->DeleteGlobalRef(env, job->uri);
    if (job->cancellation) (*env)->DeleteGlobalRef(env, job->cancellation);
    close(job->wake[0]);
    close(job->wake[1]);
    ALooper_release(job->looper);
    pthread_cond_destroy(&job->changed);
    pthread_mutex_destroy(&job->lock);
    free(job);
}
static void *review_worker(void *opaque)
{
    struct review_job *job = opaque;
    JNIEnv *env = NULL;
    if ((*job->vm)->AttachCurrentThread(job->vm, &env, NULL) != JNI_OK) {
        pthread_mutex_lock(&job->lock);
        job->attach_failed = true;
        pthread_mutex_unlock(&job->lock);
        review_wake(job);
        return NULL;
    }
    (void)pthread_detach(pthread_self());
    int input = review_open(env, job);
    pthread_mutex_lock(&job->lock);
    job->opened = input >= 0;
    pthread_mutex_unlock(&job->lock);
    review_wake(job);
    pthread_mutex_lock(&job->lock);
    while (!job->decided) pthread_cond_wait(&job->changed, &job->lock);
    bool proceed = job->proceed;
    pthread_mutex_unlock(&job->lock);
    if (proceed) {
        char path[1200], response[ZAPP_REVIEW_OUTPUT_MIN], display[512];
        bool ready = zapp_controller_review_path(path, sizeof(path));
        char *separator = ready ? strrchr(path, '/') : NULL;
        if (separator) {
            *separator = 0;
            ready = zapp_review_stage_cleanup(path);
            *separator = '/';
        } else ready = false;
        int output = ready ? mkstemp(path) : -1;
        enum zapp_review_stage stage = output >= 0 ?
            zapp_review_stage_copy(input, output, 64u * 1024u * 1024u, 30000, &job->cancel) : ZAPP_STAGE_UNAVAILABLE;
        if (output >= 0 && close(output)) stage = ZAPP_STAGE_UNAVAILABLE;
        int result = stage == ZAPP_STAGE_OK ? zapp_controller_review_run(path, response, sizeof(response), &job->cancel) : ZAPP_REVIEW_UNAVAILABLE;
        if (output >= 0) (void)unlink(path);
        if (result == ZAPP_REVIEW_OK && zapp_review_result_text(response, display, sizeof(display))) review_message(display, false);
        else if (result == ZAPP_REVIEW_OK) review_message("The verifier did not return complete identity details. Nothing was run.", false);
        else if (result == ZAPP_REVIEW_CANCELED || stage == ZAPP_STAGE_CANCELED) review_message("Review canceled. Nothing was run.", false);
        else if (stage == ZAPP_STAGE_EMPTY) review_message("The selected file is empty. Choose a signed app file.", false);
        else if (stage == ZAPP_STAGE_TOO_LARGE) review_message("The selected file is too large to review (64 MiB maximum).", false);
        else if (stage != ZAPP_STAGE_OK || result == ZAPP_REVIEW_FILE_UNAVAILABLE) review_message("Could not read or stage the file. Check private storage and try again.", false);
        else if (result == ZAPP_REVIEW_REFUSED) review_message("Could not verify this signed file. Nothing was run.", false);
        else review_message("The verifier could not start or finish. Try a full Z23 build and review again.", false);
    }
    if (input >= 0) close(input);
    JavaVM *vm = job->vm;
    review_job_free(env, job);
    (*vm)->DetachCurrentThread(vm);
    return NULL;
}

static bool review_content_uri(JNIEnv *env, jobject uri)
{
    jstring scheme = uri ? zj_object_property(env, uri, "getScheme", "()Ljava/lang/String;") : NULL;
    char text[32];
    bool ok = scheme && zj_copy_utf(env, scheme, text, sizeof(text)) && !strcmp(text, "content");
    if (scheme) (*env)->DeleteLocalRef(env, scheme);
    return ok;
}
static void review_picker_failure(const char *text)
{
    pthread_mutex_lock(&review_lock);
    review_phase = REVIEW_IDLE;
    review_return = true;
    snprintf(review_status, sizeof(review_status), "%s", text);
    pthread_mutex_unlock(&review_lock);
}

bool zapp_review_picker_result(JNIEnv *env, jobject activity, jint result, jobject data)
{
    pthread_mutex_lock(&review_lock);
    bool picking = review_phase == REVIEW_PICKING;
    pthread_mutex_unlock(&review_lock);
    if (!picking) return true;
    if (result != -1 || !data) {
        review_picker_failure("Review canceled. Nothing was run.");
        return true;
    }
    jobject uri = zj_object_property(env, data, "getData", "()Landroid/net/Uri;");
    if (!review_content_uri(env, uri)) {
        if (uri) (*env)->DeleteLocalRef(env, uri);
        review_picker_failure("Could not open the selected file. Choose a file from the picker.");
        return true;
    }
    if (!review_waiting_view(env, activity)) {
        (*env)->DeleteLocalRef(env, uri);
        review_picker_failure("Could not start file review. Try again.");
        return true;
    }
    struct review_job *job = calloc(1, sizeof(*job));
    if (!job) {
        (*env)->DeleteLocalRef(env, uri);
        review_picker_failure("Could not start file review. Try again.");
        return true;
    }
    job->wake[0] = job->wake[1] = job->timer = -1;
    if (pthread_mutex_init(&job->lock, NULL)) {
        (*env)->DeleteLocalRef(env, uri);
        free(job);
        review_picker_failure("Could not start file review. Try again.");
        return true;
    }
    if (pthread_cond_init(&job->changed, NULL)) {
        (*env)->DeleteLocalRef(env, uri);
        pthread_mutex_destroy(&job->lock);
        free(job);
        review_picker_failure("Could not start file review. Try again.");
        return true;
    }
    atomic_init(&job->cancel, false);
    pthread_mutex_lock(&review_lock);
    bool generation_ok = review_generation != UINTPTR_MAX;
    if (generation_ok) job->generation = ++review_generation;
    pthread_mutex_unlock(&review_lock);
    job->activity = (*env)->NewGlobalRef(env, activity);
    job->uri = (*env)->NewGlobalRef(env, uri);
    (*env)->DeleteLocalRef(env, uri);
    jclass cls = (*env)->FindClass(env, "android/os/CancellationSignal");
    jmethodID ctor = cls ? (*env)->GetMethodID(env, cls, "<init>", "()V") : NULL;
    jobject signal = ctor ? (*env)->NewObject(env, cls, ctor) : NULL;
    job->cancellation = signal ? (*env)->NewGlobalRef(env, signal) : NULL;
    if (signal) (*env)->DeleteLocalRef(env, signal);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    bool clean = zj_clean(env);
    bool ok = generation_ok && clean && job->activity && job->uri && job->cancellation &&
        (*env)->GetJavaVM(env, &job->vm) == JNI_OK && (job->looper = ALooper_forThread());
    if (ok) {
        ALooper_acquire(job->looper);
        ok = pipe(job->wake) == 0 && fcntl(job->wake[0], F_SETFL, O_NONBLOCK) == 0 && fcntl(job->wake[0], F_SETFD, FD_CLOEXEC) == 0 &&
             fcntl(job->wake[1], F_SETFD, FD_CLOEXEC) == 0 &&
             ALooper_addFd(job->looper, job->wake[0], ALOOPER_POLL_CALLBACK, ALOOPER_EVENT_INPUT, review_ready, (void *)job->generation) == 1;
        job->wake_active = ok;
    }
    if (ok) {
        job->timer = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
        struct itimerspec expiry = {.it_value = {.tv_sec = 30}, .it_interval = {.tv_sec = 1}};
        ok = job->timer >= 0 && timerfd_settime(job->timer, 0, &expiry, NULL) == 0 &&
             ALooper_addFd(job->looper, job->timer, ALOOPER_POLL_CALLBACK, ALOOPER_EVENT_INPUT, review_timeout, (void *)job->generation) == 1;
        job->timer_active = ok;
    }
    if (ok) {
        pthread_mutex_lock(&review_lock);
        review_job = job;
        review_phase = REVIEW_WORKING;
        snprintf(review_status, sizeof(review_status), "Opening the file. The node is not needed.");
        pthread_mutex_unlock(&review_lock);
        ok = pthread_create(&job->thread, NULL, review_worker, job) == 0;
    }
    if (ok) return false;
    if (job->looper) {
        if (job->wake_active) { job->wake_active = false; ALooper_removeFd(job->looper, job->wake[0]); }
        if (job->timer_active) { job->timer_active = false; ALooper_removeFd(job->looper, job->timer); }
    }
    if (job->timer >= 0) close(job->timer);
    if (job->looper) review_job_free(env, job);
    else {
        if (job->activity) (*env)->DeleteGlobalRef(env, job->activity);
        if (job->uri) (*env)->DeleteGlobalRef(env, job->uri);
        if (job->cancellation) (*env)->DeleteGlobalRef(env, job->cancellation);
        pthread_cond_destroy(&job->changed);
        pthread_mutex_destroy(&job->lock);
        free(job);
    }
    review_picker_failure("Could not start file review. Try again.");
    return true;
}
