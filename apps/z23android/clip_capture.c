/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "clip_capture.h"
#include <stdlib.h>
#include <string.h>

const struct zapp_clip_profile zapp_clip_profile = {
    .coded_width = 854, .coded_height = 480, .fps = 30, .video_bps = 800000, .keyframe_seconds = 2,
    .audio_rate = 48000, .audio_channels = 1, .audio_bps = 64000, .max_ms = 60000,
};

/* ImageFormat.PRIVATE and the Android thermal status CRITICAL. */
enum { FORMAT_PRIVATE = 0x22, THERMAL_CRITICAL = 4, AAC_FRAME_SAMPLES = 1024 };

int zapp_clip_pick_encoder(const struct zapp_codec_info *list, size_t count)
{
    for (size_t i = 0; list != NULL && i < count; ++i)
        if (list[i].encoder && list[i].hardware && list[i].avc) return (int)i;
    return -1;
}

bool zapp_clip_thermal_track(enum zapp_pace *pace, int thermal_status)
{
    *pace = zapp_pace_next(*pace, thermal_status);
    return *pace != ZAPP_PACE_PAUSE;
}

bool zapp_clip_thermal_stops(int thermal_status)
{
    return thermal_status >= THERMAL_CRITICAL;
}

bool zapp_clip_time_up(int64_t elapsed_ms)
{
    return elapsed_ms >= zapp_clip_profile.max_ms;
}

int zapp_clip_rotation_hint(int sensor_orientation)
{
    int degrees = ((sensor_orientation % 360) + 360) % 360;
    return (degrees + 45) / 90 % 4 * 90;
}

static int distance(int width, int height)
{
    return abs(width - zapp_clip_profile.coded_width) + abs(height - zapp_clip_profile.coded_height);
}

bool zapp_clip_pick_size(const int32_t *configs, size_t count, int *width, int *height)
{
    int best = -1;
    for (size_t i = 0; configs != NULL && i + 3 < count; i += 4) {
        int w = configs[i + 1], h = configs[i + 2];
        bool landscape = h > 0 && w * 10 >= h * 16 && w * 10 <= h * 19;
        if (configs[i] != FORMAT_PRIVATE || configs[i + 3] != 0 || !landscape) continue;
        if (best < 0 || distance(w, h) < best) { best = distance(w, h); *width = w; *height = h; }
    }
    return best >= 0;
}

int64_t zapp_clip_sample_end_us(bool video, int64_t pts_us)
{
    const struct zapp_clip_profile *p = &zapp_clip_profile;
    return pts_us + (video ? 1000000 / p->fps : (int64_t)AAC_FRAME_SAMPLES * 1000000 / p->audio_rate);
}

int64_t zapp_clip_span_ms(int64_t first_us, int64_t end_us)
{
    return first_us >= 0 && end_us > first_us ? (end_us - first_us + 500) / 1000 : 0;
}

int64_t zapp_clip_bitrate_kbps(int64_t bytes, int64_t duration_ms)
{
    return duration_ms > 0 ? bytes * 8 / duration_ms : 0;
}

#ifdef __ANDROID__
#include <aaudio/AAudio.h>
#include <android/log.h>
#include <camera/NdkCameraManager.h>
#include <fcntl.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaFormat.h>
#include <media/NdkMediaMuxer.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define TAG "z23"
#define PENDING_SAMPLES 256
#define PENDING_BYTES (512 * 1024)
#define AUDIO_BLOCK_FRAMES 1024
#define DRAIN_TIMEOUT_US 2000000
#define COLOR_FORMAT_SURFACE 0x7f000789
#define AVC_PROFILE_MAIN 2
#define AAC_OBJECT_LC 2
#define BITRATE_MODE_CBR 2

struct sample {
    int track;
    int64_t pts;
    uint32_t flags;
    size_t size, offset;
};

struct zapp_clip_recorder {
    ACameraManager *manager;
    ACameraDevice *device;
    ACaptureSessionOutputContainer *outputs;
    ACaptureSessionOutput *preview_out, *encoder_out;
    ACameraOutputTarget *preview_target, *encoder_target;
    ACaptureRequest *request;
    ACameraCaptureSession *session;
    ANativeWindow *preview, *encoder_window;
    AMediaCodec *video, *audio;
    AAudioStream *mic;
    AMediaMuxer *muxer;
    int fd;
    char camera_id[32], encoder_name[64], path[512];
    int width, height, rotation;
    bool realtime_clock;
    int video_track, audio_track;
    bool muxing, video_done, audio_done;
    int64_t base_us, first_video_us, audio_frames, audio_start_us, first_us, end_us;
    int32_t staged;
    int16_t stage[AUDIO_BLOCK_FRAMES];
    struct sample pending[PENDING_SAMPLES];
    unsigned char *pending_data;
    size_t pending_count, pending_used;
    pthread_t thread;
    bool thread_started;
    atomic_bool stop, active, failed, camera_lost, closing;
    _Atomic int64_t elapsed_ms;
    int64_t duration_ms;
    char message[160];
    size_t bytes;
};

static int64_t clock_us(clockid_t id)
{
    struct timespec now;
    return clock_gettime(id, &now) == 0 ? (int64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000 : -1;
}

static void note_failure(struct zapp_clip_recorder *r, const char *message)
{
    if (!atomic_exchange(&r->failed, true)) (void)snprintf(r->message, sizeof(r->message), "%s", message);
    __android_log_print(ANDROID_LOG_WARN, TAG, "clip capture: %s", message);
}

static bool failure(char *error, size_t cap, const char *message)
{
    if (error != NULL && cap != 0) (void)snprintf(error, cap, "%s", message);
    __android_log_print(ANDROID_LOG_WARN, TAG, "clip capture: %s", message);
    return false;
}

static bool clean(JNIEnv *env)
{
    if (!(*env)->ExceptionCheck(env)) return true;
    (*env)->ExceptionClear(env);
    return false;
}

static jobject system_service(JNIEnv *env, jobject activity, const char *name)
{
    jclass cls = (*env)->GetObjectClass(env, activity);
    jmethodID get = cls ? (*env)->GetMethodID(env, cls, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;") : NULL;
    jstring key = clean(env) ? (*env)->NewStringUTF(env, name) : NULL;
    jobject service = key && get ? (*env)->CallObjectMethod(env, activity, get, key) : NULL;
    return clean(env) ? service : NULL;
}

/* Calls an int-returning method on a system service; -1 when anything fails. */
static int service_int(JNIEnv *env, jobject activity, const char *service, const char *method, const char *sig, int arg)
{
    int value = -1;
    if ((*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)clean(env); return -1; }
    jobject object = system_service(env, activity, service);
    jclass cls = object ? (*env)->GetObjectClass(env, object) : NULL;
    jmethodID call = cls ? (*env)->GetMethodID(env, cls, method, sig) : NULL;
    if (clean(env) && call) {
        jint result = sig[1] == 'I' ? (*env)->CallIntMethod(env, object, call, arg) : (*env)->CallIntMethod(env, object, call);
        if (clean(env)) value = result;
    }
    (*env)->PopLocalFrame(env, NULL);
    return value;
}

int zapp_clip_thermal_status(JNIEnv *env, jobject activity)
{
    return service_int(env, activity, "power", "getCurrentThermalStatus", "()I", 0);
}

int zapp_clip_battery_percent(JNIEnv *env, jobject activity)
{
    return service_int(env, activity, "batterymanager", "getIntProperty", "(I)I", 4);
}

static bool codec_flag(JNIEnv *env, jobject info, const char *method)
{
    jclass cls = (*env)->GetObjectClass(env, info);
    jmethodID call = cls ? (*env)->GetMethodID(env, cls, method, "()Z") : NULL;
    bool value = clean(env) && call && (*env)->CallBooleanMethod(env, info, call);
    return clean(env) && value;
}

static bool codec_has_avc(JNIEnv *env, jobject info)
{
    jclass cls = (*env)->GetObjectClass(env, info);
    jmethodID types = cls ? (*env)->GetMethodID(env, cls, "getSupportedTypes", "()[Ljava/lang/String;") : NULL;
    jobjectArray array = clean(env) && types ? (*env)->CallObjectMethod(env, info, types) : NULL;
    bool avc = false;
    for (jsize i = 0; clean(env) && array && i < (*env)->GetArrayLength(env, array) && !avc; ++i) {
        jstring type = (*env)->GetObjectArrayElement(env, array, i);
        const char *chars = type ? (*env)->GetStringUTFChars(env, type, NULL) : NULL;
        avc = chars && !strcmp(chars, "video/avc");
        if (chars) (*env)->ReleaseStringUTFChars(env, type, chars);
        if (type) (*env)->DeleteLocalRef(env, type);
    }
    return clean(env) && avc;
}

static void codec_name(JNIEnv *env, jobject info, char *out, size_t cap)
{
    jclass cls = (*env)->GetObjectClass(env, info);
    jmethodID get = cls ? (*env)->GetMethodID(env, cls, "getName", "()Ljava/lang/String;") : NULL;
    jstring name = clean(env) && get ? (*env)->CallObjectMethod(env, info, get) : NULL;
    const char *chars = clean(env) && name ? (*env)->GetStringUTFChars(env, name, NULL) : NULL;
    (void)snprintf(out, cap, "%s", chars ? chars : "");
    if (chars) (*env)->ReleaseStringUTFChars(env, name, chars);
    (void)clean(env);
}

static jobjectArray codec_infos(JNIEnv *env)
{
    jclass cls = (*env)->FindClass(env, "android/media/MediaCodecList");
    jmethodID ctor = clean(env) && cls ? (*env)->GetMethodID(env, cls, "<init>", "(I)V") : NULL;
    jobject list = ctor ? (*env)->NewObject(env, cls, ctor, 0) : NULL;
    jmethodID infos = clean(env) && list ? (*env)->GetMethodID(env, cls, "getCodecInfos", "()[Landroid/media/MediaCodecInfo;") : NULL;
    jobjectArray array = infos ? (*env)->CallObjectMethod(env, list, infos) : NULL;
    return clean(env) ? array : NULL;
}

size_t zapp_clip_list_codecs(JNIEnv *env, struct zapp_codec_info *list, size_t cap)
{
    size_t count = 0;
    if ((*env)->PushLocalFrame(env, 64) != JNI_OK) { (void)clean(env); return 0; }
    jobjectArray infos = codec_infos(env);
    jsize total = infos ? (*env)->GetArrayLength(env, infos) : 0;
    for (jsize i = 0; i < total && count < cap; ++i) {
        jobject info = (*env)->GetObjectArrayElement(env, infos, i);
        if (!clean(env) || !info) continue;
        {
            list[count].encoder = codec_flag(env, info, "isEncoder");
            list[count].avc = codec_has_avc(env, info);
            list[count].hardware = codec_flag(env, info, "isHardwareAccelerated");
            codec_name(env, info, list[count].name, sizeof(list[count].name));
            ++count;
        }
        (*env)->DeleteLocalRef(env, info);
    }
    (*env)->PopLocalFrame(env, NULL);
    return count;
}

static void device_gone(void *context, ACameraDevice *device)
{
    (void)device;
    struct zapp_clip_recorder *r = context;
    note_failure(r, "The camera stopped or was taken by another app. Tap Record to try again.");
    atomic_store(&r->camera_lost, true);
}
static void device_error(void *context, ACameraDevice *device, int error)
{
    (void)error;
    device_gone(context, device);
}
static void session_event(void *context, ACameraCaptureSession *session) { (void)context; (void)session; }

static bool camera_traits(struct zapp_clip_recorder *r, ACameraMetadata *meta)
{
    ACameraMetadata_const_entry e;
    if (ACameraMetadata_getConstEntry(meta, ACAMERA_SENSOR_ORIENTATION, &e) != ACAMERA_OK || e.count < 1) return false;
    r->rotation = zapp_clip_rotation_hint(e.data.i32[0]);
    r->realtime_clock = ACameraMetadata_getConstEntry(meta, ACAMERA_SENSOR_INFO_TIMESTAMP_SOURCE, &e) == ACAMERA_OK &&
        e.count >= 1 && e.data.u8[0] == ACAMERA_SENSOR_INFO_TIMESTAMP_SOURCE_REALTIME;
    return ACameraMetadata_getConstEntry(meta, ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, &e) == ACAMERA_OK &&
        zapp_clip_pick_size(e.data.i32, e.count, &r->width, &r->height);
}

/* Finds the rear camera, remembers its id, orientation, clock and stream size. */
static bool find_rear(struct zapp_clip_recorder *r)
{
    ACameraIdList *ids = NULL;
    bool found = false;
    if (ACameraManager_getCameraIdList(r->manager, &ids) != ACAMERA_OK || ids == NULL) return false;
    for (int i = 0; i < ids->numCameras && !found; ++i) {
        ACameraMetadata *meta = NULL;
        ACameraMetadata_const_entry e;
        if (ACameraManager_getCameraCharacteristics(r->manager, ids->cameraIds[i], &meta) != ACAMERA_OK) continue;
        if (ACameraMetadata_getConstEntry(meta, ACAMERA_LENS_FACING, &e) == ACAMERA_OK && e.count >= 1 &&
            e.data.u8[0] == ACAMERA_LENS_FACING_BACK && camera_traits(r, meta)) {
            (void)snprintf(r->camera_id, sizeof(r->camera_id), "%s", ids->cameraIds[i]);
            found = true;
        }
        ACameraMetadata_free(meta);
    }
    ACameraManager_deleteCameraIdList(ids);
    return found;
}

static void session_close(struct zapp_clip_recorder *r)
{
    if (r->session != NULL) {
        (void)ACameraCaptureSession_stopRepeating(r->session);
        ACameraCaptureSession_close(r->session);
    }
    if (r->request != NULL) ACaptureRequest_free(r->request);
    if (r->preview_target != NULL) ACameraOutputTarget_free(r->preview_target);
    if (r->encoder_target != NULL) ACameraOutputTarget_free(r->encoder_target);
    if (r->outputs != NULL) ACaptureSessionOutputContainer_free(r->outputs);
    if (r->preview_out != NULL) ACaptureSessionOutput_free(r->preview_out);
    if (r->encoder_out != NULL) ACaptureSessionOutput_free(r->encoder_out);
    r->session = NULL; r->request = NULL; r->preview_target = r->encoder_target = NULL;
    r->outputs = NULL; r->preview_out = r->encoder_out = NULL;
}

static bool session_outputs(struct zapp_clip_recorder *r, bool with_encoder)
{
    return ACaptureSessionOutputContainer_create(&r->outputs) == ACAMERA_OK &&
        ACaptureSessionOutput_create(r->preview, &r->preview_out) == ACAMERA_OK &&
        ACaptureSessionOutputContainer_add(r->outputs, r->preview_out) == ACAMERA_OK &&
        (!with_encoder || (ACaptureSessionOutput_create(r->encoder_window, &r->encoder_out) == ACAMERA_OK &&
                           ACaptureSessionOutputContainer_add(r->outputs, r->encoder_out) == ACAMERA_OK));
}

static bool session_request(struct zapp_clip_recorder *r, bool with_encoder)
{
    return ACameraDevice_createCaptureRequest(r->device, with_encoder ? TEMPLATE_RECORD : TEMPLATE_PREVIEW, &r->request) == ACAMERA_OK &&
        ACameraOutputTarget_create(r->preview, &r->preview_target) == ACAMERA_OK &&
        ACaptureRequest_addTarget(r->request, r->preview_target) == ACAMERA_OK &&
        (!with_encoder || (ACameraOutputTarget_create(r->encoder_window, &r->encoder_target) == ACAMERA_OK &&
                           ACaptureRequest_addTarget(r->request, r->encoder_target) == ACAMERA_OK));
}

/* Replaces the capture session with one that feeds the preview and, when asked, the encoder. */
static bool session_open(struct zapp_clip_recorder *r, bool with_encoder)
{
    ACameraCaptureSession_stateCallbacks callbacks = {.context = r, .onClosed = session_event,
        .onReady = session_event, .onActive = session_event};
    session_close(r);
    bool ok = session_outputs(r, with_encoder) && session_request(r, with_encoder) &&
        ACameraDevice_createCaptureSession(r->device, r->outputs, &callbacks, &r->session) == ACAMERA_OK &&
        ACameraCaptureSession_setRepeatingRequest(r->session, NULL, 1, &r->request, NULL) == ACAMERA_OK;
    if (!ok) session_close(r);
    return ok;
}

struct zapp_clip_recorder *zapp_clip_recorder_open(ANativeWindow *preview, const char *encoder,
                                                   char *error, size_t error_cap)
{
    if (error != NULL && error_cap != 0) error[0] = '\0';
    struct zapp_clip_recorder *r = calloc(1, sizeof(*r));
    if (r == NULL) { (void)failure(error, error_cap, "Out of memory."); return NULL; }
    r->preview = preview;
    ANativeWindow_acquire(preview);
    r->fd = -1;
    r->video_track = r->audio_track = -1;
    (void)snprintf(r->encoder_name, sizeof(r->encoder_name), "%s", encoder);
    ACameraDevice_StateCallbacks callbacks = {.context = r, .onDisconnected = device_gone, .onError = device_error};
    r->manager = ACameraManager_create();
    bool ok = r->manager != NULL && find_rear(r);
    if (!ok) (void)failure(error, error_cap, "No rear camera is available.");
    ok = ok && ACameraManager_openCamera(r->manager, r->camera_id, &callbacks, &r->device) == ACAMERA_OK;
    if (ok) ok = ANativeWindow_setBuffersGeometry(preview, r->width, r->height, 0) == 0 && session_open(r, false);
    if (!ok) {
        if (error != NULL && error[0] == '\0') (void)failure(error, error_cap, "The camera is busy or unavailable. Try again.");
        zapp_clip_recorder_close(r);
        return NULL;
    }
    __android_log_print(ANDROID_LOG_INFO, TAG, "clip camera %s stream %dx%d rotation %d realtime clock %d",
                        r->camera_id, r->width, r->height, r->rotation, r->realtime_clock);
    return r;
}

static bool video_encoder(struct zapp_clip_recorder *r)
{
    const struct zapp_clip_profile *p = &zapp_clip_profile;
    AMediaFormat *f = AMediaFormat_new();
    r->video = AMediaCodec_createCodecByName(r->encoder_name);
    if (f == NULL || r->video == NULL) { if (f) AMediaFormat_delete(f); return false; }
    AMediaFormat_setString(f, AMEDIAFORMAT_KEY_MIME, "video/avc");
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_WIDTH, r->width);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_HEIGHT, r->height);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_BIT_RATE, p->video_bps);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_FRAME_RATE, p->fps);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_I_FRAME_INTERVAL, p->keyframe_seconds);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_COLOR_FORMAT, COLOR_FORMAT_SURFACE);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_BITRATE_MODE, BITRATE_MODE_CBR);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_PROFILE, AVC_PROFILE_MAIN);
    bool ok = AMediaCodec_configure(r->video, f, NULL, NULL, AMEDIACODEC_CONFIGURE_FLAG_ENCODE) == AMEDIA_OK &&
        AMediaCodec_createInputSurface(r->video, &r->encoder_window) == AMEDIA_OK &&
        AMediaCodec_start(r->video) == AMEDIA_OK;
    AMediaFormat_delete(f);
    return ok;
}

static bool audio_encoder(struct zapp_clip_recorder *r)
{
    const struct zapp_clip_profile *p = &zapp_clip_profile;
    AMediaFormat *f = AMediaFormat_new();
    r->audio = AMediaCodec_createEncoderByType("audio/mp4a-latm");
    if (f == NULL || r->audio == NULL) { if (f) AMediaFormat_delete(f); return false; }
    AMediaFormat_setString(f, AMEDIAFORMAT_KEY_MIME, "audio/mp4a-latm");
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_SAMPLE_RATE, p->audio_rate);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_CHANNEL_COUNT, p->audio_channels);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_BIT_RATE, p->audio_bps);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_AAC_PROFILE, AAC_OBJECT_LC);
    AMediaFormat_setInt32(f, AMEDIAFORMAT_KEY_MAX_INPUT_SIZE, 4 * AUDIO_BLOCK_FRAMES);
    bool ok = AMediaCodec_configure(r->audio, f, NULL, NULL, AMEDIACODEC_CONFIGURE_FLAG_ENCODE) == AMEDIA_OK &&
        AMediaCodec_start(r->audio) == AMEDIA_OK;
    AMediaFormat_delete(f);
    return ok;
}

static bool microphone(struct zapp_clip_recorder *r)
{
    AAudioStreamBuilder *b = NULL;
    if (AAudio_createStreamBuilder(&b) != AAUDIO_OK) return false;
    AAudioStreamBuilder_setDirection(b, AAUDIO_DIRECTION_INPUT);
    AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_I16);
    AAudioStreamBuilder_setChannelCount(b, zapp_clip_profile.audio_channels);
    AAudioStreamBuilder_setSampleRate(b, zapp_clip_profile.audio_rate);
    AAudioStreamBuilder_setSharingMode(b, AAUDIO_SHARING_MODE_SHARED);
    aaudio_result_t opened = AAudioStreamBuilder_openStream(b, &r->mic);
    (void)AAudioStreamBuilder_delete(b);
    return opened == AAUDIO_OK && AAudioStream_getSampleRate(r->mic) == zapp_clip_profile.audio_rate &&
        AAudioStream_getChannelCount(r->mic) == zapp_clip_profile.audio_channels &&
        AAudioStream_getFormat(r->mic) == AAUDIO_FORMAT_PCM_I16;
}

/* Queues a sample written before the muxer has both tracks, or writes it at once. */
static bool emit(struct zapp_clip_recorder *r, int track, const unsigned char *data, const AMediaCodecBufferInfo *info)
{
    if (r->muxing) {
        AMediaCodecBufferInfo out = *info;
        out.offset = 0;
        r->bytes += (size_t)info->size;
        return AMediaMuxer_writeSampleData(r->muxer, (size_t)track, data, &out) == AMEDIA_OK;
    }
    if (r->pending_count >= PENDING_SAMPLES || r->pending_used + (size_t)info->size > PENDING_BYTES) return false;
    memcpy(r->pending_data + r->pending_used, data, (size_t)info->size);
    r->pending[r->pending_count++] = (struct sample){track, info->presentationTimeUs, info->flags,
                                                     (size_t)info->size, r->pending_used};
    r->pending_used += (size_t)info->size;
    return true;
}

static bool start_muxer(struct zapp_clip_recorder *r)
{
    if (r->video_track < 0 || r->audio_track < 0) return true;
    if (AMediaMuxer_setOrientationHint(r->muxer, r->rotation) != AMEDIA_OK || AMediaMuxer_start(r->muxer) != AMEDIA_OK)
        return false;
    r->muxing = true;
    for (size_t i = 0; i < r->pending_count; ++i) {
        const struct sample *s = &r->pending[i];
        AMediaCodecBufferInfo info = {.offset = 0, .size = (int32_t)s->size, .presentationTimeUs = s->pts, .flags = s->flags};
        if (!emit(r, s->track, r->pending_data + s->offset, &info)) return false;
    }
    r->pending_count = 0;
    return true;
}

static bool add_track(struct zapp_clip_recorder *r, AMediaCodec *codec, int *track)
{
    AMediaFormat *f = AMediaCodec_getOutputFormat(codec);
    ssize_t index = f != NULL ? AMediaMuxer_addTrack(r->muxer, f) : -1;
    if (f != NULL) AMediaFormat_delete(f);
    *track = (int)index;
    return index >= 0 && start_muxer(r);
}

/* Video presentation time relative to the recording start, on the sensor clock when it is boot time. */
static int64_t video_pts(struct zapp_clip_recorder *r, int64_t pts)
{
    if (r->first_video_us < 0) r->first_video_us = pts;
    int64_t t = pts - (r->realtime_clock ? r->base_us : r->first_video_us);
    return t < 0 ? 0 : t;
}

/* Writes one encoded sample; samples at or past the 60 s cap are left out. */
static void write_sample(struct zapp_clip_recorder *r, int track, const unsigned char *data, AMediaCodecBufferInfo info, bool is_video)
{
    info.presentationTimeUs = is_video ? video_pts(r, info.presentationTimeUs) : info.presentationTimeUs;
    if (zapp_clip_time_up(info.presentationTimeUs / 1000)) return;
    if (!emit(r, track, data, &info)) note_failure(r, "The recording could not be written.");
    else {
        int64_t end = zapp_clip_sample_end_us(is_video, info.presentationTimeUs);
        if (r->first_us < 0 || info.presentationTimeUs < r->first_us) r->first_us = info.presentationTimeUs;
        if (end > r->end_us) r->end_us = end;
    }
}

/* Moves one finished buffer of a codec to the muxer; returns false when nothing was ready. */
static bool drain(struct zapp_clip_recorder *r, AMediaCodec *codec, int *track, bool *done, bool is_video)
{
    AMediaCodecBufferInfo info;
    ssize_t i = AMediaCodec_dequeueOutputBuffer(codec, &info, 0);
    if (i == AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED) {
        if (!add_track(r, codec, track)) note_failure(r, "The recording could not start.");
        return true;
    }
    if (i < 0) return i == AMEDIACODEC_INFO_OUTPUT_BUFFERS_CHANGED;
    size_t size = 0;
    unsigned char *data = AMediaCodec_getOutputBuffer(codec, (size_t)i, &size);
    if (data != NULL && info.size > 0 && !(info.flags & AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG) &&
        (size_t)info.offset + (size_t)info.size <= size) {
        write_sample(r, *track, data + info.offset, info, is_video);
    }
    if (info.flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "clip %s end of stream: size %d pts %lld", is_video ? "video" : "audio",
                            info.size, (long long)info.presentationTimeUs);
        *done = true;
    }
    (void)AMediaCodec_releaseOutputBuffer(codec, (size_t)i, false);
    return true;
}

static bool queue_audio(struct zapp_clip_recorder *r, bool end)
{
    ssize_t i = AMediaCodec_dequeueInputBuffer(r->audio, 0);
    if (i < 0) return false;
    size_t capacity = 0, bytes = end ? 0 : (size_t)r->staged * sizeof(int16_t);
    unsigned char *buffer = AMediaCodec_getInputBuffer(r->audio, (size_t)i, &capacity);
    if (buffer == NULL || bytes > capacity) { note_failure(r, "The recording could not start."); return false; }
    int64_t pts = r->audio_start_us + r->audio_frames * 1000000 / zapp_clip_profile.audio_rate;
    memcpy(buffer, r->stage, bytes);
    (void)AMediaCodec_queueInputBuffer(r->audio, (size_t)i, 0, bytes, (uint64_t)pts,
                                       end ? AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM : 0);
    r->audio_frames += r->staged;
    r->staged = 0;
    return true;
}

/* Reads available microphone samples, then hands a staged block to the encoder when it has room. */
static bool feed_audio(struct zapp_clip_recorder *r)
{
    bool moved = false;
    if (r->staged == 0) {
        aaudio_result_t n = AAudioStream_read(r->mic, r->stage, AUDIO_BLOCK_FRAMES, 0);
        if (n < 0) { note_failure(r, "The microphone stopped working."); return false; }
        if (r->audio_frames == 0 && n > 0)
            r->audio_start_us = r->realtime_clock ? clock_us(CLOCK_BOOTTIME) - r->base_us : 0;
        r->staged = n;
    }
    if (r->staged > 0) moved = queue_audio(r, false);
    return moved;
}

static void finish_inputs(struct zapp_clip_recorder *r)
{
    session_close(r);
    (void)AMediaCodec_signalEndOfInputStream(r->video);
    int64_t deadline = clock_us(CLOCK_MONOTONIC) + DRAIN_TIMEOUT_US;
    r->staged = 0;
    while (!queue_audio(r, true) && clock_us(CLOCK_MONOTONIC) < deadline) {
        struct timespec ts = {.tv_nsec = 5000000};
        (void)nanosleep(&ts, NULL);
    }
    while ((!r->video_done || !r->audio_done) && clock_us(CLOCK_MONOTONIC) < deadline) {
        bool moved = !r->video_done && drain(r, r->video, &r->video_track, &r->video_done, true);
        moved = (!r->audio_done && drain(r, r->audio, &r->audio_track, &r->audio_done, false)) || moved;
        if (!moved) { struct timespec ts = {.tv_nsec = 5000000}; (void)nanosleep(&ts, NULL); }
    }
}

static bool should_stop(struct zapp_clip_recorder *r)
{
    int64_t elapsed = (clock_us(CLOCK_BOOTTIME) - r->base_us) / 1000;
    atomic_store(&r->elapsed_ms, elapsed);
    return atomic_load(&r->stop) || atomic_load(&r->failed) || zapp_clip_time_up(elapsed);
}

static void release_codecs(struct zapp_clip_recorder *r)
{
    if (r->video != NULL) { (void)AMediaCodec_stop(r->video); (void)AMediaCodec_delete(r->video); }
    if (r->audio != NULL) { (void)AMediaCodec_stop(r->audio); (void)AMediaCodec_delete(r->audio); }
    if (r->encoder_window != NULL) ANativeWindow_release(r->encoder_window);
    if (r->mic != NULL) { (void)AAudioStream_requestStop(r->mic); (void)AAudioStream_close(r->mic); }
    r->video = r->audio = NULL; r->encoder_window = NULL; r->mic = NULL;
    free(r->pending_data);
    r->pending_data = NULL;
}

/* Closes the file; a recording that never reached the muxer leaves nothing behind. */
static int64_t finalize_file(struct zapp_clip_recorder *r)
{
    bool wrote = r->muxing && r->first_us >= 0 && r->end_us > r->first_us && !atomic_load(&r->failed);
    bool stopped = r->muxing && AMediaMuxer_stop(r->muxer) == AMEDIA_OK;
    if (r->muxer != NULL) (void)AMediaMuxer_delete(r->muxer);
    r->muxer = NULL;
    if (r->fd >= 0) (void)close(r->fd);
    r->fd = -1;
    if (!(wrote && stopped)) {
        if (r->path[0] != '\0') (void)unlink(r->path);
        r->path[0] = '\0';
        return 0;
    }
    return zapp_clip_span_ms(r->first_us, r->end_us);
}

/* Runs on the worker: records until asked to stop, then finishes the file and restores the preview. */
static void *record_loop(void *arg)
{
    struct zapp_clip_recorder *r = arg;
    while (!should_stop(r)) {
        bool moved = drain(r, r->video, &r->video_track, &r->video_done, true);
        moved = drain(r, r->audio, &r->audio_track, &r->audio_done, false) || moved;
        moved = feed_audio(r) || moved;
        if (!moved) { struct timespec ts = {.tv_nsec = 5000000}; (void)nanosleep(&ts, NULL); }
    }
    finish_inputs(r);
    release_codecs(r);
    r->duration_ms = finalize_file(r);
    __android_log_print(ANDROID_LOG_INFO, TAG, "clip capture stopped: %lld ms, %zu bytes, %lld kbit/s, %s",
                        (long long)r->duration_ms, r->bytes, (long long)zapp_clip_bitrate_kbps((int64_t)r->bytes, r->duration_ms),
                        atomic_load(&r->failed) ? r->message : "ok");
    if (!atomic_load(&r->camera_lost) && !atomic_load(&r->closing)) (void)session_open(r, false);
    atomic_store(&r->active, false);
    return NULL;
}

static bool prepare(struct zapp_clip_recorder *r, const char *path, char *error, size_t error_cap)
{
    (void)snprintf(r->path, sizeof(r->path), "%s", path);
    r->pending_data = malloc(PENDING_BYTES);
    r->fd = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    r->muxer = r->fd >= 0 ? AMediaMuxer_new(r->fd, AMEDIAMUXER_OUTPUT_FORMAT_MPEG_4) : NULL;
    if (r->pending_data == NULL || r->muxer == NULL) return failure(error, error_cap, "Could not create the clip file.");
    if (!microphone(r)) return failure(error, error_cap, "The microphone is not available.");
    if (!video_encoder(r) || !audio_encoder(r)) return failure(error, error_cap, "The video encoder could not start.");
    r->base_us = clock_us(CLOCK_BOOTTIME);
    if (!session_open(r, true)) return failure(error, error_cap, "The camera could not start recording.");
    return true;
}

/* Undoes a start that failed before the worker ran: frees what prepare made and removes the file. */
static void abandon(struct zapp_clip_recorder *r)
{
    release_codecs(r);
    (void)finalize_file(r);
    if (!atomic_load(&r->camera_lost)) (void)session_open(r, false);
}

static void reset_run(struct zapp_clip_recorder *r)
{
    r->first_video_us = -1;
    r->video_track = r->audio_track = -1;
    r->muxing = r->video_done = r->audio_done = false;
    r->audio_frames = r->end_us = r->duration_ms = 0;
    r->first_us = -1;
    r->staged = 0;
    r->pending_count = r->pending_used = r->bytes = 0;
    atomic_store(&r->stop, false);
    atomic_store(&r->failed, false);
    atomic_store(&r->elapsed_ms, 0);
}

bool zapp_clip_recorder_start(struct zapp_clip_recorder *r, const char *path, char *error, size_t error_cap)
{
    if (r == NULL || r->thread_started || atomic_load(&r->active)) return failure(error, error_cap, "Already recording.");
    if (atomic_load(&r->camera_lost)) return failure(error, error_cap, "The camera stopped. Tap Record to open it again.");
    reset_run(r);
    if (!prepare(r, path, error, error_cap)) {
        abandon(r);
        return false;
    }
    (void)AAudioStream_requestStart(r->mic);
    atomic_store(&r->active, true);
    if (pthread_create(&r->thread, NULL, record_loop, r) != 0) {
        atomic_store(&r->active, false);
        abandon(r);
        return failure(error, error_cap, "Could not start recording.");
    }
    r->thread_started = true;
    return true;
}

int64_t zapp_clip_recorder_elapsed_ms(const struct zapp_clip_recorder *r)
{
    return r != NULL ? atomic_load(&r->elapsed_ms) : 0;
}

bool zapp_clip_recorder_running(const struct zapp_clip_recorder *r)
{
    return r != NULL && atomic_load(&r->active);
}

void zapp_clip_recorder_request_stop(struct zapp_clip_recorder *r)
{
    if (r != NULL) atomic_store(&r->stop, true);
}

bool zapp_clip_recorder_wait(const struct zapp_clip_recorder *r, int timeout_ms)
{
    struct timespec ts = {.tv_nsec = 10000000};
    for (int waited = 0; zapp_clip_recorder_running(r); waited += 10) {
        if (waited >= timeout_ms) return false;
        (void)nanosleep(&ts, NULL);
    }
    return true;
}

int64_t zapp_clip_recorder_collect(struct zapp_clip_recorder *r)
{
    if (r == NULL || !r->thread_started || atomic_load(&r->active)) return 0;
    (void)pthread_join(r->thread, NULL);
    r->thread_started = false;
    return r->duration_ms;
}

const char *zapp_clip_recorder_message(const struct zapp_clip_recorder *r)
{
    return r != NULL && atomic_load(&r->failed) ? r->message : "";
}

bool zapp_clip_recorder_camera_lost(const struct zapp_clip_recorder *r)
{
    return r != NULL && atomic_load(&r->camera_lost);
}

static void teardown(struct zapp_clip_recorder *r)
{
    if (r->thread_started) (void)pthread_join(r->thread, NULL);
    session_close(r);
    if (r->device != NULL) ACameraDevice_close(r->device);
    if (r->manager != NULL) ACameraManager_delete(r->manager);
    ANativeWindow_release(r->preview);
    free(r);
}

static void *reap(void *arg)
{
    teardown(arg);
    return NULL;
}

void zapp_clip_recorder_close(struct zapp_clip_recorder *r)
{
    if (r == NULL) return;
    atomic_store(&r->closing, true);
    atomic_store(&r->stop, true);
    pthread_t thread;
    if (r->thread_started && atomic_load(&r->active) && pthread_create(&thread, NULL, reap, r) == 0) {
        (void)pthread_detach(thread);
        return;
    }
    teardown(r);
}
#endif
