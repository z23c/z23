/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "camera.h"
#include "quirc.h"
#include <camera/NdkCameraManager.h>
#include <media/NdkImageReader.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WIDTH 1280
#define HEIGHT 960
#define PREVIEW_W 320
#define PREVIEW_H 240
#define PREVIEW_STEP_X (WIDTH / PREVIEW_W)
#define PREVIEW_STEP_Y (HEIGHT / PREVIEW_H)
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool stopped;
static bool scanning, preview_ready;
static uint64_t generation = 1;
static uintptr_t scan_sequence;
static void (*frame_notify)(void);
static struct timespec last_frame_notify;
static unsigned char preview[PREVIEW_W * PREVIEW_H];

static void cancel_device(void *ctx)
{
    pthread_mutex_lock(&lock);
    if (scanning && scan_sequence == (uintptr_t)ctx) atomic_store(&stopped, true);
    pthread_mutex_unlock(&lock);
}
static void device_disconnected(void *ctx, ACameraDevice *device) { (void)device; cancel_device(ctx); }
static void device_error(void *ctx, ACameraDevice *device, int error) { (void)device; (void)error; cancel_device(ctx); }
static void session_state(void *ctx, ACameraCaptureSession *session) { (void)ctx; (void)session; }
uint64_t zapp_camera_ticket(void)
{
    pthread_mutex_lock(&lock);
    uint64_t ticket = generation;
    pthread_mutex_unlock(&lock);
    return ticket;
}
void zapp_camera_set_frame_notify(void (*notify)(void))
{
    pthread_mutex_lock(&lock); frame_notify = notify; pthread_mutex_unlock(&lock);
}
void zapp_camera_stop(void)
{
    pthread_mutex_lock(&lock);
    if (++generation == 0) ++generation;
    atomic_store(&stopped, true);
    pthread_mutex_unlock(&lock);
}

static void put32(unsigned char *p, uint32_t n)
{ for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(n >> (8 * i)); }
bool zapp_camera_preview(unsigned char **bmp, size_t *len)
{
    const size_t header = 54, size = header + PREVIEW_W * PREVIEW_H * 3;
    if (!bmp || !len) return false;
    *bmp = NULL; *len = 0;
    unsigned char *out = calloc(1, size);
    if (!out) return false;
    pthread_mutex_lock(&lock);
    if (!scanning || !preview_ready) { pthread_mutex_unlock(&lock); free(out); return false; }
    out[0] = 'B'; out[1] = 'M'; put32(out + 2, (uint32_t)size); put32(out + 10, (uint32_t)header);
    put32(out + 14, 40); put32(out + 18, PREVIEW_W); put32(out + 22, PREVIEW_H);
    out[26] = 1; out[28] = 24; put32(out + 34, PREVIEW_W * PREVIEW_H * 3);
    for (int y = 0; y < PREVIEW_H; ++y) for (int x = 0; x < PREVIEW_W; ++x) {
        unsigned char pixel = preview[(PREVIEW_H - 1 - y) * PREVIEW_W + x];
        size_t i = header + (size_t)(y * PREVIEW_W + x) * 3;
        out[i] = out[i + 1] = out[i + 2] = pixel;
    }
    pthread_mutex_unlock(&lock);
    *bmp = out; *len = size; return true;
}

static void update_preview(const uint8_t *dst)
{
    pthread_mutex_lock(&lock);
    for (int y = 0; y < PREVIEW_H; ++y) for (int x = 0; x < PREVIEW_W; ++x)
        preview[y * PREVIEW_W + x] = dst[(y * PREVIEW_STEP_Y) * WIDTH + x * PREVIEW_STEP_X];
    preview_ready = true;
    struct timespec now; void (*notify)(void) = NULL;
    if (frame_notify && clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
        ((now.tv_sec - last_frame_notify.tv_sec) * 1000000000LL + now.tv_nsec - last_frame_notify.tv_nsec >= 500000000LL)) {
        last_frame_notify = now; notify = frame_notify;
    }
    pthread_mutex_unlock(&lock);
    if (notify) notify();
}
static bool decode_frame(struct quirc *qr, char *result, size_t cap)
{
    for (int i = 0; i < quirc_count(qr); ++i) {
        struct quirc_code code; struct quirc_data data;
        quirc_extract(qr, i, &code);
        if (!quirc_decode(&code, &data) && data.payload_len > 0 &&
            (size_t)data.payload_len < cap && !memchr(data.payload, 0, (size_t)data.payload_len)) {
            memcpy(result, data.payload, (size_t)data.payload_len);
            result[data.payload_len] = 0; return true;
        }
    }
    return false;
}
static bool frame(AImage *image, struct quirc *qr, char *result, size_t cap)
{
    uint8_t *src = NULL; int length = 0, stride = 0, pixel_stride = 0;
    if (AImage_getPlaneData(image, 0, &src, &length) != AMEDIA_OK ||
        AImage_getPlaneRowStride(image, 0, &stride) != AMEDIA_OK ||
        AImage_getPlanePixelStride(image, 0, &pixel_stride) != AMEDIA_OK ||
        !src || stride <= 0 || pixel_stride <= 0 ||
        (int64_t)(HEIGHT - 1) * stride + (WIDTH - 1) * (int64_t)pixel_stride >= length) return false;
    int w, h; uint8_t *dst = quirc_begin(qr, &w, &h);
    if (!dst || w != WIDTH || h != HEIGHT) return false;
    for (int y = 0; y < HEIGHT; ++y) for (int x = 0; x < WIDTH; ++x)
        dst[y * WIDTH + x] = src[y * stride + x * pixel_stride];
    update_preview(dst);
    quirc_end(qr);
    return decode_frame(qr, result, cap);
}

struct camera_scan {
    ACameraManager *manager; ACameraIdList *ids; ACameraDevice *device;
    AImageReader *reader; ANativeWindow *window;
    ACaptureSessionOutputContainer *outputs; ACaptureSessionOutput *output;
    ACameraOutputTarget *target; ACaptureRequest *request;
    ACameraCaptureSession *session; struct quirc *qr;
};
static const char *rear_camera(struct camera_scan *r, char *error, size_t error_cap)
{
    r->manager = ACameraManager_create();
    if (!r->manager || ACameraManager_getCameraIdList(r->manager, &r->ids) != ACAMERA_OK || !r->ids || r->ids->numCameras < 1) return NULL;
    const char *id = NULL;
    for (int i = 0; i < r->ids->numCameras; ++i) {
        ACameraMetadata *metadata = NULL; ACameraMetadata_const_entry entry;
        if (ACameraManager_getCameraCharacteristics(r->manager, r->ids->cameraIds[i], &metadata) == ACAMERA_OK) {
            bool rear = ACameraMetadata_getConstEntry(metadata, ACAMERA_LENS_FACING, &entry) == ACAMERA_OK &&
                entry.count && entry.data.u8[0] == ACAMERA_LENS_FACING_BACK;
            ACameraMetadata_free(metadata);
            if (rear) { id = r->ids->cameraIds[i]; break; }
        }
    }
    if (!id) snprintf(error, error_cap, "No rear camera available.");
    return id;
}
static bool open_capture(struct camera_scan *r, const char *id, uintptr_t sequence)
{
    ACameraDevice_StateCallbacks dc = { .context = (void *)sequence, .onDisconnected = device_disconnected, .onError = device_error };
    ACameraCaptureSession_stateCallbacks sc = { .context = NULL, .onClosed = session_state, .onReady = session_state, .onActive = session_state };
    if (ACameraManager_openCamera(r->manager, id, &dc, &r->device) != ACAMERA_OK ||
        AImageReader_new(WIDTH, HEIGHT, AIMAGE_FORMAT_YUV_420_888, 2, &r->reader) != AMEDIA_OK ||
        AImageReader_getWindow(r->reader, &r->window) != AMEDIA_OK ||
        ACaptureSessionOutputContainer_create(&r->outputs) != ACAMERA_OK ||
        ACaptureSessionOutput_create(r->window, &r->output) != ACAMERA_OK ||
        ACaptureSessionOutputContainer_add(r->outputs, r->output) != ACAMERA_OK ||
        ACameraOutputTarget_create(r->window, &r->target) != ACAMERA_OK ||
        ACameraDevice_createCaptureRequest(r->device, TEMPLATE_PREVIEW, &r->request) != ACAMERA_OK ||
        ACaptureRequest_addTarget(r->request, r->target) != ACAMERA_OK ||
        ACameraDevice_createCaptureSession(r->device, r->outputs, &sc, &r->session) != ACAMERA_OK ||
        ACameraCaptureSession_setRepeatingRequest(r->session, NULL, 1, &r->request, NULL) != ACAMERA_OK) return false;
    return true;
}
static bool scan_frames(struct camera_scan *r, char *result, size_t cap, char *error, size_t error_cap)
{
    bool ok = false;
    r->qr = quirc_new(); if (!r->qr || quirc_resize(r->qr, WIDTH, HEIGHT) != 0) return false;
    struct timespec start, now, pause = { .tv_sec = 0, .tv_nsec = 100000000 };
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return false;
    snprintf(error, error_cap, "No QR code found before timeout.");
    do {
        AImage *image = NULL;
        if (AImageReader_acquireLatestImage(r->reader, &image) == AMEDIA_OK && image) {
            ok = frame(image, r->qr, result, cap); AImage_delete(image);
            if (ok) break;
        }
        nanosleep(&pause, NULL);
        if (clock_gettime(CLOCK_MONOTONIC, &now)) break;
    } while (!atomic_load(&stopped) && now.tv_sec - start.tv_sec < 30);
    return ok;
}
static void close_capture(struct camera_scan *r)
{

    if (r->session) { ACameraCaptureSession_stopRepeating(r->session); ACameraCaptureSession_close(r->session); }
    if (r->device) ACameraDevice_close(r->device);
    if (r->request) ACaptureRequest_free(r->request);
    if (r->target) ACameraOutputTarget_free(r->target);
    if (r->outputs) ACaptureSessionOutputContainer_free(r->outputs);
    if (r->output) ACaptureSessionOutput_free(r->output);
    if (r->reader) AImageReader_delete(r->reader);
    if (r->ids) ACameraManager_deleteCameraIdList(r->ids);
    if (r->manager) ACameraManager_delete(r->manager);
    if (r->qr) quirc_destroy(r->qr);
}
bool zapp_camera_scan(uint64_t ticket, char *result, size_t cap, char *error, size_t error_cap)
{
    if (!result || cap < 2 || !error || !error_cap) return false;
    result[0] = 0; snprintf(error, error_cap, "Camera scan unavailable.");
    pthread_mutex_lock(&lock);
    if (!ticket || ticket != generation) { pthread_mutex_unlock(&lock); snprintf(error, error_cap, "Camera scan cancelled."); return false; }
    if (scanning) { pthread_mutex_unlock(&lock); snprintf(error, error_cap, "Camera is already scanning."); return false; }
    scanning = true; preview_ready = false; atomic_store(&stopped, false);
    if (++scan_sequence == 0) ++scan_sequence;
    uintptr_t sequence = scan_sequence;
    pthread_mutex_unlock(&lock);
    bool ok = false;
    struct camera_scan state = {0};
    bool allowed = zapp_camera_permission(ticket);
    if (!allowed || atomic_load(&stopped)) {
        snprintf(error, error_cap, atomic_load(&stopped) ? "Camera scan cancelled." :
                 "Camera permission was not given. Allow Camera for this app in Android Settings, under Apps and Permissions, then tap Scan again."); goto out;
    }
    const char *id = rear_camera(&state, error, error_cap);
    if (!id || !open_capture(&state, id, sequence)) goto out;
    ok = scan_frames(&state, result, cap, error, error_cap);
out:
    close_capture(&state);
    pthread_mutex_lock(&lock); scanning = false; preview_ready = false; memset(preview, 0, sizeof(preview)); pthread_mutex_unlock(&lock);
    if (ok) error[0] = 0;
    return ok;
}
