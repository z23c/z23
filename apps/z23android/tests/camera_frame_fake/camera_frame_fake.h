#ifndef Z23_CAMERA_FRAME_FAKE_H
#define Z23_CAMERA_FRAME_FAKE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int ACameraManager, ACameraDevice, ACameraMetadata, ACameraCaptureSession;
typedef int ACaptureSessionOutputContainer, ACaptureSessionOutput, ACameraOutputTarget, ACaptureRequest;
typedef int AImageReader, ANativeWindow;
typedef struct ACameraIdList { int numCameras; const char *const *cameraIds; } ACameraIdList;
typedef struct ACameraMetadata_const_entry {
    union { const uint8_t *u8; const int32_t *i32; } data;
    uint32_t count;
} ACameraMetadata_const_entry;
typedef void (*ACameraDevice_StateCallback)(void *, ACameraDevice *);
typedef void (*ACameraDevice_ErrorCallback)(void *, ACameraDevice *, int);
typedef struct ACameraDevice_StateCallbacks {
    void *context;
    ACameraDevice_StateCallback onDisconnected;
    ACameraDevice_ErrorCallback onError;
} ACameraDevice_StateCallbacks;
typedef void (*ACameraCaptureSession_StateCallback)(void *, ACameraCaptureSession *);
typedef struct ACameraCaptureSession_stateCallbacks {
    void *context;
    ACameraCaptureSession_StateCallback onClosed;
    ACameraCaptureSession_StateCallback onReady;
    ACameraCaptureSession_StateCallback onActive;
} ACameraCaptureSession_stateCallbacks;

#define ACAMERA_OK 0
#define AMEDIA_OK 0
#define ACAMERA_LENS_FACING 0
#define ACAMERA_LENS_FACING_BACK 1
#define ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS 0
#define AIMAGE_FORMAT_YUV_420_888 35
#define TEMPLATE_PREVIEW 1

/* Link-only placeholders for camera-session code excluded from this fixture. */
extern ACameraManager *ACameraManager_create(void);
extern int ACameraManager_getCameraIdList(void *, ...);
extern int ACameraManager_getCameraCharacteristics(void *, ...);
extern int ACameraManager_openCamera(void *, ...);
extern int ACameraMetadata_getConstEntry(void *, ...);
extern int AImageReader_new(int, ...);
extern int AImageReader_getWindow(void *, ...);
extern int ACaptureSessionOutputContainer_create(void *, ...);
extern int ACaptureSessionOutput_create(void *, ...);
extern int ACaptureSessionOutputContainer_add(void *, ...);
extern int ACaptureSessionOutputContainer_remove(void *, ...);
extern int ACameraOutputTarget_create(void *, ...);
extern int ACameraDevice_createCaptureRequest(void *, ...);
extern int ACaptureRequest_addTarget(void *, ...);
extern int ACaptureRequest_removeTarget(void *, ...);
extern int ACameraDevice_createCaptureSession(void *, ...);
extern int ACameraCaptureSession_setRepeatingRequest(void *, ...);
extern int ACameraCaptureSession_stopRepeating(void *, ...);
extern int ACameraCaptureSession_abortCaptures(void *, ...);
extern int AImageReader_acquireLatestImage(void *, ...);
extern void ACameraManager_deleteCameraIdList(void *, ...);
extern void ACameraManager_delete(void *, ...);
extern void ACameraDevice_close(void *, ...);
extern void ACameraMetadata_free(void *, ...);
extern void ACaptureSessionOutputContainer_free(void *, ...);
extern void ACaptureSessionOutput_free(void *, ...);
extern void ACameraOutputTarget_free(void *, ...);
extern void ACaptureRequest_free(void *, ...);
extern void ACameraCaptureSession_close(void *, ...);
extern void AImageReader_delete(void *, ...);
extern void AImage_delete(void *, ...);

typedef struct AImage {
    int width, height, stride, pixel_stride, length;
    uint8_t *data;
    int width_calls, height_calls, plane_calls, row_calls, pixel_calls;
    bool fail_width, fail_height, fail_plane, fail_row, fail_pixel;
} AImage;
/* The fixture is non-const; only its instrumentation is modified. */
static int AImage_getWidth(const AImage *image, int *out)
{
    ++((AImage *)image)->width_calls;
    if (image->fail_width) return 1;
    *out = image->width;
    return AMEDIA_OK;
}
static int AImage_getHeight(const AImage *image, int *out)
{
    ++((AImage *)image)->height_calls;
    /* Write the requested height, then fail. Ignoring the status would read the plane. */
    *out = image->height;
    if (image->fail_height) return 1;
    return AMEDIA_OK;
}
static int AImage_getPlaneData(const AImage *image, int plane, uint8_t **data, int *length)
{
    (void)plane;
    ++((AImage *)image)->plane_calls;
    if (image->fail_plane) return 1;
    *data = image->data;
    *length = image->length;
    return AMEDIA_OK;
}
static int AImage_getPlaneRowStride(const AImage *image, int plane, int *out)
{
    (void)plane;
    ++((AImage *)image)->row_calls;
    if (image->fail_row) return 1;
    *out = image->stride;
    return AMEDIA_OK;
}
static int AImage_getPlanePixelStride(const AImage *image, int plane, int *out)
{
    (void)plane;
    ++((AImage *)image)->pixel_calls;
    /* Write a stride that would fit, then fail. Ignoring the status would draw the preview. */
    *out = image->pixel_stride;
    if (image->fail_pixel) return 1;
    return AMEDIA_OK;
}
#endif
