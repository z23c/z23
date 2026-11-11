/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_CAMERA_ACCESS_H
#define Z23_ANDROID_CAMERA_ACCESS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Selects an output YUV_420_888 size from camera metadata quadruples, preferring the requested area. */
bool zapp_camera_choose_size(const int32_t *entries, size_t count, int wanted_width, int wanted_height,
                             int *width, int *height);
/* Whether positive dimensions and strides put the last addressed luma byte inside the reported buffer. */
bool zapp_camera_luma_fits(int width, int height, int stride, int pixel_stride, int length);

/* What the camera scan may do, from the state of the camera permission. */
enum zapp_camera_access {
    ZAPP_CAMERA_UNKNOWN,   /* the permission state could not be read */
    ZAPP_CAMERA_GRANTED,   /* the permission is held: the camera may open */
    ZAPP_CAMERA_ASK,       /* never requested: the system dialog is shown */
    ZAPP_CAMERA_ASK_AGAIN, /* denied once: the system dialog is shown again */
    ZAPP_CAMERA_SETTINGS   /* denied for good: only the system settings page can allow it; nothing is requested */
};

/* granted: the permission is held. rationale: the system asks for a rationale. asked_before: the permission was
 * requested before. Android reports no rationale both before the first request and after a permanent denial,
 * so asked_before tells the two apart. */
enum zapp_camera_access zapp_camera_access_state(bool granted, bool rationale, bool asked_before);

/* One check of the wait for the system dialog, taken every 200 ms; tick counts from 1. paused: the activity has
 * paused since the request, which the dialog causes. dialog: the dialog has not reported its result yet. */
bool zapp_camera_wait_goes_on(unsigned tick, bool paused, bool dialog);

/* What the scan screen shows for an access state. With preview, the camera is shown with one line, hint, that says what to
 * point it at, and Cancel; the other fields are NULL. Otherwise text is shown with two buttons: open leads to the system
 * settings page and paste returns to Send, and hint is NULL. */
struct zapp_camera_screen {
    bool preview;
    const char *hint, *text, *open, *paste;
};
struct zapp_camera_screen zapp_camera_screen(enum zapp_camera_access access);

/* Poll frames until one succeeds or the owner stops the scan. */
bool zapp_camera_run_frames(void *ctx, bool (*next)(void *),
                            bool (*stopped)(void *), void (*pause)(void *));
#endif
