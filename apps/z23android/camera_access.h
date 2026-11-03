/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_CAMERA_ACCESS_H
#define Z23_ANDROID_CAMERA_ACCESS_H
#include <stdbool.h>

/* What the camera scan may do, from the state of the camera permission. */
enum zapp_camera_access {
    ZAPP_CAMERA_GRANTED,   /* the permission is held: the camera may open */
    ZAPP_CAMERA_ASK,       /* never requested: the system dialog is shown */
    ZAPP_CAMERA_ASK_AGAIN, /* denied once: the system dialog is shown again */
    ZAPP_CAMERA_SETTINGS   /* denied for good: only the system settings page can allow it; nothing is requested */
};

/* granted: the permission is held. rationale: the system asks for a rationale. asked_before: the permission was
 * requested before. Android reports no rationale both before the first request and after a permanent denial,
 * so asked_before tells the two apart. */
enum zapp_camera_access zapp_camera_access_state(bool granted, bool rationale, bool asked_before);

/* What the scan screen shows for an access state. With preview, the camera and Cancel are shown and the other
 * fields are NULL. Otherwise text is shown with two buttons: open leads to the system settings page and paste
 * returns to Send. */
struct zapp_camera_screen {
    bool preview;
    const char *text, *open, *paste;
};
struct zapp_camera_screen zapp_camera_screen(enum zapp_camera_access access);
#endif
