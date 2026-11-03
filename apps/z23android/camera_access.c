/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "camera_access.h"

enum zapp_camera_access zapp_camera_access_state(bool granted, bool rationale, bool asked_before)
{
    if (granted) return ZAPP_CAMERA_GRANTED;
    if (!asked_before) return ZAPP_CAMERA_ASK;
    return rationale ? ZAPP_CAMERA_ASK_AGAIN : ZAPP_CAMERA_SETTINGS;
}

struct zapp_camera_screen zapp_camera_screen(enum zapp_camera_access access)
{
    if (access != ZAPP_CAMERA_SETTINGS) return (struct zapp_camera_screen){ .preview = true };
    return (struct zapp_camera_screen){
        .text = "Camera access is off. Open Settings to allow it, or paste an address.",
        .open = "Open settings",
        .paste = "Paste instead",
    };
}
