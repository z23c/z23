/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_CAMERA_H
#define Z23_ANDROID_CAMERA_H
#include "camera_access.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
uint64_t zapp_camera_ticket(void);
enum zapp_camera_result { ZAPP_CAMERA_RESULT_ERROR, ZAPP_CAMERA_RESULT_OK, ZAPP_CAMERA_RESULT_DENIED };
enum zapp_camera_result zapp_camera_scan(uint64_t ticket, char *result, size_t cap, char *error, size_t error_cap);
bool zapp_camera_preview(unsigned char **bmp, size_t *len);
void zapp_camera_stop(void);
void zapp_camera_set_frame_notify(void (*notify)(void));
/* The access state for a scan. The permission is requested only in the ASK and ASK_AGAIN states, and waited for
 * only until the system dialog closes. */
enum zapp_camera_access zapp_camera_permission(uint64_t ticket);
/* The access state now, read without requesting anything. */
enum zapp_camera_access zapp_camera_access_now(void);
/* Opens the system settings page of this app. False when the page does not open. */
bool zapp_camera_open_settings(void);
#endif
