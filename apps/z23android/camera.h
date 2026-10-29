/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_CAMERA_H
#define Z23_ANDROID_CAMERA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
uint64_t zapp_camera_ticket(void);
bool zapp_camera_scan(uint64_t ticket, char *result, size_t cap, char *error, size_t error_cap);
bool zapp_camera_preview(unsigned char **bmp, size_t *len);
void zapp_camera_stop(void);
void zapp_camera_set_frame_notify(void (*notify)(void));
bool zapp_camera_permission(uint64_t ticket);
#endif
