/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_FLEET_H
#define Z23_ANDROID_FLEET_H
#include <stdbool.h>
#include <stddef.h>
/* Extracts a token or the exact manager-produced join command. This is only
 * a syntax check; the fleet command verifies the signature and expiry. */
bool zapp_fleet_invite_text(const char *text, char *token, size_t cap);
/* Returns a heap-allocated 24-bit BMP for a public fleet receipt, or NULL. */
unsigned char *zapp_fleet_qr_bmp(const char *text, size_t *size);
#endif
