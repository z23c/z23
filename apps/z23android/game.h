/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_GAME_H
#define ZAPP_GAME_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Calls start and stop off the UI thread. One session and one in-flight request. */
bool zapp_game_open(const char *files);
void zapp_game_set_notify(void (*notify)(void));
void zapp_game_close(void);
void zapp_game_controls(float x, float y, bool fire, bool boost);
/* Copy only a newer complete PNG into the caller's buffer. */
size_t zapp_game_frame(unsigned char *out, size_t cap, uint64_t *version);
void zapp_game_status(char *out, size_t cap);
#endif
