/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_GAME_HOST_H
#define ZAPP_GAME_HOST_H
#include <stdbool.h>
#include <stddef.h>
/* The path is selected by the host operator at startup, never by a phone. */
bool zapp_game_host_configure(const char *path);
/* Only one session may run. The random token binds later authenticated calls. */
bool zapp_game_host_start(int client, char token[65], char image[65], char *reply, size_t cap);
bool zapp_game_host_call(int client, const char *token, const char *request, char image[65], char *reply, size_t cap);
bool zapp_game_host_close(const char *token);
void zapp_game_host_shutdown(void);
#endif
