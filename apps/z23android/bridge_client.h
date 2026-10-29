/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_BRIDGE_CLIENT_H
#define ZAPP_BRIDGE_CLIENT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
bool zapp_bridge_chat(const char *files, const char *prompt, char *out, size_t cap,
                      const atomic_bool *cancel);
bool zapp_bridge_speech(const char *files, const char *request, char *out, size_t cap,
                       const atomic_bool *cancel);
#endif
