/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_BRIDGE_CLIENT_H
#define ZAPP_BRIDGE_CLIENT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
struct json_value;
bool zapp_bridge_chat(const char *files, const char *prompt, char *out, size_t cap,
                      const atomic_bool *cancel);
bool zapp_bridge_speech(const char *files, const char *request, char *out, size_t cap,
                       const atomic_bool *cancel);
/* Like zapp_bridge_speech for a host that streams: every line with an "event" member goes to
 * on_event before the final reply, which is handled as in zapp_bridge_speech. A false return
 * from on_event ends the call. */
bool zapp_bridge_speech_events(const char *files, const char *request, char *out, size_t cap,
    bool (*on_event)(const struct json_value *event, void *ctx), void *ctx, const atomic_bool *cancel);
#endif
