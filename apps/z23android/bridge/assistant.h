/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_ASSISTANT_H
#define Z23_ANDROID_ASSISTANT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Local inference servers on 127.0.0.1. The speaker reference is a WAV used
 * to condition synthesis; it is owned by the caller and outlives each call. */
struct zapp_assistant {
    uint16_t chat_port, asr_port, tts_port;
    const char *speaker_b64;
};
/* Every call aborts when client_fd disconnects. Errors are written as user text. */
bool zapp_assistant_transcribe(const struct zapp_assistant *a, const unsigned char *wav,
    size_t size, int client_fd, char *text, size_t cap);
/* context is untrusted observation text (node and fleet) shown to the model as data. */
bool zapp_assistant_chat(const struct zapp_assistant *a, const char *prompt,
    const char *context, int client_fd, char *answer, size_t cap);
/* Like chat, but streams: each spoken chunk is sent to client_fd as a text event followed by
 * PCM16 events (zapp_relay_emit) while the model is still writing. answer holds the full text. */
bool zapp_assistant_respond(const struct zapp_assistant *a, const char *prompt,
    const char *context, int client_fd, char *answer, size_t cap);
/* Returns mono PCM16 WAV owned by the caller, which cleanses and frees it. */
bool zapp_assistant_speak(const struct zapp_assistant *a, const char *text,
    int client_fd, unsigned char **wav, size_t *size);
/* Base64 of bytes, NUL-terminated, owned by the caller. */
char *zapp_assistant_base64(const unsigned char *bytes, size_t size);
#endif
