/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_ASSISTANT_H
#define Z23_ANDROID_ASSISTANT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

/* Read-only tools offered to the model in streamed answers: schema is an OpenAI tools array,
 * guide is added to the system prompt whenever they are offered, and run executes one call,
 * writing its result, untrusted observation text, to out; it returns false for a refused call.
 * wanted, when set, fills the call a prompt needs, a tool name and JSON arguments, which then
 * runs before the model answers. */
struct zapp_assistant_tools {
    const struct json_value *schema;
    const char *guide;
    bool (*run)(const char *name, const char *arguments, char *out, size_t cap);
    bool (*wanted)(const char *prompt, char *name, size_t name_cap, char *arguments,
                   size_t arguments_cap);
};
/* Local inference servers on 127.0.0.1. The speaker reference is a WAV used
 * to condition synthesis; it is owned by the caller and outlives each call. tools is NULL
 * when the model has none. */
struct zapp_assistant {
    uint16_t chat_port, asr_port, tts_port;
    const char *speaker_b64;
    const struct zapp_assistant_tools *tools;
};
/* Every call aborts when client_fd disconnects. Errors are written as user text. */
bool zapp_assistant_transcribe(const struct zapp_assistant *a, const unsigned char *wav,
    size_t size, int client_fd, char *text, size_t cap);
/* history is NULL or an array of at most ZAPP_ASSISTANT_TURNS [question, answer] string pairs,
 * oldest first, sent as earlier turns. context is untrusted observation text (node and fleet)
 * shown to the model as data with the current question. */
#define ZAPP_ASSISTANT_TURNS 32u
bool zapp_assistant_chat(const struct zapp_assistant *a, const char *prompt,
    const struct json_value *history, const char *context, int client_fd, char *answer, size_t cap);
/* Like chat, but streams: each spoken chunk is sent to client_fd as a text event followed by
 * PCM16 events (zapp_relay_emit) while the model is still writing. answer holds the full text.
 * With tools, a call the prompt wants runs first and its result goes with the question in the only
 * request, which offers no tools; otherwise a reply that only calls one is run and its result goes
 * to a second request without tools. */
bool zapp_assistant_respond(const struct zapp_assistant *a, const char *prompt,
    const struct json_value *history, const char *context, int client_fd, char *answer, size_t cap);
/* Returns mono PCM16 WAV owned by the caller, which cleanses and frees it. */
bool zapp_assistant_speak(const struct zapp_assistant *a, const char *text,
    int client_fd, unsigned char **wav, size_t *size);
/* Base64 of bytes, NUL-terminated, owned by the caller. */
char *zapp_assistant_base64(const unsigned char *bytes, size_t size);
#endif
