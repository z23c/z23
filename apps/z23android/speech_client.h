/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SPEECH_CLIENT_H
#define ZAPP_SPEECH_CLIENT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
struct json_value;
bool zapp_speech_client_pair(const char *files, const char *json, char *error, size_t cap);
/* True when the stored pairing is exactly this descriptor. */
bool zapp_speech_client_paired(const char *files, const char *json);
/* True when a laptop host pairing is stored, whatever its descriptor. */
bool zapp_speech_client_has_host(const char *files);
bool zapp_speech_client_transcribe(const char *files, const int16_t *samples, size_t count,
    char *text, size_t cap, const atomic_bool *cancel);
bool zapp_speech_client_speak(const char *files, const char *text, int16_t **samples,
    size_t *count, int *rate, const atomic_bool *cancel, char *error, size_t cap);
/* Asks the paired laptop's private model; on failure answer holds user-facing text. history is
 * NULL or a JSON array of earlier [question, answer] pairs, oldest first. */
bool zapp_speech_client_chat(const char *files, const char *prompt, const struct json_value *history,
    char *answer, size_t cap, const atomic_bool *cancel);
/* Streams the paired laptop's answer: on_text receives each spoken sentence and on_pcm each run
 * of mono PCM16 samples as the host produces them. answer holds the full text, or user-facing
 * error text on failure. The sample buffer is cleansed after each callback. history is as for
 * zapp_speech_client_chat. */
bool zapp_speech_client_respond(const char *files, const char *prompt, const struct json_value *history,
    void (*on_text)(const char *text, void *ctx),
    void (*on_pcm)(const int16_t *samples, size_t count, int rate, void *ctx),
    void *ctx, char *answer, size_t cap, const atomic_bool *cancel);
/* Writes the host's fleet snapshot as JSON; refresh probes the hosts again first. */
bool zapp_speech_client_fleet(const char *files, bool refresh, char *out, size_t cap,
    const atomic_bool *cancel);
/* Sends "errors <host>", "plan <host>" or "confirm <host> <plan id>" to the laptop host and writes its
 * reply object ({"host","action","text"[,"plan_id"]} or {"host","error"}). False when the host did not
 * answer; out then holds a sentence for the owner. */
bool zapp_speech_client_ops(const char *files, const char *scope, char *out, size_t cap,
    const atomic_bool *cancel);
#endif
