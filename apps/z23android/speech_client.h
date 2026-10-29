/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SPEECH_CLIENT_H
#define ZAPP_SPEECH_CLIENT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
bool zapp_speech_client_pair(const char *files, const char *json, char *error, size_t cap);
/* True when the stored pairing is exactly this descriptor. */
bool zapp_speech_client_paired(const char *files, const char *json);
bool zapp_speech_client_transcribe(const char *files, const int16_t *samples, size_t count,
    char *text, size_t cap, const atomic_bool *cancel);
bool zapp_speech_client_speak(const char *files, const char *text, int16_t **samples,
    size_t *count, int *rate, const atomic_bool *cancel, char *error, size_t cap);
/* Asks the paired laptop's private model; on failure answer holds user-facing text. */
bool zapp_speech_client_chat(const char *files, const char *prompt, char *answer, size_t cap,
    const atomic_bool *cancel);
/* Writes the host's fleet snapshot as JSON; refresh probes the hosts again first. */
bool zapp_speech_client_fleet(const char *files, bool refresh, char *out, size_t cap,
    const atomic_bool *cancel);
#endif
