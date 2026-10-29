/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_VOICE_H
#define ZAPP_VOICE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum zapp_voice_intent {
    ZAPP_VOICE_UNKNOWN, ZAPP_VOICE_STATUS, ZAPP_VOICE_BALANCE,
    ZAPP_VOICE_START, ZAPP_VOICE_STOP
};
/* START and STOP are proposals; callers must obtain confirmation to execute. */
enum zapp_voice_intent zapp_voice_interpret(const char *text);
#define ZAPP_VOICE_CAPTURE_RATE 16000u
#define ZAPP_VOICE_MAX_SECONDS 20u
#define ZAPP_VOICE_CAPTURE_SAMPLES 320000u
#define ZAPP_VOICE_PLAYBACK_SAMPLES 960000u
#define ZAPP_VOICE_WAV_BYTES 2097152u
/* Capture is mono PCM16 at 16 kHz. Output size is zero on failure. */
bool zapp_voice_wav_encode(const int16_t *samples, size_t count,
    unsigned char *wav, size_t capacity, size_t *size);
/* Playback accepts mono PCM16 at 16..48 kHz, at most 20 seconds and 2 MiB.
 * Count and rate are zero on failure; sample output may be partially written. */
bool zapp_voice_wav_decode(const unsigned char *wav, size_t size,
    int16_t *samples, size_t capacity, size_t *count, uint32_t *rate);
/* End-of-utterance detection over 100 ms frames (1600 samples at 16 kHz). A frame is speech
 * when its mean absolute level is at least four times the quietest nonzero frame and at
 * least 150. An utterance ends after 200 ms of speech followed by 800 ms without speech. */
#define ZAPP_VOICE_FRAME 1600u
struct zapp_endpoint { uint32_t floor, peak, frames, voiced, quiet; bool speech; };
void zapp_endpoint_init(struct zapp_endpoint *e);
bool zapp_endpoint_update(struct zapp_endpoint *e, const int16_t *frame, size_t count);
/* Length of the next spoken chunk of at most cap bytes: whole sentences, else clauses, else
 * words, never splitting UTF-8. Returns 0 only for empty text or a zero cap. */
size_t zapp_voice_chunk(const char *text, size_t cap);
#endif
