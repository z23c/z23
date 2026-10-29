/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_AUDIO_H
#define ZAPP_AUDIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

/* Synchronous worker-only calls. The caller retains buffers and flags until return. */

/* Records 16 kHz mono until stop, cancel, capacity, or the end of an utterance. */
bool zapp_audio_capture(int16_t *samples, size_t capacity, size_t *count,
                        const atomic_bool *stop, const atomic_bool *cancel,
                        char *error, size_t error_cap);

/* Gapless streaming playback: queued audio plays while the caller prepares more.
 * Write blocks only while 20 seconds of audio are already queued. */
struct zapp_player;
bool zapp_player_open(struct zapp_player **player, int sample_rate,
                      char *error, size_t error_cap);
int zapp_player_rate(const struct zapp_player *player);
bool zapp_player_write(struct zapp_player *player, const int16_t *samples, size_t count,
                       const atomic_bool *cancel, char *error, size_t error_cap);
/* Plays out queued audio when drain is true, then releases the player (NULL is a no-op). */
bool zapp_player_close(struct zapp_player *player, bool drain,
                       const atomic_bool *cancel, char *error, size_t error_cap);

#endif
