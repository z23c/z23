/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "audio.h"
#include "voice.h"
#include "base/cleanse.h"

#include <aaudio/AAudio.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define AUDIO_WAIT_NS INT64_C(100000000)
#define AUDIO_STALL_NS INT64_C(2000000000)
#define AUDIO_POLL_NS 20000000L
#define AUDIO_QUEUE_SECONDS 20u
/* Presentation delay after the last queued frame leaves the buffer. */
#define AUDIO_TAIL_NS INT64_C(200000000)

struct zapp_player {
    AAudioStream *stream;
    int rate;
    size_t cap;
    _Atomic uint64_t head, tail;
    atomic_bool failed;
    int16_t *ring;
    /* Written by the playback callback only; read after the stream is closed. */
    uint64_t played, silent, gap_frames;
    uint32_t gaps;
};

static bool audio_error(char *error, size_t cap, const char *message,
                        aaudio_result_t result) {
    if (error != NULL && cap != 0)
        (void)snprintf(error, cap, "%s: %s", message, AAudio_convertResultToText(result));
    return false;
}

static bool audio_flag(const atomic_bool *flag) {
    return flag != NULL && atomic_load_explicit(flag, memory_order_relaxed);
}

static int64_t audio_now(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * INT64_C(1000000000) + now.tv_nsec;
}

static void audio_pause(void) {
    struct timespec ts = {.tv_nsec = AUDIO_POLL_NS};
    (void)nanosleep(&ts, NULL);
}

static aaudio_data_callback_result_t player_feed(AAudioStream *stream, void *user,
                                                 void *data, int32_t frames) {
    (void)stream;
    struct zapp_player *p = user;
    int16_t *out = data;
    uint64_t tail = atomic_load_explicit(&p->tail, memory_order_relaxed);
    uint64_t head = atomic_load_explicit(&p->head, memory_order_acquire);
    size_t n = head - tail < (uint64_t)frames ? (size_t)(head - tail) : (size_t)frames;
    for (size_t i = 0; i < n; ++i) out[i] = p->ring[(tail + i) % p->cap];
    for (size_t i = n; i < (size_t)frames; ++i) out[i] = 0;
    if (n && p->silent) { p->gaps++; p->gap_frames += p->silent; p->silent = 0; }
    if (p->played && n < (size_t)frames) p->silent += (size_t)frames - n;
    p->played += n;
    atomic_store_explicit(&p->tail, tail + n, memory_order_release);
    return AAUDIO_CALLBACK_RESULT_CONTINUE;
}

static void player_fault(AAudioStream *stream, void *user, aaudio_result_t result) {
    (void)stream; (void)result;
    atomic_store(&((struct zapp_player *)user)->failed, true);
}

static bool audio_open(AAudioStream **stream, aaudio_direction_t direction, int rate,
                       struct zapp_player *player, char *error, size_t cap) {
    AAudioStreamBuilder *builder = NULL;
    aaudio_result_t result = AAudio_createStreamBuilder(&builder);
    if (result != AAUDIO_OK)
        return audio_error(error, cap, "Create audio builder", result);
    AAudioStreamBuilder_setDirection(builder, direction);
    AAudioStreamBuilder_setSharingMode(builder, AAUDIO_SHARING_MODE_SHARED);
    AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_I16);
    AAudioStreamBuilder_setChannelCount(builder, 1);
    AAudioStreamBuilder_setSampleRate(builder, rate);
    if (player != NULL) {
        AAudioStreamBuilder_setDataCallback(builder, player_feed, player);
        AAudioStreamBuilder_setErrorCallback(builder, player_fault, player);
    }
    result = AAudioStreamBuilder_openStream(builder, stream);
    aaudio_result_t deleted = AAudioStreamBuilder_delete(builder);
    if (result != AAUDIO_OK)
        return audio_error(error, cap, "Open audio stream", result);
    if (deleted != AAUDIO_OK)
        return audio_error(error, cap, "Delete audio builder", deleted);
    if (AAudioStream_getFormat(*stream) != AAUDIO_FORMAT_PCM_I16 ||
        AAudioStream_getChannelCount(*stream) != 1 ||
        AAudioStream_getSampleRate(*stream) != rate)
        return audio_error(error, cap, "Unsupported negotiated audio format", AAUDIO_ERROR_INVALID_FORMAT);
    result = AAudioStream_requestStart(*stream);
    if (result != AAUDIO_OK)
        return audio_error(error, cap, "Start audio stream", result);
    return true;
}

static bool audio_close(AAudioStream *stream, bool ok, char *error, size_t cap) {
    if (stream == NULL) return ok;
    aaudio_result_t result = AAudioStream_requestStop(stream);
    aaudio_result_t closed = AAudioStream_close(stream);
    if (ok && result != AAUDIO_OK)
        return audio_error(error, cap, "Stop audio stream", result);
    if (ok && closed != AAUDIO_OK)
        return audio_error(error, cap, "Close audio stream", closed);
    return ok;
}

static bool capture_precheck(const int16_t *samples, size_t capacity, const size_t *count,
                             const atomic_bool *stop, const atomic_bool *cancel,
                             char *error, size_t error_cap) {
    if (samples == NULL || count == NULL || capacity < 480 || capacity > 320000)
        return audio_error(error, error_cap, "Invalid capture buffer", AAUDIO_ERROR_ILLEGAL_ARGUMENT);
    if (audio_flag(cancel))
        return audio_error(error, error_cap, "Recording cancelled", AAUDIO_ERROR_INVALID_STATE);
    if (audio_flag(stop))
        return audio_error(error, error_cap, "Recording too short", AAUDIO_ERROR_ILLEGAL_ARGUMENT);
    return true;
}

/* Reads one frame block; advances `used` and `progress`. Fails on read error or stall. */
static bool capture_read(AAudioStream *stream, int16_t *samples, size_t *used, size_t capacity,
                         int64_t *progress, char *error, size_t error_cap) {
    size_t remaining = capacity - *used;
    int32_t frames = (int32_t)(remaining < ZAPP_VOICE_FRAME ? remaining : ZAPP_VOICE_FRAME);
    aaudio_result_t result = AAudioStream_read(stream, samples + *used, frames, AUDIO_WAIT_NS);
    int64_t now = audio_now();
    if (result < 0 || result > frames)
        return audio_error(error, error_cap, "Read microphone", result < 0 ? result : AAUDIO_ERROR_INTERNAL);
    if (now < 0 || *progress < 0 || (result == 0 && now - *progress >= AUDIO_STALL_NS))
        return audio_error(error, error_cap, "Microphone stalled", AAUDIO_ERROR_TIMEOUT);
    if (result > 0) {
        *used += (size_t)result;
        *progress = now;
    }
    return true;
}

static bool capture_scan(struct zapp_endpoint *endpoint, const int16_t *samples, size_t used, size_t *scanned) {
    bool ended = false;
    for (; !ended && used - *scanned >= ZAPP_VOICE_FRAME; *scanned += ZAPP_VOICE_FRAME)
        ended = zapp_endpoint_update(endpoint, samples + *scanned, ZAPP_VOICE_FRAME);
    return ended;
}

/* A recording that heard nothing and was not stopped by the owner is empty, not too short. */
static bool capture_verdict(bool ok, size_t used, bool kept, const atomic_bool *cancel,
                            char *error, size_t error_cap) {
    if (audio_flag(cancel))
        ok = audio_error(error, error_cap, "Recording cancelled", AAUDIO_ERROR_INVALID_STATE);
    if (ok && kept && used < 480)
        ok = audio_error(error, error_cap, "Recording too short", AAUDIO_ERROR_ILLEGAL_ARGUMENT);
    return ok;
}

static bool capture_loop(AAudioStream *stream, int16_t *samples, size_t capacity, size_t *used,
                         struct zapp_endpoint *endpoint, uint32_t wait_frames, const atomic_bool *stop,
                         const atomic_bool *cancel, char *error, size_t error_cap) {
    size_t scanned = 0;
    bool ok = true, ended = false;
    int64_t progress = audio_now();
    while (ok && !ended && *used < capacity && !audio_flag(stop) && !audio_flag(cancel)) {
        ok = capture_read(stream, samples, used, capacity, &progress, error, error_cap);
        ended = capture_scan(endpoint, samples, *used, &scanned) ||
            zapp_endpoint_waited(endpoint, wait_frames);
    }
    return ok;
}

bool zapp_audio_capture(int16_t *samples, size_t capacity, size_t *count, unsigned wait_ms,
                        bool *heard, const atomic_bool *stop, const atomic_bool *cancel,
                        char *error, size_t error_cap) {
    if (error != NULL && error_cap != 0) error[0] = '\0';
    if (count != NULL) *count = 0;
    if (heard == NULL)
        return audio_error(error, error_cap, "Invalid capture request", AAUDIO_ERROR_ILLEGAL_ARGUMENT);
    *heard = false;
    if (!capture_precheck(samples, capacity, count, stop, cancel, error, error_cap)) return false;
    AAudioStream *stream = NULL;
    bool ok = audio_open(&stream, AAUDIO_DIRECTION_INPUT, ZAPP_VOICE_CAPTURE_RATE, NULL, error, error_cap);
    struct zapp_endpoint endpoint;
    zapp_endpoint_init(&endpoint);
    uint32_t wait_frames = (uint32_t)((uint64_t)wait_ms * ZAPP_VOICE_CAPTURE_RATE / 1000 / ZAPP_VOICE_FRAME);
    size_t used = 0;
    ok = ok && capture_loop(stream, samples, capacity, &used, &endpoint, wait_frames, stop, cancel,
                             error, error_cap);
    __android_log_print(ANDROID_LOG_INFO, "z23", "voice capture %zu ms, level floor %u peak %u, %s",
                        used * 1000 / ZAPP_VOICE_CAPTURE_RATE, endpoint.floor, endpoint.peak,
                        endpoint.speech && endpoint.quiet >= 8 ? "utterance ended" :
                        endpoint.speech ? "speech, no end" : "no speech");
    *heard = endpoint.speech;
    bool kept = endpoint.speech || audio_flag(stop);
    ok = audio_close(stream, capture_verdict(ok, used, kept, cancel, error, error_cap), error, error_cap);
    if (ok) *count = used;
    return ok;
}

bool zapp_player_open(struct zapp_player **player, int sample_rate, char *error, size_t error_cap) {
    if (error != NULL && error_cap != 0) error[0] = '\0';
    if (player == NULL || sample_rate < 16000 || sample_rate > 48000)
        return audio_error(error, error_cap, "Invalid playback audio", AAUDIO_ERROR_ILLEGAL_ARGUMENT);
    *player = NULL;
    struct zapp_player *p = calloc(1, sizeof(*p));
    size_t cap = (size_t)sample_rate * AUDIO_QUEUE_SECONDS;
    if (p == NULL || (p->ring = calloc(cap, sizeof(*p->ring))) == NULL) {
        free(p);
        return audio_error(error, error_cap, "Allocate playback queue", AAUDIO_ERROR_NO_MEMORY);
    }
    p->rate = sample_rate;
    p->cap = cap;
    if (!audio_open(&p->stream, AAUDIO_DIRECTION_OUTPUT, sample_rate, p, error, error_cap)) {
        (void)zapp_player_close(p, false, NULL, NULL, 0);
        return false;
    }
    *player = p;
    return true;
}

int zapp_player_rate(const struct zapp_player *player) {
    return player != NULL ? player->rate : 0;
}

/* Waits until the queue holds at most `limit` frames; fails on cancel, fault or stall. */
static bool player_wait(struct zapp_player *p, uint64_t limit, const atomic_bool *cancel,
                        char *error, size_t cap) {
    uint64_t last = atomic_load_explicit(&p->tail, memory_order_acquire);
    int64_t progress = audio_now();
    for (;;) {
        uint64_t tail = atomic_load_explicit(&p->tail, memory_order_acquire);
        uint64_t head = atomic_load_explicit(&p->head, memory_order_relaxed);
        int64_t now = audio_now();
        if (head - tail <= limit) return true;
        if (audio_flag(cancel))
            return audio_error(error, cap, "Playback cancelled", AAUDIO_ERROR_INVALID_STATE);
        if (atomic_load(&p->failed))
            return audio_error(error, cap, "Playback interrupted", AAUDIO_ERROR_DISCONNECTED);
        if (tail != last) { last = tail; progress = now; }
        if (now < 0 || progress < 0 || now - progress >= AUDIO_STALL_NS)
            return audio_error(error, cap, "Playback stalled", AAUDIO_ERROR_TIMEOUT);
        audio_pause();
    }
}

bool zapp_player_write(struct zapp_player *p, const int16_t *samples, size_t count,
                       const atomic_bool *cancel, char *error, size_t error_cap) {
    if (error != NULL && error_cap != 0) error[0] = '\0';
    if (p == NULL || (samples == NULL && count != 0))
        return audio_error(error, error_cap, "Invalid playback audio", AAUDIO_ERROR_ILLEGAL_ARGUMENT);
    for (size_t used = 0; used < count;) {
        if (!player_wait(p, p->cap - 1, cancel, error, error_cap)) return false;
        uint64_t head = atomic_load_explicit(&p->head, memory_order_relaxed);
        uint64_t tail = atomic_load_explicit(&p->tail, memory_order_acquire);
        size_t space = p->cap - (size_t)(head - tail), n = count - used < space ? count - used : space;
        for (size_t i = 0; i < n; ++i) p->ring[(head + i) % p->cap] = samples[used + i];
        atomic_store_explicit(&p->head, head + n, memory_order_release);
        used += n;
    }
    return true;
}

bool zapp_player_close(struct zapp_player *p, bool drain, const atomic_bool *cancel,
                       char *error, size_t error_cap) {
    if (p == NULL) return true;
    bool ok = !drain || player_wait(p, 0, cancel, error, error_cap);
    if (ok && drain && p->stream != NULL) {
        int32_t buffered = AAudioStream_getBufferSizeInFrames(p->stream);
        int64_t tail = (buffered > 0 ? buffered : 0) * INT64_C(1000000000) / p->rate + AUDIO_TAIL_NS;
        for (int64_t start = audio_now(), now = start; ok && now >= 0 && now - start < tail; now = audio_now()) {
            if (audio_flag(cancel))
                ok = audio_error(error, error_cap, "Playback cancelled", AAUDIO_ERROR_INVALID_STATE);
            else audio_pause();
        }
    }
    ok = audio_close(p->stream, ok, error, error_cap);
    if (p->played)
        __android_log_print(ANDROID_LOG_INFO, "z23", "voice playback %llu ms, %u gaps totaling %llu ms",
                            (unsigned long long)(p->played * 1000 / (uint64_t)p->rate), p->gaps,
                            (unsigned long long)(p->gap_frames * 1000 / (uint64_t)p->rate));
    memory_cleanse(p->ring, p->cap * sizeof(*p->ring));
    free(p->ring);
    free(p);
    return ok;
}
