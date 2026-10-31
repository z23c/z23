/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "clip_player.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

bool zapp_clip_source_open(struct zapp_clip_source *source, const char *path)
{
    struct stat st;
    source->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (source->fd < 0) return false;
    if (fstat(source->fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        (void)close(source->fd);
        source->fd = -1;
        return false;
    }
    source->size = st.st_size;
    source->pread_fn = pread;
    source->trace = NULL;
    source->trace_user = NULL;
    return true;
}

void zapp_clip_source_close(struct zapp_clip_source *source)
{
    if (source->fd >= 0) (void)close(source->fd);
    source->fd = -1;
}

ssize_t zapp_clip_source_read_at(const struct zapp_clip_source *source, int64_t offset, void *buffer, size_t size)
{
    ssize_t result = -1;
    if (size == 0) result = 0;
    else if (offset >= 0 && offset < source->size) {
        int64_t left = source->size - offset;
        size_t want = (int64_t)size < left ? size : (size_t)left;
        size_t got = 0;
        while (got < want) {
            ssize_t n = source->pread_fn(source->fd, (char *)buffer + got, want - got, (off_t)(offset + (int64_t)got));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            got += (size_t)n;
        }
        result = got > 0 ? (ssize_t)got : -1;
    }
    if (source->trace != NULL) source->trace(source->trace_user, offset, size, result);
    return result;
}

void zapp_clip_fit(int screen_width, int screen_height, int clip_width, int clip_height, int *width, int *height)
{
    if (screen_width <= 0 || screen_height <= 0 || clip_width <= 0 || clip_height <= 0) {
        *width = screen_width;
        *height = screen_height;
        return;
    }
    if ((int64_t)screen_width * clip_height <= (int64_t)screen_height * clip_width) {
        *width = screen_width;
        *height = (int)((int64_t)screen_width * clip_height / clip_width);
    } else {
        *height = screen_height;
        *width = (int)((int64_t)screen_height * clip_width / clip_height);
    }
}

#ifdef __ANDROID__
#include "clip_store.h"
#include <aaudio/AAudio.h>
#include <android/log.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaDataSource.h>
#include <media/NdkMediaExtractor.h>
#include <media/NdkMediaFormat.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TAG "z23"
#define RING_FRAMES (48000 * 4)
#define MIN_FREE_SAMPLES 16384
#define DROP_LATE_US 60000
#define EARLY_US 8000
#define LOG_EVERY_US 10000000
#define TRACE_LIMIT 200
#define END_WAIT_US 1500000

struct zapp_clip_player {
    char dir[512], id[ZAPP_CLIP_ID_CAP], message[160];
    ANativeWindow *window;
    pthread_t thread;
    atomic_bool stop, paused, finished, failed;
    struct zapp_clip_source source;
    AMediaDataSource *data;
    AMediaExtractor *extractor;
    AMediaCodec *video, *audio;
    int video_track, audio_track;
    AAudioStream *out;
    int rate, channels;
    int16_t *ring;
    int64_t ring_head, ring_tail, pcm_start_us, written_frames;
    bool pcm_started, video_input_done, audio_input_done, video_done, audio_done, out_paused;
    ssize_t held;
    bool held_last;
    int64_t held_pts, mono_origin_us, paused_at_us, paused_total_us, log_at_us;
    uint32_t rendered, dropped, late_frames;
    int64_t drift_sum_us, drift_max_us, drift_n;
    unsigned traced;
};

static int64_t mono_us(void)
{
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 ? (int64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000 : 0;
}

static void sleep_ms(long ms)
{
    struct timespec ts = {.tv_nsec = ms * 1000000L};
    (void)nanosleep(&ts, NULL);
}

static void refuse(struct zapp_clip_player *p, const char *message)
{
    (void)snprintf(p->message, sizeof(p->message), "%s", message);
    atomic_store(&p->failed, true);
    __android_log_print(ANDROID_LOG_WARN, TAG, "clip playback: %s", message);
}

/* The platform wrapper treats a negative result as a failed read: with -1 at the end of the file the
 * extractor reported end of stream on its first sample (E5). Zero marks the end instead. */
static ssize_t data_read(void *user, off64_t offset, void *buffer, size_t size)
{
    struct zapp_clip_player *p = user;
    ssize_t n = zapp_clip_source_read_at(&p->source, offset, buffer, size);
    return n < 0 ? 0 : n;
}

static ssize_t data_size(void *user)
{
    return (ssize_t)((struct zapp_clip_player *)user)->source.size;
}

static void data_close(void *user) { (void)user; }

static void trace_read(void *user, int64_t offset, size_t size, ssize_t result)
{
    unsigned *count = user;
    if ((*count)++ < TRACE_LIMIT)
        __android_log_print(ANDROID_LOG_INFO, TAG, "clip read #%u offset=%lld want=%zu got=%zd",
                            *count, (long long)offset, size, result);
}

static bool open_source(struct zapp_clip_player *p)
{
    char path[600];
    if (!zapp_clip_store_path(p->dir, p->id, path, sizeof(path)) || !zapp_clip_source_open(&p->source, path)) return false;
    p->source.trace = trace_read;
    p->source.trace_user = &p->traced;
    p->data = AMediaDataSource_new();
    p->extractor = AMediaExtractor_new();
    if (p->data == NULL || p->extractor == NULL) return false;
    AMediaDataSource_setUserdata(p->data, p);
    AMediaDataSource_setReadAt(p->data, data_read);
    AMediaDataSource_setGetSize(p->data, data_size);
    AMediaDataSource_setClose(p->data, data_close);
    return AMediaExtractor_setDataSourceCustom(p->extractor, p->data) == AMEDIA_OK;
}

static bool starts_with(const char *text, const char *prefix) { return text != NULL && !strncmp(text, prefix, strlen(prefix)); }

static bool make_decoder(struct zapp_clip_player *p, size_t track, const char *mime, AMediaFormat *format)
{
    bool is_video = starts_with(mime, "video/");
    AMediaCodec *codec = AMediaCodec_createDecoderByType(mime);
    if (codec == NULL || AMediaExtractor_selectTrack(p->extractor, track) != AMEDIA_OK) return false;
    if (is_video) { p->video = codec; p->video_track = (int)track; } else { p->audio = codec; p->audio_track = (int)track; }
    return AMediaCodec_configure(codec, format, is_video ? p->window : NULL, NULL, 0) == AMEDIA_OK &&
        AMediaCodec_start(codec) == AMEDIA_OK;
}

static bool open_tracks(struct zapp_clip_player *p)
{
    bool ok = true;
    p->video_track = p->audio_track = -1;
    for (size_t i = 0; ok && i < AMediaExtractor_getTrackCount(p->extractor); ++i) {
        AMediaFormat *format = AMediaExtractor_getTrackFormat(p->extractor, i);
        const char *mime = NULL;
        bool known = format != NULL && AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime);
        if (known && starts_with(mime, "video/") && p->video == NULL) ok = make_decoder(p, i, mime, format);
        else if (known && starts_with(mime, "audio/") && p->audio == NULL) ok = make_decoder(p, i, mime, format);
        if (format != NULL) AMediaFormat_delete(format);
    }
    return ok && p->video != NULL;
}

static void output_open(struct zapp_clip_player *p)
{
    AMediaFormat *f = AMediaCodec_getOutputFormat(p->audio);
    int32_t rate = 0, channels = 0;
    bool known = f != NULL && AMediaFormat_getInt32(f, AMEDIAFORMAT_KEY_SAMPLE_RATE, &rate) &&
        AMediaFormat_getInt32(f, AMEDIAFORMAT_KEY_CHANNEL_COUNT, &channels);
    if (f != NULL) AMediaFormat_delete(f);
    if (!known || channels < 1 || channels > 2 || rate < 8000 || rate > 48000) { refuse(p, "This clip's sound cannot be played."); return; }
    AAudioStreamBuilder *b = NULL;
    if (AAudio_createStreamBuilder(&b) != AAUDIO_OK) { refuse(p, "Audio is not available right now."); return; }
    AAudioStreamBuilder_setDirection(b, AAUDIO_DIRECTION_OUTPUT);
    AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_I16);
    AAudioStreamBuilder_setChannelCount(b, channels);
    AAudioStreamBuilder_setSampleRate(b, rate);
    AAudioStreamBuilder_setSharingMode(b, AAUDIO_SHARING_MODE_SHARED);
    aaudio_result_t opened = AAudioStreamBuilder_openStream(b, &p->out);
    (void)AAudioStreamBuilder_delete(b);
    if (opened != AAUDIO_OK || AAudioStream_getSampleRate(p->out) != rate || AAudioStream_getChannelCount(p->out) != channels) {
        refuse(p, "Audio is not available right now.");
        return;
    }
    p->rate = rate;
    p->channels = channels;
    p->ring = calloc((size_t)RING_FRAMES * (size_t)channels, sizeof(*p->ring));
    if (p->ring == NULL) refuse(p, "Out of memory.");
}

static int64_t ring_samples(const struct zapp_clip_player *p) { return p->ring_head - p->ring_tail; }

static void ring_push(struct zapp_clip_player *p, const int16_t *pcm, size_t samples)
{
    size_t cap = (size_t)RING_FRAMES * (size_t)p->channels;
    for (size_t i = 0; i < samples; ++i) p->ring[(size_t)(p->ring_head++) % cap] = pcm[i];
}

/* Moves queued PCM to the output stream without blocking; starts the stream once a buffer's worth is queued. */
static void ring_pump(struct zapp_clip_player *p)
{
    size_t cap = (size_t)RING_FRAMES * (size_t)p->channels;
    if (p->out == NULL || p->out_paused) return;
    if (!p->pcm_started && ring_samples(p) >= (int64_t)p->rate / 5 * p->channels) {
        p->pcm_started = true;
        (void)AAudioStream_requestStart(p->out);
    }
    while (p->pcm_started && ring_samples(p) > 0) {
        size_t at = (size_t)p->ring_tail % cap, run = cap - at;
        int64_t avail = ring_samples(p);
        size_t frames = (size_t)(avail < (int64_t)run ? avail : (int64_t)run) / (size_t)p->channels;
        if (frames == 0) break;
        aaudio_result_t n = AAudioStream_write(p->out, p->ring + at, (int32_t)frames, 0);
        if (n <= 0) break;
        p->ring_tail += (int64_t)n * p->channels;
        p->written_frames += n;
    }
}

static int64_t audio_clock_us(const struct zapp_clip_player *p)
{
    if (p->out == NULL) return mono_us() - p->mono_origin_us - p->paused_total_us - (p->paused_at_us ? mono_us() - p->paused_at_us : 0);
    int64_t played = p->pcm_started ? AAudioStream_getFramesRead(p->out) : 0;
    return p->pcm_start_us + played * 1000000 / p->rate;
}

static bool audio_step(struct zapp_clip_player *p)
{
    if (p->audio == NULL || p->audio_done || p->failed) return false;
    if (ring_samples(p) > (int64_t)RING_FRAMES * p->channels - MIN_FREE_SAMPLES && p->out != NULL) return false;
    AMediaCodecBufferInfo info;
    ssize_t i = AMediaCodec_dequeueOutputBuffer(p->audio, &info, 0);
    if (i == AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED) { output_open(p); return true; }
    if (i < 0) return i == AMEDIACODEC_INFO_OUTPUT_BUFFERS_CHANGED;
    size_t size = 0;
    unsigned char *data = AMediaCodec_getOutputBuffer(p->audio, (size_t)i, &size);
    if (p->out != NULL && data != NULL && info.size > 0 && (size_t)info.offset + (size_t)info.size <= size) {
        if (ring_samples(p) == 0 && !p->pcm_started) p->pcm_start_us = info.presentationTimeUs;
        ring_push(p, (const int16_t *)(const void *)(data + info.offset), (size_t)info.size / sizeof(int16_t));
    }
    if (info.flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) p->audio_done = true;
    (void)AMediaCodec_releaseOutputBuffer(p->audio, (size_t)i, false);
    return true;
}

static void note_drift(struct zapp_clip_player *p, int64_t drift_us)
{
    int64_t magnitude = drift_us < 0 ? -drift_us : drift_us;
    p->drift_sum_us += magnitude;
    p->drift_n++;
    if (magnitude > p->drift_max_us) p->drift_max_us = magnitude;
}

static void log_stats(const struct zapp_clip_player *p, const char *when)
{
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "clip playback %s: rendered %u dropped %u, drift mean %.1f ms max %.1f ms, audio underruns %d",
        when, p->rendered, p->dropped, p->drift_n ? (double)p->drift_sum_us / (double)p->drift_n / 1000.0 : 0.0,
        (double)p->drift_max_us / 1000.0, p->out != NULL ? AAudioStream_getXRunCount(p->out) : 0);
}

/* Shows the next decoded frame when the audio clock reaches it, drops it when it is late. */
static bool video_step(struct zapp_clip_player *p)
{
    if (p->video_done || p->failed) return false;
    AMediaCodecBufferInfo info;
    if (p->held < 0) {
        ssize_t i = AMediaCodec_dequeueOutputBuffer(p->video, &info, 0);
        if (i < 0) return i == AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED || i == AMEDIACODEC_INFO_OUTPUT_BUFFERS_CHANGED;
        p->held_last = info.flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM;
        if (info.size == 0) {
            p->video_done = p->video_done || p->held_last;
            (void)AMediaCodec_releaseOutputBuffer(p->video, (size_t)i, false);
            return true;
        }
        p->held = i;
        p->held_pts = info.presentationTimeUs;
    }
    int64_t drift = audio_clock_us(p) - p->held_pts;
    if (drift < -EARLY_US && p->rendered > 0) return false;
    bool late = drift > DROP_LATE_US && p->rendered > 0;
    (void)AMediaCodec_releaseOutputBuffer(p->video, (size_t)p->held, !late);
    if (late) p->dropped++; else { p->rendered++; note_drift(p, drift); }
    p->held = -1;
    p->video_done = p->held_last;
    return true;
}

static bool feed_sample(struct zapp_clip_player *p)
{
    int track = AMediaExtractor_getSampleTrackIndex(p->extractor);
    AMediaCodec *codec = track == p->video_track ? p->video : track == p->audio_track ? p->audio : NULL;
    bool end = track < 0;
    if (end && p->video_input_done && (p->audio == NULL || p->audio_input_done)) return false;
    if (end) codec = !p->video_input_done ? p->video : p->audio;
    if (codec == NULL) { (void)AMediaExtractor_advance(p->extractor); return true; }
    ssize_t i = AMediaCodec_dequeueInputBuffer(codec, 0);
    if (i < 0) return false;
    size_t capacity = 0;
    unsigned char *buffer = AMediaCodec_getInputBuffer(codec, (size_t)i, &capacity);
    ssize_t n = !end && buffer != NULL ? AMediaExtractor_readSampleData(p->extractor, buffer, capacity) : 0;
    int64_t pts = end ? 0 : AMediaExtractor_getSampleTime(p->extractor);
    (void)AMediaCodec_queueInputBuffer(codec, (size_t)i, 0,
                                       n > 0 ? (size_t)n : 0, (uint64_t)(pts < 0 ? 0 : pts),
                                       end ? AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM : 0);
    if (end) { if (codec == p->video) p->video_input_done = true; else p->audio_input_done = true; }
    else (void)AMediaExtractor_advance(p->extractor);
    return true;
}

static void apply_pause(struct zapp_clip_player *p)
{
    bool want = atomic_load(&p->paused);
    if (want == p->out_paused) return;
    p->out_paused = want;
    if (want) p->paused_at_us = mono_us();
    else { p->paused_total_us += mono_us() - p->paused_at_us; p->paused_at_us = 0; }
    if (p->out != NULL && p->pcm_started)
        (void)(want ? AAudioStream_requestPause(p->out) : AAudioStream_requestStart(p->out));
}

static bool ended(const struct zapp_clip_player *p)
{
    return p->video_done && (p->audio == NULL || p->audio_done) && ring_samples(p) == 0;
}

static void play_loop(struct zapp_clip_player *p)
{
    int64_t end_since = 0;
    p->mono_origin_us = mono_us();
    p->log_at_us = p->mono_origin_us + LOG_EVERY_US;
    while (!atomic_load(&p->stop) && !p->failed) {
        apply_pause(p);
        if (p->out_paused) { sleep_ms(10); continue; }
        bool moved = feed_sample(p);
        moved = audio_step(p) || moved;
        ring_pump(p);
        moved = video_step(p) || moved;
        if (mono_us() >= p->log_at_us) { log_stats(p, "progress"); p->log_at_us += LOG_EVERY_US; }
        if (ended(p)) {
            if (end_since == 0) end_since = mono_us();
            if (p->out == NULL || AAudioStream_getFramesRead(p->out) >= p->written_frames || mono_us() - end_since > END_WAIT_US) break;
        }
        if (!moved) sleep_ms(2);
    }
}

static void release(struct zapp_clip_player *p)
{
    if (p->out != NULL) { (void)AAudioStream_requestStop(p->out); (void)AAudioStream_close(p->out); }
    if (p->video != NULL) { (void)AMediaCodec_stop(p->video); (void)AMediaCodec_delete(p->video); }
    if (p->audio != NULL) { (void)AMediaCodec_stop(p->audio); (void)AMediaCodec_delete(p->audio); }
    if (p->extractor != NULL) (void)AMediaExtractor_delete(p->extractor);
    if (p->data != NULL) AMediaDataSource_delete(p->data);
    zapp_clip_source_close(&p->source);
    free(p->ring);
    p->out = NULL; p->video = p->audio = NULL; p->extractor = NULL; p->data = NULL; p->ring = NULL;
}

static void *run(void *arg)
{
    struct zapp_clip_player *p = arg;
    char error[160];
    if (!zapp_clip_store_verify(p->dir, p->id, error, sizeof(error))) refuse(p, error);
    else if (!open_source(p) || !open_tracks(p)) refuse(p, "This clip cannot be played.");
    else play_loop(p);
    if (!p->failed) log_stats(p, "end");
    release(p);
    atomic_store(&p->finished, true);
    return NULL;
}

struct zapp_clip_player *zapp_clip_player_open(const char *dir, const char *id, ANativeWindow *window)
{
    struct zapp_clip_player *p = calloc(1, sizeof(*p));
    if (p == NULL) return NULL;
    (void)snprintf(p->dir, sizeof(p->dir), "%s", dir);
    (void)snprintf(p->id, sizeof(p->id), "%s", id);
    p->window = window;
    p->held = -1;
    p->source.fd = -1;
    if (pthread_create(&p->thread, NULL, run, p) != 0) { free(p); return NULL; }
    return p;
}

void zapp_clip_player_set_paused(struct zapp_clip_player *p, bool paused) { atomic_store(&p->paused, paused); }
bool zapp_clip_player_paused(const struct zapp_clip_player *p) { return atomic_load(&p->paused); }
bool zapp_clip_player_finished(const struct zapp_clip_player *p) { return atomic_load(&p->finished); }

bool zapp_clip_player_error(const struct zapp_clip_player *p, char *out, size_t cap)
{
    if (!atomic_load(&p->failed) || !atomic_load(&p->finished)) return false;
    (void)snprintf(out, cap, "%s", p->message);
    return true;
}

void zapp_clip_player_close(struct zapp_clip_player *p)
{
    if (p == NULL) return;
    atomic_store(&p->stop, true);
    (void)pthread_join(p->thread, NULL);
    free(p);
}
#endif
