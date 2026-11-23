/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* purpose: allocation-free per-frame timing summary for --qa-frames runs. */
#ifndef SKY_COMBAT_QA_TIMING_H
#define SKY_COMBAT_QA_TIMING_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#endif
#include "sky_combat/qa_frames.h"

/* Monotonic microseconds; the origin is arbitrary, only differences matter. */
static inline uint64_t sky_qa_now_us(void)
{
#if defined(_WIN32)
    LARGE_INTEGER freq, now;
    if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&now) ||
        freq.QuadPart <= 0) return 0;
    uint64_t ticks = (uint64_t)now.QuadPart, hz = (uint64_t)freq.QuadPart;
    return ticks / hz * 1000000u + ticks % hz * 1000000u / hz;
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
#endif
}

/* Fixed storage sized for the QA frame ceiling: recording never allocates. */
struct sky_qa_timing {
    uint64_t start_us;       /* sampled at main entry */
    uint64_t first_frame_us; /* start to the end of the first presented frame */
    unsigned count;
    uint32_t frame_us[SKY_COMBAT_QA_FRAMES_MAX];
};

struct sky_qa_summary {
    unsigned frames;
    uint64_t first_frame_us;
    uint32_t min_us, median_us, p95_us, p99_us, max_us;
};

static inline void sky_qa_timing_begin(struct sky_qa_timing *timing, uint64_t now_us)
{
    timing->start_us = now_us;
    timing->first_frame_us = 0;
    timing->count = 0;
}

/* One frame spanning [began_us, ended_us]. Frames past the ceiling are dropped. */
static inline void sky_qa_timing_record(struct sky_qa_timing *timing,
                                        uint64_t began_us, uint64_t ended_us)
{
    if (timing->count >= SKY_COMBAT_QA_FRAMES_MAX) return;
    uint64_t span = ended_us >= began_us ? ended_us - began_us : 0;
    if (span > UINT32_MAX) span = UINT32_MAX;
    if (timing->count == 0)
        timing->first_frame_us = ended_us >= timing->start_us ? ended_us - timing->start_us : 0;
    timing->frame_us[timing->count++] = (uint32_t)span;
}

static inline int sky_qa_u32_compare(const void *left, const void *right)
{
    uint32_t a = *(const uint32_t *)left, b = *(const uint32_t *)right;
    return (a > b) - (a < b);
}

/* Nearest-rank percentile over sorted values: index ceil(pct * n / 100) - 1. */
static inline uint32_t sky_qa_percentile(const uint32_t *sorted, unsigned count, unsigned pct)
{
    size_t rank = ((size_t)count * pct + 99u) / 100u;
    return sorted[(rank ? rank : 1u) - 1u];
}

/* Sorts timing->frame_us in place (no allocation). False when no frame ran. */
static inline bool sky_qa_timing_summarize(struct sky_qa_timing *timing,
                                           struct sky_qa_summary *out)
{
    if (!timing || !out || timing->count == 0) return false;
    unsigned n = timing->count;
    qsort(timing->frame_us, n, sizeof(timing->frame_us[0]), sky_qa_u32_compare);
    out->frames = n;
    out->first_frame_us = timing->first_frame_us;
    out->min_us = timing->frame_us[0];
    out->median_us = sky_qa_percentile(timing->frame_us, n, 50);
    out->p95_us = sky_qa_percentile(timing->frame_us, n, 95);
    out->p99_us = sky_qa_percentile(timing->frame_us, n, 99);
    out->max_us = timing->frame_us[n - 1];
    return true;
}

/* The one machine-readable line: key=value pairs, space separated, no newline. */
static inline bool sky_qa_summary_format(const struct sky_qa_summary *s, char *buffer, size_t capacity)
{
    int n = snprintf(buffer, capacity,
        "QA_FRAME_TIMES frames=%u first_frame_us=%llu min_us=%u median_us=%u p95_us=%u p99_us=%u max_us=%u",
        s->frames, (unsigned long long)s->first_frame_us, s->min_us, s->median_us,
        s->p95_us, s->p99_us, s->max_us);
    return n > 0 && (size_t)n < capacity;
}
#endif
