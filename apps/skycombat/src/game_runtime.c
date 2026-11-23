/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: explicit agent tick clock and observational cosmetic samples. */
#include "sky_combat/game_runtime.h"
#include <raylib.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

static bool sky_runtime_agent;
static bool sky_runtime_fixed_seed;
static uint32_t sky_runtime_seed = 1;
static uint64_t sky_runtime_ticks;

void sky_game_runtime_reseed(void)
{
    if (sky_runtime_agent || sky_runtime_fixed_seed) {
        srand(sky_runtime_seed);
        SetRandomSeed(sky_runtime_seed);
    }
}

void sky_game_runtime_begin(bool agent, uint32_t seed)
{
    sky_runtime_agent = agent;
    sky_runtime_seed = seed;
    sky_runtime_ticks = 0;
    sky_runtime_fixed_seed = false;
    sky_game_runtime_reseed();
}

void sky_game_runtime_tick(void)
{
    /* The agent protocol caps a session at 36000 ticks. */
    if (sky_runtime_agent) ++sky_runtime_ticks;
}

bool sky_game_runtime_agent(void) { return sky_runtime_agent; }
uint64_t sky_game_runtime_ticks(void) { return sky_runtime_ticks; }
double sky_game_runtime_time(void)
{
    return sky_runtime_agent ? (double)sky_runtime_ticks / 60.0 : GetTime();
}

int sky_game_visual_sample(uint32_t domain, uint32_t index, int minimum, int maximum)
{
    if (maximum <= minimum) return minimum;
    uint64_t tick = sky_runtime_ticks;
    if (!sky_runtime_agent) {
        double seconds = GetTime();
        tick = isfinite(seconds) && seconds >= 0 && seconds < 1.0e12
            ? (uint64_t)(seconds * 60.0) : 0;
    }
    /* Noncryptographic integer mixer; independent domains/indices make draw
     * order irrelevant, including multiple observes at the same agent tick. */
    uint64_t value = (uint64_t)sky_runtime_seed ^
        (tick * UINT64_C(0x9e3779b97f4a7c15)) ^
        ((uint64_t)domain << 32) ^ (uint64_t)index;
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    uint64_t span = (uint64_t)((int64_t)maximum - (int64_t)minimum) + 1;
    return (int)((int64_t)minimum + (int64_t)(value % span));
}

#define SKY_METRICS_CAPACITY 36000u
static float sky_metric_work[SKY_METRICS_CAPACITY];
static float sky_metric_interval[SKY_METRICS_CAPACITY];
static float sky_metric_input[SKY_METRICS_CAPACITY];
static size_t sky_metric_work_count;
static size_t sky_metric_interval_count;
static size_t sky_metric_input_count;

void sky_game_metrics_reset(void)
{
    sky_metric_work_count = 0;
    sky_metric_interval_count = 0;
    sky_metric_input_count = 0;
}

void sky_game_metrics_record(float work_ms, float input_ms, float interval_ms, bool external_input)
{
    if (!isfinite(work_ms) || work_ms < 0) return;
    if (sky_metric_work_count < SKY_METRICS_CAPACITY)
        sky_metric_work[sky_metric_work_count++] = work_ms;
    if (external_input) {
        if (isfinite(input_ms) && input_ms >= 0 &&
            sky_metric_input_count < SKY_METRICS_CAPACITY)
            sky_metric_input[sky_metric_input_count++] = input_ms;
    } else if (isfinite(interval_ms) && interval_ms >= 0 &&
               sky_metric_interval_count < SKY_METRICS_CAPACITY) {
        sky_metric_interval[sky_metric_interval_count++] = interval_ms;
    }
}

static int sky_metric_compare(const void *left, const void *right)
{
    float a = *(const float *)left, b = *(const float *)right;
    return (a > b) - (a < b);
}

static void sky_metric_report_one(const char *name, float *values, size_t count)
{
    if (!count) {
        fprintf(stderr, "Sky Combat metrics %s count=0\n", name);
        return;
    }
    qsort(values, count, sizeof(values[0]), sky_metric_compare);
    size_t p50 = count * 50 / 100, p95 = count * 95 / 100, p99 = count * 99 / 100;
    if (p50 >= count) p50 = count - 1;
    if (p95 >= count) p95 = count - 1;
    if (p99 >= count) p99 = count - 1;
    fprintf(stderr, "Sky Combat metrics %s count=%zu p50_ms=%.3f p95_ms=%.3f p99_ms=%.3f max_ms=%.3f\n",
            name, count, (double)values[p50], (double)values[p95],
            (double)values[p99], (double)values[count - 1]);
}

void sky_game_metrics_report(void)
{
    sky_metric_report_one("frame_work", sky_metric_work, sky_metric_work_count);
    sky_metric_report_one("frame_interval", sky_metric_interval, sky_metric_interval_count);
    sky_metric_report_one("input_to_frame", sky_metric_input, sky_metric_input_count);
}

/* A bounded --qa-frames run seeds both RNG streams from the session seed so
 * two runs build the same world; time and cosmetics stay interactive-style. */
void sky_game_runtime_fix_seed(void)
{
    sky_runtime_fixed_seed = true;
    sky_game_runtime_reseed();
}
