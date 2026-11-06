/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: explicit agent tick clock and observational cosmetic samples. */
#include "sky_combat/game_runtime.h"
#include <raylib.h>
#include <math.h>
#include <stdlib.h>

static bool sky_runtime_agent;
static uint32_t sky_runtime_seed = 1;
static uint64_t sky_runtime_ticks;

void sky_game_runtime_reseed(void)
{
    if (sky_runtime_agent) {
        srand(sky_runtime_seed);
        SetRandomSeed(sky_runtime_seed);
    }
}

void sky_game_runtime_begin(bool agent, uint32_t seed)
{
    sky_runtime_agent = agent;
    sky_runtime_seed = seed;
    sky_runtime_ticks = 0;
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
