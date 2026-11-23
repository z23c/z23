/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: monotonic microsecond clock for --qa-frames. Kept out of the raylib
 * translation unit because windows.h redeclares CloseWindow/ShowCursor/Rectangle. */
#include "sky_combat/qa_timing.h"
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

uint64_t sky_qa_now_us(void)
{
    LARGE_INTEGER freq, now;
    if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&now) ||
        freq.QuadPart <= 0) return 0;
    uint64_t ticks = (uint64_t)now.QuadPart, hz = (uint64_t)freq.QuadPart;
    return ticks / hz * 1000000u + ticks % hz * 1000000u / hz;
}
#else
uint64_t sky_qa_now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}
#endif
