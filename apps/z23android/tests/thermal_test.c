/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "thermal.h"
#include <assert.h>
#include <stdio.h>

/* Expected pace for each thermal status 0 to 6, from each pace in effect. */
static void transition_table_tests(void)
{
    static const enum zapp_pace normal[] = {
        ZAPP_PACE_NORMAL, ZAPP_PACE_NORMAL, ZAPP_PACE_GENTLE, ZAPP_PACE_GENTLE,
        ZAPP_PACE_PAUSE, ZAPP_PACE_PAUSE, ZAPP_PACE_PAUSE};
    static const enum zapp_pace gentle[] = {
        ZAPP_PACE_NORMAL, ZAPP_PACE_NORMAL, ZAPP_PACE_GENTLE, ZAPP_PACE_GENTLE,
        ZAPP_PACE_PAUSE, ZAPP_PACE_PAUSE, ZAPP_PACE_PAUSE};
    static const enum zapp_pace paused[] = {
        ZAPP_PACE_NORMAL, ZAPP_PACE_NORMAL, ZAPP_PACE_GENTLE, ZAPP_PACE_PAUSE,
        ZAPP_PACE_PAUSE, ZAPP_PACE_PAUSE, ZAPP_PACE_PAUSE};
    for (int status = 0; status <= 6; status++) {
        assert(zapp_pace_next(ZAPP_PACE_NORMAL, status) == normal[status]);
        assert(zapp_pace_next(ZAPP_PACE_GENTLE, status) == gentle[status]);
        assert(zapp_pace_next(ZAPP_PACE_PAUSE, status) == paused[status]);
    }
}

/* Each threshold is tested on both sides: LIGHT/MODERATE, MODERATE/SEVERE and SEVERE/CRITICAL. */
static void hysteresis_edge_tests(void)
{
    assert(zapp_pace_next(ZAPP_PACE_NORMAL, 1) == ZAPP_PACE_NORMAL);
    assert(zapp_pace_next(ZAPP_PACE_NORMAL, 2) == ZAPP_PACE_GENTLE);
    assert(zapp_pace_next(ZAPP_PACE_GENTLE, 2) == ZAPP_PACE_GENTLE);
    assert(zapp_pace_next(ZAPP_PACE_GENTLE, 1) == ZAPP_PACE_NORMAL);
    assert(zapp_pace_next(ZAPP_PACE_PAUSE, 3) == ZAPP_PACE_PAUSE);
    assert(zapp_pace_next(ZAPP_PACE_PAUSE, 2) == ZAPP_PACE_GENTLE);
    assert(zapp_pace_next(ZAPP_PACE_GENTLE, 3) == ZAPP_PACE_GENTLE);
    assert(zapp_pace_next(ZAPP_PACE_GENTLE, 4) == ZAPP_PACE_PAUSE);
    assert(zapp_pace_next(ZAPP_PACE_NORMAL, 3) == ZAPP_PACE_GENTLE);
    assert(zapp_pace_next(ZAPP_PACE_NORMAL, 4) == ZAPP_PACE_PAUSE);
}

/* A cooling device walks back down through each pace and a heating one holds its pause. */
static void trace_tests(void)
{
    static const int status[] = {0, 2, 4, 3, 2, 1, 0, 3, 4, 1};
    static const enum zapp_pace expected[] = {
        ZAPP_PACE_NORMAL, ZAPP_PACE_GENTLE, ZAPP_PACE_PAUSE, ZAPP_PACE_PAUSE, ZAPP_PACE_GENTLE,
        ZAPP_PACE_NORMAL, ZAPP_PACE_NORMAL, ZAPP_PACE_GENTLE, ZAPP_PACE_PAUSE, ZAPP_PACE_NORMAL};
    enum zapp_pace pace = ZAPP_PACE_NORMAL;
    for (size_t i = 0; i < sizeof(status) / sizeof(status[0]); i++) {
        pace = zapp_pace_next(pace, status[i]);
        assert(pace == expected[i]);
    }
}

int main(void)
{
    transition_table_tests();
    hysteresis_edge_tests();
    trace_tests();
    puts("thermal tests passed");
    return 0;
}
