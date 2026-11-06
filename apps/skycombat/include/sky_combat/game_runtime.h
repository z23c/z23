/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#ifndef SKY_COMBAT_GAME_RUNTIME_H
#define SKY_COMBAT_GAME_RUNTIME_H
#include <stdbool.h>
#include <stdint.h>

enum sky_game_visual_domain {
    SKY_VISUAL_SPEED = 1,
    SKY_VISUAL_WORLD,
    SKY_VISUAL_SHAKE
};

/* One game process/session. Agent time advances only at an accepted tick;
 * interactive time delegates to raylib. Reseed after fixed-layout world init. */
void sky_game_runtime_begin(bool agent, uint32_t seed);
void sky_game_runtime_reseed(void);
void sky_game_runtime_tick(void);
bool sky_game_runtime_agent(void);
uint64_t sky_game_runtime_ticks(void);
double sky_game_runtime_time(void);

/* Inclusive range, pure keyed sample: never touches libc/raylib RNG state.
 * Interactive cosmetics use a real-time 60 Hz bucket instead of agent ticks. */
int sky_game_visual_sample(uint32_t domain, uint32_t index, int minimum, int maximum);
#endif
