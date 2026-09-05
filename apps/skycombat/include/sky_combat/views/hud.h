/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_HUD_H
#define SKY_COMBAT_HUD_H

#include "../models/aircraft.h"
#include "../models/course.h"
#include "../controllers/input.h"

typedef struct {
    bool show_fps;
    bool show_controls;
    bool show_minimap;
} hud_config_t;

// HUD management
void hud_draw(aircraft_t* aircraft, course_t* course, input_state_t* input, hud_config_t* config);
void hud_draw_victory(int score, float time);
void hud_draw_pause_menu(void);

// HUD configuration
hud_config_t hud_default_config(void);

#endif // SKY_COMBAT_HUD_H