/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/views/hud.h"
#include <raylib.h>
#include <math.h>

hud_config_t hud_default_config(void) {
    hud_config_t config = {
        .show_fps = true,
        .show_controls = true,
        .show_minimap = false
    };
    return config;
}

void hud_draw(aircraft_t* aircraft, course_t* course, input_state_t* input, hud_config_t* config) {
    if (!aircraft || !course || !input || !config) return;
    
    // Main HUD panel
    DrawRectangle(10, 10, 340, 190, Fade(BLACK, 0.7f));
    
    // Score
    DrawText("SCORE", 20, 20, 20, GRAY);
    DrawText(TextFormat("%06d", aircraft->score), 20, 40, 30, GOLD);
    
    // Rings
    DrawText("RINGS", 170, 20, 20, GRAY);
    DrawText(TextFormat("%d/%d", aircraft->rings, course->ring_count), 170, 40, 30, WHITE);
    
    // Speed gauge
    DrawText("SPEED", 20, 80, 20, GRAY);
    int speedPercent = (int)(aircraft_get_speed_percent(aircraft) * 100);
    DrawRectangle(20, 105, 100, 20, Fade(WHITE, 0.3f));
    DrawRectangle(20, 105, speedPercent, 20, GREEN);
    DrawText(TextFormat("%d", (int)aircraft->speed), 130, 105, 20, WHITE);
    
    // Altitude
    DrawText("ALT", 200, 80, 20, GRAY);
    DrawText(TextFormat("%.0fm", aircraft->altitude), 200, 105, 20, WHITE);
    
    // Weapon status
    DrawText("WEAPONS", 20, 140, 20, GRAY);
    DrawText("L2: GUNS", 20, 165, 16, input->fire_guns ? ORANGE : DARKGRAY);
    DrawText("R2: MISSILES", 120, 165, 16, input->fire_missiles ? RED : DARKGRAY);
    
    // Controls reminder
    if (config->show_controls) {
        DrawText("ARCADE FLIGHT CONTROLS", GetScreenWidth()/2 - 150, 20, 24, WHITE);
        DrawText("Left Stick: Turn/Pitch | L1/R1: Barrel Roll | L2/R2: Weapons", 
                GetScreenWidth()/2 - 300, 50, 16, GRAY);
        DrawText("Right Stick: Camera | UR: Speed Boost | UL: Brake", 
                GetScreenWidth()/2 - 250, 70, 16, GRAY);
    }
    
    // Next ring indicator
    ring_t* next_ring = course_get_next_ring(course);
    if (next_ring) {
        float dist = course_get_distance_to_next_ring(course, aircraft->position);
        DrawText(TextFormat("Next Ring: %.0fm", dist), GetScreenWidth() - 200, 20, 20, next_ring->color);
        
        // Completion percentage
        float completion = course_get_completion_percent(course);
        DrawText(TextFormat("Progress: %.0f%%", completion), GetScreenWidth() - 200, 50, 16, WHITE);
    }
    
    // FPS counter
    if (config->show_fps) {
        DrawFPS(GetScreenWidth() - 90, GetScreenHeight() - 40);
    }
}

void hud_draw_victory(int score, float time) {
    int width = GetScreenWidth();
    int height = GetScreenHeight();
    
    // Background overlay
    DrawRectangle(0, 0, width, height, Fade(BLACK, 0.5f));
    
    // Victory panel
    DrawRectangle(width/2 - 300, height/2 - 150, 600, 300, Fade(BLACK, 0.8f));
    DrawRectangleLines(width/2 - 300, height/2 - 150, 600, 300, GOLD);
    
    // Title
    const char* title = "MISSION COMPLETE!";
    int titleWidth = MeasureText(title, 60);
    DrawText(title, width/2 - titleWidth/2, height/2 - 100, 60, GOLD);
    
    // Score
    DrawText(TextFormat("Final Score: %d", score), width/2 - 120, height/2 - 20, 30, WHITE);
    
    // Time
    int minutes = (int)(time / 60);
    int seconds = (int)time % 60;
    DrawText(TextFormat("Time: %d:%02d", minutes, seconds), width/2 - 80, height/2 + 20, 30, WHITE);
    
    // Instructions
    DrawText("Press ENTER to play again or ESC to exit", width/2 - 200, height/2 + 80, 20, GRAY);
}

void hud_draw_pause_menu(void) {
    int width = GetScreenWidth();
    int height = GetScreenHeight();
    
    // Background overlay
    DrawRectangle(0, 0, width, height, Fade(BLACK, 0.7f));
    
    // Pause panel
    DrawRectangle(width/2 - 200, height/2 - 100, 400, 200, Fade(BLACK, 0.9f));
    DrawRectangleLines(width/2 - 200, height/2 - 100, 400, 200, WHITE);
    
    // Title
    const char* title = "PAUSED";
    int titleWidth = MeasureText(title, 40);
    DrawText(title, width/2 - titleWidth/2, height/2 - 60, 40, WHITE);
    
    // Instructions
    DrawText("Press P to resume", width/2 - 90, height/2, 20, GRAY);
    DrawText("Press ESC to quit", width/2 - 85, height/2 + 30, 20, GRAY);
}