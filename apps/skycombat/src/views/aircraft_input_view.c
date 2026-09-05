/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../../specifications/joystick_control_specs.h"
#include <raylib.h>
#include <stdio.h>

/* View: Pure presentation logic for aircraft input feedback */

/* Visual constants */
#define HUD_COLOR_ACTIVE GREEN
#define HUD_COLOR_INACTIVE DARKGRAY
#define HUD_COLOR_WARNING ORANGE
#define HUD_COLOR_ERROR RED

/* Draw input state visualization */
void aircraft_input_view_draw_state(const validated_joystick_input_t* input, int x, int y) {
    if (!input || !input->is_valid) return;
    
    /* Background panel */
    DrawRectangle(x - 5, y - 5, 250, 180, Fade(BLACK, 0.8f));
    DrawRectangleLines(x - 5, y - 5, 250, 180, GREEN);
    
    /* Title */
    DrawText("INPUT STATE", x, y, 16, GREEN);
    y += 25;
    
    /* Analog inputs with visual bars */
    DrawText("PITCH:", x, y, 14, WHITE);
    DrawRectangle(x + 60, y, 100, 12, DARKGRAY);
    DrawRectangle(x + 110, y, (int)(input->pitch * 50), 12, 
                  input->pitch < 0 ? ORANGE : GREEN);
    y += 18;
    
    DrawText("ROLL:", x, y, 14, WHITE);
    DrawRectangle(x + 60, y, 100, 12, DARKGRAY);
    DrawRectangle(x + 110, y, (int)(input->roll * 50), 12,
                  input->roll < 0 ? ORANGE : GREEN);
    y += 18;
    
    DrawText("YAW:", x, y, 14, WHITE);
    DrawRectangle(x + 60, y, 100, 12, DARKGRAY);
    DrawRectangle(x + 110, y, (int)(input->yaw * 50), 12,
                  input->yaw < 0 ? ORANGE : GREEN);
    y += 18;
    
    DrawText("THRTL:", x, y, 14, WHITE);
    DrawRectangle(x + 60, y, 100, 12, DARKGRAY);
    DrawRectangle(x + 60, y, (int)(input->throttle * 100), 12, GREEN);
    y += 18;
    
    DrawText("GAS:", x, y, 14, WHITE);
    DrawCircle(x + 60, y + 7, 6, input->gas_button ? GREEN : DARKGRAY);
    DrawText("BRAKE:", x + 90, y, 14, WHITE);
    DrawCircle(x + 150, y + 7, 6, input->brake_button ? RED : DARKGRAY);
    y += 25;
    
    /* Button states */
    DrawText("AFTERBURNER:", x, y, 12, WHITE);
    DrawCircle(x + 100, y + 6, 6, input->afterburner ? HUD_COLOR_ACTIVE : HUD_COLOR_INACTIVE);
    y += 16;
    
    DrawText("LANDING GEAR:", x, y, 12, WHITE);
    DrawCircle(x + 100, y + 6, 6, input->landing_gear ? HUD_COLOR_ACTIVE : HUD_COLOR_INACTIVE);
    y += 16;
    
    DrawText("WEAPONS:", x, y, 12, WHITE);
    DrawCircle(x + 70, y + 6, 6, input->fire_primary ? RED : HUD_COLOR_INACTIVE);
    DrawCircle(x + 85, y + 6, 6, input->fire_secondary ? YELLOW : HUD_COLOR_INACTIVE);
}

/* Draw joystick visualization */
void aircraft_input_view_draw_joystick(const validated_joystick_input_t* input, int x, int y) {
    if (!input) return;
    
    /* Left stick visualization */
    DrawText("L", x - 5, y - 20, 12, WHITE);
    DrawCircle(x, y, 40, DARKGRAY);
    DrawCircleLines(x, y, 40, WHITE);
    int lx = x + (int)(input->roll * 30);
    int ly = y + (int)(input->pitch * 30);
    DrawCircle(lx, ly, 10, GREEN);
    
    /* Right stick visualization */
    x += 100;
    DrawText("R", x - 5, y - 20, 12, WHITE);
    DrawCircle(x, y, 40, DARKGRAY);
    DrawCircleLines(x, y, 40, WHITE);
    int rx = x + (int)(input->yaw * 30);
    int ry = y - (int)((input->throttle - 0.5f) * 60);
    DrawCircle(rx, ry, 10, BLUE);
}

/* Draw control hints */
void aircraft_input_view_draw_controls(bool joystick_connected, int x, int y) {
    DrawRectangle(x - 5, y - 5, 320, 200, Fade(BLACK, 0.8f));
    DrawRectangleLines(x - 5, y - 5, 320, 200, GREEN);
    
    if (joystick_connected) {
        DrawText("=== ASTRO C40 CONTROLS ===", x, y, 16, GREEN);
        y += 25;
        DrawText("Left Stick - Pitch/Roll", x, y, 14, WHITE);
        y += 18;
        DrawText("Right Stick - Yaw", x, y, 14, WHITE);
        y += 18;
        DrawText("Button 2 (UL) - Gas", x, y, 14, WHITE);
        y += 18;
        DrawText("Button 3 (UR) - Brake", x, y, 14, WHITE);
        y += 18;
        DrawText("A Button - Afterburner", x, y, 14, WHITE);
        y += 18;
        DrawText("B Button - Landing Gear", x, y, 14, WHITE);
        y += 18;
        DrawText("R2 Trigger - Missiles", x, y, 14, WHITE);
        y += 18;
        DrawText("L2 Trigger - Guns", x, y, 14, WHITE);
    } else {
        DrawText("=== KEYBOARD CONTROLS ===", x, y, 16, YELLOW);
        y += 25;
        DrawText("WASD - Pitch/Roll", x, y, 14, WHITE);
        y += 18;
        DrawText("Q/E - Yaw", x, y, 14, WHITE);
        y += 18;
        DrawText("Left Shift - Gas", x, y, 14, WHITE);
        y += 18;
        DrawText("Left Ctrl - Brake", x, y, 14, WHITE);
        y += 18;
        DrawText("X - Afterburner", x, y, 14, WHITE);
        y += 18;
        DrawText("G - Landing Gear", x, y, 14, WHITE);
        y += 18;
        DrawText("Space - Missiles", x, y, 14, WHITE);
        y += 18;
        DrawText("Z - Guns", x, y, 14, WHITE);
        y += 25;
        DrawText("(No joystick detected)", x, y, 12, ORANGE);
    }
}

/* Draw performance stats */
void aircraft_input_view_draw_stats(uint32_t total_updates, uint32_t failed_validations, int x, int y) {
    DrawRectangle(x - 5, y - 5, 200, 60, Fade(BLACK, 0.8f));
    
    DrawText("INPUT STATS", x, y, 14, GREEN);
    y += 18;
    
    float success_rate = 100.0f;
    if (total_updates > 0) {
        success_rate = 100.0f * (1.0f - (float)failed_validations / (float)total_updates);
    }
    
    DrawText(TextFormat("Updates: %u", total_updates), x, y, 12, WHITE);
    y += 14;
    
    Color rate_color = success_rate >= 99.0f ? GREEN : 
                       success_rate >= 95.0f ? YELLOW : RED;
    DrawText(TextFormat("Success: %.1f%%", success_rate), x, y, 12, rate_color);
}

/* Draw response time indicator */
void aircraft_input_view_draw_latency(uint32_t current_ms, uint32_t last_ms, int x, int y) {
    uint32_t delta = current_ms - last_ms;
    
    Color color = delta <= MAX_INPUT_LATENCY_MS ? GREEN :
                  delta <= MAX_INPUT_LATENCY_MS * 2 ? YELLOW : RED;
    
    DrawText(TextFormat("Latency: %ums", delta), x, y, 14, color);
    
    /* Visual latency bar */
    DrawRectangle(x, y + 18, 100, 8, DARKGRAY);
    int bar_width = (int)((float)delta / (float)(MAX_INPUT_LATENCY_MS * 3) * 100);
    if (bar_width > 100) bar_width = 100;
    DrawRectangle(x, y + 18, bar_width, 8, color);
}