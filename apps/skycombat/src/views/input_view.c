/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/views/input_view.h"
#include <raylib.h>
#include <stdio.h>
#include <stdlib.h>

struct input_view_s {
    Font font;
};

input_view_t* input_view_create(void) {
    input_view_t* view = calloc(1, sizeof(input_view_t));
    if (!view) return NULL;
    
    // Use default font
    view->font = GetFontDefault();
    
    return view;
}

void input_view_destroy(input_view_t* view) {
    free(view);
}

void input_view_draw_overlay(input_view_t* view,
                            const validated_input_t* input,
                            const game_actions_t* actions,
                            int screen_width,
                            int screen_height) {
    if (!input->is_valid) return;
    
    // Background panel
    int panel_width = 400;
    int panel_height = 300;
    int x = screen_width - panel_width - 10;
    int y = 10;
    
    DrawRectangle(x, y, panel_width, panel_height, Fade(BLACK, 0.8f));
    DrawRectangleLines(x, y, panel_width, panel_height, GREEN);
    
    // Title
    DrawText("ASTRO C40 INPUT (LOCKED)", x + 10, y + 10, 20, GREEN);
    
    // Draw axes
    int ax = x + 10;
    int ay = y + 40;
    
    DrawText("LEFT STICK:", ax, ay, 16, WHITE);
    DrawText(TextFormat("X: %.2f Y: %.2f", input->axes[0], input->axes[1]), 
             ax + 100, ay, 16, YELLOW);
    
    ay += 20;
    DrawText("RIGHT STICK:", ax, ay, 16, WHITE);
    DrawText(TextFormat("X: %.2f Y: %.2f", input->axes[2], input->axes[5]), 
             ax + 100, ay, 16, YELLOW);
    
    // Draw triggers
    ay += 30;
    DrawText("TRIGGERS:", ax, ay, 16, WHITE);
    ay += 20;
    
    DrawText("L2:", ax, ay, 16, WHITE);
    DrawRectangle(ax + 40, ay, 100, 16, DARKGRAY);
    float l2_pct = (input->axes[3] + 1.0f) / 2.0f;
    DrawRectangle(ax + 40, ay, (int)(100 * l2_pct), 16, actions->fire_missiles ? RED : GRAY);
    
    ay += 20;
    DrawText("R2:", ax, ay, 16, WHITE);
    DrawRectangle(ax + 40, ay, 100, 16, DARKGRAY);
    float r2_pct = 1.0f - ((input->axes[4] + 1.0f) / 2.0f);  // Inverted for ASTRO
    DrawRectangle(ax + 40, ay, (int)(100 * r2_pct), 16, actions->fire_guns ? ORANGE : GRAY);
    
    // Draw critical buttons
    ay += 30;
    DrawText("SPEED CONTROLS (LOCKED):", ax, ay, 16, WHITE);
    ay += 20;
    
    Color gas_color = actions->speed_boost ? LIME : DARKGRAY;
    Color brake_color = actions->brake ? RED : DARKGRAY;
    
    DrawText("Button 2 (Gas):", ax, ay, 16, WHITE);
    DrawCircle(ax + 130, ay + 8, 8, gas_color);
    
    ay += 20;
    DrawText("Button 3 (Brake):", ax, ay, 16, WHITE);
    DrawCircle(ax + 130, ay + 8, 8, brake_color);
    
    // Draw movement indicators
    ay += 30;
    DrawText("MOVEMENT:", ax, ay, 16, WHITE);
    DrawText(TextFormat("X: %.2f Y: %.2f", actions->move_x, actions->move_y),
             ax + 100, ay, 16, YELLOW);
}

void input_view_draw_controller(input_view_t* view,
                               const validated_input_t* input,
                               int x, int y) {
    // Draw simplified controller diagram
    int width = 300;
    int height = 200;
    
    DrawRectangle(x, y, width, height, Fade(DARKGRAY, 0.5f));
    DrawRectangleLines(x, y, width, height, WHITE);
    
    // Left stick
    int lx = x + 60;
    int ly = y + 100;
    DrawCircle(lx, ly, 30, DARKGRAY);
    int stick_x = lx + (int)(input->axes[0] * 20);
    int stick_y = ly + (int)(input->axes[1] * 20);
    DrawCircle(stick_x, stick_y, 15, WHITE);
    
    // Right stick
    int rx = x + width - 60;
    int ry = y + 100;
    DrawCircle(rx, ry, 30, DARKGRAY);
    stick_x = rx + (int)(input->axes[2] * 20);
    stick_y = ry + (int)(input->axes[5] * 20);
    DrawCircle(stick_x, stick_y, 15, WHITE);
    
    // Buttons
    DrawText("GAS", x + width/2 - 40, y + 50, 14, input->buttons[2] ? LIME : GRAY);
    DrawText("BRAKE", x + width/2 + 10, y + 50, 14, input->buttons[3] ? RED : GRAY);
}

void input_view_draw_error(input_view_t* view,
                          const char* error,
                          int screen_width,
                          int screen_height) {
    int text_width = MeasureText(error, 20);
    int x = (screen_width - text_width) / 2;
    int y = screen_height - 100;
    
    DrawRectangle(x - 10, y - 5, text_width + 20, 30, Fade(RED, 0.8f));
    DrawText(error, x, y, 20, WHITE);
}