/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <raylib.h>
#include <raymath.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Include our systems */
#include "views/flying_camera.c"
#include "models/ai_characters.c"
#include "views/building_renderer.c"

/* Forward declarations from building_generator.c */
game_building_t* create_building(int type, float x, float z);
void generate_city_block(game_building_t** buildings, int* count);

#define WINDOW_WIDTH 1280
#define WINDOW_HEIGHT 720
#define TARGET_FPS 60

/* Game state */
typedef struct {
    game_building_t* buildings;
    int building_count;
    bool show_help;
    bool show_debug;
    float time_of_day;
    bool paused;
} game_state_t;

static game_state_t g_game_state = {0};

void init_game() {
    /* Initialize random seed */
    srand(time(NULL));
    
    /* Create city */
    generate_city_block(&g_game_state.buildings, &g_game_state.building_count);
    
    /* Spawn AI characters */
    init_ai_characters(30);
    
    /* Initialize camera */
    init_flying_camera();
    
    /* Start at noon */
    g_game_state.time_of_day = 12.0f;
    g_game_state.show_help = true;
}

void update_game() {
    if (IsKeyPressed(KEY_P)) g_game_state.paused = !g_game_state.paused;
    if (IsKeyPressed(KEY_H)) g_game_state.show_help = !g_game_state.show_help;
    if (IsKeyPressed(KEY_F1)) g_game_state.show_debug = !g_game_state.show_debug;
    
    if (g_game_state.paused) return;
    
    /* Update time of day */
    g_game_state.time_of_day += GetFrameTime() * 0.5f;  /* 1 game hour = 2 real seconds */
    if (g_game_state.time_of_day >= 24.0f) g_game_state.time_of_day -= 24.0f;
    
    /* Update systems */
    update_flying_camera(GetFrameTime());
    update_ai_characters(g_game_state.buildings, g_game_state.building_count);
}

void draw_game() {
    /* Calculate sky color based on time */
    float sun_angle = (g_game_state.time_of_day - 6.0f) / 12.0f * PI;
    float brightness = fmaxf(0, cosf(sun_angle));
    Color sky_color = (Color){
        (unsigned char)(135 * brightness),
        (unsigned char)(206 * brightness),
        (unsigned char)(235 * brightness),
        255
    };
    
    BeginDrawing();
    ClearBackground(sky_color);
    
    /* 3D rendering */
    BeginMode3D(*get_flying_camera());
    
    /* Draw city ground and streets */
    draw_city_ground();
    
    /* Draw all buildings */
    for (int i = 0; i < g_game_state.building_count; i++) {
        draw_building_exterior(&g_game_state.buildings[i]);
        draw_building_interior(&g_game_state.buildings[i]);
    }
    
    /* Draw AI characters */
    draw_ai_characters();
    
    /* Draw sun/moon */
    Vector3 sun_pos = {
        sinf(sun_angle) * 500.0f,
        cosf(sun_angle) * 500.0f + 200.0f,
        0
    };
    
    if (g_game_state.time_of_day >= 6.0f && g_game_state.time_of_day <= 18.0f) {
        DrawSphere(sun_pos, 50.0f, YELLOW);
    } else {
        DrawSphere(sun_pos, 30.0f, WHITE);
    }
    
    /* Clouds */
    for (int i = 0; i < 10; i++) {
        float cloud_x = sinf(i * 1.7f + GetTime() * 0.1f) * 300.0f;
        float cloud_z = cosf(i * 2.3f + GetTime() * 0.05f) * 300.0f;
        DrawSphere((Vector3){cloud_x, 150.0f + i * 10.0f, cloud_z}, 20.0f, 
                  (Color){255, 255, 255, 100});
    }
    
    EndMode3D();
    
    /* 2D UI overlay */
    draw_flight_hud();
    
    /* Character labels */
    draw_ai_character_labels(*get_flying_camera());
    
    /* Help text */
    if (g_game_state.show_help) {
        DrawRectangle(10, 70, 400, 200, (Color){0, 0, 0, 180});
        DrawText("=== FULL NODE: FIREWALL FLY-OVER ===", 20, 80, 20, GREEN);
        DrawText("Flying Controls:", 20, 110, 16, WHITE);
        DrawText("  WASD - Move", 20, 130, 16, WHITE);
        DrawText("  Mouse - Look around", 20, 150, 16, WHITE);
        DrawText("  Space/Ctrl - Up/Down", 20, 170, 16, WHITE);
        DrawText("  Shift - Boost", 20, 190, 16, WHITE);
        DrawText("  H - Toggle help", 20, 210, 16, WHITE);
        DrawText("  P - Pause", 20, 230, 16, WHITE);
        DrawText("  F1 - Debug info", 20, 250, 16, WHITE);
    }
    
    /* Debug info */
    if (g_game_state.show_debug) {
        DrawText(TextFormat("FPS: %d", GetFPS()), GetScreenWidth() - 100, 10, 20, GREEN);
        DrawText(TextFormat("Buildings: %d", g_game_state.building_count), GetScreenWidth() - 150, 40, 16, WHITE);
        DrawText(TextFormat("Characters: %d", MAX_AI_CHARACTERS), GetScreenWidth() - 150, 60, 16, WHITE);
        DrawText(TextFormat("Time: %02d:%02d", (int)g_game_state.time_of_day, 
                (int)((g_game_state.time_of_day - (int)g_game_state.time_of_day) * 60)), 
                GetScreenWidth() - 150, 80, 16, WHITE);
        
        Camera3D* cam = get_flying_camera();
        DrawText(TextFormat("Cam: (%.1f, %.1f, %.1f)", 
                cam->position.x, cam->position.y, cam->position.z),
                GetScreenWidth() - 250, 100, 16, WHITE);
    }
    
    /* Pause indicator */
    if (g_game_state.paused) {
        DrawText("PAUSED", GetScreenWidth()/2 - 60, GetScreenHeight()/2 - 20, 40, YELLOW);
    }
    
    EndDrawing();
}

void cleanup_game() {
    if (g_game_state.buildings) {
        free(g_game_state.buildings);
    }
}

int main() {
    /* Enforce 3D specifications */
    ENFORCE_3D_SPECIFICATIONS();
    
    printf("=== FULL NODE: FIREWALL FLY-OVER ===\n");
    printf("3D World with Walkable Buildings\n\n");
    
    /* Initialize window */
    InitWindow(WINDOW_WIDTH, WINDOW_HEIGHT, "Full Node: Firewall Fly-Over - 3D World");
    SetTargetFPS(TARGET_FPS);
    DisableCursor();
    
    /* Initialize game */
    init_game();
    
    printf("Controls:\n");
    printf("  WASD + Mouse - Fly around\n");
    printf("  Space/Ctrl - Up/Down\n");
    printf("  Shift - Boost\n");
    printf("  H - Help\n");
    printf("  P - Pause\n");
    printf("  F1 - Debug\n\n");
    
    /* Main game loop */
    while (!WindowShouldClose()) {
        update_game();
        draw_game();
    }
    
    /* Cleanup */
    cleanup_game();
    CloseWindow();
    
    return 0;
}