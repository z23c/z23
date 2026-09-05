/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

// Modified version of sky_combat_ultimate.c with 5 players
#include <raylib.h>
#include <raymath.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "sky_combat/controllers/sky_combat.h"
#include "sky_combat/models/aircraft.h"
#include "sky_combat/models/aircraft_manager.h"
#include "sky_combat/models/weapons.h"
#include "sky_combat/controllers/input_mvc_fast.h"
#include "sky_combat/models/enemies.h"
#include "sky_combat/models/cyberpunk_world.h"
#include "sky_combat/views/combat_effects.h"
#include "sky_combat/models/overdrive.h"

// Forward declare responsive functions
void aircraft_update_responsive(aircraft_t* aircraft, float stick_x, float stick_y, float dt);
void camera_update_responsive(Camera3D* camera, Vector3 target, float yaw, float distance, float height, float dt);

typedef struct {
    // ADDED: Aircraft manager for 5 players
    aircraft_manager_t* aircraft_mgr;
    
    // Core systems (keeping most of original)
    input_mvc_fast_t* input;
    enemy_manager_t* enemies;
    cyberpunk_world_t* world;
    effects_manager_t* effects;
    overdrive_system_t* overdrive;
    
    // Camera
    Camera3D camera;
    int camera_follow_id;  // Which aircraft to follow (0-4)
    
    // Game state
    int score;
    int combo;
    float combo_timer;
    int wave;
    bool game_over;
    float boost_timer;
    
    // Visual settings
    bool motion_blur_enabled;
    bool chromatic_enabled;
    float speed_lines_intensity;
} ultimate_game_t;

static Color player_colors[5] = {
    {50, 255, 50, 255},    // Green (Player)
    {255, 50, 50, 255},    // Red
    {50, 50, 255, 255},    // Blue  
    {255, 255, 50, 255},   // Yellow
    {255, 50, 255, 255}    // Magenta
};

static ultimate_game_t* game_create(void) {
    ultimate_game_t* game = calloc(1, sizeof(ultimate_game_t));
    
    // Create aircraft manager and add 5 aircraft
    game->aircraft_mgr = aircraft_manager_create();
    aircraft_manager_add(game->aircraft_mgr, "Player", player_colors[0], false, true);
    aircraft_manager_add(game->aircraft_mgr, "Red AI", player_colors[1], true, false);
    aircraft_manager_add(game->aircraft_mgr, "Blue AI", player_colors[2], true, false);
    aircraft_manager_add(game->aircraft_mgr, "Yellow AI", player_colors[3], true, false);
    aircraft_manager_add(game->aircraft_mgr, "Purple AI", player_colors[4], true, false);
    
    // Create other systems
    game->input = input_mvc_fast_create();
    game->enemies = enemies_create(200);
    game->world = cyberpunk_world_create();
    game->effects = effects_create(1000, 10000);
    game->overdrive = overdrive_create();
    
    // Setup camera
    game->camera.position = (Vector3){0, 20, -30};
    game->camera.target = (Vector3){0, 0, 0};
    game->camera.up = (Vector3){0, 1, 0};
    game->camera.fovy = 65.0f;
    game->camera.projection = CAMERA_PERSPECTIVE;
    game->camera_follow_id = 0;  // Follow player by default
    
    // Visual settings
    game->motion_blur_enabled = true;
    game->chromatic_enabled = true;
    
    // Generate world
    cyberpunk_world_generate(game->world, 42);
    
    return game;
}

static void game_destroy(ultimate_game_t* game) {
    aircraft_manager_destroy(game->aircraft_mgr);
    overdrive_destroy(game->overdrive);
    effects_destroy(game->effects);
    cyberpunk_world_destroy(game->world);
    enemies_destroy(game->enemies);
    input_mvc_fast_destroy(game->input);
    free(game);
}

int main(void) {
    // Window setup
    SetConfigFlags(FLAG_MSAA_4X_HINT | FLAG_VSYNC_HINT);
    InitWindow(1280, 720, "Sky Combat Ultimate - 5 Player Battle");
    SetTargetFPS(60);
    
    printf("\n=== SKY_COMBAT: 5 PLAYER ULTIMATE ===\n\n");
    printf("You are GREEN. Fight 4 AI enemies!\n");
    printf("\nCONTROLS:\n");
    printf("  WASD/Arrows - Turn/Pitch\n");
    printf("  Space - Fire\n");
    printf("  Shift - Boost\n");
    printf("  1-5 - Switch camera to follow different aircraft\n");
    printf("  ESC - Exit\n\n");
    
    // Create game
    ultimate_game_t* game = game_create();
    
    // Pre-render setup
    RenderTexture2D screen_target = LoadRenderTexture(GetScreenWidth(), GetScreenHeight());
    Shader motion_blur_shader = LoadShader(0, 0);  // Placeholder
    
    // Main game loop
    while (!WindowShouldClose() && !game->game_over) {
        float dt = GetFrameTime();
        
        // Update input
        input_view_fast_t view = input_mvc_fast_update(game->input);
        input_state_fast_t input = input_view_get_state(view);
        
        // Update player aircraft with input
        managed_aircraft_t* player = aircraft_manager_get(game->aircraft_mgr, 0);
        if (player && player->health > 0) {
            aircraft_update_responsive(player->aircraft, input.move_x, input.move_y, dt);
            
            // Fire weapon
            if (input.fire_guns) {
                aircraft_manager_fire_weapon(game->aircraft_mgr, 0);
            }
            
            // Boost
            if (input.speed_boost && game->boost_timer <= 0) {
                game->boost_timer = 0.75f;
                player->aircraft->speed = AIRCRAFT_MAX_SPEED * 2.5f;
                effects_sonic_boom(game->effects, player->aircraft->position, 
                                 aircraft_get_forward_vector(player->aircraft));
            }
        }
        
        // Boost decay
        if (game->boost_timer > 0) {
            game->boost_timer -= dt;
            game->speed_lines_intensity = 1.0f;
        } else {
            game->speed_lines_intensity *= 0.95f;
        }
        
        // Camera switching (1-5 keys)
        for (int i = 0; i < 5; i++) {
            if (IsKeyPressed(KEY_ONE + i)) {
                game->camera_follow_id = i;
                printf("Now following: %s\n", game->aircraft_mgr->aircraft[i].name);
            }
        }
        
        // Update camera to follow selected aircraft
        managed_aircraft_t* followed = aircraft_manager_get(game->aircraft_mgr, game->camera_follow_id);
        if (followed && followed->aircraft) {
            camera_update_responsive(&game->camera, followed->aircraft->position,
                                   followed->aircraft->yaw, 50.0f, 20.0f, dt);
        }
        
        // Update systems
        aircraft_manager_update(game->aircraft_mgr, dt);
        overdrive_update(game->overdrive, dt);
        weapons_update(player->weapons, dt);
        effects_update(game->effects, dt);
        enemies_update(game->enemies, player->aircraft->position, dt);
        
        // Add explosions for destroyed aircraft
        for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
            managed_aircraft_t* ma = &game->aircraft_mgr->aircraft[i];
            if (ma->health <= 0 && ma->aircraft) {
                effects_spawn_explosion(game->effects, ma->aircraft->position, 5.0f, ma->color);
            }
        }
        
        // RENDERING
        BeginTextureMode(screen_target);
        ClearBackground((Color){20, 24, 40, 255});
        
        BeginMode3D(game->camera);
        
        // Draw world
        cyberpunk_world_draw(game->world, game->camera);
        
        // Draw all 5 aircraft
        for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
            managed_aircraft_t* ma = &game->aircraft_mgr->aircraft[i];
            if (!ma->aircraft || ma->health <= 0) continue;
            
            // Save color in unused field
            int saved = ma->aircraft->score;
            ma->aircraft->score = ColorToInt(ma->color);
            
            aircraft_draw(ma->aircraft, GetTime());
            
            // Draw weapons
            weapons_draw(ma->weapons);
            
            ma->aircraft->score = saved;
        }
        
        // Draw enemies
        enemies_draw(game->enemies);
        
        // Draw effects
        effects_draw(game->effects, game->camera);
        
        // Speed lines effect - removed for now
        
        EndMode3D();
        EndTextureMode();
        
        // Final render
        BeginDrawing();
        DrawTextureRec(screen_target.texture, 
                      (Rectangle){0, 0, screen_target.texture.width, -screen_target.texture.height},
                      (Vector2){0, 0}, WHITE);
        
        // HUD - Show all 5 aircraft status
        int y = 10;
        for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
            managed_aircraft_t* ma = &game->aircraft_mgr->aircraft[i];
            
            // Highlight who camera is following
            if (i == game->camera_follow_id) {
                DrawRectangle(8, y-2, 350, 24, Fade(ma->color, 0.2f));
            }
            
            DrawText(TextFormat("%d. %s  HP:%.0f  K:%d D:%d", 
                               i+1, ma->name, ma->health, ma->kills, ma->deaths),
                     10, y, 20, ma->color);
            y += 25;
        }
        
        // Controls reminder
        DrawText("1-5: Switch Camera | Space: Fire | Shift: Boost", 
                 10, GetScreenHeight() - 25, 16, GRAY);
        
        EndDrawing();
    }
    
    // Final stats
    printf("\n=== BATTLE RESULTS ===\n");
    for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
        managed_aircraft_t* ma = &game->aircraft_mgr->aircraft[i];
        printf("%s: %d kills, %d deaths\n", ma->name, ma->kills, ma->deaths);
    }
    
    // Cleanup
    UnloadRenderTexture(screen_target);
    UnloadShader(motion_blur_shader);
    game_destroy(game);
    CloseWindow();
    
    return 0;
}