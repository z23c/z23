/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/controllers/sky_combat.h"
#include "sky_combat/models/aircraft.h"
#include "sky_combat/models/course.h"
#include "sky_combat/models/weapons.h"
#include "sky_combat/controllers/input.h"
#include "sky_combat/views/hud.h"
#include <raylib.h>
#include <raymath.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

typedef struct sky_combat_game {
    // Core systems
    aircraft_t* aircraft;
    course_t* course;
    weapons_system_t* weapons;
    joystick_t* input;
    
    // Camera
    Camera3D camera;
    float camera_yaw;
    float camera_pitch;
    
    // Gun aiming (controlled by right stick)
    float gun_aim_offset_x;
    float gun_aim_offset_y;
    
    // Game state
    float game_time;
    float elapsed_time;
    bool paused;
    bool completed;
    
    // Configuration
    int width;
    int height;
    const char* title;
    hud_config_t hud_config;
    bool joystick_enabled;
} sky_combat_game_t;

sky_combat_game_t* sky_combat_create(int width, int height, const char* title) {
    sky_combat_game_t* game = calloc(1, sizeof(sky_combat_game_t));
    if (!game) return NULL;
    
    // Initialize window
    SetConfigFlags(FLAG_MSAA_4X_HINT | FLAG_VSYNC_HINT);
    InitWindow(width, height, title);
    SetTargetFPS(60);
    
    // Store configuration
    game->width = width;
    game->height = height;
    game->title = title;
    game->joystick_enabled = true;
    
    // Create systems
    game->aircraft = aircraft_create((Vector3){0, 50, 0});
    if (!game->aircraft) {
        CloseWindow();
        free(game);
        return NULL;
    }
    
    game->course = course_create();
    if (!game->course) {
        aircraft_destroy(game->aircraft);
        CloseWindow();
        free(game);
        return NULL;
    }
    
    game->weapons = weapons_create();
    if (!game->weapons) {
        aircraft_destroy(game->aircraft);
        course_destroy(game->course);
        CloseWindow();
        free(game);
        return NULL;
    }
    
    game->input = input_create();
    if (!game->input) {
        aircraft_destroy(game->aircraft);
        course_destroy(game->course);
        weapons_destroy(game->weapons);
        CloseWindow();
        free(game);
        return NULL;
    }
    
    // Load default course
    course_load_intermediate(game->course);
    
    // Setup camera
    game->camera.position = (Vector3){0, 60, -50};
    game->camera.target = game->aircraft->position;
    game->camera.up = (Vector3){0, 1, 0};
    game->camera.fovy = 60.0f;
    game->camera.projection = CAMERA_PERSPECTIVE;
    
    // Default HUD config
    game->hud_config = hud_default_config();
    
    return game;
}

void sky_combat_destroy(sky_combat_game_t* game) {
    if (!game) return;
    
    aircraft_destroy(game->aircraft);
    course_destroy(game->course);
    weapons_destroy(game->weapons);
    input_destroy(game->input);
    
    CloseWindow();
    free(game);
}

void draw_environment(sky_combat_game_t* game) {
    if (!game || !game->aircraft) return;
    
    // Sky gradient effect
    for (int i = 0; i < 10; i++) {
        float y = -500 + i * 200;
        Color skyColor = ColorFromHSV(200 + i * 5, 0.3f - i * 0.02f, 1);
        DrawCube((Vector3){0, y, game->aircraft->position.z}, 5000, 1, 5000, skyColor);
    }
    
    // Ground
    DrawPlane((Vector3){0, 0, 0}, (Vector2){5000, 5000}, DARKGREEN);
    
    // Simple terrain
    for (int x = -10; x <= 10; x++) {
        for (int z = -10; z <= 10; z++) {
            float height = sinf(x * 0.3f) * cosf(z * 0.3f) * 30;
            Vector3 pos = {
                x * 200 + (int)(game->aircraft->position.x / 200) * 200,
                height / 2,
                z * 200 + (int)(game->aircraft->position.z / 200) * 200
            };
            
            if (height > 10) {
                DrawCube(pos, 180, height, 180, BROWN);
            }
        }
    }
    
    // Clouds
    for (int i = 0; i < 15; i++) {
        Vector3 cloudPos = {
            sinf(i * 1.7f) * 300,
            150 + sinf(i * 2.3f + game->game_time * 0.1f) * 50,
            game->aircraft->position.z + (i - 7) * 200
        };
        DrawSphere(cloudPos, 50, Fade(WHITE, 0.3f));
    }
}

void draw_navigation_helpers(sky_combat_game_t* game) {
    if (!game || !game->course || !game->aircraft) return;
    
    ring_t* next_ring = course_get_next_ring(game->course);
    if (!next_ring) return;
    
    Vector3 toRing = Vector3Subtract(next_ring->position, game->aircraft->position);
    if (Vector3Length(toRing) < 300) {
        for (int j = 1; j <= 5; j++) {
            Vector3 dotPos = Vector3Add(game->aircraft->position, 
                                      Vector3Scale(Vector3Normalize(toRing), j * 20));
            DrawSphere(dotPos, 2, Fade(next_ring->color, 0.5f));
        }
    }
}

void update_camera(sky_combat_game_t* game, float dt) {
    if (!game || !game->aircraft) return;
    
    // Camera is controlled by mouse/keyboard ONLY - right stick is for aiming
    // game->camera_yaw += game->input ? input_get_state(game->input).camera_x * 100 * dt : 0;
    // game->camera_pitch += game->input ? input_get_state(game->input).camera_y * 80 * dt : 0;
    // game->camera_pitch = Clamp(game->camera_pitch, -60, 60);
    
    // Right stick now controls gun aim offset
    float aim_x = game->input ? input_get_state(game->input).camera_x : 0;
    float aim_y = game->input ? input_get_state(game->input).camera_y : 0;
    game->gun_aim_offset_x = aim_x * 15.0f;  // ±15 degrees horizontal
    game->gun_aim_offset_y = aim_y * 15.0f;  // ±15 degrees vertical
    
    // Third person camera with look controls
    float camDistance = 60 + game->aircraft->speed * 0.5f;
    float camAngle = (game->aircraft->yaw + game->camera_yaw) * DEG2RAD;
    Vector3 camOffset = {
        -sinf(camAngle) * camDistance * cosf(game->camera_pitch * DEG2RAD),
        20 + sinf(game->camera_pitch * DEG2RAD) * camDistance,
        -cosf(camAngle) * camDistance * cosf(game->camera_pitch * DEG2RAD)
    };
    
    game->camera.position = Vector3Lerp(game->camera.position, 
                                      Vector3Add(game->aircraft->position, camOffset), 
                                      3 * dt);
    game->camera.target = Vector3Lerp(game->camera.target, game->aircraft->position, 5 * dt);
}

void sky_combat_run(sky_combat_game_t* game) {
    if (!game || !game->aircraft || !game->course || !game->weapons || !game->input) return;
    
    while (!WindowShouldClose()) {
        float dt = GetFrameTime();
        game->game_time += dt;
        
        // Pause handling
        if (IsKeyPressed(KEY_P)) {
            game->paused = !game->paused;
        }
        
        if (!game->paused && !game->completed) {
            game->elapsed_time += dt;
            
            // Update input
            input_update(game->input);
            input_state_t input_state = input_get_state(game->input);
            
            // Update aircraft
            aircraft_update(game->aircraft, input_state.move_x, input_state.move_y, dt);
            
            // Handle special moves
            if (input_state.barrel_roll_left) {
                aircraft_barrel_roll_left(game->aircraft, dt);
            } else if (input_state.barrel_roll_right) {
                aircraft_barrel_roll_right(game->aircraft, dt);
            }
            
            if (input_state.speed_boost) {
                aircraft_boost(game->aircraft, dt);
            }
            if (input_state.brake) {
                aircraft_brake(game->aircraft, dt);
            }
            
            // Handle weapons with right stick aiming
            if (input_state.fire_guns && game->aircraft->fireTimer <= 0) {
                // Apply aim offset to firing angle
                float adjusted_yaw = game->aircraft->yaw + game->gun_aim_offset_x;
                float adjusted_pitch = game->aircraft->pitch + game->gun_aim_offset_y;
                
                // Calculate aimed forward vector
                Vector3 aimed_forward = {
                    cosf(adjusted_yaw * DEG2RAD) * cosf(adjusted_pitch * DEG2RAD),
                    sinf(adjusted_pitch * DEG2RAD),
                    sinf(adjusted_yaw * DEG2RAD) * cosf(adjusted_pitch * DEG2RAD)
                };
                
                weapons_fire_bullet(game->weapons, game->aircraft->position, 
                                  aimed_forward, adjusted_yaw);
                game->aircraft->fireTimer = FIRE_RATE;
            }
            
            if (input_state.fire_missiles && game->aircraft->missileTimer <= 0) {
                ring_t* target = course_get_next_ring(game->course);
                weapons_fire_missile(game->weapons, game->aircraft->position,
                                   aircraft_get_forward_vector(game->aircraft),
                                   game->aircraft->yaw,
                                   game->aircraft->missileSide,
                                   target);
                // Alternate missile sides
                game->aircraft->missileSide *= -1;
                game->aircraft->missileTimer = MISSILE_RATE;
            }
            
            // Update weapons
            weapons_update(game->weapons, dt);
            
            // Check ring collection
            if (course_check_ring_collection(game->course, game->aircraft->position, 0)) {
                game->aircraft->rings++;
                game->aircraft->score = course_get_total_score(game->course);
            }
            
            // Check completion
            if (game->aircraft->rings >= game->course->ring_count) {
                game->completed = true;
            }
            
            // Update camera
            update_camera(game, dt);
        }
        
        // Restart handling
        if (game->completed && IsKeyPressed(KEY_ENTER)) {
            // Reset game
            game->aircraft->position = (Vector3){0, 50, 0};
            game->aircraft->score = 0;
            game->aircraft->rings = 0;
            game->aircraft->speed = AIRCRAFT_BASE_SPEED;
            game->aircraft->yaw = 0;
            game->aircraft->pitch = 0;
            game->aircraft->roll = 0;
            
            course_load_intermediate(game->course);
            game->completed = false;
            game->elapsed_time = 0;
        }
        
        // Render
        BeginDrawing();
        ClearBackground(SKYBLUE);
        
        BeginMode3D(game->camera);
        
        draw_environment(game);
        course_draw_rings(game->course, game->game_time);
        draw_navigation_helpers(game);
        aircraft_draw(game->aircraft, game->game_time);
        weapons_draw(game->weapons);
        
        EndMode3D();
        
        // Draw HUD
        input_state_t input_state = input_get_state(game->input);
        hud_draw(game->aircraft, game->course, &input_state, &game->hud_config);
        
        if (game->completed) {
            hud_draw_victory(game->aircraft->score, game->elapsed_time);
        }
        
        if (game->paused) {
            hud_draw_pause_menu();
        }
        
        EndDrawing();
    }
}

// Configuration functions
void sky_combat_set_course(sky_combat_game_t* game, int course_id) {
    if (!game || !game->course) return;
    course_load_custom(game->course, course_id);
}

void sky_combat_enable_joystick(sky_combat_game_t* game, bool enable) {
    if (!game) return;
    game->joystick_enabled = enable;
}

void sky_combat_set_difficulty(sky_combat_game_t* game, int difficulty) {
    if (!game || !game->course) return;
    game->course->difficulty = difficulty;
}

// Query functions
int sky_combat_get_score(sky_combat_game_t* game) {
    if (!game || !game->aircraft) return 0;
    return game->aircraft->score;
}

int sky_combat_get_rings_collected(sky_combat_game_t* game) {
    if (!game || !game->aircraft) return 0;
    return game->aircraft->rings;
}

float sky_combat_get_time_elapsed(sky_combat_game_t* game) {
    if (!game) return 0.0f;
    return game->elapsed_time;
}

bool sky_combat_is_complete(sky_combat_game_t* game) {
    if (!game) return false;
    return game->completed;
}