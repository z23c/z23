/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <raylib.h>
#include <raymath.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <rlgl.h>

#include "sky_combat/models/aircraft_manager.h"
#include "sky_combat/models/match_rules.h"
#include "sky_combat/models/powerups.h"
#include "sky_combat/models/cyberpunk_world.h"
#include "sky_combat/views/camera_controller.h"
#include "sky_combat/controllers/input_mvc_fast.h"

#define SCREEN_WIDTH 1920
#define SCREEN_HEIGHT 1080
#define TARGET_FPS 60

/* Render aircraft using basic shapes */
static void render_aircraft(const managed_aircraft_t* aircraft) {
    if (!aircraft || !aircraft->aircraft) return;
    
    Vector3 pos = aircraft->aircraft->position;
    float scale = 3.0f;
    
    /* Save transform */
    rlPushMatrix();
    rlTranslatef(pos.x, pos.y, pos.z);
    
    /* Apply rotation based on yaw/pitch/roll */
    rlRotatef(aircraft->aircraft->yaw, 0, 1, 0);
    rlRotatef(aircraft->aircraft->pitch, 1, 0, 0);
    rlRotatef(aircraft->aircraft->roll, 0, 0, 1);
    
    /* Fuselage */
    DrawCube((Vector3){0, 0, 0}, scale * 2.0f, scale * 0.5f, scale * 0.5f, aircraft->color);
    
    /* Wings */
    DrawCube((Vector3){0, 0, 0}, scale * 0.2f, scale * 0.1f, scale * 3.0f, aircraft->color);
    
    /* Tail */
    DrawCube((Vector3){-scale, scale * 0.3f, 0}, scale * 0.1f, scale * 0.8f, scale * 0.8f, aircraft->color);
    
    /* Engine glow */
    if (aircraft->aircraft->speed > AIRCRAFT_BASE_SPEED) {
        DrawSphere((Vector3){-scale, 0, 0}, scale * 0.3f, ORANGE);
    }
    
    rlPopMatrix();
}

/* Render power-up */
static void render_powerup(const powerup_t* powerup) {
    if (!powerup->active) return;
    
    /* Floating animation */
    float bob = sinf(GetTime() * 2.0f) * 2.0f;
    Vector3 pos = powerup->position;
    pos.y += bob;
    
    /* Rotating cube with glow */
    DrawCube(pos, 3.0f, 3.0f, 3.0f, powerup->color);
    DrawCubeWires(pos, 3.5f, 3.5f, 3.5f, WHITE);
    
    /* Glow effect */
    DrawSphere(pos, 4.0f, Fade(powerup->color, 0.3f));
}

/* Simple HUD */
static void render_hud(const aircraft_manager_t* aircraft_mgr,
                      const match_state_t* match,
                      int local_player_id,
                      bool joystick_connected) {
    /* FPS */
    DrawFPS(10, 10);
    
    /* Match timer */
    int minutes = (int)(match->elapsed_time / 60.0f);
    int seconds = (int)match->elapsed_time % 60;
    char timer[32];
    snprintf(timer, sizeof(timer), "%02d:%02d", minutes, seconds);
    DrawText(timer, GetScreenWidth()/2 - MeasureText(timer, 40)/2, 10, 40, WHITE);
    
    /* Team scores */
    int y_offset = 60;
    if (match->rules.team_count > 0) {
        for (int i = 0; i < match->rules.team_count && i < 4; i++) {
            char score[64];
            Color team_color = (Color[]){RED, BLUE, GREEN, YELLOW}[i];
            snprintf(score, sizeof(score), "Team %d: %d", i+1, match->team_scores[i]);
            DrawText(score, GetScreenWidth() - 200, y_offset + i * 30, 24, team_color);
        }
    } else {
        /* Show top 5 players */
        DrawText("SCORES", GetScreenWidth() - 200, y_offset, 24, WHITE);
        y_offset += 30;
        
        for (int i = 0; i < aircraft_mgr->aircraft_count && i < 5; i++) {
            const managed_aircraft_t* aircraft = &aircraft_mgr->aircraft[i];
            char score[64];
            snprintf(score, sizeof(64), "%s: %d", aircraft->name, aircraft->kills);
            DrawText(score, GetScreenWidth() - 200, y_offset + i * 25, 20, aircraft->color);
        }
    }
    
    /* Local player status */
    const managed_aircraft_t* player = aircraft_manager_get((aircraft_manager_t*)aircraft_mgr, local_player_id);
    if (player) {
        /* Health */
        float health_percent = player->health / player->max_health;
        DrawRectangle(50, GetScreenHeight() - 100, 200, 30, BLACK);
        DrawRectangle(50, GetScreenHeight() - 100, 200 * health_percent, 30, GREEN);
        DrawText("HEALTH", 50, GetScreenHeight() - 130, 20, WHITE);
        
        /* Weapon status */
        if (player->weapons) {
            char ammo[32];
            snprintf(ammo, sizeof(ammo), "WEAPON: %d", player->weapons->current_weapon);
            DrawText(ammo, 50, GetScreenHeight() - 160, 20, WHITE);
        }
        
        /* Kills/Deaths */
        char kd[64];
        snprintf(kd, sizeof(kd), "K: %d  D: %d", player->kills, player->deaths);
        DrawText(kd, 50, GetScreenHeight() - 190, 20, WHITE);
    }
    
    /* Controls help */
    int help_y = GetScreenHeight() - 250;
    if (joystick_connected) {
        DrawText("JOYSTICK CONTROLS:", 10, help_y, 18, GREEN);
        DrawText("Left Stick - Fly", 10, help_y + 25, 16, GRAY);
        DrawText("Right Stick - Camera", 10, help_y + 45, 16, GRAY);
        DrawText("UR Paddle - BOOST!", 10, help_y + 65, 16, ORANGE);
        DrawText("UL Paddle - Throttle", 10, help_y + 85, 16, GRAY);
        DrawText("L2 - Fire Weapon", 10, help_y + 105, 16, GRAY);
        DrawText("1-5 - Camera Views", 10, help_y + 125, 16, GRAY);
    } else {
        DrawText("KEYBOARD CONTROLS:", 10, help_y, 18, WHITE);
        DrawText("A/D or Left/Right - Roll & Turn", 10, help_y + 25, 16, GRAY);
        DrawText("W/S or Up/Down - Pitch", 10, help_y + 45, 16, GRAY);
        DrawText("Space - BOOST! (Mario Kart style)", 10, help_y + 65, 16, ORANGE);
        DrawText("Shift - Throttle Up", 10, help_y + 85, 16, GRAY);
        DrawText("Ctrl - Fire Weapon", 10, help_y + 105, 16, GRAY);
        DrawText("1-5 - Camera Views", 10, help_y + 125, 16, GRAY);
    }
}


int main(void) {
    /* Initialize window */
    SetConfigFlags(FLAG_WINDOW_RESIZABLE | FLAG_VSYNC_HINT);
    InitWindow(SCREEN_WIDTH, SCREEN_HEIGHT, "Sky Combat - 5 Player Multiplayer");
    SetTargetFPS(TARGET_FPS);
    
    /* Create game systems */
    aircraft_manager_t* aircraft_mgr = aircraft_manager_create();
    powerup_manager_t* powerup_mgr = powerup_manager_create();
    match_state_t* match = match_state_create(MATCH_TYPE_DEATHMATCH);
    cyberpunk_world_t* world = cyberpunk_world_create();
    camera_controller_t* camera = camera_controller_create();
    input_mvc_fast_t* input_system = input_mvc_fast_create();
    
    if (!aircraft_mgr || !powerup_mgr || !match || !world || !camera || !input_system) {
        fprintf(stderr, "Failed to create game systems\n");
        return 1;
    }
    
    printf("Multiplayer Sky Combat - Joystick %s\n", 
           input_system->model.connected ? "CONNECTED" : "NOT FOUND (using keyboard)");
    if (input_system->model.is_astro_c40) {
        printf("ASTRO C40 detected - optimized controls active\n");
    }
    
    /* Configure match */
    match->rules.score_limit = 20;
    match->rules.time_limit = 300.0f;  /* 5 minutes */
    match->rules.respawn_time = 3.0f;
    match->rules.friendly_fire = false;
    match->rules.team_count = 2;
    
    /* Add players */
    int local_player = aircraft_manager_add(aircraft_mgr, "Player 1", RED, false, true);
    aircraft_manager_add_with_team(aircraft_mgr, "AI Blue 1", BLUE, true, false, 1);
    aircraft_manager_add_with_team(aircraft_mgr, "AI Blue 2", SKYBLUE, true, false, 1);
    aircraft_manager_add_with_team(aircraft_mgr, "AI Red 1", MAROON, true, false, 0);
    aircraft_manager_add_with_team(aircraft_mgr, "AI Red 2", ORANGE, true, false, 0);
    
    /* Set AI skill levels */
    for (int i = 1; i < aircraft_mgr->aircraft_count; i++) {
        aircraft_mgr->aircraft[i].ai_skill = 0.7f + (float)(rand() % 30) / 100.0f;
    }
    
    /* Add power-up spawn points */
    Vector3 spawn_points[] = {
        {0, 50, 0},
        {100, 50, 100},
        {-100, 50, 100},
        {100, 50, -100},
        {-100, 50, -100},
        {200, 80, 0},
        {-200, 80, 0},
        {0, 100, 200},
        {0, 100, -200}
    };
    
    for (int i = 0; i < 9; i++) {
        powerup_manager_add_spawn_point(powerup_mgr, spawn_points[i], 
                                      POWERUP_HEALTH + (i % 8), 30.0f);
    }
    
    /* Set up camera */
    camera_controller_set_target(camera, (Vector3){0, 50, 0}, (Vector3){0, 0, 0}, 0);
    
    /* Main game loop */
    while (!WindowShouldClose()) {
        float dt = GetFrameTime();
        
        /* Update input system */
        input_view_fast_t view = input_mvc_fast_update(input_system);
        input_state_fast_t input = input_view_get_state(view);
        
        /* Handle input */
        managed_aircraft_t* player = aircraft_manager_get(aircraft_mgr, local_player);
        if (player && player->aircraft) {
            /* Use joystick input if connected, otherwise use keyboard fallback */
            float stick_x = input.move_x;
            float stick_y = input.move_y;
            
            /* Keyboard fallback if no joystick */
            if (!input_system->model.connected) {
                stick_x = 0.0f;
                stick_y = 0.0f;
                
                /* Left/Right for roll and turning */
                if (IsKeyDown(KEY_LEFT) || IsKeyDown(KEY_A)) stick_x = -1.0f;
                if (IsKeyDown(KEY_RIGHT) || IsKeyDown(KEY_D)) stick_x = 1.0f;
                
                /* Up/Down for pitch */
                if (IsKeyDown(KEY_UP) || IsKeyDown(KEY_W)) stick_y = 1.0f;  /* Pull up */
                if (IsKeyDown(KEY_DOWN) || IsKeyDown(KEY_S)) stick_y = -1.0f;  /* Push down */
            }
            
            /* Use the same responsive aircraft update as ultimate */
            aircraft_update_responsive(player->aircraft, stick_x, stick_y, dt);
            
            /* Speed control system like ultimate */
            static float boost_timer = 0.0f;
            boost_timer -= dt;
            
            /* UR button = Mario Kart style boost (ASTRO C40 paddle) */
            bool boost_pressed = input.speed_boost || 
                               (!input_system->model.connected && IsKeyPressed(KEY_SPACE));
            
            if (boost_pressed && boost_timer <= 0) {
                boost_timer = 0.75f;  /* 0.75 second boost */
                player->aircraft->speed = AIRCRAFT_MAX_SPEED * 2.5f;
                
                /* Visual feedback */
                camera_controller_shake(camera, SHAKE_MEDIUM, 0.5f);
            }
            
            /* Boost decay */
            if (boost_timer > 0) {
                if (boost_timer < 0.5f) {
                    /* Rapid decay back to normal */
                    float decay_rate = 300.0f * dt;
                    player->aircraft->speed = fmaxf(player->aircraft->speed - decay_rate,
                                                  AIRCRAFT_MAX_SPEED * 1.2f);
                }
            }
            /* UL button = Normal throttle (ASTRO C40 paddle) */
            else if (input.brake || (!input_system->model.connected && IsKeyDown(KEY_LEFT_SHIFT))) {
                player->aircraft->speed = fminf(player->aircraft->speed + 60.0f * dt,
                                              AIRCRAFT_MAX_SPEED * 1.2f);
            }
            /* No throttle = gradual slowdown */
            else {
                player->aircraft->speed = fmaxf(player->aircraft->speed - 25.0f * dt,
                                              AIRCRAFT_MIN_SPEED);
            }
            
            /* Fire weapons - L2/R2 triggers or keyboard */
            if (input.fire_guns || (!input_system->model.connected && IsKeyPressed(KEY_LEFT_CONTROL))) {
                aircraft_manager_fire_weapon(aircraft_mgr, local_player);
            }
            
            /* Camera control with right stick */
            if (input_system->model.connected) {
                /* Orbit camera with right stick when connected */
                if (fabsf(input.camera_x) > 0.1f || fabsf(input.camera_y) > 0.1f) {
                    camera_controller_orbit(camera, input.camera_x * 180.0f * dt, 
                                          input.camera_y * 50.0f * dt);
                }
            }
            
            /* Camera modes */
            if (IsKeyPressed(KEY_ONE)) camera_controller_set_mode(camera, CAMERA_MODE_FOLLOW, 0.5f);
            if (IsKeyPressed(KEY_TWO)) camera_controller_set_mode(camera, CAMERA_MODE_ORBIT, 0.5f);
            if (IsKeyPressed(KEY_THREE)) camera_controller_set_mode(camera, CAMERA_MODE_COCKPIT, 0.5f);
            if (IsKeyPressed(KEY_FOUR)) camera_controller_set_mode(camera, CAMERA_MODE_OVERVIEW, 0.5f);
            if (IsKeyPressed(KEY_FIVE)) camera_controller_set_mode(camera, CAMERA_MODE_FREE, 0.5f);
            
            /* Update camera with dynamic distance based on speed */
            float cam_distance = 35.0f + player->aircraft->speed * 0.1f;
            camera->base_distance = cam_distance;
            
            Vector3 forward = aircraft_get_forward_vector(player->aircraft);
            Vector3 velocity = Vector3Scale(forward, player->aircraft->speed);
            camera_controller_set_target(camera, player->aircraft->position,
                                       velocity, player->aircraft->speed);
        }
        
        /* Free camera controls */
        if (camera->mode == CAMERA_MODE_FREE) {
            camera_controller_free_camera_input(camera, dt);
        }
        
        /* Update systems */
        aircraft_manager_update(aircraft_mgr, dt);
        powerup_manager_update(powerup_mgr, dt);
        match_state_update(match, dt);
        camera_controller_update(camera, dt);
        
        /* Check power-up collections */
        for (int i = 0; i < aircraft_mgr->aircraft_count; i++) {
            managed_aircraft_t* aircraft = &aircraft_mgr->aircraft[i];
            if (!aircraft->aircraft) continue;
            
            for (int j = 0; j < powerup_mgr->spawn_point_count; j++) {
                powerup_t* powerup = &powerup_mgr->powerups[j];
                if (!powerup->active) continue;
                
                /* Check distance */
                float dist = Vector3Distance(aircraft->aircraft->position, powerup->position);
                if (dist < 10.0f) {
                    powerup_type_t type;
                    if (powerup_manager_check_collection(powerup_mgr, aircraft->aircraft->position, 10.0f, &type)) {
                        /* Apply power-up effect */
                        switch (type) {
                            case POWERUP_HEALTH:
                                aircraft->health = aircraft->max_health;
                                break;
                            case POWERUP_SHIELD:
                                aircraft->powerup_effects.shield_active = true;
                                break;
                            case POWERUP_RAPID_FIRE:
                                aircraft->powerup_effects.rapid_fire_active = true;
                                break;
                            case POWERUP_SPEED_BOOST:
                                aircraft->powerup_effects.speed_boost_active = true;
                                break;
                            default:
                                break;
                        }
                    }
                }
            }
        }
        
        /* Update match scores from kills */
        for (int i = 0; i < aircraft_mgr->aircraft_count; i++) {
            const managed_aircraft_t* aircraft = &aircraft_mgr->aircraft[i];
            if (aircraft->team_id >= 0 && aircraft->team_id < 4) {
                match->team_scores[aircraft->team_id] = 0;  /* Reset first */
            }
        }
        for (int i = 0; i < aircraft_mgr->aircraft_count; i++) {
            const managed_aircraft_t* aircraft = &aircraft_mgr->aircraft[i];
            if (aircraft->team_id >= 0 && aircraft->team_id < 4) {
                match->team_scores[aircraft->team_id] += aircraft->kills;
            }
        }
        
        /* Render */
        BeginDrawing();
        ClearBackground(SKYBLUE);
        
        /* 3D rendering */
        BeginMode3D(camera->camera);
        
        /* Draw world */
        cyberpunk_world_draw(world, camera->camera);
        
        /* Draw aircraft */
        for (int i = 0; i < aircraft_mgr->aircraft_count; i++) {
            render_aircraft(&aircraft_mgr->aircraft[i]);
        }
        
        /* Draw power-ups */
        for (int i = 0; i < powerup_mgr->spawn_point_count; i++) {
            render_powerup(&powerup_mgr->powerups[i]);
        }
        
        /* Draw spawn points (debug) */
        for (int i = 0; i < MAX_SPAWN_POINTS; i++) {
            if (Vector3Length(aircraft_mgr->spawn_points[i]) > 0) {
                DrawCubeWires(aircraft_mgr->spawn_points[i], 5, 5, 5, GREEN);
            }
        }
        
        EndMode3D();
        
        /* 2D HUD */
        render_hud(aircraft_mgr, match, local_player, input_system->model.connected);
        
        /* Camera mode indicator */
        const char* mode_name = camera_controller_get_mode_name(camera->mode);
        DrawText(mode_name, 10, 40, 20, WHITE);
        
        EndDrawing();
    }
    
    /* Cleanup */
    input_mvc_fast_destroy(input_system);
    camera_controller_destroy(camera);
    cyberpunk_world_destroy(world);
    match_state_destroy(match);
    powerup_manager_destroy(powerup_mgr);
    aircraft_manager_destroy(aircraft_mgr);
    
    CloseWindow();
    return 0;
}