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
#include "sky_combat/models/weapons.h"
#include "sky_combat/models/enemies.h"
#include "sky_combat/controllers/input_mvc_fast.h"
#include "sky_combat/views/combat_effects.h"

#define SCREEN_WIDTH 1920
#define SCREEN_HEIGHT 1080
#define TARGET_FPS 60

/* Forward declarations */
static void render_aircraft_ultimate(const managed_aircraft_t* aircraft, 
                                   effects_manager_t* effects, float game_time);
static void render_powerup_ultimate(const powerup_t* powerup, 
                                  effects_manager_t* effects, float game_time);
void camera_update_responsive(Camera3D* camera, Vector3 target, float yaw, 
                            float distance, float height, float dt);

/* Game state */
typedef struct {
    /* Core systems */
    aircraft_manager_t* aircraft_mgr;
    powerup_manager_t* powerup_mgr;
    match_state_t* match;
    cyberpunk_world_t* world;
    input_mvc_fast_t* input_system;
    effects_manager_t* effects;
    weapons_system_t* weapons;
    
    /* Camera with smooth following */
    Camera3D camera;
    float camera_yaw;
    float camera_distance;
    
    /* Local player */
    int local_player_id;
    float boost_timer;
    float damage_flash;
    
    /* Visual settings */
    float speed_lines_intensity;
    bool motion_blur_enabled;
} multiplayer_game_t;

/* Draw speed lines effect */
static void draw_speed_effects(multiplayer_game_t* game) {
    if (game->speed_lines_intensity <= 0) return;
    
    int line_count = (int)(game->speed_lines_intensity * 30);
    Vector2 center = {GetScreenWidth() / 2.0f, GetScreenHeight() / 2.0f};
    
    for (int i = 0; i < line_count; i++) {
        float angle = (float)i / line_count * 360.0f;
        float length = GetRandomValue(100, 300) * game->speed_lines_intensity;
        float offset = GetRandomValue(50, 150);
        
        Vector2 start = {
            center.x + cosf(angle * DEG2RAD) * offset,
            center.y + sinf(angle * DEG2RAD) * offset
        };
        Vector2 end = {
            center.x + cosf(angle * DEG2RAD) * (offset + length),
            center.y + sinf(angle * DEG2RAD) * (offset + length)
        };
        
        Color color = Fade(WHITE, 0.3f * game->speed_lines_intensity);
        DrawLineEx(start, end, 2.0f, color);
    }
}

/* Render aircraft with effects */
static void render_aircraft_ultimate(const managed_aircraft_t* aircraft, 
                                   effects_manager_t* effects, float game_time) {
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
    
    /* Fuselage with team color */
    DrawCube((Vector3){0, 0, 0}, scale * 2.0f, scale * 0.5f, scale * 0.5f, aircraft->color);
    DrawCubeWires((Vector3){0, 0, 0}, scale * 2.0f, scale * 0.5f, scale * 0.5f, BLACK);
    
    /* Wings with detail */
    DrawCube((Vector3){0, 0, 0}, scale * 0.2f, scale * 0.1f, scale * 3.0f, aircraft->color);
    DrawCubeWires((Vector3){0, 0, 0}, scale * 0.2f, scale * 0.1f, scale * 3.0f, BLACK);
    
    /* Tail */
    DrawCube((Vector3){-scale, scale * 0.3f, 0}, scale * 0.1f, scale * 0.8f, scale * 0.8f, aircraft->color);
    
    /* Engine glow with pulsing effect */
    if (aircraft->aircraft->speed > AIRCRAFT_BASE_SPEED) {
        float glow = 1.0f + sinf(game_time * 10.0f) * 0.2f;
        DrawSphere((Vector3){-scale, 0, 0}, scale * 0.3f * glow, ORANGE);
        DrawSphere((Vector3){-scale, 0, 0}, scale * 0.5f, Fade(ORANGE, 0.3f));
        
        /* Engine particles - TODO: Add when effects_spawn_debris is implemented */
    }
    
    /* Shield effect */
    if (aircraft->powerup_effects.shield_active) {
        DrawSphere((Vector3){0, 0, 0}, scale * 2.5f, Fade(SKYBLUE, 0.2f + sinf(game_time * 5) * 0.1f));
        DrawCircle3D(pos, scale * 2.5f, (Vector3){1, 0, 0}, 90, Fade(SKYBLUE, 0.5f));
        DrawCircle3D(pos, scale * 2.5f, (Vector3){0, 1, 0}, 90, Fade(SKYBLUE, 0.5f));
    }
    
    rlPopMatrix();
    
    /* Damage smoke - using small explosions for now */
    if (aircraft->health < aircraft->max_health * 0.5f && GetRandomValue(0, 100) < 10) {
        Vector3 smoke_pos = pos;
        smoke_pos.y += 1.0f;
        effects_spawn_explosion(effects, smoke_pos, 0.5f, DARKGRAY);
    }
}

/* Render power-up with effects */
static void render_powerup_ultimate(const powerup_t* powerup, effects_manager_t* effects, float game_time) {
    if (!powerup->active) return;
    
    /* Floating animation */
    float bob = sinf(game_time * 2.0f) * 2.0f;
    Vector3 pos = powerup->position;
    pos.y += bob;
    
    /* Rotating cube with glow */
    rlPushMatrix();
    rlTranslatef(pos.x, pos.y, pos.z);
    rlRotatef(game_time * 100, 0, 1, 0);
    rlRotatef(game_time * 70, 1, 0, 0);
    
    DrawCube((Vector3){0, 0, 0}, 3.0f, 3.0f, 3.0f, powerup->color);
    DrawCubeWires((Vector3){0, 0, 0}, 3.5f, 3.5f, 3.5f, WHITE);
    
    rlPopMatrix();
    
    /* Glow effect */
    DrawSphere(pos, 4.0f + sinf(game_time * 3) * 0.5f, Fade(powerup->color, 0.3f));
    
    /* Particle ring */
    for (int i = 0; i < 8; i++) {
        float angle = (i / 8.0f) * PI * 2 + game_time;
        Vector3 particle_pos = {
            pos.x + cosf(angle) * 5,
            pos.y,
            pos.z + sinf(angle) * 5
        };
        DrawSphere(particle_pos, 0.5f, Fade(powerup->color, 0.8f));
    }
}

/* Advanced HUD */
static void render_hud_ultimate(multiplayer_game_t* game) {
    const managed_aircraft_t* player = aircraft_manager_get(game->aircraft_mgr, game->local_player_id);
    if (!player) return;
    
    /* FPS and debug */
    DrawFPS(10, 10);
    
    /* Debug controls - show stick values */
    if (game->input_system->model.connected) {
        char debug[256];
        snprintf(debug, sizeof(debug), "LX: %.2f LY: %.2f", 
                game->input_system->model.normalized.move_x,
                game->input_system->model.normalized.move_y);
        DrawText(debug, 10, 40, 16, LIME);
    }
    
    /* Match timer with style */
    int minutes = (int)(game->match->elapsed_time / 60.0f);
    int seconds = (int)game->match->elapsed_time % 60;
    char timer[32];
    snprintf(timer, sizeof(timer), "%02d:%02d", minutes, seconds);
    
    int timer_width = MeasureText(timer, 50);
    DrawRectangle(GetScreenWidth()/2 - timer_width/2 - 20, 5, timer_width + 40, 60, Fade(BLACK, 0.5f));
    DrawText(timer, GetScreenWidth()/2 - timer_width/2, 10, 50, WHITE);
    
    /* Team scores with bars */
    int y_offset = 80;
    for (int i = 0; i < game->match->rules.team_count && i < 4; i++) {
        Color team_color = (Color[]){RED, BLUE, GREEN, YELLOW}[i];
        char score[64];
        snprintf(score, sizeof(score), "TEAM %d", i+1);
        
        DrawRectangle(GetScreenWidth() - 250, y_offset + i * 35, 240, 30, Fade(BLACK, 0.5f));
        DrawRectangle(GetScreenWidth() - 250, y_offset + i * 35, 
                     (int)(240.0f * game->match->team_scores[i] / game->match->rules.score_limit), 
                     30, Fade(team_color, 0.7f));
        DrawText(score, GetScreenWidth() - 240, y_offset + i * 35 + 5, 20, WHITE);
        DrawText(TextFormat("%d", game->match->team_scores[i]), 
                GetScreenWidth() - 50, y_offset + i * 35 + 5, 20, WHITE);
    }
    
    /* Player status with style */
    int status_y = GetScreenHeight() - 150;
    
    /* Health bar */
    float health_percent = player->health / player->max_health;
    DrawRectangle(50, status_y, 300, 30, Fade(BLACK, 0.7f));
    DrawRectangle(50, status_y, (int)(300 * health_percent), 30, 
                 health_percent > 0.3f ? GREEN : (game->damage_flash > 0 ? WHITE : RED));
    DrawRectangleLines(50, status_y, 300, 30, WHITE);
    DrawText("HULL", 10, status_y + 5, 20, WHITE);
    
    /* Shield indicator */
    if (player->powerup_effects.shield_active) {
        DrawRectangle(50, status_y + 35, 300, 15, Fade(BLACK, 0.7f));
        DrawRectangle(50, status_y + 35, 300, 15, Fade(SKYBLUE, 0.8f));
        DrawText("SHIELD", 10, status_y + 35, 15, SKYBLUE);
    }
    
    /* Boost indicator */
    if (game->boost_timer > 0) {
        DrawText("BOOST!", 50, status_y - 40, 40, ORANGE);
        DrawRectangle(50, status_y - 10, (int)(300 * (game->boost_timer / 0.75f)), 5, ORANGE);
    }
    
    /* Kill feed style */
    int feed_y = 150;
    DrawText("COMBAT LOG", 10, feed_y - 25, 18, WHITE);
    
    /* Weapon indicator */
    if (player->weapons) {
        const char* weapon_names[] = {"MACHINE GUN", "MISSILES", "LASER", "PLASMA"};
        DrawText(weapon_names[player->weapons->current_weapon % 4], 
                10, GetScreenHeight() - 200, 24, YELLOW);
    }
    
    /* Controls (smaller) */
    if (game->input_system->model.connected) {
        DrawText("ASTRO C40 CONNECTED", 10, GetScreenHeight() - 30, 16, GREEN);
    } else {
        DrawText("KEYBOARD MODE", 10, GetScreenHeight() - 30, 16, GRAY);
    }
}

/* Update camera with smooth following */
static void update_camera_ultimate(multiplayer_game_t* game, float dt) {
    const managed_aircraft_t* player = aircraft_manager_get(game->aircraft_mgr, game->local_player_id);
    if (!player || !player->aircraft) return;
    
    /* Dynamic camera distance based on speed */
    float cam_distance = 35.0f + player->aircraft->speed * 0.1f;
    float cam_height = 15.0f;
    
    /* Use the same camera update as ultimate */
    camera_update_responsive(&game->camera, player->aircraft->position,
                           player->aircraft->yaw + game->camera_yaw,
                           cam_distance, cam_height, dt);
}

int main(void) {
    /* Initialize window */
    SetConfigFlags(FLAG_WINDOW_RESIZABLE | FLAG_VSYNC_HINT | FLAG_MSAA_4X_HINT);
    InitWindow(SCREEN_WIDTH, SCREEN_HEIGHT, "Sky Combat - Multiplayer Ultimate");
    SetTargetFPS(TARGET_FPS);
    
    /* Create game state */
    multiplayer_game_t game = {0};
    
    /* Create systems */
    game.aircraft_mgr = aircraft_manager_create();
    game.powerup_mgr = powerup_manager_create();
    game.match = match_state_create(MATCH_TYPE_TEAM_DEATHMATCH);
    game.world = cyberpunk_world_create();
    game.input_system = input_mvc_fast_create();
    game.effects = effects_create(1000, 10000);  /* Lots of particles! */
    game.weapons = weapons_create();
    
    if (!game.aircraft_mgr || !game.powerup_mgr || !game.match || 
        !game.world || !game.input_system || !game.effects || !game.weapons) {
        fprintf(stderr, "Failed to create game systems\n");
        return 1;
    }
    
    printf("Sky Combat Multiplayer Ultimate\n");
    printf("Joystick: %s\n", game.input_system->model.connected ? "CONNECTED" : "Keyboard Mode");
    if (game.input_system->model.is_astro_c40) {
        printf("ASTRO C40 TR Controller detected!\n");
    }
    
    /* Configure match */
    game.match->rules.score_limit = 30;
    game.match->rules.time_limit = 300.0f;
    game.match->rules.respawn_time = 3.0f;
    game.match->rules.friendly_fire = false;
    game.match->rules.team_count = 2;
    
    /* Add players with teams */
    game.local_player_id = aircraft_manager_add(game.aircraft_mgr, "PLAYER 1", RED, false, true);
    aircraft_manager_add_with_team(game.aircraft_mgr, "BLUE LEADER", BLUE, true, false, 1);
    aircraft_manager_add_with_team(game.aircraft_mgr, "BLUE WING", SKYBLUE, true, false, 1);
    aircraft_manager_add_with_team(game.aircraft_mgr, "RED LEADER", MAROON, true, false, 0);
    aircraft_manager_add_with_team(game.aircraft_mgr, "RED WING", ORANGE, true, false, 0);
    
    /* Set AI skill levels */
    for (int i = 1; i < game.aircraft_mgr->aircraft_count; i++) {
        game.aircraft_mgr->aircraft[i].ai_skill = 0.6f + (float)(rand() % 40) / 100.0f;
    }
    
    /* Add power-up spawn points in cool locations */
    Vector3 spawn_points[] = {
        {0, 100, 0},      /* Center high */
        {150, 50, 150},   /* Corners */
        {-150, 50, 150},
        {150, 50, -150},
        {-150, 50, -150},
        {0, 150, 200},    /* High points */
        {0, 150, -200},
        {200, 75, 0},
        {-200, 75, 0}
    };
    
    for (int i = 0; i < 9; i++) {
        powerup_manager_add_spawn_point(game.powerup_mgr, spawn_points[i], 
                                      POWERUP_HEALTH + (i % 8), 20.0f);
    }
    
    /* Setup camera */
    game.camera.position = (Vector3){0, 50, -50};
    game.camera.target = (Vector3){0, 50, 0};
    game.camera.up = (Vector3){0, 1, 0};
    game.camera.fovy = 65.0f;
    game.camera.projection = CAMERA_PERSPECTIVE;
    game.camera_distance = 35.0f;
    
    /* Visual settings */
    game.motion_blur_enabled = true;
    
    /* Generate cyberpunk world */
    cyberpunk_world_generate(game.world, 42);
    cyberpunk_set_theme_blade_runner(game.world);
    
    /* Create render texture for post-processing */
    RenderTexture2D screen_buffer = LoadRenderTexture(GetScreenWidth(), GetScreenHeight());
    
    /* Main game loop */
    float game_time = 0;
    
    while (!WindowShouldClose()) {
        float dt = GetFrameTime();
        game_time += dt;
        
        /* Update input system */
        input_view_fast_t view = input_mvc_fast_update(game.input_system);
        input_state_fast_t input = input_view_get_state(view);
        
        /* Handle input for local player */
        managed_aircraft_t* player = aircraft_manager_get(game.aircraft_mgr, game.local_player_id);
        if (player && player->aircraft) {
            /* Get input from joystick or keyboard */
            float stick_x = input.move_x;
            float stick_y = input.move_y;
            
            if (!game.input_system->model.connected) {
                stick_x = 0.0f;
                stick_y = 0.0f;
                if (IsKeyDown(KEY_LEFT) || IsKeyDown(KEY_A)) stick_x = -1.0f;
                if (IsKeyDown(KEY_RIGHT) || IsKeyDown(KEY_D)) stick_x = 1.0f;
                if (IsKeyDown(KEY_UP) || IsKeyDown(KEY_W)) stick_y = -1.0f;  /* Up = negative Y */
                if (IsKeyDown(KEY_DOWN) || IsKeyDown(KEY_S)) stick_y = 1.0f;   /* Down = positive Y */
            }
            
            /* Responsive aircraft control */
            aircraft_update_responsive(player->aircraft, stick_x, stick_y, dt);
            
            /* Mario Kart boost system - UR button (speed_boost) is mushroom boost */
            game.boost_timer -= dt;
            
            bool boost_pressed = input.speed_boost || 
                               (!game.input_system->model.connected && IsKeyPressed(KEY_SPACE));
            
            if (boost_pressed && game.boost_timer <= 0) {
                game.boost_timer = 0.75f;
                /* INSTANT massive speed increase (like mushroom boost) */
                player->aircraft->speed = AIRCRAFT_MAX_SPEED * 2.5f;
                
                /* Epic boost effects */
                effects_sonic_boom(game.effects, player->aircraft->position,
                                 aircraft_get_forward_vector(player->aircraft));
                effects_screen_shake(game.effects, 3.0f, 0.5f);
                effects_screen_flash(game.effects, SKYBLUE, 0.3f);
                effects_spawn_powerup_collect(game.effects, player->aircraft->position, SKYBLUE);
            }
            
            /* Boost decay - rapid falloff like Mario Kart */
            if (game.boost_timer > 0) {
                /* Keep speed lines at max during boost */
                game.speed_lines_intensity = 1.0f;
                
                /* Only start decaying speed after 0.25 seconds */
                if (game.boost_timer < 0.5f) {
                    /* Rapid decay back to normal max speed */
                    float decay_rate = 300.0f * dt;
                    player->aircraft->speed = fmaxf(player->aircraft->speed - decay_rate,
                                                  AIRCRAFT_MAX_SPEED * 1.2f);
                }
            }
            /* UL button (brake) = normal throttle (SWAPPED) */
            else if (input.brake || (!game.input_system->model.connected && IsKeyDown(KEY_LEFT_SHIFT))) {
                player->aircraft->speed = fminf(player->aircraft->speed + 60.0f * dt,
                                              AIRCRAFT_MAX_SPEED * 1.2f);
                game.speed_lines_intensity = 0.6f;
            }
            /* No throttle = gradual speed decrease */
            else {
                player->aircraft->speed = fmaxf(player->aircraft->speed - 25.0f * dt,
                                              AIRCRAFT_MIN_SPEED);
                game.speed_lines_intensity = fmaxf(0, game.speed_lines_intensity - dt * 2);
            }
            
            /* Weapons */
            if (input.fire_guns || (!game.input_system->model.connected && IsKeyPressed(KEY_LEFT_CONTROL))) {
                aircraft_manager_fire_weapon(game.aircraft_mgr, game.local_player_id);
                
                /* Weapon effects */
                Vector3 pos = player->aircraft->position;
                Vector3 forward = aircraft_get_forward_vector(player->aircraft);
                weapons_fire_bullet(game.weapons, pos, forward, player->aircraft->yaw);
                effects_spawn_laser_hit(game.effects, pos, forward, YELLOW);
            }
            
            /* Camera control from right stick */
            game.camera_yaw += input.camera_x * 100.0f * dt;
        }
        
        /* Update systems */
        aircraft_manager_update(game.aircraft_mgr, dt);
        powerup_manager_update(game.powerup_mgr, dt);
        match_state_update(game.match, dt);
        weapons_update(game.weapons, dt);
        effects_update(game.effects, dt);
        update_camera_ultimate(&game, dt);
        
        /* Check collisions */
        for (int i = 0; i < game.aircraft_mgr->aircraft_count; i++) {
            managed_aircraft_t* aircraft = &game.aircraft_mgr->aircraft[i];
            if (!aircraft->aircraft) continue;
            
            /* Power-up collection */
            for (int j = 0; j < game.powerup_mgr->spawn_point_count; j++) {
                powerup_t* powerup = &game.powerup_mgr->powerups[j];
                if (!powerup->active) continue;
                
                float dist = Vector3Distance(aircraft->aircraft->position, powerup->position);
                if (dist < 10.0f) {
                    powerup_type_t type;
                    if (powerup_manager_check_collection(game.powerup_mgr, 
                                                       aircraft->aircraft->position, 10.0f, &type)) {
                        /* Apply effect */
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
                        
                        /* Collection effect */
                        effects_spawn_powerup_collect(game.effects, powerup->position, powerup->color);
                        effects_show_achievement(game.effects, "POWER-UP!");
                    }
                }
            }
        }
        
        /* Update scores */
        for (int i = 0; i < 4; i++) {
            game.match->team_scores[i] = 0;
        }
        for (int i = 0; i < game.aircraft_mgr->aircraft_count; i++) {
            const managed_aircraft_t* aircraft = &game.aircraft_mgr->aircraft[i];
            if (aircraft->team_id >= 0 && aircraft->team_id < 4) {
                game.match->team_scores[aircraft->team_id] += aircraft->kills;
            }
        }
        
        /* Damage flash */
        if (game.damage_flash > 0) game.damage_flash -= dt;
        
        /* Render to texture for post-processing */
        BeginTextureMode(screen_buffer);
        ClearBackground(BLACK);
        
        BeginMode3D(game.camera);
        
        /* Draw world */
        cyberpunk_world_draw(game.world, game.camera);
        
        /* Draw aircraft with effects */
        for (int i = 0; i < game.aircraft_mgr->aircraft_count; i++) {
            render_aircraft_ultimate(&game.aircraft_mgr->aircraft[i], game.effects, game_time);
        }
        
        /* Draw power-ups */
        for (int i = 0; i < game.powerup_mgr->spawn_point_count; i++) {
            render_powerup_ultimate(&game.powerup_mgr->powerups[i], game.effects, game_time);
        }
        
        /* Draw weapons */
        weapons_draw(game.weapons);
        
        /* Draw effects */
        effects_draw(game.effects, game.camera);
        
        EndMode3D();
        
        EndTextureMode();
        
        /* Final render with post-processing */
        BeginDrawing();
        
        /* Draw screen buffer */
        DrawTextureRec(screen_buffer.texture, 
                      (Rectangle){0, 0, screen_buffer.texture.width, -screen_buffer.texture.height},
                      (Vector2){0, 0}, WHITE);
        
        /* Speed effects */
        draw_speed_effects(&game);
        
        /* UI and effects */
        effects_draw_ui(game.effects, GetScreenWidth(), GetScreenHeight());
        render_hud_ultimate(&game);
        
        /* Damage flash */
        if (game.damage_flash > 0) {
            DrawRectangle(0, 0, GetScreenWidth(), GetScreenHeight(), 
                         Fade(RED, game.damage_flash * 0.3f));
        }
        
        EndDrawing();
    }
    
    /* Cleanup */
    UnloadRenderTexture(screen_buffer);
    input_mvc_fast_destroy(game.input_system);
    cyberpunk_world_destroy(game.world);
    match_state_destroy(game.match);
    powerup_manager_destroy(game.powerup_mgr);
    aircraft_manager_destroy(game.aircraft_mgr);
    effects_destroy(game.effects);
    weapons_destroy(game.weapons);
    
    CloseWindow();
    return 0;
}