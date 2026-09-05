/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

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
#include "sky_combat/models/boss_cyber_dragon.h"

// Forward declare responsive functions
void aircraft_update_responsive(aircraft_t* aircraft, float stick_x, float stick_y, float dt);
void camera_update_responsive(Camera3D* camera, Vector3 target, float yaw, float distance, float height, float dt);

// PHASE 2: Helper to get player aircraft
#define GET_PLAYER_AIRCRAFT(game) \
    (aircraft_manager_get((game)->aircraft_mgr, (game)->player_id))
    
#define GET_PLAYER_AIRCRAFT_DIRECT(game) \
    (GET_PLAYER_AIRCRAFT(game) ? GET_PLAYER_AIRCRAFT(game)->aircraft : NULL)

typedef struct {
    // Core systems
    aircraft_manager_t* aircraft_mgr;  // PHASE 2: Replace single aircraft with manager
    int player_id;                     // PHASE 2: Track which aircraft is the player
    weapons_system_t* weapons;
    input_mvc_fast_t* input;
    enemy_manager_t* enemies;
    cyberpunk_world_t* world;
    effects_manager_t* effects;
    overdrive_system_t* overdrive;
    
    // Boss
    cyber_dragon_t* boss;
    bool boss_spawned;
    bool boss_defeated;
    
    // Camera
    Camera3D camera;
    
    // Game state
    int score;
    int combo;
    float combo_timer;
    int max_combo;
    int wave;
    bool game_over;
    bool victory;
    
    // Player state
    float boost_fuel;
    float shield_power;
    float player_health;
    float damage_flash;
    float boost_timer;  // Timer for UL boost burst
    
    // Progression
    int rank;  // 0=Rookie, 1=Pilot, 2=Ace, 3=Legend
    int total_kills;
    int boss_kills;
    float play_time;
    
    // Visual settings
    bool motion_blur_enabled;
    bool chromatic_enabled;
    float speed_lines_intensity;
} ultimate_game_t;

static ultimate_game_t* game_create(void) {
    ultimate_game_t* game = calloc(1, sizeof(ultimate_game_t));
    
    // Create systems
    game->aircraft_mgr = aircraft_manager_create();  // PHASE 2: Create manager
    game->weapons = weapons_create();
    game->input = input_mvc_fast_create();
    game->enemies = enemies_create(200);
    game->world = cyberpunk_world_create();
    game->effects = effects_create(1000, 10000);  // More particles!
    game->overdrive = overdrive_create();
    
    // PHASE 2: Add single player aircraft to manager
    game->player_id = aircraft_manager_add(game->aircraft_mgr, "PLAYER", SKYBLUE, false, true);
    
    // PHASE 2: Position player aircraft
    managed_aircraft_t* player = aircraft_manager_get(game->aircraft_mgr, game->player_id);
    if (player && player->aircraft) {
        player->aircraft->position = (Vector3){0, 50, 0};
    }
    
    // PHASE 3: Add AI aircraft (no combat yet, just flying around)
    int ai1 = aircraft_manager_add(game->aircraft_mgr, "SECRETARIAT", RED, true, false);
    int ai2 = aircraft_manager_add(game->aircraft_mgr, "SEATTLE SLEW", MAROON, true, false);
    int ai3 = aircraft_manager_add(game->aircraft_mgr, "AFFIRMED", BLUE, true, false);
    int ai4 = aircraft_manager_add(game->aircraft_mgr, "WAR ADMIRAL", DARKGREEN, true, false);
    
    // PHASE 3: Set AI skill levels - LOW like Pac-Man ghosts
    for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
        if (game->aircraft_mgr->aircraft[i].is_ai) {
            game->aircraft_mgr->aircraft[i].ai_skill = 0.1f + (float)(rand() % 20) / 100.0f; // 0.1 to 0.3
            game->aircraft_mgr->aircraft[i].ai_aggression = 0.2f; // Low aggression
        }
    }
    
    // Setup camera
    game->camera.position = (Vector3){0, 20, -30};
    game->camera.target = (Vector3){0, 0, 0};
    game->camera.up = (Vector3){0, 1, 0};
    game->camera.fovy = 65.0f;
    game->camera.projection = CAMERA_PERSPECTIVE;
    
    // Initial state
    game->boost_fuel = 100.0f;
    game->shield_power = 100.0f;
    game->player_health = 100.0f;
    game->boost_timer = 0.0f;  // Initialize boost timer
    
    // Visual settings
    game->motion_blur_enabled = true;
    game->chromatic_enabled = true;
    
    // Generate world
    cyberpunk_world_generate(game->world, 42);
    cyberpunk_set_theme_blade_runner(game->world);
    
    return game;
}

static void spawn_boss(ultimate_game_t* game) {
    if (game->boss_spawned) return;
    
    // Epic boss entrance
    Vector3 spawn_pos = {0, 200, 300};
    game->boss = cyber_dragon_create(spawn_pos);
    game->boss_spawned = true;
    
    // Clear all enemies manually
    // TODO: Add proper clear function to enemy manager
    
    // Screen effects
    effects_screen_flash(game->effects, WHITE, 1.0f);
    effects_screen_shake(game->effects, 5.0f, 2.0f);
    effects_show_achievement(game->effects, "BOSS: CYBER DRAGON AWAKENS!");
    
    printf("BOSS BATTLE INITIATED!\n");
}

static void handle_combat_ultimate(ultimate_game_t* game, input_state_fast_t* input, float dt) {
    // PHASE 2: Get player aircraft from manager
    aircraft_t* player_aircraft = GET_PLAYER_AIRCRAFT_DIRECT(game);
    if (!player_aircraft) return;
    
    Vector3 pos = player_aircraft->position;
    Vector3 forward = aircraft_get_forward_vector(player_aircraft);
    float yaw = player_aircraft->yaw;
    
    // OVERDRIVE activation - Triangle button (Y on Xbox layout)
    if (IsGamepadButtonPressed(0, GAMEPAD_BUTTON_RIGHT_FACE_UP) && 
        overdrive_can_activate(game->overdrive)) {
        overdrive_activate(game->overdrive);
        effects_show_achievement(game->effects, "OVERDRIVE ACTIVATED!");
        effects_screen_flash(game->effects, ORANGE, 0.5f);
        
        // Instant effects
        game->boost_fuel = 100.0f;
        game->shield_power = 100.0f;
    }
    
    // Weapon switching
    if (IsGamepadButtonPressed(0, GAMEPAD_BUTTON_RIGHT_FACE_DOWN)) {
        weapons_switch_weapon(game->weapons, WEAPON_MACHINE_GUN);
    }
    if (IsGamepadButtonPressed(0, GAMEPAD_BUTTON_RIGHT_FACE_RIGHT)) {
        weapons_switch_weapon(game->weapons, WEAPON_LASER);
    }
    if (IsGamepadButtonPressed(0, GAMEPAD_BUTTON_RIGHT_FACE_LEFT)) {
        weapons_switch_weapon(game->weapons, WEAPON_SPREAD);
    }
    if (IsGamepadButtonPressed(0, GAMEPAD_BUTTON_LEFT_THUMB)) {
        weapons_switch_weapon(game->weapons, WEAPON_RAILGUN);
    }
    
    // Apply overdrive multipliers
    float damage_mult = overdrive_get_damage_multiplier(game->overdrive);
    
    // Firing is now handled in main loop for continuous stream
    // Overdrive triple shot is handled there too
    
    if (input->fire_missiles) {
        static int wing = 1;
        wing = -wing;
        
        // Target boss if present
        void* target = game->boss_spawned && !game->boss_defeated ? game->boss : NULL;
        
        weapons_fire_missile(game->weapons, pos, forward, yaw, wing, target);
        effects_spawn_powerup_collect(game->effects, pos, wing > 0 ? ORANGE : RED);
        
        if (overdrive_is_active(game->overdrive)) {
            // Fire extra missiles in overdrive
            weapons_fire_missile(game->weapons, pos, forward, yaw + 10, wing, target);
            weapons_fire_missile(game->weapons, pos, forward, yaw - 10, -wing, target);
        }
    }
    
    // Barrel rolls
    if (input->barrel_roll_left) {
        aircraft_barrel_roll_left(player_aircraft, dt);
        effects_sonic_boom(game->effects, pos, forward);
        effects_activate_bullet_time(game->effects, 0.5f);
    }
    if (input->barrel_roll_right) {
        aircraft_barrel_roll_right(player_aircraft, dt);
        effects_sonic_boom(game->effects, pos, forward);
        effects_activate_bullet_time(game->effects, 0.5f);
    }
}

static void update_progression(ultimate_game_t* game) {
    // Rank progression
    if (game->total_kills >= 100 && game->rank < 1) {
        game->rank = 1;
        effects_show_achievement(game->effects, "RANK UP: PILOT!");
    } else if (game->total_kills >= 500 && game->rank < 2) {
        game->rank = 2;
        effects_show_achievement(game->effects, "RANK UP: ACE!");
    } else if (game->boss_kills >= 1 && game->rank < 3) {
        game->rank = 3;
        effects_show_achievement(game->effects, "RANK UP: LEGEND!");
    }
}

static void draw_advanced_ui(ultimate_game_t* game) {
    // Rank display
    const char* ranks[] = {"ROOKIE", "PILOT", "ACE", "LEGEND"};
    Color rank_colors[] = {GRAY, GREEN, BLUE, GOLD};
    DrawText(ranks[game->rank], 10, 10, 30, rank_colors[game->rank]);
    
    // Score with combo
    char score_text[128];
    if (game->combo > 1) {
        snprintf(score_text, sizeof(score_text), "SCORE: %d (x%d COMBO)", 
                game->score, game->combo);
        DrawText(score_text, 10, 50, 20, YELLOW);
    } else {
        snprintf(score_text, sizeof(score_text), "SCORE: %d", game->score);
        DrawText(score_text, 10, 50, 20, WHITE);
    }
    
    // Wave or boss indicator
    if (game->boss_spawned && !game->boss_defeated) {
        cyber_dragon_draw_health_bar(game->boss);
    } else {
        char wave_text[64];
        snprintf(wave_text, sizeof(wave_text), "WAVE %d | ENEMIES: %d", 
                game->wave + 1, enemies_get_active_count(game->enemies));
        DrawText(wave_text, 10, 80, 20, WHITE);
    }
    
    // Weapon
    const char* weapons[] = {"MACHINEGUN", "MISSILES", "LASER", "PLASMA", "RAILGUN", "SPREAD"};
    DrawText(weapons[game->weapons->current_weapon], 10, 110, 20, YELLOW);
    
    // Overdrive bar
    overdrive_draw_ui(game->overdrive, 10, GetScreenHeight() - 160);
    
    // Player bars
    int bar_y = GetScreenHeight() - 120;
    
    // Health
    DrawText("HULL", 10, bar_y, 16, WHITE);
    DrawRectangle(60, bar_y, 200, 20, DARKGRAY);
    DrawRectangle(60, bar_y, (int)(game->player_health * 2), 20, 
                 game->damage_flash > 0 ? WHITE : GREEN);
    
    // Shield
    DrawText("SHIELD", 10, bar_y + 25, 16, WHITE);
    DrawRectangle(60, bar_y + 25, 200, 20, DARKGRAY);
    DrawRectangle(60, bar_y + 25, (int)(game->shield_power * 2), 20, SKYBLUE);
    
    // Boost
    DrawText("BOOST", 10, bar_y + 50, 16, WHITE);
    DrawRectangle(60, bar_y + 50, 200, 20, DARKGRAY);
    DrawRectangle(60, bar_y + 50, (int)(game->boost_fuel * 2), 20, ORANGE);
    
    // World position indicator
    aircraft_t* player_pos_check = GET_PLAYER_AIRCRAFT_DIRECT(game);
    if (player_pos_check) {
        // Show warning when near world edge
        float edge_dist_x = fminf(fabsf(player_pos_check->position.x - WORLD_HALF_SIZE), 
                                  fabsf(player_pos_check->position.x + WORLD_HALF_SIZE));
        float edge_dist_z = fminf(fabsf(player_pos_check->position.z - WORLD_HALF_SIZE), 
                                  fabsf(player_pos_check->position.z + WORLD_HALF_SIZE));
        float min_edge_dist = fminf(edge_dist_x, edge_dist_z);
        
        if (min_edge_dist < 200.0f) {
            Color edge_color = ColorLerp(RED, YELLOW, min_edge_dist / 200.0f);
            DrawText("APPROACHING WORLD EDGE", GetScreenWidth()/2 - 150, 150, 24, edge_color);
            DrawText("(WILL WRAP TO OTHER SIDE)", GetScreenWidth()/2 - 140, 180, 18, edge_color);
        }
    }
    
    // Stats on right side
    int stats_x = GetScreenWidth() - 200;
    DrawText("STATISTICS", stats_x, 10, 20, WHITE);
    
    // Get player's actual stats from aircraft manager
    managed_aircraft_t* player_stats = aircraft_manager_get(game->aircraft_mgr, game->player_id);
    int player_kills = player_stats ? player_stats->kills : 0;
    int player_deaths = player_stats ? player_stats->deaths : 0;
    
    char stats[256];
    snprintf(stats, sizeof(stats), 
            "Player K/D: %d/%d\n"
            "Max Combo: %d\n"
            "Time: %.1f\n"
            "FPS: %d",
            player_kills,
            player_deaths,
            game->max_combo,
            game->play_time,
            GetFPS());
    DrawText(stats, stats_x, 40, 16, LIGHTGRAY);
}

static void draw_speed_effects(ultimate_game_t* game) {
    if (game->speed_lines_intensity <= 0) return;
    
    // Speed lines from center
    int line_count = (int)(20 * game->speed_lines_intensity);
    Vector2 center = {GetScreenWidth() / 2.0f, GetScreenHeight() / 2.0f};
    
    for (int i = 0; i < line_count; i++) {
        float angle = (float)i / line_count * PI * 2.0f;
        float speed = 500 + GetRandomValue(0, 300);
        float length = 50 + GetRandomValue(0, 100);
        
        Vector2 start = {
            center.x + cosf(angle) * speed,
            center.y + sinf(angle) * speed
        };
        
        Vector2 end = {
            center.x + cosf(angle) * (speed - length),
            center.y + sinf(angle) * (speed - length)
        };
        
        Color line_color = WHITE;
        line_color.a = (unsigned char)(game->speed_lines_intensity * 100);
        
        DrawLineEx(start, end, 2.0f, line_color);
    }
}

int main(void) {
    InitWindow(1280, 720, "Full Node: Firewall Fly-over");
    SetTargetFPS(60);
    
    ultimate_game_t* game = game_create();
    
    printf("\n=== ULTIMATE CYBERPUNK COMBAT ===\n");
    printf("Features:\n");
    printf("- OVERDRIVE MODE (Press Y when charged)\n");
    printf("- EPIC BOSS BATTLES\n");
    printf("- VISUAL EFFECTS GALORE\n");
    printf("- PROGRESSION SYSTEM\n");
    printf("- COMBO MULTIPLIERS\n\n");
    
    // Spawn initial enemies
    enemies_spawn_wave(game->enemies, 0);
    
    // Render targets for effects
    RenderTexture2D screen_buffer = LoadRenderTexture(GetScreenWidth(), GetScreenHeight());
    
    while (!WindowShouldClose() && !game->game_over && !game->victory) {
        float dt = GetFrameTime();
        game->play_time += dt;
        
        // Fast MVC update
        input_view_fast_t view = input_mvc_fast_update(game->input);
        input_state_fast_t input = input_view_get_state(view);
        
        // Update overdrive
        overdrive_update(game->overdrive, dt);
        
        // Apply overdrive speed boost
        float speed_mult = overdrive_is_active(game->overdrive) ? 1.5f : 1.0f;
        
        // Aircraft update
        // PHASE 2: Get player aircraft from manager
        aircraft_t* player_aircraft = GET_PLAYER_AIRCRAFT_DIRECT(game);
        if (!player_aircraft) continue;
        
        // Handle keyboard input if no joystick
        float move_x = input.move_x;
        float move_y = input.move_y;
        
        if (!game->input->model.connected) {
            move_x = 0.0f;
            move_y = 0.0f;
            if (IsKeyDown(KEY_LEFT) || IsKeyDown(KEY_A)) move_x = -1.0f;
            if (IsKeyDown(KEY_RIGHT) || IsKeyDown(KEY_D)) move_x = 1.0f;
            if (IsKeyDown(KEY_UP) || IsKeyDown(KEY_W)) move_y = -1.0f;  // Up = negative Y
            if (IsKeyDown(KEY_DOWN) || IsKeyDown(KEY_S)) move_y = 1.0f;   // Down = positive Y
        }
        
        aircraft_update_responsive(player_aircraft, move_x, move_y, dt);
        
        // DEBUG: Print input values every 60 frames
        static int debug_counter = 0;
        if (++debug_counter >= 60) {
            debug_counter = 0;
            printf("Input - X: %.3f, Y: %.3f | Speed: %.1f | Boost: %d, Brake: %d\n", 
                   move_x, move_y, player_aircraft->speed,
                   input.speed_boost ? 1 : 0, input.brake ? 1 : 0);
        }
        
        // Speed control - New system with UR throttle and UL boost
        
        // UR button = Mario Kart style mushroom boost (SWAPPED)
        bool boost_pressed = input.speed_boost || 
                           (!game->input->model.connected && IsKeyPressed(KEY_SPACE));
        if (boost_pressed && game->boost_timer <= 0) {  // 'speed_boost' is now UR boost
            game->boost_timer = 0.75f;  // 0.75 second duration (HALF recharge time)
            
            // INSTANT massive speed increase (like mushroom boost)
            player_aircraft->speed = AIRCRAFT_MAX_SPEED * 3.25f * speed_mult;  // 30% faster: 243.75 instead of 187.5
            
            // Visual/audio feedback
            effects_sonic_boom(game->effects, player_aircraft->position, 
                             aircraft_get_forward_vector(player_aircraft));
            effects_screen_shake(game->effects, 3.0f, 0.5f);
            effects_screen_flash(game->effects, SKYBLUE, 0.3f);
            effects_spawn_powerup_collect(game->effects, player_aircraft->position, SKYBLUE);
        }
        
        // Boost decay - rapid falloff like Mario Kart
        if (game->boost_timer > 0) {
            game->boost_timer -= dt;
            
            // Keep speed lines at max during boost
            game->speed_lines_intensity = 1.0f;
            
            // Only start decaying speed after 0.25 seconds (proportionally reduced)
            if (game->boost_timer < 0.5f) {
                // Rapid decay back to normal max speed
                float decay_rate = 300.0f * dt;  // Faster decay for shorter boost
                player_aircraft->speed = fmaxf(player_aircraft->speed - decay_rate, 
                                             AIRCRAFT_MAX_SPEED * 1.2f * speed_mult);
            }
        }
        // UL button = normal throttle (SWAPPED)
        else {
            bool throttle_pressed = input.brake ||
                                  (!game->input->model.connected && IsKeyDown(KEY_LEFT_SHIFT));
            if (throttle_pressed) {  // 'brake' is now UL throttle
                player_aircraft->speed = fminf(player_aircraft->speed + 90.0f * dt * speed_mult,  // 50% faster acceleration
                                             AIRCRAFT_MAX_SPEED * 1.2f * speed_mult);
                game->speed_lines_intensity = 0.6f;
            }
            // No throttle = gradual speed decrease
            else {
                player_aircraft->speed = fmaxf(player_aircraft->speed - 25.0f * dt, AIRCRAFT_MIN_SPEED);
                game->speed_lines_intensity = fmaxf(0, game->speed_lines_intensity - dt * 2);
            }
        }
        // Camera - Fixed behind aircraft (no right stick control)
        float cam_distance = 35.0f + player_aircraft->speed * 0.1f;
        float cam_height = 15.0f;  // Fixed height, no right stick Y
        camera_update_responsive(&game->camera, player_aircraft->position, 
                               player_aircraft->yaw,  // No right stick X adjustment
                               cam_distance, cam_height, dt);
        
        // Continuous firing when R2 is held - EVERY FRAME!
        if (input.fire_guns || (!game->input->model.connected && IsKeyDown(KEY_LEFT_CONTROL))) {
            // Use right stick to fine-tune bullet direction
            float aim_x = -input.camera_x;  // Right stick X INVERTED - right moves bullets right
            float aim_y = input.camera_y;   // Right stick Y normal - up moves bullets up
            
            // Fire continuously with aiming adjustment
            aircraft_manager_fire_weapon_aimed(game->aircraft_mgr, game->player_id, aim_x, aim_y);
            
            // Triple shot in overdrive mode
            if (overdrive_is_active(game->overdrive)) {
                aircraft_manager_fire_weapon_aimed(game->aircraft_mgr, game->player_id, 
                                                 aim_x - 0.1f, aim_y);
                aircraft_manager_fire_weapon_aimed(game->aircraft_mgr, game->player_id, 
                                                 aim_x + 0.1f, aim_y);
            }
        }
        
        // Combat (other combat actions)
        handle_combat_ultimate(game, &input, dt);
        
        // PHASE 3: Update all aircraft (including AI)
        // This also updates each aircraft's weapons and checks collisions
        aircraft_manager_update(game->aircraft_mgr, dt);
        
        // Check for destroyed aircraft and spawn explosions BEFORE respawn
        static int last_kills[MAX_MANAGED_AIRCRAFT] = {0};
        static bool first_check = true;
        
        for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
            managed_aircraft_t* ma = &game->aircraft_mgr->aircraft[i];
            
            // Initialize kill tracking
            if (first_check) {
                last_kills[i] = ma->deaths;
            }
            
            // Check if aircraft got a new death (was just destroyed)
            if (ma->deaths > last_kills[i]) {
                // BIG EXPLOSION at current position!
                Vector3 explosion_pos = ma->aircraft->position;
                
                // Multiple layered explosions for massive effect
                effects_spawn_explosion(game->effects, explosion_pos, 80.0f, ORANGE);
                effects_spawn_explosion(game->effects, explosion_pos, 60.0f, RED);
                effects_spawn_explosion(game->effects, explosion_pos, 40.0f, YELLOW);
                effects_spawn_explosion(game->effects, explosion_pos, 20.0f, WHITE);
                
                // Spawn many particles as debris
                for (int p = 0; p < 50; p++) {
                    float angle = (float)p * (PI * 2.0f / 50.0f);
                    float speed = 150.0f + GetRandomValue(0, 300);
                    Vector3 vel = {
                        cosf(angle) * speed,
                        100.0f + GetRandomValue(0, 200),
                        sinf(angle) * speed
                    };
                    effects_spawn_missile_trail(game->effects, explosion_pos, vel);
                }
                
                // More particles going up
                for (int p = 0; p < 20; p++) {
                    Vector3 vel = {
                        GetRandomValue(-100, 100),
                        200.0f + GetRandomValue(0, 200),
                        GetRandomValue(-100, 100)
                    };
                    effects_spawn_missile_trail(game->effects, explosion_pos, vel);
                }
                
                effects_screen_shake(game->effects, 8.0f, 1.0f);
                effects_screen_flash(game->effects, WHITE, 0.3f);
                
                // Extra effects for enemy kill
                if (i != game->player_id) { // Enemy destroyed (not player)
                    effects_show_achievement(game->effects, "ENEMY DESTROYED!");
                    effects_spawn_powerup_collect(game->effects, explosion_pos, GOLD);
                    Vector3 boom_dir = {1.0f, 0.0f, 0.0f}; // Safe non-zero direction
                    effects_sonic_boom(game->effects, explosion_pos, boom_dir);
                }
                
                // Update death count
                last_kills[i] = ma->deaths;
            }
        }
        first_check = false;
        
        // Enemy/Boss update
        if (game->boss_spawned && !game->boss_defeated) {
            cyber_dragon_update(game->boss, player_aircraft->position, dt);
            
            // Check boss collision with player
            if (cyber_dragon_check_collision(game->boss, player_aircraft->position, 5.0f)) {
                game->player_health -= 20.0f * dt;
                game->damage_flash = 0.3f;
            }
            
            // Check weapon hits on boss
            // (In full implementation, would check all projectiles)
            
            if (game->boss->health <= 0) {
                game->boss_defeated = true;
                game->boss_kills++;
                game->score += 10000;
                effects_show_achievement(game->effects, "CYBER DRAGON DEFEATED!");
                overdrive_charge(game->overdrive, 100.0f);  // Full charge reward
            }
        } else {
            enemies_update(game->enemies, player_aircraft->position, dt);
            
            // Spawn boss after wave 3
            if (game->wave >= 3 && !game->boss_spawned) {
                spawn_boss(game);
            }
        }
        
        // World updates
        cyberpunk_world_update(game->world, dt);
        effects_update(game->effects, dt);
        
        // Check player damage
        if (enemies_check_player_hit(game->enemies, player_aircraft->position, 5.0f)) {
            if (!overdrive_is_active(game->overdrive)) {  // Invincible in overdrive
                float damage = 10.0f;
                if (game->shield_power > 0) {
                    game->shield_power -= damage;
                    if (game->shield_power < 0) {
                        damage = -game->shield_power;
                        game->shield_power = 0;
                    }
                    effects_spawn_shield_ripple(game->effects, player_aircraft->position, 15.0f);
                }
                
                if (damage > 0) {
                    game->player_health -= damage;
                    game->damage_flash = 0.3f;
                    effects_screen_flash(game->effects, RED, 0.2f);
                    effects_screen_shake(game->effects, 1.5f, 0.2f);
                    
                    if (game->player_health <= 0) {
                        game->game_over = true;
                    }
                }
            }
        }
        
        // Combo system
        if (game->combo_timer > 0) {
            game->combo_timer -= dt;
        } else {
            if (game->combo > game->max_combo) {
                game->max_combo = game->combo;
            }
            game->combo = 0;
        }
        
        // Enemy kills give overdrive charge
        // TODO: Implement proper weapon hit detection
        int kills = 0;  // Placeholder for enemies_check_weapon_hits
        if (enemies_get_active_count(game->enemies) < 10 && rand() % 100 < 5) {
            kills = 1;  // Simulate kills for demo
            game->total_kills += kills;
            game->score += kills * 100 * (game->combo + 1);
            game->combo += kills;
            game->combo_timer = 3.0f;
            
            overdrive_charge(game->overdrive, kills * 5.0f);
        }
        
        // Regeneration
        if (game->damage_flash > 0) game->damage_flash -= dt;
        
        if (game->boost_fuel < 100 && !input.speed_boost) {
            game->boost_fuel += 15 * dt;
        }
        
        if (game->shield_power < 100 && !enemies_check_player_hit(game->enemies, 
                                                                  player_aircraft->position, 50.0f)) {
            game->shield_power += 5 * dt;  // Slow shield regen when safe
        }
        
        // Wave management
        if (!game->boss_spawned && enemies_wave_complete(game->enemies)) {
            game->wave++;
            if (game->wave < 3) {
                enemies_spawn_wave(game->enemies, game->wave);
                effects_show_achievement(game->effects, "WAVE CLEARED!");
                overdrive_charge(game->overdrive, 20.0f);
            }
        }
        
        // Victory condition
        if (game->boss_defeated && enemies_get_active_count(game->enemies) == 0) {
            game->victory = true;
        }
        
        // Update progression
        update_progression(game);
        
        // Drawing with effects
        BeginTextureMode(screen_buffer);
        ClearBackground(BLACK);
        
        BeginMode3D(game->camera);
        
        // World
        cyberpunk_world_draw(game->world, game->camera);
        
        // Overdrive effects behind aircraft
        if (overdrive_is_active(game->overdrive)) {
            overdrive_draw_effects(game->overdrive, player_aircraft->position, game->camera);
        }
        
        // PHASE 3: Draw all aircraft and their weapons
        for (int i = 0; i < game->aircraft_mgr->aircraft_count; i++) {
            managed_aircraft_t* aircraft = &game->aircraft_mgr->aircraft[i];
            
            // Don't draw if respawning
            if (aircraft->respawn_timer > 0) {
                continue;
            }
            
            if (aircraft->aircraft && aircraft->health > 0) {
                aircraft_draw(aircraft->aircraft, game->world->time);
            }
            // Draw each aircraft's weapons
            if (aircraft->weapons) {
                weapons_draw(aircraft->weapons);
            }
        }
        
        if (game->boss_spawned && !game->boss_defeated) {
            cyber_dragon_draw(game->boss, game->camera);
            cyber_dragon_draw_effects(game->boss, game->camera);
        } else {
            enemies_draw(game->enemies);
        }
        
        effects_draw(game->effects, game->camera);
        
        // Draw planet surface grid that wraps
        // Draw main grid
        DrawGrid(40, 50);
        
        // Draw boundary markers
        DrawCubeWires((Vector3){0, -50, 0}, WORLD_SIZE, 100, WORLD_SIZE, DARKGREEN);
        
        // Draw compass markers at boundaries
        DrawCube((Vector3){WORLD_HALF_SIZE, 0, 0}, 10, 100, 10, RED);      // East
        DrawCube((Vector3){-WORLD_HALF_SIZE, 0, 0}, 10, 100, 10, RED);     // West
        DrawCube((Vector3){0, 0, WORLD_HALF_SIZE}, 10, 100, 10, BLUE);     // North
        DrawCube((Vector3){0, 0, -WORLD_HALF_SIZE}, 10, 100, 10, BLUE);    // South
        
        EndMode3D();
        
        EndTextureMode();
        
        // Post-processing
        BeginDrawing();
        
        // Draw screen buffer
        DrawTextureRec(screen_buffer.texture, 
                      (Rectangle){0, 0, screen_buffer.texture.width, -screen_buffer.texture.height},
                      (Vector2){0, 0}, WHITE);
        
        // Speed effects
        draw_speed_effects(game);
        
        // UI
        effects_draw_ui(game->effects, GetScreenWidth(), GetScreenHeight());
        draw_advanced_ui(game);
        
        // Victory/Game Over
        if (game->victory) {
            DrawText("VICTORY!", GetScreenWidth()/2 - 150, GetScreenHeight()/2 - 50, 60, GOLD);
            DrawText("You are a LEGEND!", GetScreenWidth()/2 - 120, GetScreenHeight()/2 + 20, 30, WHITE);
        } else if (game->game_over) {
            DrawText("GAME OVER", GetScreenWidth()/2 - 120, GetScreenHeight()/2 - 30, 50, RED);
        }
        
        EndDrawing();
    }
    
    // Cleanup
    UnloadRenderTexture(screen_buffer);
    CloseWindow();
    
    // Save high score
    printf("\n=== FINAL STATS ===\n");
    printf("Score: %d\n", game->score);
    printf("Rank: %d\n", game->rank);
    printf("Total Kills: %d\n", game->total_kills);
    printf("Max Combo: %d\n", game->max_combo);
    printf("Play Time: %.1f seconds\n", game->play_time);
    
    // Cleanup
    // PHASE 2: Manager handles aircraft cleanup
    aircraft_manager_destroy(game->aircraft_mgr);
    weapons_destroy(game->weapons);
    input_mvc_fast_destroy(game->input);
    enemies_destroy(game->enemies);
    cyberpunk_world_destroy(game->world);
    effects_destroy(game->effects);
    overdrive_destroy(game->overdrive);
    if (game->boss) cyber_dragon_destroy(game->boss);
    free(game);
    
    return 0;
}