/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <raylib.h>
#include <raymath.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../specifications/3d_building_specs.h"

#define UNUSED __attribute__((unused))

#define MAX_AI_CHARACTERS 50
#define CHARACTER_THINK_TIME 2.0f

typedef enum {
    AI_STATE_WANDERING,
    AI_STATE_ENTERING_BUILDING,
    AI_STATE_IN_BUILDING,
    AI_STATE_CLIMBING_STAIRS,
    AI_STATE_EXITING_BUILDING
} ai_state_t;

typedef struct {
    character_state_t physics;
    ai_state_t ai_state;
    float think_timer;
    Vector3 target_position;
    int current_building_id;
    int target_floor;
    int current_floor;
    Color color;
    float animation_phase;
    bool active;
} ai_character_t;

static ai_character_t g_ai_characters[MAX_AI_CHARACTERS];
static int g_num_active_characters = 0;

void init_ai_characters(int count) {
    g_num_active_characters = (count > MAX_AI_CHARACTERS) ? MAX_AI_CHARACTERS : count;
    
    for (int i = 0; i < g_num_active_characters; i++) {
        ai_character_t* ai = &g_ai_characters[i];
        
        /* Random starting position */
        ai->physics.x = (float)(rand() % 400 - 200);
        ai->physics.y = 0.0f;
        ai->physics.z = (float)(rand() % 400 - 200);
        ai->physics.is_grounded = true;
        
        /* Random appearance */
        ai->color = (Color){
            rand() % 128 + 128,
            rand() % 128 + 128,
            rand() % 128 + 128,
            255
        };
        
        ai->ai_state = AI_STATE_WANDERING;
        ai->think_timer = (float)(rand() % 3);
        ai->current_building_id = -1;
        ai->active = true;
    }
    
    printf("Spawned %d AI characters\n", g_num_active_characters);
}

static void think_ai(ai_character_t* ai, void* buildings UNUSED, int building_count) {
    ai->think_timer -= GetFrameTime();
    if (ai->think_timer > 0) return;
    
    ai->think_timer = CHARACTER_THINK_TIME + (float)(rand() % 2);
    
    switch (ai->ai_state) {
        case AI_STATE_WANDERING: {
            /* 30% chance to enter a nearby building */
            if (rand() % 100 < 30 && building_count > 0) {
                /* Find nearest building */
                ai->current_building_id = rand() % building_count;
                ai->ai_state = AI_STATE_ENTERING_BUILDING;
                ai->target_floor = rand() % 3;  /* Go to random floor */
            } else {
                /* Wander to random location */
                ai->target_position.x = ai->physics.x + (float)(rand() % 60 - 30);
                ai->target_position.z = ai->physics.z + (float)(rand() % 60 - 30);
            }
            break;
        }
        
        case AI_STATE_IN_BUILDING: {
            /* 50% chance to go to different floor */
            if (rand() % 100 < 50) {
                ai->target_floor = rand() % 5;
                if (ai->target_floor != ai->current_floor) {
                    ai->ai_state = AI_STATE_CLIMBING_STAIRS;
                }
            } else if (rand() % 100 < 30) {
                /* Exit building */
                ai->ai_state = AI_STATE_EXITING_BUILDING;
            } else {
                /* Wander within building */
                ai->target_position.x = ai->physics.x + (float)(rand() % 10 - 5);
                ai->target_position.z = ai->physics.z + (float)(rand() % 10 - 5);
            }
            break;
        }
        
        case AI_STATE_CLIMBING_STAIRS: {
            /* Continue climbing */
            break;
        }
        
        default:
            break;
    }
}

static void move_ai(ai_character_t* ai) {
    Vector3 current = {ai->physics.x, ai->physics.y, ai->physics.z};
    Vector3 target = ai->target_position;
    
    /* Only move horizontally */
    target.y = current.y;
    
    Vector3 direction = Vector3Subtract(target, current);
    float distance = Vector3Length(direction);
    
    if (distance > 0.5f) {
        direction = Vector3Normalize(direction);
        float speed = (ai->ai_state == AI_STATE_IN_BUILDING) ? PLAYER_WALK_SPEED : PLAYER_RUN_SPEED;
        
        ai->physics.vx = direction.x * speed;
        ai->physics.vz = direction.z * speed;
        
        /* Update position */
        ai->physics.x += ai->physics.vx * GetFrameTime();
        ai->physics.z += ai->physics.vz * GetFrameTime();
        
        /* Animation */
        ai->animation_phase += speed * GetFrameTime() * 0.5f;
    } else {
        ai->physics.vx = 0;
        ai->physics.vz = 0;
    }
    
    /* Random jumping when wandering */
    if (ai->ai_state == AI_STATE_WANDERING && ai->physics.is_grounded) {
        if (rand() % 1000 < 5) {  /* 0.5% chance per frame */
            ai->physics.is_jumping = true;
            ai->physics.jump_charge = 0.5f + (float)(rand() % 50) / 100.0f;
        }
    }
    
    /* Apply jump physics */
    if (ai->physics.is_jumping || !ai->physics.is_grounded) {
        calculate_jump_physics(&ai->physics, GetFrameTime());
    }
    
    /* Ground check */
    if (ai->physics.y <= 0 && ai->physics.vy <= 0) {
        ai->physics.y = 0;
        ai->physics.vy = 0;
        ai->physics.is_grounded = true;
        ai->physics.is_jumping = false;
    }
}

void update_ai_characters(void* buildings, int building_count) {
    for (int i = 0; i < g_num_active_characters; i++) {
        ai_character_t* ai = &g_ai_characters[i];
        if (!ai->active) continue;
        
        think_ai(ai, buildings, building_count);
        move_ai(ai);
        
        /* State-specific updates */
        switch (ai->ai_state) {
            case AI_STATE_CLIMBING_STAIRS: {
                /* Simulate climbing */
                float target_y = ai->target_floor * 4.0f;  /* 4 units per floor */
                if (ai->physics.y < target_y) {
                    ai->physics.y += PLAYER_CLIMB_SPEED * GetFrameTime();
                    if (ai->physics.y >= target_y) {
                        ai->physics.y = target_y;
                        ai->current_floor = ai->target_floor;
                        ai->ai_state = AI_STATE_IN_BUILDING;
                    }
                }
                break;
            }
            
            case AI_STATE_EXITING_BUILDING: {
                /* Move to ground floor */
                if (ai->physics.y > 0) {
                    ai->physics.y -= PLAYER_CLIMB_SPEED * GetFrameTime();
                } else {
                    ai->physics.y = 0;
                    ai->current_building_id = -1;
                    ai->ai_state = AI_STATE_WANDERING;
                    /* Set target outside */
                    ai->target_position.x = ai->physics.x + (float)(rand() % 40 - 20);
                    ai->target_position.z = ai->physics.z + (float)(rand() % 40 - 20);
                }
                break;
            }
        }
    }
}

void draw_ai_characters() {
    for (int i = 0; i < g_num_active_characters; i++) {
        ai_character_t* ai = &g_ai_characters[i];
        if (!ai->active) continue;
        
        Vector3 position = {ai->physics.x, ai->physics.y + PLAYER_HEIGHT/2, ai->physics.z};
        
        /* Draw body */
        DrawCapsule(position, position, PLAYER_RADIUS, 8, 8, ai->color);
        
        /* Draw state indicator */
        Vector3 indicator_pos = {position.x, position.y + PLAYER_HEIGHT, position.z};
        Color indicator_color = WHITE;
        
        switch (ai->ai_state) {
            case AI_STATE_WANDERING:
                indicator_color = GREEN;
                break;
            case AI_STATE_ENTERING_BUILDING:
                indicator_color = YELLOW;
                break;
            case AI_STATE_IN_BUILDING:
                indicator_color = BLUE;
                break;
            case AI_STATE_CLIMBING_STAIRS:
                indicator_color = ORANGE;
                break;
            case AI_STATE_EXITING_BUILDING:
                indicator_color = PURPLE;
                break;
        }
        
        /* Draw state sphere above head */
        DrawSphere(indicator_pos, 0.3f, indicator_color);
        
        /* Draw jumping shadow */
        if (ai->physics.is_jumping || !ai->physics.is_grounded) {
            Vector3 shadow = {ai->physics.x, 0.01f, ai->physics.z};
            DrawCylinder(shadow, PLAYER_RADIUS * 1.5f, PLAYER_RADIUS * 1.5f, 0.01f, 8, BLACK);
        }
        
        /* Animated legs when moving */
        if (Vector3Length((Vector3){ai->physics.vx, 0, ai->physics.vz}) > 0.1f) {
            float leg_offset = sinf(ai->animation_phase) * 0.3f;
            Vector3 leg1 = {position.x + leg_offset, position.y - PLAYER_HEIGHT/2, position.z};
            Vector3 leg2 = {position.x - leg_offset, position.y - PLAYER_HEIGHT/2, position.z};
            DrawSphere(leg1, 0.2f, ai->color);
            DrawSphere(leg2, 0.2f, ai->color);
        }
    }
}

void draw_ai_character_labels(Camera3D camera) {
    for (int i = 0; i < g_num_active_characters; i++) {
        ai_character_t* ai = &g_ai_characters[i];
        if (!ai->active) continue;
        
        Vector3 position = {ai->physics.x, ai->physics.y + PLAYER_HEIGHT + 1.0f, ai->physics.z};
        Vector2 screen_pos = GetWorldToScreen(position, camera);
        
        if (screen_pos.x > 0 && screen_pos.x < GetScreenWidth() &&
            screen_pos.y > 0 && screen_pos.y < GetScreenHeight()) {
            
            const char* state_text = "";
            switch (ai->ai_state) {
                case AI_STATE_WANDERING: state_text = "Wandering"; break;
                case AI_STATE_IN_BUILDING: state_text = TextFormat("Floor %d", ai->current_floor); break;
                case AI_STATE_CLIMBING_STAIRS: state_text = "Climbing"; break;
                default: break;
            }
            
            DrawText(state_text, (int)screen_pos.x - 30, (int)screen_pos.y, 14, WHITE);
        }
    }
}