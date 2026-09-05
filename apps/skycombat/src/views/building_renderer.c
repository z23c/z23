/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <raylib.h>
#include <raymath.h>
#include <stdlib.h>
#include "../../include/building_types.h"

/* Building colors based on type */
static Color get_building_color(building_type_t type) {
    switch (type) {
        case BUILDING_TOWER: return (Color){100, 100, 150, 255};
        case BUILDING_WAREHOUSE: return (Color){150, 120, 100, 255};
        case BUILDING_COMPLEX: return (Color){120, 140, 120, 255};
        case BUILDING_FORTRESS: return (Color){140, 100, 100, 255};
        default: return GRAY;
    }
}

void draw_building_interior(const game_building_t* building) {
    Vector3 position = {building->world_x, 0, building->world_z};
    
    /* Draw floors */
    for (uint32_t i = 0; i < building->spec.num_floors; i++) {
        float floor_y = building->spec.floor_heights[i];
        
        /* Floor plane */
        DrawCube(
            (Vector3){position.x + building->spec.width/2, floor_y, position.z + building->spec.depth/2},
            building->spec.width - 1.0f,
            FLOOR_THICKNESS,
            building->spec.depth - 1.0f,
            (Color){80, 80, 80, 200}
        );
        
        /* Floor marking - draw a number shape */
        DrawCube(
            (Vector3){position.x + 5.0f, floor_y + 0.05f, position.z + 5.0f},
            2.0f, 0.1f, 0.2f + i * 0.2f,
            WHITE
        );
    }
    
    /* Draw stairs between floors */
    for (uint32_t i = 0; i < building->spec.num_floors - 1; i++) {
        float bottom_y = building->spec.floor_heights[i];
        float top_y = building->spec.floor_heights[i + 1];
        float stair_height = top_y - bottom_y;
        
        /* Stairwell location */
        Vector3 stair_base = {
            position.x + building->spec.width * 0.8f,
            bottom_y,
            position.z + building->spec.depth * 0.8f
        };
        
        /* Draw stair steps */
        int num_steps = 10;
        for (int step = 0; step < num_steps; step++) {
            float step_progress = (float)step / num_steps;
            Vector3 step_pos = {
                stair_base.x - step_progress * 3.0f,
                stair_base.y + step_progress * stair_height,
                stair_base.z - step_progress * 3.0f
            };
            
            DrawCube(step_pos, 3.0f, 0.3f, 3.0f, (Color){60, 60, 60, 255});
        }
        
        /* Stair railings */
        DrawCylinder(stair_base, 0.05f, 0.05f, stair_height, 8, DARKGRAY);
        DrawCylinder(
            (Vector3){stair_base.x - 3.0f, stair_base.y, stair_base.z - 3.0f},
            0.05f, 0.05f, stair_height, 8, DARKGRAY
        );
    }
    
    /* Draw elevator shaft if building has one */
    if (building->has_elevator) {
        Vector3 elevator_base = {
            position.x + building->spec.width * 0.2f,
            0,
            position.z + building->spec.depth * 0.2f
        };
        
        /* Elevator shaft */
        DrawCubeWires(
            (Vector3){elevator_base.x, building->spec.height/2, elevator_base.z},
            4.0f, building->spec.height, 4.0f,
            DARKGRAY
        );
        
        /* Elevator car (animated) */
        float elevator_y = (sinf(GetTime() * 0.5f) + 1.0f) * 0.5f * (building->spec.height - 3.0f);
        DrawCube(
            (Vector3){elevator_base.x, elevator_y + 1.5f, elevator_base.z},
            3.5f, 3.0f, 3.5f,
            (Color){150, 150, 100, 255}
        );
    }
    
    /* Draw interior walls/rooms */
    for (uint32_t floor = 0; floor < building->spec.num_floors; floor++) {
        float floor_y = building->spec.floor_heights[floor];
        
        /* Room divisions (simple grid) */
        float room_width = building->spec.width / 2;
        float room_depth = building->spec.depth / 2;
        
        for (int rx = 0; rx < 2; rx++) {
            for (int rz = 0; rz < 2; rz++) {
                /* Skip elevator area */
                if (building->has_elevator && rx == 0 && rz == 0) continue;
                
                /* Interior walls */
                Vector3 wall_pos = {
                    position.x + rx * room_width + room_width/2,
                    floor_y + BUILDING_MIN_CEILING_HEIGHT/2,
                    position.z + rz * room_depth
                };
                
                /* Only draw some walls to allow movement */
                if (rand() % 100 < 70) {
                    DrawCube(wall_pos, room_width * 0.9f, BUILDING_MIN_CEILING_HEIGHT, 0.2f,
                            (Color){100, 100, 100, 100});
                }
            }
        }
    }
}

void draw_building_exterior(const game_building_t* building) {
    Vector3 position = {building->world_x, 0, building->world_z};
    Color base_color = get_building_color(building->type);
    
    /* Main building structure with transparency */
    DrawCubeWires(
        (Vector3){position.x + building->spec.width/2, building->spec.height/2, position.z + building->spec.depth/2},
        building->spec.width,
        building->spec.height,
        building->spec.depth,
        BLACK
    );
    
    /* Semi-transparent walls */
    Color transparent_color = base_color;
    transparent_color.a = 100;
    
    /* Front wall with entrance */
    DrawCube(
        (Vector3){position.x + building->spec.width/2, building->spec.height/2, position.z},
        building->spec.width, building->spec.height, 0.3f,
        transparent_color
    );
    
    /* Draw entrance */
    DrawCube(
        (Vector3){position.x + building->spec.width/2, 2.0f, position.z},
        4.0f, 4.0f, 0.5f,
        BLACK
    );
    
    /* Side walls */
    DrawCube(
        (Vector3){position.x, building->spec.height/2, position.z + building->spec.depth/2},
        0.3f, building->spec.height, building->spec.depth,
        transparent_color
    );
    DrawCube(
        (Vector3){position.x + building->spec.width, building->spec.height/2, position.z + building->spec.depth/2},
        0.3f, building->spec.height, building->spec.depth,
        transparent_color
    );
    
    /* Back wall */
    DrawCube(
        (Vector3){position.x + building->spec.width/2, building->spec.height/2, position.z + building->spec.depth},
        building->spec.width, building->spec.height, 0.3f,
        transparent_color
    );
    
    /* Windows */
    for (uint32_t floor = 0; floor < building->spec.num_floors; floor++) {
        float window_y = building->spec.floor_heights[floor] + BUILDING_MIN_CEILING_HEIGHT/2;
        
        for (int w = 0; w < 4; w++) {
            /* Front windows */
            DrawCube(
                (Vector3){position.x + 3.0f + w * 5.0f, window_y, position.z + 0.2f},
                2.0f, 1.5f, 0.2f,
                (Color){150, 150, 200, 200}
            );
            
            /* Side windows */
            DrawCube(
                (Vector3){position.x + 0.2f, window_y, position.z + 3.0f + w * 5.0f},
                0.2f, 1.5f, 2.0f,
                (Color){150, 150, 200, 200}
            );
        }
    }
    
    /* Rooftop features */
    if (building->has_rooftop_access) {
        /* Helipad */
        DrawCylinder(
            (Vector3){position.x + building->spec.width/2, building->spec.height + 0.1f, position.z + building->spec.depth/2},
            10.0f, 10.0f, 0.2f, 16,
            (Color){255, 255, 0, 100}
        );
        
        /* H marking */
        DrawCube(
            (Vector3){position.x + building->spec.width/2, building->spec.height + 0.2f, position.z + building->spec.depth/2},
            1.0f, 0.1f, 3.0f,
            WHITE
        );
    }
    
    /* Building type indicator */
    Vector3 sign_pos = {position.x + building->spec.width/2, building->spec.height + 2.0f, position.z + building->spec.depth/2};
    Color sign_color = WHITE;
    
    switch (building->type) {
        case BUILDING_TOWER:
            DrawCube(sign_pos, 2.0f, 4.0f, 2.0f, sign_color);
            break;
        case BUILDING_WAREHOUSE:
            DrawCube(sign_pos, 4.0f, 2.0f, 4.0f, sign_color);
            break;
        case BUILDING_COMPLEX:
            DrawSphere(sign_pos, 2.0f, sign_color);
            break;
        case BUILDING_FORTRESS:
            DrawCylinder(sign_pos, 2.0f, 2.0f, 3.0f, 8, sign_color);
            break;
    }
    
    /* Glowing effect for buildings with powerups */
    if (building->contains_powerup) {
        float glow = (sinf(GetTime() * 3.0f) + 1.0f) * 0.5f;
        DrawCubeWires(
            (Vector3){position.x + building->spec.width/2, building->spec.height/2, position.z + building->spec.depth/2},
            building->spec.width + glow * 2.0f,
            building->spec.height + glow * 2.0f,
            building->spec.depth + glow * 2.0f,
            (Color){255, 255, 0, (unsigned char)(glow * 100)}
        );
    }
}

void draw_city_ground() {
    /* Draw ground plane */
    DrawPlane((Vector3){0, 0, 0}, (Vector2){1000, 1000}, DARKGRAY);
    
    /* Grid lines for streets */
    float spacing = 100.0f;
    for (int i = -5; i <= 5; i++) {
        /* Streets running X direction */
        DrawCube(
            (Vector3){0, 0.01f, i * spacing},
            1000.0f, 0.02f, 10.0f,
            (Color){60, 60, 60, 255}
        );
        
        /* Streets running Z direction */
        DrawCube(
            (Vector3){i * spacing, 0.01f, 0},
            10.0f, 0.02f, 1000.0f,
            (Color){60, 60, 60, 255}
        );
        
        /* Street markings */
        for (int j = -50; j < 50; j++) {
            DrawCube(
                (Vector3){j * 10.0f, 0.02f, i * spacing},
                4.0f, 0.01f, 1.0f,
                YELLOW
            );
        }
    }
    
    /* Sidewalks */
    for (int i = -5; i <= 5; i++) {
        for (int j = -5; j <= 5; j++) {
            DrawCube(
                (Vector3){i * spacing - 45, 0.1f, j * spacing - 45},
                90.0f, 0.2f, 90.0f,
                (Color){100, 100, 100, 255}
            );
        }
    }
}