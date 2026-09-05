/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/cyberpunk_world.h"
#include <raymath.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define MAX_WORLD_ELEMENTS 1000
#define MAX_PARTICLES 5000

cyberpunk_world_t* cyberpunk_world_create(void) {
    cyberpunk_world_t* world = calloc(1, sizeof(cyberpunk_world_t));
    if (!world) return NULL;
    
    world->elements = calloc(MAX_WORLD_ELEMENTS, sizeof(world_element_t));
    if (!world->elements) {
        free(world);
        return NULL;
    }
    world->max_elements = MAX_WORLD_ELEMENTS;
    
    world->particle_positions = calloc(MAX_PARTICLES, sizeof(Vector3));
    if (!world->particle_positions) {
        free(world->elements);
        free(world);
        return NULL;
    }
    
    world->particle_velocities = calloc(MAX_PARTICLES, sizeof(Vector3));
    if (!world->particle_velocities) {
        free(world->particle_positions);
        free(world->elements);
        free(world);
        return NULL;
    }
    
    world->particle_colors = calloc(MAX_PARTICLES, sizeof(Color));
    if (!world->particle_colors) {
        free(world->particle_velocities);
        free(world->particle_positions);
        free(world->elements);
        free(world);
        return NULL;
    }
    world->particle_count = 0;
    
    // Default cyberpunk atmosphere
    world->sky_gradient_top = (Color){10, 0, 30, 255};      // Deep purple
    world->sky_gradient_bottom = (Color){50, 0, 80, 255};   // Lighter purple
    world->fog_color = (Color){20, 0, 40, 100};
    world->fog_density = 0.02f;
    world->ambient_light = (Color){40, 20, 60, 255};
    world->sun_direction = Vector3Normalize((Vector3){0.3f, -0.5f, 0.7f});
    world->global_glow = 1.0f;
    
    return world;
}

void cyberpunk_world_destroy(cyberpunk_world_t* world) {
    if (!world) return;
    free(world->elements);
    free(world->particle_positions);
    free(world->particle_velocities);
    free(world->particle_colors);
    free(world);
}

void cyberpunk_world_generate(cyberpunk_world_t* world, int seed) {
    if (!world) return;
    
    srand(seed);
    world->element_count = 0;
    
    // Generate city grid within world boundaries
    int grid_size = 16;  // Reduced to fit in 2000x2000 world
    float spacing = 120.0f;
    
    for (int x = -grid_size/2; x < grid_size/2; x++) {
        for (int z = -grid_size/2; z < grid_size/2; z++) {
            // Random chance for building
            if (rand() % 100 < 70) {
                float height = 50 + (rand() % 200);
                Vector3 pos = {x * spacing, height/2, z * spacing};
                cyberpunk_spawn_building(world, pos, height);
                
                // Add hologram on tall buildings
                if (height > 150 && rand() % 100 < 30) {
                    Vector3 holo_pos = pos;
                    holo_pos.y = height + 20;
                    cyberpunk_spawn_hologram(world, holo_pos, "CYBER");
                }
            }
            
            // Floating platforms
            if (rand() % 100 < 20) {
                Vector3 plat_pos = {
                    x * spacing + (rand() % 50) - 25,
                    50 + rand() % 100,
                    z * spacing + (rand() % 50) - 25
                };
                world_element_t* platform = &world->elements[world->element_count++];
                platform->type = WORLD_FLOATING_PLATFORM;
                platform->position = plat_pos;
                platform->scale = (Vector3){20, 2, 20};
                platform->primary_color = SKYBLUE;
                platform->emission_color = (Color){100, 200, 255, 255};
                platform->glow_intensity = 2.0f;
                platform->pulse_speed = 0.5f;
                platform->is_interactive = true;
            }
        }
    }
    
    // Add energy rings (racing checkpoints) within bounds
    for (int i = 0; i < 20; i++) {
        Vector3 ring_pos = {
            (rand() % 1600) - 800,  // Keep within ±800 units
            50 + (rand() % 150),
            (rand() % 1600) - 800
        };
        cyberpunk_spawn_energy_ring(world, ring_pos, 15.0f);
    }
    
    // Add laser grids (hazards) within bounds
    for (int i = 0; i < 10; i++) {
        Vector3 start = {
            (rand() % 1200) - 600,  // Keep within ±600 units
            20 + (rand() % 100),
            (rand() % 1200) - 600
        };
        Vector3 end = start;
        end.x += (rand() % 100) - 50;
        end.y += (rand() % 50) - 25;
        cyberpunk_spawn_laser_grid(world, start, end);
    }
    
    // Initialize data rain particles
    cyberpunk_create_data_rain(world);
}

void cyberpunk_spawn_building(cyberpunk_world_t* world, Vector3 pos, float height) {
    if (!world || !world->elements || world->element_count >= world->max_elements) return;
    
    world_element_t* building = &world->elements[world->element_count++];
    building->type = WORLD_NEON_BUILDING;
    building->position = pos;
    building->scale = (Vector3){30 + rand() % 20, height, 30 + rand() % 20};
    
    // Neon colors
    int color_scheme = rand() % 4;
    switch (color_scheme) {
        case 0:  // Cyan
            building->primary_color = (Color){0, 100, 120, 255};
            building->emission_color = (Color){0, 255, 255, 255};
            break;
        case 1:  // Magenta
            building->primary_color = (Color){120, 0, 100, 255};
            building->emission_color = (Color){255, 0, 255, 255};
            break;
        case 2:  // Yellow
            building->primary_color = (Color){120, 100, 0, 255};
            building->emission_color = (Color){255, 255, 0, 255};
            break;
        case 3:  // Green
            building->primary_color = (Color){0, 120, 50, 255};
            building->emission_color = (Color){0, 255, 100, 255};
            break;
    }
    
    building->glow_intensity = 0.5f + (float)(rand() % 100) / 100.0f;
    building->neon_flicker = (float)(rand() % 100) / 100.0f;
    building->pulse_speed = 0.1f + (float)(rand() % 20) / 100.0f;
}

void cyberpunk_spawn_hologram(cyberpunk_world_t* world, Vector3 pos, const char* text) {
    if (!world || !world->elements || world->element_count >= world->max_elements) return;
    
    world_element_t* hologram = &world->elements[world->element_count++];
    hologram->type = WORLD_HOLOGRAM;
    hologram->position = pos;
    hologram->scale = (Vector3){40, 20, 1};
    hologram->primary_color = (Color){100, 200, 255, 100};
    hologram->emission_color = (Color){150, 255, 255, 255};
    hologram->glow_intensity = 3.0f;
    hologram->animation_time = (float)(rand() % 100) / 10.0f;
    hologram->has_trail = true;
}

void cyberpunk_spawn_energy_ring(cyberpunk_world_t* world, Vector3 pos, float radius) {
    if (!world || !world->elements || world->element_count >= world->max_elements) return;
    
    world_element_t* ring = &world->elements[world->element_count++];
    ring->type = WORLD_ENERGY_RING;
    ring->position = pos;
    ring->scale = (Vector3){radius, radius, 2};
    ring->primary_color = (Color){0, 255, 200, 150};
    ring->emission_color = (Color){0, 255, 255, 255};
    ring->glow_intensity = 4.0f;
    ring->pulse_speed = 2.0f;
    ring->is_interactive = true;
    ring->gives_powerup = true;
    ring->effect_radius = radius * 1.5f;
}

void cyberpunk_spawn_laser_grid(cyberpunk_world_t* world, Vector3 start, Vector3 end) {
    if (!world || !world->elements || world->element_count >= world->max_elements) return;
    
    world_element_t* laser = &world->elements[world->element_count++];
    laser->type = WORLD_LASER_GRID;
    laser->position = Vector3Lerp(start, end, 0.5f);
    laser->scale = (Vector3){
        Vector3Distance(start, end),
        0.5f,
        0.5f
    };
    laser->rotation = Vector3Subtract(end, start);
    laser->primary_color = RED;
    laser->emission_color = (Color){255, 100, 100, 255};
    laser->glow_intensity = 5.0f;
    laser->is_hazard = true;
    laser->animation_time = (float)(rand() % 100) / 10.0f;
}

void cyberpunk_world_update(cyberpunk_world_t* world, float dt) {
    if (!world) return;
    
    world->time += dt;
    
    // Update elements
    for (int i = 0; i < world->element_count; i++) {
        world_element_t* elem = &world->elements[i];
        elem->animation_time += dt;
        
        // Animate based on type
        switch (elem->type) {
            case WORLD_NEON_BUILDING:
                // Neon flicker
                if (elem->neon_flicker > 0) {
                    float flicker = sinf(elem->animation_time * 20) * 0.5f + 0.5f;
                    elem->glow_intensity = 0.5f + flicker * elem->neon_flicker;
                }
                break;
                
            case WORLD_HOLOGRAM:
                // Floating animation
                elem->position.y += sinf(elem->animation_time * 2) * 0.1f;
                elem->rotation.y = elem->animation_time * 0.5f;
                break;
                
            case WORLD_ENERGY_RING:
                // Pulsing glow
                elem->glow_intensity = 3.0f + sinf(elem->animation_time * elem->pulse_speed) * 2.0f;
                elem->rotation.z = elem->animation_time;
                break;
                
            case WORLD_LASER_GRID:
                // Dangerous pulsing
                elem->glow_intensity = 4.0f + sinf(elem->animation_time * 5) * 2.0f;
                break;
                
            case WORLD_FLOATING_PLATFORM:
                // Gentle bobbing
                elem->position.y += sinf(elem->animation_time * elem->pulse_speed) * 0.5f;
                break;
        }
        
        // Update trails
        if (elem->has_trail) {
            // Shift trail positions
            for (int j = 9; j > 0; j--) {
                elem->trail_positions[j] = elem->trail_positions[j-1];
            }
            elem->trail_positions[0] = elem->position;
        }
    }
    
    // Update particles (data rain)
    if (world->particle_positions && world->particle_velocities) {
        for (int i = 0; i < world->particle_count; i++) {
            world->particle_positions[i] = Vector3Add(
                world->particle_positions[i],
                Vector3Scale(world->particle_velocities[i], dt)
            );
        
        // Reset particles that fall too low
        if (world->particle_positions[i].y < -50) {
            world->particle_positions[i].y = 300;
            world->particle_positions[i].x = (rand() % 2000) - 1000;
            world->particle_positions[i].z = (rand() % 2000) - 1000;
        }
    }
    
    // Global effects
    world->global_glow = 1.0f + sinf(world->time * 0.2f) * 0.1f;
    }
}

void cyberpunk_world_draw(cyberpunk_world_t* world, Camera3D camera) {
    if (!world) return;
    
    // Draw skybox first
    cyberpunk_world_draw_skybox(world);
    
    // Sort elements by distance for transparency
    // (simplified - just draw in order for now)
    
    for (int i = 0; i < world->element_count; i++) {
        world_element_t* elem = &world->elements[i];
        
        // Skip if too far (simple frustum culling)
        float distance = Vector3Distance(elem->position, camera.position);
        if (distance > 1000) continue;
        
        // Apply glow
        Color glow_color = elem->emission_color;
        glow_color.a = (unsigned char)(elem->glow_intensity * world->global_glow * 50);
        
        switch (elem->type) {
            case WORLD_NEON_BUILDING:
                // Building base
                DrawCube(elem->position, elem->scale.x, elem->scale.y, elem->scale.z, elem->primary_color);
                DrawCubeWires(elem->position, elem->scale.x, elem->scale.y, elem->scale.z, elem->emission_color);
                
                // Neon strips on sides
                for (int j = 0; j < 4; j++) {
                    float strip_y = elem->position.y - elem->scale.y/2 + (elem->scale.y/4) * j;
                    Vector3 strip_pos = {elem->position.x, strip_y, elem->position.z};
                    DrawCube(strip_pos, elem->scale.x + 1, 2, elem->scale.z + 1, glow_color);
                }
                break;
                
            case WORLD_HOLOGRAM:
                // Holographic billboard - draw as wireframe cube instead
                DrawCubeWires(elem->position, elem->scale.x, elem->scale.y, elem->scale.z, elem->emission_color);
                
                // Glitch effect
                if (fmodf(elem->animation_time, 3.0f) < 0.1f) {
                    Vector3 glitch_pos = elem->position;
                    glitch_pos.x += (rand() % 10) - 5;
                    DrawCubeWires(glitch_pos, elem->scale.x * 1.1f, elem->scale.y * 1.1f, elem->scale.z * 1.1f, RED);
                }
                break;
                
            case WORLD_ENERGY_RING:
                // Rotating energy ring (using circle as torus not available)
                DrawCircle3D(elem->position, elem->scale.x, (Vector3){1, 0, 0}, 0, elem->primary_color);
                DrawCircle3D(elem->position, elem->scale.x, (Vector3){0, 1, 0}, 0, elem->primary_color);
                DrawCircle3D(elem->position, elem->scale.x, (Vector3){0, 0, 1}, 0, elem->emission_color);
                
                // Energy particles
                for (int j = 0; j < 8; j++) {
                    float angle = elem->animation_time * 2 + (j * PI / 4);
                    Vector3 particle_pos = {
                        elem->position.x + cosf(angle) * elem->scale.x,
                        elem->position.y,
                        elem->position.z + sinf(angle) * elem->scale.x
                    };
                    DrawSphere(particle_pos, 1.0f, elem->emission_color);
                }
                break;
                
            case WORLD_LASER_GRID:
                // Deadly laser beams
                DrawCylinder(elem->position, 0.5f, 0.5f, elem->scale.x, 8, elem->emission_color);
                
                // Warning glow
                DrawCylinder(elem->position, 2.0f, 2.0f, elem->scale.x, 8, glow_color);
                break;
                
            case WORLD_FLOATING_PLATFORM:
                // Anti-gravity platform
                DrawCube(elem->position, elem->scale.x, elem->scale.y, elem->scale.z, elem->primary_color);
                
                // Energy field underneath
                Vector3 field_pos = elem->position;
                field_pos.y -= elem->scale.y;
                DrawCylinder(field_pos, elem->scale.x/2, elem->scale.x/2, 5.0f, 16, glow_color);
                break;
        }
    }
    
    // Draw particles (data rain)
    BeginBlendMode(BLEND_ADDITIVE);
    if (world->particle_positions && world->particle_colors) {
        for (int i = 0; i < world->particle_count; i++) {
            DrawCube(world->particle_positions[i], 0.5f, 2.0f, 0.5f, world->particle_colors[i]);
        }
    }
    EndBlendMode();
}

void cyberpunk_world_draw_skybox(cyberpunk_world_t* world) {
    if (!world) return;
    
    // Draw gradient background
    DrawRectangleGradientV(0, 0, GetScreenWidth(), GetScreenHeight()/2, 
                           world->sky_gradient_top, world->sky_gradient_bottom);
    DrawRectangleGradientV(0, GetScreenHeight()/2, GetScreenWidth(), GetScreenHeight()/2,
                           world->sky_gradient_bottom, BLACK);
    
    // Draw distant city lights
    for (int i = 0; i < 100; i++) {
        int x = (i * 37) % GetScreenWidth();
        int y = GetScreenHeight()/2 + (i * 23) % (GetScreenHeight()/4);
        int size = 1 + (i % 3);
        Color light_color = (Color){
            200 + (i % 55),
            100 + (i % 100),
            255,
            100 + (i % 155)
        };
        DrawRectangle(x, y, size, size, light_color);
    }
}

void cyberpunk_create_data_rain(cyberpunk_world_t* world) {
    if (!world || !world->particle_positions || !world->particle_velocities || !world->particle_colors) return;
    
    world->particle_count = 1000;  // Start with 1000 particles
    
    for (int i = 0; i < world->particle_count; i++) {
        world->particle_positions[i] = (Vector3){
            (rand() % 2000) - 1000,
            (rand() % 300),
            (rand() % 2000) - 1000
        };
        
        world->particle_velocities[i] = (Vector3){
            0,
            -20.0f - (rand() % 30),  // Falling speed
            0
        };
        
        // Matrix-style green
        int green = 100 + (rand() % 155);
        world->particle_colors[i] = (Color){0, green, 50, 200};
    }
}

void cyberpunk_set_theme_tron(cyberpunk_world_t* world) {
    if (!world) return;
    
    world->sky_gradient_top = BLACK;
    world->sky_gradient_bottom = (Color){0, 20, 40, 255};
    world->fog_color = (Color){0, 50, 100, 50};
    world->ambient_light = (Color){0, 100, 200, 255};
    
    // Update all elements to Tron colors
    if (world->elements) {
        for (int i = 0; i < world->element_count; i++) {
            world_element_t* elem = &world->elements[i];
            if (elem->type == WORLD_NEON_BUILDING) {
                elem->primary_color = (Color){10, 10, 10, 255};
                elem->emission_color = (Color){0, 200, 255, 255};
            }
        }
    }
}

void cyberpunk_set_theme_blade_runner(cyberpunk_world_t* world) {
    if (!world) return;
    
    world->sky_gradient_top = (Color){20, 10, 10, 255};
    world->sky_gradient_bottom = (Color){50, 30, 20, 255};
    world->fog_color = (Color){80, 60, 40, 100};
    world->fog_density = 0.05f;  // Heavy fog
    world->ambient_light = (Color){100, 80, 60, 255};
    world->is_raining_data = true;
}