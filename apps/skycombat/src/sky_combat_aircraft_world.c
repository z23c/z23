/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <raylib.h>
#include <raymath.h>
#include <rlgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

/* Include our systems */
#include "../include/building_types.h"
#include "../specifications/3d_building_specs.h"
#include "../specifications/joystick_control_specs.h"
#include "controllers/aircraft_input_controller.c"
#include "models/ai_characters.c"
#include "views/building_renderer.c"

/* Forward declarations */
game_building_t* create_building(int type, float x, float z);
void generate_city_block(game_building_t** buildings, int* count);

#define WINDOW_WIDTH 1280
#define WINDOW_HEIGHT 720
#define TARGET_FPS 60

/* Aircraft state */
typedef struct {
    Vector3 position;
    Vector3 velocity;
    Vector3 rotation;  /* pitch, yaw, roll */
    float throttle;
    bool afterburner;
    bool landing_gear;
    float health;
    int ammo;
} aircraft_t;

/* Game state */
typedef struct {
    aircraft_t player_aircraft;
    Camera3D camera;
    game_building_t* buildings;
    int building_count;
    float time_of_day;
    bool show_help;
    bool show_debug;
    bool paused;
} game_state_t;

static game_state_t g_game = {0};

/* Initialize aircraft */
void init_aircraft() {
    g_game.player_aircraft.position = (Vector3){0, 150.0f, -200.0f};
    g_game.player_aircraft.velocity = (Vector3){0, 0, 50.0f};
    g_game.player_aircraft.rotation = (Vector3){0, 0, 0};
    g_game.player_aircraft.throttle = 0.5f;
    g_game.player_aircraft.health = 100.0f;
    g_game.player_aircraft.ammo = 1000;
    g_game.player_aircraft.landing_gear = false;
    
    /* Setup camera behind aircraft */
    g_game.camera.position = (Vector3){0, 180.0f, -250.0f};
    g_game.camera.target = g_game.player_aircraft.position;
    g_game.camera.up = (Vector3){0, 1, 0};
    g_game.camera.fovy = 60.0f;
    g_game.camera.projection = CAMERA_PERSPECTIVE;
}

/* Update aircraft physics */
void update_aircraft(float delta) {
    aircraft_t* aircraft = &g_game.player_aircraft;
    
    /* Apply input from MVC controller */
    aircraft_input_controller_apply_to_aircraft(
        &aircraft->position,
        &aircraft->rotation,
        &aircraft->throttle,
        &aircraft->afterburner,
        &aircraft->landing_gear,
        delta
    );
    
    /* Clamp rotations */
    aircraft->rotation.x = Clamp(aircraft->rotation.x, -80.0f, 80.0f);
    if (aircraft->rotation.z > 180.0f) aircraft->rotation.z -= 360.0f;
    if (aircraft->rotation.z < -180.0f) aircraft->rotation.z += 360.0f;
    
    /* Calculate forward vector based on rotation */
    float pitch = aircraft->rotation.x * DEG2RAD;
    float yaw = aircraft->rotation.y * DEG2RAD;
    
    Vector3 forward = {
        sinf(yaw) * cosf(pitch),
        -sinf(pitch),
        cosf(yaw) * cosf(pitch)
    };
    
    /* Apply thrust */
    float speed = 100.0f + aircraft->throttle * 200.0f + (aircraft->afterburner ? 100.0f : 0.0f);
    aircraft->velocity = Vector3Scale(forward, speed);
    
    /* Update position */
    aircraft->position = Vector3Add(aircraft->position, Vector3Scale(aircraft->velocity, delta));
    
    /* Keep above ground */
    float ground_height = aircraft->landing_gear ? 2.0f : 50.0f;
    if (aircraft->position.y < ground_height) {
        aircraft->position.y = ground_height;
        if (aircraft->landing_gear && Vector3Length(aircraft->velocity) < 50.0f) {
            /* Landed */
            aircraft->velocity = Vector3Scale(aircraft->velocity, 0.9f);
        }
    }
    
    /* Update camera to follow aircraft */
    Vector3 camera_offset = {
        -sinf(yaw) * 50.0f,
        20.0f,
        -cosf(yaw) * 50.0f
    };
    
    g_game.camera.position = Vector3Add(aircraft->position, camera_offset);
    g_game.camera.target = aircraft->position;
    
    /* Banking effect */
    g_game.camera.up = (Vector3){
        sinf(aircraft->rotation.z * DEG2RAD * 0.3f),
        cosf(aircraft->rotation.z * DEG2RAD * 0.3f),
        0
    };
}

/* Draw aircraft model */
void draw_aircraft(const aircraft_t* aircraft) {
    /* Save transform */
    rlPushMatrix();
    
    /* Position and rotate */
    rlTranslatef(aircraft->position.x, aircraft->position.y, aircraft->position.z);
    rlRotatef(aircraft->rotation.y, 0, 1, 0);
    rlRotatef(aircraft->rotation.x, 1, 0, 0);
    rlRotatef(aircraft->rotation.z, 0, 0, 1);
    
    /* Fuselage */
    DrawCube((Vector3){0, 0, 0}, 2.0f, 1.0f, 8.0f, DARKGRAY);
    
    /* Cockpit */
    DrawCube((Vector3){0, 0.5f, 2.0f}, 1.5f, 1.0f, 2.0f, SKYBLUE);
    
    /* Wings */
    DrawCube((Vector3){0, 0, 0}, 12.0f, 0.2f, 3.0f, GRAY);
    
    /* Tail */
    DrawCube((Vector3){0, 2.0f, -3.5f}, 0.2f, 3.0f, 2.0f, GRAY);
    DrawCube((Vector3){0, 0, -3.5f}, 3.0f, 0.2f, 2.0f, GRAY);
    
    /* Engines */
    DrawCylinder((Vector3){2.0f, -0.5f, -2.0f}, 0.5f, 0.5f, 3.0f, 8, DARKGRAY);
    DrawCylinder((Vector3){-2.0f, -0.5f, -2.0f}, 0.5f, 0.5f, 3.0f, 8, DARKGRAY);
    
    /* Afterburner effect */
    if (aircraft->afterburner) {
        DrawCylinder((Vector3){2.0f, -0.5f, -4.0f}, 0.3f, 0.6f, 2.0f, 6, ORANGE);
        DrawCylinder((Vector3){-2.0f, -0.5f, -4.0f}, 0.3f, 0.6f, 2.0f, 6, ORANGE);
    }
    
    /* Landing gear */
    if (aircraft->landing_gear) {
        DrawCylinder((Vector3){0, -1.5f, 2.0f}, 0.2f, 0.2f, 1.5f, 4, BLACK);
        DrawCylinder((Vector3){2.0f, -1.5f, -1.0f}, 0.2f, 0.2f, 1.5f, 4, BLACK);
        DrawCylinder((Vector3){-2.0f, -1.5f, -1.0f}, 0.2f, 0.2f, 1.5f, 4, BLACK);
    }
    
    rlPopMatrix();
}

/* Draw HUD */
void draw_aircraft_hud() {
    const aircraft_t* aircraft = &g_game.player_aircraft;
    
    /* Speed indicator */
    float speed = Vector3Length(aircraft->velocity);
    DrawText(TextFormat("SPEED: %.0f", speed), 10, 10, 20, GREEN);
    DrawText(TextFormat("ALT: %.0f", aircraft->position.y), 10, 40, 20, GREEN);
    
    /* Throttle bar */
    DrawRectangle(10, 70, 20, 100, DARKGRAY);
    DrawRectangle(10, 170 - (int)(aircraft->throttle * 100), 20, (int)(aircraft->throttle * 100), GREEN);
    DrawText("THR", 10, 175, 10, WHITE);
    
    /* Health bar */
    DrawRectangle(10, 200, 100, 20, DARKGRAY);
    DrawRectangle(10, 200, (int)aircraft->health, 20, RED);
    DrawText("HEALTH", 10, 225, 10, WHITE);
    
    /* Ammo counter */
    DrawText(TextFormat("AMMO: %d", aircraft->ammo), 10, 250, 16, YELLOW);
    
    /* Landing gear indicator */
    if (aircraft->landing_gear) {
        DrawText("GEAR DOWN", 10, 280, 16, ORANGE);
    }
    
    /* Afterburner indicator */
    if (aircraft->afterburner) {
        DrawText("AFTERBURNER", GetScreenWidth()/2 - 60, GetScreenHeight() - 50, 20, ORANGE);
    }
    
    /* Crosshair */
    int cx = GetScreenWidth() / 2;
    int cy = GetScreenHeight() / 2;
    DrawCircle(cx, cy, 20, Fade(GREEN, 0.3f));
    DrawLine(cx - 30, cy, cx - 10, cy, GREEN);
    DrawLine(cx + 10, cy, cx + 30, cy, GREEN);
    DrawLine(cx, cy - 30, cx, cy - 10, GREEN);
    DrawLine(cx, cy + 10, cx, cy + 30, GREEN);
    
    /* Altitude warning */
    if (aircraft->position.y < 100.0f && !aircraft->landing_gear) {
        DrawText("LOW ALTITUDE", GetScreenWidth()/2 - 80, 100, 24, RED);
    }
    
}

/* Initialize game */
void init_game() {
    srand(time(NULL));
    
    /* Initialize aircraft */
    init_aircraft();
    
    /* Create city */
    generate_city_block(&g_game.buildings, &g_game.building_count);
    
    /* Spawn AI characters on ground */
    init_ai_characters(50);  /* More characters visible from air */
    
    /* Start at noon */
    g_game.time_of_day = 12.0f;
    g_game.show_help = true;
}

/* Update game */
void update_game() {
    if (IsKeyPressed(KEY_F1)) g_game.show_help = !g_game.show_help;
    if (IsKeyPressed(KEY_F2)) g_game.show_debug = !g_game.show_debug;
    if (IsKeyPressed(KEY_P)) g_game.paused = !g_game.paused;
    
    if (g_game.paused) return;
    
    float delta = GetFrameTime();
    
    /* Update time */
    g_game.time_of_day += delta * 0.5f;
    if (g_game.time_of_day >= 24.0f) g_game.time_of_day -= 24.0f;
    
    /* Update input controller */
    aircraft_input_controller_update();
    
    /* Update aircraft */
    update_aircraft(delta);
    
    /* Update AI characters on ground */
    update_ai_characters(g_game.buildings, g_game.building_count);
    
    /* Weapon firing from controller */
    static float fire_cooldown = 0;
    fire_cooldown -= delta;
    
    bool fire_primary, fire_secondary;
    aircraft_input_controller_get_weapons(&fire_primary, &fire_secondary);
    
    if (fire_primary && fire_cooldown <= 0 && g_game.player_aircraft.ammo > 0) {
        g_game.player_aircraft.ammo--;
        fire_cooldown = 0.1f;
        /* Primary weapon effects */
    }
    
    if (fire_secondary && g_game.player_aircraft.ammo > 0) {
        g_game.player_aircraft.ammo -= 2;
        /* Secondary weapon effects */
    }
}

/* Draw game */
void draw_game() {
    /* Sky color based on time */
    float sun_angle = (g_game.time_of_day - 6.0f) / 12.0f * PI;
    float brightness = fmaxf(0, cosf(sun_angle));
    Color sky_color = (Color){
        (unsigned char)(135 * brightness),
        (unsigned char)(206 * brightness),
        (unsigned char)(235 * brightness),
        255
    };
    
    BeginDrawing();
    ClearBackground(sky_color);
    
    BeginMode3D(g_game.camera);
    
    /* Draw ground */
    draw_city_ground();
    
    /* Draw buildings */
    for (int i = 0; i < g_game.building_count; i++) {
        draw_building_exterior(&g_game.buildings[i]);
        /* Only draw interiors if close enough */
        float dist = Vector3Distance(g_game.player_aircraft.position, 
                                    (Vector3){g_game.buildings[i].world_x, 0, g_game.buildings[i].world_z});
        if (dist < 200.0f) {
            draw_building_interior(&g_game.buildings[i]);
        }
    }
    
    /* Draw AI characters on ground */
    draw_ai_characters();
    
    /* Draw other aircraft (placeholder) */
    for (int i = 0; i < 5; i++) {
        aircraft_t enemy = {
            .position = {(float)(i * 100 - 200), 100.0f + i * 50.0f, (float)(i * 150)},
            .rotation = {0, (float)(i * 45), 0},
            .afterburner = 0,
            .landing_gear = false
        };
        draw_aircraft(&enemy);
    }
    
    /* Draw player aircraft */
    draw_aircraft(&g_game.player_aircraft);
    
    /* Draw sun */
    Vector3 sun_pos = {
        sinf(sun_angle) * 500.0f,
        cosf(sun_angle) * 500.0f + 200.0f,
        0
    };
    DrawSphere(sun_pos, 50.0f, YELLOW);
    
    /* Draw clouds */
    for (int i = 0; i < 20; i++) {
        float cloud_x = sinf(i * 1.7f + GetTime() * 0.05f) * 400.0f;
        float cloud_z = cosf(i * 2.3f + GetTime() * 0.03f) * 400.0f;
        float cloud_y = 200.0f + i * 10.0f;
        DrawSphere((Vector3){cloud_x, cloud_y, cloud_z}, 30.0f, 
                  (Color){255, 255, 255, 100});
    }
    
    EndMode3D();
    
    /* Draw HUD */
    draw_aircraft_hud();
    
    /* Draw input controller overlay */
    aircraft_input_controller_draw_overlay();
    
    /* Debug info */
    if (g_game.show_debug) {
        DrawText(TextFormat("FPS: %d", GetFPS()), 10, GetScreenHeight() - 100, 16, GREEN);
        DrawText(TextFormat("Pos: %.1f, %.1f, %.1f", 
                g_game.player_aircraft.position.x,
                g_game.player_aircraft.position.y,
                g_game.player_aircraft.position.z), 
                10, GetScreenHeight() - 80, 16, WHITE);
        DrawText(TextFormat("Rot: %.1f, %.1f, %.1f", 
                g_game.player_aircraft.rotation.x,
                g_game.player_aircraft.rotation.y,
                g_game.player_aircraft.rotation.z), 
                10, GetScreenHeight() - 60, 16, WHITE);
        DrawText(TextFormat("Buildings: %d, AI: %d", g_game.building_count, 50), 
                10, GetScreenHeight() - 40, 16, WHITE);
    }
    
    /* Pause indicator */
    if (g_game.paused) {
        DrawText("PAUSED", GetScreenWidth()/2 - 60, GetScreenHeight()/2 - 20, 40, YELLOW);
    }
    
    EndDrawing();
}

/* Cleanup */
void cleanup_game() {
    if (g_game.buildings) {
        free(g_game.buildings);
    }
}

/* Main */
int main() {
    /* Enforce specifications */
    ENFORCE_3D_SPECIFICATIONS();
    ENFORCE_JOYSTICK_CONTROLS();
    
    printf("=== FULL NODE: FIREWALL FLY-OVER ===\n");
    printf("Aircraft View with Ground Characters\n\n");
    
    InitWindow(WINDOW_WIDTH, WINDOW_HEIGHT, "Full Node: Firewall Fly-Over - Aircraft View");
    SetTargetFPS(TARGET_FPS);
    
    init_game();
    
    printf("You are flying an aircraft above the city!\n");
    printf("Look down to see AI characters running around.\n");
    printf("Press F1 for help, F2 for debug.\n\n");
    
    while (!WindowShouldClose()) {
        update_game();
        draw_game();
    }
    
    cleanup_game();
    aircraft_input_controller_cleanup();
    CloseWindow();
    
    return 0;
}