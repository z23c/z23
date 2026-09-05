/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <raylib.h>
#include <raymath.h>
#include <math.h>
#include "../../specifications/3d_building_specs.h"

typedef struct {
    Camera3D camera;
    Vector3 velocity;
    float pitch;
    float yaw;
    bool is_flying;
    float boost_timer;
} flying_camera_t;

static flying_camera_t g_flying_camera = {0};

void init_flying_camera() {
    g_flying_camera.camera.position = (Vector3){50.0f, 50.0f, 50.0f};
    g_flying_camera.camera.target = (Vector3){0.0f, 0.0f, 0.0f};
    g_flying_camera.camera.up = (Vector3){0.0f, 1.0f, 0.0f};
    g_flying_camera.camera.fovy = 60.0f;
    g_flying_camera.camera.projection = CAMERA_PERSPECTIVE;
    g_flying_camera.is_flying = true;
    g_flying_camera.yaw = -PI/4;
    g_flying_camera.pitch = -PI/6;
}

void update_flying_camera(float delta) {
    /* Mouse look */
    Vector2 mouse_delta = GetMouseDelta();
    g_flying_camera.yaw -= mouse_delta.x * 0.003f;
    g_flying_camera.pitch -= mouse_delta.y * 0.003f;
    
    /* Clamp pitch to prevent flipping */
    if (g_flying_camera.pitch > PI/2 - 0.1f) g_flying_camera.pitch = PI/2 - 0.1f;
    if (g_flying_camera.pitch < -PI/2 + 0.1f) g_flying_camera.pitch = -PI/2 + 0.1f;
    
    /* Calculate forward direction */
    Vector3 forward = {
        cosf(g_flying_camera.pitch) * sinf(g_flying_camera.yaw),
        sinf(g_flying_camera.pitch),
        cosf(g_flying_camera.pitch) * cosf(g_flying_camera.yaw)
    };
    
    Vector3 right = Vector3CrossProduct(forward, (Vector3){0, 1, 0});
    right = Vector3Normalize(right);
    
    /* Flying controls */
    float speed = FLYING_CRUISE_SPEED;
    if (IsKeyDown(KEY_LEFT_SHIFT)) {
        speed = FLYING_BOOST_SPEED;
        g_flying_camera.boost_timer = 1.0f;
    }
    
    Vector3 move_dir = {0, 0, 0};
    
    /* WASD movement */
    if (IsKeyDown(KEY_W)) move_dir = Vector3Add(move_dir, forward);
    if (IsKeyDown(KEY_S)) move_dir = Vector3Subtract(move_dir, forward);
    if (IsKeyDown(KEY_A)) move_dir = Vector3Subtract(move_dir, right);
    if (IsKeyDown(KEY_D)) move_dir = Vector3Add(move_dir, right);
    
    /* Up/Down */
    if (IsKeyDown(KEY_SPACE)) move_dir.y += 1.0f;
    if (IsKeyDown(KEY_LEFT_CONTROL)) move_dir.y -= 1.0f;
    
    /* Normalize and apply speed */
    if (Vector3Length(move_dir) > 0) {
        move_dir = Vector3Normalize(move_dir);
        g_flying_camera.velocity = Vector3Scale(move_dir, speed * delta);
    } else {
        /* Deceleration */
        g_flying_camera.velocity = Vector3Scale(g_flying_camera.velocity, 0.9f);
    }
    
    /* Update position */
    g_flying_camera.camera.position = Vector3Add(g_flying_camera.camera.position, g_flying_camera.velocity);
    
    /* Keep above ground */
    if (g_flying_camera.camera.position.y < FLYING_MIN_ALTITUDE + 1.0f) {
        g_flying_camera.camera.position.y = FLYING_MIN_ALTITUDE + 1.0f;
    }
    
    /* Update target */
    g_flying_camera.camera.target = Vector3Add(g_flying_camera.camera.position, forward);
    
    /* Visual effects */
    if (g_flying_camera.boost_timer > 0) {
        g_flying_camera.boost_timer -= delta;
        g_flying_camera.camera.fovy = 60.0f + g_flying_camera.boost_timer * 10.0f;
    } else {
        g_flying_camera.camera.fovy = 60.0f;
    }
}

Camera3D* get_flying_camera() {
    return &g_flying_camera.camera;
}

void draw_flight_hud() {
    /* Speed indicator */
    float speed = Vector3Length(g_flying_camera.velocity) / 0.016f;
    DrawText(TextFormat("Speed: %.0f m/s", speed), 10, 10, 20, GREEN);
    DrawText(TextFormat("Altitude: %.0f m", g_flying_camera.camera.position.y), 10, 40, 20, GREEN);
    
    /* Controls help */
    DrawText("WASD: Move | Mouse: Look | Space/Ctrl: Up/Down | Shift: Boost", 10, GetScreenHeight() - 30, 16, WHITE);
    
    /* Crosshair */
    int cx = GetScreenWidth() / 2;
    int cy = GetScreenHeight() / 2;
    DrawLine(cx - 10, cy, cx + 10, cy, WHITE);
    DrawLine(cx, cy - 10, cx, cy + 10, WHITE);
    
    /* Boost indicator */
    if (g_flying_camera.boost_timer > 0) {
        DrawText("BOOST!", cx - 30, cy + 30, 24, YELLOW);
    }
}