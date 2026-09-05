/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <raylib.h>
#include <raymath.h>

void camera_follow_aircraft(Camera3D* camera, Vector3 aircraft_pos, float yaw, float speed, float dt) {
    float cam_dist = 60 + speed * 0.5f;
    float cam_angle = yaw * DEG2RAD;
    
    Vector3 cam_offset = {
        -sinf(cam_angle) * cam_dist,
        30,
        -cosf(cam_angle) * cam_dist
    };
    
    camera->position = Vector3Lerp(camera->position,
                                  Vector3Add(aircraft_pos, cam_offset),
                                  3 * dt);
    camera->target = Vector3Lerp(camera->target, aircraft_pos, 5 * dt);
}