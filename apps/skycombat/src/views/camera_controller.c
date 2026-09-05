/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/views/camera_controller.h"
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <raymath.h>

/* Constants */
#define DEFAULT_FOV 60.0f
#define DEFAULT_DISTANCE 30.0f
#define MIN_DISTANCE 10.0f
#define MAX_DISTANCE 100.0f
#define MIN_HEIGHT 5.0f
#define MAX_PITCH 85.0f
#define DEFAULT_POSITION_SMOOTHING 0.15f
#define DEFAULT_ROTATION_SMOOTHING 0.2f
#define OVERVIEW_HEIGHT 150.0f
#define ORBIT_RADIUS 40.0f
#define SHAKE_FREQUENCY 15.0f

/* Shake intensity values */
static const float shake_intensities[] = {
    0.0f,    /* SHAKE_NONE */
    0.5f,    /* SHAKE_LIGHT */
    1.5f,    /* SHAKE_MEDIUM */
    3.0f,    /* SHAKE_HEAVY */
    5.0f     /* SHAKE_CRITICAL */
};

/* Helper functions */
static Vector3 calculate_follow_position(camera_controller_t* controller);
static Vector3 calculate_orbit_position(camera_controller_t* controller);
static Vector3 calculate_cockpit_position(camera_controller_t* controller);
static void update_shake(camera_controller_t* controller, float dt);
static void update_smooth_values(camera_controller_t* controller, float dt);
static void update_transition(camera_controller_t* controller, float dt);
static void apply_constraints(camera_controller_t* controller);

/*
 * Core Functions
 */

camera_controller_t* camera_controller_create(void) {
    camera_controller_t* controller = (camera_controller_t*)calloc(1, sizeof(camera_controller_t));
    if (!controller) return NULL;
    
    /* Initialize camera */
    controller->camera.position = (Vector3){ 0.0f, 50.0f, 50.0f };
    controller->camera.target = (Vector3){ 0.0f, 0.0f, 0.0f };
    controller->camera.up = (Vector3){ 0.0f, 1.0f, 0.0f };
    controller->camera.fovy = DEFAULT_FOV;
    controller->camera.projection = CAMERA_PERSPECTIVE;
    
    /* Default settings */
    controller->mode = CAMERA_MODE_FOLLOW;
    controller->position_smoothing = DEFAULT_POSITION_SMOOTHING;
    controller->rotation_smoothing = DEFAULT_ROTATION_SMOOTHING;
    controller->base_distance = DEFAULT_DISTANCE;
    controller->current_distance = DEFAULT_DISTANCE;
    controller->combat_zoom_factor = 1.0f;
    controller->speed_zoom_factor = 1.0f;
    
    /* Constraints */
    controller->min_distance = MIN_DISTANCE;
    controller->max_distance = MAX_DISTANCE;
    controller->min_height = MIN_HEIGHT;
    controller->max_pitch = MAX_PITCH;
    
    /* Mode-specific */
    controller->orbit_angle = 0.0f;
    controller->orbit_height = 20.0f;
    controller->overview_height = OVERVIEW_HEIGHT;
    
    /* Initialize smooth values */
    controller->smooth_position = controller->camera.position;
    controller->smooth_target = controller->camera.target;
    
    return controller;
}

void camera_controller_destroy(camera_controller_t* controller) {
    free(controller);
}

void camera_controller_reset(camera_controller_t* controller) {
    if (!controller) return;
    
    controller->camera.position = (Vector3){ 0.0f, 50.0f, 50.0f };
    controller->camera.target = (Vector3){ 0.0f, 0.0f, 0.0f };
    controller->current_distance = controller->base_distance;
    controller->shake_type = SHAKE_NONE;
    controller->shake_duration = 0.0f;
    controller->in_transition = false;
    controller->orbit_angle = 0.0f;
}

/*
 * Update Functions
 */

void camera_controller_update(camera_controller_t* controller, float dt) {
    if (!controller) return;
    
    /* Update shake */
    update_shake(controller, dt);
    
    /* Update transition */
    if (controller->in_transition) {
        update_transition(controller, dt);
    }
    
    /* Calculate target position based on mode */
    Vector3 desired_position = controller->camera.position;
    Vector3 desired_target = controller->target_position;
    
    switch (controller->mode) {
        case CAMERA_MODE_FOLLOW:
            desired_position = calculate_follow_position(controller);
            break;
            
        case CAMERA_MODE_ORBIT:
            desired_position = calculate_orbit_position(controller);
            break;
            
        case CAMERA_MODE_COCKPIT:
            desired_position = calculate_cockpit_position(controller);
            desired_target = Vector3Add(desired_position, 
                Vector3Scale(Vector3Normalize(controller->target_velocity), 10.0f));
            break;
            
        case CAMERA_MODE_OVERVIEW:
            desired_position = (Vector3){
                controller->target_position.x,
                controller->target_position.y + controller->overview_height,
                controller->target_position.z + 10.0f
            };
            break;
            
        case CAMERA_MODE_CINEMATIC:
        case CAMERA_MODE_FREE:
            /* Handled by external input */
            break;
    }
    
    /* Update smooth values */
    controller->smooth_position = Vector3Lerp(controller->smooth_position, 
                                            desired_position, 
                                            controller->position_smoothing);
    controller->smooth_target = Vector3Lerp(controller->smooth_target,
                                          desired_target,
                                          controller->rotation_smoothing);
    
    /* Apply to camera with shake */
    controller->camera.position = Vector3Add(controller->smooth_position, controller->shake_offset);
    controller->camera.target = controller->smooth_target;
    
    /* Apply constraints */
    apply_constraints(controller);
    
    /* Adjust FOV based on speed */
    if (controller->speed_zoom_factor > 1.0f) {
        float speed_factor = controller->target_speed / 100.0f;
        float fov_adjust = 1.0f + (speed_factor * 0.2f);
        controller->camera.fovy = DEFAULT_FOV * fov_adjust;
    }
}

void camera_controller_set_target(camera_controller_t* controller,
                                Vector3 position, Vector3 velocity, float speed) {
    if (!controller) return;
    
    controller->target_position = position;
    controller->target_velocity = velocity;
    controller->target_speed = speed;
}

void camera_controller_set_mode(camera_controller_t* controller,
                              camera_mode_t mode, float transition_time) {
    if (!controller) return;
    if (controller->mode == mode) return;
    
    /* Start transition */
    if (transition_time > 0.0f) {
        controller->in_transition = true;
        controller->transition_time = transition_time;
        controller->transition_progress = 0.0f;
        controller->transition_start_pos = controller->camera.position;
        controller->transition_start_target = controller->camera.target;
    }
    
    controller->mode = mode;
}

/*
 * Camera Effects
 */

void camera_controller_shake(camera_controller_t* controller,
                           camera_shake_t type, float duration) {
    if (!controller || type == SHAKE_NONE) return;
    
    controller->shake_type = type;
    controller->shake_intensity = shake_intensities[type];
    controller->shake_duration = duration;
}

void camera_controller_set_combat_zoom(camera_controller_t* controller, float factor) {
    if (!controller) return;
    controller->combat_zoom_factor = fmaxf(1.0f, factor);
}

void camera_controller_set_speed_zoom(camera_controller_t* controller, bool enabled) {
    if (!controller) return;
    controller->speed_zoom_factor = enabled ? 1.5f : 1.0f;
}

/*
 * Camera Control
 */

void camera_controller_free_camera_input(camera_controller_t* controller, float dt) {
    if (!controller || controller->mode != CAMERA_MODE_FREE) return;
    
    float move_speed = 50.0f * dt;
    float rotate_speed = 2.0f * dt;
    
    /* Movement */
    if (IsKeyDown(KEY_W)) {
        Vector3 forward = Vector3Normalize(Vector3Subtract(controller->camera.target, 
                                                          controller->camera.position));
        controller->camera.position = Vector3Add(controller->camera.position,
                                               Vector3Scale(forward, move_speed));
        controller->camera.target = Vector3Add(controller->camera.target,
                                             Vector3Scale(forward, move_speed));
    }
    if (IsKeyDown(KEY_S)) {
        Vector3 forward = Vector3Normalize(Vector3Subtract(controller->camera.target,
                                                          controller->camera.position));
        controller->camera.position = Vector3Subtract(controller->camera.position,
                                                    Vector3Scale(forward, move_speed));
        controller->camera.target = Vector3Subtract(controller->camera.target,
                                                  Vector3Scale(forward, move_speed));
    }
    if (IsKeyDown(KEY_A)) {
        Vector3 forward = Vector3Normalize(Vector3Subtract(controller->camera.target,
                                                          controller->camera.position));
        Vector3 right = Vector3CrossProduct(forward, controller->camera.up);
        controller->camera.position = Vector3Subtract(controller->camera.position,
                                                    Vector3Scale(right, move_speed));
        controller->camera.target = Vector3Subtract(controller->camera.target,
                                                  Vector3Scale(right, move_speed));
    }
    if (IsKeyDown(KEY_D)) {
        Vector3 forward = Vector3Normalize(Vector3Subtract(controller->camera.target,
                                                          controller->camera.position));
        Vector3 right = Vector3CrossProduct(forward, controller->camera.up);
        controller->camera.position = Vector3Add(controller->camera.position,
                                               Vector3Scale(right, move_speed));
        controller->camera.target = Vector3Add(controller->camera.target,
                                             Vector3Scale(right, move_speed));
    }
    
    /* Rotation with mouse */
    Vector2 mouse_delta = GetMouseDelta();
    if (IsMouseButtonDown(MOUSE_BUTTON_RIGHT)) {
        UpdateCameraPro(&controller->camera,
                       (Vector3){0, 0, 0},
                       (Vector3){mouse_delta.x * rotate_speed, 
                                mouse_delta.y * rotate_speed, 0},
                       0);
    }
}

void camera_controller_orbit(camera_controller_t* controller,
                           float delta_angle, float delta_height) {
    if (!controller || controller->mode != CAMERA_MODE_ORBIT) return;
    
    controller->orbit_angle += delta_angle;
    controller->orbit_height = fmaxf(5.0f, fminf(50.0f, 
                                    controller->orbit_height + delta_height));
}

/*
 * Utility Functions
 */

Camera3D* camera_controller_get_camera(camera_controller_t* controller) {
    return controller ? &controller->camera : NULL;
}

bool camera_controller_is_transitioning(camera_controller_t* controller) {
    return controller ? controller->in_transition : false;
}

const char* camera_controller_get_mode_name(camera_mode_t mode) {
    switch (mode) {
        case CAMERA_MODE_FOLLOW:    return "Follow";
        case CAMERA_MODE_ORBIT:     return "Orbit";
        case CAMERA_MODE_COCKPIT:   return "Cockpit";
        case CAMERA_MODE_CINEMATIC: return "Cinematic";
        case CAMERA_MODE_FREE:      return "Free";
        case CAMERA_MODE_OVERVIEW:  return "Overview";
        default:                    return "Unknown";
    }
}

/*
 * Helper Function Implementations
 */

static Vector3 calculate_follow_position(camera_controller_t* controller) {
    /* Calculate position behind and above target */
    Vector3 velocity_norm = Vector3Normalize(controller->target_velocity);
    if (Vector3Length(velocity_norm) < 0.1f) {
        velocity_norm = (Vector3){0, 0, -1};  /* Default forward */
    }
    
    /* Dynamic distance based on combat and speed */
    float distance = controller->base_distance;
    distance *= controller->combat_zoom_factor;
    if (controller->speed_zoom_factor > 1.0f) {
        distance *= (1.0f + controller->target_speed / 200.0f);
    }
    controller->current_distance = distance;
    
    /* Position behind aircraft */
    Vector3 offset = Vector3Scale(velocity_norm, -distance);
    offset.y = distance * 0.5f;  /* Above aircraft */
    
    return Vector3Add(controller->target_position, offset);
}

static Vector3 calculate_orbit_position(camera_controller_t* controller) {
    float angle_rad = controller->orbit_angle * DEG2RAD;
    float radius = ORBIT_RADIUS * controller->combat_zoom_factor;
    
    Vector3 offset = {
        sinf(angle_rad) * radius,
        controller->orbit_height,
        cosf(angle_rad) * radius
    };
    
    return Vector3Add(controller->target_position, offset);
}

static Vector3 calculate_cockpit_position(camera_controller_t* controller) {
    /* Position slightly ahead of aircraft center */
    Vector3 forward = Vector3Normalize(controller->target_velocity);
    if (Vector3Length(forward) < 0.1f) {
        forward = (Vector3){0, 0, 1};
    }
    
    Vector3 offset = Vector3Scale(forward, 2.0f);
    offset.y += 1.0f;  /* Cockpit height */
    
    return Vector3Add(controller->target_position, offset);
}

static void update_shake(camera_controller_t* controller, float dt) {
    if (controller->shake_duration <= 0.0f) {
        controller->shake_offset = (Vector3){0, 0, 0};
        return;
    }
    
    controller->shake_duration -= dt;
    
    /* Generate shake offset */
    float time = GetTime();
    controller->shake_offset = (Vector3){
        sinf(time * SHAKE_FREQUENCY) * controller->shake_intensity,
        sinf(time * SHAKE_FREQUENCY * 1.3f) * controller->shake_intensity * 0.7f,
        sinf(time * SHAKE_FREQUENCY * 0.7f) * controller->shake_intensity * 0.5f
    };
    
    /* Fade out */
    if (controller->shake_duration < 0.5f) {
        float fade = controller->shake_duration / 0.5f;
        controller->shake_offset = Vector3Scale(controller->shake_offset, fade);
    }
}

static void update_transition(camera_controller_t* controller, float dt) {
    controller->transition_progress += dt / controller->transition_time;
    
    if (controller->transition_progress >= 1.0f) {
        controller->transition_progress = 1.0f;
        controller->in_transition = false;
    }
    
    /* Smooth interpolation */
    float t = controller->transition_progress;
    t = t * t * (3.0f - 2.0f * t);  /* Smoothstep */
    
    controller->smooth_position = Vector3Lerp(controller->transition_start_pos,
                                            controller->smooth_position, t);
    controller->smooth_target = Vector3Lerp(controller->transition_start_target,
                                          controller->smooth_target, t);
}

static void apply_constraints(camera_controller_t* controller) {
    /* Minimum height */
    if (controller->camera.position.y < controller->min_height) {
        controller->camera.position.y = controller->min_height;
    }
    
    /* Distance constraints */
    Vector3 to_target = Vector3Subtract(controller->camera.target,
                                      controller->camera.position);
    float distance = Vector3Length(to_target);
    
    if (distance < controller->min_distance) {
        to_target = Vector3Scale(Vector3Normalize(to_target), controller->min_distance);
        controller->camera.position = Vector3Subtract(controller->camera.target, to_target);
    } else if (distance > controller->max_distance) {
        to_target = Vector3Scale(Vector3Normalize(to_target), controller->max_distance);
        controller->camera.position = Vector3Subtract(controller->camera.target, to_target);
    }
    
    /* Pitch constraints */
    Vector3 forward = Vector3Normalize(to_target);
    float pitch = asinf(forward.y) * RAD2DEG;
    
    if (fabsf(pitch) > controller->max_pitch) {
        float sign = pitch > 0 ? 1.0f : -1.0f;
        float max_pitch_rad = controller->max_pitch * DEG2RAD * sign;
        forward.y = sinf(max_pitch_rad);
        float horizontal_scale = cosf(max_pitch_rad);
        forward.x *= horizontal_scale / sqrtf(forward.x * forward.x + forward.z * forward.z);
        forward.z *= horizontal_scale / sqrtf(forward.x * forward.x + forward.z * forward.z);
        
        controller->camera.target = Vector3Add(controller->camera.position,
                                             Vector3Scale(forward, distance));
    }
}

/* Responsive camera update for enhanced gameplay */
void camera_update_responsive(Camera3D* camera, Vector3 target, float yaw, float distance, float height, float dt) {
    if (!camera) return;
    
    /* Calculate ideal camera position behind and above aircraft */
    float cam_x = target.x - sinf(yaw * DEG2RAD) * distance;
    float cam_z = target.z - cosf(yaw * DEG2RAD) * distance;
    float cam_y = target.y + height;
    
    Vector3 ideal_pos = (Vector3){cam_x, cam_y, cam_z};
    
    /* Smooth camera movement */
    camera->position.x = Lerp(camera->position.x, ideal_pos.x, 5.0f * dt);
    camera->position.y = Lerp(camera->position.y, ideal_pos.y, 5.0f * dt);
    camera->position.z = Lerp(camera->position.z, ideal_pos.z, 5.0f * dt);
    
    /* Look at target with some forward offset */
    Vector3 look_target = target;
    look_target.x += sinf(yaw * DEG2RAD) * 10.0f;
    look_target.z += cosf(yaw * DEG2RAD) * 10.0f;
    
    camera->target = look_target;
    camera->up = (Vector3){0, 1, 0};
}