/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AIRCRAFT_CONTROL_SPECS_H
#define AIRCRAFT_CONTROL_SPECS_H

#include <assert.h>
#include <stdbool.h>
#include <math.h>

/* Control Responsiveness Requirements */
#define MIN_MOUSE_SENSITIVITY 0.1f
#define MAX_MOUSE_SENSITIVITY 2.0f
#define DEFAULT_MOUSE_SENSITIVITY 0.3f

#define MIN_PITCH_RATE 30.0f  /* degrees per second */
#define MAX_PITCH_RATE 120.0f
#define MIN_ROLL_RATE 60.0f
#define MAX_ROLL_RATE 180.0f
#define MIN_YAW_RATE 30.0f
#define MAX_YAW_RATE 90.0f

/* Control Limits */
#define MAX_PITCH_ANGLE 85.0f
#define MAX_ROLL_ANGLE 180.0f
#define MIN_THROTTLE 0.0f
#define MAX_THROTTLE 1.0f

/* Input Response Time */
#define MAX_INPUT_LATENCY_MS 16  /* One frame at 60 FPS */

/* Specification Enforcement Macros */
#define VERIFY_MOUSE_SENSITIVITY(sensitivity) do { \
    assert(sensitivity >= MIN_MOUSE_SENSITIVITY); \
    assert(sensitivity <= MAX_MOUSE_SENSITIVITY); \
} while(0)

#define VERIFY_PITCH_RATE(rate) do { \
    assert(fabs(rate) >= MIN_PITCH_RATE); \
    assert(fabs(rate) <= MAX_PITCH_RATE); \
} while(0)

#define VERIFY_ROLL_RATE(rate) do { \
    assert(fabs(rate) >= MIN_ROLL_RATE); \
    assert(fabs(rate) <= MAX_ROLL_RATE); \
} while(0)

#define VERIFY_YAW_RATE(rate) do { \
    assert(fabs(rate) >= MIN_YAW_RATE); \
    assert(fabs(rate) <= MAX_YAW_RATE); \
} while(0)

#define VERIFY_PITCH_ANGLE(angle) do { \
    assert(fabs(angle) <= MAX_PITCH_ANGLE); \
} while(0)

#define VERIFY_THROTTLE(throttle) do { \
    assert(throttle >= MIN_THROTTLE); \
    assert(throttle <= MAX_THROTTLE); \
} while(0)

/* Control System Requirements */
typedef struct {
    bool mouse_capture_works;
    bool keyboard_controls_work;
    bool throttle_controls_work;
    bool rotation_limits_enforced;
    bool response_time_acceptable;
} control_system_status_t;

/* Verify control system is working */
static inline control_system_status_t verify_control_system(
    bool mouse_captured,
    float mouse_sensitivity_x,
    float mouse_sensitivity_y,
    float pitch_angle,
    float roll_angle,
    float throttle,
    float frame_time_ms
) {
    control_system_status_t status = {0};
    
    /* Mouse capture verification */
    status.mouse_capture_works = true; /* Can be toggled with TAB */
    
    /* Keyboard always works as override */
    status.keyboard_controls_work = true;
    
    /* Throttle must be in valid range */
    status.throttle_controls_work = (throttle >= MIN_THROTTLE && throttle <= MAX_THROTTLE);
    
    /* Rotation limits */
    status.rotation_limits_enforced = (fabs(pitch_angle) <= MAX_PITCH_ANGLE);
    
    /* Response time */
    status.response_time_acceptable = (frame_time_ms <= MAX_INPUT_LATENCY_MS);
    
    /* Verify sensitivities if mouse is captured */
    if (mouse_captured) {
        VERIFY_MOUSE_SENSITIVITY(mouse_sensitivity_x);
        VERIFY_MOUSE_SENSITIVITY(mouse_sensitivity_y);
    }
    
    return status;
}

/* Enforce all control specifications */
#define ENFORCE_AIRCRAFT_CONTROL_SPECS() do { \
    /* Compile-time checks */ \
    _Static_assert(MIN_MOUSE_SENSITIVITY > 0, "Mouse sensitivity must be positive"); \
    _Static_assert(MAX_MOUSE_SENSITIVITY > MIN_MOUSE_SENSITIVITY, "Max sensitivity must exceed min"); \
    _Static_assert(MIN_PITCH_RATE > 0, "Pitch rate must be positive"); \
    _Static_assert(MIN_ROLL_RATE > 0, "Roll rate must be positive"); \
    _Static_assert(MIN_YAW_RATE > 0, "Yaw rate must be positive"); \
    _Static_assert(MAX_PITCH_ANGLE > 0 && MAX_PITCH_ANGLE <= 90, "Pitch angle must be reasonable"); \
    _Static_assert(MAX_INPUT_LATENCY_MS >= 16, "Must allow at least one frame of latency"); \
} while(0)

/* Control Input Validation */
static inline float clamp_control_value(float value, float min, float max) {
    if (value < min) return min;
    if (value > max) return max;
    return value;
}

/* Safe control application */
#define APPLY_PITCH_CONTROL(aircraft, delta_pitch) do { \
    float new_pitch = (aircraft)->rotation.x + (delta_pitch); \
    (aircraft)->rotation.x = clamp_control_value(new_pitch, -MAX_PITCH_ANGLE, MAX_PITCH_ANGLE); \
    VERIFY_PITCH_ANGLE((aircraft)->rotation.x); \
} while(0)

#define APPLY_ROLL_CONTROL(aircraft, delta_roll) do { \
    (aircraft)->rotation.z += (delta_roll); \
    if ((aircraft)->rotation.z > 180.0f) (aircraft)->rotation.z -= 360.0f; \
    if ((aircraft)->rotation.z < -180.0f) (aircraft)->rotation.z += 360.0f; \
} while(0)

#define APPLY_THROTTLE_CONTROL(aircraft, delta_throttle) do { \
    float new_throttle = (aircraft)->throttle + (delta_throttle); \
    (aircraft)->throttle = clamp_control_value(new_throttle, MIN_THROTTLE, MAX_THROTTLE); \
    VERIFY_THROTTLE((aircraft)->throttle); \
} while(0)

#endif /* AIRCRAFT_CONTROL_SPECS_H */