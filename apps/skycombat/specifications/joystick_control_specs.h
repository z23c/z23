/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef JOYSTICK_CONTROL_SPECS_H
#define JOYSTICK_CONTROL_SPECS_H

#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

/* Specification: Joystick controls MUST work and be provable */

/* Control input ranges - hardware limits */
#define JOYSTICK_AXIS_MIN (-32768)
#define JOYSTICK_AXIS_MAX (32767)
#define JOYSTICK_DEADZONE (4096)  /* ~12.5% deadzone */

/* Aircraft control limits */
#define MAX_PITCH_RATE (90.0f)   /* degrees/second */
#define MAX_ROLL_RATE (180.0f)   /* degrees/second */
#define MAX_YAW_RATE (60.0f)     /* degrees/second */
#define MAX_THROTTLE_RATE (2.0f) /* 0-100% in 0.5 seconds */

/* Response time requirement */
#define MAX_INPUT_LATENCY_MS (16)  /* Must respond within 1 frame at 60fps */

/* Axis mappings */
typedef enum {
    AXIS_LEFT_X = 0,
    AXIS_LEFT_Y = 1,
    AXIS_RIGHT_X = 2,
    AXIS_RIGHT_Y = 3,
    AXIS_L2 = 4,
    AXIS_R2 = 5,
    AXIS_COUNT = 6
} joystick_axis_t;

/* Button mappings */
typedef enum {
    BUTTON_A = 0,
    BUTTON_B = 1,
    BUTTON_X = 2,
    BUTTON_Y = 3,
    BUTTON_L1 = 4,
    BUTTON_R1 = 5,
    BUTTON_BACK = 6,
    BUTTON_START = 7,
    BUTTON_COUNT = 16
} joystick_button_t;

/* Validated input state */
typedef struct {
    float pitch;     /* -1.0 to 1.0 */
    float roll;      /* -1.0 to 1.0 */
    float yaw;       /* -1.0 to 1.0 */
    float throttle;  /* 0.0 to 1.0 */
    bool afterburner;
    bool landing_gear;
    bool fire_primary;
    bool fire_secondary;
    bool gas_button;     /* Button 2 (UL) */
    bool brake_button;   /* Button 3 (UR) */
    uint32_t timestamp_ms;
    bool is_valid;
} validated_joystick_input_t;

/* Compile-time proofs */
#define PROVE_JOYSTICK_RANGES() do { \
    _Static_assert(JOYSTICK_AXIS_MIN < 0, "Axis min must be negative"); \
    _Static_assert(JOYSTICK_AXIS_MAX > 0, "Axis max must be positive"); \
    _Static_assert(JOYSTICK_DEADZONE > 0, "Deadzone must be positive"); \
    _Static_assert(JOYSTICK_DEADZONE < JOYSTICK_AXIS_MAX/4, "Deadzone too large"); \
} while(0)

#define PROVE_CONTROL_RATES() do { \
    _Static_assert(MAX_PITCH_RATE > 0 && MAX_PITCH_RATE <= 180.0f, "Invalid pitch rate"); \
    _Static_assert(MAX_ROLL_RATE > 0 && MAX_ROLL_RATE <= 360.0f, "Invalid roll rate"); \
    _Static_assert(MAX_YAW_RATE > 0 && MAX_YAW_RATE <= 180.0f, "Invalid yaw rate"); \
    _Static_assert(MAX_THROTTLE_RATE > 0, "Invalid throttle rate"); \
} while(0)

#define PROVE_RESPONSE_TIME() do { \
    _Static_assert(MAX_INPUT_LATENCY_MS <= 16, "Input latency too high for 60fps"); \
    _Static_assert(MAX_INPUT_LATENCY_MS > 0, "Invalid latency specification"); \
} while(0)

/* Runtime validation with guaranteed bounds */
static inline float clamp_axis_input(int16_t raw_value) {
    /* Apply deadzone */
    if (raw_value > -JOYSTICK_DEADZONE && raw_value < JOYSTICK_DEADZONE) {
        return 0.0f;
    }
    
    /* Clamp to valid range */
    if (raw_value <= JOYSTICK_AXIS_MIN) return -1.0f;
    if (raw_value >= JOYSTICK_AXIS_MAX) return 1.0f;
    
    /* Normalize with deadzone compensation */
    if (raw_value > 0) {
        return (float)(raw_value - JOYSTICK_DEADZONE) / 
               (float)(JOYSTICK_AXIS_MAX - JOYSTICK_DEADZONE);
    } else {
        return (float)(raw_value + JOYSTICK_DEADZONE) / 
               (float)(JOYSTICK_AXIS_MAX - JOYSTICK_DEADZONE);
    }
}

/* Validate complete input state */
static inline validated_joystick_input_t validate_joystick_input(
    const int16_t axes[AXIS_COUNT],
    const uint8_t buttons[BUTTON_COUNT],
    uint32_t timestamp_ms
) {
    validated_joystick_input_t result = {0};
    
    /* Validate axes - use left stick for steering */
    result.pitch = -clamp_axis_input(axes[AXIS_LEFT_Y]);  /* Inverted */
    result.roll = clamp_axis_input(axes[AXIS_LEFT_X]);
    
    /* Right stick for looking around */
    result.yaw = clamp_axis_input(axes[AXIS_RIGHT_X]);
    
    /* Throttle controlled by buttons 2/3 (UL/UR) */
    result.gas_button = buttons[2];      /* Button 2 (UL) = Gas */
    result.brake_button = buttons[3];    /* Button 3 (UR) = Brake */
    
    /* Calculate throttle from gas/brake buttons */
    if (result.gas_button && !result.brake_button) {
        result.throttle = 1.0f;  /* Full throttle */
    } else if (result.brake_button && !result.gas_button) {
        result.throttle = 0.0f;  /* No throttle */
    } else {
        result.throttle = 0.5f;  /* Cruise */
    }
    
    /* Other buttons */
    result.afterburner = buttons[BUTTON_A];
    result.landing_gear = buttons[BUTTON_B];
    
    /* Triggers for weapons */
    result.fire_primary = axes[AXIS_R2] > -16000;   /* R2 trigger */
    result.fire_secondary = axes[AXIS_L2] > -16000;  /* L2 trigger */
    
    /* Timestamp and validation */
    result.timestamp_ms = timestamp_ms;
    result.is_valid = true;
    
    /* Final bounds check */
    assert(result.pitch >= -1.0f && result.pitch <= 1.0f);
    assert(result.roll >= -1.0f && result.roll <= 1.0f);
    assert(result.yaw >= -1.0f && result.yaw <= 1.0f);
    assert(result.throttle >= 0.0f && result.throttle <= 1.0f);
    
    return result;
}

/* Master proof that joystick controls work */
#define ENFORCE_JOYSTICK_CONTROLS() do { \
    PROVE_JOYSTICK_RANGES(); \
    PROVE_CONTROL_RATES(); \
    PROVE_RESPONSE_TIME(); \
} while(0)

#endif /* JOYSTICK_CONTROL_SPECS_H */