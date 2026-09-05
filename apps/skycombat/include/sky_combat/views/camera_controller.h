/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_CAMERA_CONTROLLER_H
#define SKY_COMBAT_CAMERA_CONTROLLER_H

/**
 * @file camera_controller.h
 * @brief Advanced camera system for multiplayer Sky Combat
 * 
 * Features:
 * - Smooth aircraft following
 * - Combat-aware positioning
 * - Dynamic FOV adjustments
 * - Transition effects
 * - Multiple camera modes
 */

#include <raylib.h>
#include <stdbool.h>

/** Camera modes */
typedef enum {
    CAMERA_MODE_FOLLOW,      /**< Follow behind aircraft */
    CAMERA_MODE_ORBIT,       /**< Orbit around aircraft */
    CAMERA_MODE_COCKPIT,     /**< First-person view */
    CAMERA_MODE_CINEMATIC,   /**< Cinematic kill cam */
    CAMERA_MODE_FREE,        /**< Free spectator camera */
    CAMERA_MODE_OVERVIEW     /**< Tactical overview */
} camera_mode_t;

/** Camera shake types */
typedef enum {
    SHAKE_NONE = 0,
    SHAKE_LIGHT,             /**< Light turbulence */
    SHAKE_MEDIUM,            /**< Weapon fire */
    SHAKE_HEAVY,             /**< Explosions */
    SHAKE_CRITICAL           /**< Near death */
} camera_shake_t;

/**
 * @brief Camera controller state
 */
typedef struct {
    /* Core camera */
    Camera3D camera;                    /**< Raylib camera */
    camera_mode_t mode;                 /**< Current camera mode */
    
    /* Target tracking */
    Vector3 target_position;            /**< Target to follow */
    Vector3 target_velocity;            /**< Target velocity for prediction */
    float target_speed;                 /**< Target speed for zoom adjustment */
    
    /* Smooth following */
    Vector3 smooth_position;            /**< Smoothed camera position */
    Vector3 smooth_target;              /**< Smoothed look-at target */
    float position_smoothing;           /**< Position smoothing factor (0-1) */
    float rotation_smoothing;           /**< Rotation smoothing factor (0-1) */
    
    /* Dynamic adjustments */
    float base_distance;                /**< Base follow distance */
    float current_distance;             /**< Current follow distance */
    float combat_zoom_factor;           /**< Zoom out during combat */
    float speed_zoom_factor;            /**< Zoom based on speed */
    
    /* Camera shake */
    camera_shake_t shake_type;          /**< Current shake type */
    float shake_intensity;              /**< Shake intensity (0-1) */
    float shake_duration;               /**< Remaining shake time */
    Vector3 shake_offset;               /**< Current shake offset */
    
    /* Transitions */
    bool in_transition;                 /**< Currently transitioning */
    float transition_time;              /**< Transition duration */
    float transition_progress;          /**< Transition progress (0-1) */
    Vector3 transition_start_pos;       /**< Start position for transition */
    Vector3 transition_start_target;    /**< Start target for transition */
    
    /* Mode-specific settings */
    float orbit_angle;                  /**< Angle for orbit mode */
    float orbit_height;                 /**< Height for orbit mode */
    float overview_height;              /**< Height for overview mode */
    
    /* Constraints */
    float min_distance;                 /**< Minimum follow distance */
    float max_distance;                 /**< Maximum follow distance */
    float min_height;                   /**< Minimum camera height */
    float max_pitch;                    /**< Maximum pitch angle */
} camera_controller_t;

/*
 * Core Functions
 */

/**
 * @brief Create a new camera controller
 * @return Allocated camera controller or NULL on failure
 */
camera_controller_t* camera_controller_create(void);

/**
 * @brief Destroy a camera controller
 * @param controller Controller to destroy
 */
void camera_controller_destroy(camera_controller_t* controller);

/**
 * @brief Reset camera to default state
 * @param controller Camera controller
 */
void camera_controller_reset(camera_controller_t* controller);

/*
 * Update Functions
 */

/**
 * @brief Update camera position and orientation
 * @param controller Camera controller
 * @param dt Delta time in seconds
 */
void camera_controller_update(camera_controller_t* controller, float dt);

/**
 * @brief Set target to follow
 * @param controller Camera controller
 * @param position Target position
 * @param velocity Target velocity (for prediction)
 * @param speed Target speed (for zoom adjustment)
 */
void camera_controller_set_target(camera_controller_t* controller,
                                 Vector3 position, Vector3 velocity, float speed);

/**
 * @brief Switch camera mode with transition
 * @param controller Camera controller
 * @param mode New camera mode
 * @param transition_time Time for transition (0 for instant)
 */
void camera_controller_set_mode(camera_controller_t* controller,
                               camera_mode_t mode, float transition_time);

/*
 * Camera Effects
 */

/**
 * @brief Apply camera shake
 * @param controller Camera controller
 * @param type Shake type
 * @param duration Duration in seconds
 */
void camera_controller_shake(camera_controller_t* controller,
                            camera_shake_t type, float duration);

/**
 * @brief Set combat zoom factor
 * @param controller Camera controller
 * @param factor Zoom factor (1.0 = normal, >1.0 = zoom out)
 */
void camera_controller_set_combat_zoom(camera_controller_t* controller, float factor);

/**
 * @brief Enable/disable speed-based zoom
 * @param controller Camera controller
 * @param enabled Enable speed zoom
 */
void camera_controller_set_speed_zoom(camera_controller_t* controller, bool enabled);

/*
 * Camera Control
 */

/**
 * @brief Handle free camera input
 * @param controller Camera controller
 * @param dt Delta time
 */
void camera_controller_free_camera_input(camera_controller_t* controller, float dt);

/**
 * @brief Orbit camera around target
 * @param controller Camera controller
 * @param delta_angle Angle change in degrees
 * @param delta_height Height change
 */
void camera_controller_orbit(camera_controller_t* controller,
                            float delta_angle, float delta_height);

/*
 * Utility Functions
 */

/**
 * @brief Get the active Camera3D for rendering
 * @param controller Camera controller
 * @return Pointer to Camera3D structure
 */
Camera3D* camera_controller_get_camera(camera_controller_t* controller);

/**
 * @brief Check if camera is in transition
 * @param controller Camera controller
 * @return True if transitioning
 */
bool camera_controller_is_transitioning(camera_controller_t* controller);

/**
 * @brief Get camera mode name
 * @param mode Camera mode
 * @return Mode name string
 */
const char* camera_controller_get_mode_name(camera_mode_t mode);

#endif /* SKY_COMBAT_CAMERA_CONTROLLER_H */