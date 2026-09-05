/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_AI_PILOT_H
#define SKY_COMBAT_AI_PILOT_H

#include <raylib.h>
#include <stdbool.h>
#include "../models/aircraft.h"
#include "../models/course.h"
#include "../controllers/input.h"

// Neural network configuration
#define AI_INPUT_SIZE 12      // Observations: position, velocity, ring data
#define AI_HIDDEN_SIZE 64     // Hidden layer neurons
#define AI_OUTPUT_SIZE 4      // Actions: pitch, yaw, boost, brake

// Training parameters
#define AI_LEARNING_RATE 0.001f
#define AI_DISCOUNT_FACTOR 0.95f
#define AI_EPSILON_START 1.0f
#define AI_EPSILON_MIN 0.01f
#define AI_EPSILON_DECAY 0.995f

typedef struct {
    // Neural network weights
    float weights_input_hidden[AI_INPUT_SIZE][AI_HIDDEN_SIZE];
    float weights_hidden_output[AI_HIDDEN_SIZE][AI_OUTPUT_SIZE];
    float bias_hidden[AI_HIDDEN_SIZE];
    float bias_output[AI_OUTPUT_SIZE];
    
    // Training state
    float epsilon;              // Exploration rate
    int episodes_trained;
    float total_reward;
    float best_score;
    
    // Current state
    float last_observation[AI_INPUT_SIZE];
    float last_action[AI_OUTPUT_SIZE];
    bool is_training;
} ai_pilot_t;

// State observation
typedef struct {
    float relative_ring_x;      // Next ring position relative to plane
    float relative_ring_y;
    float relative_ring_z;
    float distance_to_ring;
    float plane_velocity_x;
    float plane_velocity_y;
    float plane_velocity_z;
    float plane_pitch;
    float plane_yaw;
    float plane_roll;
    float plane_altitude;
    float rings_collected_ratio;  // Progress through course
} ai_observation_t;

// AI pilot management
ai_pilot_t* ai_pilot_create(void);
void ai_pilot_destroy(ai_pilot_t* pilot);
void ai_pilot_reset_episode(ai_pilot_t* pilot);
void ai_pilot_end_episode(ai_pilot_t* pilot);

// Neural network operations
void ai_pilot_forward_pass(ai_pilot_t* pilot, const float* input, float* output);
void ai_pilot_backpropagate(ai_pilot_t* pilot, float reward, const float* next_observation);

// Game integration
ai_observation_t ai_pilot_observe_state(aircraft_t* aircraft, course_t* course);
input_state_t ai_pilot_get_action(ai_pilot_t* pilot, ai_observation_t obs, bool training);
void ai_pilot_update_reward(ai_pilot_t* pilot, float reward);

// Training utilities
void ai_pilot_save(ai_pilot_t* pilot, const char* filename);
bool ai_pilot_load(ai_pilot_t* pilot, const char* filename);
void ai_pilot_print_stats(ai_pilot_t* pilot);

#endif // SKY_COMBAT_AI_PILOT_H