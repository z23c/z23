/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/ai_pilot.h"
#include <raymath.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

// Activation functions
static float relu(float x) {
    return fmaxf(0.0f, x);
}

static float tanh_activation(float x) {
    return tanhf(x);
}

// Random initialization
static float random_weight(void) {
    return ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
}

ai_pilot_t* ai_pilot_create(void) {
    ai_pilot_t* pilot = calloc(1, sizeof(ai_pilot_t));
    if (!pilot) return NULL;
    
    // Initialize weights randomly
    for (int i = 0; i < AI_INPUT_SIZE; i++) {
        for (int j = 0; j < AI_HIDDEN_SIZE; j++) {
            pilot->weights_input_hidden[i][j] = random_weight() * 0.5f;
        }
    }
    
    for (int i = 0; i < AI_HIDDEN_SIZE; i++) {
        for (int j = 0; j < AI_OUTPUT_SIZE; j++) {
            pilot->weights_hidden_output[i][j] = random_weight() * 0.5f;
        }
        pilot->bias_hidden[i] = random_weight() * 0.1f;
    }
    
    for (int i = 0; i < AI_OUTPUT_SIZE; i++) {
        pilot->bias_output[i] = random_weight() * 0.1f;
    }
    
    // Set initial values
    pilot->epsilon = AI_EPSILON_START;  // This is 1.0f
    pilot->is_training = true;
    pilot->episodes_trained = 0;  // Explicitly set to 0
    pilot->best_score = 0.0f;
    pilot->total_reward = 0.0f;
    
    return pilot;
}

void ai_pilot_destroy(ai_pilot_t* pilot) {
    if (!pilot) return;
    free(pilot);
}

void ai_pilot_reset_episode(ai_pilot_t* pilot) {
    if (!pilot) return;
    pilot->total_reward = 0;
    memset(pilot->last_observation, 0, sizeof(pilot->last_observation));
    memset(pilot->last_action, 0, sizeof(pilot->last_action));
}

void ai_pilot_end_episode(ai_pilot_t* pilot) {
    if (!pilot) return;
    // Update epsilon for exploration (decay once per episode)
    if (pilot->is_training) {
        pilot->epsilon = fmaxf(AI_EPSILON_MIN, pilot->epsilon * AI_EPSILON_DECAY);
    }
    
    // Increment episode count
    pilot->episodes_trained++;
}

void ai_pilot_forward_pass(ai_pilot_t* pilot, const float* input, float* output) {
    if (!pilot || !input || !output) return;
    float hidden[AI_HIDDEN_SIZE];
    
    // Input to hidden layer
    for (int i = 0; i < AI_HIDDEN_SIZE; i++) {
        hidden[i] = pilot->bias_hidden[i];
        for (int j = 0; j < AI_INPUT_SIZE; j++) {
            hidden[i] += input[j] * pilot->weights_input_hidden[j][i];
        }
        hidden[i] = relu(hidden[i]);
    }
    
    // Hidden to output layer
    for (int i = 0; i < AI_OUTPUT_SIZE; i++) {
        output[i] = pilot->bias_output[i];
        for (int j = 0; j < AI_HIDDEN_SIZE; j++) {
            output[i] += hidden[j] * pilot->weights_hidden_output[j][i];
        }
        output[i] = tanh_activation(output[i]);  // Output in [-1, 1]
    }
}

ai_observation_t ai_pilot_observe_state(aircraft_t* aircraft, course_t* course) {
    ai_observation_t obs = {0};
    
    if (!aircraft || !course) return obs;
    
    // Get next ring
    ring_t* next_ring = course_get_next_ring(course);
    if (next_ring) {
        // Calculate relative position to next ring
        Vector3 to_ring = Vector3Subtract(next_ring->position, aircraft->position);
        obs.relative_ring_x = to_ring.x;
        obs.relative_ring_y = to_ring.y;
        obs.relative_ring_z = to_ring.z;
        obs.distance_to_ring = Vector3Length(to_ring);
    } else {
        // No more rings - head to finish
        obs.distance_to_ring = 1000.0f;
    }
    
    // Aircraft state
    Vector3 forward = aircraft_get_forward_vector(aircraft);
    Vector3 velocity = Vector3Scale(forward, aircraft->speed);
    obs.plane_velocity_x = velocity.x;
    obs.plane_velocity_y = velocity.y;
    obs.plane_velocity_z = velocity.z;
    
    obs.plane_pitch = aircraft->pitch;
    obs.plane_yaw = aircraft->yaw;
    obs.plane_roll = aircraft->roll;
    obs.plane_altitude = aircraft->altitude;
    
    // Progress
    if (course->ring_count > 0) {
        obs.rings_collected_ratio = (float)aircraft->rings / (float)course->ring_count;
    } else {
        obs.rings_collected_ratio = 0.0f;
    }
    
    return obs;
}

input_state_t ai_pilot_get_action(ai_pilot_t* pilot, ai_observation_t obs, bool training) {
    input_state_t action = {0};
    
    if (!pilot) return action;
    
    // Convert observation to neural network input
    float input[AI_INPUT_SIZE] = {
        obs.relative_ring_x / 100.0f,    // Normalize positions
        obs.relative_ring_y / 100.0f,
        obs.relative_ring_z / 100.0f,
        obs.distance_to_ring / 200.0f,
        obs.plane_velocity_x / 50.0f,
        obs.plane_velocity_y / 50.0f,
        obs.plane_velocity_z / 50.0f,
        obs.plane_pitch / 45.0f,
        obs.plane_yaw / 180.0f,
        obs.plane_roll / 45.0f,
        obs.plane_altitude / 100.0f,
        obs.rings_collected_ratio
    };
    
    // Store observation for learning
    memcpy(pilot->last_observation, input, sizeof(input));
    
    // Epsilon-greedy exploration during training
    if (training && pilot->is_training && ((float)rand() / RAND_MAX) < pilot->epsilon) {
        // Random action
        action.move_x = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
        action.move_y = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
        action.speed_boost = rand() % 2;
        action.brake = rand() % 2;
        
        pilot->last_action[0] = action.move_x;
        pilot->last_action[1] = action.move_y;
        pilot->last_action[2] = action.speed_boost ? 1.0f : 0.0f;
        pilot->last_action[3] = action.brake ? 1.0f : 0.0f;
    } else {
        // Neural network action
        float output[AI_OUTPUT_SIZE];
        ai_pilot_forward_pass(pilot, input, output);
        
        action.move_x = output[0];  // Yaw control [-1, 1]
        action.move_y = output[1];  // Pitch control [-1, 1]
        action.speed_boost = output[2] > 0.5f;
        action.brake = output[3] > 0.5f;
        
        memcpy(pilot->last_action, output, sizeof(output));
    }
    
    return action;
}

void ai_pilot_backpropagate(ai_pilot_t* pilot, float reward, const float* next_observation) {
    if (!pilot || !next_observation) return;
    
    // Simple gradient descent update (simplified for demonstration)
    // In a real implementation, you'd want Q-learning or policy gradients
    
    float output[AI_OUTPUT_SIZE];
    float hidden[AI_HIDDEN_SIZE];
    float error[AI_OUTPUT_SIZE];
    
    // Forward pass to get current values
    for (int i = 0; i < AI_HIDDEN_SIZE; i++) {
        hidden[i] = pilot->bias_hidden[i];
        for (int j = 0; j < AI_INPUT_SIZE; j++) {
            hidden[i] += pilot->last_observation[j] * pilot->weights_input_hidden[j][i];
        }
        hidden[i] = relu(hidden[i]);
    }
    
    for (int i = 0; i < AI_OUTPUT_SIZE; i++) {
        output[i] = pilot->bias_output[i];
        for (int j = 0; j < AI_HIDDEN_SIZE; j++) {
            output[i] += hidden[j] * pilot->weights_hidden_output[j][i];
        }
        output[i] = tanh_activation(output[i]);
    }
    
    // Calculate error based on reward
    for (int i = 0; i < AI_OUTPUT_SIZE; i++) {
        error[i] = reward * (pilot->last_action[i] - output[i]);
    }
    
    // Update output layer weights
    for (int i = 0; i < AI_HIDDEN_SIZE; i++) {
        for (int j = 0; j < AI_OUTPUT_SIZE; j++) {
            pilot->weights_hidden_output[i][j] += AI_LEARNING_RATE * error[j] * hidden[i];
        }
    }
    
    // Update output biases
    for (int i = 0; i < AI_OUTPUT_SIZE; i++) {
        pilot->bias_output[i] += AI_LEARNING_RATE * error[i];
    }
}

void ai_pilot_update_reward(ai_pilot_t* pilot, float reward) {
    pilot->total_reward += reward;
    
    // NOTE: Epsilon decay should be done once per episode, not per frame
    // The epsilon decay has been moved to a separate function
}

void ai_pilot_save(ai_pilot_t* pilot, const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (!file) return;
    
    // Save network weights and training state
    fwrite(pilot->weights_input_hidden, sizeof(pilot->weights_input_hidden), 1, file);
    fwrite(pilot->weights_hidden_output, sizeof(pilot->weights_hidden_output), 1, file);
    fwrite(pilot->bias_hidden, sizeof(pilot->bias_hidden), 1, file);
    fwrite(pilot->bias_output, sizeof(pilot->bias_output), 1, file);
    fwrite(&pilot->episodes_trained, sizeof(pilot->episodes_trained), 1, file);
    fwrite(&pilot->best_score, sizeof(pilot->best_score), 1, file);
    
    fclose(file);
    printf("AI Pilot saved to %s\n", filename);
}

bool ai_pilot_load(ai_pilot_t* pilot, const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) return false;
    
    // Load network weights and training state
    fread(pilot->weights_input_hidden, sizeof(pilot->weights_input_hidden), 1, file);
    fread(pilot->weights_hidden_output, sizeof(pilot->weights_hidden_output), 1, file);
    fread(pilot->bias_hidden, sizeof(pilot->bias_hidden), 1, file);
    fread(pilot->bias_output, sizeof(pilot->bias_output), 1, file);
    fread(&pilot->episodes_trained, sizeof(pilot->episodes_trained), 1, file);
    fread(&pilot->best_score, sizeof(pilot->best_score), 1, file);
    
    fclose(file);
    printf("AI Pilot loaded from %s\n", filename);
    return true;
}

void ai_pilot_print_stats(ai_pilot_t* pilot) {
    printf("AI Pilot Stats:\n");
    printf("  Episodes: %d\n", pilot->episodes_trained);
    printf("  Best Score: %.1f\n", pilot->best_score);
    printf("  Current Reward: %.1f\n", pilot->total_reward);
    printf("  Epsilon: %.3f\n", pilot->epsilon);
}