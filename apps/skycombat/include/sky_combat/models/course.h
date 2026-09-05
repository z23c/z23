/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SKY_COMBAT_COURSE_H
#define SKY_COMBAT_COURSE_H

#include <raylib.h>
#include <stdbool.h>

#define MAX_RINGS 100

typedef struct {
    Vector3 position;
    Color color;
    bool collected;
    int points;
} ring_t;

typedef struct {
    ring_t rings[MAX_RINGS];
    int ring_count;
    const char* name;
    int difficulty;
} course_t;

// Course management
course_t* course_create(void);
void course_destroy(course_t* course);

// Preset courses
void course_load_beginner(course_t* course);
void course_load_intermediate(course_t* course);
void course_load_advanced(course_t* course);
void course_load_custom(course_t* course, int id);

// Ring operations
void course_draw_rings(course_t* course, float gameTime);
bool course_check_ring_collection(course_t* course, Vector3 position, float radius);
ring_t* course_get_next_ring(course_t* course);
float course_get_distance_to_next_ring(course_t* course, Vector3 position);

// Course queries
int course_get_total_score(course_t* course);
float course_get_completion_percent(course_t* course);

#endif // SKY_COMBAT_COURSE_H