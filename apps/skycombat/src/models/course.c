/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/models/course.h"
#include <raylib.h>
#include <raymath.h>
#include <rlgl.h>
#include <stdlib.h>
#include <math.h>

course_t* course_create(void) {
    course_t* course = calloc(1, sizeof(course_t));
    if (!course) return NULL;
    
    course->ring_count = 0;
    course->name = "Custom Course";
    course->difficulty = 1;
    
    return course;
}

void course_destroy(course_t* course) {
    if (!course) return;
    free(course);
}

void course_load_beginner(course_t* course) {
    if (!course) return;
    course->ring_count = 0;
    course->name = "Beginner Course";
    course->difficulty = 1;
    
    float distance = 200;
    
    // Starting rings - straight line
    for (int i = 0; i < 10 && course->ring_count < MAX_RINGS; i++) {
        course->rings[course->ring_count].position = (Vector3){0, 50, distance};
        course->rings[course->ring_count].color = GOLD;
        course->rings[course->ring_count].points = 100;
        course->rings[course->ring_count].collected = false;
        course->ring_count++;
        distance += 100;
    }
}

void course_load_intermediate(course_t* course) {
    if (!course) return;
    course->ring_count = 0;
    course->name = "Intermediate Course";
    course->difficulty = 2;
    
    float distance = 200;
    
    // Starting rings - straight line
    for (int i = 0; i < 5 && course->ring_count < MAX_RINGS; i++) {
        course->rings[course->ring_count].position = (Vector3){0, 50, distance};
        course->rings[course->ring_count].color = GOLD;
        course->rings[course->ring_count].points = 100;
        course->rings[course->ring_count].collected = false;
        course->ring_count++;
        distance += 100;
    }
    
    // Left turn section
    float angle = 0;
    for (int i = 0; i < 8 && course->ring_count < MAX_RINGS; i++) {
        angle -= 15 * DEG2RAD;  // Turn left
        course->rings[course->ring_count].position = (Vector3){
            sinf(angle) * distance,
            50,
            cosf(angle) * distance
        };
        course->rings[course->ring_count].color = SKYBLUE;
        course->rings[course->ring_count].points = 200;
        course->rings[course->ring_count].collected = false;
        course->ring_count++;
        distance += 80;
    }
    
    // Climb section
    for (int i = 0; i < 6 && course->ring_count < MAX_RINGS; i++) {
        course->rings[course->ring_count].position = (Vector3){
            sinf(angle) * distance,
            50 + i * 25,
            cosf(angle) * distance
        };
        course->rings[course->ring_count].color = LIME;
        course->rings[course->ring_count].points = 300;
        course->rings[course->ring_count].collected = false;
        course->ring_count++;
        distance += 80;
    }
}

void course_load_advanced(course_t* course) {
    if (!course) return;
    course->ring_count = 0;
    course->name = "Advanced Course";
    course->difficulty = 3;
    
    float distance = 200;
    
    // Starting rings
    for (int i = 0; i < 5; i++) {
        course->rings[course->ring_count].position = (Vector3){0, 50, distance};
        course->rings[course->ring_count].color = GOLD;
        course->rings[course->ring_count].points = 100;
        course->rings[course->ring_count].collected = false;
        course->ring_count++;
        distance += 100;
    }
    
    // Complex turn pattern
    float angle = 0;
    for (int i = 0; i < 20 && course->ring_count < MAX_RINGS; i++) {
        angle += sinf(i * 0.3f) * 20 * DEG2RAD;
        float height = 50 + sinf(i * 0.5f) * 50;
        
        course->rings[course->ring_count].position = (Vector3){
            sinf(angle) * distance,
            height,
            cosf(angle) * distance
        };
        course->rings[course->ring_count].color = ColorFromHSV(i * 18, 1, 1);
        course->rings[course->ring_count].points = 250 + i * 25;
        course->rings[course->ring_count].collected = false;
        course->ring_count++;
        distance += 70;
    }
}

void course_load_custom(course_t* course, int id) {
    if (!course) return;
    // Load different layouts based on ID
    switch (id) {
        case 0: course_load_beginner(course); break;
        case 1: course_load_intermediate(course); break;
        case 2: course_load_advanced(course); break;
        default: course_load_intermediate(course); break;
    }
}

void course_draw_rings(course_t* course, float gameTime) {
    if (!course) return;
    for (int i = 0; i < course->ring_count; i++) {
        ring_t* r = &course->rings[i];
        if (r->collected) continue;
        
        // Rotating ring
        rlPushMatrix();
        rlTranslatef(r->position.x, r->position.y, r->position.z);
        rlRotatef(gameTime * 50, 0, 1, 0);
        
        // Draw torus
        int segments = 32;
        float radius = 30;
        float thickness = 4;
        
        for (int j = 0; j < segments; j++) {
            float angle1 = (float)j / segments * 2 * PI;
            float angle2 = (float)(j + 1) / segments * 2 * PI;
            
            Vector3 p1 = {radius * cosf(angle1), radius * sinf(angle1), 0};
            Vector3 p2 = {radius * cosf(angle2), radius * sinf(angle2), 0};
            
            DrawCylinder(p1, thickness, thickness, Vector3Distance(p1, p2), 8, r->color);
        }
        
        // Center marker
        DrawSphere(Vector3Zero(), 8, Fade(r->color, 0.5f));
        
        rlPopMatrix();
    }
}

bool course_check_ring_collection(course_t* course, Vector3 position, float radius) {
    if (!course) return false;
    bool collected_any = false;
    
    for (int i = 0; i < course->ring_count; i++) {
        if (course->rings[i].collected) continue;
        
        float dist = Vector3Distance(position, course->rings[i].position);
        if (dist < radius + 35) {  // 35 is ring radius
            course->rings[i].collected = true;
            collected_any = true;
        }
    }
    
    return collected_any;
}

ring_t* course_get_next_ring(course_t* course) {
    if (!course) return NULL;
    for (int i = 0; i < course->ring_count; i++) {
        if (!course->rings[i].collected) {
            return &course->rings[i];
        }
    }
    return NULL;
}

float course_get_distance_to_next_ring(course_t* course, Vector3 position) {
    if (!course) return -1;
    ring_t* next = course_get_next_ring(course);
    if (!next) return -1;
    
    return Vector3Distance(position, next->position);
}

int course_get_total_score(course_t* course) {
    int total = 0;
    for (int i = 0; i < course->ring_count; i++) {
        if (course->rings[i].collected) {
            total += course->rings[i].points;
        }
    }
    return total;
}

float course_get_completion_percent(course_t* course) {
    if (course->ring_count == 0) return 100.0f;
    
    int collected = 0;
    for (int i = 0; i < course->ring_count; i++) {
        if (course->rings[i].collected) collected++;
    }
    
    return (float)collected / course->ring_count * 100.0f;
}