/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sky Combat: physics integration system.
 */

#include <stdlib.h>
#include <raylib.h>
#include <raymath.h>

void physics_update([[maybe_unused]] float dt) {
    // Physics simulation
}

bool physics_check_collision(Vector3 pos1, float radius1, Vector3 pos2, float radius2) {
    float dist = Vector3Distance(pos1, pos2);
    return dist < (radius1 + radius2);
}
