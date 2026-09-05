/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sky Combat: damage and scoring system.
 */

#include <stdlib.h>
#include <raylib.h>

void combat_process_damage(int* health, int damage) {
    *health -= damage;
    if (*health < 0) *health = 0;
}

void combat_update_projectiles([[maybe_unused]] float dt) {
    // Update projectile positions and collisions
}
