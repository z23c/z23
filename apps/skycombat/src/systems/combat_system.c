/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <raylib.h>

void combat_process_damage(int* health, int damage) {
    *health -= damage;
    if (*health < 0) *health = 0;
}

void combat_update_projectiles(float dt) {
    // Update projectile positions and collisions
}