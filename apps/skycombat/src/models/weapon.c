/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <raylib.h>

typedef struct {
    Vector3 position;
    Vector3 velocity;
    bool active;
    float lifetime;
} projectile_t;

void weapon_fire_gun(Vector3 pos, Vector3 dir) {
    // Fire gun projectile
}

void weapon_fire_missile(Vector3 pos, Vector3 dir) {
    // Fire missile
}

void weapon_update_projectiles(float dt) {
    // Update all projectiles
}