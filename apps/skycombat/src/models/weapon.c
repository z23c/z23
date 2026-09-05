/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sky Combat: single-weapon model.
 */

#include <stdlib.h>
#include <raylib.h>

typedef struct {
    Vector3 position;
    Vector3 velocity;
    bool active;
    float lifetime;
} projectile_t;

void weapon_fire_gun([[maybe_unused]] Vector3 pos,[[maybe_unused]] Vector3 dir) {
    // Fire gun projectile
}

void weapon_fire_missile([[maybe_unused]] Vector3 pos,[[maybe_unused]] Vector3 dir) {
    // Fire missile
}

void weapon_update_projectiles([[maybe_unused]] float dt) {
    // Update all projectiles
}
