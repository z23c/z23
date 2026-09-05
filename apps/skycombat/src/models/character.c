/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sky Combat: on-foot character model.
 */

#include <stdlib.h>
#include <raylib.h>

typedef struct {
    Vector3 position;
    Vector3 target;
    float speed;
    bool active;
} character_t;

void character_create([[maybe_unused]] Vector3 pos) {
    // Character creation
}

void character_update([[maybe_unused]] float dt) {
    // Character AI update
}

void character_draw(void) {
    // Character rendering
}
