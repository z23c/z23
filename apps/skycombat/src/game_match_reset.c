/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "sky_combat/models/match_rules.h"
#include "sky_combat/models/aircraft_manager.h"
#include "sky_combat/models/weapons.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool match_state_restart(match_state_t *s) {
    if (!s || !s->match_started || !s->match_ended) {
        fprintf(stderr, "match restart: no finished match\n"); return false;
    }
    match_rules_t rules = s->rules;
    memset(s, 0, sizeof(*s));
    s->rules = rules;
    s->winning_team = -1;
    s->winning_player = -1;
    s->zone_controller = -1;
    return match_state_begin(s);
}

void weapons_reset(weapons_system_t *weapons) {
    if (!weapons) return;
    bullet_t *current = weapons->bullets_head;
    while (current) {
        bullet_t *next = current->next;
        free(current);
        current = next;
    }
    memset(weapons, 0, sizeof(*weapons));
    weapons->current_weapon = WEAPON_MACHINE_GUN;
    weapons->damage_multiplier = 1.0f;
    weapons->fire_rate_multiplier = 1.0f;
    weapons->bend_strength = 450.0f;
    for (int i = 0; i < WEAPON_COUNT; i++) weapons->ammo[i] = -1;
}

void aircraft_manager_reset_match(aircraft_manager_t *manager) {
    if (!manager) return;
    for (int i = 0; i < manager->aircraft_count; ++i) {
        managed_aircraft_t *ma = &manager->aircraft[i];
        char name[AIRCRAFT_NAME_LENGTH];
        memcpy(name, ma->name, sizeof(name));
        Color color = ma->color;
        bool is_ai = ma->is_ai, is_local = ma->is_local_player;
        int id = ma->id, team = ma->team_id;
        float skill = ma->ai_skill, aggression = ma->ai_aggression;
        aircraft_t *aircraft = ma->aircraft;
        weapons_system_t *weapons = ma->weapons;
        memset(ma, 0, sizeof(*ma));
        ma->aircraft = aircraft;
        ma->weapons = weapons;
        ma->target_id = -1;
        memcpy(ma->name, name, sizeof(ma->name));
        ma->color = color;
        ma->is_ai = is_ai;
        ma->is_local_player = is_local;
        ma->id = id;
        ma->team_id = team;
        ma->ai_skill = skill;
        ma->ai_aggression = aggression;
        ma->max_health = 100.0f;
        ma->health = ma->max_health;
        powerup_effects_init(&ma->powerup_effects);
        if (ma->aircraft) {
            memset(ma->aircraft, 0, sizeof(*ma->aircraft));
            ma->aircraft->position = aircraft_manager_get_spawn_point(manager);
            ma->aircraft->speed = AIRCRAFT_BASE_SPEED;
            ma->aircraft->altitude = ma->aircraft->position.y;
        }
        weapons_reset(ma->weapons);
    }
}
