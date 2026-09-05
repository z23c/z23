/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Headless coverage for the Sky Combat models under apps/skycombat: the
 * aircraft flight step, the world wrap that keeps it inside the arena, and
 * the weapon cooldown clock. No window is opened and no frame is drawn.
 *
 * The imported game's own headless runners (src/models/test_*.c) each carry a
 * main() and print rather than assert, so their intent is ported here instead
 * of linked: fixed inputs, fixed dt, and a stated expectation per step.
 *
 * Shape follows tests/harness/src/test_arena_view.c: the model sources are
 * #included into this translation unit rather than linked, so the group needs
 * no new object in the node's link set. That also means these two files are
 * compiled at the NODE flag set, -Wdouble-promotion and all, not at the looser
 * application set apps/ uses - which is a stronger bar than `make game-check`
 * holds them to.
 *
 * aircraft.c reaches for nothing outside libc and libm. weapons.c calls seven
 * raylib entry points, all of them draw or clock calls, and this file defines
 * those seven and nothing else: DrawSphere, DrawCapsule, DrawCylinderEx,
 * DrawLine3D, Fade, GetRandomValue and GetTime. The three that return a value
 * return a fixed one, so every assertion below is deterministic; the four that
 * draw do nothing. If the models ever start calling an eighth, the link fails
 * and names it, which is the point of stubbing exactly this list.
 *
 * Pure and deterministic: no clock, no RNG, no I/O, no live DB. */

#include "test/test_core.h"

#include <math.h>

/* raymath.h picks its implementation on this macro and warns under -Wundef if
 * it is merely absent. Spelled out here so the node flag set stays intact. */
#define RAYMATH_USE_SIMD_INTRINSICS 0

#include <raylib.h>
#include <raymath.h>

/* ── the seven raylib entry points weapons.c reaches for ──────────────────
 *
 * Defined as file-static under private names, and redirected with #define
 * AFTER <raylib.h> has been read, so this file exports none of the seven.
 * That is not tidiness: the first version defined a plain `GetTime` and the
 * harness link failed on "multiple definition of 'GetTime'" against
 * core/modules/core/src/utiltime.c. A test shim must not be able to collide
 * with a node symbol, whatever raylib decides to call things next.
 *
 * The three that return a value return a fixed one, so every assertion below
 * is deterministic; the four that draw do nothing. If the models ever start
 * calling an eighth, the link fails and names it, which is the point of
 * stubbing exactly this list. */

static double skycombat_stub_time = 0.0;

static double skycombat_stub_GetTime(void) { return skycombat_stub_time; }
static int skycombat_stub_GetRandomValue(int lo, int hi) { return lo + (hi - lo) / 2; }
static Color skycombat_stub_Fade(Color c, float a) { (void)a; return c; }
static void skycombat_stub_DrawSphere(Vector3 c, float r, Color t)
{ (void)c; (void)r; (void)t; }
static void skycombat_stub_DrawCapsule(Vector3 a, Vector3 b, float r, int s, int n, Color t)
{ (void)a; (void)b; (void)r; (void)s; (void)n; (void)t; }
static void skycombat_stub_DrawCylinderEx(Vector3 a, Vector3 b, float rt, float rb, int s, Color t)
{ (void)a; (void)b; (void)rt; (void)rb; (void)s; (void)t; }
static void skycombat_stub_DrawLine3D(Vector3 a, Vector3 b, Color t)
{ (void)a; (void)b; (void)t; }

#define GetTime skycombat_stub_GetTime
#define GetRandomValue skycombat_stub_GetRandomValue
#define Fade skycombat_stub_Fade
#define DrawSphere skycombat_stub_DrawSphere
#define DrawCapsule skycombat_stub_DrawCapsule
#define DrawCylinderEx skycombat_stub_DrawCylinderEx
#define DrawLine3D skycombat_stub_DrawLine3D

#include "../../../apps/skycombat/src/models/aircraft.c"
#include "../../../apps/skycombat/src/models/weapons.c"

int test_skycombat_models(void);
int test_skycombat_models(void)
{
    int failures = 0;

    /* ───────────────────────── aircraft physics ───────────────────────── */

    TEST("aircraft_create: starts at the requested point, level and unscored") {
        aircraft_t *a = aircraft_create((Vector3){ 1.0f, 200.0f, -3.0f });
        ASSERT(a != NULL);
        ASSERT_EQ(a->position.x, 1.0f);
        ASSERT_EQ(a->position.y, 200.0f);
        ASSERT_EQ(a->position.z, -3.0f);
        ASSERT_EQ(a->altitude, 200.0f);
        ASSERT_EQ(a->yaw, 0.0f);
        ASSERT_EQ(a->pitch, 0.0f);
        ASSERT_EQ(a->roll, 0.0f);
        ASSERT_EQ(a->score, 0);
        ASSERT_EQ(a->speed, AIRCRAFT_BASE_SPEED);
        aircraft_destroy(a);
    }

    TEST("aircraft_update: neutral stick flies forward along +Z") {
        aircraft_t *a = aircraft_create((Vector3){ 0.0f, 200.0f, 0.0f });
        ASSERT(a != NULL);
        aircraft_update(a, 0.0f, 0.0f, 1.0f / 60.0f);
        /* yaw 0, pitch 0 => forward is +Z, so z grows and x does not move */
        ASSERT(a->position.z > 0.0f);
        ASSERT(fabsf(a->position.x) < 1e-4f);
        ASSERT_EQ(a->yaw, 0.0f);
        aircraft_destroy(a);
    }

    TEST("aircraft_update: the step is proportional to dt") {
        aircraft_t *one = aircraft_create((Vector3){ 0.0f, 200.0f, 0.0f });
        aircraft_t *two = aircraft_create((Vector3){ 0.0f, 200.0f, 0.0f });
        ASSERT(one != NULL);
        ASSERT(two != NULL);
        aircraft_update(one, 0.0f, 0.0f, 0.05f);
        aircraft_update(two, 0.0f, 0.0f, 0.10f);
        ASSERT(fabsf(two->position.z - 2.0f * one->position.z) < 1e-3f);
        aircraft_destroy(one);
        aircraft_destroy(two);
    }

    TEST("aircraft_update: stick sign sets the turn, and banks the other way") {
        aircraft_t *l = aircraft_create((Vector3){ 0.0f, 200.0f, 0.0f });
        aircraft_t *r = aircraft_create((Vector3){ 0.0f, 200.0f, 0.0f });
        ASSERT(l != NULL);
        ASSERT(r != NULL);
        aircraft_update(l, -1.0f, 0.0f, 1.0f / 60.0f);   /* stick left */
        aircraft_update(r, 1.0f, 0.0f, 1.0f / 60.0f);    /* stick right */
        ASSERT(l->yaw < 0.0f);
        ASSERT(r->yaw > 0.0f);
        ASSERT(l->roll > 0.0f);
        ASSERT(r->roll < 0.0f);
        aircraft_destroy(l);
        aircraft_destroy(r);
    }

    TEST("wrapped flight holds the ceiling and the floor") {
        /* aircraft_update() integrates without a bound; aircraft_wrap_position()
         * is where the arena's ceiling and floor live, and the game loop calls
         * them as a pair. Assert the pair, which is the invariant that matters. */
        aircraft_t *a = aircraft_create((Vector3){ 0.0f, 200.0f, 0.0f });
        ASSERT(a != NULL);
        for (int i = 0; i < 2000; i++) {                     /* climb, hard */
            aircraft_update(a, 0.0f, -1.0f, 1.0f / 60.0f);
            aircraft_wrap_position(a);
            ASSERT(a->position.y <= WORLD_MAX_HEIGHT);
            ASSERT(a->position.y >= WORLD_MIN_HEIGHT);
        }
        ASSERT_EQ(a->position.y, WORLD_MAX_HEIGHT);
        for (int i = 0; i < 4000; i++) {                     /* dive, hard */
            aircraft_update(a, 0.0f, 1.0f, 1.0f / 60.0f);
            aircraft_wrap_position(a);
            ASSERT(a->position.y <= WORLD_MAX_HEIGHT);
            ASSERT(a->position.y >= WORLD_MIN_HEIGHT);
        }
        ASSERT_EQ(a->position.y, WORLD_MIN_HEIGHT);
        aircraft_destroy(a);
    }

    TEST("aircraft_update: speed stays between the model's own bounds") {
        aircraft_t *a = aircraft_create((Vector3){ 0.0f, 200.0f, 0.0f });
        ASSERT(a != NULL);
        for (int i = 0; i < 600; i++) {
            aircraft_boost(a, 1.0f / 60.0f);
            aircraft_update(a, 0.0f, 0.0f, 1.0f / 60.0f);
            ASSERT(a->speed <= AIRCRAFT_MAX_SPEED);
            ASSERT(a->speed >= AIRCRAFT_MIN_SPEED);
        }
        for (int i = 0; i < 600; i++) {
            aircraft_brake(a, 1.0f / 60.0f);
            aircraft_update(a, 0.0f, 0.0f, 1.0f / 60.0f);
            ASSERT(a->speed <= AIRCRAFT_MAX_SPEED);
            ASSERT(a->speed >= AIRCRAFT_MIN_SPEED);
        }
        aircraft_destroy(a);
    }

    /* ────────────────────────── world bounds ──────────────────────────── */

    TEST("aircraft_wrap_position: leaving one edge arrives at the other") {
        aircraft_t *a = aircraft_create((Vector3){ WORLD_HALF_SIZE + 5.0f,
                                                   200.0f, 0.0f });
        ASSERT(a != NULL);
        aircraft_wrap_position(a);
        ASSERT(a->position.x < 0.0f);
        ASSERT(a->position.x >= -WORLD_HALF_SIZE);
        a->position.z = -WORLD_HALF_SIZE - 5.0f;
        aircraft_wrap_position(a);
        ASSERT(a->position.z > 0.0f);
        ASSERT(a->position.z <= WORLD_HALF_SIZE);
        aircraft_destroy(a);
    }

    TEST("aircraft_wrap_position: a point inside the arena is left alone") {
        aircraft_t *a = aircraft_create((Vector3){ 10.0f, 200.0f, -20.0f });
        ASSERT(a != NULL);
        aircraft_wrap_position(a);
        ASSERT_EQ(a->position.x, 10.0f);
        ASSERT_EQ(a->position.z, -20.0f);
        aircraft_destroy(a);
    }

    TEST("aircraft_wrap_position: flying straight never escapes the arena") {
        aircraft_t *a = aircraft_create((Vector3){ 0.0f, 200.0f, 0.0f });
        ASSERT(a != NULL);
        for (int i = 0; i < 5000; i++) {
            aircraft_update(a, 0.0f, 0.0f, 1.0f / 60.0f);
            aircraft_wrap_position(a);
            ASSERT(a->position.x >= -WORLD_HALF_SIZE);
            ASSERT(a->position.x <= WORLD_HALF_SIZE);
            ASSERT(a->position.z >= -WORLD_HALF_SIZE);
            ASSERT(a->position.z <= WORLD_HALF_SIZE);
        }
        aircraft_destroy(a);
    }

    /* ───────────────────────── weapon cooldown ────────────────────────── */

    TEST("weapons_create: every weapon starts ready to fire") {
        weapons_system_t *w = weapons_create();
        ASSERT(w != NULL);
        for (int i = 0; i < WEAPON_COUNT; i++)
            ASSERT_EQ(w->fire_cooldown[i], 0.0f);
        ASSERT(weapons_can_fire(w, WEAPON_MISSILES));
        ASSERT(weapons_can_fire(w, WEAPON_LASER));
        weapons_destroy(w);
    }

    TEST("weapons_can_fire: a cooldown blocks the shot until it runs out") {
        weapons_system_t *w = weapons_create();
        ASSERT(w != NULL);
        w->fire_cooldown[WEAPON_MISSILES] = 0.5f;
        ASSERT(!weapons_can_fire(w, WEAPON_MISSILES));
        /* other weapons are unaffected */
        ASSERT(weapons_can_fire(w, WEAPON_LASER));
        for (int i = 0; i < 29; i++)
            weapons_update(w, 1.0f / 60.0f);
        ASSERT(!weapons_can_fire(w, WEAPON_MISSILES));
        for (int i = 0; i < 3; i++)
            weapons_update(w, 1.0f / 60.0f);
        ASSERT(weapons_can_fire(w, WEAPON_MISSILES));
        weapons_destroy(w);
    }

    TEST("weapons_update: a cooldown falls by exactly dt and stops at zero") {
        weapons_system_t *w = weapons_create();
        ASSERT(w != NULL);
        w->fire_cooldown[WEAPON_RAILGUN] = 1.0f;
        weapons_update(w, 0.25f);
        ASSERT(fabsf(w->fire_cooldown[WEAPON_RAILGUN] - 0.75f) < 1e-5f);
        weapons_update(w, 10.0f);
        ASSERT(w->fire_cooldown[WEAPON_RAILGUN] <= 0.0f);
        weapons_update(w, 10.0f);
        ASSERT(w->fire_cooldown[WEAPON_RAILGUN] <= 0.0f);
        ASSERT(weapons_can_fire(w, WEAPON_RAILGUN));
        weapons_destroy(w);
    }

    TEST("weapons_update: no missile outlives its lifetime") {
        weapons_system_t *w = weapons_create();
        ASSERT(w != NULL);
        weapons_fire_missile(w, (Vector3){ 0.0f, 200.0f, 0.0f },
                             (Vector3){ 0.0f, 0.0f, -1.0f }, 0.0f, -1, NULL);
        int live = 0;
        for (int i = 0; i < MAX_MISSILES; i++)
            if (w->missiles[i].active) live++;
        ASSERT_EQ(live, 1);
        for (int i = 0; i < 3600; i++)
            weapons_update(w, 1.0f / 60.0f);
        live = 0;
        for (int i = 0; i < MAX_MISSILES; i++)
            if (w->missiles[i].active) live++;
        ASSERT_EQ(live, 0);
        weapons_destroy(w);
    }

_test_next:;
    if (failures == 0)
        printf("test_skycombat_models: all passed\n");
    else
        printf("test_skycombat_models: %d FAILED\n", failures);
    return failures;
}
