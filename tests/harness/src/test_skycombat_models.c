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
 * no new object in the node's link set. The included model sources are
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
 * Deterministic models use no live clock, RNG, devices or DB. The document
 * oracle reads only docs/commons/GAME.md as a bounded public source fixture. */

#include "test/test_core.h"

#include <math.h>
#include <float.h>
#include <limits.h>

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
static bool skycombat_stub_random_min;
static int skycombat_stub_GetRandomValue(int lo, int hi)
{ return skycombat_stub_random_min ? lo : lo + (hi - lo) / 2; }
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
#include "../../../apps/skycombat/src/models/match_rules.c"

/* Inspect the argument before variadic promotion. The explicit conversion in
 * this seam lets a removed production cast compile, then fail the type check
 * through the real collection caller instead of failing compilation. */
static unsigned skycombat_collect_messages;
static bool skycombat_collect_double;
static char skycombat_collect_message[128];
static int skycombat_powerup_printf(const char *format, const char *name,
                                   bool explicit_double, double value)
{
    if (strcmp(format, "Spawned %s powerup at spawn point %d\n") == 0)
        return printf("Spawned %s powerup at spawn point %d\n", name, (int)value);
    ++skycombat_collect_messages;
    skycombat_collect_double = explicit_double;
    return snprintf(skycombat_collect_message, sizeof(skycombat_collect_message),
                    format, name, value);
}
#define printf(format, name, value) \
    skycombat_powerup_printf((format), (name), \
                            _Generic((value), double: true, default: false), (double)(value))
#include "../../../apps/skycombat/src/models/powerups.c"
#undef printf

static int skycombat_collect_diagnostic_tests(void)
{
    int failures = 0;
    powerup_manager_t m = {0};
    m.powerup_count = 1;
    m.spawn_point_count = 1;
    m.spawn_points[0].respawn_time = 7.5f;
    m.powerups[0].type = POWERUP_HEALTH;
    m.powerups[0].active = true;
    m.powerups[0].spawn_point_id = 0;
    skycombat_collect_messages = 0;
    TEST("pickups: collection diagnostic supplies double and preserves custom timer") {
        powerup_manager_collect(&m, 0);
        ASSERT_EQ(skycombat_collect_messages, 1);
        ASSERT(skycombat_collect_double);
        ASSERT(strcmp(skycombat_collect_message,
                      "Collected Health powerup (respawn in 7.5s)\n") == 0);
        ASSERT(!m.powerups[0].active);
        ASSERT_EQ(m.powerups[0].respawn_timer, 7.5f);
        PASS();
    }
    TEST("pickups: collision collection diagnostic supplies double for default timer") {
        m.powerups[0].active = true;
        m.powerups[0].spawn_point_id = -1;
        skycombat_collect_messages = 0;
        ASSERT(powerup_manager_check_collection(&m, (Vector3){0}, 1.0f, NULL));
        ASSERT_EQ(skycombat_collect_messages, 1);
        ASSERT(skycombat_collect_double);
        ASSERT(strcmp(skycombat_collect_message,
                      "Collected Health powerup (respawn in 20.0s)\n") == 0);
        ASSERT(!m.powerups[0].active);
        ASSERT_EQ(m.powerups[0].respawn_timer, 20.0f);
        PASS();
    }
_test_next:;
    return failures;
}

static int skycombat_pickup_active(const powerup_manager_t *m, int point)
{
    int count = 0;
    for (int i = 0; i < m->powerup_count; i++)
        if (m->powerups[i].active && m->powerups[i].spawn_point_id == point) count++;
    return count;
}

static int skycombat_pickup_time_tests(bool update)
{
    int failures = 0;
    const float invalid[] = {NAN, INFINITY, -INFINITY, -1.0f};
    powerup_manager_t m = {0}, before;
    m.spawn_check_interval = 5.0f;
    powerup_manager_add_spawn_point(&m, (Vector3){10, 20, 30}, POWERUP_HEALTH, 20.0f);
    powerup_manager_spawn_at_point(&m, 0);
    powerup_manager_collect(&m, 0);
    memcpy(&before, &m, sizeof(before));
    TEST(update ? "pickups: invalid timestep preserves pending reservation and all state"
                : "pickups: invalid cooldown refuses append and preserves all state") {
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
            if (update) powerup_manager_update(&m, invalid[i]);
            else powerup_manager_add_spawn_point(&m, (Vector3){100, 20, 30}, POWERUP_SHIELD, invalid[i]);
            ASSERT(memcmp(&before, &m, sizeof(m)) == 0);
        }
        PASS();
    }
_test_next:;
    return failures;
}

static int skycombat_pickup_tests(void)
{
    int failures = 0;
    powerup_manager_t m = {0};
    m.spawn_check_interval = 5.0f;
    skycombat_stub_random_min = true;
    powerup_manager_add_spawn_point(&m, (Vector3){10, 20, 30}, POWERUP_HEALTH, 20.0f);
    TEST("pickups: periodic, direct and random spawn respect the respawn deadline") {
        powerup_manager_update(&m, 5.0f);
        ASSERT_EQ(m.powerup_count, 1); ASSERT_EQ(skycombat_pickup_active(&m, 0), 1);
        powerup_manager_collect(&m, 0);
        ASSERT_EQ(m.powerups[0].respawn_timer, 20.0f);
        powerup_manager_spawn_at_point(&m, 0); powerup_manager_spawn_random(&m);
        ASSERT(!m.powerups[0].active); ASSERT_EQ(m.powerups[0].respawn_timer, 20.0f);
        powerup_manager_update(&m, 0.0f); powerup_manager_update(&m, 5.0f);
        ASSERT(!m.powerups[0].active); ASSERT_EQ(m.powerups[0].respawn_timer, 15.0f);
        powerup_manager_update(&m, 14.0f);
        ASSERT(!m.powerups[0].active); ASSERT_EQ(m.powerups[0].respawn_timer, 1.0f);
        m.spawn_check_timer = m.spawn_check_interval;
        powerup_manager_update(&m, 1.0f);
        ASSERT_EQ(m.powerup_count, 1); ASSERT_EQ(skycombat_pickup_active(&m, 0), 1);
        ASSERT_EQ(m.powerups[0].position.x, 10.0f);
        ASSERT_EQ(m.powerups[0].position.y, 20.0f); ASSERT_EQ(m.powerups[0].position.z, 30.0f);
        powerup_manager_spawn_at_point(&m, 0);
        ASSERT_EQ(m.powerup_count, 1); ASSERT_EQ(skycombat_pickup_active(&m, 0), 1); PASS();
    }
    TEST("pickups: an unrelated point cannot steal a pending slot") {
        memset(&m, 0, sizeof(m)); m.spawn_check_interval = 5.0f;
        powerup_manager_add_spawn_point(&m, (Vector3){10, 20, 30}, POWERUP_HEALTH, 20.0f);
        powerup_manager_add_spawn_point(&m, (Vector3){100, 20, 30}, POWERUP_SHIELD, 20.0f);
        powerup_manager_spawn_at_point(&m, 0); powerup_manager_collect(&m, 0);
        powerup_manager_update(&m, 5.0f);
        ASSERT_EQ(m.powerup_count, 2); ASSERT(!m.powerups[0].active);
        ASSERT_EQ(m.powerups[0].spawn_point_id, 0); ASSERT_EQ(m.powerups[0].respawn_timer, 15.0f);
        ASSERT_EQ(skycombat_pickup_active(&m, 0), 0); ASSERT_EQ(skycombat_pickup_active(&m, 1), 1);
        powerup_manager_update(&m, 15.0f);
        ASSERT_EQ(skycombat_pickup_active(&m, 0), 1); ASSERT_EQ(skycombat_pickup_active(&m, 1), 1); PASS();
    }
    TEST("pickups: a full pool refuses reserved slots but reuses a free slot") {
        memset(&m, 0, sizeof(m)); m.spawn_check_interval = 5.0f;
        powerup_manager_add_spawn_point(&m, (Vector3){10, 20, 30}, POWERUP_HEALTH, 20.0f);
        powerup_manager_add_spawn_point(&m, (Vector3){100, 20, 30}, POWERUP_SHIELD, 20.0f);
        m.powerup_count = 32;
        for (int i = 0; i < 32; i++) {
            m.powerups[i].spawn_point_id = -1; m.powerups[i].respawn_timer = 20.0f;
        }
        m.powerups[0].spawn_point_id = 0;
        powerup_manager_update(&m, 5.0f);
        ASSERT_EQ(m.powerup_count, 32); ASSERT_EQ(skycombat_pickup_active(&m, 1), 0);
        for (int i = 0; i < 32; i++) {
            ASSERT(!m.powerups[i].active); ASSERT_EQ(m.powerups[i].respawn_timer, 15.0f);
        }
        m.powerups[31].respawn_timer = 0.0f; powerup_manager_spawn_at_point(&m, 1);
        ASSERT_EQ(m.powerup_count, 32); ASSERT(m.powerups[31].active);
        ASSERT_EQ(m.powerups[31].spawn_point_id, 1); ASSERT_EQ(m.powerups[0].respawn_timer, 15.0f);
        powerup_manager_update(&m, 15.0f);
        ASSERT_EQ(skycombat_pickup_active(&m, 0), 1); ASSERT_EQ(skycombat_pickup_active(&m, 1), 1); PASS();
    }
_test_next:;
    skycombat_stub_random_min = false;
    return failures;
}

static int skycombat_match_lifecycle_tests(void)
{
    int failures = 0;
    match_state_t *s = match_state_create(MATCH_TYPE_TEAM_DEATHMATCH);
    ASSERT(s != NULL);
    match_state_t before; memcpy(&before, s, sizeof(before));
    int scores[4] = {2, 3, 0, 0}, winner = 99;
    bool team = false;
    TEST("match: unstarted ledger refuses progress, finish and snapshots") {
        match_state_update(s, 2.0f); match_add_score(s, 0, 0, 1);
        ASSERT(!match_state_set_team_scores(s, scores)); ASSERT(!match_state_finish(s));
        ASSERT(!match_check_win_condition(s, &winner, &team)); ASSERT_EQ(winner, 99);
        ASSERT(memcmp(s, &before, sizeof(before)) == 0); PASS();
    }
    TEST("match: begin once, tick and invalid timestep preserve state") {
        ASSERT(match_state_begin(s)); memcpy(&before, s, sizeof(before));
        ASSERT(!match_state_begin(s)); ASSERT(memcmp(s, &before, sizeof(before)) == 0);
        match_state_update(s, -1.0f); match_state_update(s, NAN); match_state_update(s, INFINITY);
        ASSERT(memcmp(s, &before, sizeof(before)) == 0);
        match_state_update(s, 2.0f); ASSERT_EQ(s->elapsed_time, 2.0f); PASS();
    }
    TEST("match: snapshots commit together; invalid inactive teams refuse") {
        ASSERT(match_state_set_team_scores(s, scores)); ASSERT_EQ(s->team_scores[1], 3);
        ASSERT(match_state_set_team_scores(s, s->team_scores));
        memcpy(&before, s, sizeof(before)); scores[2] = 1;
        ASSERT(!match_state_set_team_scores(s, scores)); ASSERT(memcmp(s, &before, sizeof(before)) == 0);
        scores[2] = 0; scores[0] = -1;
        ASSERT(!match_state_set_team_scores(s, scores)); ASSERT(memcmp(s, &before, sizeof(before)) == 0);
        scores[0] = 30; scores[1] = 30; ASSERT(match_state_set_team_scores(s, scores));
        ASSERT(match_is_over(s)); ASSERT_EQ(s->winning_team, -1);
        ASSERT(match_check_win_condition(s, &winner, &team)); ASSERT(team); ASSERT_EQ(winner, -1);
        memcpy(&before, s, sizeof(before)); match_state_update(s, 3.0f); match_add_score(s, 0, 0, 2);
        ASSERT(!match_state_set_team_scores(s, scores)); ASSERT(!match_state_finish(s));
        ASSERT(memcmp(s, &before, sizeof(before)) == 0); PASS();
    }
_test_next:;
    match_state_destroy(s);
    return failures;
}

static int skycombat_match_bounds_tests(void)
{
    int failures = 0;
    match_state_t *s = match_state_create(MATCH_TYPE_TEAM_DEATHMATCH);
    ASSERT(s != NULL);
    TEST("match: invalid creation/rules, score overflow and timeout winner") {
        ASSERT(match_state_create((match_type_t)-1) == NULL);
        ASSERT(match_state_create((match_type_t)99) == NULL);
        s->rules.team_count = 5; match_state_t before; memcpy(&before, s, sizeof(before));
        ASSERT(!match_state_begin(s)); ASSERT(memcmp(s, &before, sizeof(before)) == 0);
        s->rules.team_count = 2; ASSERT(match_state_begin(s));
        s->team_scores[0] = INT_MAX; memcpy(&before, s, sizeof(before)); match_add_score(s, 0, 0, 1);
        ASSERT(memcmp(s, &before, sizeof(before)) == 0);
        s->team_scores[0] = INT_MIN; memcpy(&before, s, sizeof(before)); match_add_score(s, 0, 0, -1);
        ASSERT(memcmp(s, &before, sizeof(before)) == 0);
        s->elapsed_time = FLT_MAX; memcpy(&before, s, sizeof(before)); match_state_update(s, FLT_MAX);
        ASSERT(memcmp(s, &before, sizeof(before)) == 0);
        s->elapsed_time = 0; s->team_scores[0] = 2; s->team_scores[1] = 4;
        s->rules.time_limit = 1.0f; match_state_update(s, 1.0f);
        ASSERT(match_is_over(s)); ASSERT_EQ(s->winning_team, 1); PASS();
    }
_test_next:;
    match_state_destroy(s);
    return failures;
}

/* Observe only the new bullets, not internal pattern state. */
static bool skycombat_gun_shot(weapons_system_t *w, int count, int right_count)
{
    const Vector3 origin = {100, 200, 300}, direction = {0, 0, 1};
    bullet_t *old_head = w->bullets_head;
    int old_count = w->bullet_count;
    weapons_fire_bullet(w, origin, direction, 0.0f);
    int seen = 0, right = 0;
    for (bullet_t *b = w->bullets_head; b != old_head; b = b->next) {
        if (!b || seen >= count) return false;
        float dx = b->position.x - origin.x;
        if (fabsf(fabsf(dx) - 8.0f) > 0.0001f ||
            b->position.y != origin.y || b->position.z != origin.z) return false;
        if (dx > 0) right++;
        if (w->current_upgrade == WEAPON_UPGRADE_NONE &&
            (b->velocity.x != 0 || b->velocity.y != 0 || b->velocity.z != BULLET_SPEED)) return false;
        seen++;
    }
    return seen == count && right == right_count && w->bullet_count == old_count + count;
}

static int skycombat_gun_pattern_tests(void)
{
    int failures = 0;
    weapons_system_t *a = weapons_create(), *b = weapons_create(), *reference = weapons_create();
    ASSERT(a && b && reference);
    TEST("guns: fresh systems and interleaving preserve each wing cycle") {
        ASSERT(skycombat_gun_shot(a, 1, 1)); ASSERT(skycombat_gun_shot(b, 1, 1));
        ASSERT(skycombat_gun_shot(reference, 1, 1));
        ASSERT(skycombat_gun_shot(reference, 1, 0)); ASSERT(skycombat_gun_shot(reference, 2, 1));
        ASSERT(skycombat_gun_shot(reference, 1, 1));
        ASSERT(skycombat_gun_shot(b, 1, 0)); ASSERT(skycombat_gun_shot(a, 1, 0));
        ASSERT(skycombat_gun_shot(b, 2, 1)); ASSERT(skycombat_gun_shot(b, 1, 1));
        ASSERT(skycombat_gun_shot(a, 2, 1)); ASSERT(skycombat_gun_shot(b, 1, 0));
        ASSERT(skycombat_gun_shot(a, 1, 1)); PASS();
    }
    TEST("guns: spread advances the cycle and recreation resets it") {
        weapons_apply_upgrade(a, WEAPON_UPGRADE_SPREAD_SHOT, 10.0f);
        ASSERT(skycombat_gun_shot(a, 6, 3)); weapons_clear_upgrade(a);
        ASSERT(skycombat_gun_shot(a, 2, 1));
        weapons_destroy(b); b = weapons_create();
        ASSERT(b && skycombat_gun_shot(b, 1, 1)); PASS();
    }
_test_next:;
    weapons_destroy(reference); weapons_destroy(b); weapons_destroy(a);
    return failures;
}

/* The launch document is a public source fixture, not a session or live store. */
static int skycombat_document_tests(void)
{
    int failures = 0;
    FILE *f = fopen("docs/commons/GAME.md", "r");
    ASSERT(f != NULL);
    char prose[16384] = {0}, line[512];
    size_t used = 0;
    bool fenced = false, bounded = true;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "```", 3) == 0) { fenced = !fenced; continue; }
        if (fenced) continue;
        size_t n = strlen(line);
        if (n >= sizeof(prose) - used) { bounded = false; break; }
        memcpy(prose + used, line, n); used += n;
    }
    bool read_ok = !ferror(f);
    int close_result = fclose(f); f = NULL;
    TEST("game documentation: playable topology and match lifecycle are explicit") {
        ASSERT(bounded && read_ok && close_result == 0);
        ASSERT(strstr(prose, "one local player") != NULL);
        ASSERT(strstr(prose, "four AI aircraft") != NULL);
        ASSERT(strstr(prose, "single view") != NULL);
        ASSERT(strstr(prose, "The match starts once") != NULL);
        ASSERT(strstr(prose, "scores freeze") != NULL);
        ASSERT(strstr(prose, "Building entry is not yet wired") != NULL);
        ASSERT(strstr(prose, "five-player split-screen") == NULL);
        ASSERT(strstr(prose, "enterable buildings") == NULL);
        ASSERT(strstr(prose, "fleetgame1") == NULL);
        ASSERT(strstr(prose, "never starts the match") == NULL); PASS();
    }
_test_next:;
    if (f) fclose(f);
    return failures;
}

static int skycombat_wrap_tests(void)
{
    int failures = 0;
    const Vector3 input[] = {
        {3 * WORLD_SIZE + 125, 600, -4 * WORLD_SIZE - 250},
        {WORLD_HALF_SIZE, 250, -WORLD_HALF_SIZE}, {1001, 9, -1001},
        {3000, 500, -3000}, {5000, 10, -5000}, {0, 250, 0},
        {NAN, NAN, INFINITY}, {-INFINITY, INFINITY, NAN},
        {INFINITY, -INFINITY, -INFINITY}, {NAN, 250, 123}, {123, NAN, -456}
    };
    const Vector3 expected[] = {
        {125, 500, -250}, {WORLD_HALF_SIZE, 250, -WORLD_HALF_SIZE}, {-999, 10, 999},
        {1000, 500, -1000}, {1000, 10, -1000}, {0, 250, 0},
        {0, WORLD_MIN_HEIGHT, 0}, {0, WORLD_MIN_HEIGHT, 0},
        {0, WORLD_MIN_HEIGHT, 0}, {0, 250, 123}, {123, WORLD_MIN_HEIGHT, -456}
    };
    TEST("wrap: multiple spans, signed edges, invalid components and altitude") {
        for (size_t i = 0; i < sizeof(input) / sizeof(input[0]); i++) {
            aircraft_t a = {.position = input[i], .altitude = -99};
            aircraft_wrap_position(&a);
            ASSERT_EQ(a.position.x, expected[i].x); ASSERT_EQ(a.position.y, expected[i].y);
            ASSERT_EQ(a.position.z, expected[i].z); ASSERT_EQ(a.altitude, expected[i].y);
            Vector3 before = a.position; aircraft_wrap_position(&a);
            ASSERT_EQ(a.position.x, before.x); ASSERT_EQ(a.position.y, before.y);
            ASSERT_EQ(a.position.z, before.z); ASSERT_EQ(a.altitude, before.y);
        }
        PASS();
    }
    TEST("wrap: finite extremes and immediately outside the boundary remain bounded") {
        aircraft_t a = {.position = {FLT_MAX, 250, -FLT_MAX}};
        aircraft_wrap_position(&a);
        ASSERT(isfinite(a.position.x) && isfinite(a.position.z));
        ASSERT(fabsf(a.position.x) <= WORLD_HALF_SIZE && fabsf(a.position.z) <= WORLD_HALF_SIZE);
        ASSERT_EQ(a.altitude, 250.0f);
        float outside = nextafterf(WORLD_HALF_SIZE, INFINITY);
        a.position = (Vector3){outside, 250, -outside}; aircraft_wrap_position(&a);
        ASSERT_EQ(a.position.x, outside - WORLD_SIZE);
        ASSERT_EQ(a.position.z, WORLD_SIZE - outside); PASS();
    }
_test_next:;
    return failures;
}

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
    failures += skycombat_match_lifecycle_tests();
    failures += skycombat_match_bounds_tests();
    failures += skycombat_pickup_time_tests(false);
    failures += skycombat_pickup_time_tests(true);
    failures += skycombat_pickup_tests();
    failures += skycombat_collect_diagnostic_tests();
    failures += skycombat_wrap_tests();
    failures += skycombat_document_tests();
    failures += skycombat_gun_pattern_tests();
    if (failures == 0)
        printf("test_skycombat_models: all passed\n");
    else
        printf("test_skycombat_models: %d FAILED\n", failures);
    return failures;
}
