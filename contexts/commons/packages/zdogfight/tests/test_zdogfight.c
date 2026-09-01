/* zdogfight tests.
 *
 * Born-red coverage of the match rules: cross-instance determinism,
 * seed divergence via respawn PRNG, kill/score/respawn timing, world
 * bounds and toroidal wrap, shot TTL, friendly-fire immunity, match
 * end by score limit and by time limit (draw), wire round-trips and
 * truncation rejection, and DONE no-op behavior.
 */
#include "zdogfight/zdogfight.h"

#include <stdio.h>
#include <string.h>

#include "../src/zdogfix.h"

static int failures;

static void check(int cond, const char *name)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

/* ------------------------------------------------------------------ */
/* Scripted pilots (integer only)                                      */
/* ------------------------------------------------------------------ */

/* Sitting duck: minimum throttle, straight ahead, never fires. */
static void pilot_sit(zdog_ctl *c)
{
    c->roll = 0;
    c->pitch = 0;
    c->throttle = 0;
    c->fire = 0;
}

/* Deterministic per-tick pseudo-pilot driven purely by tick/index,
 * used for determinism checks. */
static void pilot_scripted(uint64_t tick, unsigned i, zdog_ctl *c)
{
    c->roll = (int16_t)(((int)((tick + i * 7u) % 120u) - 60) * 400);
    c->pitch = (int16_t)(((int)((tick / 3u + i * 11u) % 60u) - 30) * 500);
    c->throttle = (int16_t)(10000 + (int)((tick + i * 13u) % 100u) * 200);
    c->fire = (uint8_t)(((tick + i * 5u) % 37u) == 0u);
}

/* Always-firing head-on pilot: full throttle straight ahead, always
 * firing. Mirrored spawn pairs meet head-on, which reliably produces
 * kills (and therefore respawn PRNG draws). */
static void pilot_straight_fire(zdog_ctl *c)
{
    c->roll = 0;
    c->pitch = 0;
    c->throttle = 32767;
    c->fire = 1;
}

static int32_t tor_d(int32_t a, int32_t b)
{
    int64_t d = (int64_t)a - b;

    if (d > 1000000)
        d -= 2000000;
    else if (d < -1000000)
        d += 2000000;
    return (int32_t)d;
}

/* Proportional homing pilot toward an absolute target point; fires
 * when lined up within 4 m across and 400 m range. Integer only. */
static void chase_point(const zdog_match *m, unsigned idx, int32_t tx,
                        int32_t ty, int32_t tz, zdog_ctl *c)
{
    const zdog_plane *p = &m->planes[idx];
    int32_t rx = tor_d(tx, p->x);
    int32_t ry = ty - p->y;
    int32_t rz = tor_d(tz, p->z);
    int16_t sy = zdog_sin(p->yaw), cy = zdog_cos(p->yaw);
    int64_t dot = (int64_t)sy * rx + (int64_t)cy * rz;
    int64_t cross = (int64_t)cy * rx - (int64_t)sy * rz;
    uint64_t d2 = (uint64_t)((int64_t)rx * rx + (int64_t)ry * ry +
                             (int64_t)rz * rz);

    c->roll = 0;
    c->pitch = 0;
    c->throttle = 32767;
    c->fire = 0;
    if (dot <= 0) {
        c->roll = (int16_t)(cross < 0 ? -30000 : 30000);
        return;
    }
    /* roll proportional to bearing error, saturating past ~3.6 deg:
     * cross/(32767*range) == perp/range and dot/32767 approximates
     * the along-boresight range, so no square root is needed. */
    int64_t rr = cross * 16 / (dot / 32767 > 0 ? dot / 32767 : 1);

    if (rr > 30000)
        rr = 30000;
    else if (rr < -30000)
        rr = -30000;
    c->roll = (int16_t)rr;
    c->pitch = (int16_t)(ry > 500 ? -14000 : ry < -500 ? 14000 : 0);
    if (d2 < UINT64_C(400000) * 400000 &&
        (cross < 0 ? -cross : cross) < INT64_C(4000) * 32767)
        c->fire = 1;
}

/* Homing pilot that hunts the nearest living enemy via the pilot ABI
 * observation. */
static void pilot_chase(const zdog_match *m, unsigned idx, zdog_ctl *c)
{
    zdog_obs o;

    pilot_sit(c);
    if (!m->planes[idx].alive)
        return;
    zdog_observe(m, idx, &o);
    if (!o.enemy_valid)
        return;
    chase_point(m, idx, o.x + o.rel_x, o.y + o.rel_y, o.z + o.rel_z, c);
}

/* ------------------------------------------------------------------ */
/* 1. Determinism: two instances, same seed, identical trajectory      */
/* ------------------------------------------------------------------ */

static void test_determinism(void)
{
    zdog_match a, b;

    zdog_match_init(&a, 42, 2);
    zdog_match_init(&b, 42, 2);
    for (uint64_t t = 0; t < 6000; t++) {
        zdog_ctl ca[ZDOG_MAX_PLANES], cb[ZDOG_MAX_PLANES];

        for (unsigned i = 0; i < ZDOG_MAX_PLANES; i++) {
            pilot_scripted(t, i, &ca[i]);
            cb[i] = ca[i];
        }
        zdog_tick(&a, ca);
        zdog_tick(&b, cb);
        if (t % 60 == 0)
            check(zdog_state_checksum(&a) == zdog_state_checksum(&b),
                  "determinism checksum");
    }
    uint8_t ea[ZDOG_STATE_WIRE_MAX], eb[ZDOG_STATE_WIRE_MAX];
    size_t na = zdog_state_encode(&a, ea, sizeof ea);
    size_t nb = zdog_state_encode(&b, eb, sizeof eb);

    check(na == ZDOG_STATE_WIRE_MAX && nb == ZDOG_STATE_WIRE_MAX,
          "determinism encode size");
    check(memcmp(ea, eb, na) == 0, "determinism encode bytes");
}

/* ------------------------------------------------------------------ */
/* 2. Different seed -> different state (respawn PRNG engages)         */
/* ------------------------------------------------------------------ */

static void test_seed_divergence(void)
{
    zdog_match a, b;

    zdog_match_init(&a, 42, 2);
    zdog_match_init(&b, 4242, 2);
    for (uint64_t t = 0; t < 600; t++) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        for (unsigned i = 0; i < ZDOG_MAX_PLANES; i++)
            pilot_straight_fire(&c[i]);
        zdog_tick(&a, c);
        zdog_tick(&b, c);
    }
    check(a.score[0] + a.score[1] > 0, "seed test kills happened");
    check(b.score[0] + b.score[1] > 0, "seed test kills happened (b)");
    check(zdog_state_checksum(&a) != zdog_state_checksum(&b),
          "different seed diverges");
}

/* ------------------------------------------------------------------ */
/* 3. Kill, score, and exactly-180-tick respawn                        */
/* ------------------------------------------------------------------ */

static void test_kill_and_respawn(void)
{
    zdog_match m;
    uint64_t death_tick = UINT64_MAX;

    zdog_match_init(&m, 7, 1);
    for (uint64_t t = 0; t < 6000 && m.score[0] == 0; t++) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        pilot_chase(&m, 0, &c[0]);
        pilot_sit(&c[1]);
        zdog_tick(&m, c);
        if (!m.planes[1].alive)
            death_tick = m.tick;
    }
    check(m.score[0] == 1, "kill scored for red");
    check(m.score[1] == 0, "blue did not score");
    check(death_tick != UINT64_MAX, "kill within 6000 ticks");
    check(!m.planes[1].alive && m.planes[1].health == 0,
          "dead plane health clamped");
    check(m.planes[1].respawn_in == ZDOG_RESPAWN_TICKS - 1 ||
          m.planes[1].respawn_in == ZDOG_RESPAWN_TICKS,
          "respawn countdown armed");

    /* Both pilots go quiet so the respawn observation is clean. */
    int alive_after = -1;

    for (unsigned k = 1; k <= ZDOG_RESPAWN_TICKS + 2; k++) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        pilot_sit(&c[0]);
        pilot_sit(&c[1]);
        zdog_tick(&m, c);
        if (k < ZDOG_RESPAWN_TICKS)
            check(!m.planes[1].alive, "still dead before 180 ticks");
        if (k == ZDOG_RESPAWN_TICKS) {
            alive_after = m.planes[1].alive;
            /* Inspect the fresh respawn before further ticks can
             * change it. */
            check(m.planes[1].health == 100, "respawn health 100");
            check(m.planes[1].speed == 60000, "respawn speed 60000");
            check(m.planes[1].y == 200000, "respawn y");
            check(m.planes[1].x >= -900000 && m.planes[1].x <= 900000 &&
                      m.planes[1].z >= -900000 &&
                      m.planes[1].z <= 900000,
                  "respawn x/z range");
        }
    }
    check(alive_after == 1, "respawn after exactly 180 ticks");
    check(m.phase == ZDOG_PHASE_RUNNING, "still running after 1 kill");
}

/* ------------------------------------------------------------------ */
/* 4. World bounds: y clamp (+ pitch zeroed), x/z toroidal wrap        */
/* ------------------------------------------------------------------ */

static void test_bounds_and_wrap(void)
{
    zdog_match m;
    int wrap_x = 0, wrap_z = 0, clamp_hi = 0, clamp_lo = 0;
    int in_bounds = 1;
    int32_t prev_x0 = 0, prev_z1 = 0;

    zdog_match_init(&m, 99, 2);
    for (uint64_t t = 0; t < 1300; t++) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        for (unsigned i = 0; i < ZDOG_MAX_PLANES; i++)
            pilot_sit(&c[i]);
        /* plane 0: straight east at full throttle -> wraps +x */
        c[0].throttle = 32767;
        /* plane 1: turn until facing +z (yaw 0), then full throttle */
        c[1].throttle = 32767;
        if (m.planes[1].yaw > 300 && m.planes[1].yaw <= 32768)
            c[1].roll = -30000;
        else if (m.planes[1].yaw > 32768 && m.planes[1].yaw < 65236)
            c[1].roll = 30000;
        /* plane 3: climb into the ceiling, then dive into the floor */
        c[3].pitch = (int16_t)(t < 600 ? -32767 : 32767);
        c[3].throttle = 32767;

        zdog_tick(&m, c);

        for (unsigned i = 0; i < m.num_planes; i++) {
            const zdog_plane *p = &m.planes[i];

            if (p->x < -1000000 || p->x >= 1000000 || p->z < -1000000 ||
                p->z >= 1000000 || p->y < 10000 || p->y > 500000)
                in_bounds = 0;
        }
        if (t > 0) {
            if (m.planes[0].x - prev_x0 < -100000)
                wrap_x = 1;
            if (m.planes[1].z - prev_z1 < -100000 ||
                m.planes[1].z - prev_z1 > 100000)
                wrap_z = 1;
        }
        prev_x0 = m.planes[0].x;
        prev_z1 = m.planes[1].z;
        if (t > 100 && m.planes[3].y == 500000 && m.planes[3].pitch == 0)
            clamp_hi = 1;
        if (t > 700 && m.planes[3].y == 10000 && m.planes[3].pitch == 0)
            clamp_lo = 1;
        if (t > 1000 && t % 100 == 0)
            check(m.planes[3].y == 10000, "y stays on the floor");
        if (t > 200 && t < 600 && t % 100 == 0)
            check(m.planes[3].y == 500000, "y stays on the ceiling");
    }
    check(in_bounds, "all planes in bounds every tick");
    check(wrap_x, "x toroidal wrap observed");
    check(wrap_z, "z toroidal wrap observed");
    check(clamp_hi, "y ceiling clamp with pitch zeroed");
    check(clamp_lo, "y floor clamp with pitch zeroed");
}

/* ------------------------------------------------------------------ */
/* 5. Shot TTL expiry after exactly 600 ticks                          */
/* ------------------------------------------------------------------ */

static void test_shot_ttl(void)
{
    zdog_match m;
    int fired = 0;
    int spawned_seen = 0;

    zdog_match_init(&m, 5, 1);
    /* Red climbs away from the sitting target's altitude and fires a
     * single shot while still climbing gently, so the shot can never
     * come down onto blue (y separation stays > 50 m). */
    for (uint64_t t = 0; t < 4000 && !fired; t++) {
        zdog_ctl c[ZDOG_MAX_PLANES];
        const zdog_plane *rp = &m.planes[0];
        int32_t sp = rp->pitch <= 32767u ? rp->pitch
                                         : (int32_t)rp->pitch - 65536;

        pilot_sit(&c[0]);
        pilot_sit(&c[1]);
        if (rp->y < 260000) {
            c[0].pitch = (int16_t)(sp > -8000 ? -32767 : 32767);
        } else {
            c[0].pitch = (int16_t)(sp > -300 ? -32767 : 32767);
            if (sp <= -100 && sp >= -600) {
                c[0].fire = 1;
                fired = 1;
            }
        }
        zdog_tick(&m, c);
        if (fired) {
            check(m.shots[0].active, "shot spawned in slot 0");
            spawned_seen = 1;
        }
    }
    check(spawned_seen, "single shot fired");
    check(m.shots[0].active && m.shots[0].ttl == ZDOG_SHOT_TTL - 1,
          "ttl 599 right after spawn tick");

    /* 598 further ticks: still alive with ttl 1. */
    for (unsigned k = 0; k < 598; k++) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        pilot_sit(&c[0]);
        pilot_sit(&c[1]);
        zdog_tick(&m, c);
    }
    check(m.shots[0].active && m.shots[0].ttl == 1,
          "shot alive at tick 599 of its life");
    check(m.score[0] == 0 && m.score[1] == 0, "no accidental hit");

    zdog_ctl c[ZDOG_MAX_PLANES];

    pilot_sit(&c[0]);
    pilot_sit(&c[1]);
    zdog_tick(&m, c);
    check(!m.shots[0].active, "shot inactive after exactly 600 ticks");
}

/* ------------------------------------------------------------------ */
/* 6. Friendly fire: own-team shots never damage                       */
/* ------------------------------------------------------------------ */

static void test_friendly_fire(void)
{
    zdog_match m;
    int shots_seen = 0;
    int red_hurt = 0, blue_hurt = 0;

    zdog_match_init(&m, 11, 2);
    for (uint64_t t = 0; t < 3000; t++) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        for (unsigned i = 0; i < ZDOG_MAX_PLANES; i++)
            pilot_sit(&c[i]);
        /* red 0 circles tightly above its spawn; red 1 hunts red 0
         * (a friendly) and fires whenever lined up; blues climb to
         * the ceiling, far from every red shot. */
        c[0].roll = 30000;
        c[0].throttle = 0;
        chase_point(&m, 1, m.planes[0].x, m.planes[0].y, m.planes[0].z,
                    &c[1]);
        c[2].pitch = -32767;
        c[3].pitch = -32767;
        zdog_tick(&m, c);
        for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++)
            if (m.shots[i].active)
                shots_seen = 1;
        if (m.planes[0].health != 100 || m.planes[1].health != 100)
            red_hurt = 1;
        if (m.planes[2].health != 100 || m.planes[3].health != 100)
            blue_hurt = 1;
    }
    check(shots_seen, "friendly-fire test actually fired shots");
    check(!red_hurt, "own team never damaged");
    check(!blue_hurt, "stray shots hit nobody");
    check(m.score[0] == 0 && m.score[1] == 0, "no friendly-fire score");
}

/* ------------------------------------------------------------------ */
/* 7. Match end: score limit, time limit draw, DONE no-op              */
/* ------------------------------------------------------------------ */

static void test_match_end_score_limit(void)
{
    zdog_match m;

    zdog_match_init(&m, 13, 1);
    while (m.phase == ZDOG_PHASE_RUNNING) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        pilot_chase(&m, 0, &c[0]);
        pilot_sit(&c[1]);
        zdog_tick(&m, c);
    }
    check(m.score[0] == ZDOG_SCORE_LIMIT, "red reached score limit");
    check(m.winner == ZDOG_WINNER_RED, "winner red");
    check(m.tick < ZDOG_TICK_LIMIT, "ended before time limit");

    /* DONE: further ticks are a no-op. */
    uint64_t done_tick = m.tick;
    uint64_t sum = zdog_state_checksum(&m);
    zdog_ctl c[ZDOG_MAX_PLANES];

    for (unsigned i = 0; i < ZDOG_MAX_PLANES; i++)
        pilot_straight_fire(&c[i]);
    for (unsigned k = 0; k < 100; k++)
        zdog_tick(&m, c);
    check(m.tick == done_tick, "DONE tick frozen");
    check(zdog_state_checksum(&m) == sum, "DONE state frozen");
}

static void test_match_end_draw(void)
{
    zdog_match m;

    zdog_match_init(&m, 17, 1);
    while (m.phase == ZDOG_PHASE_RUNNING) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        pilot_sit(&c[0]);
        pilot_sit(&c[1]);
        zdog_tick(&m, c);
    }
    check(m.tick == ZDOG_TICK_LIMIT, "draw at tick limit");
    check(m.score[0] == 0 && m.score[1] == 0, "draw has no kills");
    check(m.winner == ZDOG_WINNER_DRAW, "winner draw");
}

/* ------------------------------------------------------------------ */
/* 8. Wire round-trips                                                 */
/* ------------------------------------------------------------------ */

static int obs_eq(const zdog_obs *a, const zdog_obs *b)
{
    return a->tick == b->tick && a->self_index == b->self_index &&
           a->num_planes == b->num_planes && a->x == b->x && a->y == b->y &&
           a->z == b->z && a->yaw == b->yaw && a->pitch == b->pitch &&
           a->roll == b->roll && a->speed == b->speed &&
           a->health == b->health && a->team == b->team &&
           a->score_red == b->score_red && a->score_blue == b->score_blue &&
           a->ticks_left == b->ticks_left &&
           a->enemy_valid == b->enemy_valid && a->rel_x == b->rel_x &&
           a->rel_y == b->rel_y && a->rel_z == b->rel_z &&
           a->dist == b->dist && a->evx == b->evx && a->evy == b->evy &&
           a->evz == b->evz && a->ehealth == b->ehealth;
}

static void test_wire_roundtrip(void)
{
    zdog_match m;

    check(ZDOG_STATE_WIRE_MAX == 2163, "state wire size constant");
    zdog_match_init(&m, 23, 4);
    for (uint64_t t = 0; t < 300; t++) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        for (unsigned i = 0; i < ZDOG_MAX_PLANES; i++)
            pilot_scripted(t, i, &c[i]);
        zdog_tick(&m, c);
    }

    /* obs round-trip for every plane */
    for (unsigned i = 0; i < m.num_planes; i++) {
        zdog_obs o, back;
        uint8_t buf[ZDOG_OBS_WIRE_LEN];

        zdog_observe(&m, i, &o);
        check(zdog_obs_encode(&o, buf, sizeof buf) == ZDOG_OBS_WIRE_LEN,
              "obs encode size");
        check(zdog_obs_encode(&o, buf, ZDOG_OBS_WIRE_LEN - 1) == 0,
              "obs encode cap overflow");
        check(zdog_obs_decode(buf, sizeof buf, &back), "obs decode rc");
        check(obs_eq(&o, &back), "obs round-trip identity");
        check(!zdog_obs_decode(buf, ZDOG_OBS_WIRE_LEN - 1, &back),
              "obs truncated decode fails");
        check(!zdog_obs_decode(buf, 0, &back), "obs empty decode fails");
    }

    /* ctl round-trip with extreme values */
    zdog_ctl c = { -32768, 32767, -12345, 255 }, cback;
    uint8_t cbuf[ZDOG_CTL_WIRE_LEN];

    check(zdog_ctl_encode(&c, cbuf, sizeof cbuf) == ZDOG_CTL_WIRE_LEN,
          "ctl encode size");
    check(zdog_ctl_encode(&c, cbuf, ZDOG_CTL_WIRE_LEN - 1) == 0,
          "ctl encode cap overflow");
    check(zdog_ctl_decode(cbuf, sizeof cbuf, &cback), "ctl decode rc");
    check(cback.roll == c.roll && cback.pitch == c.pitch &&
              cback.throttle == c.throttle && cback.fire == c.fire,
          "ctl round-trip identity");
    check(!zdog_ctl_decode(cbuf, ZDOG_CTL_WIRE_LEN - 1, &cback),
          "ctl truncated decode fails");

    /* state encode: exact stable size, overflow rejected */
    uint8_t s1[ZDOG_STATE_WIRE_MAX], s2[ZDOG_STATE_WIRE_MAX];

    check(zdog_state_encode(&m, s1, sizeof s1) == ZDOG_STATE_WIRE_MAX,
          "state encode exact size");
    check(zdog_state_encode(&m, s2, sizeof s2) == ZDOG_STATE_WIRE_MAX,
          "state encode stable size");
    check(memcmp(s1, s2, sizeof s1) == 0, "state encode reproducible");
    check(zdog_state_encode(&m, s1, ZDOG_STATE_WIRE_MAX - 1) == 0,
          "state encode overflow rejected");
}

/* ------------------------------------------------------------------ */
/* 10. DONE matches with different winners differ                      */
/* ------------------------------------------------------------------ */

static uint64_t run_to_done(uint64_t seed, unsigned chaser)
{
    zdog_match m;

    zdog_match_init(&m, seed, 1);
    while (m.phase == ZDOG_PHASE_RUNNING) {
        zdog_ctl c[ZDOG_MAX_PLANES];

        pilot_sit(&c[0]);
        pilot_sit(&c[1]);
        pilot_chase(&m, chaser, &c[chaser]);
        zdog_tick(&m, c);
    }
    check(m.winner == (chaser == 0 ? ZDOG_WINNER_RED : ZDOG_WINNER_BLUE),
          "chaser wins");
    return zdog_state_checksum(&m);
}

static void test_winner_states_differ(void)
{
    uint64_t red_win = run_to_done(29, 0);
    uint64_t blue_win = run_to_done(29, 1);

    check(red_win != blue_win, "red-win and blue-win roots differ");
}

/* Same built-in demo pilots as app/main.c — the playable package CLI. */
static void demo_straight(zdog_ctl *c)
{
    c->roll = 0;
    c->pitch = 0;
    c->throttle = 32767;
    c->fire = 1;
}

static void demo_weave(uint64_t tick, zdog_ctl *c)
{
    c->roll = (int16_t)((tick / 90u) % 2u ? 12000 : -12000);
    c->pitch = 0;
    c->throttle = 32767;
    c->fire = (uint8_t)(tick % 6u == 0u);
}

static uint64_t demo_play(uint64_t seed, uint8_t planes)
{
    zdog_match m;
    zdog_match_init(&m, seed, planes);
    while (m.phase == ZDOG_PHASE_RUNNING) {
        zdog_ctl ctls[ZDOG_MAX_PLANES] = {{0}};
        for (unsigned i = 0; i < m.num_planes; i++) {
            if (m.planes[i].team == 0)
                demo_straight(&ctls[i]);
            else
                demo_weave(m.tick, &ctls[i]);
        }
        zdog_tick(&m, ctls);
    }
    return zdog_state_checksum(&m);
}

static void test_play_demo_is_deterministic(void)
{
    uint64_t a = demo_play(7, 2);
    uint64_t b = demo_play(7, 2);
    uint64_t c = demo_play(8, 2);
    check(a != 0, "demo play produces a state checksum");
    check(a == b, "same seed and demo pilots replay identically");
    check(a != c, "a different seed is a different match");
}

int main(void)
{
    test_determinism();
    test_seed_divergence();
    test_kill_and_respawn();
    test_bounds_and_wrap();
    test_shot_ttl();
    test_friendly_fire();
    test_match_end_score_limit();
    test_match_end_draw();
    test_wire_roundtrip();
    test_winner_states_differ();
    test_play_demo_is_deterministic();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("zdogfight: all tests passed");
    return 0;
}
