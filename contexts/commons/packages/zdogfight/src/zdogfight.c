/* zdogfight — implementation. See include/zdogfight/zdogfight.h for
 * the contract and the determinism rules. All arithmetic below is
 * integer only (no floating point): positions int32 mm, angles brad16,
 * Q1.15 products via zdog_floor_q15, and every per-second rate is
 * integer-divided by 60 per tick. */
#include "zdogfight/zdogfight.h"

#include <string.h>

#include "zdogfix.h"

#define BRAD_FULL 65536
#define Q15_ONE 32767

/* Clamp a Q1.15 control to the symmetric range -32767..32767 so the
 * int16 minimum -32768 can never produce an overflow elsewhere (the
 * positive side cannot exceed 32767 in an int16). */
static int32_t clamp_q15(int16_t v)
{
    if (v < -Q15_ONE)
        return -Q15_ONE;
    return v;
}

/* Toroidal x/z: single-step wrap is enough because no per-tick motion
 * exceeds 8,000 mm. */
static int32_t wrap_xz(int32_t v)
{
    if (v >= ZDOG_WORLD_HALF)
        return v - 2 * ZDOG_WORLD_HALF;
    if (v < -ZDOG_WORLD_HALF)
        return v + 2 * ZDOG_WORLD_HALF;
    return v;
}

/* Shortest wrapped delta a - b on the toroidal x/z axes. */
static int32_t tor_delta(int32_t a, int32_t b)
{
    int64_t d = (int64_t)a - b;

    if (d > ZDOG_WORLD_HALF)
        d -= 2 * (int64_t)ZDOG_WORLD_HALF;
    else if (d < -ZDOG_WORLD_HALF)
        d += 2 * (int64_t)ZDOG_WORLD_HALF;
    return (int32_t)d;
}

/* Q1.15 * Q1.15 -> Q1.15, floor semantics. */
static int16_t q15_mul(int16_t a, int16_t b)
{
    return (int16_t)zdog_floor_q15((int32_t)a * b);
}

/* Forward vector, reference convention: fx = sin(yaw)*cos(pitch),
 * fy = -sin(pitch), fz = cos(yaw)*cos(pitch), all Q1.15. */
static void forward_vec(const zdog_plane *p, int16_t *fx, int16_t *fy,
                        int16_t *fz)
{
    int16_t sy = zdog_sin(p->yaw);
    int16_t cy = zdog_cos(p->yaw);
    int16_t cp = zdog_cos(p->pitch);

    *fx = q15_mul(sy, cp);
    *fy = (int16_t)-zdog_sin(p->pitch);
    *fz = q15_mul(cy, cp);
}

static void respawn(zdog_match *m, zdog_plane *p)
{
    p->x = (int32_t)zxoshiro256ss_below(&m->rng, 1800001u) - 900000;
    p->z = (int32_t)zxoshiro256ss_below(&m->rng, 1800001u) - 900000;
    p->y = 200000;
    p->yaw = (uint16_t)zxoshiro256ss_below(&m->rng, 65536u);
    p->pitch = 0;
    p->roll = 0;
    p->speed = 60000;
    p->health = 100;
    p->alive = 1;
    p->fire_cd = 0;
    p->respawn_in = 0;
}

/* Returns 1 if a shot was spawned, 0 if every slot was busy (the
 * trigger pull is lost and no cooldown is started). */
static int spawn_shot(zdog_match *m, const zdog_plane *p, unsigned idx,
                      int16_t fx, int16_t fy, int16_t fz)
{
    zdog_shot *s = NULL;

    for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++) {
        if (!m->shots[i].active) {
            s = &m->shots[i];
            break;
        }
    }
    if (!s)
        return 0;
    s->x = wrap_xz(p->x + zdog_floor_q15((int32_t)fx * ZDOG_SHOT_SPAWN_MM));
    s->y = p->y + zdog_floor_q15((int32_t)fy * ZDOG_SHOT_SPAWN_MM);
    s->z = wrap_xz(p->z + zdog_floor_q15((int32_t)fz * ZDOG_SHOT_SPAWN_MM));
    s->vx = zdog_floor_q15((int64_t)fx * ZDOG_SHOT_SPEED);
    s->vy = zdog_floor_q15((int64_t)fy * ZDOG_SHOT_SPEED);
    s->vz = zdog_floor_q15((int64_t)fz * ZDOG_SHOT_SPEED);
    s->owner = (uint8_t)idx;
    s->team = p->team;
    s->ttl = ZDOG_SHOT_TTL;
    s->active = 1;
    return 1;
}

static void plane_update(zdog_match *m, unsigned idx, const zdog_ctl *c)
{
    zdog_plane *p = &m->planes[idx];

    if (!p->alive) {
        if (p->respawn_in > 0 && --p->respawn_in == 0)
            respawn(m, p);
        return;
    }

    /* Bank-to-turn: actual roll approaches the target at 360 deg/s. */
    int32_t target_roll = clamp_q15(c->roll);
    int32_t dr = target_roll - p->roll;

    if (dr > ZDOG_ROLL_STEP)
        dr = ZDOG_ROLL_STEP;
    else if (dr < -ZDOG_ROLL_STEP)
        dr = -ZDOG_ROLL_STEP;
    p->roll = (int16_t)(p->roll + dr);

    /* Yaw rate 150 deg/s * sin(actual roll). */
    int32_t roll_brad = (int32_t)p->roll * ZDOG_ROLL_MAX_BRAD / Q15_ONE;
    int16_t sroll = zdog_sin((uint16_t)roll_brad);

    p->yaw = (uint16_t)(p->yaw +
                        (int32_t)ZDOG_YAW_RATE_BRAD * sroll / Q15_ONE / 60);

    /* Pitch rate 100 deg/s at full stick, clamped to +/-60 deg. */
    int32_t pd = clamp_q15(c->pitch) * ZDOG_PITCH_RATE_BRAD / Q15_ONE / 60;
    int32_t sp = p->pitch <= 32767u ? p->pitch
                                    : (int32_t)p->pitch - BRAD_FULL;

    sp += pd;
    if (sp > ZDOG_PITCH_MAX_BRAD)
        sp = ZDOG_PITCH_MAX_BRAD;
    else if (sp < -ZDOG_PITCH_MAX_BRAD)
        sp = -ZDOG_PITCH_MAX_BRAD;
    p->pitch = (uint16_t)sp;

    /* Speed approaches the throttle target at 36,000 mm/s per second. */
    int32_t thr = clamp_q15(c->throttle);

    if (thr < 0)
        thr = 0;
    int32_t target_speed =
        ZDOG_SPEED_MIN +
        (int32_t)((int64_t)thr * (ZDOG_SPEED_MAX - ZDOG_SPEED_MIN) / Q15_ONE);

    if (p->speed < target_speed) {
        p->speed += ZDOG_SPEED_STEP;
        if (p->speed > target_speed)
            p->speed = target_speed;
    } else if (p->speed > target_speed) {
        p->speed -= ZDOG_SPEED_STEP;
        if (p->speed < target_speed)
            p->speed = target_speed;
    }

    /* Move along the forward vector. */
    int16_t fx, fy, fz;

    forward_vec(p, &fx, &fy, &fz);
    p->x = wrap_xz(p->x + zdog_floor_q15((int64_t)fx * p->speed) / 60);
    p->y += zdog_floor_q15((int64_t)fy * p->speed) / 60;
    p->z = wrap_xz(p->z + zdog_floor_q15((int64_t)fz * p->speed) / 60);
    if (p->y > ZDOG_Y_MAX) {
        p->y = ZDOG_Y_MAX;
        p->pitch = 0;
    } else if (p->y < ZDOG_Y_MIN) {
        p->y = ZDOG_Y_MIN;
        p->pitch = 0;
    }

    /* Gun: only a successful spawn starts the cooldown. */
    if (p->fire_cd > 0)
        p->fire_cd--;
    if (c->fire && p->fire_cd == 0 &&
        spawn_shot(m, p, idx, fx, fy, fz))
        p->fire_cd = ZDOG_FIRE_CD;
}

static void shot_update(zdog_match *m, zdog_shot *s)
{
    s->x = wrap_xz(s->x + s->vx / 60);
    s->y += s->vy / 60;
    s->z = wrap_xz(s->z + s->vz / 60);

    /* Enemy alive planes only, ascending index; first hit kills the
     * shot. Deltas are toroidal-aware on x/z. */
    for (unsigned j = 0; j < m->num_planes; j++) {
        zdog_plane *p = &m->planes[j];

        if (!p->alive || p->team == s->team)
            continue;
        int64_t dx = tor_delta(s->x, p->x);
        int64_t dy = (int64_t)s->y - p->y;
        int64_t dz = tor_delta(s->z, p->z);

        if (dx * dx + dy * dy + dz * dz >= ZDOG_HIT_RADIUS2)
            continue;
        p->health -= ZDOG_SHOT_DAMAGE;
        s->active = 0;
        if (p->health <= 0) {
            p->health = 0;
            p->alive = 0;
            p->respawn_in = ZDOG_RESPAWN_TICKS;
            m->score[s->team]++;
        }
        break;
    }

    if (s->active && --s->ttl == 0)
        s->active = 0;
}

void zdog_match_init(zdog_match *m, uint64_t seed, unsigned planes_per_team)
{
    memset(m, 0, sizeof *m);
    if (planes_per_team < 1)
        planes_per_team = 1;
    if (planes_per_team > ZDOG_MAX_PLANES / 2u)
        planes_per_team = ZDOG_MAX_PLANES / 2u;
    m->num_planes = (uint8_t)(2u * planes_per_team);
    m->phase = ZDOG_PHASE_RUNNING;
    m->winner = ZDOG_WINNER_DRAW; /* meaningless until DONE */
    zxoshiro256ss_init(&m->rng, seed);
    for (unsigned i = 0; i < m->num_planes; i++) {
        zdog_plane *p = &m->planes[i];
        unsigned k = i < planes_per_team ? i : i - planes_per_team;

        p->team = i < planes_per_team ? 0u : 1u;
        p->x = p->team == 0 ? -500000 : 500000;
        p->y = 200000;
        p->z = (int32_t)(2u * k + 1u - planes_per_team) * 100000;
        p->yaw = p->team == 0 ? 16384u : 49152u;
        p->speed = 60000;
        p->health = 100;
        p->alive = 1;
    }
}

void zdog_tick(zdog_match *m, const zdog_ctl *ctls)
{
    if (!m || !ctls || m->phase != ZDOG_PHASE_RUNNING)
        return;

    /* Planes first, ascending index: movement, guns, and respawns
     * (the only PRNG draws, hence ascending plane index order). */
    for (unsigned i = 0; i < m->num_planes; i++)
        plane_update(m, i, &ctls[i]);

    /* Then shots, ascending slot index. */
    for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++)
        if (m->shots[i].active)
            shot_update(m, &m->shots[i]);

    m->tick++;
    if (m->score[0] >= ZDOG_SCORE_LIMIT || m->score[1] >= ZDOG_SCORE_LIMIT ||
        m->tick >= ZDOG_TICK_LIMIT) {
        m->phase = ZDOG_PHASE_DONE;
        m->winner = m->score[0] > m->score[1]   ? ZDOG_WINNER_RED
                    : m->score[1] > m->score[0] ? ZDOG_WINNER_BLUE
                                                : ZDOG_WINNER_DRAW;
    }
}

/* floor(sqrt(v)) for v < 2^63, bitwise method. */
static uint32_t isqrt64(uint64_t v)
{
    uint64_t r = 0, bit = UINT64_C(1) << 62;

    while (bit > v)
        bit >>= 2;
    while (bit) {
        if (v >= r + bit) {
            v -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
        bit >>= 2;
    }
    return (uint32_t)r;
}

void zdog_observe(const zdog_match *m, unsigned plane_index, zdog_obs *out)
{
    const zdog_plane *p = &m->planes[plane_index];

    memset(out, 0, sizeof *out);
    out->tick = m->tick;
    out->self_index = (uint8_t)plane_index;
    out->num_planes = m->num_planes;
    out->x = p->x;
    out->y = p->y;
    out->z = p->z;
    out->yaw = p->yaw;
    out->pitch = p->pitch;
    out->roll = p->roll;
    out->speed = p->speed;
    out->health = p->health;
    out->team = p->team;
    out->score_red = m->score[0];
    out->score_blue = m->score[1];
    out->ticks_left = m->tick < ZDOG_TICK_LIMIT
                          ? (uint32_t)(ZDOG_TICK_LIMIT - m->tick)
                          : 0;

    /* Nearest living enemy by squared toroidal-aware distance,
     * ascending index tie-break. */
    uint64_t best = UINT64_MAX;

    for (unsigned i = 0; i < m->num_planes; i++) {
        const zdog_plane *e = &m->planes[i];

        if (!e->alive || e->team == p->team)
            continue;
        int64_t dx = tor_delta(e->x, p->x);
        int64_t dy = (int64_t)e->y - p->y;
        int64_t dz = tor_delta(e->z, p->z);
        uint64_t d2 = (uint64_t)(dx * dx + dy * dy + dz * dz);

        if (d2 >= best)
            continue;
        best = d2;
        out->enemy_valid = 1;
        out->rel_x = (int32_t)dx;
        out->rel_y = (int32_t)dy;
        out->rel_z = (int32_t)dz;
        out->dist = isqrt64(d2);
        int16_t fx, fy, fz;
        forward_vec(e, &fx, &fy, &fz);
        out->evx = zdog_floor_q15((int64_t)fx * e->speed);
        out->evy = zdog_floor_q15((int64_t)fy * e->speed);
        out->evz = zdog_floor_q15((int64_t)fz * e->speed);
        out->ehealth = e->health;
    }
}

/* Canonical little-endian writers/readers: explicit field-by-field,
 * fixed order, no padding, no struct memcpy. */
static void put_u8(uint8_t **p, uint8_t v)
{
    *(*p)++ = v;
}

static void put_u16(uint8_t **p, uint16_t v)
{
    put_u8(p, (uint8_t)v);
    put_u8(p, (uint8_t)(v >> 8));
}

static void put_u32(uint8_t **p, uint32_t v)
{
    put_u16(p, (uint16_t)v);
    put_u16(p, (uint16_t)(v >> 16));
}

static void put_u64(uint8_t **p, uint64_t v)
{
    put_u32(p, (uint32_t)v);
    put_u32(p, (uint32_t)(v >> 32));
}

static void put_i32(uint8_t **p, int32_t v)
{
    put_u32(p, (uint32_t)v);
}

static void put_i16(uint8_t **p, int16_t v)
{
    put_u16(p, (uint16_t)v);
}

static uint16_t get_u16(const uint8_t **p)
{
    uint16_t v = (uint16_t)(*p)[0] | (uint16_t)((uint16_t)(*p)[1] << 8);

    *p += 2;
    return v;
}

static uint32_t get_u32(const uint8_t **p)
{
    uint32_t v = (uint32_t)get_u16(p) | (uint32_t)get_u16(p) << 16;

    return v;
}

static uint64_t get_u64(const uint8_t **p)
{
    return (uint64_t)get_u32(p) | (uint64_t)get_u32(p) << 32;
}

static void encode_plane(uint8_t **p, const zdog_plane *pl)
{
    put_i32(p, pl->x);
    put_i32(p, pl->y);
    put_i32(p, pl->z);
    put_u16(p, pl->yaw);
    put_u16(p, pl->pitch);
    put_i16(p, pl->roll);
    put_i32(p, pl->speed);
    put_i32(p, pl->health);
    put_u8(p, pl->team);
    put_u8(p, pl->alive);
    put_u16(p, pl->fire_cd);
    put_u16(p, pl->respawn_in);
}

static void encode_shot(uint8_t **p, const zdog_shot *s)
{
    put_i32(p, s->x);
    put_i32(p, s->y);
    put_i32(p, s->z);
    put_i32(p, s->vx);
    put_i32(p, s->vy);
    put_i32(p, s->vz);
    put_u8(p, s->owner);
    put_u8(p, s->team);
    put_u16(p, s->ttl);
    put_u8(p, s->active);
}

size_t zdog_state_encode(const zdog_match *m, uint8_t *out, size_t cap)
{
    uint8_t *p = out;

    if (!out || cap < ZDOG_STATE_WIRE_MAX)
        return 0;
    put_u64(&p, m->tick);
    put_u8(&p, m->num_planes);
    put_u8(&p, m->phase);
    put_u8(&p, m->winner);
    put_u32(&p, m->score[0]);
    put_u32(&p, m->score[1]);
    for (unsigned i = 0; i < 4; i++)
        put_u64(&p, m->rng.s[i]);
    for (unsigned i = 0; i < ZDOG_MAX_PLANES; i++)
        encode_plane(&p, &m->planes[i]);
    for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++)
        encode_shot(&p, &m->shots[i]);
    return (size_t)(p - out);
}

uint64_t zdog_state_checksum(const zdog_match *m)
{
    uint8_t buf[ZDOG_STATE_WIRE_MAX];
    size_t n = zdog_state_encode(m, buf, sizeof buf);
    uint64_t h = UINT64_C(14695981039346656037); /* FNV-1a 64 */

    for (size_t i = 0; i < n; i++) {
        h ^= buf[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

size_t zdog_obs_encode(const zdog_obs *o, uint8_t *out, size_t cap)
{
    uint8_t *p = out;

    if (!out || cap < ZDOG_OBS_WIRE_LEN)
        return 0;
    put_u64(&p, o->tick);
    put_u8(&p, o->self_index);
    put_u8(&p, o->num_planes);
    put_i32(&p, o->x);
    put_i32(&p, o->y);
    put_i32(&p, o->z);
    put_u16(&p, o->yaw);
    put_u16(&p, o->pitch);
    put_i16(&p, o->roll);
    put_i32(&p, o->speed);
    put_i32(&p, o->health);
    put_u8(&p, o->team);
    put_u32(&p, o->score_red);
    put_u32(&p, o->score_blue);
    put_u32(&p, o->ticks_left);
    put_u8(&p, o->enemy_valid);
    put_i32(&p, o->rel_x);
    put_i32(&p, o->rel_y);
    put_i32(&p, o->rel_z);
    put_u32(&p, o->dist);
    put_i32(&p, o->evx);
    put_i32(&p, o->evy);
    put_i32(&p, o->evz);
    put_i32(&p, o->ehealth);
    return (size_t)(p - out);
}

bool zdog_obs_decode(const uint8_t *in, size_t len, zdog_obs *out)
{
    const uint8_t *p = in;

    if (!in || !out || len < ZDOG_OBS_WIRE_LEN)
        return false;
    out->tick = get_u64(&p);
    out->self_index = *p++;
    out->num_planes = *p++;
    out->x = (int32_t)get_u32(&p);
    out->y = (int32_t)get_u32(&p);
    out->z = (int32_t)get_u32(&p);
    out->yaw = get_u16(&p);
    out->pitch = get_u16(&p);
    out->roll = (int16_t)get_u16(&p);
    out->speed = (int32_t)get_u32(&p);
    out->health = (int32_t)get_u32(&p);
    out->team = *p++;
    out->score_red = get_u32(&p);
    out->score_blue = get_u32(&p);
    out->ticks_left = get_u32(&p);
    out->enemy_valid = *p++;
    out->rel_x = (int32_t)get_u32(&p);
    out->rel_y = (int32_t)get_u32(&p);
    out->rel_z = (int32_t)get_u32(&p);
    out->dist = get_u32(&p);
    out->evx = (int32_t)get_u32(&p);
    out->evy = (int32_t)get_u32(&p);
    out->evz = (int32_t)get_u32(&p);
    out->ehealth = (int32_t)get_u32(&p);
    return true;
}

size_t zdog_ctl_encode(const zdog_ctl *c, uint8_t *out, size_t cap)
{
    uint8_t *p = out;

    if (!out || cap < ZDOG_CTL_WIRE_LEN)
        return 0;
    put_i16(&p, c->roll);
    put_i16(&p, c->pitch);
    put_i16(&p, c->throttle);
    put_u8(&p, c->fire);
    return (size_t)(p - out);
}

bool zdog_ctl_decode(const uint8_t *in, size_t len, zdog_ctl *out)
{
    const uint8_t *p = in;

    if (!in || !out || len < ZDOG_CTL_WIRE_LEN)
        return false;
    out->roll = (int16_t)get_u16(&p);
    out->pitch = (int16_t)get_u16(&p);
    out->throttle = (int16_t)get_u16(&p);
    out->fire = *p++;
    return true;
}

int16_t zdog_sin16(uint16_t brad)
{
    return zdog_sin(brad);
}

int16_t zdog_cos16(uint16_t brad)
{
    return zdog_cos(brad);
}
