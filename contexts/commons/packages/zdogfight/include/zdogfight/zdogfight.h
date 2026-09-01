/* zdogfight — deterministic headless 2-team aerial dogfight match core
 * (C23).
 *
 * This is the authoritative match simulation for cross-node,
 * byte-identical replays: same seed + same per-tick controls produce
 * byte-identical state on any machine and any compiler.
 *
 * Determinism contract:
 *  - fixed-point / integer arithmetic only; no floating point anywhere
 *    in the library (trig is a 256-entry int16 Q1.15 quarter-wave table
 *    with integer linear interpolation);
 *  - no heap allocation, no clock, no rand(), no filesystem, no
 *    network: all state lives in the caller-provided zdog_match;
 *  - the only entropy source is the embedded zxoshiro256ss (zprng),
 *    drawn ONLY by respawns, in ascending plane index order;
 *  - per-tick dt is exactly 1/60 s; every rate is integer-divided by
 *    60 (truncation toward zero is part of the spec).
 *
 * Units and bounds:
 *  - positions are int32 millimetres; x,z are toroidal with wrap at
 *    +/-1,000,000 mm; y is clamped to [10,000, 500,000] mm and pitch
 *    is zeroed at the y limits;
 *  - angles are uint16 "brad16" (65536 == 360 degrees);
 *  - speeds are int32 mm/s in [30,000, 120,000];
 *  - plane roll is int16 Q1.15 of +/-80 degrees (32767 == +80 deg).
 *
 * Match rules: first team to 10 kills wins, otherwise the match ends
 * at tick 36,000 (10 minutes) and the higher score wins (tie -> draw).
 * Once ZDOG_PHASE_DONE, zdog_tick is a no-op.
 *
 * Self-contained except for zprng.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZDOGFIGHT_H
#define ZDOGFIGHT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zprng/zprng.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZDOG_MAX_PLANES 8u
#define ZDOG_MAX_SHOTS 64u

/* World / entity tuning constants (part of the wire-stable spec). */
#define ZDOG_WORLD_HALF 1000000       /* x,z toroidal wrap at +/-mm */
#define ZDOG_Y_MIN 10000              /* mm */
#define ZDOG_Y_MAX 500000             /* mm */
#define ZDOG_SPEED_MIN 30000          /* mm/s */
#define ZDOG_SPEED_MAX 120000         /* mm/s */
#define ZDOG_SPEED_STEP 600           /* mm/s per tick (36,000 per s) */
#define ZDOG_ROLL_STEP 2457           /* roll Q15 per tick (360 deg/s) */
#define ZDOG_ROLL_MAX_BRAD 14563      /* +/-80 deg in brad16 */
#define ZDOG_PITCH_MAX_BRAD 10923     /* +/-60 deg in brad16 */
#define ZDOG_PITCH_RATE_BRAD 18204    /* 100 deg/s in brad16 */
#define ZDOG_YAW_RATE_BRAD 27307      /* 150 deg/s in brad16 */
#define ZDOG_FIRE_CD 6                /* ticks between shots (10/s) */
#define ZDOG_SHOT_SPAWN_MM 8000       /* muzzle offset along forward */
#define ZDOG_SHOT_SPEED 450000        /* mm/s */
#define ZDOG_SHOT_TTL 600             /* ticks (10 s) */
#define ZDOG_SHOT_DAMAGE 10
#define ZDOG_HIT_RADIUS2 25000000     /* (5000 mm)^2 */
#define ZDOG_RESPAWN_TICKS 180
#define ZDOG_SCORE_LIMIT 10
#define ZDOG_TICK_LIMIT 36000         /* 10 minutes at 60 Hz */

#define ZDOG_PHASE_RUNNING 0
#define ZDOG_PHASE_DONE 1

#define ZDOG_WINNER_RED 0
#define ZDOG_WINNER_BLUE 1
#define ZDOG_WINNER_DRAW 2

/* Per-plane per-tick controls. roll/pitch/throttle are Q1.15 and are
 * clamped to -32767..32767 on use (throttle additionally clamped to
 * >= 0): roll full scale == +/-80 deg, pitch full scale == 100 deg/s,
 * throttle maps to ZDOG_SPEED_MIN..ZDOG_SPEED_MAX. fire != 0 fires if
 * the cooldown has expired. */
typedef struct {
    int16_t roll;
    int16_t pitch;
    int16_t throttle;
    uint8_t fire;
} zdog_ctl;

typedef struct {
    int32_t x, y, z;       /* mm */
    uint16_t yaw, pitch;   /* brad16 */
    int16_t roll;          /* Q1.15 of +/-80 deg, actual bank */
    int32_t speed;         /* mm/s */
    int32_t health;        /* 0..100 */
    uint8_t team;          /* 0 = red, 1 = blue */
    uint8_t alive;
    uint16_t fire_cd;      /* ticks until the gun is ready */
    uint16_t respawn_in;   /* ticks until respawn, when dead */
} zdog_plane;

typedef struct {
    int32_t x, y, z;       /* mm */
    int32_t vx, vy, vz;    /* mm/s */
    uint8_t owner;         /* plane index of the shooter */
    uint8_t team;
    uint16_t ttl;          /* ticks of life left */
    uint8_t active;
} zdog_shot;

typedef struct {
    uint64_t tick;         /* completed ticks */
    uint8_t num_planes;    /* 2 * planes_per_team */
    uint8_t phase;         /* ZDOG_PHASE_* */
    uint8_t winner;        /* ZDOG_WINNER_*; meaningful only when DONE
                              (initialised to ZDOG_WINNER_DRAW) */
    uint32_t score[2];     /* kills per team */
    zxoshiro256ss rng;     /* drawn ONLY by respawns */
    zdog_plane planes[ZDOG_MAX_PLANES];
    zdog_shot shots[ZDOG_MAX_SHOTS];
} zdog_match;

/* Set up a match: 1..4 planes per team (values outside are clamped).
 * planes[0..n) are red, planes[n..2n) blue. Red spawns at x=-500,000
 * facing +x (yaw 16384), blue at x=+500,000 facing -x (yaw 49152),
 * y=200,000, z spread on a fixed line; no PRNG is drawn at init. */
void zdog_match_init(zdog_match *m, uint64_t seed, unsigned planes_per_team);

/* Advance one tick (1/60 s). ctls has one entry per plane, in index
 * order; dead planes ignore their controls. No-op when DONE. */
void zdog_tick(zdog_match *m, const zdog_ctl *ctls);

/* Pilot ABI observation for one plane. */
typedef struct {
    uint64_t tick;
    uint8_t self_index;
    uint8_t num_planes;
    int32_t x, y, z;
    uint16_t yaw, pitch;
    int16_t roll;
    int32_t speed;
    int32_t health;
    uint8_t team;
    uint32_t score_red, score_blue;
    uint32_t ticks_left;   /* ZDOG_TICK_LIMIT - tick, saturating */
    /* Nearest living enemy (valid iff enemy_valid): toroidal-aware
     * relative position in mm, Euclidean distance in mm (floor of the
     * integer square root), its velocity in mm/s, its health. */
    uint8_t enemy_valid;
    int32_t rel_x, rel_y, rel_z;
    uint32_t dist;
    int32_t evx, evy, evz;
    int32_t ehealth;
} zdog_obs;

void zdog_observe(const zdog_match *m, unsigned plane_index, zdog_obs *out);

/* Canonical little-endian field-by-field state encoding: fixed order,
 * exact sizes, no struct memcpy, no padding. The encoded size is
 * always exactly ZDOG_STATE_WIRE_MAX bytes. Hashing these bytes (e.g.
 * SHA-256) is the caller's state root; zdog_state_checksum is the
 * built-in cheap FNV-1a/64 over the same bytes. */
#define ZDOG_STATE_WIRE_MAX                                                   \
    (8u + 1u + 1u + 1u + 8u + 32u + /* header + rng */                        \
     ZDOG_MAX_PLANES * 32u + ZDOG_MAX_SHOTS * 29u) /* = 2163 */

size_t zdog_state_encode(const zdog_match *m, uint8_t *out, size_t cap);
uint64_t zdog_state_checksum(const zdog_match *m);

/* Pilot ABI wire codec: fixed-layout little-endian, exact sizes, no
 * padding. zdog_ctl is 7 bytes: int16 LE roll, pitch, throttle +
 * uint8 fire. Decoders require at least the exact wire length and
 * fail on truncated input. */
#define ZDOG_OBS_WIRE_LEN 82u
#define ZDOG_CTL_WIRE_LEN 7u

size_t zdog_obs_encode(const zdog_obs *o, uint8_t *out, size_t cap);
bool zdog_obs_decode(const uint8_t *in, size_t len, zdog_obs *out);
size_t zdog_ctl_encode(const zdog_ctl *c, uint8_t *out, size_t cap);
bool zdog_ctl_decode(const uint8_t *in, size_t len, zdog_ctl *out);

/* Public brad16 trig for pilots: sin/cos of a brad16 angle
 * (65536 == 360 deg) as Q1.15 (32767 == 1.0). These are the exact
 * functions the simulation itself uses, so a pilot's bearing math can
 * never drift from the arena's. Pure integer, no state. */
int16_t zdog_sin16(uint16_t brad);
int16_t zdog_cos16(uint16_t brad);

#ifdef __cplusplus
}
#endif

#endif /* ZDOGFIGHT_H */
