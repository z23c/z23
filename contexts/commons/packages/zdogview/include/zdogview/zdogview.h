/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zdogview — C23 integer 3D view of a verified zdogfight replay.
 *
 * No raylib, no OpenGL, no heap, no clock. The hosted package re-simulates
 * a canonical ZDOGREPL stream with the integer match core, refuses any
 * replay it cannot re-derive, and projects the live match into a fixed
 * RGB framebuffer with integer isometric math. Pixels never write match
 * state. Two nodes that accept the same replay produce the same frame
 * bytes.
 */
#ifndef ZDOGVIEW_H
#define ZDOGVIEW_H

#include <stddef.h>
#include <stdint.h>

#include "zdogfight/zdogfight.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZDOGVIEW_REPLAY_MAGIC "ZDOGREPL"
#define ZDOGVIEW_REPLAY_MAGIC_LEN 8u
#define ZDOGVIEW_REPLAY_VERSION 1u
#define ZDOGVIEW_HEADER_LEN (ZDOGVIEW_REPLAY_MAGIC_LEN + 4u + 8u + 1u)

#define ZDOGVIEW_WIDTH 320u
#define ZDOGVIEW_HEIGHT 180u
#define ZDOGVIEW_MAX_KILLS 1024u

#define ZDOGVIEW_OK 0
#define ZDOGVIEW_MISMATCH 1
#define ZDOGVIEW_BAD_ARG 2
#define ZDOGVIEW_FAIL 4

typedef struct {
    uint64_t tick;
    int32_t x, y, z; /* millimetres */
    uint8_t team;
} zdogview_kill;

typedef struct {
    uint64_t seed;
    uint8_t planes_per_team;
    unsigned num_planes;
    uint64_t recorded_ticks;
    zdog_match final_m;
    zdogview_kill kills[ZDOGVIEW_MAX_KILLS];
    unsigned num_kills;
    const char *reason; /* named mismatch, or NULL on success */
} zdogview_verified;

typedef struct {
    uint8_t rgb[ZDOGVIEW_WIDTH * ZDOGVIEW_HEIGHT * 3u];
} zdogview_frame;

/* Re-simulate `buf`. Returns ZDOGVIEW_OK only when the recorded controls
 * drive the match to ZDOG_PHASE_DONE at the recorded tick count with a
 * byte-identical final state. On mismatch, out->reason is a stable name. */
int zdogview_verify(const uint8_t *buf, size_t len, zdogview_verified *out);

/* Walk the already-verified control stream to `tick` (clamped). */
int zdogview_seek(const uint8_t *buf, size_t len, const zdogview_verified *v,
                  uint64_t tick, zdog_match *out);

/* Integer isometric projection of `m` into `out`. Deterministic. */
void zdogview_render(const zdog_match *m, zdogview_frame *out);

/* Same projection plus a seed-derived city (zprng), kill bursts from
 * `kills[0..num_kills)`, and a score/tick HUD. `kills` may be NULL when
 * num_kills is 0. Two nodes that pass the same verified replay produce
 * the same frame bytes. */
void zdogview_render_scene(const zdog_match *m, uint64_t seed,
                           const zdogview_kill *kills, unsigned num_kills,
                           zdogview_frame *out);

#ifdef __cplusplus
}
#endif

#endif /* ZDOGVIEW_H */
