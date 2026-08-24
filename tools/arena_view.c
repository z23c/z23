/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * arena_view: interactive 3D replay viewer for the ZCODE Arena (raylib).
 *
 * Re-simulates one canonical zdogfight replay (the format written by
 * tools/arena_runner.c) with no pilots. A window opens only after the
 * recorded controls drive the match to ZDOG_PHASE_DONE at the recorded
 * tick count with a byte-identical final state. HUD roots are recomputed
 * here. Pixels never write match state; rendering floats stay on this
 * side of the integer core.
 *
 * City geometry is a function of the replay seed through zprng. Kill
 * bursts come from alive->dead transitions observed during verification.
 *
 * Usage:
 *   arena_view --replay <file> [--red-label <text>] [--blue-label <text>]
 *              [--check-only] [--frames <n>] [--screenshot <file.png>]
 *              [--seek <tick>] [--cam chase|cockpit|orbit|overview]
 *              [--show]
 *
 *   --check-only    verify and print roots; no window
 *   --frames <n>    close after n rendered frames
 *   --screenshot    PNG of the last rendered frame (requires --frames)
 *   --seek <tick>   start playback at this tick
 *   --cam <mode>    initial camera
 *   --show          visible window; default is hidden for automation
 *
 * Controls (window):
 *   TAB cycle plane   C camera   SPACE pause   F step
 *   LEFT/RIGHT seek 1s   PGUP/PGDN 10s   HOME/END ends
 *   +/- speed   R restart   ESC quit
 *   ORBIT: drag rotate, wheel zoom
 *
 * Exit codes: 0 ok; 1 replay mismatch; 2 usage;
 * 4 runtime failure (read/allocation/video, logged to stderr).
 */

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <raylib.h>
#include <raymath.h>
#include <rlgl.h>

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "zdogfight/zdogfight.h"
#include "zdogview/zdogview.h"

/* Replay container constants — must track tools/arena_runner.c and
 * tools/arena_svg.c. The format is the contract between the writer and
 * its readers and is asserted by the verification below. */
#define AV_REPLAY_MAGIC "ZDOGREPL"
#define AV_REPLAY_MAGIC_LEN 8u
#define AV_REPLAY_VERSION 1u
#define AV_HEADER_LEN (AV_REPLAY_MAGIC_LEN + 4u + 8u + 1u)
#define AV_MAX_REPLAY_BYTES                                              \
    (AV_HEADER_LEN + (size_t)ZDOG_TICK_LIMIT * ZDOG_MAX_PLANES *         \
                         ZDOG_CTL_WIRE_LEN +                             \
     (size_t)ZDOG_STATE_WIRE_MAX)

#define AV_MM_TO_M 0.001f
#define AV_WORLD_SPAN_M (2.0f * ZDOG_WORLD_HALF * AV_MM_TO_M)

/* Explosion lifetime, in ticks (0.75 s at the fixed 60 Hz). */
#define AV_BURST_TICKS 45u
#define AV_MAX_EVENTS 1024u

/* Per-plane trail: ring of sampled positions. */
#define AV_TRAIL_LEN 64u
#define AV_TRAIL_EVERY 3u

typedef struct {
    uint64_t tick;
    float x, y, z; /* metres */
    uint8_t team;
} av_event;

typedef struct {
    const char *replay_path;
    const char *red_label;
    const char *blue_label;
} av_opts;

static void av_err(const char *what, const char *detail)
{
    fprintf(stderr, "arena_view: error: %s%s%s\n", what, detail ? ": " : "",
            detail ? detail : "");
}

static void av_usage(FILE *out)
{
    fprintf(out,
            "usage:\n"
            "  arena_view --replay <file>\n"
            "      [--red-label <text>] [--blue-label <text>]\n"
            "      [--check-only] [--frames <n>] [--screenshot <file>]\n"
            "      [--seek <tick>] [--cam chase|cockpit|orbit|overview]\n"
            "      [--show]\n"
            "  the window stays hidden unless --show is passed\n");
}

static int av_mismatch(const char *what)
{
    fprintf(stderr, "arena_view: replay=MISMATCH %s\n", what);
    return 1;
}

static uint8_t *av_read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        av_err("cannot open replay", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        av_err("fseek failed", path);
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz <= 0 || (unsigned long)sz > AV_MAX_REPLAY_BYTES) {
        av_err("bad replay size (0 or above the replay cap)", path);
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        av_err("fseek(set) failed", path);
        fclose(f);
        return NULL;
    }
    uint8_t *buf = zcl_malloc((size_t)sz, "arena_view.replay");
    if (!buf) {
        av_err("malloc failed for replay file", path);
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        av_err("short read", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len_out = (size_t)sz;
    return buf;
}

static void av_sha3(const uint8_t *data, size_t len,
                    uint8_t out[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, data, len);
    sha3_256_finalize(&ctx, out);
}

/* Walk every recorded tick once. Returns 0 only on the same acceptance
 * arena_runner --verify-replay applies. */
typedef struct {
    uint64_t seed;
    uint8_t planes_per_team;
    unsigned num_planes;
    uint64_t recorded_ticks;
    zdog_match final_m;
    av_event events[AV_MAX_EVENTS];
    unsigned num_events;
    zdogview_kill kills[ZDOGVIEW_MAX_KILLS];
    unsigned num_kills;
    uint8_t replay_root[SHA3_256_OUTPUT_SIZE];
    uint8_t state_root[SHA3_256_OUTPUT_SIZE];
} av_verified;

static int av_verify(const uint8_t *buf, size_t len, av_verified *v)
{
    memset(v, 0, sizeof(*v));
    zdogview_verified z;
    const int rc = zdogview_verify(buf, len, &z);
    if (rc == ZDOGVIEW_MISMATCH)
        return av_mismatch(z.reason ? z.reason : "unknown");
    if (rc != ZDOGVIEW_OK)
        return rc;
    v->seed = z.seed;
    v->planes_per_team = z.planes_per_team;
    v->num_planes = z.num_planes;
    v->recorded_ticks = z.recorded_ticks;
    v->final_m = z.final_m;
    v->num_kills = z.num_kills;
    if (v->num_kills > ZDOGVIEW_MAX_KILLS)
        v->num_kills = ZDOGVIEW_MAX_KILLS;
    memcpy(v->kills, z.kills, (size_t)v->num_kills * sizeof(v->kills[0]));
    v->num_events = v->num_kills;
    if (v->num_events > AV_MAX_EVENTS)
        v->num_events = AV_MAX_EVENTS;
    for (unsigned i = 0; i < v->num_events; i++) {
        v->events[i].tick = z.kills[i].tick;
        v->events[i].x = z.kills[i].x * AV_MM_TO_M;
        v->events[i].y = z.kills[i].y * AV_MM_TO_M;
        v->events[i].z = z.kills[i].z * AV_MM_TO_M;
        v->events[i].team = z.kills[i].team;
    }
    uint8_t state[ZDOG_STATE_WIRE_MAX];
    if (zdog_state_encode(&z.final_m, state, sizeof(state)) != sizeof(state)) {
        av_err("zdog_state_encode short", "tool bug");
        return 4;
    }
    av_sha3(buf, len, v->replay_root);
    av_sha3(state, sizeof(state), v->state_root);
    return 0;
}

/* City geometry is a pure function of the replay seed. */
#define AV_CITY_CELL 140.0f       /* metres between blocks */
#define AV_CITY_HALF_CELLS 7      /* grid spans -7..7 cells per axis */
#define AV_MAX_BUILDINGS ((2 * AV_CITY_HALF_CELLS + 1) *                        \
                          (2 * AV_CITY_HALF_CELLS + 1))

typedef struct {
    float x, z;        /* centre, metres */
    float w, d, h;     /* footprint and height, metres */
    Color wall;
    Color trim;
} av_building;

typedef struct {
    av_building b[AV_MAX_BUILDINGS];
    unsigned n;
} av_city;

static Color av_city_wall(unsigned k)
{
    /* Dark navy/cyberpunk palette, echoing the contact-sheet colours. */
    static const Color walls[] = {
        { 27, 32, 44, 255 },   { 34, 42, 58, 255 },
        { 24, 36, 40, 255 },   { 43, 37, 58, 255 },
        { 30, 46, 52, 255 },
    };
    return walls[k % 5u];
}

static void av_city_build(av_city *city, uint64_t seed)
{
    memset(city, 0, sizeof(*city));
    zxoshiro256ss rng;
    zxoshiro256ss_init(&rng, seed ^ UINT64_C(0xC17B116));
    for (int gx = -AV_CITY_HALF_CELLS; gx <= AV_CITY_HALF_CELLS; gx++) {
        for (int gz = -AV_CITY_HALF_CELLS; gz <= AV_CITY_HALF_CELLS; gz++) {
            const float cx = gx * AV_CITY_CELL;
            const float cz = gz * AV_CITY_CELL;
            /* Leave the two spawn corridors open so the opening line-up
             * reads clearly. Spawns sit at x = +/-500, z near 0. */
            if (fabsf(cx) > 380.0f && fabsf(cz) < 130.0f)
                continue;
            if (zxoshiro256ss_below(&rng, 100u) < 34u)
                continue; /* keep gaps: streets, plazas, sight lines */
            if (city->n >= AV_MAX_BUILDINGS)
                return;
            av_building *b = &city->b[city->n++];
            b->x = cx + (float)zxoshiro256ss_below(&rng, 4000u) / 100.0f -
                   20.0f;
            b->z = cz + (float)zxoshiro256ss_below(&rng, 4000u) / 100.0f -
                   20.0f;
            b->w = 30.0f + (float)zxoshiro256ss_below(&rng, 4500u) / 100.0f;
            b->d = 30.0f + (float)zxoshiro256ss_below(&rng, 4500u) / 100.0f;
            /* A few landmark towers break the skyline; the rest stay low
             * relative to the 10..500 m flight band. */
            if (zxoshiro256ss_below(&rng, 100u) < 12u)
                b->h = 95.0f + (float)zxoshiro256ss_below(&rng, 6000u) /
                                 100.0f;
            else
                b->h = 18.0f + (float)zxoshiro256ss_below(&rng, 5500u) /
                                 100.0f;
            const unsigned pick =
                (unsigned)zxoshiro256ss_below(&rng, 100000u);
            b->wall = av_city_wall(pick);
            b->trim = pick % 3u == 0 ? (Color){ 70, 205, 170, 255 }
                                     : (Color){ 96, 84, 190, 255 };
        }
    }
}

/* Integer sim state -> render space. None of this writes the match. */

static Vector3 av_forward(const zdog_plane *p)
{
    /* Exact reference convention from packages/zdogfight: fx =
     * sin(yaw)*cos(pitch), fy = -sin(pitch), fz = cos(yaw)*cos(pitch),
     * all Q1.15. */
    const float sy = (float)zdog_sin16(p->yaw) / 32768.0f;
    const float cy = (float)zdog_cos16(p->yaw) / 32768.0f;
    const float sp = (float)zdog_sin16(p->pitch) / 32768.0f;
    const float cp = (float)zdog_cos16(p->pitch) / 32768.0f;
    Vector3 f = { sy * cp, -sp, cy * cp };
    return Vector3Normalize(f);
}

static Vector3 av_position(const zdog_plane *p)
{
    Vector3 v = { p->x * AV_MM_TO_M, p->y * AV_MM_TO_M, p->z * AV_MM_TO_M };
    return v;
}

/* Orientation basis for one plane: forward from the sim, banked by roll
 * around forward (positive roll = right turn in the sim = right wing
 * down here). */
static void av_basis(const zdog_plane *p, Vector3 *fwd, Vector3 *up,
                     Vector3 *right)
{
    const Vector3 f = av_forward(p);
    const Vector3 wu = { 0, 1, 0 };
    Vector3 r = Vector3CrossProduct(wu, f);
    if (Vector3Length(r) < 1e-4f)
        r = (Vector3){ 1, 0, 0 };
    r = Vector3Normalize(r);
    Vector3 u = Vector3Normalize(Vector3CrossProduct(f, r));
    const float bank =
        -(float)p->roll / 32767.0f * 80.0f * DEG2RAD; /* +roll banks right */
    const float cb = cosf(bank), sb = sinf(bank);
    const Vector3 fr = Vector3CrossProduct(f, r);
    const Vector3 fu = Vector3CrossProduct(f, u);
    *right = Vector3Normalize(Vector3Add(
        Vector3Scale(r, cb), Vector3Scale(fr, sb)));
    *up = Vector3Normalize(
        Vector3Add(Vector3Scale(u, cb), Vector3Scale(fu, sb)));
    *fwd = f;
}

static Matrix av_plane_matrix(const zdog_plane *p)
{
    Vector3 f, u, r;
    av_basis(p, &f, &u, &r);
    const Vector3 pos = av_position(p);
    /* Column-major OpenGL layout: columns are right/up/forward/position. */
    Matrix m = { r.x,  u.x,  f.x,  pos.x,
                 r.y,  u.y,  f.y,  pos.y,
                 r.z,  u.z,  f.z,  pos.z,
                 0.0f, 0.0f, 0.0f, 1.0f };
    return m;
}

static Color av_team_color(uint8_t team)
{
    return team == 0 ? (Color){ 255, 107, 94, 255 }   /* red  */
                     : (Color){ 87, 166, 255, 255 };  /* blue */
}

static Color av_team_dim(uint8_t team)
{
    return team == 0 ? (Color){ 140, 52, 46, 255 }
                     : (Color){ 44, 78, 122, 255 };
}

static void av_draw_plane(const zdog_plane *p)
{
    const Matrix m = av_plane_matrix(p);
    const Color body = av_team_color(p->team);
    rlPushMatrix();
    rlMultMatrixf(MatrixToFloat(m));
    if (!p->alive) {
        /* Wreckage: dark cross of two boxes at the death point. */
        DrawCube((Vector3){ 0 }, 3.0f, 0.4f, 0.8f,
                 (Color){ 61, 74, 92, 220 });
        DrawCube((Vector3){ 0 }, 0.8f, 0.4f, 3.0f,
                 (Color){ 61, 74, 92, 220 });
        rlPopMatrix();
        return;
    }
    DrawCube((Vector3){ 0 }, 1.1f, 0.7f, 4.2f, body);      /* fuselage */
    DrawCube((Vector3){ 0, 0, 2.4f }, 0.8f, 0.5f, 1.0f,
             av_team_dim(p->team));                        /* nose     */
    DrawCube((Vector3){ 0, 0, -1.6f }, 0.5f, 1.6f, 0.9f,
             av_team_dim(p->team));                        /* tail fin */
    DrawCube((Vector3){ 0, -0.1f, -1.2f }, 6.4f, 0.18f, 1.5f,
             body);                                        /* wings    */
    DrawSphere((Vector3){ 0, 0.45f, 0.4f }, 0.34f,
               (Color){ 230, 240, 250, 255 });             /* canopy   */
    DrawSphere((Vector3){ -3.15f, 0.0f, -1.2f }, 0.14f,
               (Color){ 255, 48, 48, 255 });               /* left nav */
    DrawSphere((Vector3){ 3.15f, 0.0f, -1.2f }, 0.14f,
               (Color){ 48, 220, 96, 255 });               /* right nav */
    DrawSphere((Vector3){ 0, 0, -2.35f }, 0.42f,
               (Color){ 255, 150, 48, 230 });              /* exhaust  */
    DrawSphere((Vector3){ 0, 0, -2.85f }, 0.22f,
               (Color){ 255, 230, 160, 190 });
    rlPopMatrix();
}

static void av_draw_shadow(const zdog_plane *p)
{
    const Vector3 pos = av_position(p);
    DrawCylinder((Vector3){ pos.x, 0.04f, pos.z }, 2.8f, 2.8f, 0.06f, 10,
                 (Color){ 0, 0, 0, p->alive ? 90 : 40 });
}

static void av_draw_shots(const zdog_match *m)
{
    for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++) {
        const zdog_shot *s = &m->shots[i];
        if (!s->active)
            continue;
        Vector3 pos = { s->x * AV_MM_TO_M, s->y * AV_MM_TO_M,
                        s->z * AV_MM_TO_M };
        Vector3 vel = { s->vx * AV_MM_TO_M, s->vy * AV_MM_TO_M,
                        s->vz * AV_MM_TO_M };
        const Vector3 tail = Vector3Subtract(
            pos, Vector3Scale(Vector3Normalize(vel), 6.0f));
        DrawLine3D(tail, pos,
                   s->team == 0 ? (Color){ 255, 200, 120, 220 }
                                : (Color){ 160, 220, 255, 220 });
        DrawSphere(pos, 0.55f, (Color){ 255, 245, 200, 255 });
    }
}

static void av_draw_explosions(const av_verified *v, uint64_t tick)
{
    for (unsigned i = 0; i < v->num_events; i++) {
        const av_event *e = &v->events[i];
        if (tick < e->tick || tick >= e->tick + AV_BURST_TICKS)
            continue;
        const float t = (float)(tick - e->tick) / (float)AV_BURST_TICKS;
        const float radius = 2.0f + 30.0f * t;
        const unsigned char alpha = (unsigned char)(200.0f * (1.0f - t));
        const Vector3 pos = { e->x, e->y, e->z };
        DrawSphere(pos, radius,
                   (Color){ 255, (unsigned char)(150 + 80 * (1.0f - t)),
                            60, alpha });
        /* Eight debris shards, directions fixed per event index. */
        for (unsigned d = 0; d < 8u; d++) {
            const float ang =
                (float)d * (PI / 4.0f) + (float)(i % 7u) * 0.19f;
            const float el = (d % 2u == 0) ? 0.35f : -0.2f;
            const float reach = 4.0f + 44.0f * t;
            Vector3 off = { cosf(ang) * cosf(el) * reach, sinf(el) * reach,
                            sinf(ang) * cosf(el) * reach };
            DrawCube(Vector3Add(pos, off), 1.2f, 1.2f, 1.2f,
                     (Color){ 255, 120, 50, alpha });
        }
    }
}

/* Viewer state */

typedef enum {
    AV_CAM_CHASE = 0,
    AV_CAM_COCKPIT,
    AV_CAM_ORBIT,
    AV_CAM_OVERVIEW,
    AV_CAM_COUNT
} av_cam_mode;

typedef struct {
    const uint8_t *buf;      /* replay bytes (borrowed) */
    const av_verified *v;    /* verified facts (borrowed) */
    const char *replay_path; /* for diagnostics (borrowed) */
    const char *red_label;   /* HUD labels (borrowed) */
    const char *blue_label;
    zdog_match m;            /* state at the current tick */
    uint64_t tick;           /* current completed ticks */
    bool playing;
    float speed;             /* 0.25 .. 8 */
    float acc;               /* fractional tick accumulator */
    unsigned follow;         /* followed plane index */
    av_cam_mode cam;
    Camera3D camera;
    Vector3 chase_pos;       /* smoothed chase position */
    /* orbit controls */
    float orbit_yaw, orbit_pitch, orbit_dist;
    /* trails */
    Vector3 trail[ZDOG_MAX_PLANES][AV_TRAIL_LEN];
    unsigned trail_len[ZDOG_MAX_PLANES];
    unsigned trail_head[ZDOG_MAX_PLANES];
    unsigned trail_skip;
    float shake;             /* screen-shake amplitude, decays */
} av_view;

static void av_trail_clear(av_view *vw, unsigned i)
{
    vw->trail_len[i] = 0;
    vw->trail_head[i] = 0;
}

static void av_trail_push(av_view *vw, unsigned i)
{
    if (vw->m.planes[i].alive == 0)
        return;
    Vector3 *slot;
    if (vw->trail_len[i] < AV_TRAIL_LEN) {
        slot = &vw->trail[i][vw->trail_len[i]++];
    } else {
        slot = &vw->trail[i][vw->trail_head[i]];
        vw->trail_head[i] = (vw->trail_head[i] + 1u) % AV_TRAIL_LEN;
    }
    *slot = av_position(&vw->m.planes[i]);
}

/* Re-derive the match at an arbitrary tick by walking from tick zero. */
static void av_seek(av_view *vw, uint64_t target)
{
    if (target > vw->v->recorded_ticks)
        target = vw->v->recorded_ticks;
    zdog_match_init(&vw->m, vw->v->seed, vw->v->planes_per_team);
    vw->tick = 0;
    vw->acc = 0.0f;
    for (unsigned i = 0; i < vw->v->num_planes; i++)
        av_trail_clear(vw, i);
    vw->trail_skip = 0;
    const uint8_t *fp = vw->buf + AV_HEADER_LEN;
    while (vw->tick < target) {
        zdog_ctl ctls[ZDOG_MAX_PLANES];
        for (unsigned i = 0; i < vw->v->num_planes; i++) {
            /* Post-verification these decodes cannot fail; refuse loudly
             * rather than rendering a lie if memory were corrupted. */
            if (!zdog_ctl_decode(fp, ZDOG_CTL_WIRE_LEN, &ctls[i])) {
                av_err("ctl-frame re-decode failed", vw->replay_path);
                exit(4);
            }
            fp += ZDOG_CTL_WIRE_LEN;
        }
        zdog_tick(&vw->m, ctls);
        vw->tick++;
        if (++vw->trail_skip >= AV_TRAIL_EVERY) {
            vw->trail_skip = 0;
            for (unsigned i = 0; i < vw->v->num_planes; i++)
                av_trail_push(vw, i);
        }
    }
    /* Snap the chase camera behind the followed plane instead of gliding
     * across the whole arena after a seek. */
    if (vw->follow < vw->v->num_planes) {
        const zdog_plane *pl = &vw->m.planes[vw->follow];
        const Vector3 f = av_forward(pl);
        vw->chase_pos = Vector3Subtract(av_position(pl),
                                        Vector3Scale(f, 16.0f));
        vw->chase_pos.y += 5.0f;
    }
}

static void av_advance(av_view *vw, unsigned n)
{
    const uint8_t *fp =
        vw->buf + AV_HEADER_LEN +
        (size_t)vw->tick * (size_t)vw->v->num_planes * ZDOG_CTL_WIRE_LEN;
    for (unsigned k = 0; k < n && vw->tick < vw->v->recorded_ticks; k++) {
        zdog_ctl ctls[ZDOG_MAX_PLANES];
        for (unsigned i = 0; i < vw->v->num_planes; i++) {
            if (!zdog_ctl_decode(fp, ZDOG_CTL_WIRE_LEN, &ctls[i])) {
                av_err("ctl-frame re-decode failed", vw->replay_path);
                exit(4);
            }
            fp += ZDOG_CTL_WIRE_LEN;
        }
        zdog_tick(&vw->m, ctls);
        vw->tick++;
        if (++vw->trail_skip >= AV_TRAIL_EVERY) {
            vw->trail_skip = 0;
            for (unsigned i = 0; i < vw->v->num_planes; i++)
                av_trail_push(vw, i);
        }
    }
}

static void av_camera_update(av_view *vw, float dt)
{
    const zdog_plane *pl = &vw->m.planes[vw->follow];
    const Vector3 pos = av_position(pl);
    Camera3D *c = &vw->camera;
    switch (vw->cam) {
    case AV_CAM_CHASE: {
        const Vector3 f = av_forward(pl);
        Vector3 want = Vector3Subtract(pos, Vector3Scale(f, 16.0f));
        want.y += 5.0f;
        const float k = 1.0f - expf(-dt * 6.0f);
        vw->chase_pos = Vector3Lerp(vw->chase_pos, want, k);
        c->position = vw->chase_pos;
        c->target = Vector3Add(pos, Vector3Scale(f, 10.0f));
        c->up = (Vector3){ 0, 1, 0 };
        break;
    }
    case AV_CAM_COCKPIT: {
        Vector3 f, u, r;
        av_basis(pl, &f, &u, &r);
        (void)r;
        c->position = Vector3Add(pos, Vector3Add(Vector3Scale(f, 2.2f),
                                                 Vector3Scale(u, 0.9f)));
        c->target = Vector3Add(pos, Vector3Scale(f, 60.0f));
        c->up = u;
        break;
    }
    case AV_CAM_ORBIT: {
        if (IsMouseButtonDown(MOUSE_BUTTON_LEFT)) {
            const Vector2 d = GetMouseDelta();
            vw->orbit_yaw -= d.x * 0.005f;
            vw->orbit_pitch += d.y * 0.005f;
            vw->orbit_pitch = Clamp(vw->orbit_pitch, -1.35f, 1.35f);
        }
        const float w = GetMouseWheelMove();
        if (w != 0.0f)
            vw->orbit_dist = Clamp(vw->orbit_dist - w * 12.0f, 12.0f,
                                   400.0f);
        const float cp = cosf(vw->orbit_pitch);
        Vector3 off = { sinf(vw->orbit_yaw) * cp, sinf(vw->orbit_pitch),
                        cosf(vw->orbit_yaw) * cp };
        c->position = Vector3Add(pos, Vector3Scale(off, vw->orbit_dist));
        c->target = pos;
        c->up = (Vector3){ 0, 1, 0 };
        break;
    }
    case AV_CAM_OVERVIEW: {
        const float w = GetMouseWheelMove();
        static float ov_h = 1050.0f;
        if (w != 0.0f)
            ov_h = Clamp(ov_h - w * 60.0f, 350.0f, 1800.0f);
        c->position = (Vector3){ 0, ov_h, ov_h * 0.42f };
        c->target = (Vector3){ 0, 40, 0 };
        c->up = (Vector3){ 0, 1, 0 };
        break;
    }
    default:
        break;
    }
    if (vw->shake > 0.01f) {
        c->position.x += (float)GetRandomValue(-100, 100) / 100.0f *
                         vw->shake;
        c->position.y += (float)GetRandomValue(-100, 100) / 100.0f *
                         vw->shake;
        vw->shake *= expf(-dt * 5.0f);
    }
}

static void av_draw_world(const av_view *vw, const av_city *city)
{
    ClearBackground((Color){ 8, 11, 18, 255 });
    DrawSphere((Vector3){ 420.0f, 740.0f, -580.0f }, 48.0f,
               (Color){ 255, 214, 120, 255 });
    DrawSphere((Vector3){ 420.0f, 740.0f, -580.0f }, 90.0f,
               (Color){ 255, 170, 70, 40 });
    DrawPlane((Vector3){ 0, 0, 0 }, (Vector2){ AV_WORLD_SPAN_M,
                                               AV_WORLD_SPAN_M },
              (Color){ 13, 17, 26, 255 });
    DrawGrid((int)(AV_WORLD_SPAN_M / 50.0f) + 2, 50.0f);
    for (int i = 0; i < 16; i++) {
        const float a = (float)i / 16.0f * 2.0f * PI;
        const float px = cosf(a) * 995.0f, pz = sinf(a) * 995.0f;
        DrawCube((Vector3){ px, 6, pz }, 2, 12, 2,
                 (Color){ 70, 205, 170, 140 });
    }
    for (unsigned i = 0; i < city->n; i++) {
        const av_building *b = &city->b[i];
        DrawCube((Vector3){ b->x, b->h / 2.0f, b->z }, b->w, b->h, b->d,
                 b->wall);
        DrawCubeWires((Vector3){ b->x, b->h / 2.0f, b->z }, b->w, b->h,
                      b->d, b->trim);
    }
    /* Trails, oldest first, fading in. */
    for (unsigned i = 0; i < vw->v->num_planes; i++) {
        for (unsigned k = 1; k < vw->trail_len[i]; k++) {
            const Vector3 *a =
                &vw->trail[i][(vw->trail_head[i] + k - 1u) % AV_TRAIL_LEN];
            const Vector3 *b =
                &vw->trail[i][(vw->trail_head[i] + k) % AV_TRAIL_LEN];
            /* Skip the segment that crosses the toroidal seam. */
            if (fabsf(a->x - b->x) > 500.0f ||
                fabsf(a->z - b->z) > 500.0f)
                continue;
            const float fade = (float)k / (float)vw->trail_len[i];
            Color col = av_team_color(vw->m.planes[i].team);
            col.a = (unsigned char)(90.0f * fade);
            DrawLine3D(*a, *b, col);
        }
    }
    av_draw_shots(&vw->m);
    for (unsigned i = 0; i < vw->v->num_planes; i++) {
        av_draw_shadow(&vw->m.planes[i]);
        av_draw_plane(&vw->m.planes[i]);
    }
    av_draw_explosions(vw->v, vw->tick);
}

/* HUD */

static const char *av_winner_name(uint8_t winner)
{
    switch (winner) {
    case ZDOG_WINNER_RED:  return "RED WINS";
    case ZDOG_WINNER_BLUE: return "BLUE WINS";
    default:               return "DRAW";
    }
}

static void av_draw_hud(const av_view *vw)
{
    const av_verified *v = vw->v;
    const Color hud_green = { 110, 231, 160, 255 };
    const Color hud_dim = { 130, 145, 165, 255 };
    const Color red_col = { 255, 107, 94, 255 };
    const Color blue_col = { 87, 166, 255, 255 };

    /* Team scores. */
    DrawText(TextFormat("%u", vw->m.score[0]), 28, 22, 44, red_col);
    DrawText(vw->red_label, 30, 72, 20, red_col);
    const int bw = MeasureText(TextFormat("%u", vw->m.score[1]), 44);
    DrawText(TextFormat("%u", vw->m.score[1]), GetScreenWidth() - bw - 28,
             22, 44, blue_col);
    const int blw = MeasureText(vw->blue_label, 20);
    DrawText(vw->blue_label, GetScreenWidth() - blw - 30, 72, 20,
             blue_col);
    /* Clock / phase. */
    const unsigned secs = (unsigned)(vw->tick / 60u);
    const char *speed_tag =
        vw->playing ? TextFormat("x%g", (double)vw->speed) : "PAUSED";
    const char *clock = TextFormat("T+%02u:%02u  %s", secs / 60u, secs % 60u,
                                   speed_tag);
    DrawText(clock, GetScreenWidth() / 2 - MeasureText(clock, 24) / 2, 24,
             24, hud_green);

    if (vw->m.phase == ZDOG_PHASE_DONE) {
        const char *banner = TextFormat(
            "%s %u-%u", av_winner_name(v->final_m.winner),
            vw->m.score[0], vw->m.score[1]);
        const int fs = 64;
        const int bwide = MeasureText(banner, fs);
        const Color banner_col =
            v->final_m.winner == ZDOG_WINNER_BLUE ? blue_col
            : v->final_m.winner == ZDOG_WINNER_RED ? red_col
                                                   : hud_dim;
        DrawText(banner, GetScreenWidth() / 2 - bwide / 2,
                 GetScreenHeight() / 3, fs, banner_col);
    }

    if (vw->cam == AV_CAM_COCKPIT) {
        const int cx = GetScreenWidth() / 2;
        const int cy = GetScreenHeight() / 2;
        DrawCircleLines(cx, cy, 18, hud_green);
        DrawLine(cx - 28, cy, cx - 10, cy, hud_green);
        DrawLine(cx + 10, cy, cx + 28, cy, hud_green);
        DrawLine(cx, cy - 28, cx, cy - 10, hud_green);
        DrawLine(cx, cy + 10, cx, cy + 28, hud_green);
    }

    /* Followed-plane panel. */
    const zdog_plane *pl = &vw->m.planes[vw->follow];
    const int px = 28, py = GetScreenHeight() - 118;
    DrawText(TextFormat("PLANE %u/%u  %s", vw->follow + 1u,
                        v->num_planes,
                        pl->team == 0 ? vw->red_label : vw->blue_label),
             px, py, 20, hud_dim);
    DrawText(TextFormat("ALT %5dm   SPD %3dm/s   HDG %3ddeg",
                        (int)(pl->y * AV_MM_TO_M),
                        pl->speed / 1000,
                        (int)((float)pl->yaw / 65536.0f * 360.0f)),
             px, py + 26, 22, hud_green);
    /* Health bar. */
    DrawRectangle(px, py + 56, 220, 14, (Color){ 30, 38, 50, 255 });
    const float hf = (float)pl->health / 100.0f;
    const Color hc = pl->team == 0 ? red_col : blue_col;
    DrawRectangle(px + 2, py + 58, (int)(216.0f * hf), 10, hc);
    DrawText(pl->alive ? TextFormat("HULL %d", pl->health) : "DESTROYED",
             px + 232, py + 54, 18,
             pl->alive ? hud_dim : (Color){ 255, 120, 90, 255 });

    /* Camera + help, bottom-right. */
    static const char *cam_names[] = { "CHASE", "COCKPIT", "ORBIT",
                                       "OVERVIEW" };
    const char *help2 = "+/- speed   R restart   ESC quit";
    const char *help1 =
        vw->cam == AV_CAM_ORBIT
            ? "TAB plane  C cam  SPACE pause  F step  drag/wheel orbit"
            : "TAB plane  C cam  SPACE pause  F step";
    const char *seek =
        "LEFT/RIGHT seek 1s   PGUP/PGDN seek 10s   HOME/END ends";
    DrawText(TextFormat("[%s]", cam_names[vw->cam]), GetScreenWidth() - 150,
             py, 20, hud_green);
    DrawText(help1, GetScreenWidth() - MeasureText(help1, 18) - 28,
             py + 26, 18, hud_dim);
    DrawText(seek, GetScreenWidth() - MeasureText(seek, 18) - 28,
             py + 48, 18, hud_dim);
    DrawText(help2, GetScreenWidth() - MeasureText(help2, 18) - 28,
             py + 70, 18, hud_dim);

    /* Verified tag: the recomputed roots are the point of the picture. */
    char rr[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    char sr[SHA3_256_OUTPUT_SIZE * 2u + 1u];

    /* Live tactical minimap — the contact-sheet's overhead view, live.
     * Same mapping as tools/arena_svg.c: +x right, +z up. */
    const int map_s = 172, pad = 16;
    const int mx = GetScreenWidth() - map_s - pad, my = 104;
    DrawRectangle(mx, my, map_s, map_s, (Color){ 11, 15, 22, 205 });
    DrawRectangleLinesEx((Rectangle){ (float)mx, (float)my, (float)map_s,
                                      (float)map_s },
                         2, (Color){ 36, 48, 68, 255 });
    for (int g = 1; g < 5; g++) {
        const int d = map_s * g / 5;
        DrawLine(mx + d, my, mx + d, my + map_s,
                 (Color){ 26, 36, 50, 160 });
        DrawLine(mx, my + d, mx + map_s, my + d,
                 (Color){ 26, 36, 50, 160 });
    }
    for (unsigned i = 0; i < v->num_planes; i++) {
        const zdog_plane *pl2 = &vw->m.planes[i];
        const int cx2 =
            mx + (int)(((int64_t)pl2->x + ZDOG_WORLD_HALF) * map_s /
                       (2 * (int64_t)ZDOG_WORLD_HALF));
        const int cy2 =
            my + (int)(((int64_t)ZDOG_WORLD_HALF - pl2->z) * map_s /
                       (2 * (int64_t)ZDOG_WORLD_HALF));
        const Color tc = pl2->team == 0 ? red_col : blue_col;
        if (!pl2->alive) {
            DrawLine(cx2 - 4, cy2 - 4, cx2 + 4, cy2 + 4,
                     (Color){ 61, 74, 92, 220 });
            DrawLine(cx2 - 4, cy2 + 4, cx2 + 4, cy2 - 4,
                     (Color){ 61, 74, 92, 220 });
            continue;
        }
        DrawCircle(cx2, cy2, 4.0f, tc);
        /* Heading tick, from the sim's own trig convention. */
        DrawCircle(cx2 +
                       (int)((float)zdog_sin16(pl2->yaw) / 32768.0f * 8.0f),
                   cy2 -
                       (int)((float)zdog_cos16(pl2->yaw) / 32768.0f * 8.0f),
                   1.6f, tc);
        if (i == vw->follow)
            DrawCircleLines(cx2, cy2, 6.5f,
                            (Color){ 235, 242, 250, 230 });
    }
    for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++) {
        const zdog_shot *s = &vw->m.shots[i];
        if (!s->active)
            continue;
        const int sx =
            mx + (int)(((int64_t)s->x + ZDOG_WORLD_HALF) * map_s /
                       (2 * (int64_t)ZDOG_WORLD_HALF));
        const int sy2 =
            my + (int)(((int64_t)ZDOG_WORLD_HALF - s->z) * map_s /
                       (2 * (int64_t)ZDOG_WORLD_HALF));
        DrawRectangle(sx - 1, sy2 - 1, 3, 3,
                      s->team == 0 ? (Color){ 255, 200, 120, 230 }
                                   : (Color){ 160, 220, 255, 230 });
    }

    /* Roots footer. */
    zcl_hex_encode(v->replay_root, SHA3_256_OUTPUT_SIZE, rr);
    zcl_hex_encode(v->state_root, SHA3_256_OUTPUT_SIZE, sr);
    const char *line = TextFormat(
        "VERIFIED  replay %.16s..  state %.16s..  tick %llu/%llu", rr, sr,
        (unsigned long long)vw->tick,
        (unsigned long long)v->recorded_ticks);
    DrawText(line, GetScreenWidth() / 2 - MeasureText(line, 16) / 2,
             GetScreenHeight() - 26, 16, hud_green);
}

/* Composite the hosted C23 integer view (zdogview) into the local window.
 * Same match bytes, no GL in that path. */
static void av_draw_hosted(Texture2D *tex, const av_view *vw)
{
    static zdogview_frame fr;
    static uint8_t rgba[ZDOGVIEW_WIDTH * ZDOGVIEW_HEIGHT * 4u];
    zdogview_render_scene(&vw->m, vw->v->seed, vw->v->kills, vw->v->num_kills,
                          &fr);
    for (unsigned i = 0; i < ZDOGVIEW_WIDTH * ZDOGVIEW_HEIGHT; i++) {
        rgba[i * 4u + 0u] = fr.rgb[i * 3u + 0u];
        rgba[i * 4u + 1u] = fr.rgb[i * 3u + 1u];
        rgba[i * 4u + 2u] = fr.rgb[i * 3u + 2u];
        rgba[i * 4u + 3u] = 255;
    }
    UpdateTexture(*tex, rgba);
    const int x = 16;
    const int y = GetScreenHeight() - (int)ZDOGVIEW_HEIGHT - 36;
    DrawRectangle(x - 2, y - 18, (int)ZDOGVIEW_WIDTH + 4,
                  (int)ZDOGVIEW_HEIGHT + 22, (Color){ 11, 15, 22, 205 });
    DrawText("C23 HOSTED VIEW", x, y - 16, 12, (Color){ 110, 231, 160, 255 });
    DrawTexture(*tex, x, y, WHITE);
    DrawRectangleLines(x - 1, y - 1, (int)ZDOGVIEW_WIDTH + 2,
                       (int)ZDOGVIEW_HEIGHT + 2, (Color){ 36, 48, 68, 255 });
}

/* Input */

static void av_input(av_view *vw)
{
    if (IsKeyPressed(KEY_TAB))
        vw->follow = (vw->follow + 1u) % vw->v->num_planes;
    if (IsKeyPressed(KEY_C))
        vw->cam = (av_cam_mode)(((int)vw->cam + 1) % (int)AV_CAM_COUNT);
    if (IsKeyPressed(KEY_SPACE)) {
        vw->playing = !vw->playing;
        vw->acc = 0.0f;
    }
    if (IsKeyPressed(KEY_F) && !vw->playing)
        av_advance(vw, 1);
    if (IsKeyPressed(KEY_R))
        av_seek(vw, 0);
    if (IsKeyPressed(KEY_HOME))
        av_seek(vw, 0);
    if (IsKeyPressed(KEY_END))
        av_seek(vw, vw->v->recorded_ticks);
    if (IsKeyPressed(KEY_RIGHT))
        av_seek(vw, vw->tick + 60);
    if (IsKeyPressed(KEY_LEFT))
        av_seek(vw, vw->tick > 60 ? vw->tick - 60 : 0);
    if (IsKeyPressed(KEY_PAGE_UP))
        av_seek(vw, vw->tick + 600);
    if (IsKeyPressed(KEY_PAGE_DOWN))
        av_seek(vw, vw->tick > 600 ? vw->tick - 600 : 0);
    static const float speeds[] = { 0.25f, 0.5f, 1.0f, 2.0f, 4.0f, 8.0f };
    const unsigned ns = sizeof(speeds) / sizeof(speeds[0]);
    unsigned cur = 0;
    float bd = 1e9f;
    for (unsigned i = 0; i < ns; i++) {
        const float d = fabsf(speeds[i] - vw->speed);
        if (d < bd) {
            bd = d;
            cur = i;
        }
    }
    if (IsKeyPressed(KEY_EQUAL) || IsKeyPressed(KEY_KP_ADD)) {
        if (cur + 1u < ns)
            vw->speed = speeds[cur + 1u];
    }
    if (IsKeyPressed(KEY_MINUS) || IsKeyPressed(KEY_KP_SUBTRACT)) {
        if (cur > 0)
            vw->speed = speeds[cur - 1u];
    }
}

/* Advance playback by the accumulated real time. */
static void av_playback(av_view *vw, float dt)
{
    if (!vw->playing)
        return;
    vw->acc += vw->speed * 60.0f * dt;
    unsigned n = (unsigned)vw->acc;
    if (n > 480u)
        n = 480u;
    vw->acc -= (float)n;
    if (n > 0) {
        const uint64_t before = vw->tick;
        av_advance(vw, n);
        if (vw->tick == before && vw->tick >= vw->v->recorded_ticks)
            vw->playing = false;
    }
    for (unsigned i = 0; i < vw->v->num_events; i++) {
        if (vw->v->events[i].tick == vw->tick) {
            const av_event *e = &vw->v->events[i];
            const Vector3 p = { e->x, e->y, e->z };
            const float dist = Vector3Distance(p, vw->camera.position);
            if (dist < 260.0f)
                vw->shake = 3.5f * (1.0f - dist / 260.0f);
        }
    }
}

static int av_parse_cam(const char *v, int *cam_mode)
{
    if (strcmp(v, "chase") == 0)
        *cam_mode = AV_CAM_CHASE;
    else if (strcmp(v, "cockpit") == 0)
        *cam_mode = AV_CAM_COCKPIT;
    else if (strcmp(v, "orbit") == 0)
        *cam_mode = AV_CAM_ORBIT;
    else if (strcmp(v, "overview") == 0)
        *cam_mode = AV_CAM_OVERVIEW;
    else {
        av_err("unknown camera (chase|cockpit|orbit|overview)", v);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    av_opts o = { NULL, "red", "blue" };
    bool check_only = false;
    long frames_limit = 0; /* 0 = run until closed */
    const char *screenshot = NULL;
    const char *shot_dir = NULL;
    long shot_every = 1;
    const char *shot_every_s = NULL;
    const char *frames_s = NULL;
    const char *seek_s = NULL;
    const char *cam_s = NULL;
    unsigned long long seek_to = 0;
    bool show_window = false;
    int cam_mode = AV_CAM_CHASE;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = NULL;
        char name[64];
        const char *eq = strchr(a, '=');
        size_t nl = eq ? (size_t)(eq - a) : strlen(a);
        if (nl == 0 || nl >= sizeof(name)) {
            av_err("bad argument", a);
            av_usage(stderr);
            return 2;
        }
        memcpy(name, a, nl);
        name[nl] = '\0';
        if (eq)
            v = eq + 1;
        else if (i + 1 < argc)
            v = argv[i + 1];
        bool takes_value = true;
        if (strcmp(name, "--help") == 0) {
            av_usage(stdout);
            return 0;
        }
        if (strcmp(name, "--replay") == 0)
            o.replay_path = v;
        else if (strcmp(name, "--red-label") == 0)
            o.red_label = v;
        else if (strcmp(name, "--blue-label") == 0)
            o.blue_label = v;
        else if (strcmp(name, "--check-only") == 0)
            takes_value = false, check_only = true;
        else if (strcmp(name, "--show") == 0)
            takes_value = false, show_window = true;
        else if (strcmp(name, "--frames") == 0)
            frames_s = v;
        else if (strcmp(name, "--seek") == 0)
            seek_s = v;
        else if (strcmp(name, "--cam") == 0)
            cam_s = v;
        else if (strcmp(name, "--screenshot") == 0)
            screenshot = v;
        else if (strcmp(name, "--screenshot-dir") == 0)
            shot_dir = v;
        else if (strcmp(name, "--screenshot-every") == 0)
            shot_every_s = v;
        else {
            av_err("unknown argument", a);
            av_usage(stderr);
            return 2;
        }
        if (takes_value) {
            if (!v) {
                av_err("missing value for", name);
                av_usage(stderr);
                return 2;
            }
            if (!eq)
                i++;
        }
    }
    if (frames_s) {
        char *end = NULL;
        frames_limit = strtol(frames_s, &end, 10);
        if (!end || *end || frames_limit < 1) {
            av_err("--frames needs a positive integer", frames_s);
            return 2;
        }
    }
    if (seek_s) {
        char *end = NULL;
        seek_to = strtoull(seek_s, &end, 10);
        if (!end || *end) {
            av_err("--seek needs a non-negative integer", seek_s);
            return 2;
        }
    }
    if (cam_s && av_parse_cam(cam_s, &cam_mode) != 0)
        return 2;
    if (!o.replay_path) {
        av_err("missing required argument", "--replay");
        av_usage(stderr);
        return 2;
    }
    if (screenshot && !check_only && frames_limit <= 0) {
        av_err("--screenshot requires --frames", "see usage");
        return 2;
    }
    if (shot_every_s) {
        char *end = NULL;
        shot_every = strtol(shot_every_s, &end, 10);
        if (!end || *end || shot_every < 1) {
            av_err("--screenshot-every needs a positive integer",
                   shot_every_s);
            return 2;
        }
    }
    if (shot_dir && !shot_dir[0]) {
        av_err("--screenshot-dir needs a directory path", shot_dir);
        return 2;
    }

    size_t len = 0;
    uint8_t *buf = av_read_file(o.replay_path, &len);
    if (!buf)
        return 4;

    av_verified *ver = zcl_malloc(sizeof(*ver), "arena_view.verified");
    if (!ver) {
        av_err("malloc failed for verification state", o.replay_path);
        free(buf);
        return 4;
    }
    const int vrc = av_verify(buf, len, ver);
    if (vrc != 0) {
        free(ver);
        free(buf);
        return vrc;
    }

    char rr[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    char sr[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    zcl_hex_encode(ver->replay_root, SHA3_256_OUTPUT_SIZE, rr);
    zcl_hex_encode(ver->state_root, SHA3_256_OUTPUT_SIZE, sr);

    if (check_only) {
        printf("verified replay=%s ticks=%llu events=%u "
               "score=%u-%u winner=%s replay_root=%s state_root=%s\n",
               o.replay_path, (unsigned long long)ver->recorded_ticks,
               ver->num_events, ver->final_m.score[0],
               ver->final_m.score[1],
               av_winner_name(ver->final_m.winner), rr, sr);
        free(ver);
        free(buf);
        return 0;
    }

    av_city city;
    av_city_build(&city, ver->seed);

    av_view vw = { 0 };
    vw.buf = buf;
    vw.v = ver;
    vw.replay_path = o.replay_path;
    vw.red_label = o.red_label;
    vw.blue_label = o.blue_label;
    vw.playing = true;
    vw.speed = 1.0f;
    vw.cam = cam_s ? (av_cam_mode)cam_mode : AV_CAM_CHASE;
    vw.orbit_dist = 60.0f;
    vw.orbit_pitch = 0.45f;
    vw.camera.fovy = 62.0f;
    vw.camera.projection = CAMERA_PERSPECTIVE;
    SetConfigFlags(FLAG_MSAA_4X_HINT);
    if (!show_window)
        SetConfigFlags(FLAG_WINDOW_HIDDEN);
    InitWindow(1280, 720, "ZCODE Arena — verified replay viewer");
    if (!IsWindowReady()) {
        av_err("display/GL context failed",
               show_window ? "visible window" : "hidden window");
        CloseWindow();
        free(ver);
        free(buf);
        return 4;
    }
    SetTargetFPS(60);
    Image hosted_blank =
        GenImageColor((int)ZDOGVIEW_WIDTH, (int)ZDOGVIEW_HEIGHT, BLACK);
    Texture2D hosted_tex = LoadTextureFromImage(hosted_blank);
    UnloadImage(hosted_blank);
    av_seek(&vw, 0);
    if (seek_s)
        av_seek(&vw, seek_to);

    long frame = 0;
    bool io_failed = false;
    while (!WindowShouldClose()) {
        if (frames_limit > 0 && frame >= frames_limit)
            break;
        const float dt = GetFrameTime();
        av_input(&vw);
        av_playback(&vw, dt);
        av_camera_update(&vw, dt);
        BeginDrawing();
        BeginMode3D(vw.camera);
        av_draw_world(&vw, &city);
        EndMode3D();
        av_draw_hud(&vw);
        if (IsTextureValid(hosted_tex))
            av_draw_hosted(&hosted_tex, &vw);
        const char *shot_path = NULL;
        char shot_name[512];
        if (screenshot && frames_limit > 0 && frame + 1 == frames_limit) {
            shot_path = screenshot;
        } else if (shot_dir && frame % shot_every == 0) {
            snprintf(shot_name, sizeof(shot_name), "%s/frame_%08ld.png",
                     shot_dir, frame);
            shot_path = shot_name;
        }
        if (shot_path) {
            /* TakeScreenshot() has no error reporting. Flush the 2D
             * batch first so HUD vertices are in the GL backbuffer. */
            int sw = GetScreenWidth(), sh = GetScreenHeight();
            rlDrawRenderBatchActive();
            unsigned char *rawpx = rlReadScreenPixels(sw, sh);
            if (!rawpx) {
                av_err("backbuffer read failed", shot_path);
                io_failed = true;
            } else {
                Color *px = (Color *)rawpx;
                Image shot = { .data = px,
                               .width = sw,
                               .height = sh,
                               .mipmaps = 1,
                               .format = PIXELFORMAT_UNCOMPRESSED_R8G8B8A8 };
                if (!ExportImage(shot, shot_path)) {
                    av_err("PNG write failed", shot_path);
                    io_failed = true;
                }
                MemFree(px);
            }
        }
        EndDrawing();
        frame++;
    }
    if (IsTextureValid(hosted_tex))
        UnloadTexture(hosted_tex);
    CloseWindow();

    free(ver);
    free(buf);
    return io_failed ? 4 : 0;
}
