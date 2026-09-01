/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Replay verification and integer isometric 3D for zdogview.
 */
#include "zdogview/zdogview.h"

#include <string.h>

static uint32_t zv_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t zv_u64(const uint8_t *p)
{
    return (uint64_t)zv_u32(p) | ((uint64_t)zv_u32(p + 4) << 32);
}

static int zv_fail(zdogview_verified *out, const char *reason)
{
    if (out)
        out->reason = reason;
    return ZDOGVIEW_MISMATCH;
}

int zdogview_verify(const uint8_t *buf, size_t len, zdogview_verified *out)
{
    if (!out)
        return ZDOGVIEW_BAD_ARG;
    memset(out, 0, sizeof(*out));
    if (!buf)
        return zv_fail(out, "truncated");
    if (len < ZDOGVIEW_HEADER_LEN + ZDOG_STATE_WIRE_MAX)
        return zv_fail(out, "truncated");
    if (memcmp(buf, ZDOGVIEW_REPLAY_MAGIC, ZDOGVIEW_REPLAY_MAGIC_LEN) != 0)
        return zv_fail(out, "header-magic");
    if (zv_u32(buf + ZDOGVIEW_REPLAY_MAGIC_LEN) != ZDOGVIEW_REPLAY_VERSION)
        return zv_fail(out, "header-version");
    out->seed = zv_u64(buf + ZDOGVIEW_REPLAY_MAGIC_LEN + 4u);
    out->planes_per_team = buf[ZDOGVIEW_REPLAY_MAGIC_LEN + 4u + 8u];
    if (out->planes_per_team < 1 || out->planes_per_team > 4)
        return zv_fail(out, "header-planes");
    out->num_planes = 2u * out->planes_per_team;
    const size_t tick_bytes = (size_t)out->num_planes * ZDOG_CTL_WIRE_LEN;
    const size_t frames_len = len - ZDOGVIEW_HEADER_LEN - ZDOG_STATE_WIRE_MAX;
    if (tick_bytes == 0 || frames_len % tick_bytes != 0)
        return zv_fail(out, "size");
    out->recorded_ticks = frames_len / tick_bytes;

    zdog_match m;
    zdog_match_init(&m, out->seed, out->planes_per_team);
    bool was_alive[ZDOG_MAX_PLANES];
    for (unsigned i = 0; i < out->num_planes; i++)
        was_alive[i] = m.planes[i].alive != 0;

    const uint8_t *fp = buf + ZDOGVIEW_HEADER_LEN;
    for (uint64_t t = 0; t < out->recorded_ticks; t++) {
        zdog_ctl ctls[ZDOG_MAX_PLANES];
        for (unsigned i = 0; i < out->num_planes; i++) {
            if (!zdog_ctl_decode(fp, ZDOG_CTL_WIRE_LEN, &ctls[i]))
                return zv_fail(out, "ctl-frame");
            fp += ZDOG_CTL_WIRE_LEN;
        }
        zdog_tick(&m, ctls);
        for (unsigned i = 0; i < out->num_planes; i++) {
            if (was_alive[i] && m.planes[i].alive == 0 &&
                out->num_kills < ZDOGVIEW_MAX_KILLS) {
                zdogview_kill *k = &out->kills[out->num_kills++];
                k->tick = m.tick;
                k->x = m.planes[i].x;
                k->y = m.planes[i].y;
                k->z = m.planes[i].z;
                k->team = m.planes[i].team;
            }
            was_alive[i] = m.planes[i].alive != 0;
        }
    }

    if (m.phase != ZDOG_PHASE_DONE)
        return zv_fail(out, "match-incomplete");
    if (m.tick != out->recorded_ticks)
        return zv_fail(out, "tick-count");
    uint8_t state[ZDOG_STATE_WIRE_MAX];
    if (zdog_state_encode(&m, state, sizeof(state)) != sizeof(state))
        return ZDOGVIEW_FAIL;
    if (memcmp(state, fp, ZDOG_STATE_WIRE_MAX) != 0)
        return zv_fail(out, "final-state");

    out->final_m = m;
    out->reason = NULL;
    return ZDOGVIEW_OK;
}

int zdogview_seek(const uint8_t *buf, size_t len, const zdogview_verified *v,
                  uint64_t tick, zdog_match *out)
{
    if (!buf || !v || !out)
        return ZDOGVIEW_BAD_ARG;
    const size_t need = ZDOGVIEW_HEADER_LEN +
                        (size_t)v->recorded_ticks * (size_t)v->num_planes *
                            ZDOG_CTL_WIRE_LEN +
                        ZDOG_STATE_WIRE_MAX;
    if (len < need)
        return ZDOGVIEW_FAIL;
    if (tick > v->recorded_ticks)
        tick = v->recorded_ticks;
    zdog_match_init(out, v->seed, v->planes_per_team);
    const uint8_t *fp = buf + ZDOGVIEW_HEADER_LEN;
    for (uint64_t t = 0; t < tick; t++) {
        zdog_ctl ctls[ZDOG_MAX_PLANES];
        for (unsigned i = 0; i < v->num_planes; i++) {
            if (!zdog_ctl_decode(fp, ZDOG_CTL_WIRE_LEN, &ctls[i]))
                return ZDOGVIEW_FAIL;
            fp += ZDOG_CTL_WIRE_LEN;
        }
        zdog_tick(out, ctls);
    }
    return ZDOGVIEW_OK;
}

static void zv_put(zdogview_frame *f, int x, int y, uint8_t r, uint8_t g,
                   uint8_t b)
{
    if (x < 0 || y < 0 || x >= (int)ZDOGVIEW_WIDTH ||
        y >= (int)ZDOGVIEW_HEIGHT)
        return;
    uint8_t *p = &f->rgb[((size_t)y * ZDOGVIEW_WIDTH + (size_t)x) * 3u];
    p[0] = r;
    p[1] = g;
    p[2] = b;
}

static void zv_project(int32_t x, int32_t y, int32_t z, int *sx, int *sy)
{
    *sx = (int)((int)ZDOGVIEW_WIDTH / 2 + ((int64_t)x - (int64_t)z) / 8000);
    *sy = (int)((int)ZDOGVIEW_HEIGHT / 2 + ((int64_t)x + (int64_t)z) / 16000 -
                (int64_t)y / 8000);
}

static int64_t zv_edge(int x0, int y0, int x1, int y1, int x, int y)
{
    return (int64_t)(x - x0) * (y1 - y0) - (int64_t)(y - y0) * (x1 - x0);
}

static void zv_tri(zdogview_frame *f, int x0, int y0, int x1, int y1, int x2,
                   int y2, uint8_t r, uint8_t g, uint8_t b)
{
    int minx = x0, maxx = x0, miny = y0, maxy = y0;
    if (x1 < minx)
        minx = x1;
    if (x1 > maxx)
        maxx = x1;
    if (y1 < miny)
        miny = y1;
    if (y1 > maxy)
        maxy = y1;
    if (x2 < minx)
        minx = x2;
    if (x2 > maxx)
        maxx = x2;
    if (y2 < miny)
        miny = y2;
    if (y2 > maxy)
        maxy = y2;
    if (minx < 0)
        minx = 0;
    if (miny < 0)
        miny = 0;
    if (maxx >= (int)ZDOGVIEW_WIDTH)
        maxx = (int)ZDOGVIEW_WIDTH - 1;
    if (maxy >= (int)ZDOGVIEW_HEIGHT)
        maxy = (int)ZDOGVIEW_HEIGHT - 1;
    const int64_t a01 = zv_edge(x0, y0, x1, y1, x2, y2);
    if (a01 == 0)
        return;
    for (int y = miny; y <= maxy; y++) {
        for (int x = minx; x <= maxx; x++) {
            const int64_t w0 = zv_edge(x1, y1, x2, y2, x, y);
            const int64_t w1 = zv_edge(x2, y2, x0, y0, x, y);
            const int64_t w2 = zv_edge(x0, y0, x1, y1, x, y);
            if (a01 > 0) {
                if (w0 >= 0 && w1 >= 0 && w2 >= 0)
                    zv_put(f, x, y, r, g, b);
            } else if (w0 <= 0 && w1 <= 0 && w2 <= 0) {
                zv_put(f, x, y, r, g, b);
            }
        }
    }
}

static void zv_line(zdogview_frame *f, int x0, int y0, int x1, int y1,
                    uint8_t r, uint8_t g, uint8_t b)
{
    int dx = x1 - x0;
    int dy = y1 - y0;
    if (dx < 0)
        dx = -dx;
    if (dy < 0)
        dy = -dy;
    const int sx = x0 < x1 ? 1 : -1;
    const int sy = y0 < y1 ? 1 : -1;
    int err = dx - dy;
    int x = x0, y = y0;
    for (;;) {
        zv_put(f, x, y, r, g, b);
        if (x == x1 && y == y1)
            break;
        const int e2 = 2 * err;
        if (e2 > -dy) {
            err -= dy;
            x += sx;
        }
        if (e2 < dx) {
            err += dx;
            y += sy;
        }
    }
}

#define ZV_CITY_CELL_MM 140000
#define ZV_CITY_HALF 7
#define ZV_CITY_MAX ((2 * ZV_CITY_HALF + 1) * (2 * ZV_CITY_HALF + 1))
#define ZV_BURST_TICKS 45u

typedef struct {
    int32_t x, z, w, d, h;
    uint8_t wr, wg, wb;
} zv_bldg;

static void zv_quad(zdogview_frame *f, int x0, int y0, int x1, int y1, int x2,
                    int y2, int x3, int y3, uint8_t r, uint8_t g, uint8_t b)
{
    zv_tri(f, x0, y0, x1, y1, x2, y2, r, g, b);
    zv_tri(f, x0, y0, x2, y2, x3, y3, r, g, b);
}

static void zv_box(zdogview_frame *f, const zv_bldg *b)
{
    const int32_t hx = b->w / 2, hz = b->d / 2;
    int t[4][2], gnd[4][2];
    const int32_t cx[4] = { b->x - hx, b->x + hx, b->x + hx, b->x - hx };
    const int32_t cz[4] = { b->z - hz, b->z - hz, b->z + hz, b->z + hz };
    for (int i = 0; i < 4; i++) {
        zv_project(cx[i], b->h, cz[i], &t[i][0], &t[i][1]);
        zv_project(cx[i], 0, cz[i], &gnd[i][0], &gnd[i][1]);
    }
    /* Far sides then roof so nearer faces paint over. */
    zv_quad(f, t[3][0], t[3][1], t[2][0], t[2][1], gnd[2][0], gnd[2][1],
            gnd[3][0], gnd[3][1], (uint8_t)(b->wr / 2), (uint8_t)(b->wg / 2),
            (uint8_t)(b->wb / 2));
    zv_quad(f, t[1][0], t[1][1], t[2][0], t[2][1], gnd[2][0], gnd[2][1],
            gnd[1][0], gnd[1][1], (uint8_t)((b->wr * 3) / 4),
            (uint8_t)((b->wg * 3) / 4), (uint8_t)((b->wb * 3) / 4));
    zv_quad(f, t[0][0], t[0][1], t[1][0], t[1][1], t[2][0], t[2][1], t[3][0],
            t[3][1], b->wr, b->wg, b->wb);
}

static unsigned zv_city_fill(uint64_t seed, zv_bldg *out, unsigned cap)
{
    static const uint8_t walls[][3] = {
        { 27, 32, 44 }, { 34, 42, 58 }, { 24, 36, 40 },
        { 43, 37, 58 }, { 30, 46, 52 },
    };
    zxoshiro256ss rng;
    zxoshiro256ss_init(&rng, seed ^ UINT64_C(0xC17B116));
    unsigned n = 0;
    for (int gx = -ZV_CITY_HALF; gx <= ZV_CITY_HALF; gx++) {
        for (int gz = -ZV_CITY_HALF; gz <= ZV_CITY_HALF; gz++) {
            const int32_t cx = (int32_t)gx * ZV_CITY_CELL_MM;
            const int32_t cz = (int32_t)gz * ZV_CITY_CELL_MM;
            const int32_t acx = cx < 0 ? -cx : cx;
            const int32_t acz = cz < 0 ? -cz : cz;
            if (acx > 380000 && acz < 130000)
                continue;
            if (zxoshiro256ss_below(&rng, 100u) < 34u)
                continue;
            if (n >= cap)
                return n;
            zv_bldg *b = &out[n++];
            b->x = cx + (int32_t)zxoshiro256ss_below(&rng, 4000u) * 10 -
                   20000;
            b->z = cz + (int32_t)zxoshiro256ss_below(&rng, 4000u) * 10 -
                   20000;
            b->w = 30000 + (int32_t)zxoshiro256ss_below(&rng, 4500u) * 10;
            b->d = 30000 + (int32_t)zxoshiro256ss_below(&rng, 4500u) * 10;
            if (zxoshiro256ss_below(&rng, 100u) < 12u)
                b->h = 95000 + (int32_t)zxoshiro256ss_below(&rng, 6000u) * 10;
            else
                b->h = 18000 + (int32_t)zxoshiro256ss_below(&rng, 5500u) * 10;
            const unsigned pick =
                (unsigned)zxoshiro256ss_below(&rng, 100000u);
            const unsigned wi = pick % 5u;
            b->wr = walls[wi][0];
            b->wg = walls[wi][1];
            b->wb = walls[wi][2];
        }
    }
    return n;
}

static void zv_city_sort(zv_bldg *b, unsigned n)
{
    /* Far (large x+z) first so nearer roofs overpaint. */
    for (unsigned i = 1; i < n; i++) {
        zv_bldg key = b[i];
        int j = (int)i - 1;
        const int64_t kd = (int64_t)key.x + (int64_t)key.z;
        while (j >= 0 && (int64_t)b[j].x + (int64_t)b[j].z < kd) {
            b[j + 1] = b[j];
            j--;
        }
        b[j + 1] = key;
    }
}

static void zv_draw_ground(zdogview_frame *out)
{
    int gx[4], gy[4];
    const int32_t h = ZDOG_WORLD_HALF;
    zv_project(-h, 0, -h, &gx[0], &gy[0]);
    zv_project(h, 0, -h, &gx[1], &gy[1]);
    zv_project(h, 0, h, &gx[2], &gy[2]);
    zv_project(-h, 0, h, &gx[3], &gy[3]);
    zv_tri(out, gx[0], gy[0], gx[1], gy[1], gx[2], gy[2], 13, 17, 26);
    zv_tri(out, gx[0], gy[0], gx[2], gy[2], gx[3], gy[3], 13, 17, 26);
    zv_line(out, gx[0], gy[0], gx[1], gy[1], 36, 48, 68);
    zv_line(out, gx[1], gy[1], gx[2], gy[2], 36, 48, 68);
    zv_line(out, gx[2], gy[2], gx[3], gy[3], 36, 48, 68);
    zv_line(out, gx[3], gy[3], gx[0], gy[0], 36, 48, 68);
    for (int i = -2; i <= 2; i++) {
        int ax0, ay0, ax1, ay1, bx0, by0, bx1, by1;
        const int32_t g = (int32_t)i * (h / 2);
        zv_project(-h, 0, g, &ax0, &ay0);
        zv_project(h, 0, g, &ax1, &ay1);
        zv_project(g, 0, -h, &bx0, &by0);
        zv_project(g, 0, h, &bx1, &by1);
        zv_line(out, ax0, ay0, ax1, ay1, 26, 36, 50);
        zv_line(out, bx0, by0, bx1, by1, 26, 36, 50);
    }
}

static void zv_draw_plane(zdogview_frame *out, const zdog_plane *p)
{
    const int16_t sy = zdog_sin16(p->yaw);
    const int16_t cy = zdog_cos16(p->yaw);
    const int16_t sp = zdog_sin16(p->pitch);
    const int16_t cp = zdog_cos16(p->pitch);
    const int32_t fx = (int32_t)((int64_t)sy * cp / 32768);
    const int32_t fy = -sp;
    const int32_t fz = (int32_t)((int64_t)cy * cp / 32768);
    const int32_t nx = p->x + fx * 12000 / 32768;
    const int32_t ny = p->y + fy * 12000 / 32768;
    const int32_t nz = p->z + fz * 12000 / 32768;
    const int32_t lx = p->x + cy * 5000 / 32768 - fx * 4000 / 32768;
    const int32_t ly = p->y;
    const int32_t lz = p->z - sy * 5000 / 32768 - fz * 4000 / 32768;
    const int32_t rx = p->x - cy * 5000 / 32768 - fx * 4000 / 32768;
    const int32_t ry = p->y;
    const int32_t rz = p->z + sy * 5000 / 32768 - fz * 4000 / 32768;
    int x0, y0, x1, y1, x2, y2, sx, sy2;
    zv_project(p->x, 0, p->z, &sx, &sy2);
    zv_put(out, sx, sy2, 0, 0, 0);
    zv_put(out, sx + 1, sy2, 0, 0, 0);
    zv_project(nx, ny, nz, &x0, &y0);
    zv_project(lx, ly, lz, &x1, &y1);
    zv_project(rx, ry, rz, &x2, &y2);
    if (!p->alive)
        zv_tri(out, x0, y0, x1, y1, x2, y2, 61, 74, 92);
    else if (p->team == 0)
        zv_tri(out, x0, y0, x1, y1, x2, y2, 255, 107, 94);
    else
        zv_tri(out, x0, y0, x1, y1, x2, y2, 87, 166, 255);
}

static void zv_draw_shots(zdogview_frame *out, const zdog_match *m)
{
    for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++) {
        const zdog_shot *s = &m->shots[i];
        if (!s->active)
            continue;
        int hx, hy, tx, ty;
        zv_project(s->x, s->y, s->z, &hx, &hy);
        zv_project(s->x - s->vx / 60, s->y - s->vy / 60, s->z - s->vz / 60,
                   &tx, &ty);
        if (s->team == 0)
            zv_line(out, tx, ty, hx, hy, 255, 200, 120);
        else
            zv_line(out, tx, ty, hx, hy, 160, 220, 255);
        zv_put(out, hx, hy, 255, 245, 200);
        zv_put(out, hx + 1, hy, 255, 245, 200);
    }
}

static void zv_draw_bursts(zdogview_frame *out, uint64_t tick,
                           const zdogview_kill *kills, unsigned n)
{
    if (!kills)
        return;
    for (unsigned i = 0; i < n; i++) {
        const zdogview_kill *k = &kills[i];
        if (tick < k->tick || tick >= k->tick + ZV_BURST_TICKS)
            continue;
        const unsigned age = (unsigned)(tick - k->tick);
        const int rad = 1 + (int)(age / 6u);
        int sx, sy;
        zv_project(k->x, k->y, k->z, &sx, &sy);
        const uint8_t r = 255, g = (uint8_t)(150u + (45u - age) * 2u), b = 60;
        for (int dy = -rad; dy <= rad; dy++) {
            for (int dx = -rad; dx <= rad; dx++) {
                if (dx * dx + dy * dy <= rad * rad)
                    zv_put(out, sx + dx, sy + dy, r, g, b);
            }
        }
    }
}

/* 3x5 digits; each row is a 3-bit mask (bit 0 = left). */
static const uint8_t zv_font[10][5] = {
    { 0x7, 0x5, 0x5, 0x5, 0x7 }, { 0x2, 0x2, 0x2, 0x2, 0x2 },
    { 0x7, 0x1, 0x7, 0x4, 0x7 }, { 0x7, 0x1, 0x7, 0x1, 0x7 },
    { 0x5, 0x5, 0x7, 0x1, 0x1 }, { 0x7, 0x4, 0x7, 0x1, 0x7 },
    { 0x7, 0x4, 0x7, 0x5, 0x7 }, { 0x7, 0x1, 0x1, 0x1, 0x1 },
    { 0x7, 0x5, 0x7, 0x5, 0x7 }, { 0x7, 0x5, 0x7, 0x1, 0x7 }
};

static void zv_glyph(zdogview_frame *out, int x, int y, unsigned d, uint8_t r,
                     uint8_t g, uint8_t b)
{
    if (d > 9)
        d = 0;
    for (int row = 0; row < 5; row++) {
        for (int col = 0; col < 3; col++) {
            if (zv_font[d][row] & (uint8_t)(1u << col)) {
                zv_put(out, x + col, y + row, r, g, b);
                zv_put(out, x + col, y + row + 1, r, g, b);
            }
        }
    }
}

static void zv_num(zdogview_frame *out, int x, int y, unsigned v, uint8_t r,
                   uint8_t g, uint8_t b)
{
    unsigned d0 = (v / 10u) % 10u, d1 = v % 10u;
    zv_glyph(out, x, y, d0, r, g, b);
    zv_glyph(out, x + 5, y, d1, r, g, b);
}

static void zv_draw_hud(zdogview_frame *out, const zdog_match *m)
{
    zv_num(out, 4, 4, m->score[0] % 100u, 255, 107, 94);
    zv_num(out, (int)ZDOGVIEW_WIDTH - 14, 4, m->score[1] % 100u, 87, 166,
           255);
    const unsigned secs = (unsigned)(m->tick / 60u);
    zv_num(out, (int)ZDOGVIEW_WIDTH / 2 - 12, 4, (secs / 60u) % 100u, 110,
           231, 160);
    zv_put(out, (int)ZDOGVIEW_WIDTH / 2 - 2, 8, 110, 231, 160);
    zv_num(out, (int)ZDOGVIEW_WIDTH / 2 + 2, 4, secs % 60u, 110, 231, 160);
}

static void zv_draw_match(const zdog_match *m, zdogview_frame *out)
{
    zv_draw_ground(out);
    for (unsigned i = 0; i < m->num_planes; i++)
        zv_draw_plane(out, &m->planes[i]);
    zv_draw_shots(out, m);
}

void zdogview_render(const zdog_match *m, zdogview_frame *out)
{
    if (!m || !out)
        return;
    memset(out->rgb, 0, sizeof(out->rgb));
    for (unsigned i = 0; i < sizeof(out->rgb); i += 3u) {
        out->rgb[i] = 8;
        out->rgb[i + 1u] = 11;
        out->rgb[i + 2u] = 18;
    }
    zv_draw_match(m, out);
}

void zdogview_render_scene(const zdog_match *m, uint64_t seed,
                           const zdogview_kill *kills, unsigned num_kills,
                           zdogview_frame *out)
{
    if (!m || !out)
        return;
    zdogview_render(m, out);
    zv_bldg city[ZV_CITY_MAX];
    unsigned n = zv_city_fill(seed, city, ZV_CITY_MAX);
    zv_city_sort(city, n);
    for (unsigned i = 0; i < n; i++)
        zv_box(out, &city[i]);
    /* Planes and shots over the city so contacts stay readable. */
    for (unsigned i = 0; i < m->num_planes; i++)
        zv_draw_plane(out, &m->planes[i]);
    zv_draw_shots(out, m);
    zv_draw_bursts(out, m->tick, kills, num_kills);
    zv_draw_hud(out, m);
}
