/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 1280x720 game HUD: integer 3D scene, Inter typography, minimap,
 * hosted 320x180 inset, verified roots. Pixels never write match state.
 */
#include "arena_hud.h"

#include <stdio.h>
#include <string.h>

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "presentation/canvas.h"

#define AH_LOG "arena_hud"

static const struct zcl_present_color ah_red = { 255, 107, 94 };
static const struct zcl_present_color ah_blue = { 87, 166, 255 };
static const struct zcl_present_color ah_green = { 110, 231, 160 };
static const struct zcl_present_color ah_dim = { 168, 180, 196 };
static const struct zcl_present_color ah_ink = { 235, 242, 250 };
static const struct zcl_present_color ah_panel = { 11, 15, 22 };
static const struct zcl_present_color ah_edge = { 36, 48, 68 };
static const struct zcl_present_color ah_grid = { 26, 36, 50 };
static const struct zcl_present_color ah_wreck = { 61, 74, 92 };
static const struct zcl_present_color ah_bar = { 30, 38, 50 };

static void ah_err(const char *what, const char *detail)
{
    fprintf(stderr, "%s: error: %s%s%s\n", AH_LOG, what, detail ? ": " : "",
            detail ? detail : "");
}

bool arena_hud_fonts_ready(void)
{
    return zcl_present_canvas_text_width("Z23", 3u, 16u) > 0u &&
           zcl_present_canvas_text_width_strong("Z23", 3u, 16u) > 0u;
}

static const char *ah_str(const char *s, const char *fallback)
{
    return s && s[0] ? s : fallback;
}

static void ah_text(struct zcl_present_canvas *c, int32_t x, int32_t y,
                    const char *s, uint32_t px, struct zcl_present_color col,
                    bool strong)
{
    size_t n = strlen(s);
    if (strong)
        zcl_present_canvas_text_strong(c, x, y, s, n, px, col);
    else
        zcl_present_canvas_text(c, x, y, s, n, px, col);
}

static uint32_t ah_width(const char *s, uint32_t px, bool strong)
{
    size_t n = strlen(s);
    return strong ? zcl_present_canvas_text_width_strong(s, n, px)
                  : zcl_present_canvas_text_width(s, n, px);
}

static const char *ah_winner(uint8_t w)
{
    switch (w) {
    case ZDOG_WINNER_RED:
        return "RED WINS";
    case ZDOG_WINNER_BLUE:
        return "BLUE WINS";
    default:
        return "DRAW";
    }
}

static void ah_blit(uint8_t *dst, int32_t x, int32_t y, const uint8_t *src,
                    unsigned sw, unsigned sh)
{
    for (unsigned row = 0; row < sh; row++) {
        int32_t dy = y + (int32_t)row;
        if (dy < 0 || dy >= (int32_t)ARENA_HUD_HEIGHT)
            continue;
        for (unsigned col = 0; col < sw; col++) {
            int32_t dx = x + (int32_t)col;
            if (dx < 0 || dx >= (int32_t)ARENA_HUD_WIDTH)
                continue;
            size_t si = ((size_t)row * sw + col) * 3u;
            size_t di = ((size_t)dy * ARENA_HUD_WIDTH + (size_t)dx) * 3u;
            dst[di] = src[si];
            dst[di + 1u] = src[si + 1u];
            dst[di + 2u] = src[si + 2u];
        }
    }
}

static int ah_map_x(int32_t world, int mx, int map_s)
{
    return mx + (int)(((int64_t)world + ZDOG_WORLD_HALF) * map_s /
                      (2 * (int64_t)ZDOG_WORLD_HALF));
}

static int ah_map_y(int32_t world_z, int my, int map_s)
{
    return my + (int)(((int64_t)ZDOG_WORLD_HALF - world_z) * map_s /
                      (2 * (int64_t)ZDOG_WORLD_HALF));
}

static void ah_minimap(struct zcl_present_canvas *c, const zdog_match *m,
                       unsigned follow)
{
    const int map_s = 200, pad = 16;
    const int mx = (int)ARENA_HUD_WIDTH - map_s - pad;
    const int my = 108;
    zcl_present_canvas_fill_rect(c, mx, my, (uint32_t)map_s, (uint32_t)map_s,
                                 ah_panel);
    zcl_present_canvas_stroke_rect(c, mx, my, (uint32_t)map_s, (uint32_t)map_s,
                                   2u, ah_edge);
    for (int g = 1; g < 5; g++) {
        const int d = map_s * g / 5;
        zcl_present_canvas_line(c, mx + d, my, mx + d, my + map_s, ah_grid);
        zcl_present_canvas_line(c, mx, my + d, mx + map_s, my + d, ah_grid);
    }
    ah_text(c, mx, my - 22, "MINIMAP", 14u, ah_green, true);
    for (unsigned i = 0; i < m->num_planes; i++) {
        const zdog_plane *pl = &m->planes[i];
        const int cx = ah_map_x(pl->x, mx, map_s);
        const int cy = ah_map_y(pl->z, my, map_s);
        const struct zcl_present_color tc = pl->team == 0 ? ah_red : ah_blue;
        if (!pl->alive) {
            zcl_present_canvas_line(c, cx - 4, cy - 4, cx + 4, cy + 4, ah_wreck);
            zcl_present_canvas_line(c, cx - 4, cy + 4, cx + 4, cy - 4, ah_wreck);
            continue;
        }
        zcl_present_canvas_fill_rect(c, cx - 3, cy - 3, 7u, 7u, tc);
        const int hx =
            cx + (int)((int32_t)zdog_sin16(pl->yaw) * 8 / 32768);
        const int hy =
            cy - (int)((int32_t)zdog_cos16(pl->yaw) * 8 / 32768);
        zcl_present_canvas_fill_rect(c, hx - 1, hy - 1, 3u, 3u, tc);
        if (i == follow)
            zcl_present_canvas_stroke_rect(c, cx - 6, cy - 6, 13u, 13u, 1u,
                                           ah_ink);
    }
    for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++) {
        const zdog_shot *s = &m->shots[i];
        if (!s->active)
            continue;
        const int sx = ah_map_x(s->x, mx, map_s);
        const int sy = ah_map_y(s->z, my, map_s);
        const struct zcl_present_color sc =
            s->team == 0 ? (struct zcl_present_color){ 255, 200, 120 }
                         : (struct zcl_present_color){ 160, 220, 255 };
        zcl_present_canvas_fill_rect(c, sx - 1, sy - 1, 3u, 3u, sc);
    }
}

static void ah_health(struct zcl_present_canvas *c, int x, int y,
                      const zdog_plane *pl)
{
    zcl_present_canvas_fill_rect(c, x, y, 220u, 14u, ah_bar);
    int fill = (int)((int64_t)pl->health * 216 / 100);
    if (fill < 0)
        fill = 0;
    if (fill > 216)
        fill = 216;
    zcl_present_canvas_fill_rect(c, x + 2, y + 2, (uint32_t)fill, 10u,
                                 pl->team == 0 ? ah_red : ah_blue);
}

int arena_hud_compose(const arena_hud_in *in, uint8_t *rgb)
{
    if (!in || !rgb || !in->m) {
        ah_err("compose requires match state and a 1280x720 RGB buffer",
               NULL);
        return ARENA_HUD_BAD_ARG;
    }
    if (!arena_hud_fonts_ready()) {
        ah_err("bundled Inter Medium/SemiBold subsets refused to rasterize",
               "HUD text is not drawn without those faces");
        return ARENA_HUD_FAIL;
    }

    const int rc =
        zdogview_render_rgb(in->m, in->seed, in->kills, in->num_kills, rgb,
                            ARENA_HUD_WIDTH, ARENA_HUD_HEIGHT);
    if (rc != ZDOGVIEW_OK) {
        ah_err("zdogview_render_rgb failed", "hosted scene");
        return ARENA_HUD_FAIL;
    }

    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(&canvas, rgb, ARENA_HUD_RGB_BYTES,
                                 ARENA_HUD_WIDTH, ARENA_HUD_HEIGHT)) {
        ah_err("canvas init failed", "1280x720");
        return ARENA_HUD_FAIL;
    }

    const zdog_match *m = in->m;
    const char *red = ah_str(in->red_label, "Red");
    const char *blue = ah_str(in->blue_label, "Blue");
    const char *cam = ah_str(in->cam_name, "ISOMETRIC");
    const char *speed = in->playing ? ah_str(in->speed_tag, "x1") : "PAUSED";
    unsigned follow = in->follow;
    if (follow >= m->num_planes)
        follow = 0;

    zcl_present_canvas_fill_rect(&canvas, 0, 0, ARENA_HUD_WIDTH, 92u, ah_panel);
    zcl_present_canvas_fill_rect(&canvas, 0, 90, ARENA_HUD_WIDTH, 2u, ah_edge);

    char score[8];
    (void)snprintf(score, sizeof(score), "%u", m->score[0]);
    ah_text(&canvas, 28, 10, score, 48u, ah_red, true);
    ah_text(&canvas, 28, 62, red, 16u, ah_red, false);

    (void)snprintf(score, sizeof(score), "%u", m->score[1]);
    uint32_t bw = ah_width(score, 48u, true);
    ah_text(&canvas, (int32_t)ARENA_HUD_WIDTH - 28 - (int32_t)bw, 10, score,
            48u, ah_blue, true);
    uint32_t blw = ah_width(blue, 16u, false);
    ah_text(&canvas, (int32_t)ARENA_HUD_WIDTH - 28 - (int32_t)blw, 62, blue,
            16u, ah_blue, false);

    const unsigned secs = (unsigned)(m->tick / 60u);
    char clock[48];
    (void)snprintf(clock, sizeof(clock), "T+%02u:%02u  %s", secs / 60u,
                   secs % 60u, speed);
    uint32_t cw = ah_width(clock, 22u, true);
    ah_text(&canvas, (int32_t)(ARENA_HUD_WIDTH / 2u) - (int32_t)cw / 2, 14,
            clock, 22u, ah_green, true);

    char cam_line[40];
    (void)snprintf(cam_line, sizeof(cam_line), "CAMERA  %s", cam);
    uint32_t camw = ah_width(cam_line, 16u, true);
    ah_text(&canvas, (int32_t)(ARENA_HUD_WIDTH / 2u) - (int32_t)camw / 2, 44,
            cam_line, 16u, ah_ink, true);

    ah_text(&canvas, (int32_t)(ARENA_HUD_WIDTH / 2u) - 52, 66, "Z23 ARENA", 18u,
            ah_green, true);

    ah_minimap(&canvas, m, follow);

    if (m->phase == ZDOG_PHASE_DONE) {
        char banner[40];
        (void)snprintf(banner, sizeof(banner), "%s  %u-%u",
                       ah_winner(m->winner), m->score[0], m->score[1]);
        const struct zcl_present_color bc =
            m->winner == ZDOG_WINNER_BLUE
                ? ah_blue
                : (m->winner == ZDOG_WINNER_RED ? ah_red : ah_dim);
        uint32_t tw = ah_width(banner, 48u, true);
        const int32_t bx =
            (int32_t)(ARENA_HUD_WIDTH / 2u) - (int32_t)tw / 2;
        zcl_present_canvas_fill_rect(&canvas, bx - 24, 250, tw + 48u, 72u,
                                     ah_panel);
        zcl_present_canvas_stroke_rect(&canvas, bx - 24, 250, tw + 48u, 72u,
                                       2u, bc);
        ah_text(&canvas, bx, 262, banner, 48u, bc, true);
    }

    zdogview_frame *hosted = zcl_malloc(sizeof(*hosted), "arena_hud.hosted");
    if (!hosted) {
        ah_err("cannot allocate the hosted 320x180 inset", NULL);
        return ARENA_HUD_FAIL;
    }
    zdogview_render_scene(m, in->seed, in->kills, in->num_kills, hosted);
    const int hx = 16, hy = (int)ARENA_HUD_HEIGHT - (int)ZDOGVIEW_HEIGHT - 52;
    zcl_present_canvas_fill_rect(&canvas, hx - 4, hy - 24,
                                 (uint32_t)ZDOGVIEW_WIDTH + 8u,
                                 (uint32_t)ZDOGVIEW_HEIGHT + 30u, ah_panel);
    ah_text(&canvas, hx, hy - 22, "C23 HOSTED VIEW", 14u, ah_green, true);
    ah_blit(rgb, hx, hy, hosted->rgb, ZDOGVIEW_WIDTH, ZDOGVIEW_HEIGHT);
    zcl_present_canvas_stroke_rect(&canvas, hx - 1, hy - 1,
                                   (uint32_t)ZDOGVIEW_WIDTH + 2u,
                                   (uint32_t)ZDOGVIEW_HEIGHT + 2u, 1u, ah_edge);
    free(hosted);

    const zdog_plane *pl = &m->planes[follow];
    const int px = 352, py = (int)ARENA_HUD_HEIGHT - 86;
    char plane_line[96];
    (void)snprintf(plane_line, sizeof(plane_line), "PLANE %u/%u  %s",
                   follow + 1u, (unsigned)m->num_planes,
                   pl->team == 0 ? red : blue);
    ah_text(&canvas, px, py, plane_line, 16u, ah_dim, false);
    char tel[80];
    (void)snprintf(tel, sizeof(tel), "ALT %5dm   SPD %3dm/s   HDG %3ddeg",
                   (int)(pl->y / 1000), pl->speed / 1000,
                   (int)((uint32_t)pl->yaw * 360u / 65536u));
    ah_text(&canvas, px, py + 22, tel, 16u, ah_green, false);
    ah_health(&canvas, px, py + 46, pl);
    char hull[24];
    if (pl->alive)
        (void)snprintf(hull, sizeof(hull), "HULL %d", pl->health);
    else
        (void)snprintf(hull, sizeof(hull), "DESTROYED");
    ah_text(&canvas, px + 232, py + 44, hull, 14u,
            pl->alive ? ah_dim : ah_red, true);

    const int cx = (int)ARENA_HUD_WIDTH - 28;
    const char *help1 = "TAB plane   C camera   SPACE pause   F step";
    const char *help2 = "arrows seek 1s   PGUP/PGDN 10s   +/- speed   ESC quit";
    uint32_t h1 = ah_width(help1, 14u, false);
    uint32_t h2 = ah_width(help2, 14u, false);
    ah_text(&canvas, cx - (int32_t)h1, py, help1, 14u, ah_dim, false);
    ah_text(&canvas, cx - (int32_t)h2, py + 22, help2, 14u, ah_dim, false);

    char roots[160];
    char rr[ARENA_HUD_ROOT_LEN * 2u + 1u];
    char sr[ARENA_HUD_ROOT_LEN * 2u + 1u];
    rr[0] = 0;
    sr[0] = 0;
    if (in->replay_root)
        zcl_hex_encode(in->replay_root, ARENA_HUD_ROOT_LEN, rr);
    if (in->state_root)
        zcl_hex_encode(in->state_root, ARENA_HUD_ROOT_LEN, sr);
    (void)snprintf(roots, sizeof(roots),
                   "VERIFIED  replay %.16s..  state %.16s..  tick %llu/%llu",
                   rr[0] ? rr : "unknown", sr[0] ? sr : "unknown",
                   (unsigned long long)m->tick,
                   (unsigned long long)in->recorded_ticks);
    uint32_t rw = ah_width(roots, 14u, false);
    ah_text(&canvas, (int32_t)(ARENA_HUD_WIDTH / 2u) - (int32_t)rw / 2,
            (int32_t)ARENA_HUD_HEIGHT - 28, roots, 14u, ah_green, false);
    return ARENA_HUD_OK;
}
