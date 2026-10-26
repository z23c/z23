/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * arena_svg: deterministic headless replay renderer for the ZCODE Arena.
 *
 * Reads one canonical zdogfight replay file (the exact format written by
 * tools/arena_runner.c), RE-SIMULATES it from the seed with no pilots, and
 * emits a static SVG contact sheet of six overhead snapshots. Standalone
 * developer tool — NOT a native command.
 *
 * REFUSES ANYTHING IT CANNOT RE-DERIVE. The whole point of the picture is
 * that it depicts a verified match, so this tool runs the same acceptance
 * arena_runner --verify-replay runs before it draws a single pixel: the
 * recorded control stream must drive the match to ZDOG_PHASE_DONE at
 * exactly the recorded tick count, and the re-encoded final state must
 * byte-equal the file's trailing state block. A mismatch exits 1 with a
 * named reason and writes no output file. The roots printed on the artwork
 * are recomputed here, never copied from an argument.
 *
 * DETERMINISTIC BYTES. Same replay file in, byte-identical SVG out, on any
 * machine and compiler: the simulation is the integer-only zdogfight core,
 * every layout coordinate is integer arithmetic in tenths of a pixel, and
 * no float, clock, locale, hostname, or path ever reaches the output. That
 * is what makes `make arena-svg-check` a real staleness gate rather than a
 * timestamp comparison.
 *
 * The six snapshots are chosen by deterministic rules over the
 * re-simulation, never by hand:
 *   1 START            tick 0, the fixed spawn line
 *   2 FIRST ENGAGEMENT the first tick with a round in flight
 *   3 FIRST KILL       the first tick a team's score increments
 *   4 MIDPOINT         tick floor(total/2)
 *   5 WINNING ATTACK   one second (AS_LAG ticks) BEFORE the last tick a
 *                      score increments — the gun run itself. The kill that
 *                      ends a score-limit match lands on the final tick, so
 *                      snapshotting the increment would just reprint panel
 *                      6; the second before it is the frame that shows how
 *                      the match was won.
 *   6 FINAL            the last tick
 * An event that never happens in a given replay is labelled as absent
 * rather than silently substituted.
 *
 * Usage:
 *   arena_svg --replay <file> --out <file.svg>
 *             [--red-label <text>] [--blue-label <text>]
 *
 * Exit codes: 0 ok; 1 replay verification mismatch or write failure;
 * 2 usage; 4 runtime failure (read/allocation, logged to stderr).
 */

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "zdogfight/zdogfight.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Replay container constants — must track tools/arena_runner.c. The two
 * tools are deliberately separate programs (one drives live confined
 * pilots, one only reads); the format is the contract between them and is
 * asserted by the shared verification below, not by a shared header. */
#define AS_REPLAY_MAGIC "ZDOGREPL"
#define AS_REPLAY_MAGIC_LEN 8u
#define AS_REPLAY_VERSION 1u
#define AS_HEADER_LEN (AS_REPLAY_MAGIC_LEN + 4u + 8u + 1u)
#define AS_MAX_REPLAY_BYTES                                              \
    (AS_HEADER_LEN + (size_t)ZDOG_TICK_LIMIT * ZDOG_MAX_PLANES *         \
                         ZDOG_CTL_WIRE_LEN +                             \
     (size_t)ZDOG_STATE_WIRE_MAX)

/* ── Layout, in tenths of a pixel ──────────────────────────────────────
 * The SVG user-unit grid is 10x the pixel grid so plane glyphs can be
 * rotated with integer arithmetic and still look smooth. Nothing here is
 * ever divided into a float. */
#define AS_S 10 /* user units per pixel */
#define AS_MARGIN (28 * AS_S)
#define AS_PANEL (300 * AS_S)
#define AS_GAP (20 * AS_S)
#define AS_CAP_H (34 * AS_S)
#define AS_HEADER_H (118 * AS_S)
#define AS_FOOTER_H (86 * AS_S)
#define AS_COLS 3
#define AS_ROWS 2
#define AS_W (AS_MARGIN * 2 + AS_PANEL * AS_COLS + AS_GAP * (AS_COLS - 1))
#define AS_H                                                             \
    (AS_HEADER_H + (AS_PANEL + AS_CAP_H) * AS_ROWS +                     \
     AS_GAP * (AS_ROWS - 1) + AS_FOOTER_H)

/* World is toroidal on x,z at +/-ZDOG_WORLD_HALF mm. */
#define AS_WORLD_SPAN (2 * ZDOG_WORLD_HALF)

#define AS_SNAPS 6u

/* Lag, in ticks, from the winning-attack frame to the kill it produced.
 * 60 ticks is exactly one second at the arena's fixed 60 Hz. */
#define AS_LAG 60u

/* Plane glyph size, in user units. */
#define AS_NOSE 62
#define AS_TAIL 34
#define AS_HALF_W 34

#define AS_COL_BG "#0b0f16"
#define AS_COL_PANEL "#111823"
#define AS_COL_EDGE "#243044"
#define AS_COL_GRID "#1a2432"
#define AS_COL_TEXT "#c9d6e4"
#define AS_COL_DIM "#66788c"
#define AS_COL_RED "#ff6b5e"
#define AS_COL_BLUE "#57a6ff"
#define AS_COL_DEAD "#3d4a5c"

struct as_snap {
    bool present;
    const char *title;
    const char *note; /* set when the event never occurred */
    zdog_match m;
};

static void as_err(const char *what, const char *detail)
{
    fprintf(stderr, "arena_svg: error: %s%s%s\n", what, detail ? ": " : "",
            detail ? detail : "");
}

static void as_usage(FILE *out)
{
    fprintf(out,
            "usage:\n"
            "  arena_svg --replay <file> --out <file.svg>\n"
            "      [--red-label <text>] [--blue-label <text>]\n");
}

static int as_mismatch(const char *what)
{
    fprintf(stderr, "arena_svg: replay=MISMATCH %s\n", what);
    return 1;
}

static uint8_t *as_read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        as_err("cannot open replay", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        as_err("fseek failed", path);
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz <= 0 || (unsigned long)sz > AS_MAX_REPLAY_BYTES) {
        as_err("bad replay size (0 or above the replay cap)", path);
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        as_err("fseek(set) failed", path);
        fclose(f);
        return NULL;
    }
    uint8_t *buf = zcl_malloc((size_t)sz, "arena_svg.replay");
    if (!buf) {
        as_err("malloc failed for replay file", path);
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        as_err("short read", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len_out = (size_t)sz;
    return buf;
}

static void as_sha3(const uint8_t *data, size_t len,
                    uint8_t out[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, data, len);
    sha3_256_finalize(&ctx, out);
}

static bool as_any_shot(const zdog_match *m)
{
    for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++)
        if (m->shots[i].active)
            return true;
    return false;
}

/* ── Coordinate mapping ───────────────────────────────────────────────
 * World millimetres -> user units inside a panel whose top-left corner is
 * (ox, oy). +z is drawn up, matching an ordinary overhead map. */
static int32_t as_map_x(int32_t ox, int32_t x)
{
    return ox + (int32_t)(((int64_t)x + ZDOG_WORLD_HALF) * AS_PANEL /
                          AS_WORLD_SPAN);
}

static int32_t as_map_y(int32_t oy, int32_t z)
{
    return oy + (int32_t)(((int64_t)ZDOG_WORLD_HALF - z) * AS_PANEL /
                          AS_WORLD_SPAN);
}

/* Scale a Q1.15 direction component by a glyph length, truncating toward
 * zero. Pure integer: identical on every platform. */
static int32_t as_q15(int32_t q, int32_t len)
{
    return (int32_t)(((int64_t)q * len) / 32768);
}

/* ── Emitters ─────────────────────────────────────────────────────────
 * Every value written is an integer or a hex digest, so the output bytes
 * are a pure function of the replay. */
static void as_plane_glyph(FILE *f, int32_t ox, int32_t oy,
                           const zdog_plane *p)
{
    const int32_t cx = as_map_x(ox, p->x);
    const int32_t cy = as_map_y(oy, p->z);
    const char *col = p->team == 0 ? AS_COL_RED : AS_COL_BLUE;
    if (!p->alive) {
        /* A destroyed plane is drawn at its wreck point as a dim cross, so
         * a reader can see the hole in a formation instead of a silent
         * absence. */
        fprintf(f,
                "<g stroke=\"%s\" stroke-width=\"16\" opacity=\"0.75\">"
                "<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\"/>"
                "<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\"/></g>\n",
                AS_COL_DEAD, cx - 34, cy - 34, cx + 34, cy + 34, cx - 34,
                cy + 34, cx + 34, cy - 34);
        return;
    }
    /* Forward is (sin yaw, cos yaw) in world x,z; screen y is inverted. */
    const int32_t fx = zdog_sin16(p->yaw);
    const int32_t fy = -(int32_t)zdog_cos16(p->yaw);
    const int32_t nx = cx + as_q15(fx, AS_NOSE);
    const int32_t ny = cy + as_q15(fy, AS_NOSE);
    const int32_t tx = cx - as_q15(fx, AS_TAIL);
    const int32_t ty = cy - as_q15(fy, AS_TAIL);
    /* Perpendicular in screen space. */
    const int32_t px = -as_q15(fy, AS_HALF_W);
    const int32_t py = as_q15(fx, AS_HALF_W);
    fprintf(f,
            "<polygon points=\"%d,%d %d,%d %d,%d\" fill=\"%s\" "
            "fill-opacity=\"0.9\" stroke=\"%s\" stroke-width=\"7\"/>\n",
            nx, ny, tx + px, ty + py, tx - px, ty - py, col, col);
}

static void as_shots(FILE *f, int32_t ox, int32_t oy, const zdog_match *m)
{
    for (unsigned i = 0; i < ZDOG_MAX_SHOTS; i++) {
        const zdog_shot *s = &m->shots[i];
        if (!s->active)
            continue;
        fprintf(f, "<circle cx=\"%d\" cy=\"%d\" r=\"13\" fill=\"%s\"/>\n",
                as_map_x(ox, s->x), as_map_y(oy, s->z),
                s->team == 0 ? AS_COL_RED : AS_COL_BLUE);
    }
}

static void as_panel(FILE *f, int32_t ox, int32_t oy, unsigned n,
                     const struct as_snap *snap)
{
    fprintf(f,
            "<rect x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" rx=\"60\" "
            "fill=\"%s\" stroke=\"%s\" stroke-width=\"10\"/>\n",
            ox, oy, AS_PANEL, AS_PANEL, AS_COL_PANEL, AS_COL_EDGE);
    /* Four interior grid lines: a 5x5 read of the 2 km toroidal world. */
    for (int i = 1; i < 5; i++) {
        const int32_t d = AS_PANEL * i / 5;
        fprintf(f,
                "<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"%s\" "
                "stroke-width=\"5\"/>\n",
                ox + d, oy, ox + d, oy + AS_PANEL, AS_COL_GRID);
        fprintf(f,
                "<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"%s\" "
                "stroke-width=\"5\"/>\n",
                ox, oy + d, ox + AS_PANEL, oy + d, AS_COL_GRID);
    }
    if (snap->present) {
        as_shots(f, ox, oy, &snap->m);
        for (unsigned i = 0; i < snap->m.num_planes; i++)
            as_plane_glyph(f, ox, oy, &snap->m.planes[i]);
    }
    /* Panel index badge, top-left inside the frame. */
    fprintf(f,
            "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
            "font-size=\"115\" fill=\"%s\">%u</text>\n",
            ox + 130, oy + 210, AS_COL_DIM, n);
    /* Caption band below the panel. */
    if (snap->present)
        fprintf(f,
                "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
                "font-size=\"120\" fill=\"%s\">%s</text>\n"
                "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
                "font-size=\"110\" fill=\"%s\">tick %llu &#183; red %u "
                "&#183; blue %u</text>\n",
                ox, oy + AS_PANEL + 150, AS_COL_TEXT, snap->title, ox,
                oy + AS_PANEL + 290, AS_COL_DIM,
                (unsigned long long)snap->m.tick, snap->m.score[0],
                snap->m.score[1]);
    else
        fprintf(f,
                "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
                "font-size=\"120\" fill=\"%s\">%s</text>\n"
                "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
                "font-size=\"110\" fill=\"%s\">%s</text>\n",
                ox, oy + AS_PANEL + 150, AS_COL_TEXT, snap->title, ox,
                oy + AS_PANEL + 290, AS_COL_DIM,
                snap->note ? snap->note : "did not occur in this replay");
}

static const char *as_winner_name(uint8_t winner)
{
    switch (winner) {
    case ZDOG_WINNER_RED:  return "RED";
    case ZDOG_WINNER_BLUE: return "BLUE";
    default:               return "DRAW";
    }
}

/* XML-escape into a bounded buffer; labels come from the command line. */
static void as_escape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; in && in[i] && o + 8 < cap; i++) {
        const char *rep = NULL;
        switch (in[i]) {
        case '&': rep = "&amp;"; break;
        case '<': rep = "&lt;"; break;
        case '>': rep = "&gt;"; break;
        case '"': rep = "&quot;"; break;
        default: break;
        }
        if (rep) {
            size_t rl = strlen(rep);
            memcpy(out + o, rep, rl);
            o += rl;
        } else if ((unsigned char)in[i] >= 0x20) {
            out[o++] = in[i];
        }
    }
    out[o] = '\0';
}

static bool as_write_svg(const char *path, const struct as_snap *snaps,
                         const zdog_match *final_m, uint64_t seed,
                         unsigned planes_per_team, const char *red_label,
                         const char *blue_label,
                         const uint8_t replay_root[SHA3_256_OUTPUT_SIZE],
                         const uint8_t state_root[SHA3_256_OUTPUT_SIZE])
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        as_err("cannot open output for writing", path);
        return false;
    }
    char replay_hex[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    char state_hex[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    zcl_hex_encode(replay_root, SHA3_256_OUTPUT_SIZE, replay_hex);
    zcl_hex_encode(state_root, SHA3_256_OUTPUT_SIZE, state_hex);
    char red_esc[192], blue_esc[192];
    as_escape(red_label, red_esc, sizeof(red_esc));
    as_escape(blue_label, blue_esc, sizeof(blue_esc));

    fprintf(f,
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" "
            "height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" "
            "aria-label=\"ZCODE Arena deterministic replay contact "
            "sheet\">\n",
            AS_W / AS_S, AS_H / AS_S, AS_W, AS_H);
    fprintf(f,
            "<rect width=\"%d\" height=\"%d\" fill=\"%s\"/>\n", AS_W, AS_H,
            AS_COL_BG);

    /* Header. */
    fprintf(f,
            "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
            "font-size=\"215\" font-weight=\"bold\" fill=\"%s\">ZCODE "
            "ARENA</text>\n",
            AS_MARGIN, AS_MARGIN + 190, AS_COL_TEXT);
    fprintf(f,
            "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
            "font-size=\"125\" fill=\"%s\">"
            "<tspan fill=\"%s\">%s</tspan> vs <tspan fill=\"%s\">%s</tspan>"
            " &#183; seed %llu &#183; %uv%u &#183; %llu ticks &#183; "
            "%s wins %u&#8211;%u</text>\n",
            AS_MARGIN, AS_MARGIN + 400, AS_COL_DIM, AS_COL_RED, red_esc,
            AS_COL_BLUE, blue_esc, (unsigned long long)seed,
            planes_per_team, planes_per_team,
            (unsigned long long)final_m->tick,
            as_winner_name(final_m->winner), final_m->score[0],
            final_m->score[1]);
    fprintf(f,
            "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
            "font-size=\"105\" fill=\"%s\">overhead view of a 2 km "
            "toroidal world &#183; integer-only simulation &#183; every "
            "frame re-derived from the replay</text>\n",
            AS_MARGIN, AS_MARGIN + 590, AS_COL_DIM);

    /* Panels. */
    for (unsigned i = 0; i < AS_SNAPS; i++) {
        const int32_t ox =
            AS_MARGIN + (int32_t)(i % AS_COLS) * (AS_PANEL + AS_GAP);
        const int32_t oy = AS_HEADER_H + (int32_t)(i / AS_COLS) *
                                             (AS_PANEL + AS_CAP_H + AS_GAP);
        as_panel(f, ox, oy, i + 1u, &snaps[i]);
    }

    /* Footer: the two roots that make the picture checkable. */
    const int32_t fy = AS_H - AS_FOOTER_H + 220;
    fprintf(f,
            "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
            "font-size=\"105\" fill=\"%s\">replay root       %s</text>\n",
            AS_MARGIN, fy, AS_COL_DIM, replay_hex);
    fprintf(f,
            "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
            "font-size=\"105\" fill=\"%s\">final-state root  %s</text>\n",
            AS_MARGIN, fy + 180, AS_COL_DIM, state_hex);
    fprintf(f,
            "<text x=\"%d\" y=\"%d\" font-family=\"monospace\" "
            "font-size=\"105\" fill=\"%s\">rendered only after the recorded "
            "controls re-derived this exact final state</text>\n",
            AS_MARGIN, fy + 360, AS_COL_DIM);
    fprintf(f, "</svg>\n");

    if (ferror(f)) {
        as_err("write error", path);
        fclose(f);
        return false;
    }
    if (fclose(f) != 0) {
        as_err("close failed", path);
        return false;
    }
    return true;
}

static bool as_planes_out_of_range(uint8_t planes_per_team)
{
    return planes_per_team < 1 || planes_per_team > 4;
}

static bool as_decode_ctls(const uint8_t **fp, unsigned num_planes,
                           zdog_ctl ctls[])
{
    for (unsigned i = 0; i < num_planes; i++) {
        if (!zdog_ctl_decode(*fp, ZDOG_CTL_WIRE_LEN, &ctls[i]))
            return false;
        *fp += ZDOG_CTL_WIRE_LEN;
    }
    return true;
}

static void as_note_first_engagement(struct as_snap *snaps,
                                     const zdog_match *m)
{
    if (!snaps[1].present && as_any_shot(m)) {
        snaps[1].present = true;
        snaps[1].m = *m;
    }
}

static void as_track_kill(struct as_snap *snaps, const zdog_match *m,
                          const zdog_match *lag, unsigned lag_len,
                          unsigned lag_head, uint32_t *prev_score)
{
    const uint32_t score = m->score[0] + m->score[1];
    if (score > *prev_score) {
        if (!snaps[2].present) {
            snaps[2].present = true;
            snaps[2].m = *m;
        }
        /* The oldest entry still in the window is the state AS_LAG
         * ticks ago (fewer, and possibly none, very early in a match).
         * Overwritten by every later kill, so it settles on the run-in
         * to the last one. */
        snaps[4].present = true;
        snaps[4].m = lag_len > 0 ? lag[lag_head] : *m;
        *prev_score = score;
    }
}

static void as_note_midpoint(struct as_snap *snaps, const zdog_match *m,
                             uint64_t mid_tick)
{
    if (m->tick == mid_tick) {
        snaps[3].present = true;
        snaps[3].m = *m;
    }
}

static void as_push_lag(zdog_match *lag, unsigned *lag_len,
                        unsigned *lag_head, const zdog_match *m)
{
    /* Push this state into the rolling window AFTER the kill check, so
     * the window still holds the pre-kill history at that moment. Once
     * full it holds ticks [T-AS_LAG, T-1], oldest first at lag_head. */
    if (*lag_len < AS_LAG) {
        lag[(*lag_len)++] = *m;
    } else {
        lag[*lag_head] = *m;
        *lag_head = (*lag_head + 1u) % AS_LAG;
    }
}

static void as_record_final_snap(struct as_snap *snaps, const zdog_match *m)
{
    snaps[5].present = true;
    snaps[5].m = *m;
    if (!snaps[4].present)
        snaps[4].note = "no kill was scored in this replay";
    if (!snaps[2].present)
        snaps[2].note = "no kill was scored in this replay";
    if (!snaps[1].present)
        snaps[1].note = "no round was ever fired";
}

static int as_render(const char *replay_path, const char *out_path,
                     const char *red_label, const char *blue_label)
{
    size_t len = 0;
    uint8_t *buf = as_read_file(replay_path, &len);
    if (!buf)
        return 4;

    int rc = 1;
    struct as_snap snaps[AS_SNAPS] = { 0 };
    /* Declared before the first `goto out` so the cleanup path is uniform. */
    zdog_match *lag = NULL;
    snaps[0].title = "1  START";
    snaps[1].title = "2  FIRST ENGAGEMENT";
    snaps[2].title = "3  FIRST KILL";
    snaps[3].title = "4  MIDPOINT";
    snaps[4].title = "5  WINNING ATTACK";
    snaps[5].title = "6  FINAL";

    if (len < AS_HEADER_LEN + ZDOG_STATE_WIRE_MAX) {
        rc = as_mismatch("truncated");
        goto out;
    }
    if (memcmp(buf, AS_REPLAY_MAGIC, AS_REPLAY_MAGIC_LEN) != 0) {
        rc = as_mismatch("header-magic");
        goto out;
    }
    if (zcl_read_u32_le(buf + AS_REPLAY_MAGIC_LEN) != AS_REPLAY_VERSION) {
        rc = as_mismatch("header-version");
        goto out;
    }
    const uint64_t seed = zcl_read_u64_le(buf + AS_REPLAY_MAGIC_LEN + 4u);
    const uint8_t planes_per_team = buf[AS_REPLAY_MAGIC_LEN + 4u + 8u];
    if (as_planes_out_of_range(planes_per_team)) {
        rc = as_mismatch("header-planes");
        goto out;
    }
    const unsigned num_planes = 2u * planes_per_team;
    const size_t tick_bytes = num_planes * ZDOG_CTL_WIRE_LEN;
    const size_t frames_len = len - AS_HEADER_LEN - ZDOG_STATE_WIRE_MAX;
    if (frames_len % tick_bytes != 0) {
        rc = as_mismatch("size");
        goto out;
    }
    const uint64_t recorded_ticks = frames_len / tick_bytes;
    const uint64_t mid_tick = recorded_ticks / 2u;

    zdog_match m;
    zdog_match_init(&m, seed, planes_per_team);
    snaps[0].present = true;
    snaps[0].m = m;

    /* Rolling window of the last AS_LAG states, so panel 5 can look one
     * second back from a kill without a second simulation pass. */
    lag = zcl_malloc(sizeof(*lag) * AS_LAG, "arena_svg.lag");
    if (!lag) {
        as_err("malloc failed for the lag window", replay_path);
        rc = 4;
        goto out;
    }
    unsigned lag_len = 0, lag_head = 0;

    uint32_t prev_score = 0;
    const uint8_t *fp = buf + AS_HEADER_LEN;
    for (uint64_t t = 0; t < recorded_ticks; t++) {
        zdog_ctl ctls[ZDOG_MAX_PLANES];
        if (!as_decode_ctls(&fp, num_planes, ctls)) {
            rc = as_mismatch("ctl-frame");
            goto out;
        }
        zdog_tick(&m, ctls);
        as_note_first_engagement(snaps, &m);
        as_track_kill(snaps, &m, lag, lag_len, lag_head, &prev_score);
        as_note_midpoint(snaps, &m, mid_tick);
        as_push_lag(lag, &lag_len, &lag_head, &m);
    }

    /* The same acceptance arena_runner --verify-replay applies. */
    if (m.phase != ZDOG_PHASE_DONE) {
        rc = as_mismatch("match-incomplete");
        goto out;
    }
    if (m.tick != recorded_ticks) {
        rc = as_mismatch("tick-count");
        goto out;
    }
    uint8_t state[ZDOG_STATE_WIRE_MAX];
    if (zdog_state_encode(&m, state, sizeof(state)) != sizeof(state)) {
        as_err("zdog_state_encode short", "tool bug");
        rc = 4;
        goto out;
    }
    if (memcmp(state, fp, ZDOG_STATE_WIRE_MAX) != 0) {
        rc = as_mismatch("final-state");
        goto out;
    }
    as_record_final_snap(snaps, &m);

    uint8_t replay_root[SHA3_256_OUTPUT_SIZE];
    uint8_t state_root[SHA3_256_OUTPUT_SIZE];
    as_sha3(buf, len, replay_root);
    as_sha3(state, sizeof(state), state_root);

    if (!as_write_svg(out_path, snaps, &m, seed, planes_per_team, red_label,
                      blue_label, replay_root, state_root)) {
        rc = 1;
        goto out;
    }
    char replay_hex[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    zcl_hex_encode(replay_root, SHA3_256_OUTPUT_SIZE, replay_hex);
    printf("svg=%s ticks=%llu replay_root=%s\n", out_path,
           (unsigned long long)m.tick, replay_hex);
    rc = 0;
out:
    free(lag);
    free(buf);
    return rc;
}

static const char *as_option_value(int argc, char **argv, int i,
                                   const char *eq)
{
    if (eq)
        return eq + 1;
    return i + 1 < argc ? argv[i + 1] : NULL;
}

int main(int argc, char **argv)
{
    const char *replay = NULL;
    const char *out = NULL;
    const char *red_label = "red";
    const char *blue_label = "blue";

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = NULL;
        char name[64];
        const char *eq = strchr(a, '=');
        size_t nl = eq ? (size_t)(eq - a) : strlen(a);
        if (nl == 0 || nl >= sizeof(name)) {
            as_err("bad argument", a);
            as_usage(stderr);
            return 2;
        }
        memcpy(name, a, nl);
        name[nl] = '\0';
        v = as_option_value(argc, argv, i, eq);
        if (strcmp(name, "--help") == 0) {
            as_usage(stdout);
            return 0;
        }
        if (strcmp(name, "--replay") == 0)
            replay = v;
        else if (strcmp(name, "--out") == 0)
            out = v;
        else if (strcmp(name, "--red-label") == 0)
            red_label = v;
        else if (strcmp(name, "--blue-label") == 0)
            blue_label = v;
        else {
            as_err("unknown argument", a);
            as_usage(stderr);
            return 2;
        }
        if (!v) {
            as_err("missing value for", name);
            as_usage(stderr);
            return 2;
        }
        if (!eq)
            i++;
    }
    if (!replay || !out) {
        as_err("missing required argument(s)", "--replay --out");
        as_usage(stderr);
        return 2;
    }
    return as_render(replay, out, red_label, blue_label);
}
