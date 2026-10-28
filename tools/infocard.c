/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * infocard SPEC OUT.png: render a one-page update card (an "infographic")
 * from a small line-based text spec, with the Inter canvas and the native
 * PNG writer. No toolkit, no network, no shell. SPEC "-" reads stdin.
 *
 * One directive per line; fields are separated by " | "; '#' starts a
 * comment line; text is printable ASCII (the embedded fonts have no other
 * glyphs). The page flows top to bottom:
 *   canvas W H                 page size in plain digits (no sign), 320 or
 *                              more; first directive only (default 1080 1350)
 *   title TEXT | KICKER | DATE big title, a tag and a date beside it
 *   subtitle TEXT              wrapped text under the title
 *   stat VALUE | LABEL         consecutive stats share one row (up to 4)
 *   section TEXT               a section heading with a rule
 *   bar LABEL | PERCENT | NOTE a progress bar; PERCENT is a whole number
 *                              0..100, NOTE (default "PERCENT%") sits right
 *   check TEXT                 a ticked list item
 *   cta HEADING | HANDLE | LINE  a call-to-action card with a helper robot
 *   footer TEXT                centered at the bottom of the page (only one)
 * Anything that does not fit (page height, a line's width, a seventh wrapped
 * line, an extra field, a second footer) is an error that names the spec
 * line; nothing is clipped or dropped silently and no PNG is written.
 */
#include "base/safe_alloc.h"
#include "presentation/canvas.h"
#include "util/png_writer.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IC_LINE_MAX 512u
#define IC_FIELDS 3u
#define IC_STATS 4u
#define IC_WRAP_LINES 6u
#define IC_MARGIN 72
#define IC_MIN_TILE 96

typedef struct zcl_present_color ic_color;

static const ic_color IC_BG_TOP = {11, 21, 29};
static const ic_color IC_BG_BOTTOM = {20, 37, 46};
static const ic_color IC_CARD = {23, 40, 50};
static const ic_color IC_TRACK = {36, 56, 68};
static const ic_color IC_GOLD = {242, 181, 68};
static const ic_color IC_TEAL = {46, 196, 182};
static const ic_color IC_GREEN = {91, 214, 138};
static const ic_color IC_WHITE = {244, 241, 234};
static const ic_color IC_MUTED = {160, 181, 192};
static const ic_color IC_DIM = {52, 78, 92};

/* Spec lines are shorter than IC_LINE_MAX, so any field fits these. */
struct ic_stat {
    char value[IC_LINE_MAX];
    char label[IC_LINE_MAX];
    unsigned line;
};

struct ic_page {
    struct zcl_present_canvas canvas;
    uint8_t *pixels;
    int32_t y;
    struct ic_stat stats[IC_STATS];
    unsigned stat_count;
    char footer[IC_LINE_MAX];
    unsigned footer_line;
    unsigned over_line; /* first spec line whose content passed the page end */
    unsigned line_no;
    bool failed;
};

/* Reports the first error against the current spec line. */
static void ic_fail(struct ic_page *p, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void ic_fail(struct ic_page *p, const char *fmt, ...)
{
    if (p->failed) return;
    p->failed = true;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "infocard: line %u: ", p->line_no);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static int32_t ic_width(const struct ic_page *p)
{
    return (int32_t)p->canvas.width;
}

static int32_t ic_content_width(const struct ic_page *p)
{
    return ic_width(p) - 2 * IC_MARGIN;
}

static uint32_t ic_text_w(const char *s, uint32_t px, bool strong)
{
    return strong ? zcl_present_canvas_text_width_strong(s, strlen(s), px)
                  : zcl_present_canvas_text_width(s, strlen(s), px);
}

static void ic_text(struct ic_page *p, int32_t x, int32_t y, const char *s,
                    uint32_t px, bool strong, ic_color c)
{
    if (strong)
        zcl_present_canvas_text_strong(&p->canvas, x, y, s, strlen(s), px, c);
    else
        zcl_present_canvas_text(&p->canvas, x, y, s, strlen(s), px, c);
}

/* Fails unless s, drawn at px, fits in max_w pixels; empty text always fits. */
static bool ic_fit(struct ic_page *p, const char *what, const char *s,
                   uint32_t px, bool strong, int32_t max_w)
{
    if (!s[0]) return true;
    uint32_t w = ic_text_w(s, px, strong);
    if (max_w > 0 && w <= (uint32_t)max_w) return true;
    ic_fail(p, "%s '%s' does not fit (%u px wide, %d px available)", what, s, w,
            max_w > 0 ? max_w : 0);
    return false;
}

static void ic_round_rect(struct ic_page *p, int32_t x, int32_t y, uint32_t w,
                          uint32_t h, uint32_t r, ic_color c)
{
    if (2u * r > w) r = w / 2u;
    if (2u * r > h) r = h / 2u;
    zcl_present_canvas_fill_rect(&p->canvas, x + (int32_t)r, y, w - 2u * r, h, c);
    zcl_present_canvas_fill_rect(&p->canvas, x, y + (int32_t)r, w, h - 2u * r, c);
    int32_t x1 = x + (int32_t)(w - r) - 1, y1 = y + (int32_t)(h - r) - 1;
    zcl_present_canvas_fill_circle(&p->canvas, x + (int32_t)r, y + (int32_t)r, r, c);
    zcl_present_canvas_fill_circle(&p->canvas, x1, y + (int32_t)r, r, c);
    zcl_present_canvas_fill_circle(&p->canvas, x + (int32_t)r, y1, r, c);
    zcl_present_canvas_fill_circle(&p->canvas, x1, y1, r, c);
}

/* Copies the next space-separated word of *s into word; false at the end.
 * A word comes from one spec line, so it always fits. */
static bool ic_next_word(const char **s, char word[IC_LINE_MAX])
{
    while (**s == ' ') (*s)++;
    size_t len = strcspn(*s, " ");
    if (len == 0 || len >= IC_LINE_MAX) return false;
    memcpy(word, *s, len);
    word[len] = '\0';
    *s += len;
    return true;
}

/* Greedy word wrap into at most IC_WRAP_LINES lines of max_w pixels and
 * returns the count; a word wider than max_w or a seventh line fails. */
static unsigned ic_wrap(struct ic_page *p, const char *what, const char *s,
                        uint32_t px, bool strong, int32_t max_w,
                        char lines[IC_WRAP_LINES][IC_LINE_MAX])
{
    unsigned n = 0;
    char cur[IC_LINE_MAX] = "", word[IC_LINE_MAX], next[IC_LINE_MAX];
    while (ic_next_word(&s, word)) {
        if (!ic_fit(p, what, word, px, strong, max_w)) return 0;
        int k = snprintf(next, sizeof(next), "%s%s%s", cur, cur[0] ? " " : "", word);
        if (k > 0 && (size_t)k < sizeof(next) && ic_text_w(next, px, strong) <= (uint32_t)max_w) {
            memcpy(cur, next, sizeof(cur));
            continue;
        }
        if (n + 1u == IC_WRAP_LINES) {
            ic_fail(p, "%s needs more than %u lines", what, IC_WRAP_LINES);
            return 0;
        }
        memcpy(lines[n++], cur, sizeof(cur));
        memcpy(cur, word, sizeof(cur));
    }
    if (cur[0]) memcpy(lines[n++], cur, sizeof(cur));
    return n;
}

static int32_t ic_draw_lines(struct ic_page *p, int32_t x, int32_t y,
                             char lines[IC_WRAP_LINES][IC_LINE_MAX], unsigned n,
                             uint32_t px, ic_color c)
{
    int32_t step = (int32_t)(px * 13u / 10u);
    for (unsigned i = 0; i < n; i++)
        ic_text(p, x, y + (int32_t)i * step, lines[i], px, false, c);
    return (int32_t)n * step;
}

static int32_t ic_text_wrapped(struct ic_page *p, const char *what, int32_t x,
                               int32_t y, const char *s, uint32_t px,
                               int32_t max_w, ic_color c)
{
    char lines[IC_WRAP_LINES][IC_LINE_MAX];
    unsigned n = ic_wrap(p, what, s, px, false, max_w, lines);
    return p->failed ? 0 : ic_draw_lines(p, x, y, lines, n, px, c);
}

/* Splits "a | b | c" in place into at most max fields (more is an error);
 * missing fields are empty. */
static bool ic_fields(struct ic_page *p, const char *name, char *s,
                      unsigned max, char *out[IC_FIELDS])
{
    unsigned n = 0;
    for (char *bar = s;; s = bar + 3) {
        while (*s == ' ') s++;
        if (n == max) {
            ic_fail(p, "'%s' takes at most %u field%s", name, max, max == 1u ? "" : "s");
            return false;
        }
        out[n++] = s;
        bar = strstr(s, " | ");
        if (!bar) break;
        *bar = '\0';
    }
    for (unsigned i = 0; i < n; i++) {
        size_t len = strlen(out[i]);
        while (len > 0 && out[i][len - 1] == ' ') out[i][--len] = '\0';
    }
    for (unsigned i = n; i < IC_FIELDS; i++) out[i] = "";
    return true;
}

/* A small network of linked nodes, the sharing motif, top right. */
static void ic_network(struct ic_page *p)
{
    static const int32_t pts[][2] = {
        {0, 40}, {90, 0}, {170, 60}, {260, 20}, {120, 110}, {230, 120}};
    static const int links[][2] = {{0, 1}, {1, 2}, {2, 3}, {1, 4},
                                   {4, 2}, {2, 5}, {3, 5}};
    int32_t ox = ic_width(p) - IC_MARGIN - 270, oy = p->y + 4;
    for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
        const int32_t *a = pts[links[i][0]], *b = pts[links[i][1]];
        zcl_present_canvas_line_thick(&p->canvas, ox + a[0], oy + a[1],
                                      ox + b[0], oy + b[1], 2u, IC_DIM);
    }
    for (size_t i = 0; i < sizeof(pts) / sizeof(pts[0]); i++)
        zcl_present_canvas_fill_circle(&p->canvas, ox + pts[i][0], oy + pts[i][1],
                                       i % 2u ? 7u : 10u, i % 2u ? IC_TEAL : IC_GOLD);
}

/* The motif is decoration: it is drawn only where the title leaves room. */
static void ic_title(struct ic_page *p, char *f[IC_FIELDS])
{
    if (!ic_fit(p, "title", f[0], 96u, true, ic_content_width(p))) return;
    int32_t kx = IC_MARGIN + (int32_t)ic_text_w(f[0], 96u, true) + 28;
    int32_t room = ic_width(p) - IC_MARGIN - kx;
    if (!ic_fit(p, "title kicker", f[1], 28u, true, room) ||
        !ic_fit(p, "title date", f[2], 26u, false, room)) return;
    uint32_t side = ic_text_w(f[1], 28u, true), date = ic_text_w(f[2], 26u, false);
    if (kx + (int32_t)(side > date ? side : date) + 40 <= ic_width(p) - IC_MARGIN - 270)
        ic_network(p);
    ic_text(p, IC_MARGIN, p->y, f[0], 96u, true, IC_GOLD);
    ic_text(p, kx, p->y + 26, f[1], 28u, true, IC_TEAL);
    ic_text(p, kx, p->y + 62, f[2], 26u, false, IC_MUTED);
    p->y += 132;
}

static void ic_subtitle(struct ic_page *p, char *f[IC_FIELDS])
{
    p->y += ic_text_wrapped(p, "subtitle", IC_MARGIN, p->y, f[0], 30u,
                            ic_content_width(p), IC_WHITE);
    p->y += 18;
    zcl_present_canvas_fill_rect(&p->canvas, IC_MARGIN, p->y, 140u, 4u, IC_GOLD);
    p->y += 40;
}

static void ic_draw_stats(struct ic_page *p, unsigned n, int32_t tw, unsigned most)
{
    const int32_t gap = 24;
    uint32_t th = 104u + most * 31u + 18u;
    char lines[IC_WRAP_LINES][IC_LINE_MAX];
    for (unsigned i = 0; i < n; i++) {
        int32_t x = IC_MARGIN + (int32_t)i * (tw + gap);
        unsigned k = ic_wrap(p, "stat label", p->stats[i].label, 24u, false, tw - 48, lines);
        ic_round_rect(p, x, p->y, (uint32_t)tw, th, 22u, IC_CARD);
        zcl_present_canvas_fill_rect(&p->canvas, x + 24, p->y + 18, 36u, 4u, IC_TEAL);
        ic_text(p, x + 24, p->y + 30, p->stats[i].value, 56u, true, IC_GOLD);
        ic_draw_lines(p, x + 24, p->y + 104, lines, k, 24u, IC_MUTED);
    }
    p->y += (int32_t)th + 44;
}

/* Remembers the first spec line whose content reaches past the page. */
static void ic_note_height(struct ic_page *p, unsigned line)
{
    if (!p->over_line && p->y > (int32_t)p->canvas.height - 24) p->over_line = line;
}

/* Lays out the pending stats as one row of tiles; errors name the stat's line. */
static void ic_flush_stats(struct ic_page *p)
{
    unsigned n = p->stat_count, here = p->line_no, most = 1;
    if (n == 0) return;
    p->stat_count = 0;
    int32_t tw = (ic_content_width(p) - 24 * (int32_t)(n - 1u)) / (int32_t)n;
    char lines[IC_WRAP_LINES][IC_LINE_MAX];
    for (unsigned i = 0; i < n && !p->failed; i++) {
        p->line_no = p->stats[i].line;
        if (tw < IC_MIN_TILE)
            ic_fail(p, "the canvas is too narrow for %u stats in a row (%d px tiles, need %d)",
                    n, tw, IC_MIN_TILE);
        ic_fit(p, "stat value", p->stats[i].value, 56u, true, tw - 48);
        unsigned k = ic_wrap(p, "stat label", p->stats[i].label, 24u, false, tw - 48, lines);
        if (k > most) most = k;
    }
    p->line_no = here;
    if (p->failed) return;
    ic_draw_stats(p, n, tw, most);
    ic_note_height(p, p->stats[0].line);
}

static void ic_stat(struct ic_page *p, char *f[IC_FIELDS])
{
    if (p->stat_count == IC_STATS) ic_flush_stats(p);
    struct ic_stat *s = &p->stats[p->stat_count++];
    snprintf(s->value, sizeof(s->value), "%s", f[0]);
    snprintf(s->label, sizeof(s->label), "%s", f[1]);
    s->line = p->line_no;
}

static void ic_section(struct ic_page *p, char *f[IC_FIELDS])
{
    if (!ic_fit(p, "section", f[0], 26u, true, ic_content_width(p))) return;
    ic_text(p, IC_MARGIN, p->y, f[0], 26u, true, IC_TEAL);
    int32_t x = IC_MARGIN + (int32_t)ic_text_w(f[0], 26u, true) + 20;
    int32_t right = ic_width(p) - IC_MARGIN;
    if (right > x)
        zcl_present_canvas_fill_rect(&p->canvas, x, p->y + 15, (uint32_t)(right - x), 2u, IC_DIM);
    p->y += 52;
}

/* Parses a whole-number percent from 0 to 100; anything else fails. */
static bool ic_percent(struct ic_page *p, const char *s, long *out)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || errno != 0 || v < 0 || v > 100) {
        ic_fail(p, "bar percent '%s' is not a whole number from 0 to 100", s);
        return false;
    }
    *out = v;
    return true;
}

static void ic_bar(struct ic_page *p, char *f[IC_FIELDS])
{
    long pct;
    char dflt[8];
    if (!ic_percent(p, f[1], &pct)) return;
    snprintf(dflt, sizeof(dflt), "%ld%%", pct);
    const char *note = f[2][0] ? f[2] : dflt;
    int32_t cw = ic_content_width(p), nw = (int32_t)ic_text_w(note, 28u, true);
    if (!ic_fit(p, "bar note", note, 28u, true, cw) ||
        !ic_fit(p, "bar label", f[0], 28u, false, cw - nw - 24)) return;
    ic_color tone = pct == 100 ? IC_GREEN : IC_GOLD;
    ic_text(p, IC_MARGIN, p->y, f[0], 28u, false, IC_WHITE);
    ic_text(p, ic_width(p) - IC_MARGIN - nw, p->y, note, 28u, true, tone);
    p->y += 44;
    ic_round_rect(p, IC_MARGIN, p->y, (uint32_t)cw, 18u, 9u, IC_TRACK);
    uint32_t fill = (uint32_t)((uint64_t)cw * (uint64_t)pct / 100u);
    if (pct > 0 && fill < 18u) fill = 18u;
    if (fill > 0) ic_round_rect(p, IC_MARGIN, p->y, fill, 18u, 9u, tone);
    p->y += 18 + 32;
}

static void ic_check(struct ic_page *p, char *f[IC_FIELDS])
{
    int32_t cx = IC_MARGIN + 16, cy = p->y + 18;
    int32_t h = ic_text_wrapped(p, "check", IC_MARGIN + 52, p->y, f[0], 28u,
                                ic_content_width(p) - 52, IC_WHITE);
    if (p->failed) return;
    zcl_present_canvas_fill_circle(&p->canvas, cx, cy, 16u, IC_GREEN);
    zcl_present_canvas_line_thick(&p->canvas, cx - 8, cy, cx - 2, cy + 7, 4u, IC_BG_TOP);
    zcl_present_canvas_line_thick(&p->canvas, cx - 2, cy + 7, cx + 9, cy - 7, 4u, IC_BG_TOP);
    p->y += (h > 36 ? h : 36) + 16;
}

/* The helper robot: antenna, white head, dark screen with two teal eyes. */
static void ic_robot(struct ic_page *p, int32_t x, int32_t y)
{
    zcl_present_canvas_line_thick(&p->canvas, x + 48, y + 2, x + 48, y + 22, 4u, IC_WHITE);
    zcl_present_canvas_fill_circle(&p->canvas, x + 48, y + 2, 8u, IC_GOLD);
    ic_round_rect(p, x, y + 20, 96u, 84u, 24u, IC_WHITE);
    ic_round_rect(p, x + 12, y + 34, 72u, 48u, 14u, IC_BG_TOP);
    zcl_present_canvas_fill_circle(&p->canvas, x + 34, y + 56, 8u, IC_TEAL);
    zcl_present_canvas_fill_circle(&p->canvas, x + 62, y + 56, 8u, IC_TEAL);
    zcl_present_canvas_fill_rect(&p->canvas, x + 36, y + 70, 24u, 4u, IC_TEAL);
}

static void ic_cta(struct ic_page *p, char *f[IC_FIELDS])
{
    int32_t cw = ic_content_width(p), tx = IC_MARGIN + 40 + 96 + 32;
    int32_t tmax = cw - (tx - IC_MARGIN) - 32;
    char lines[IC_WRAP_LINES][IC_LINE_MAX];
    if (!ic_fit(p, "cta heading", f[0], 34u, true, tmax) ||
        !ic_fit(p, "cta handle", f[1], 52u, true, tmax)) return;
    unsigned n = ic_wrap(p, "cta line", f[2], 26u, false, tmax, lines);
    if (p->failed) return;
    uint32_t h = 150u + n * 34u + 28u;
    p->y += 8;
    ic_round_rect(p, IC_MARGIN, p->y, (uint32_t)cw, h, 30u, IC_TEAL);
    ic_round_rect(p, IC_MARGIN + 3, p->y + 3, (uint32_t)cw - 6u, h - 6u, 27u, IC_CARD);
    ic_robot(p, IC_MARGIN + 40, p->y + (int32_t)(h - 104u) / 2);
    ic_text(p, tx, p->y + 34, f[0], 34u, true, IC_WHITE);
    ic_text(p, tx, p->y + 82, f[1], 52u, true, IC_GOLD);
    ic_draw_lines(p, tx, p->y + 150, lines, n, 26u, IC_MUTED);
    p->y += (int32_t)h + 36;
}

static void ic_footer(struct ic_page *p, char *f[IC_FIELDS])
{
    if (p->footer_line) {
        ic_fail(p, "only one footer is allowed (the first is on line %u)", p->footer_line);
        return;
    }
    if (!ic_fit(p, "footer", f[0], 22u, false, ic_content_width(p))) return;
    snprintf(p->footer, sizeof(p->footer), "%s", f[0]);
    p->footer_line = p->line_no;
}

struct ic_directive_def {
    const char *name;
    unsigned fields;
    void (*draw)(struct ic_page *p, char *f[IC_FIELDS]);
};

static const struct ic_directive_def IC_DIRECTIVES[] = {
    {"title", 3, ic_title},     {"subtitle", 1, ic_subtitle}, {"stat", 2, ic_stat},
    {"section", 1, ic_section}, {"bar", 3, ic_bar},           {"check", 1, ic_check},
    {"cta", 3, ic_cta},         {"footer", 1, ic_footer},
};

static bool ic_directive(struct ic_page *p, char *line)
{
    char *rest = line + strcspn(line, " ");
    if (*rest) *rest++ = '\0';
    const struct ic_directive_def *d = NULL;
    for (size_t i = 0; i < sizeof(IC_DIRECTIVES) / sizeof(IC_DIRECTIVES[0]); i++)
        if (strcmp(line, IC_DIRECTIVES[i].name) == 0) d = &IC_DIRECTIVES[i];
    if (!d && strcmp(line, "canvas") == 0)
        ic_fail(p, "canvas must be the first directive");
    else if (!d)
        ic_fail(p, "unknown directive '%s'", line);
    char *f[IC_FIELDS];
    if (!d || !ic_fields(p, d->name, rest, d->fields, f)) return false;
    if (d->draw != ic_stat) ic_flush_stats(p);
    if (!p->failed) d->draw(p, f);
    ic_note_height(p, p->line_no);
    return !p->failed;
}

/* Dark vertical gradient with 4x4 ordered dither: a plain gradient this dark
 * steps one level in every channel at once and shows bands, worse after a
 * chat app recompresses the image. */
static void ic_background(struct ic_page *p)
{
    static const uint8_t bayer[16] = {0, 8, 2, 10, 12, 4, 14, 6,
                                      3, 11, 1, 9, 15, 7, 13, 5};
    const uint8_t top[3] = {IC_BG_TOP.r, IC_BG_TOP.g, IC_BG_TOP.b};
    const uint8_t bot[3] = {IC_BG_BOTTOM.r, IC_BG_BOTTOM.g, IC_BG_BOTTOM.b};
    uint32_t w = p->canvas.width, h = p->canvas.height;
    uint32_t den = h > 1u ? h - 1u : 1u;
    for (uint32_t row = 0; row < h; row++) {
        uint8_t *px = p->canvas.pixels + (size_t)row * p->canvas.stride;
        for (uint32_t col = 0; col < w; col++) {
            uint32_t d = bayer[(row & 3u) * 4u + (col & 3u)];
            for (unsigned ch = 0; ch < 3u; ch++) {
                uint32_t v16 = (((uint32_t)top[ch] * (den - row) +
                                 (uint32_t)bot[ch] * row) * 16u + den / 2u) / den;
                uint32_t v = (v16 + d) / 16u;
                px[col * 3u + ch] = (uint8_t)(v > 255u ? 255u : v);
            }
        }
    }
}

static bool ic_open_canvas(struct ic_page *p, uint32_t w, uint32_t h)
{
    if (w < 320u || h < 320u || w > ZCL_PRESENT_CANVAS_DIMENSION_MAX ||
        h > ZCL_PRESENT_CANVAS_DIMENSION_MAX) {
        fprintf(stderr, "infocard: canvas %ux%u out of range (320..%u)\n", w, h,
                ZCL_PRESENT_CANVAS_DIMENSION_MAX);
        return false;
    }
    size_t cap = (size_t)w * h * 3u;
    p->pixels = zcl_malloc(cap, "infocard_pixels");
    if (!p->pixels || !zcl_present_canvas_init(&p->canvas, p->pixels, cap, w, h)) {
        fprintf(stderr, "infocard: cannot allocate a %ux%u canvas\n", w, h);
        return false;
    }
    ic_background(p);
    p->y = 56;
    return true;
}

/* Checks every byte, so an embedded NUL cannot hide the rest of a line. */
static bool ic_printable(const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if ((unsigned char)s[i] < 0x20u || (unsigned char)s[i] > 0x7eu) return false;
    return true;
}

static int ic_read_failed(struct ic_page *p)
{
    fprintf(stderr, "infocard: cannot read the spec after line %u\n", p->line_no);
    p->failed = true;
    return -1;
}

/* Reads the next spec line into line without its line ending. Returns 1 for
 * a line, 0 at the end and -1 after a reported error. */
static int ic_read_line(struct ic_page *p, FILE *in, char line[IC_LINE_MAX])
{
    int c = getc(in);
    if (c == EOF) return ferror(in) ? ic_read_failed(p) : 0;
    p->line_no++;
    size_t len = 0;
    for (; c != EOF && c != '\n'; c = getc(in)) {
        if (len == IC_LINE_MAX - 2u) {
            ic_fail(p, "the line is longer than %u characters", IC_LINE_MAX - 2u);
            return -1;
        }
        line[len++] = (char)c;
    }
    if (c == EOF && ferror(in)) return ic_read_failed(p);
    if (len > 0 && line[len - 1] == '\r') len--;
    line[len] = '\0';
    if (!ic_printable(line, len)) {
        ic_fail(p, "only printable ASCII text is supported");
        return -1;
    }
    return 1;
}

static bool ic_is_canvas(const char *line)
{
    return strncmp(line, "canvas", 6) == 0 && (!line[6] || line[6] == ' ');
}

/* Parses " N" (spaces, then digits) at *s; a value too large for unsigned
 * becomes UINT_MAX so the range check names it. */
static bool ic_dimension(const char **s, unsigned *out)
{
    if (**s != ' ') return false;
    while (**s == ' ') (*s)++;
    if (**s < '0' || **s > '9') return false;
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(*s, &end, 10);
    *out = errno == ERANGE || v > UINT_MAX ? UINT_MAX : (unsigned)v;
    *s = end;
    return true;
}

/* Parses "canvas W H"; anything else after "canvas" fails. */
static bool ic_canvas_size(struct ic_page *p, const char *line, unsigned *w, unsigned *h)
{
    const char *s = line + 6;
    if (ic_dimension(&s, w) && ic_dimension(&s, h) && !*s) return true;
    ic_fail(p, "canvas takes a width and a height in pixels");
    return false;
}

/* Reads up to the first directive; a leading "canvas W H" sizes the page,
 * any other directive is left pending in line for the caller. */
static bool ic_start(struct ic_page *p, FILE *in, char line[IC_LINE_MAX], bool *pending)
{
    unsigned w = 1080, h = 1350;
    int got;
    while ((got = ic_read_line(p, in, line)) == 1 && (!line[0] || line[0] == '#')) {}
    if (got < 0) return false;
    bool canvas = got == 1 && ic_is_canvas(line);
    *pending = got == 1 && !canvas;
    if (canvas && !ic_canvas_size(p, line, &w, &h)) return false;
    return ic_open_canvas(p, w, h);
}

/* Checks the page height (naming the first line past the end, or the footer
 * whose space it took) and draws the footer. */
static bool ic_finish(struct ic_page *p)
{
    int32_t h = (int32_t)p->canvas.height, need = p->y + (p->footer[0] ? 72 : 24);
    if (need > h) {
        p->line_no = p->over_line ? p->over_line : p->footer_line;
        ic_fail(p, "content needs %d px but the page is %d px tall", need, h);
        return false;
    }
    if (p->footer[0])
        ic_text(p, (ic_width(p) - (int32_t)ic_text_w(p->footer, 22u, false)) / 2,
                h - 56, p->footer, 22u, false, IC_MUTED);
    return true;
}

static bool ic_render(struct ic_page *p, FILE *in)
{
    char line[IC_LINE_MAX];
    bool pending;
    int got = 1;
    if (!ic_start(p, in, line, &pending)) return false;
    while (pending || (got = ic_read_line(p, in, line)) == 1) {
        pending = false;
        if (!line[0] || line[0] == '#') continue;
        if (!ic_directive(p, line)) return false;
    }
    if (got < 0) return false;
    ic_flush_stats(p);
    return !p->failed && ic_finish(p);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: infocard SPEC OUT.png\n");
        return 2;
    }
    FILE *in = strcmp(argv[1], "-") == 0 ? stdin : fopen(argv[1], "r");
    if (!in) {
        fprintf(stderr, "infocard: cannot open %s\n", argv[1]);
        return 2;
    }
    struct ic_page page = {0};
    bool ok = ic_render(&page, in);
    if (in != stdin) fclose(in);
    if (ok && !png_write_rgb(argv[2], page.pixels, page.canvas.width, page.canvas.height)) {
        fprintf(stderr, "infocard: cannot write %s\n", argv[2]);
        ok = false;
    }
    free(page.pixels);
    return ok ? 0 : 1;
}
