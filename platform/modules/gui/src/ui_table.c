/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: virtual-row table: only visible rows ask the source for cells;
 * header sort, wheel/keyboard scrolling, row selection, double-click open
 * and right-click menu actions. Cell styles: a pill style means the cell
 * text is "<pill label>\t<text>" (pill, 8 px gap, text elided at the right);
 * amount styles are drawn right-aligned with 8 px padding. */
#include <stdio.h>
#include <string.h>

#include "gui/ui.h"

#define RGB(r, g, b) (((uint32_t)(r) << 16) | ((uint32_t)(g) << 8) | (uint32_t)(b))

size_t gui_ui_glyph_map(const char *in, size_t len, char *out, size_t cap);
int32_t gui_ui_run_width(enum gui_font f, int32_t px, const char *s, size_t len);
bool gui_ui_is_pill(enum gui_style st);
int32_t gui_ui_pill_h(const struct gui_ui *ui, enum gui_style st);
void gui_ui_run_draw(struct gui_surface *s, enum gui_font f, int32_t px, int32_t x, int32_t baseline,
                     const char *str, size_t len, uint32_t color, uint32_t dot_color);
void gui_ui_pill_draw(struct gui_ui *ui, struct gui_surface *s, struct gui_rect r, enum gui_style st,
                      const char *label, size_t len);
bool gui_ui_table_row_rect(struct gui_ui *ui, const struct gui_node *n, int64_t row, struct gui_rect *out);
bool gui_ui_table_menu(struct gui_ui *ui, struct gui_node *n, int32_t x, int32_t y, struct gui_action *out);

struct gui_table_state *gui_ui_table_find(struct gui_ui *ui, const char *id)
{
    struct gui_table_state *free_slot = NULL;
    for (size_t i = 0; i < 4; i++) {
        struct gui_table_state *s = &ui->tables_st[i];
        if (s->id[0] && !strcmp(s->id, id)) return s;
        if (!s->id[0] && !free_slot) free_slot = s;
    }
    if (!free_slot) return NULL;
    snprintf(free_slot->id, sizeof(free_slot->id), "%s", id);
    free_slot->selected = -1;
    free_slot->sort_col = -1;
    return free_slot;
}

const struct gui_table_source *gui_ui_source(const struct gui_ui *ui, const char *name)
{
    for (size_t i = 0; i < 4; i++)
        if (ui->sources[i] && !strcmp(ui->sources[i]->name, name)) return ui->sources[i];
    return NULL;
}

void gui_ui_table_source(struct gui_ui *ui, const struct gui_table_source *s)
{
    for (size_t i = 0; i < 4; i++)
        if (!ui->sources[i] || !strcmp(ui->sources[i]->name, s->name)) {
            ui->sources[i] = s;
            return;
        }
}

/* Row pitch and header height match the beta13 capture (30 and 47 at 100%
 * with the bundled Inter metrics): row = max(text + 11, pill + 6). */
static int32_t row_h(const struct gui_ui *ui)
{
    int32_t asc, desc, lh;
    gui_font_metrics(GUI_FONT_TEXT, gui_ui_text_px(ui, GS_TABLE), &asc, &desc, &lh);
    int32_t r = lh + gui_px(ui, 11), p = gui_ui_pill_h(ui, GS_PILL_PRIVATE) + gui_px(ui, 6);
    return r > p ? r : p;
}

static int32_t head_px(const struct gui_ui *ui) { return gui_px(ui, 16); }

static int32_t head_h(const struct gui_ui *ui)
{
    int32_t asc, desc, lh;
    gui_font_metrics(GUI_FONT_STRONG, head_px(ui), &asc, &desc, &lh);
    return lh + gui_px(ui, 31);
}

static int64_t visible_rows(const struct gui_ui *ui, const struct gui_node *n)
{
    int64_t v = (n->frame.h - head_h(ui)) / row_h(ui);
    return v < 1 ? 1 : v;
}

static int64_t max_scroll(const struct gui_ui *ui, const struct gui_node *n,
                          const struct gui_table_source *src)
{
    int64_t rows = (int64_t)src->rows(src->ctx), m = rows - visible_rows(ui, n);
    return m < 0 ? 0 : m;
}

/* Rows a fit column measures: the first ones, so widths never jump on scroll. */
#define FIT_ROWS_MAX 64

static int32_t cell_fit_w(const struct gui_ui *ui, const struct gui_table_source *src, size_t row, uint8_t c,
                          int32_t px)
{
    char raw[256], cell[300];
    enum gui_style cs = GS_BODY;
    if (!src->cell(src->ctx, row, c, raw, sizeof(raw), &cs)) return 0;
    size_t cl = gui_ui_glyph_map(raw, strlen(raw), cell, sizeof(cell));
    return gui_ui_run_width(GUI_FONT_TEXT, px, cell, cl) + 2 * gui_px(ui, 10);
}

/* A negative width fits the header and the first rows' cells (at least
 * -width logical px, at most half the table), like Qt's ResizeToContents. */
static int32_t fit_width(const struct gui_ui *ui, const struct gui_node *n, uint8_t c)
{
    const struct gui_column *col = &n->cols[c];
    int32_t w = gui_px(ui, -col->width);
    int32_t hw = gui_text_width(GUI_FONT_STRONG, head_px(ui), col->label, strlen(col->label)) + 2 * gui_px(ui, 12);
    if (hw > w) w = hw;
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    int32_t px = gui_ui_text_px(ui, GS_TABLE);
    size_t rows = src ? src->rows(src->ctx) : 0;
    for (size_t r = 0; r < rows && r < FIT_ROWS_MAX; r++) {
        int32_t cw = cell_fit_w(ui, src, r, c, px);
        if (cw > w) w = cw;
    }
    return w < n->frame.w / 2 ? w : n->frame.w / 2;
}

static void col_geometry(const struct gui_ui *ui, const struct gui_node *n,
                         int32_t *x, int32_t *w)
{
    int32_t fixed = 0, grow = 0;
    for (uint8_t c = 0; c < n->ncols; c++) {
        int32_t cw = n->cols[c].width;
        w[c] = cw > 0 ? gui_px(ui, cw) : cw < 0 ? fit_width(ui, n, c) : 0;
        if (cw) fixed += w[c];
        else grow++;
    }
    int32_t rest = n->frame.w - fixed;
    int32_t each = grow && rest > 0 ? rest / grow : 0, pos = n->frame.x;
    for (uint8_t c = 0; c < n->ncols; c++) {
        x[c] = pos;
        if (!n->cols[c].width) w[c] = each;
        pos += w[c];
    }
}

bool gui_ui_table_row_rect(struct gui_ui *ui, const struct gui_node *n, int64_t row, struct gui_rect *out)
{
    const struct gui_table_state *st = gui_ui_table_find(ui, n->id);
    if (!st || row < st->scroll || row >= st->scroll + visible_rows(ui, n)) return false;
    int32_t rh = row_h(ui);
    *out = (struct gui_rect){ n->frame.x + 1, n->frame.y + head_h(ui) + (int32_t)(row - st->scroll) * rh,
                              n->frame.w - 2, rh };
    return true;
}

void gui_ui_table_wheel(struct gui_ui *ui, struct gui_node *n, float dy)
{
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    struct gui_table_state *st = gui_ui_table_find(ui, n->id);
    if (!src || !st) return;
    int64_t step = 0;
    int64_t to, mx;
    st->wheel_milli += (int64_t)((double)dy * 3000.0);
    step = st->wheel_milli / 1000;
    if (step == 0) return;
    st->wheel_milli -= step * 1000;
    to = st->scroll - step;
    mx = max_scroll(ui, n, src);
    to = to < 0 ? 0 : to > mx ? mx : to;
    if (to != st->scroll) {
        st->scroll = to;
        gui_ui_mark_rect(ui, n->frame);
    }
}

/* New selection for a navigation key; *known is false for any other key. */
static int64_t key_target(enum gui_key k, int64_t sel, int64_t rows, int64_t vis, bool *known)
{
    *known = true;
    switch (k) {
    case GUI_KEY_DOWN: return sel < 0 ? 0 : sel + 1;
    case GUI_KEY_UP: return sel < 0 ? 0 : sel - 1;
    case GUI_KEY_PAGE_DOWN: return sel + vis;
    case GUI_KEY_PAGE_UP: return sel - vis;
    case GUI_KEY_HOME: return 0;
    case GUI_KEY_END: return rows - 1;
    default: break;
    }
    *known = false;
    return sel;
}

static bool row_action(const struct gui_node *n, const struct gui_table_state *st, const char *verb,
                       struct gui_action *out)
{
    if (st->selected < 0) return false;
    snprintf(out->name, sizeof(out->name), "%.24s.%s", n->bind, verb);
    snprintf(out->node_id, sizeof(out->node_id), "%s", n->id);
    out->row = st->selected;
    return true;
}

bool gui_ui_table_key(struct gui_ui *ui, struct gui_node *n, const struct gui_event *ev,
                      struct gui_action *out)
{
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    struct gui_table_state *st = gui_ui_table_find(ui, n->id);
    if (!src || !st || !ev->key.down) return false;
    int64_t rows = (int64_t)src->rows(src->ctx), vis = visible_rows(ui, n);
    if (ev->key.key == GUI_KEY_ENTER) return row_action(n, st, "open", out);
    bool known;
    int64_t sel = key_target(ev->key.key, st->selected, rows, vis, &known);
    if (!known) return false;
    sel = sel < 0 ? 0 : sel >= rows ? rows - 1 : sel;
    st->selected = rows == 0 ? -1 : sel;
    if (sel >= 0 && sel < st->scroll) st->scroll = sel;
    if (sel >= st->scroll + vis) st->scroll = sel - vis + 1;
    gui_ui_mark_rect(ui, n->frame);
    return false;
}

/* Select the row under y; false when y is on the header or past the rows. */
static bool select_at(struct gui_ui *ui, struct gui_node *n, const struct gui_table_source *src,
                      struct gui_table_state *st, int32_t y)
{
    int32_t rh = row_h(ui), hh = head_h(ui);
    if (y < n->frame.y + hh) return false;
    int64_t row = st->scroll + (y - n->frame.y - hh) / rh;
    gui_ui_mark_rect(ui, n->frame);
    if (row >= (int64_t)src->rows(src->ctx)) return false;
    st->selected = row;
    return true;
}

bool gui_ui_table_click(struct gui_ui *ui, struct gui_node *n, int32_t x, int32_t y,
                        struct gui_action *out)
{
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    struct gui_table_state *st = gui_ui_table_find(ui, n->id);
    if (!src || !st) return false;
    int32_t cx[GUI_MAX_COLS], cw[GUI_MAX_COLS];
    col_geometry(ui, n, cx, cw);
    if (y < n->frame.y + head_h(ui)) {
        for (uint8_t c = 0; c < n->ncols; c++)
            if (x >= cx[c] && x < cx[c] + cw[c] && n->cols[c].sortable && src->sort) {
                st->sort_desc = st->sort_col == c ? !st->sort_desc : false;
                st->sort_col = c;
                src->sort(src->ctx, c, st->sort_desc);
                gui_ui_mark_rect(ui, n->frame);
            }
        return false;
    }
    bool hit = select_at(ui, n, src, st, y);
    return hit && out->row == -2 && row_action(n, st, "open", out); /* row -2: double click */
}

/* Right button: select the row under the pointer and ask for its menu. */
bool gui_ui_table_menu(struct gui_ui *ui, struct gui_node *n, int32_t x, int32_t y, struct gui_action *out)
{
    (void)x;
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    struct gui_table_state *st = gui_ui_table_find(ui, n->id);
    if (!src || !st || !select_at(ui, n, src, st, y)) return false;
    return row_action(n, st, "menu", out);
}

static void paint_header(struct gui_ui *ui, struct gui_surface *s, const struct gui_node *n,
                         const struct gui_table_state *st, const int32_t *cx, const int32_t *cw)
{
    int32_t px = head_px(ui), asc, desc, lh, hh = head_h(ui), pad = gui_px(ui, 12);
    gui_font_metrics(GUI_FONT_STRONG, px, &asc, &desc, &lh);
    /* The header band follows the table's rounded top corners (beta13), so no
     * strip of the table border shows above it as a separate rule. */
    int32_t rad = gui_px(ui, gui_theme(GS_TABLE)->radius) - 1;
    rad = rad < 0 ? 0 : rad > hh / 2 ? hh / 2 : rad;
    gui_fill_round_rect(s, (struct gui_rect){ n->frame.x + 1, n->frame.y + 1, n->frame.w - 2, hh - 1 }, rad,
                        RGB(0x15, 0x17, 0x1c));
    gui_fill_rect(s, (struct gui_rect){ n->frame.x + 1, n->frame.y + 1 + rad, n->frame.w - 2, hh - 1 - rad },
                  RGB(0x15, 0x17, 0x1c));
    gui_fill_rect(s, (struct gui_rect){ n->frame.x + 1, n->frame.y + hh - 1, n->frame.w - 2, 1 },
                  RGB(0x2a, 0x2d, 0x35));
    for (uint8_t c = 0; c < n->ncols; c++) {
        const char *lbl = n->cols[c].label;
        int32_t tw = gui_text_width(GUI_FONT_STRONG, px, lbl, strlen(lbl));
        int32_t x = n->cols[c].right ? cx[c] + cw[c] - pad - tw : cx[c] + (cw[c] - tw) / 2;
        gui_text_draw(s, GUI_FONT_STRONG, px, x, n->frame.y + (hh - lh) / 2 + asc, lbl, strlen(lbl),
                      RGB(0x9a, 0xa0, 0xa6));
        if (st && st->sort_col == c)
            gui_fill_rect(s, (struct gui_rect){ cx[c] + cw[c] - pad - gui_px(ui, 4), n->frame.y + hh / 2 - 1,
                          gui_px(ui, 5), gui_px(ui, 2) }, RGB(0x34, 0xc7, 0x59));
    }
}

static void draw_fit(struct gui_surface *s, int32_t px, int32_t x, int32_t base, int32_t maxw, const char *t,
                     size_t len, uint32_t color)
{
    if (gui_ui_run_width(GUI_FONT_TEXT, px, t, len) <= maxw) {
        gui_ui_run_draw(s, GUI_FONT_TEXT, px, x, base, t, len, color, color);
        return;
    }
    int32_t dots = gui_text_width(GUI_FONT_TEXT, px, "...", 3);
    size_t fit = gui_text_fit(GUI_FONT_TEXT, px, t, len, maxw - dots);
    gui_ui_run_draw(s, GUI_FONT_TEXT, px, x, base, t, fit, color, color);
    gui_text_draw(s, GUI_FONT_TEXT, px, x + gui_ui_run_width(GUI_FONT_TEXT, px, t, fit), base, "...", 3, color);
}

struct cell_geo { struct gui_rect rr; int32_t x, w, px, asc, lh; bool selected, right; };

static void paint_pill_cell(struct gui_ui *ui, struct gui_surface *s, const struct cell_geo *g,
                            enum gui_style cs, const char *cell, size_t cl)
{
    const char *tab = memchr(cell, '\t', cl);
    size_t ll = tab ? (size_t)(tab - cell) : cl;
    int32_t ph = gui_ui_pill_h(ui, cs), ppx = gui_ui_text_px(ui, cs);
    int32_t pw = gui_ui_run_width(gui_theme(cs)->font, ppx, cell, ll) + 2 * gui_px(ui, 8);
    int32_t pad = gui_px(ui, 10);
    struct gui_rect pr = { g->x + pad, g->rr.y + (g->rr.h - ph) / 2, pw, ph };
    gui_ui_pill_draw(ui, s, pr, cs, cell, ll);
    if (!tab) return;
    int32_t tx = pr.x + pw + gui_px(ui, 8);
    draw_fit(s, g->px, tx, g->rr.y + (g->rr.h - g->lh) / 2 + g->asc, g->x + g->w - pad - tx, tab + 1,
             cl - ll - 1, g->selected ? RGB(0xff, 0xff, 0xff) : gui_theme(GS_BODY)->fg);
}

static void paint_cell(struct gui_ui *ui, struct gui_surface *s, const struct gui_table_source *src,
                       int64_t row, uint8_t c, struct cell_geo *g)
{
    char raw[256], cell[300];
    enum gui_style cs = GS_BODY;
    if (!src->cell(src->ctx, (size_t)row, c, raw, sizeof(raw), &cs)) return;
    size_t cl = gui_ui_glyph_map(raw, strlen(raw), cell, sizeof(cell));
    if (gui_ui_is_pill(cs)) { paint_pill_cell(ui, s, g, cs, cell, cl); return; }
    bool amount = cs == GS_AMOUNT_MONO || cs == GS_WARN_TEXT || g->right;
    int32_t pad = gui_px(ui, amount ? 8 : 10);
    int32_t tw = gui_ui_run_width(GUI_FONT_TEXT, g->px, cell, cl);
    int32_t x = amount ? g->x + g->w - pad - tw : g->x + pad;
    if (x < g->x + pad) x = g->x + pad;
    uint32_t fg = g->selected ? RGB(0xff, 0xff, 0xff) : gui_theme(cs)->fg;
    draw_fit(s, g->px, x, g->rr.y + (g->rr.h - g->lh) / 2 + g->asc, g->w - 2 * pad, cell, cl, fg);
}

static void paint_rows(struct gui_ui *ui, struct gui_surface *s, const struct gui_node *n,
                       const struct gui_table_state *st, const int32_t *cx, const int32_t *cw)
{
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    if (!src || !st) return;
    struct cell_geo g;
    int32_t desc, rh = row_h(ui);
    g.px = gui_ui_text_px(ui, GS_TABLE);
    gui_font_metrics(GUI_FONT_TEXT, g.px, &g.asc, &desc, &g.lh);
    int64_t rows = (int64_t)src->rows(src->ctx), vis = visible_rows(ui, n);
    for (int64_t r = 0; r < vis && st->scroll + r < rows; r++) {
        int64_t row = st->scroll + r;
        g.rr = (struct gui_rect){ n->frame.x + 1, n->frame.y + head_h(ui) + (int32_t)r * rh, n->frame.w - 2, rh };
        g.selected = row == st->selected;
        if (g.selected) gui_fill_rect(s, g.rr, RGB(0x24, 0x30, 0x47));
        for (uint8_t c = 0; c < n->ncols; c++) {
            g.x = cx[c];
            g.w = cw[c];
            g.right = n->cols[c].right;
            paint_cell(ui, s, src, row, c, &g);
        }
    }
}

void gui_ui_table_paint(struct gui_ui *ui, struct gui_surface *s, struct gui_node *n)
{
    const struct gui_theme_entry *th = gui_theme(GS_TABLE);
    int32_t rad = gui_px(ui, th->radius), cx[GUI_MAX_COLS], cw[GUI_MAX_COLS];
    gui_fill_round_rect(s, n->frame, rad, th->border);
    gui_fill_round_rect(s, (struct gui_rect){ n->frame.x + 1, n->frame.y + 1, n->frame.w - 2, n->frame.h - 2 },
                        rad > 0 ? rad - 1 : 0, th->bg);
    struct gui_table_state *st = gui_ui_table_find(ui, n->id);
    col_geometry(ui, n, cx, cw);
    if (!gui_clip_push(s, (struct gui_rect){ n->frame.x + 1, n->frame.y + 1, n->frame.w - 2, n->frame.h - 2 }))
        return;
    paint_header(ui, s, n, st, cx, cw);
    paint_rows(ui, s, n, st, cx, cw);
    gui_clip_pop(s);
    if (ui->focus[0] && !strcmp(ui->focus, n->id) && ui->kbd_focus) {
        int32_t t = gui_px(ui, 2), o = t + gui_px(ui, 2);
        gui_stroke_rect(s, (struct gui_rect){ n->frame.x - o, n->frame.y - o, n->frame.w + 2 * o,
                        n->frame.h + 2 * o }, t, RGB(0x34, 0xc7, 0x59));
    }
}
