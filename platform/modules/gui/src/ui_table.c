/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: virtual-row table: only visible rows ask the source for cells;
 * header sort, wheel/keyboard scrolling and row selection. */
#include <stdio.h>
#include <string.h>

#include "gui/ui.h"

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

static int32_t row_h(const struct gui_ui *ui)
{
    int32_t asc, desc, lh;
    gui_font_metrics(GUI_FONT_TEXT, gui_ui_text_px(ui, GS_TABLE), &asc, &desc, &lh);
    return lh + 2 * gui_px(ui, 6);
}

static int64_t visible_rows(const struct gui_ui *ui, const struct gui_node *n)
{
    int64_t v = (n->frame.h - row_h(ui)) / row_h(ui);
    return v < 1 ? 1 : v;
}

static int64_t max_scroll(const struct gui_ui *ui, const struct gui_node *n,
                          const struct gui_table_source *src)
{
    int64_t rows = (int64_t)src->rows(src->ctx), m = rows - visible_rows(ui, n);
    return m < 0 ? 0 : m;
}

static void col_geometry(const struct gui_ui *ui, const struct gui_node *n,
                         int32_t *x, int32_t *w)
{
    int32_t fixed = 0, grow = 0;
    for (uint8_t c = 0; c < n->ncols; c++) {
        if (n->cols[c].width) fixed += gui_px(ui, n->cols[c].width);
        else grow++;
    }
    int32_t rest = n->frame.w - fixed;
    int32_t each = grow && rest > 0 ? rest / grow : 0, pos = n->frame.x;
    for (uint8_t c = 0; c < n->ncols; c++) {
        x[c] = pos;
        w[c] = n->cols[c].width ? gui_px(ui, n->cols[c].width) : each;
        pos += w[c];
    }
}

void gui_ui_table_wheel(struct gui_ui *ui, struct gui_node *n, float dy)
{
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    struct gui_table_state *st = gui_ui_table_find(ui, n->id);
    if (!src || !st) return;
    int64_t to = st->scroll - (int64_t)(dy * 3.0f);
    int64_t mx = max_scroll(ui, n, src);
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

bool gui_ui_table_key(struct gui_ui *ui, struct gui_node *n, const struct gui_event *ev,
                      struct gui_action *out)
{
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    struct gui_table_state *st = gui_ui_table_find(ui, n->id);
    if (!src || !st || !ev->key.down) return false;
    int64_t rows = (int64_t)src->rows(src->ctx), vis = visible_rows(ui, n);
    if (ev->key.key == GUI_KEY_ENTER) {
        if (st->selected < 0) return false;
        snprintf(out->name, sizeof(out->name), "%.26s.open", n->bind);
        snprintf(out->node_id, sizeof(out->node_id), "%s", n->id);
        out->row = st->selected;
        return true;
    }
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

bool gui_ui_table_click(struct gui_ui *ui, struct gui_node *n, int32_t x, int32_t y,
                        struct gui_action *out)
{
    (void)out;
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    struct gui_table_state *st = gui_ui_table_find(ui, n->id);
    if (!src || !st) return false;
    int32_t rh = row_h(ui), cx[GUI_MAX_COLS], cw[GUI_MAX_COLS];
    col_geometry(ui, n, cx, cw);
    if (y < n->frame.y + rh) {
        for (uint8_t c = 0; c < n->ncols; c++)
            if (x >= cx[c] && x < cx[c] + cw[c] && n->cols[c].sortable && src->sort) {
                st->sort_desc = st->sort_col == c ? !st->sort_desc : false;
                st->sort_col = c;
                src->sort(src->ctx, c, st->sort_desc);
                gui_ui_mark_rect(ui, n->frame);
            }
        return false;
    }
    int64_t row = st->scroll + (y - n->frame.y - rh) / rh;
    if (row < (int64_t)src->rows(src->ctx)) st->selected = row;
    gui_ui_mark_rect(ui, n->frame);
    return false;
}

static void paint_header(struct gui_ui *ui, struct gui_surface *s, const struct gui_node *n,
                         const struct gui_table_state *st, const int32_t *cx, const int32_t *cw)
{
    int32_t px = gui_ui_text_px(ui, GS_TABLE), asc, desc, lh;
    int32_t rh = row_h(ui), pad = gui_px(ui, 8);
    gui_font_metrics(GUI_FONT_TEXT, px, &asc, &desc, &lh);
    gui_fill_rect(s, (struct gui_rect){ n->frame.x + 1, n->frame.y + 1, n->frame.w - 2, rh - 1 },
                  gui_rgb(0x24, 0x28, 0x32));
    for (uint8_t c = 0; c < n->ncols; c++) {
        const char *lbl = n->cols[c].label;
        int32_t tw = gui_text_width(GUI_FONT_STRONG, px, lbl, strlen(lbl));
        int32_t x = n->cols[c].right ? cx[c] + cw[c] - pad - tw : cx[c] + pad;
        gui_text_draw(s, GUI_FONT_STRONG, px, x, n->frame.y + gui_px(ui, 6) + asc, lbl, strlen(lbl),
                      gui_rgb(0xe8, 0xea, 0xf0));
        if (st && st->sort_col == c)
            gui_fill_rect(s, (struct gui_rect){ cx[c] + cw[c] - pad - gui_px(ui, 4), n->frame.y + rh / 2 - 1,
                          gui_px(ui, 5), gui_px(ui, 2) }, gui_rgb(0x7a, 0xb8, 0xff));
    }
}

static void paint_cell(struct gui_ui *ui, struct gui_surface *s, const struct gui_node *n,
                       const struct gui_table_source *src, int64_t row, uint8_t c,
                       struct gui_rect rr, const int32_t *cx, const int32_t *cw)
{
    int32_t px = gui_ui_text_px(ui, GS_TABLE), asc, desc, lh, pad = gui_px(ui, 8);
    gui_font_metrics(GUI_FONT_TEXT, px, &asc, &desc, &lh);
    char cell[128];
    enum gui_style cs = GS_BODY;
    if (!src->cell(src->ctx, (size_t)row, c, cell, sizeof(cell), &cs)) return;
    size_t cl = strlen(cell);
    size_t fit = gui_text_fit(GUI_FONT_TEXT, px, cell, cl, cw[c] - 2 * pad);
    int32_t tw = gui_text_width(GUI_FONT_TEXT, px, cell, fit);
    int32_t x = n->cols[c].right ? cx[c] + cw[c] - pad - tw : cx[c] + pad;
    gui_text_draw(s, GUI_FONT_TEXT, px, x, rr.y + gui_px(ui, 6) + asc, cell, fit, gui_theme(cs)->fg);
}

static void paint_rows(struct gui_ui *ui, struct gui_surface *s, const struct gui_node *n,
                       const struct gui_table_state *st, const int32_t *cx, const int32_t *cw)
{
    const struct gui_table_source *src = gui_ui_source(ui, n->bind);
    if (!src || !st) return;
    int32_t rh = row_h(ui);
    int64_t rows = (int64_t)src->rows(src->ctx), vis = visible_rows(ui, n);
    for (int64_t r = 0; r < vis && st->scroll + r < rows; r++) {
        int64_t row = st->scroll + r;
        struct gui_rect rr = { n->frame.x + 1, n->frame.y + rh + (int32_t)r * rh, n->frame.w - 2, rh };
        if (row == st->selected) gui_fill_rect(s, rr, gui_rgb(0x2a, 0x33, 0x50));
        else if (r & 1) gui_fill_rect(s, rr, gui_rgb(0x20, 0x23, 0x2c));
        for (uint8_t c = 0; c < n->ncols; c++) paint_cell(ui, s, n, src, row, c, rr, cx, cw);
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
    gui_clip_push(s, n->frame);
    paint_header(ui, s, n, st, cx, cw);
    paint_rows(ui, s, n, st, cx, cw);
    gui_clip_pop(s);
    if (ui->focus[0] && !strcmp(ui->focus, n->id) && ui->kbd_focus) {
        int32_t t = gui_px(ui, 2);
        gui_stroke_rect(s, (struct gui_rect){ n->frame.x - t, n->frame.y - t, n->frame.w + 2 * t,
                        n->frame.h + 2 * t }, t, gui_rgb(0x7a, 0xb8, 0xff));
    }
}
