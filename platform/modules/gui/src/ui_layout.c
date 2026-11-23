/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure and arrange the widget tree in physical pixels. Logical
 * values are multiplied by the window scale exactly once, here. */
#include <math.h>
#include <string.h>

#include "gui/ui.h"

int32_t gui_px(const struct gui_ui *ui, int32_t logical)
{
    return (int32_t)lroundf((float)logical * ui->scale);
}

int32_t gui_ui_text_px(const struct gui_ui *ui, enum gui_style st)
{
    int32_t lp = gui_theme(st)->text_px;
    if (lp < GUI_MIN_TEXT_PX) lp = GUI_MIN_TEXT_PX;
    return gui_px(ui, lp);
}

/* One wrapped line: bytes consumed (including a swallowed space/newline). */
size_t gui_wrap_line(enum gui_font f, int32_t px, const char *s, size_t len,
                     int32_t max_w)
{
    size_t nl = 0;
    while (nl < len && s[nl] != '\n') nl++;
    if (nl < len && gui_text_width(f, px, s, nl) <= max_w) return nl + 1;
    size_t fit = gui_text_fit(f, px, s, len, max_w);
    if (fit >= len) return len;
    size_t brk = fit;
    while (brk > 0 && s[brk - 1] != ' ') brk--;
    if (brk == 0) return fit ? fit : (size_t)1;
    return brk;
}

static const char *node_text(const struct gui_ui *ui, const struct gui_node *n)
{
    return n->bind[0] && n->kind == GUI_TEXT ? gui_ui_get(ui, n->bind)
                                             : gui_tree_text(ui->tree, n);
}

static size_t node_text_len(const struct gui_ui *ui, const struct gui_node *n)
{
    return strlen(node_text(ui, n));
}

static bool visible(const struct gui_node *n)
{
    return !(n->flags & GUI_F_HIDDEN) && n->kind != GUI_DIALOG;
}

static void measure(struct gui_ui *ui, uint16_t i, int32_t avail_w);

static int32_t count_visible(const struct gui_ui *ui, const struct gui_node *n)
{
    int32_t k = 0;
    for (uint16_t c = n->first; c != GUI_NONE; c = ui->tree->nodes[c].next)
        if (visible(&ui->tree->nodes[c])) k++;
    return k;
}

static void measure_text(struct gui_ui *ui, struct gui_node *n, int32_t avail_w)
{
    const struct gui_theme_entry *th = gui_theme(n->style);
    int32_t px = gui_ui_text_px(ui, n->style), asc, desc, lh;
    gui_font_metrics(th->font, px, &asc, &desc, &lh);
    const char *s = node_text(ui, n);
    size_t len = node_text_len(ui, n);
    if ((n->flags & GUI_F_WRAP) && avail_w > 0) {
        int32_t maxw = 0, lines = 0;
        size_t at = 0;
        while (at < len || lines == 0) {
            size_t k = gui_wrap_line(th->font, px, s + at, len - at, avail_w);
            size_t shown = k;
            while (shown > 0 && (s[at + shown - 1] == ' ' || s[at + shown - 1] == '\n')) shown--;
            int32_t lw = gui_text_width(th->font, px, s + at, shown);
            if (lw > maxw) maxw = lw;
            lines++;
            at += k;
            if (k == 0) break;
        }
        n->nat_w = maxw;
        n->nat_h = lines * lh;
    } else {
        n->nat_w = gui_text_width(th->font, px, s, len);
        n->nat_h = lh;
    }
    if (n->style >= GS_BADGE_PRIVATE && n->style <= GS_BADGE_DANGER) {
        n->nat_w += 2 * gui_px(ui, 9);
        n->nat_h += 2 * gui_px(ui, 3);
    }
}

static void measure_leaf(struct gui_ui *ui, struct gui_node *n, int32_t avail_w)
{
    const struct gui_theme_entry *th = gui_theme(n->style);
    int32_t px = gui_ui_text_px(ui, n->style), asc, desc, lh;
    gui_font_metrics(th->font, px, &asc, &desc, &lh);
    switch (n->kind) {
    case GUI_TEXT: measure_text(ui, n, avail_w); break;
    case GUI_BUTTON:
        n->nat_w = gui_text_width(th->font, px, gui_tree_text(ui->tree, n), n->text_len) +
                   2 * gui_px(ui, 14);
        n->nat_h = lh + 2 * gui_px(ui, 8);
        break;
    case GUI_INPUT:
        n->nat_w = gui_px(ui, n->w ? n->w : 240);
        n->nat_h = (n->ikind == GUI_IN_MEMO ? 3 * lh : lh) + 2 * gui_px(ui, 8);
        break;
    case GUI_PROGRESS:
        n->nat_w = n->w ? gui_px(ui, n->w) : 0;
        n->nat_h = gui_px(ui, 8);
        break;
    case GUI_TABLE:
        n->nat_w = gui_px(ui, n->w ? n->w : 480);
        n->nat_h = gui_px(ui, n->h ? n->h : 220);
        break;
    default: n->nat_w = n->nat_h = 0; break;
    }
}

/* A row measures its fixed children first (pass 0); growing children (pass 1)
 * then learn the width left over so wrapped text inside them wraps right. A
 * column measures everyone in pass 1. */
static bool in_pass(const struct gui_node *n, const struct gui_node *ch, int pass)
{
    if (!visible(ch)) return false;
    if (n->dir == GUI_COL) return pass == 1;
    return pass == 0 ? ch->grow <= 0 : ch->grow > 0;
}

static int32_t child_avail(const struct gui_ui *ui, const struct gui_node *n,
                           const struct gui_node *ch, int32_t inner, int32_t fixed_sum)
{
    if (n->dir == GUI_COL) return inner;
    if (ch->grow <= 0 || inner <= 0) return 0;
    int32_t a = inner - fixed_sum - gui_px(ui, n->gap) * (count_visible(ui, n) - 1);
    return a < 0 ? 0 : a;
}

static void measure_children(struct gui_ui *ui, struct gui_node *n, int32_t avail_w)
{
    int32_t inner = avail_w > 0 ? avail_w - 2 * gui_px(ui, n->pad) : 0, fixed_sum = 0;
    for (int pass = n->dir == GUI_COL ? 1 : 0; pass < 2; pass++)
        for (uint16_t c = n->first; c != GUI_NONE; c = ui->tree->nodes[c].next) {
            struct gui_node *ch = &ui->tree->nodes[c];
            if (!in_pass(n, ch, pass)) continue;
            measure(ui, c, child_avail(ui, n, ch, inner, fixed_sum));
            if (pass == 0 && n->dir == GUI_ROW) fixed_sum += ch->nat_w;
        }
}

static void measure_box(struct gui_ui *ui, struct gui_node *n, int32_t avail_w)
{
    int32_t pad = gui_px(ui, n->pad), gap = gui_px(ui, n->gap);
    int32_t main_sum = 0, cross_max = 0, count = 0;
    bool col = n->dir == GUI_COL;
    measure_children(ui, n, avail_w);
    for (uint16_t c = n->first; c != GUI_NONE; c = ui->tree->nodes[c].next) {
        const struct gui_node *ch = &ui->tree->nodes[c];
        if (!visible(ch)) continue;
        main_sum += col ? ch->nat_h : ch->nat_w;
        int32_t cr = col ? ch->nat_w : ch->nat_h;
        if (cr > cross_max) cross_max = cr;
        count++;
    }
    if (count > 1) main_sum += gap * (count - 1);
    n->nat_w = 2 * pad + (col ? cross_max : main_sum);
    n->nat_h = 2 * pad + (col ? main_sum : cross_max);
}

static void measure(struct gui_ui *ui, uint16_t i, int32_t avail_w)
{
    struct gui_node *n = &ui->tree->nodes[i];
    if (n->kind == GUI_BOX || n->kind == GUI_DIALOG) measure_box(ui, n, avail_w);
    else measure_leaf(ui, n, avail_w);
    if (n->w && n->kind != GUI_INPUT && n->kind != GUI_TABLE) n->nat_w = gui_px(ui, n->w);
    if (n->h && n->kind != GUI_TABLE) n->nat_h = gui_px(ui, n->h);
}

static void arrange(struct gui_ui *ui, uint16_t i, struct gui_rect fr);

struct flow {
    struct gui_rect in;
    int32_t gap, extra, grow_sum, given, seen_grow, pos;
    bool col;
};

static void flow_totals(const struct gui_ui *ui, const struct gui_node *n, struct flow *f)
{
    int32_t total = 0, count = 0;
    for (uint16_t c = n->first; c != GUI_NONE; c = ui->tree->nodes[c].next) {
        const struct gui_node *ch = &ui->tree->nodes[c];
        if (!visible(ch)) continue;
        if (ch->grow <= 0) total += f->col ? ch->nat_h : ch->nat_w; /* growers start from zero */
        else f->grow_sum += ch->grow;
        count++;
    }
    if (count > 1) total += f->gap * (count - 1);
    f->extra = (f->col ? f->in.h : f->in.w) - total;
    if (f->extra < 0) f->extra = 0;
}

/* Main-axis size of one child: its natural size, or its share of the slack. */
static int32_t main_size(struct flow *f, const struct gui_node *ch)
{
    if (ch->grow <= 0) return f->col ? ch->nat_h : ch->nat_w;
    f->seen_grow += ch->grow;
    int32_t share = f->seen_grow == f->grow_sum ? f->extra - f->given
                                                : f->extra * ch->grow / f->grow_sum;
    f->given += share;
    return share;
}

static int32_t cross_size(const struct gui_node *n, const struct gui_node *ch, bool col,
                          int32_t cross_avail)
{
    int32_t cross = col ? ch->nat_w : ch->nat_h;
    bool fixed = col ? ch->w != 0 : ch->h != 0;
    if (n->align == GUI_ALIGN_STRETCH && !fixed && ch->kind != GUI_BUTTON) cross = cross_avail;
    if (ch->kind == GUI_PROGRESS || ch->kind == GUI_TABLE) cross = col && !ch->w ? cross_avail : cross;
    return cross > cross_avail ? cross_avail : cross;
}

static struct gui_rect child_rect(const struct gui_node *n, const struct gui_node *ch,
                                  const struct flow *f, int32_t main)
{
    int32_t cross_avail = f->col ? f->in.w : f->in.h;
    int32_t cross = cross_size(n, ch, f->col, cross_avail), off = 0;
    if (n->align == GUI_ALIGN_CENTER) off = (cross_avail - cross) / 2;
    else if (n->align == GUI_ALIGN_END) off = cross_avail - cross;
    return f->col ? (struct gui_rect){ f->in.x + off, f->pos, cross, main }
                  : (struct gui_rect){ f->pos, f->in.y + off, main, cross };
}

/* Distribute main-axis space and place children. */
static void arrange_children(struct gui_ui *ui, struct gui_node *n,
                             struct gui_rect box, int32_t top_inset)
{
    int32_t pad = gui_px(ui, n->pad);
    struct flow f = { .in = { box.x + pad, box.y + pad + top_inset, box.w - 2 * pad,
                              box.h - 2 * pad - top_inset },
                      .gap = gui_px(ui, n->gap), .col = n->dir == GUI_COL };
    flow_totals(ui, n, &f);
    f.pos = f.col ? f.in.y : f.in.x;
    for (uint16_t c = n->first; c != GUI_NONE; c = ui->tree->nodes[c].next) {
        struct gui_node *ch = &ui->tree->nodes[c];
        if (!visible(ch)) continue;
        int32_t main = main_size(&f, ch);
        struct gui_rect fr = child_rect(n, ch, &f, main);
        if (f.col && ch->kind == GUI_TEXT && (ch->flags & GUI_F_WRAP)) {
            measure(ui, c, fr.w);
            fr.h = ch->nat_h;
            main = ch->nat_h;
        }
        arrange(ui, c, fr);
        f.pos += main + f.gap;
    }
}

static void arrange(struct gui_ui *ui, uint16_t i, struct gui_rect fr)
{
    struct gui_node *n = &ui->tree->nodes[i];
    n->frame = fr;
    if (n->kind == GUI_BOX) arrange_children(ui, n, fr, 0);
}

static void layout_dialog(struct gui_ui *ui, uint16_t i)
{
    struct gui_node *n = &ui->tree->nodes[i];
    if (!n->pad) n->pad = 20;
    if (!n->gap) n->gap = 12;
    int32_t dw = gui_px(ui, n->w ? n->w : 440);
    if (dw > ui->w - 2 * gui_px(ui, 16)) dw = ui->w - 2 * gui_px(ui, 16);
    int32_t px = gui_ui_text_px(ui, GS_TITLE), asc, desc, lh;
    gui_font_metrics(GUI_FONT_STRONG, px, &asc, &desc, &lh);
    int32_t inset = lh + gui_px(ui, 12);
    measure_box(ui, n, dw);
    int32_t dh = n->nat_h + inset;
    if (dh > ui->h - 2 * gui_px(ui, 16)) dh = ui->h - 2 * gui_px(ui, 16);
    n->frame = (struct gui_rect){ (ui->w - dw) / 2, (ui->h - dh) / 3, dw, dh };
    arrange_children(ui, n, n->frame, inset);
    /* Children of a dialog box were measured at dw; re-arranged above. */
}

static void layout_dialogs(struct gui_ui *ui, uint16_t i)
{
    const struct gui_tree *t = ui->tree;
    for (uint16_t c = t->nodes[i].first; c != GUI_NONE; c = t->nodes[c].next) {
        if (t->nodes[c].flags & GUI_F_HIDDEN) continue;
        if (t->nodes[c].kind == GUI_DIALOG) layout_dialog(ui, c);
        else if (t->nodes[c].kind == GUI_BOX) layout_dialogs(ui, c);
    }
}

void gui_ui_layout(struct gui_ui *ui, int32_t w, int32_t h)
{
    struct gui_tree *t = ui->tree;
    ui->w = w;
    ui->h = h;
    if (t->root == GUI_NONE) return;
    measure(ui, t->root, w);
    arrange(ui, t->root, (struct gui_rect){ 0, 0, w, h });
    layout_dialogs(ui, t->root);
    ui->layout_dirty = false;
    ui->dirty[0] = (struct gui_rect){ 0, 0, w, h };
    ui->ndirty = 1; /* a relayout repaints and presents everything */
}
