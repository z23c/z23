/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: arena tree builder with hard limits, canonical dump, and the
 * bound-data table. Builders never check per call: the first overflow is
 * recorded and every later call becomes a no-op. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "gui/ui.h"

struct gui_tree *gui_tree_new(void)
{
    struct gui_tree *t = zcl_calloc(1, sizeof(*t), "gui_tree");
    if (!t) return NULL;
    t->nodes = zcl_calloc(GUI_MAX_NODES, sizeof(*t->nodes), "gui_nodes");
    t->text = zcl_malloc(GUI_TEXT_ARENA, "gui_text_arena");
    if (!t->nodes || !t->text) {
        gui_tree_free(t);
        return NULL;
    }
    gui_tree_begin(t);
    return t;
}

void gui_tree_free(struct gui_tree *t)
{
    if (!t) return;
    free(t->nodes);
    free(t->text);
    free(t);
}

void gui_tree_begin(struct gui_tree *t)
{
    memset(t->nodes, 0, sizeof(*t->nodes) * t->count);
    t->count = 0;
    t->root = GUI_NONE;
    t->cur = GUI_NONE;
    t->depth = 0;
    t->text_used = 0;
    t->error[0] = 0;
}

static void fail(struct gui_tree *t, const char *msg)
{
    if (!t->error[0]) snprintf(t->error, sizeof(t->error), "%s", msg);
}

static bool put_str(char *dst, size_t cap, const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n >= cap) return false;
    if (n) memcpy(dst, s, n);
    dst[n] = 0;
    return true;
}

static uint32_t arena_put(struct gui_tree *t, const char *s, uint16_t *len)
{
    size_t n = s ? strlen(s) : 0;
    if (t->text_used + n + 1 > GUI_TEXT_ARENA || n > UINT16_MAX) {
        fail(t, "text arena overflow (64 KiB)");
        *len = 0;
        return 0;
    }
    uint32_t off = t->text_used;
    if (n) memcpy(t->text + off, s, n);
    t->text[off + n] = 0;
    t->text_used += (uint32_t)n + 1;
    *len = (uint16_t)n;
    return off;
}

static struct gui_node *add(struct gui_tree *t, enum gui_kind kind,
                            const char *id, enum gui_style style)
{
    if (t->error[0]) return NULL;
    if (t->count >= GUI_MAX_NODES) { fail(t, "too many nodes (limit 1024)"); return NULL; }
    if (t->root != GUI_NONE && t->cur == GUI_NONE) { fail(t, "second root element"); return NULL; }
    struct gui_node *n = &t->nodes[t->count];
    memset(n, 0, sizeof(*n));
    n->kind = kind;
    n->style = style;
    n->parent = t->cur;
    n->first = n->next = n->last = GUI_NONE;
    n->depth = t->depth;
    if (!put_str(n->id, sizeof(n->id), id)) { fail(t, "id longer than 31 bytes"); return NULL; }
    uint16_t idx = t->count++;
    if (t->cur == GUI_NONE) {
        t->root = idx;
    } else {
        struct gui_node *p = &t->nodes[t->cur];
        if (p->last == GUI_NONE) p->first = idx; else t->nodes[p->last].next = idx;
        p->last = idx;
    }
    return n;
}

static uint16_t idx_of(const struct gui_tree *t, const struct gui_node *n)
{
    return (uint16_t)(n - t->nodes);
}

static void push(struct gui_tree *t, struct gui_node *n)
{
    if (t->depth + 1u > GUI_MAX_DEPTH) { fail(t, "nesting too deep (limit 16)"); return; }
    t->cur = idx_of(t, n);
    t->depth++;
}

void gui_box(struct gui_tree *t, const char *id, enum gui_dir dir,
             enum gui_style style)
{
    struct gui_node *n = add(t, GUI_BOX, id, style);
    if (!n) return;
    n->dir = dir;
    push(t, n);
}

void gui_end(struct gui_tree *t)
{
    if (t->error[0]) return;
    if (t->cur == GUI_NONE) { fail(t, "gui_end without an open box"); return; }
    t->cur = t->nodes[t->cur].parent;
    t->depth--;
}

void gui_text(struct gui_tree *t, const char *id, enum gui_style style,
              const char *utf8)
{
    struct gui_node *n = add(t, GUI_TEXT, id, style);
    if (n) n->text_off = arena_put(t, utf8, &n->text_len);
}

void gui_text_bind(struct gui_tree *t, const char *id, enum gui_style style,
                   const char *bind)
{
    struct gui_node *n = add(t, GUI_TEXT, id, style);
    if (n && !put_str(n->bind, sizeof(n->bind), bind)) fail(t, "bind key too long");
}

void gui_button(struct gui_tree *t, const char *id, enum gui_style style,
                const char *label, const char *action)
{
    struct gui_node *n = add(t, GUI_BUTTON, id, style);
    if (!n) return;
    n->flags |= GUI_F_FOCUSABLE;
    n->text_off = arena_put(t, label, &n->text_len);
    if (!put_str(n->action, sizeof(n->action), action)) fail(t, "action name too long");
}

void gui_input(struct gui_tree *t, const char *id, enum gui_input_kind kind,
               const char *bind, const char *placeholder, uint16_t max_bytes)
{
    struct gui_node *n = add(t, GUI_INPUT, id, GS_INPUT);
    if (!n) return;
    n->flags |= GUI_F_FOCUSABLE;
    n->ikind = kind;
    n->max_bytes = max_bytes ? max_bytes : 256;
    if (n->max_bytes > 512) n->max_bytes = 512;
    if (kind == GUI_IN_MEMO) n->flags |= GUI_F_MULTILINE;
    if (kind == GUI_IN_SECRET) n->flags |= GUI_F_SECRET;
    n->text_off = arena_put(t, placeholder, &n->text_len);
    if (!put_str(n->bind, sizeof(n->bind), bind)) fail(t, "bind key too long");
}

void gui_table(struct gui_tree *t, const char *id, const char *bind,
               const struct gui_column *cols, size_t ncols)
{
    struct gui_node *n = add(t, GUI_TABLE, id, GS_TABLE);
    if (!n) return;
    if (ncols == 0 || ncols > GUI_MAX_COLS) { fail(t, "table needs 1..8 columns"); return; }
    n->flags |= GUI_F_FOCUSABLE;
    n->ncols = (uint8_t)ncols;
    for (size_t i = 0; i < ncols; i++) {
        n->cols[i] = cols[i];
        if (!put_str(n->col_labels[i], sizeof(n->col_labels[i]), cols[i].label)) {
            fail(t, "column label too long");
            return;
        }
        n->cols[i].label = n->col_labels[i];
    }
    if (!put_str(n->bind, sizeof(n->bind), bind)) fail(t, "bind key too long");
}

void gui_progress(struct gui_tree *t, const char *id, const char *bind)
{
    struct gui_node *n = add(t, GUI_PROGRESS, id, GS_BODY);
    if (n && !put_str(n->bind, sizeof(n->bind), bind)) fail(t, "bind key too long");
}

void gui_spacer(struct gui_tree *t, int16_t grow)
{
    struct gui_node *n = add(t, GUI_SPACER, "", GS_BODY);
    if (n) n->grow = grow;
}

void gui_dialog(struct gui_tree *t, const char *id, const char *title,
                const char *cancel_action)
{
    struct gui_node *n = add(t, GUI_DIALOG, id, GS_DIALOG);
    if (!n) return;
    n->dir = GUI_COL;
    n->text_off = arena_put(t, title, &n->text_len);
    if (!put_str(n->action, sizeof(n->action), cancel_action)) fail(t, "action name too long");
    push(t, n);
}

void gui_attr(struct gui_tree *t, enum gui_attr a, int32_t v)
{
    if (t->error[0] || t->count == 0) return;
    struct gui_node *n = &t->nodes[t->count - 1];
    if (v < -32768 || v > 32767) { fail(t, "attribute out of range"); return; }
    switch (a) {
    case GUI_A_GAP: n->gap = (int16_t)v; break;
    case GUI_A_PAD: n->pad = (int16_t)v; break;
    case GUI_A_W: n->w = (int16_t)v; break;
    case GUI_A_H: n->h = (int16_t)v; break;
    case GUI_A_GROW: n->grow = (int16_t)v; break;
    case GUI_A_ALIGN: n->align = (enum gui_align)v; break;
    }
}

void gui_flag(struct gui_tree *t, uint16_t f)
{
    if (t->error[0] || t->count == 0) return;
    t->nodes[t->count - 1].flags |= f;
}

bool gui_tree_end(struct gui_tree *t, char *err, size_t cap)
{
    if (!t->error[0] && t->cur != GUI_NONE) fail(t, "unclosed box");
    if (!t->error[0] && t->root == GUI_NONE) fail(t, "empty tree");
    for (uint16_t i = 0; !t->error[0] && i < t->count; i++) {
        if (!t->nodes[i].id[0]) continue;
        for (uint16_t j = (uint16_t)(i + 1u); j < t->count; j++)
            if (!strcmp(t->nodes[i].id, t->nodes[j].id)) {
                snprintf(t->error, sizeof(t->error), "duplicate id %s", t->nodes[i].id);
                break;
            }
    }
    if (t->error[0]) {
        if (err && cap) snprintf(err, cap, "%s", t->error);
        return false;
    }
    return true;
}

const char *gui_tree_text(const struct gui_tree *t, const struct gui_node *n)
{
    return t->text + n->text_off;
}

int gui_tree_find(const struct gui_tree *t, const char *id)
{
    if (!id || !id[0]) return -1;
    for (uint16_t i = 0; i < t->count; i++)
        if (!strcmp(t->nodes[i].id, id)) return i;
    return -1;
}

/* ---- dump ------------------------------------------------------------ */

static const char *const k_kind[] = { "box", "text", "button", "input", "table",
    "progress", "qr", "tabs", "spacer", "dialog", "menu" };
static const char *const k_style[GS_COUNT] = { "screen", "card", "card_warn",
    "title", "body", "muted", "hero", "amount", "badge_private", "badge_public",
    "badge_danger", "button", "button_primary", "button_danger", "input",
    "table", "nav", "nav_active", "status", "toast", "dialog",
    "rail", "nav_item", "nav_item_active", "nav_adv", "nav_adv_active", "page",
    "group", "group_title", "hero_card", "hero_caption", "hero_amount_ok",
    "hero_amount_warm", "hero_total", "hero_note", "button_secondary",
    "button_amber", "card_amber", "amber_text", "pill_private", "pill_public",
    "pill_deshield", "amount_mono", "sync_pill", "banner_connecting",
    "banner_syncing", "banner_info", "banner_text", "menubar", "menubar_item",
    "menu_popup", "menu_item", "statusbar", "status_label", "status_msg",
    "icon_ok", "icon_warn", "icon_crit", "warn_text" };
static const char *const k_align[] = { "stretch", "start", "center", "end" };
static const char *const k_ikind[] = { "text", "amount", "address", "memo", "secret" };
static const struct { uint16_t f; const char *n; } k_flags[] = {
    { GUI_F_SCROLL_Y, "scroll" }, { GUI_F_DISABLED, "disabled" },
    { GUI_F_HIDDEN, "hidden" }, { GUI_F_DEFAULT, "default" },
    { GUI_F_WRAP, "wrap" }, { GUI_F_ELLIPSIS, "ellipsis" },
    { GUI_F_SELECTABLE, "selectable" }, { GUI_F_RIGHT, "right" },
};

const char *gui_style_name(enum gui_style s)
{
    return s < GS_COUNT ? k_style[s] : "?";
}

struct dump { char *buf; size_t cap, len; };

static void emit(struct dump *d, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void emit(struct dump *d, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (d->len < d->cap) {
        int n = vsnprintf(d->buf + d->len, d->cap - d->len, fmt, ap);
        if (n > 0) d->len += (size_t)n;
    }
    va_end(ap);
}

/* Kind, id, direction, input kind, style and the numeric attributes. */
static void dump_layout_attrs(struct dump *d, const struct gui_node *n)
{
    if (n->kind == GUI_BOX || n->kind == GUI_DIALOG) emit(d, " dir=%s", n->dir == GUI_ROW ? "row" : "col");
    if (n->kind == GUI_INPUT) emit(d, " input=%s max=%u", k_ikind[n->ikind], n->max_bytes);
    emit(d, " style=%s", gui_style_name(n->style));
    if (n->gap) emit(d, " gap=%d", n->gap);
    if (n->pad) emit(d, " pad=%d", n->pad);
    if (n->w) emit(d, " w=%d", n->w);
    if (n->h) emit(d, " h=%d", n->h);
    if (n->grow) emit(d, " grow=%d", n->grow);
    if (n->align) emit(d, " align=%s", k_align[n->align]);
}

/* Flags, bindings, columns and text. */
static void dump_content_attrs(struct dump *d, const struct gui_tree *t, const struct gui_node *n)
{
    for (size_t k = 0; k < sizeof(k_flags) / sizeof(k_flags[0]); k++)
        if (n->flags & k_flags[k].f) emit(d, " %s", k_flags[k].n);
    if (n->bind[0]) emit(d, " bind=%s", n->bind);
    if (n->action[0]) emit(d, " action=%s", n->action);
    for (uint8_t c = 0; c < n->ncols; c++)
        emit(d, " col=%s/%d%s%s", n->cols[c].label, n->cols[c].width, n->cols[c].right ? "r" : "",
             n->cols[c].sortable ? "s" : "");
    if (n->text_len) emit(d, " \"%s\"", gui_tree_text(t, n));
}

static void dump_node(const struct gui_tree *t, uint16_t i, struct dump *d)
{
    const struct gui_node *n = &t->nodes[i];
    emit(d, "%*s%s", n->depth * 2, "", k_kind[n->kind]);
    if (n->id[0]) emit(d, "#%s", n->id);
    dump_layout_attrs(d, n);
    dump_content_attrs(d, t, n);
    emit(d, "\n");
    for (uint16_t c = n->first; c != GUI_NONE; c = t->nodes[c].next) dump_node(t, c, d);
}

size_t gui_tree_dump(const struct gui_tree *t, char *buf, size_t cap)
{
    struct dump d = { buf, cap, 0 };
    if (cap) buf[0] = 0;
    if (t->root != GUI_NONE) dump_node(t, t->root, &d);
    if (cap) buf[d.len < cap ? d.len : cap - 1] = 0;
    return d.len;
}

/* ---- bound data ------------------------------------------------------ */

static int data_find(const struct gui_data *d, const char *key)
{
    for (size_t i = 0; i < d->n; i++)
        if (!strcmp(d->e[i].key, key)) return (int)i;
    return -1;
}

static bool data_compact(struct gui_data *d)
{
    char *np = zcl_malloc(GUI_DATA_BYTES, "gui_data_compact");
    if (!np) return false;
    uint32_t used = 0;
    for (size_t i = 0; i < d->n; i++) {
        memcpy(np + used, d->pool + d->e[i].off, (size_t)d->e[i].len + 1u);
        d->e[i].off = used;
        d->e[i].cap = d->e[i].len;
        used += d->e[i].len + 1u;
    }
    free(d->pool);
    d->pool = np;
    d->used = used;
    return true;
}

/* Append an empty entry for key; -1 (and no change) when the table or the pool is
 * full. The pool is checked before the terminator byte is written, so used can
 * never pass GUI_DATA_BYTES; compaction first reclaims dead slack. */
static int data_add_key(struct gui_data *d, const char *key)
{
    if (d->n >= GUI_DATA_KEYS) {
        fprintf(stderr, "gui: data table full, dropping key %s\n", key);
        return -1;
    }
    if (d->used + 1u > GUI_DATA_BYTES && !data_compact(d)) return -1;
    if (d->used + 1u > GUI_DATA_BYTES) {
        fprintf(stderr, "gui: data pool full, dropping key %s\n", key);
        return -1;
    }
    int at = (int)d->n++;
    snprintf(d->e[at].key, sizeof(d->e[at].key), "%s", key);
    d->e[at].len = 0;
    d->e[at].cap = 0;
    d->pool[d->used] = 0;
    d->e[at].off = d->used;
    d->used += 1;
    return at;
}

bool gui_ui_set(struct gui_ui *ui, const char *key, const char *value)
{
    struct gui_data *d = &ui->data;
    size_t len = value ? strlen(value) : 0;
    if (!key || strlen(key) >= GUI_ID_MAX || len > 4096) return false;
    int at = data_find(d, key);
    if (at >= 0 && d->e[at].len == len && !memcmp(d->pool + d->e[at].off, value, len))
        return false;
    if (at < 0 && (at = data_add_key(d, key)) < 0) return false;
    if (len > d->e[at].cap) {
        if (d->used + len + 1 > GUI_DATA_BYTES) {
            d->e[at].len = 0;
            if (!data_compact(d) || d->used + len + 1 > GUI_DATA_BYTES) {
                fprintf(stderr, "gui: data pool full, dropping key %s\n", key);
                return false;
            }
        }
        d->e[at].off = d->used;
        d->e[at].cap = (uint16_t)len;
        d->used += (uint32_t)len + 1u;
    }
    if (len) memcpy(d->pool + d->e[at].off, value, len);
    d->pool[d->e[at].off + len] = 0;
    d->e[at].len = (uint16_t)len;
    ui->layout_dirty = true;
    return true;
}

const char *gui_ui_get(const struct gui_ui *ui, const char *key)
{
    int at = key ? data_find(&ui->data, key) : -1;
    return at < 0 ? "" : ui->data.pool + ui->data.e[at].off;
}
