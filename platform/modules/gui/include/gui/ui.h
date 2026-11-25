/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the retained widget tree (THE document model), its builder,
 * layout, painting and input. Screens are built in C against this API; the
 * later markup parser produces exactly the same tree (compare gui_tree_dump).
 * Limits match the future parser: 1024 nodes, depth 16, 64 KiB of text. */
#ifndef ZCL_GUI_UI_H
#define ZCL_GUI_UI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gui/draw.h"
#include "gui/window.h"

#define GUI_MAX_NODES 1024u
#define GUI_MAX_DEPTH 16u
#define GUI_TEXT_ARENA 65536u
#define GUI_ID_MAX 32u
#define GUI_MAX_COLS 8u
#define GUI_DATA_KEYS 256u
#define GUI_DATA_BYTES 32768u
#define GUI_MIN_TEXT_PX 13
#define GUI_MAX_INPUTS 32u /* live text fields (Send alone has seven) */

enum gui_kind {
    GUI_BOX, GUI_TEXT, GUI_BUTTON, GUI_INPUT, GUI_TABLE, GUI_PROGRESS,
    GUI_QR,   /* reserved: M2 */
    GUI_TABS, /* reserved: nav rail is built from buttons in M1 */
    GUI_SPACER, GUI_DIALOG,
    GUI_MENU  /* reserved: context menus land with the Activity screen */
};

/* Closed style vocabulary; markup may only name these tokens. */
enum gui_style {
    GS_SCREEN, GS_CARD, GS_CARD_WARN, GS_TITLE, GS_BODY, GS_MUTED, GS_HERO,
    GS_AMOUNT, GS_BADGE_PRIVATE, GS_BADGE_PUBLIC, GS_BADGE_DANGER, GS_BUTTON,
    GS_BUTTON_PRIMARY, GS_BUTTON_DANGER, GS_INPUT, GS_TABLE, GS_NAV,
    GS_NAV_ACTIVE, GS_STATUS, GS_TOAST, GS_DIALOG,
    /* ZclWallet beta13 parity tokens (visual_spec sections 1-4). */
    GS_RAIL, GS_NAV_ITEM, GS_NAV_ITEM_ACTIVE, GS_NAV_ADV, GS_NAV_ADV_ACTIVE,
    GS_PAGE, GS_GROUP, GS_GROUP_TITLE, GS_HERO_CARD, GS_HERO_CAPTION,
    GS_HERO_AMOUNT_OK, GS_HERO_AMOUNT_WARM, GS_HERO_TOTAL, GS_HERO_NOTE,
    GS_BUTTON_SECONDARY, GS_BUTTON_AMBER, GS_CARD_AMBER, GS_AMBER_TEXT,
    GS_PILL_PRIVATE, GS_PILL_PUBLIC, GS_PILL_DESHIELD, GS_AMOUNT_MONO,
    GS_SYNC_PILL, GS_BANNER_CONNECTING, GS_BANNER_SYNCING, GS_BANNER_INFO,
    GS_BANNER_TEXT, GS_MENUBAR, GS_MENUBAR_ITEM, GS_MENU_POPUP, GS_MENU_ITEM,
    GS_STATUSBAR, GS_STATUS_LABEL, GS_STATUS_MSG, GS_ICON_OK, GS_ICON_WARN,
    GS_ICON_CRIT, GS_WARN_TEXT,
    /* Send: address and amount borders (visual_spec: valid #34c759, invalid #c0392b). */
    GS_INPUT_VALID, GS_INPUT_INVALID,
    GS_COUNT
};

enum gui_dir { GUI_COL, GUI_ROW };
enum gui_align { GUI_ALIGN_STRETCH, GUI_ALIGN_START, GUI_ALIGN_CENTER,
                 GUI_ALIGN_END }; /* stretch is the default */
enum gui_input_kind { GUI_IN_TEXT, GUI_IN_AMOUNT, GUI_IN_ADDRESS, GUI_IN_MEMO,
                      GUI_IN_SECRET };

enum {
    GUI_F_SCROLL_Y = 1u << 0, GUI_F_FOCUSABLE = 1u << 1,
    GUI_F_DISABLED = 1u << 2, GUI_F_HIDDEN = 1u << 3, GUI_F_DEFAULT = 1u << 4,
    GUI_F_SECRET = 1u << 5, GUI_F_MULTILINE = 1u << 6, GUI_F_WRAP = 1u << 7,
    GUI_F_ELLIPSIS = 1u << 8, GUI_F_SELECTABLE = 1u << 9,
    GUI_F_RIGHT = 1u << 10 /* right-align text inside its box */
};

enum gui_attr { GUI_A_GAP, GUI_A_PAD, GUI_A_W, GUI_A_H, GUI_A_GROW,
                GUI_A_ALIGN };

#define GUI_COL_FIT (-1) /* gui_column.width: as wide as its header and cells */
struct gui_column {
    const char *label;
    int32_t width; /* logical px; 0 = grow; < 0 = fit header and first rows, at least -width */
    bool right, sortable;
};

struct gui_node {
    enum gui_kind kind;
    uint16_t parent, first, next, last;
    char id[GUI_ID_MAX];
    enum gui_style style;
    enum gui_dir dir;
    enum gui_align align;
    int16_t gap, pad, w, h, grow;
    uint16_t flags;
    uint32_t text_off;
    uint16_t text_len;
    char action[GUI_ID_MAX];
    char bind[GUI_ID_MAX];
    enum gui_input_kind ikind;
    uint16_t max_bytes;
    uint8_t ncols;
    struct gui_column cols[GUI_MAX_COLS];
    char col_labels[GUI_MAX_COLS][24];
    struct gui_rect frame; /* computed, physical px */
    int32_t nat_w, nat_h;
    uint8_t depth;
};

#define GUI_NONE 0xFFFFu

struct gui_tree {
    struct gui_node *nodes;
    uint16_t count, root, cur;
    uint8_t depth;
    char *text;
    uint32_t text_used;
    char error[96];
};

struct gui_tree *gui_tree_new(void);
void gui_tree_free(struct gui_tree *t);
void gui_tree_begin(struct gui_tree *t);
bool gui_tree_end(struct gui_tree *t, char *err, size_t cap);

/* One builder call per markup element; after the first overflow every call
 * is a no-op and gui_tree_end reports the error. */
void gui_box(struct gui_tree *t, const char *id, enum gui_dir dir,
             enum gui_style style);
void gui_end(struct gui_tree *t);
void gui_text(struct gui_tree *t, const char *id, enum gui_style style,
              const char *utf8);
void gui_text_bind(struct gui_tree *t, const char *id, enum gui_style style,
                   const char *bind);
void gui_button(struct gui_tree *t, const char *id, enum gui_style style,
                const char *label, const char *action);
void gui_input(struct gui_tree *t, const char *id, enum gui_input_kind kind,
               const char *bind, const char *placeholder, uint16_t max_bytes);
void gui_table(struct gui_tree *t, const char *id, const char *bind,
               const struct gui_column *cols, size_t n);
void gui_progress(struct gui_tree *t, const char *id, const char *bind);
void gui_spacer(struct gui_tree *t, int16_t grow);
void gui_dialog(struct gui_tree *t, const char *id, const char *title,
                const char *cancel_action);
void gui_attr(struct gui_tree *t, enum gui_attr a, int32_t v);
void gui_flag(struct gui_tree *t, uint16_t f);
const char *gui_tree_text(const struct gui_tree *t, const struct gui_node *n);
int gui_tree_find(const struct gui_tree *t, const char *id);

/* Canonical indented text, the equivalence oracle for the markup parser. */
size_t gui_tree_dump(const struct gui_tree *t, char *buf, size_t cap);

/* Key to UTF-8 value table. */
struct gui_data {
    struct { char key[GUI_ID_MAX]; uint32_t off; uint16_t len, cap; } e[GUI_DATA_KEYS];
    size_t n;
    char *pool;
    uint32_t used;
};

/* Virtual table rows: cell() is only called for visible rows. */
struct gui_table_source {
    const char *name;
    size_t (*rows)(void *ctx);
    bool (*cell)(void *ctx, size_t row, size_t col, char *buf, size_t cap,
                 enum gui_style *style);
    void (*sort)(void *ctx, size_t col, bool desc);
    void *ctx;
};

struct gui_action {
    char name[GUI_ID_MAX];
    char node_id[GUI_ID_MAX];
    int64_t row; /* table row, else -1 */
};

enum gui_edit_kind { GUI_EDIT_NONE, GUI_EDIT_INSERT, GUI_EDIT_BACKSPACE };

struct gui_input_state {
    char id[GUI_ID_MAX];
    char *buf; /* max_bytes + 1, cleansed on clear and free */
    size_t cap, len, caret, anchor;
    int32_t scroll_x;
};

struct gui_table_state {
    char id[GUI_ID_MAX];
    int64_t scroll, selected;
    int32_t sort_col;
    bool sort_desc;
    int64_t wheel_milli; /* leftover thousandths of a row */
};

struct gui_ui {
    struct gui_tree *tree;
    struct gui_data data;
    struct gui_input_state inputs[GUI_MAX_INPUTS];
    struct gui_table_state tables_st[4];
    const struct gui_table_source *sources[4];
    char focus[GUI_ID_MAX], hover[GUI_ID_MAX], pressed[GUI_ID_MAX];
    bool kbd_focus, caret_on, win_focused;
    float scale;
    int32_t w, h;
    bool layout_dirty;
    struct gui_rect dirty[8];
    size_t ndirty;
    struct gui_window *win;
    char toast[96];
    uint64_t toast_until_ns;
    int32_t last_mx, last_my;
};

struct gui_ui *gui_ui_new(struct gui_tree *tree);
void gui_ui_free(struct gui_ui *ui);
void gui_ui_set_window(struct gui_ui *ui, struct gui_window *w);
void gui_ui_set_scale(struct gui_ui *ui, float scale);
/* Binding: returns true if the stored value changed (marks layout dirty). */
bool gui_ui_set(struct gui_ui *ui, const char *key, const char *value);
const char *gui_ui_get(const struct gui_ui *ui, const char *key);
void gui_ui_table_source(struct gui_ui *ui, const struct gui_table_source *s);
/* A rebuilt tree keeps focus, input buffers, scroll and selection by id. */
void gui_ui_rebind(struct gui_ui *ui);
void gui_ui_layout(struct gui_ui *ui, int32_t w, int32_t h);
void gui_ui_paint(struct gui_ui *ui, struct gui_surface *s,
                  const struct gui_rect *dirty, size_t n);
bool gui_ui_event(struct gui_ui *ui, const struct gui_event *ev,
                  struct gui_action *out);
size_t gui_ui_take_dirty(struct gui_ui *ui, struct gui_rect *out, size_t cap);
void gui_ui_toast(struct gui_ui *ui, const char *utf8, uint32_t ms);
/* Called by the app on a timer; returns true if toast state changed. */
bool gui_ui_tick(struct gui_ui *ui);
void gui_ui_blink(struct gui_ui *ui);
bool gui_ui_wants_blink(const struct gui_ui *ui);
enum gui_cursor gui_ui_cursor(const struct gui_ui *ui);
bool gui_ui_input_text(const struct gui_ui *ui, const char *id, char *buf,
                       size_t cap);
void gui_ui_input_set(struct gui_ui *ui, const char *id, const char *utf8);
void gui_ui_input_clear(struct gui_ui *ui, const char *id);
void gui_ui_focus(struct gui_ui *ui, const char *id);

/* Theme. */
struct gui_theme_entry {
    uint32_t fg, bg, border;
    int32_t radius, text_px; /* logical */
    enum gui_font font;
};
const struct gui_theme_entry *gui_theme(enum gui_style s);
const char *gui_style_name(enum gui_style s);
/* WCAG relative-luminance contrast ratio, scaled by 100. */
int32_t gui_contrast_x100(uint32_t a, uint32_t b);

/* Internals shared between the ui_*.c files. */
void gui_ui_mark_rect(struct gui_ui *ui, struct gui_rect r);
void gui_ui_mark_node(struct gui_ui *ui, const char *id);
int32_t gui_px(const struct gui_ui *ui, int32_t logical);
struct gui_input_state *gui_ui_input_find(struct gui_ui *ui, const char *id,
                                          bool create, size_t cap);
struct gui_table_state *gui_ui_table_find(struct gui_ui *ui, const char *id);
const struct gui_table_source *gui_ui_source(const struct gui_ui *ui,
                                             const char *name);
bool gui_ui_text_key(struct gui_ui *ui, const struct gui_event *ev,
                     struct gui_node *n);
bool gui_ui_text_insert(struct gui_ui *ui, struct gui_node *n, uint32_t cp);
bool gui_ui_table_key(struct gui_ui *ui, struct gui_node *n,
                      const struct gui_event *ev, struct gui_action *out);
void gui_ui_table_wheel(struct gui_ui *ui, struct gui_node *n, float dy);
bool gui_ui_table_click(struct gui_ui *ui, struct gui_node *n, int32_t x,
                        int32_t y, struct gui_action *out);
void gui_ui_table_paint(struct gui_ui *ui, struct gui_surface *s,
                        struct gui_node *n);
void gui_ui_input_paint(struct gui_ui *ui, struct gui_surface *s,
                        struct gui_node *n);
void gui_ui_input_click(struct gui_ui *ui, struct gui_node *n, int32_t x,
                        bool extend);
int32_t gui_ui_text_px(const struct gui_ui *ui, enum gui_style st);
size_t gui_wrap_line(enum gui_font f, int32_t px, const char *s, size_t len,
                     int32_t max_w);

#endif
