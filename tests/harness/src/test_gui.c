/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: gui group. UTF-8, drawing, text, the widget tree and its layout,
 * focus/dialog/text-field/table behaviour, the window event ring and timers,
 * the headless script runner, theme contrast and the golden gallery. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gui/draw.h"
#include "gui/ui.h"
#include "gui/window.h"

static int g_fail;
#define CHECK(name, cond) \
    do { \
        bool ok_ = (cond); \
        printf("  %s... %s\n", (name), ok_ ? "OK" : "FAIL"); \
        if (!ok_) g_fail++; \
    } while (0)

static struct gui_window *open_headless(int32_t w, int32_t h)
{
    struct gui_window_desc d = { .title_utf8 = "t", .width = w, .height = h,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_HEADLESS };
    struct gui_window *win = NULL;
    char err[96];
    if (!gui_window_open(&d, &win, err, sizeof(err))) printf("  open failed: %s\n", err);
    return win;
}

static void test_utf8(void)
{
    size_t i = 0;
    const char *s = "A\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80";
    CHECK("utf8 decodes 1-4 byte scalars",
          gui_utf8_next(s, 10, &i) == 'A' && gui_utf8_next(s, 10, &i) == 0xE9 &&
          gui_utf8_next(s, 10, &i) == 0x20AC && gui_utf8_next(s, 10, &i) == 0x1F600 && i == 10);
    i = 0;
    CHECK("overlong C0 80 is U+FFFD one byte at a time",
          gui_utf8_next("\xC0\x80", 2, &i) == 0xFFFD && i == 1);
    i = 0;
    CHECK("surrogate ED A0 80 is U+FFFD", gui_utf8_next("\xED\xA0\x80", 3, &i) == 0xFFFD && i == 1);
    i = 0;
    CHECK("truncated sequence is U+FFFD", gui_utf8_next("\xE2\x82", 2, &i) == 0xFFFD && i == 1);
    char out[4];
    CHECK("encode round trip", gui_utf8_encode(0x20AC, out) == 3 && (unsigned char)out[0] == 0xE2);
    CHECK("prev steps over multibyte", gui_utf8_prev(s, 10, 10) == 6 && gui_utf8_prev(s, 10, 6) == 3 &&
          gui_utf8_prev(s, 10, 0) == 0);
    CHECK("valid and invalid text", gui_utf8_valid(s, 10) && !gui_utf8_valid("\xFF", 1));
}

static void test_draw(void)
{
    uint32_t px[10 * 10];
    memset(px, 0, sizeof(px));
    struct gui_surface s = { .px = px, .w = 10, .h = 10, .stride = 10, .clip = { 0, 0, 10, 10 } };
    gui_fill_rect(&s, (struct gui_rect){ -5, -5, 8, 8 }, 0xFFFFFF);
    CHECK("fill clips at the top-left edge", px[0] == 0xFFFFFF && px[2 * 10 + 2] == 0xFFFFFF && px[3 * 10 + 3] == 0);
    gui_fill_rect(&s, (struct gui_rect){ 8, 8, 100, 100 }, 0x112233);
    CHECK("fill clips at the bottom-right edge", px[9 * 10 + 9] == 0x112233);
    uint32_t before = px[5 * 10 + 5];
    gui_fill_rect(&s, (struct gui_rect){ 5, 5, 0, 4 }, 0x1);
    gui_fill_rect(&s, (struct gui_rect){ 5, 5, -3, 4 }, 0x1);
    CHECK("zero and negative sizes draw nothing", px[5 * 10 + 5] == before);
    gui_clip_push(&s, (struct gui_rect){ 0, 0, 2, 2 });
    gui_fill_rect(&s, (struct gui_rect){ 0, 0, 10, 10 }, 0xABCDEF);
    gui_clip_pop(&s);
    CHECK("clip push limits drawing and pop restores", px[1 * 10 + 1] == 0xABCDEF && px[5 * 10 + 5] != 0xABCDEF &&
          s.clip.w == 10);
    gui_fill_rect_blend(&s, (struct gui_rect){ 6, 0, 2, 2 }, 0xFFFFFF, 128);
    CHECK("blend mixes", (px[6] & 255u) > 100 && (px[6] & 255u) < 160);
    uint32_t big[40 * 40] = { 0 };
    struct gui_surface b = { .px = big, .w = 40, .h = 40, .stride = 40, .clip = { 0, 0, 40, 40 } };
    gui_fill_round_rect(&b, (struct gui_rect){ 0, 0, 40, 40 }, 12, 0xFFFFFF);
    CHECK("round rect leaves the corner empty and the centre full", big[0] == 0 && big[20 * 40 + 20] == 0xFFFFFF);
}

static void test_text(void)
{
    int32_t w16 = gui_text_width(GUI_FONT_TEXT, 16, "Hello", 5);
    CHECK("text width is positive and repeatable", w16 > 20 && w16 == gui_text_width(GUI_FONT_TEXT, 16, "Hello", 5));
    CHECK("strong is not narrower than text", gui_text_width(GUI_FONT_STRONG, 16, "Hello", 5) >= w16 - 1);
    size_t fit = gui_text_fit(GUI_FONT_TEXT, 16, "Hello world", 11, w16);
    CHECK("fit returns the bytes that fit", fit == 5 || fit == 4 || fit == 5);
    CHECK("index_at_x maps the far left and right",
          gui_text_index_at_x(GUI_FONT_TEXT, 16, "Hello", 5, -4) == 0 &&
          gui_text_index_at_x(GUI_FONT_TEXT, 16, "Hello", 5, 9999) == 5);
    uint32_t a[200 * 40] = { 0 }, c[200 * 40] = { 0 };
    struct gui_surface sa = { .px = a, .w = 200, .h = 40, .stride = 200, .clip = { 0, 0, 200, 40 } };
    struct gui_surface sc = sa;
    sc.px = c;
    gui_text_draw(&sa, GUI_FONT_TEXT, 20, 4, 28, "Cache me 123", 12, 0xFFFFFF);
    gui_text_cache_reset();
    gui_text_draw(&sc, GUI_FONT_TEXT, 20, 4, 28, "Cache me 123", 12, 0xFFFFFF);
    CHECK("cache reset leaves the pixels identical", memcmp(a, c, sizeof(a)) == 0);
    uint32_t d[200 * 40] = { 0 };
    sa.px = d;
    for (int32_t px = 5; px < 120; px++) gui_text_draw(&sa, GUI_FONT_TEXT, px, 0, 30, "abcXYZ09", 8, 1);
    CHECK("many sizes force an eviction without a crash", gui_text_cache_resets() >= 1);
}

static void test_tree(void)
{
    struct gui_tree *t = gui_tree_new();
    char err[96];
    for (int i = 0; i < 1025; i++) {
        char id[16];
        snprintf(id, sizeof(id), "n%d", i);
        if (i == 0) gui_box(t, "root", GUI_COL, GS_SCREEN);
        gui_text(t, id, GS_BODY, "x");
    }
    gui_end(t);
    CHECK("node 1025 fails cleanly", !gui_tree_end(t, err, sizeof(err)) && strstr(err, "too many nodes"));
    gui_tree_begin(t);
    for (int i = 0; i < 17; i++) gui_box(t, "", GUI_COL, GS_BODY);
    CHECK("depth 17 fails cleanly", !gui_tree_end(t, err, sizeof(err)) && strstr(err, "too deep"));
    gui_tree_begin(t);
    gui_box(t, "root", GUI_COL, GS_SCREEN);
    char big[4096];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = 0;
    for (int i = 0; i < 20; i++) gui_text(t, "", GS_BODY, big);
    gui_end(t);
    CHECK("text arena overflow fails cleanly", !gui_tree_end(t, err, sizeof(err)) && strstr(err, "arena"));
    gui_tree_begin(t);
    gui_box(t, "home", GUI_COL, GS_SCREEN);
    gui_attr(t, GUI_A_GAP, 12);
    gui_text_bind(t, "hero", GS_HERO, "home.private");
    gui_button(t, "go", GS_BUTTON_PRIMARY, "Go", "home.refresh");
    gui_end(t);
    char dump[512];
    gui_tree_dump(t, dump, sizeof(dump));
    CHECK("dump is canonical", gui_tree_end(t, err, sizeof(err)) &&
          !strcmp(dump, "box#home dir=col style=screen gap=12\n"
                        "  text#hero style=hero bind=home.private\n"
                        "  button#go style=button_primary action=home.refresh \"Go\"\n"));
    gui_tree_begin(t);
    gui_box(t, "r", GUI_COL, GS_SCREEN);
    gui_text(t, "same", GS_BODY, "a");
    gui_text(t, "same", GS_BODY, "b");
    gui_end(t);
    CHECK("duplicate ids are rejected", !gui_tree_end(t, err, sizeof(err)) && strstr(err, "duplicate"));
    gui_tree_free(t);
}

static void build_pair(struct gui_tree *t)
{
    gui_tree_begin(t);
    gui_box(t, "root", GUI_COL, GS_SCREEN);
    gui_attr(t, GUI_A_PAD, 10);
    gui_attr(t, GUI_A_GAP, 6);
    gui_box(t, "row", GUI_ROW, GS_BODY);
    gui_attr(t, GUI_A_GAP, 4);
    gui_box(t, "a", GUI_COL, GS_BODY);
    gui_attr(t, GUI_A_W, 100);
    gui_attr(t, GUI_A_H, 30);
    gui_end(t);
    gui_box(t, "b", GUI_COL, GS_BODY);
    gui_attr(t, GUI_A_GROW, 1);
    gui_attr(t, GUI_A_H, 30);
    gui_end(t);
    gui_end(t);
    gui_end(t);
    gui_tree_end(t, NULL, 0);
}

static void test_layout(void)
{
    struct gui_tree *t = gui_tree_new();
    struct gui_ui *ui = gui_ui_new(t);
    build_pair(t);
    static const float scales[] = { 1.0f, 1.25f, 1.5f, 2.0f, 3.0f };
    bool exact = true;
    for (size_t i = 0; i < 5; i++) {
        gui_ui_set_scale(ui, scales[i]);
        gui_ui_layout(ui, 800, 600);
        const struct gui_node *a = &t->nodes[gui_tree_find(t, "a")], *b = &t->nodes[gui_tree_find(t, "b")];
        int32_t pad = gui_px(ui, 10), gap = gui_px(ui, 4);
        exact = exact && a->frame.x == pad && a->frame.y == pad && a->frame.w == gui_px(ui, 100) &&
                a->frame.h == gui_px(ui, 30) && b->frame.x == pad + a->frame.w + gap &&
                b->frame.x + b->frame.w == 800 - pad;
    }
    CHECK("row frames are exact at scales 1.0 to 3.0", exact);
    gui_ui_free(ui);
    gui_tree_free(t);
}

static void key(struct gui_ui *ui, enum gui_key k, uint32_t mods, struct gui_action *act, bool *fired)
{
    struct gui_event e = { .type = GUI_EV_KEY, .mods = mods, .key = { k, 0, true, false } };
    *fired = gui_ui_event(ui, &e, act);
}

static void text_in(struct gui_ui *ui, const char *s)
{
    struct gui_action act;
    size_t i = 0, n = strlen(s);
    while (i < n) {
        struct gui_event e = { .type = GUI_EV_TEXT, .text = { gui_utf8_next(s, n, &i) } };
        gui_ui_event(ui, &e, &act);
    }
}

static void build_form(struct gui_tree *t, bool dialog)
{
    gui_tree_begin(t);
    gui_box(t, "root", GUI_COL, GS_SCREEN);
    gui_input(t, "amt", GUI_IN_AMOUNT, "form.amt", "0.0", 20);
    gui_input(t, "sec", GUI_IN_SECRET, "", "secret", 32);
    gui_button(t, "b1", GS_BUTTON, "One", "act.one");
    gui_button(t, "b2", GS_BUTTON, "Two", "act.two");
    if (dialog) {
        gui_dialog(t, "dlg", "Confirm", "dlg.cancel");
        gui_text(t, "msg", GS_BODY, "Sure?");
        gui_button(t, "d_cancel", GS_BUTTON, "Cancel", "dlg.cancel");
        gui_flag(t, GUI_F_DEFAULT);
        gui_button(t, "d_ok", GS_BUTTON_DANGER, "Send", "dlg.ok");
        gui_end(t);
    }
    gui_end(t);
    gui_tree_end(t, NULL, 0);
}

static void test_focus_and_fields(void)
{
    struct gui_tree *t = gui_tree_new();
    struct gui_ui *ui = gui_ui_new(t);
    struct gui_action act;
    bool fired;
    build_form(t, false);
    gui_ui_layout(ui, 600, 400);
    key(ui, GUI_KEY_TAB, 0, &act, &fired);
    CHECK("Tab focuses the first focusable in tree order", !strcmp(ui->focus, "amt"));
    key(ui, GUI_KEY_TAB, 0, &act, &fired);
    key(ui, GUI_KEY_TAB, 0, &act, &fired);
    CHECK("Tab walks in order", !strcmp(ui->focus, "b1"));
    key(ui, GUI_KEY_TAB, GUI_MOD_SHIFT, &act, &fired);
    CHECK("Shift-Tab goes back", !strcmp(ui->focus, "sec"));
    key(ui, GUI_KEY_TAB, 0, &act, &fired);
    key(ui, GUI_KEY_ENTER, 0, &act, &fired);
    CHECK("Enter activates the focused button", fired && !strcmp(act.name, "act.one"));
    key(ui, GUI_KEY_TAB, 0, &act, &fired);
    key(ui, GUI_KEY_SPACE, 0, &act, &fired);
    CHECK("Space activates the focused button", fired && !strcmp(act.name, "act.two"));
    gui_ui_focus(ui, "amt");
    text_in(ui, "12.345678901");
    char buf[64];
    gui_ui_input_text(ui, "amt", buf, sizeof(buf));
    CHECK("AMOUNT refuses a 9th decimal", !strcmp(buf, "12.34567890"));
    text_in(ui, ".");
    gui_ui_input_text(ui, "amt", buf, sizeof(buf));
    CHECK("AMOUNT refuses a second dot", !strcmp(buf, "12.34567890"));
    CHECK("bound data follows the field", !strcmp(gui_ui_get(ui, "form.amt"), "12.34567890"));
    gui_ui_input_clear(ui, "amt");
    gui_ui_focus(ui, "amt");
    text_in(ui, "A\xC3\xA9");
    gui_ui_input_text(ui, "amt", buf, sizeof(buf));
    CHECK("AMOUNT refuses letters", buf[0] == 0);
    struct gui_window *cw = open_headless(100, 100);
    gui_ui_set_window(ui, cw);
    gui_clipboard_set_text(cw, "sentinel", 8);
    gui_ui_focus(ui, "sec");
    text_in(ui, "p\xC3\xA9ss");
    key(ui, GUI_KEY_BACKSPACE, 0, &act, &fired);
    key(ui, GUI_KEY_LEFT, 0, &act, &fired);
    key(ui, GUI_KEY_BACKSPACE, 0, &act, &fired);
    gui_ui_input_text(ui, "sec", buf, sizeof(buf));
    CHECK("multibyte backspace removes whole characters", !strcmp(buf, "ps"));
    key(ui, GUI_KEY_A, GUI_MOD_CTRL, &act, &fired);
    key(ui, GUI_KEY_C, GUI_MOD_CTRL, &act, &fired);
    char clipb[16];
    gui_clipboard_get_text(cw, clipb, sizeof(clipb));
    CHECK("SECRET refuses copy", !strcmp(clipb, "sentinel"));
    gui_ui_input_clear(ui, "sec");
    bool zero = true;
    for (size_t i = 0; i < 8; i++)
        if (ui->inputs[i].buf && !strcmp(ui->inputs[i].id, "sec"))
            for (size_t k = 0; k < ui->inputs[i].cap; k++) zero = zero && ui->inputs[i].buf[k] == 0;
    CHECK("SECRET buffer is all zero after clear", zero);
    build_form(t, true);
    gui_ui_rebind(ui);
    gui_ui_layout(ui, 600, 400);
    gui_ui_focus(ui, "b1");
    key(ui, GUI_KEY_TAB, 0, &act, &fired);
    CHECK("a dialog traps focus", !strncmp(ui->focus, "d_", 2));
    key(ui, GUI_KEY_ENTER, 0, &act, &fired);
    CHECK("Enter hits the DEFAULT button (Cancel)", fired && !strcmp(act.name, "dlg.cancel"));
    key(ui, GUI_KEY_ESCAPE, 0, &act, &fired);
    CHECK("Esc fires the dialog cancel", fired && !strcmp(act.name, "dlg.cancel"));
    gui_ui_free(ui);
    gui_tree_free(t);
    gui_window_close(cw);
}

static size_t g_rows_calls, g_cells_calls;
static size_t src_rows(void *c) { (void)c; g_rows_calls++; return 10000; }
static bool src_cell(void *c, size_t r, size_t col, char *b, size_t cap, enum gui_style *st)
{
    (void)c; (void)st;
    g_cells_calls++;
    snprintf(b, cap, "r%zu c%zu", r, col);
    return true;
}
static size_t g_sorted_col = 99;
static void src_sort(void *c, size_t col, bool desc) { (void)c; (void)desc; g_sorted_col = col; }

static void test_wheel_notch(void)
{
    struct gui_tree *t = gui_tree_new();
    struct gui_ui *ui = gui_ui_new(t);
    static const struct gui_table_source src = { "tx", src_rows, src_cell, src_sort, NULL };
    struct gui_column cols[2] = { { "A", 0, false, true }, { "B", 120, true, false } };
    struct gui_event w = { .type = GUI_EV_MOUSE_WHEEL, .wheel = { 100, 100, 0, 0 } };
    struct gui_action act;
    int64_t moved;
    CHECK("a mouse line stays one notch", gui_wheel_notch(1.0f, false) == 1.0f);
    CHECK("ten precise pixels are one notch", gui_wheel_notch(10.0f, true) == 1.0f);
    CHECK("precise direction stays signed", gui_wheel_notch(-10.0f, true) == -1.0f);
    gui_ui_table_source(ui, &src);
    gui_tree_begin(t);
    gui_box(t, "root", GUI_COL, GS_SCREEN);
    gui_table(t, "tbl", "tx", cols, 2);
    gui_attr(t, GUI_A_H, 200);
    gui_end(t);
    gui_tree_end(t, NULL, 0);
    gui_ui_layout(ui, 500, 400);
    w.wheel.dy = -gui_wheel_notch(30.0f, true);
    gui_ui_event(ui, &w, &act);
    moved = gui_ui_table_find(ui, "tbl")->scroll;
    if (moved != 9) printf("  precise flick moved %lld rows\n", (long long)moved);
    CHECK("one precise flick scrolls nine rows", moved == 9);
    gui_ui_free(ui);
    gui_tree_free(t);
}

static void test_wheel_small(void)
{
    struct gui_tree *t = gui_tree_new();
    struct gui_ui *ui = gui_ui_new(t);
    static const struct gui_table_source src = { "tx", src_rows, src_cell, src_sort, NULL };
    struct gui_column cols[2] = { { "A", 0, false, true }, { "B", 120, true, false } };
    struct gui_event w = { .type = GUI_EV_MOUSE_WHEEL, .wheel = { 100, 100, 0, 0 } };
    struct gui_action act;
    int64_t moved;
    int i;
    gui_ui_table_source(ui, &src);
    gui_tree_begin(t);
    gui_box(t, "root", GUI_COL, GS_SCREEN);
    gui_table(t, "tbl", "tx", cols, 2);
    gui_attr(t, GUI_A_H, 200);
    gui_end(t);
    gui_tree_end(t, NULL, 0);
    gui_ui_layout(ui, 500, 400);
    w.wheel.dy = -gui_wheel_notch(2.5f, true);
    gui_ui_event(ui, &w, &act);
    CHECK("one small precise step stays put", gui_ui_table_find(ui, "tbl")->scroll == 0);
    for (i = 0; i < 3; i++) gui_ui_event(ui, &w, &act);
    moved = gui_ui_table_find(ui, "tbl")->scroll;
    if (moved != 3) printf("  small precise steps moved %lld rows\n", (long long)moved);
    CHECK("small precise steps add up to rows", moved == 3);
    gui_ui_free(ui);
    gui_tree_free(t);
}

static void test_table(void)
{
    struct gui_tree *t = gui_tree_new();
    struct gui_ui *ui = gui_ui_new(t);
    static const struct gui_table_source src = { "tx", src_rows, src_cell, src_sort, NULL };
    gui_ui_table_source(ui, &src);
    struct gui_column cols[2] = { { "A", 0, false, true }, { "B", 120, true, false } };
    gui_tree_begin(t);
    gui_box(t, "root", GUI_COL, GS_SCREEN);
    gui_table(t, "tbl", "tx", cols, 2);
    gui_attr(t, GUI_A_H, 200);
    gui_end(t);
    gui_tree_end(t, NULL, 0);
    gui_ui_layout(ui, 500, 400);
    uint32_t px[500 * 400];
    struct gui_surface s = { .px = px, .w = 500, .h = 400, .stride = 500, .clip = { 0, 0, 500, 400 } };
    g_cells_calls = 0;
    gui_ui_paint(ui, &s, NULL, 0);
    CHECK("only visible rows call cell()", g_cells_calls > 0 && g_cells_calls < 100);
    struct gui_event w = { .type = GUI_EV_MOUSE_WHEEL, .wheel = { 100, 100, 0, -10000.0f } };
    struct gui_action act;
    gui_ui_event(ui, &w, &act);
    CHECK("wheel clamps to the last page", gui_ui_table_find(ui, "tbl")->scroll < 10000 &&
          gui_ui_table_find(ui, "tbl")->scroll > 9900);
    w.wheel.dy = 5000.0f;
    gui_ui_event(ui, &w, &act);
    CHECK("wheel clamps at the top", gui_ui_table_find(ui, "tbl")->scroll == 0);
    const struct gui_node *n = &t->nodes[gui_tree_find(t, "tbl")];
    struct gui_event c = { .type = GUI_EV_MOUSE_BUTTON, .button = { n->frame.x + 20, n->frame.y + 5, 1, true, 1 } };
    gui_ui_event(ui, &c, &act);
    CHECK("header click sorts through the source", g_sorted_col == 0);
    gui_ui_free(ui);
    gui_tree_free(t);
}

static void *waker(void *p)
{
    gui_window_wake((struct gui_window *)p);
    return NULL;
}

static void test_resize_coalesce(void)
{
    struct gui_window *w = open_headless(200, 100);
    struct gui_event ev = { .type = GUI_EV_RESIZE };
    int i;
    int n = 0;
    int32_t last_w = 0;
    for (i = 0; i < 300; i++) {
        ev.size.w = 100 + i;
        ev.size.h = 80;
        gui_headless_inject(w, &ev);
    }
    while (gui_window_wait(w, 0, &ev) && ev.type == GUI_EV_RESIZE) {
        n++;
        last_w = ev.size.w;
    }
    CHECK("a full ring keeps the latest resize", n == 256 && last_w == 399);
    gui_window_close(w);
}

static void test_window_common(void)
{
    struct gui_window *w = open_headless(200, 100);
    struct gui_event ev = { .type = GUI_EV_MOUSE_MOVE };
    for (int i = 0; i < 1000; i++) {
        ev.move.x = i;
        gui_headless_inject(w, &ev);
    }
    int moves = 0;
    while (gui_window_wait(w, 0, &ev) && ev.type == GUI_EV_MOUSE_MOVE) moves++;
    CHECK("event ring coalesces moves when full", moves == 256);
    gui_window_timer_set(w, 2, 50, false);
    gui_window_timer_set(w, 1, 20, false);
    bool order = gui_window_wait(w, 100, &ev) && ev.type == GUI_EV_TIMER && ev.timer.id == 1 &&
                 gui_window_wait(w, 100, &ev) && ev.timer.id == 2;
    CHECK("timers fire in deadline order", order);
    gui_window_timer_set(w, 3, 10, true);
    int fires = 0;
    for (int i = 0; i < 3; i++) fires += gui_window_wait(w, 20, &ev) && ev.timer.id == 3;
    gui_window_timer_cancel(w, 3);
    CHECK("a repeating timer repeats and cancels", fires == 3 && !gui_window_wait(w, 30, &ev));
    pthread_t th;
    pthread_create(&th, NULL, waker, w);
    pthread_join(th, NULL);
    CHECK("wake from another thread yields GUI_EV_WAKE", gui_window_wait(w, 0, &ev) && ev.type == GUI_EV_WAKE);
    gui_window_close(w);
}

static void test_script_and_golden(void)
{
    struct gui_window *w = open_headless(300, 200);
    char err[96] = "";
    struct gui_script *bad = gui_headless_script_load("size 300 200\nbogus 1 2\n", 22, err, sizeof(err));
    CHECK("malformed script line reports its number", !bad && strstr(err, "line 2"));
    const char *good = "# comment\nsize 400 300\nscale 2\nclick 10 10\nclick 5 5 right\nwheel 5 5 -1\n"
                       "key tab shift\ntext \"h\xC3\xA9llo\"\npaste \"clip\"\nwait 5\nuntil-idle\nshot first\n";
    struct gui_script *s = gui_headless_script_load(good, strlen(good), err, sizeof(err));
    CHECK("every script command parses", s != NULL);
    int ran = 0, shots = 0, idles = 0;
    char name[32] = "";
    for (enum gui_script_step st; s && (st = gui_headless_script_step(w, s, name, sizeof(name))) != GUI_SCRIPT_DONE;) {
        ran++;
        shots += st == GUI_SCRIPT_SHOT && !strcmp(name, "first");
        idles += st == GUI_SCRIPT_IDLE;
        struct gui_event ev;
        while (gui_window_wait(w, 0, &ev)) { }
    }
    int32_t pw, ph;
    float sc;
    gui_window_size(w, &pw, &ph, &sc);
    CHECK("script runs to completion with a shot and idle", ran == 11 && shots == 1 && idles == 1 && pw == 400 && sc == 2.0f);
    char clip[16];
    CHECK("script paste fills the clipboard", gui_clipboard_get_text(w, clip, sizeof(clip)) == 4 && !strcmp(clip, "clip"));
    gui_headless_script_free(s);
    gui_window_close(w);
}

/* The checked-in gallery session (tests/fixtures/gui/scripts/gallery.txt) parses and
 * runs to completion on a headless window, ending in the named shot. */
static void test_gallery_script(void)
{
    FILE *f = fopen("tests/fixtures/gui/scripts/gallery.txt", "rb");
    static char text[4096];
    size_t n = f ? fread(text, 1, sizeof(text) - 1, f) : 0;
    if (f) fclose(f);
    char err[96] = "";
    struct gui_script *s = n ? gui_headless_script_load(text, n, err, sizeof(err)) : NULL;
    CHECK("the gallery script fixture loads", s != NULL);
    struct gui_window *w = open_headless(300, 200);
    int steps = 0, shots = 0;
    char name[32] = "";
    for (enum gui_script_step st; s && (st = gui_headless_script_step(w, s, name, sizeof(name))) != GUI_SCRIPT_DONE;) {
        steps++;
        shots += st == GUI_SCRIPT_SHOT && !strcmp(name, "gallery_session");
        struct gui_event ev;
        while (gui_window_wait(w, 0, &ev)) {
        }
    }
    int32_t pw = 0, ph = 0;
    gui_window_size(w, &pw, &ph, NULL);
    CHECK("the gallery script runs every step and ends in its shot", steps == 10 && shots == 1 && pw == 560 && ph == 480);
    gui_headless_script_free(s);
    gui_window_close(w);
}

static void test_theme(void)
{
    bool ok = true;
    for (int i = 0; i < GS_COUNT; i++) {
        const struct gui_theme_entry *e = gui_theme((enum gui_style)i);
        if (i == GS_SCREEN || i == GS_CARD_WARN || i == GS_CARD) {
            ok = ok && gui_contrast_x100(e->fg, e->bg) >= 450;
        } else if (i != GS_INPUT && e->fg != e->bg) {
            ok = ok && gui_contrast_x100(e->fg, e->bg) >= (e->text_px >= 24 ? 300 : 450);
        }
        ok = ok && e->text_px >= GUI_MIN_TEXT_PX - 0 * 1;
        if (!ok) printf("    contrast fail style %s\n", gui_style_name((enum gui_style)i));
    }
    CHECK("theme text contrast is at least 4.5:1 (3:1 for hero) and sizes >= 13", ok);
}

static void gallery_tree(struct gui_tree *t, bool dialog)
{
    static const struct gui_column cols[3] = { { "Name", 0, false, true }, { "Value", 100, true, true },
                                              { "State", 90, false, false } };
    gui_tree_begin(t);
    gui_box(t, "root", GUI_COL, GS_SCREEN);
    gui_attr(t, GUI_A_PAD, 14);
    gui_attr(t, GUI_A_GAP, 10);
    gui_text(t, "t1", GS_TITLE, "Widget gallery");
    gui_text(t, "t2", GS_MUTED, "Muted caption, 13 px minimum");
    gui_box(t, "r1", GUI_ROW, GS_CARD);
    gui_attr(t, GUI_A_PAD, 10);
    gui_attr(t, GUI_A_GAP, 8);
    gui_button(t, "b1", GS_BUTTON_PRIMARY, "Primary", "g.primary");
    gui_button(t, "b2", GS_BUTTON, "Normal", "g.normal");
    gui_button(t, "b3", GS_BUTTON_DANGER, "Danger", "g.danger");
    gui_button(t, "b4", GS_BUTTON, "Disabled", "g.off");
    gui_flag(t, GUI_F_DISABLED);
    gui_text(t, "badge", GS_BADGE_PRIVATE, "PRIVATE");
    gui_end(t);
    gui_input(t, "in", GUI_IN_TEXT, "", "Type here", 64);
    gui_progress(t, "pg", "gallery.progress");
    gui_table(t, "tbl", "gallery", cols, 3);
    gui_attr(t, GUI_A_H, 160);
    if (dialog) {
        gui_dialog(t, "dlg", "Send to a PUBLIC address?", "dlg.cancel");
        gui_text(t, "dm", GS_BODY, "This amount and recipient become visible forever.");
        gui_flag(t, GUI_F_WRAP);
        gui_box(t, "dr", GUI_ROW, GS_BODY);
        gui_attr(t, GUI_A_GAP, 8);
        gui_button(t, "dc", GS_BUTTON, "Cancel", "dlg.cancel");
        gui_flag(t, GUI_F_DEFAULT);
        gui_button(t, "dk", GS_BUTTON_DANGER, "Send anyway", "dlg.ok");
        gui_end(t);
        gui_end(t);
    }
    gui_end(t);
    gui_tree_end(t, NULL, 0);
}

static bool golden_check(const char *name, const struct gui_cpu_frame *f)
{
    uint8_t h[32];
    gui_frame_sha3(f, h);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", h[i]);
    char png[256];
    snprintf(png, sizeof(png), "build/test-artifacts/gui/%s.png", name);
    gui_frame_write_png(f, png);
    FILE *g = fopen("tests/fixtures/gui/golden.tsv", "r");
    char line[256], want[65] = "";
    while (g && fgets(line, sizeof(line), g)) {
        char n[64];
        int w, hh;
        char hx[80];
        if (sscanf(line, "%63[^\t]\t%d\t%d\t%79s", n, &w, &hh, hx) == 4 && !strcmp(n, name) &&
            w == f->width && hh == f->height) snprintf(want, sizeof(want), "%.64s", hx);
    }
    if (g) fclose(g);
    if (strcmp(want, hex)) printf("    golden %s: got %s want %s\n", name, hex, want[0] ? want : "(none)");
    return !strcmp(want, hex);
}

static void render_gallery(const char *name, float scale, bool dialog, bool type)
{
    struct gui_window *w = open_headless(560, 480);
    gui_headless_set_size(w, (int32_t)(560 * scale), (int32_t)(480 * scale), scale);
    struct gui_tree *t = gui_tree_new();
    struct gui_ui *ui = gui_ui_new(t);
    static const struct gui_table_source src = { "gallery", src_rows, src_cell, NULL, NULL };
    gui_ui_table_source(ui, &src);
    gui_ui_set_window(ui, w);
    gallery_tree(t, dialog);
    gui_ui_set_scale(ui, scale);
    gui_ui_set(ui, "gallery.progress", "400");
    int32_t pw, ph;
    gui_window_size(w, &pw, &ph, NULL);
    gui_ui_layout(ui, pw, ph);
    struct gui_table_state *ts = gui_ui_table_find(ui, "tbl");
    ts->scroll = 50;
    if (type) {
        gui_ui_focus(ui, "in");
        text_in(ui, "selected text");
        struct gui_action act;
        bool f;
        for (int i = 0; i < 4; i++) key(ui, GUI_KEY_LEFT, GUI_MOD_SHIFT, &act, &f);
    }
    struct gui_cpu_frame fr;
    gui_cpu_acquire(w, &fr);
    struct gui_surface s = gui_surface_from_frame(&fr);
    ui->caret_on = true;
    gui_ui_paint(ui, &s, NULL, 0);
    CHECK(name, golden_check(name, &fr));
    gui_ui_free(ui);
    gui_tree_free(t);
    gui_window_close(w);
}

static void test_draw_gallery(void)
{
    struct gui_window *w = open_headless(360, 200);
    struct gui_cpu_frame f;
    gui_cpu_acquire(w, &f);
    struct gui_surface s = gui_surface_from_frame(&f);
    gui_fill_rect(&s, (struct gui_rect){ 0, 0, 360, 200 }, gui_rgb(0x12, 0x14, 0x1a));
    gui_fill_round_rect(&s, (struct gui_rect){ 10, 10, 100, 50 }, 12, gui_rgb(0x2f, 0x6f, 0xed));
    gui_fill_circle(&s, 150, 35, 22, gui_rgb(0x34, 0xc7, 0x59));
    gui_stroke_rect(&s, (struct gui_rect){ 190, 10, 80, 50 }, 3, gui_rgb(0xd9, 0x82, 0x2b));
    gui_line(&s, 280, 10, 350, 60, gui_rgb(255, 255, 255));
    static const int32_t sizes[4] = { 13, 16, 24, 40 };
    int32_t y = 70;
    for (int i = 0; i < 4; i++) {
        gui_text_draw(&s, GUI_FONT_TEXT, sizes[i], 10, y + sizes[i], "Inter 0123 ZCL", 14, gui_rgb(232, 234, 240));
        gui_text_draw(&s, GUI_FONT_STRONG, sizes[i], 200, y + sizes[i], "Strong 7", 8, gui_rgb(232, 234, 240));
        y += sizes[i] + 6;
    }
    CHECK("draw_gallery", golden_check("draw_gallery", &f));
    gui_window_close(w);
}

/* Present geometry. The Win32 blit passes gui_dib_src_y as ySrc of a top-down DIB;
 * GDI counts source rows from the bottom, so a partial present of rows y..y+h-1
 * must start at fb_h - y - h. The review probe showed rows 467..503 on screen
 * where 22..58 were asked for when ySrc was y. */
static void test_present_geometry(void)
{
    struct gui_rect full = { 0, 0, 320, 200 }, mid = { 20, 20, 60, 40 }, top = { 0, 0, 10, 10 },
                    bot = { 0, 190, 10, 10 };
    CHECK("a full-height rectangle starts at source row 0", gui_dib_src_y(200, &full) == 0);
    CHECK("a middle rectangle starts at fb_h - y - h", gui_dib_src_y(200, &mid) == 140);
    CHECK("the top rows are the last source rows", gui_dib_src_y(200, &top) == 190);
    CHECK("the bottom rows are the first source rows", gui_dib_src_y(200, &bot) == 0);
    bool mirrored_ok = true;
    for (int32_t y = 0; y < 200; y += 7) { /* the last row asked for, counted from the bottom */
        struct gui_rect r = { 0, y, 4, 200 - y };
        mirrored_ok = mirrored_ok && gui_dib_src_y(200, &r) == 0 &&
                      gui_dib_src_y(200, &(struct gui_rect){ 0, y, 4, 1 }) == 199 - y;
    }
    CHECK("source rows mirror the top-down rows over the whole frame", mirrored_ok);

    struct gui_rect r = { -5, -5, 20, 20 };
    CHECK("clipping trims a rectangle that starts outside",
          gui_rect_clip_frame(&r, 100, 100) && r.x == 0 && r.y == 0 && r.w == 15 && r.h == 15);
    r = (struct gui_rect){ 90, 90, 50, 50 };
    CHECK("clipping trims a rectangle that ends outside",
          gui_rect_clip_frame(&r, 100, 100) && r.x == 90 && r.w == 10 && r.h == 10);
    r = (struct gui_rect){ 100, 0, 10, 10 };
    CHECK("a rectangle fully outside is empty", !gui_rect_clip_frame(&r, 100, 100));
    r = (struct gui_rect){ 5, 5, 0, 10 };
    CHECK("an empty rectangle is refused", !gui_rect_clip_frame(&r, 100, 100));
    r = (struct gui_rect){ 10, 10, INT32_MAX, INT32_MAX };
    CHECK("a huge rectangle clips without overflow",
          gui_rect_clip_frame(&r, 100, 80) && r.w == 90 && r.h == 70);
    r = (struct gui_rect){ INT32_MIN, INT32_MIN, 10, 10 };
    CHECK("a far negative rectangle is empty", !gui_rect_clip_frame(&r, 100, 100));
    gui_window_set_live_hook(NULL, NULL, NULL);
    CHECK("the live hook tolerates a NULL window", true);
}

/* Bound data pool: fill it to exactly GUI_DATA_BYTES, then add keys. The old
 * new-key path wrote pool[used] with used == GUI_DATA_BYTES (one byte past the
 * allocation) and left used above the bound. */
static void test_data_pool_exact(void)
{
    struct gui_tree *t = gui_tree_new();
    struct gui_ui *ui = gui_ui_new(t);
    static char val[4097];
    bool filled = true;
    for (int i = 0; i < 8; i++) {
        char key[16];
        snprintf(key, sizeof(key), "fill.%d", i);
        size_t len = i < 7 ? 4096 : 4080; /* 7 * (4096 + 2) + 1 + 4080 + 1 = 32768 */
        memset(val, 'a' + i, len);
        val[len] = 0;
        filled = filled && gui_ui_set(ui, key, val);
    }
    CHECK("eight keys fill the pool to exactly GUI_DATA_BYTES", filled && ui->data.used == GUI_DATA_BYTES);
    bool set_empty = gui_ui_set(ui, "extra.empty", "");
    CHECK("a new key on a full pool never passes the bound", ui->data.used <= GUI_DATA_BYTES);
    CHECK("the new key is stored after compaction", set_empty && !strcmp(gui_ui_get(ui, "extra.empty"), ""));
    CHECK("another new key with a value fits", gui_ui_set(ui, "extra.v", "v") && !strcmp(gui_ui_get(ui, "extra.v"), "v") &&
          ui->data.used <= GUI_DATA_BYTES);
    bool intact = true;
    for (int i = 0; i < 8; i++) {
        char key[16];
        snprintf(key, sizeof(key), "fill.%d", i);
        const char *g = gui_ui_get(ui, key);
        intact = intact && g[0] == 'a' + i && strlen(g) == (i < 7 ? 4096u : 4080u);
    }
    CHECK("the older values survive compaction", intact);
    memset(val, 'z', 4096);
    val[4096] = 0;
    bool refused = true;
    for (int i = 0; i < 4; i++) {
        char key[16];
        snprintf(key, sizeof(key), "more.%d", i);
        (void)gui_ui_set(ui, key, val); /* some fit, then the pool is full: refused, not overrun */
        refused = refused && ui->data.used <= GUI_DATA_BYTES;
    }
    CHECK("repeated large writes stay inside the pool", refused);
    gui_ui_free(ui);
    gui_tree_free(t);
}

#if defined(__APPLE__)
struct cocoa_wake_arg { struct gui_window *win; };

static void *cocoa_wake_later(void *p)
{
    struct cocoa_wake_arg *a = p;
    struct timespec ts = { .tv_nsec = 80000000L };
    nanosleep(&ts, NULL);
    gui_window_wake(a->win);
    return NULL;
}

static void test_cocoa_wake(struct gui_window *win)
{
    pthread_t th;
    struct cocoa_wake_arg arg = { .win = win };
    struct gui_event ev;
    bool saw = false;
    int spins = 0;
    bool started = pthread_create(&th, NULL, cocoa_wake_later, &arg) == 0;
    while (started && !saw && spins < 32) {
        spins++;
        if (!gui_window_wait(win, 2000, &ev)) break;
        saw = ev.type == GUI_EV_WAKE;
    }
    if (started) pthread_join(th, NULL);
    CHECK("cocoa wake unblocks a native wait", started && saw);
}
#endif

/* Darwin AUTO must open the shared CPU window, not refuse the platform. */
static void test_cocoa_auto(void)
{
#if defined(__APPLE__)
    struct gui_window_desc d = { .title_utf8 = "z23 cocoa", .width = 640, .height = 420,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_AUTO };
    struct gui_window *win = NULL;
    char err[120] = "";
    bool opened = gui_window_open(&d, &win, err, sizeof(err));
    CHECK("auto backend opens a cocoa window", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    struct gui_cpu_frame frame;
    bool acquired = gui_cpu_acquire(win, &frame);
    CHECK("cocoa window provides a cpu frame",
          acquired && frame.pixels && frame.width >= 640 && frame.height >= 420);
    if (acquired && frame.pixels)
        frame.pixels[0] = 0x00FF0000u;
    CHECK("cocoa window presents the cpu frame", acquired && gui_cpu_present(win, NULL, 0));
    test_cocoa_wake(win);
    {
        char saved[65537];
        char back[32];
        size_t saved_n = gui_clipboard_get_text(win, saved, sizeof(saved));
        bool full = saved_n + 1u < sizeof(saved);
        bool set = gui_clipboard_set_text(win, "z23-paste", 9);
        size_t n = gui_clipboard_get_text(win, back, sizeof(back));
        CHECK("cocoa window round-trips pasteboard text",
              set && n == 9 && strcmp(back, "z23-paste") == 0);
        if (full) {
            const char *restore = saved_n ? saved : "";
            (void)gui_clipboard_set_text(win, restore, saved_n);
        }
    }
    gui_window_close(win);
#else
    printf("  auto backend opens a cocoa window... SKIP\n");
#endif
}

/* The shared open path must apply GUI_WINDOW_FULLSCREEN on Cocoa. */
static void test_cocoa_fullscreen(void)
{
#if defined(__APPLE__)
    struct gui_window_desc d = {
        .title_utf8 = "z23 fullscreen", .width = 640, .height = 420,
        .flags = GUI_WINDOW_FULLSCREEN, .surface = GUI_SURFACE_CPU,
        .backend = GUI_BACKEND_COCOA };
    struct gui_window *win = NULL;
    char err[120] = "";
    int32_t pw = 0, ph = 0;
    float scale = 0.0f;
    bool opened = gui_window_open(&d, &win, err, sizeof(err));
    CHECK("fullscreen cocoa window opens", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    gui_window_size(win, &pw, &ph, &scale);
    CHECK("open applies the fullscreen flag", gui_window_is_fullscreen(win));
    CHECK("fullscreen frame is larger than requested",
          scale > 0.0f && pw > (int32_t)(640.0f * scale) &&
          ph > (int32_t)(420.0f * scale));
    CHECK("leaving fullscreen clears the flag",
          gui_window_set_fullscreen(win, false) && !gui_window_is_fullscreen(win));
    gui_window_close(win);
#else
    printf("  open applies the fullscreen flag... SKIP\n");
#endif
}

#if defined(__APPLE__)
bool gui_cocoa_move_frame(struct gui_window *w, double width, double height);
unsigned long gui_cocoa_presentation(void);
void gui_cocoa_set_presentation(unsigned long options);
int gui_cocoa_cursor(void);
bool gui_cocoa_aim_frame(struct gui_window *w, int contain);
uint64_t gui_cocoa_copied_pixels(void);
uint64_t gui_cocoa_images_built(void);
uint32_t gui_cocoa_cached_pixel(const struct gui_window *w, int32_t x, int32_t y);
uint32_t gui_cocoa_view_pixel(const struct gui_window *w, int32_t x, int32_t y);

static void paint_frame(struct gui_cpu_frame *f, uint32_t px)
{
    size_t n = (size_t)f->width * (size_t)f->height;
    size_t i;
    for (i = 0; i < n; i++)
        f->pixels[i] = px;
}

static void paint_rect(struct gui_cpu_frame *f, struct gui_rect r, uint32_t px)
{
    int32_t y, x;
    for (y = r.y; y < r.y + r.h; y++)
        for (x = r.x; x < r.x + r.w; x++)
            f->pixels[(size_t)y * (size_t)f->stride_px + (size_t)x] = px;
}

static int cocoa_dirty_pixels_ok(struct gui_window *win)
{
    return gui_cocoa_cached_pixel(win, 0, 0) == 0x00FF0000u &&
           gui_cocoa_cached_pixel(win, 4, 6) == 0x0000FF00u;
}

static int cocoa_view_matches(struct gui_window *win)
{
    return gui_cocoa_view_pixel(win, 0, 0) == 0x00FF0000u &&
           gui_cocoa_view_pixel(win, 4, 6) == 0x0000FF00u;
}

static uint64_t cocoa_time_dirty(struct gui_window *win, struct gui_rect dirty)
{
    uint64_t t0 = gui_now_ns();
    int i;
    for (i = 0; i < 20; i++)
        (void)gui_cpu_present(win, &dirty, 1);
    return (gui_now_ns() - t0) / 1000u;
}
#endif

/* A dirty rect must not swizzle the rest of the framebuffer. */
static void test_cocoa_dirty_present(void)
{
#if defined(__APPLE__)
    struct gui_window_desc d = {
        .title_utf8 = "z23 dirty", .width = 320, .height = 200,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window *win = NULL;
    char err[120] = "";
    struct gui_cpu_frame frame;
    struct gui_rect dirty = { 4, 6, 8, 8 };
    uint64_t before, copied, timed;
    bool opened = gui_window_open(&d, &win, err, sizeof err);
    CHECK("dirty-rect window opens", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    opened = gui_cpu_acquire(win, &frame) && frame.pixels != NULL;
    CHECK("dirty-rect window provides a frame", opened);
    if (!opened) {
        gui_window_close(win);
        return;
    }
    paint_frame(&frame, 0x00FF0000u);
    CHECK("full present fills the cache", gui_cpu_present(win, NULL, 0));
    frame.pixels[0] = 0x000000FFu;
    paint_rect(&frame, dirty, 0x0000FF00u);
    before = gui_cocoa_copied_pixels();
    CHECK("dirty present copies only that rect",
          gui_cpu_present(win, &dirty, 1) &&
          gui_cocoa_copied_pixels() - before == 64u);
    CHECK("dirty present keeps pixels outside the rect",
          cocoa_dirty_pixels_ok(win));
    copied = gui_cocoa_copied_pixels() - before;
    timed = cocoa_time_dirty(win, dirty);
    printf("present_dirty: copied=%llu full=%llu repeat20_us=%llu\n",
           (unsigned long long)copied,
           (unsigned long long)frame.width * (unsigned long long)frame.height,
           (unsigned long long)timed);
    gui_window_close(win);
#else
    printf("  dirty present copies only that rect... SKIP\n");
#endif
}

/* The first image replaces the whole view, so a fresh cache must keep the frame. */
static void test_cocoa_fresh_cache(void)
{
#if defined(__APPLE__)
    struct gui_window_desc d = {
        .title_utf8 = "z23 fresh", .width = 320, .height = 200,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window *win = NULL;
    char err[120] = "";
    struct gui_cpu_frame frame;
    struct gui_rect dirty = { 4, 6, 8, 8 };
    bool opened = gui_window_open(&d, &win, err, sizeof err);
    CHECK("fresh-cache window opens", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    opened = gui_cpu_acquire(win, &frame) && frame.pixels != NULL;
    CHECK("fresh-cache window provides a frame", opened);
    if (!opened) {
        gui_window_close(win);
        return;
    }
    paint_frame(&frame, 0x00FF0000u);
    paint_rect(&frame, dirty, 0x0000FF00u);
    CHECK("a first dirty present keeps the rest of the frame",
          gui_cpu_present(win, &dirty, 1) &&
          gui_cocoa_cached_pixel(win, 0, 0) == 0x00FF0000u);
    gui_window_close(win);
#else
    printf("  a first dirty present keeps the rest of the frame... SKIP\n");
#endif
}

/* Later dirty presents must reuse the image the first present installed. */
static void test_cocoa_image_reuse(void)
{
#if defined(__APPLE__)
    struct gui_window_desc d = {
        .title_utf8 = "z23 image", .width = 320, .height = 200,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window *win = NULL;
    char err[120] = "";
    struct gui_cpu_frame frame;
    struct gui_rect dirty = { 4, 6, 8, 8 };
    uint64_t base, before, images, timed;
    uint32_t view00, view46;
    bool opened = gui_window_open(&d, &win, err, sizeof err);
    CHECK("image-reuse window opens", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    if (!gui_cpu_acquire(win, &frame) || frame.pixels == NULL) {
        printf("  image-reuse window provides a frame... FAIL\n");
        g_fail++;
        gui_window_close(win);
        return;
    }
    base = gui_cocoa_images_built();
    paint_frame(&frame, 0x00FF0000u);
    if (!gui_cpu_present(win, NULL, 0)) {
        printf("  full present installs an image... FAIL\n");
        g_fail++;
        gui_window_close(win);
        return;
    }
    frame.pixels[0] = 0x000000FFu;
    paint_rect(&frame, dirty, 0x0000FF00u);
    before = gui_cocoa_copied_pixels();
    CHECK("dirty present copies only that rect",
          gui_cpu_present(win, &dirty, 1) &&
          gui_cocoa_copied_pixels() - before == 64u);
    view00 = gui_cocoa_view_pixel(win, 0, 0);
    view46 = gui_cocoa_view_pixel(win, 4, 6);
    timed = cocoa_time_dirty(win, dirty);
    images = gui_cocoa_images_built() - base;
    printf("present_image: images=%llu view00=%08x view46=%08x repeat20_us=%llu\n",
           (unsigned long long)images, (unsigned int)view00,
           (unsigned int)view46, (unsigned long long)timed);
    CHECK("one image serves later dirty presents", images == 1u);
    CHECK("the view shows the dirty update", cocoa_view_matches(win));
    gui_window_close(win);
#else
    printf("  one image serves later dirty presents... SKIP\n");
#endif
}

/* A window that is never shown must not hide the Dock or the menu bar. */
static void test_cocoa_hidden_fullscreen(void)
{
#if defined(__APPLE__)
    struct gui_window_desc warm = {
        .title_utf8 = "z23 warm", .width = 200, .height = 100,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window_desc d = {
        .title_utf8 = "z23 hidden fullscreen", .width = 640, .height = 420,
        .flags = GUI_WINDOW_HIDDEN | GUI_WINDOW_FULLSCREEN,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window *warm_win = NULL;
    struct gui_window *win = NULL;
    char err[120] = "";
    unsigned long before = 0;
    unsigned long after = 0;
    bool opened = gui_window_open(&warm, &warm_win, err, sizeof(err));
    CHECK("a visible window opens before the hidden fullscreen check", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    before = gui_cocoa_presentation();
    opened = gui_window_open(&d, &win, err, sizeof(err));
    CHECK("a hidden fullscreen window opens", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        gui_window_close(warm_win);
        return;
    }
    after = gui_cocoa_presentation();
    CHECK("a hidden fullscreen window stays fullscreen", gui_window_is_fullscreen(win));
    CHECK("a hidden fullscreen window leaves the Dock and menu bar alone", before == after);
    gui_window_close(win);
    gui_window_close(warm_win);
#else
    printf("  a hidden fullscreen window leaves the Dock and menu bar alone... SKIP\n");
#endif
}

/* Closing a window that never hid the Dock must not uncover one that did. */
static void test_cocoa_hidden_close_keeps_presentation(void)
{
#if defined(__APPLE__)
    struct gui_window_desc warm = {
        .title_utf8 = "z23 warm", .width = 200, .height = 100,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window_desc shown = {
        .title_utf8 = "z23 shown fullscreen", .width = 640, .height = 420,
        .flags = GUI_WINDOW_FULLSCREEN,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window_desc hidden = {
        .title_utf8 = "z23 hidden fullscreen", .width = 320, .height = 200,
        .flags = GUI_WINDOW_HIDDEN | GUI_WINDOW_FULLSCREEN,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window *warm_win = NULL;
    struct gui_window *shown_win = NULL;
    struct gui_window *hidden_win = NULL;
    char err[120] = "";
    unsigned long base = 0;
    unsigned long covered = 0;
    bool opened = gui_window_open(&warm, &warm_win, err, sizeof(err));
    if (!opened) {
        printf("  open error: %s\n", err);
        CHECK("a normal window opens before the shared presentation check", false);
        return;
    }
    base = gui_cocoa_presentation();
    opened = gui_window_open(&shown, &shown_win, err, sizeof(err));
    if (!opened) {
        printf("  open error: %s\n", err);
        CHECK("a visible fullscreen window opens", false);
        gui_window_close(warm_win);
        return;
    }
    covered = gui_cocoa_presentation();
    opened = gui_window_open(&hidden, &hidden_win, err, sizeof(err));
    if (!opened) {
        printf("  open error: %s\n", err);
        CHECK("a hidden fullscreen window opens beside it", false);
        gui_window_close(shown_win);
        gui_window_close(warm_win);
        return;
    }
    gui_window_close(hidden_win);
    CHECK("closing the hidden window keeps the visible presentation",
          covered != base && gui_cocoa_presentation() == covered);
    gui_window_close(shown_win);
    gui_window_close(warm_win);
#else
    printf("  closing the hidden window keeps the visible presentation... SKIP\n");
#endif
}

/* HideDock | HideMenuBar must be added to options the process already set.
 * DisableProcessSwitching cannot be set unless the Dock is already hidden,
 * and AutoHideDock is the alternative to HideDock. The bit under test is
 * DisableAppleMenu (1<<4), which fullscreen does not itself mean. */
static void test_cocoa_presentation_keeps_bits(void)
{
#if defined(__APPLE__)
    struct gui_window_desc warm = {
        .title_utf8 = "z23 warm", .width = 200, .height = 100,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window_desc full = {
        .title_utf8 = "z23 fullscreen bits", .width = 640, .height = 420,
        .flags = GUI_WINDOW_FULLSCREEN,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window *warm_win = NULL;
    struct gui_window *full_win = NULL;
    char err[120] = "";
    unsigned long keep = 1ul << 4;
    unsigned long during = 0;
    bool opened = gui_window_open(&warm, &warm_win, err, sizeof(err));
    CHECK("a window opens before the presentation bit check", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    gui_cocoa_set_presentation(keep);
    opened = gui_window_open(&full, &full_win, err, sizeof(err));
    CHECK("fullscreen opens over an existing presentation bit", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        gui_cocoa_set_presentation(0ul);
        gui_window_close(warm_win);
        return;
    }
    during = gui_cocoa_presentation();
    printf("    presentation during fullscreen %lu\n", during);
    CHECK("fullscreen keeps the existing presentation bit",
          (during & (keep | 2ul | 8ul)) == (keep | 2ul | 8ul));
    gui_window_close(full_win);
    CHECK("leaving fullscreen restores the earlier presentation bit",
          gui_cocoa_presentation() == keep);
    gui_cocoa_set_presentation(0ul);
    gui_window_close(warm_win);
#else
    printf("  fullscreen keeps the existing presentation bit... SKIP\n");
#endif
}

/* AutoHideDock and HideDock cannot both be set. Fullscreen must still hide
 * the Dock, then restore the auto-hide bit when the window leaves. */
static void test_cocoa_presentation_hides_over_autohide(void)
{
#if defined(__APPLE__)
    struct gui_window_desc warm = {
        .title_utf8 = "z23 warm", .width = 200, .height = 100,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window_desc full = {
        .title_utf8 = "z23 fullscreen autohide", .width = 640, .height = 420,
        .flags = GUI_WINDOW_FULLSCREEN,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window *warm_win = NULL;
    struct gui_window *full_win = NULL;
    char err[120] = "";
    unsigned long during = 0;
    bool opened = gui_window_open(&warm, &warm_win, err, sizeof(err));
    CHECK("a window opens before the auto-hide check", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    gui_cocoa_set_presentation(1ul);
    opened = gui_window_open(&full, &full_win, err, sizeof(err));
    CHECK("fullscreen opens over auto-hide", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        gui_cocoa_set_presentation(0ul);
        gui_window_close(warm_win);
        return;
    }
    during = gui_cocoa_presentation();
    printf("    presentation over auto-hide %lu\n", during);
    CHECK("fullscreen hides the Dock without the auto-hide bit",
          (during & (1ul | 2ul | 8ul)) == (2ul | 8ul));
    gui_window_close(full_win);
    CHECK("leaving fullscreen restores auto-hide",
          gui_cocoa_presentation() == 1ul);
    gui_cocoa_set_presentation(0ul);
    gui_window_close(warm_win);
#else
    printf("  fullscreen hides the Dock without the auto-hide bit... SKIP\n");
#endif
}

/* The wallet asks for an I-beam over a text field and a hand over a button.
 * Win32 changes the pointer. Cocoa must do the same through the shared call,
 * and only while the pointer is inside that window. */
#if defined(__APPLE__)
static void test_cocoa_cursor_outside(struct gui_window *win, const char *placed)
{
    int before = gui_cocoa_cursor();
    enum gui_cursor ask = before == (int)GUI_CURSOR_IBEAM
        ? GUI_CURSOR_HAND : GUI_CURSOR_IBEAM;
    int after = 0;
    CHECK(placed, gui_cocoa_aim_frame(win, 0));
    gui_window_set_cursor(win, ask);
    after = gui_cocoa_cursor();
    printf("    cursor outside before %d after %d\n", before, after);
    CHECK("a pointer outside the window keeps its cursor", after == before);
}

static void test_cocoa_cursor_over(struct gui_window *win)
{
    int kind = 0;
    CHECK("the window can cover the pointer", gui_cocoa_aim_frame(win, 1));
    gui_window_set_cursor(win, GUI_CURSOR_IBEAM);
    kind = gui_cocoa_cursor();
    printf("    cursor after ibeam %d\n", kind);
    CHECK("a text field asks for the I-beam cursor", kind == (int)GUI_CURSOR_IBEAM);
    gui_window_set_cursor(win, GUI_CURSOR_HAND);
    kind = gui_cocoa_cursor();
    printf("    cursor after hand %d\n", kind);
    CHECK("a button asks for the hand cursor", kind == (int)GUI_CURSOR_HAND);
    gui_window_set_cursor(win, GUI_CURSOR_ARROW);
    kind = gui_cocoa_cursor();
    printf("    cursor after arrow %d\n", kind);
    CHECK("the arrow cursor comes back", kind == (int)GUI_CURSOR_ARROW);
}

static void test_cocoa_cursor_title(struct gui_window *win)
{
    int before = gui_cocoa_cursor();
    enum gui_cursor ask = before == (int)GUI_CURSOR_IBEAM
        ? GUI_CURSOR_HAND : GUI_CURSOR_IBEAM;
    int after = 0;
    CHECK("the title bar can cover the pointer", gui_cocoa_aim_frame(win, 2));
    gui_window_set_cursor(win, ask);
    after = gui_cocoa_cursor();
    printf("    cursor on title before %d after %d\n", before, after);
    CHECK("the title bar keeps its cursor", after == before);
}

static void test_cocoa_cursor_covered(struct gui_window *back)
{
    struct gui_window_desc d = {
        .title_utf8 = "z23 cursor cover", .width = 200, .height = 100,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window *cover = NULL;
    char err[120] = "";
    int before = gui_cocoa_cursor();
    enum gui_cursor ask = before == (int)GUI_CURSOR_IBEAM
        ? GUI_CURSOR_HAND : GUI_CURSOR_IBEAM;
    int after = 0;
    bool opened = gui_window_open(&d, &cover, err, sizeof(err));
    CHECK("a second window opens over the pointer", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    CHECK("the cover can take the pointer", gui_cocoa_aim_frame(cover, 1));
    gui_window_set_cursor(back, ask);
    after = gui_cocoa_cursor();
    printf("    cursor covered before %d after %d\n", before, after);
    CHECK("a covered window does not take the cursor", after == before);
    gui_window_close(cover);
}
#endif

static void test_cocoa_cursor(void)
{
#if defined(__APPLE__)
    struct gui_window_desc d = {
        .title_utf8 = "z23 cursor", .width = 200, .height = 100,
        .surface = GUI_SURFACE_CPU, .backend = GUI_BACKEND_COCOA };
    struct gui_window *win = NULL;
    char err[120] = "";
    bool opened = gui_window_open(&d, &win, err, sizeof(err));
    CHECK("a window opens before the cursor check", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    test_cocoa_cursor_outside(win, "the window can leave the pointer");
    test_cocoa_cursor_title(win);
    test_cocoa_cursor_over(win);
    test_cocoa_cursor_covered(win);
    test_cocoa_cursor_outside(win, "the window can leave the pointer again");
    gui_window_close(win);
#else
    printf("  a text field asks for the I-beam cursor... SKIP\n");
#endif
}

/* A Cocoa frame change must reach the shared window without a later wait.
 * AppKit tells the delegate during setFrame and during a live drag. */
static void test_cocoa_live_resize(void)
{
#if defined(__APPLE__)
    struct gui_window_desc d = {
        .title_utf8 = "z23 resize", .width = 640, .height = 420,
        .flags = GUI_WINDOW_RESIZABLE, .surface = GUI_SURFACE_CPU,
        .backend = GUI_BACKEND_COCOA };
    struct gui_window *win = NULL;
    char err[120] = "";
    int32_t before_w = 0, before_h = 0, after_w = 0, after_h = 0;
    float scale = 0.0f;
    bool opened = gui_window_open(&d, &win, err, sizeof(err));
    CHECK("resizable cocoa window opens", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    gui_window_size(win, &before_w, &before_h, &scale);
    CHECK("a frame change reaches the shared window",
          before_w > 0 && before_h > 0 && scale > 0.0f &&
          gui_cocoa_move_frame(win, 960.0, 720.0));
    gui_window_size(win, &after_w, &after_h, &scale);
    CHECK("shared size follows the new frame", after_w > before_w && after_h > before_h);
    gui_window_close(win);
#else
    printf("  a frame change reaches the shared window... SKIP\n");
#endif
}

/* A frame that is already wider than the screen must still enter fullscreen. */
static void test_cocoa_fullscreen_wide(void)
{
#if defined(__APPLE__)
    struct gui_window_desc d = {
        .title_utf8 = "z23 fullscreen wide", .width = 4000, .height = 400,
        .flags = GUI_WINDOW_FULLSCREEN, .surface = GUI_SURFACE_CPU,
        .backend = GUI_BACKEND_COCOA };
    struct gui_window *win = NULL;
    char err[120] = "";
    bool opened = gui_window_open(&d, &win, err, sizeof(err));
    CHECK("wide fullscreen window opens", opened);
    if (!opened) {
        printf("  open error: %s\n", err);
        return;
    }
    CHECK("wide window still applies fullscreen", gui_window_is_fullscreen(win));
    gui_window_close(win);
#else
    printf("  wide window still applies fullscreen... SKIP\n");
#endif
}

int test_gui(void)
{
    printf("\n=== gui ===\n");
    g_fail = 0;
    test_wheel_notch();
    test_wheel_small();
    test_cocoa_auto();
    test_cocoa_fullscreen();
    test_cocoa_fullscreen_wide();
    test_cocoa_hidden_fullscreen();
    test_cocoa_hidden_close_keeps_presentation();
    test_cocoa_presentation_keeps_bits();
    test_cocoa_presentation_hides_over_autohide();
    test_cocoa_cursor();
    test_cocoa_live_resize();
    test_cocoa_dirty_present();
    test_cocoa_fresh_cache();
    test_cocoa_image_reuse();
    test_utf8();
    test_draw();
    test_text();
    test_tree();
    test_layout();
    test_focus_and_fields();
    test_table();
    test_resize_coalesce();
    test_window_common();
    test_present_geometry();
    test_data_pool_exact();
    test_script_and_golden();
    test_gallery_script();
    test_theme();
    test_draw_gallery();
    render_gallery("gallery_idle", 1.0f, false, true);
    render_gallery("gallery_dialog", 1.0f, true, false);
    render_gallery("gallery_scale2", 2.0f, false, true);
    return g_fail;
}
