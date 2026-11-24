/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: memory-framebuffer window backend on a virtual clock, with event
 * injection and a line-oriented script runner for deterministic UI tests. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "gui/draw.h"
#include "gui_internal.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
static void real_sleep_ms(unsigned ms) { Sleep(ms); }
#else
#include <time.h>
static void real_sleep_ms(unsigned ms)
{
    struct timespec ts = { 0, (long)ms * 1000000L };
    nanosleep(&ts, NULL);
}
#endif

struct headless {
    bool hold;
    uint64_t presented_px;
    size_t presents;
    char clip[GUI_CLIP_CAP + 1];
    size_t clip_len;
};

static struct headless *hl(const struct gui_window *w)
{
    return (struct headless *)w->be;
}

static bool hl_open(struct gui_window *w, const struct gui_window_desc *d,
                    char *err, size_t cap)
{
    struct headless *h = zcl_calloc(1, sizeof(*h), "gui_headless");
    if (!h) {
        if (err && cap) snprintf(err, cap, "out of memory opening headless window");
        return false;
    }
    w->be = h;
    w->w = d->width;
    w->h = d->height;
    gui_virtual_clock_set(true);
    return true;
}

static void hl_close(struct gui_window *w)
{
    free(w->be);
    w->be = NULL;
}

static void hl_wait(struct gui_window *w, int32_t ms)
{
    if (w->count || atomic_load(&w->wake_pending)) return;
    if (hl(w)->hold) {
        real_sleep_ms(1);
        gui_virtual_clock_advance(1000000ull);
        return;
    }
    gui_virtual_clock_advance((ms < 0 ? 1u : (uint32_t)ms) * 1000000ull);
}

static void hl_wake(struct gui_window *w) { (void)w; }

static bool hl_present(struct gui_window *w, const struct gui_rect *r, size_t n)
{
    struct headless *h = hl(w);
    h->presents++;
    if (n == 0) {
        h->presented_px += (uint64_t)w->fb_w * (uint64_t)w->fb_h;
        return true;
    }
    for (size_t i = 0; i < n; i++)
        if (r[i].w > 0 && r[i].h > 0)
            h->presented_px += (uint64_t)r[i].w * (uint64_t)r[i].h;
    return true;
}

static bool hl_clip_set(struct gui_window *w, const char *utf8, size_t len)
{
    struct headless *h = hl(w);
    memcpy(h->clip, utf8, len);
    h->clip[len] = 0;
    h->clip_len = len;
    return true;
}

static size_t hl_clip_get(struct gui_window *w, char *buf, size_t cap)
{
    struct headless *h = hl(w);
    size_t n = h->clip_len < cap - 1 ? h->clip_len : cap - 1;
    memcpy(buf, h->clip, n);
    buf[n] = 0;
    return n;
}

const struct gui_backend_ops gui_backend_headless = {
    .open = hl_open, .close = hl_close, .wait_native = hl_wait,
    .wake = hl_wake, .present = hl_present, .clip_set = hl_clip_set,
    .clip_get = hl_clip_get,
};

bool gui_headless_inject(struct gui_window *w, const struct gui_event *ev)
{
    if (!w || !ev || w->kind != GUI_BACKEND_HEADLESS) return false;
    gui_ring_push(w, ev);
    return true;
}

void gui_headless_set_size(struct gui_window *w, int32_t pw, int32_t ph,
                           float scale)
{
    if (!w || w->kind != GUI_BACKEND_HEADLESS || pw <= 0 || ph <= 0) return;
    w->w = pw;
    w->h = ph;
    if (scale > 0.0f) w->scale = scale;
    struct gui_event e = { .type = GUI_EV_RESIZE,
                           .size = { pw, ph, w->scale } };
    gui_ring_push(w, &e);
}

/* w->be is the backend's private state: only a headless window has a struct
 * headless there. The wallet calls set_hold on whatever window it opened, and on a
 * Win32 window this used to write its flag over the first byte of the HWND. */
static bool is_headless(const struct gui_window *w)
{
    return w && w->be && w->kind == GUI_BACKEND_HEADLESS;
}

void gui_headless_set_hold(struct gui_window *w, bool hold)
{
    if (is_headless(w)) hl(w)->hold = hold;
}
uint64_t gui_headless_presented_pixels(const struct gui_window *w)
{
    return is_headless(w) ? hl(w)->presented_px : 0;
}
size_t gui_headless_present_count(const struct gui_window *w)
{
    return is_headless(w) ? hl(w)->presents : 0;
}

/* ---- script ---------------------------------------------------------- */

#define SCRIPT_LINES 4096u
#define SCRIPT_LINE_MAX 512u

enum cmd_kind { C_SIZE, C_SCALE, C_MOVE, C_CLICK, C_DCLICK, C_WHEEL, C_KEY,
                C_TEXT, C_PASTE, C_WAIT, C_IDLE, C_SHOT };

struct cmd {
    enum cmd_kind kind;
    int32_t a, b;
    float f;
    uint32_t mods;
    bool right;
    char s[200];
};

struct gui_script {
    size_t n, pos;
    struct cmd *cmds;
};

static const struct { const char *name; enum gui_key key; } k_keys[] = {
    { "tab", GUI_KEY_TAB }, { "enter", GUI_KEY_ENTER },
    { "esc", GUI_KEY_ESCAPE }, { "escape", GUI_KEY_ESCAPE },
    { "backspace", GUI_KEY_BACKSPACE }, { "delete", GUI_KEY_DELETE },
    { "left", GUI_KEY_LEFT }, { "right", GUI_KEY_RIGHT },
    { "up", GUI_KEY_UP }, { "down", GUI_KEY_DOWN }, { "home", GUI_KEY_HOME },
    { "end", GUI_KEY_END }, { "pageup", GUI_KEY_PAGE_UP },
    { "pagedown", GUI_KEY_PAGE_DOWN }, { "space", GUI_KEY_SPACE },
};

static enum gui_key key_by_name(const char *n)
{
    for (size_t i = 0; i < sizeof(k_keys) / sizeof(k_keys[0]); i++)
        if (!strcmp(n, k_keys[i].name)) return k_keys[i].key;
    if (n[0] == 'f' && n[1] >= '1' && n[1] <= '9') {
        int v = atoi(n + 1);
        if (v >= 1 && v <= 12) return (enum gui_key)(GUI_KEY_F1 + v - 1);
    }
    if (n[0] && !n[1]) {
        if (n[0] >= 'a' && n[0] <= 'z') return (enum gui_key)(GUI_KEY_A + n[0] - 'a');
        if (n[0] >= '0' && n[0] <= '9') return (enum gui_key)(GUI_KEY_0 + n[0] - '0');
    }
    return GUI_KEY_NONE;
}

/* Parse a quoted string argument (no escapes beyond \" and \\). */
static bool quoted(const char *p, char *out, size_t cap)
{
    while (*p == ' ') p++;
    if (*p++ != '"') return false;
    size_t n = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;
        if (n + 1 >= cap) return false;
        out[n++] = *p++;
    }
    out[n] = 0;
    return *p == '"';
}

struct toks { char *op, *t[3]; };

static bool is_op(const struct toks *k, const char *name) { return !strcmp(k->op, name); }

/* size, scale, wait, until-idle */
static bool parse_simple(const struct toks *k, struct cmd *c)
{
    if (is_op(k, "size") && k->t[1]) {
        *c = (struct cmd){ .kind = C_SIZE, .a = atoi(k->t[0]), .b = atoi(k->t[1]) };
        return c->a > 0 && c->b > 0;
    }
    if (is_op(k, "scale") && k->t[0]) {
        *c = (struct cmd){ .kind = C_SCALE, .f = (float)atof(k->t[0]) };
        return c->f > 0.0f;
    }
    if (is_op(k, "wait") && k->t[0]) {
        *c = (struct cmd){ .kind = C_WAIT, .a = atoi(k->t[0]) };
        return c->a >= 0;
    }
    if (is_op(k, "until-idle")) {
        *c = (struct cmd){ .kind = C_IDLE };
        return true;
    }
    return false;
}

/* move, click, dclick, wheel */
static bool parse_pointer(const struct toks *k, struct cmd *c)
{
    if (is_op(k, "move") && k->t[1]) {
        *c = (struct cmd){ .kind = C_MOVE, .a = atoi(k->t[0]), .b = atoi(k->t[1]) };
        return true;
    }
    if ((is_op(k, "click") || is_op(k, "dclick")) && k->t[1]) {
        *c = (struct cmd){ .kind = k->op[0] == 'd' ? C_DCLICK : C_CLICK, .a = atoi(k->t[0]),
                           .b = atoi(k->t[1]), .right = k->t[2] && !strcmp(k->t[2], "right") };
        return !k->t[2] || c->right;
    }
    if (is_op(k, "wheel") && k->t[2]) {
        *c = (struct cmd){ .kind = C_WHEEL, .a = atoi(k->t[0]), .b = atoi(k->t[1]),
                           .f = (float)atof(k->t[2]) };
        return true;
    }
    return false;
}

static uint32_t mod_by_name(const char *m)
{
    if (!strcmp(m, "shift")) return GUI_MOD_SHIFT;
    if (!strcmp(m, "ctrl")) return GUI_MOD_CTRL;
    if (!strcmp(m, "alt")) return GUI_MOD_ALT;
    return 0;
}

static bool parse_key_cmd(const struct toks *k, struct cmd *c)
{
    if (!is_op(k, "key") || !k->t[0]) return false;
    *c = (struct cmd){ .kind = C_KEY, .a = (int32_t)key_by_name(k->t[0]) };
    for (size_t i = 1; i < 3 && k->t[i]; i++) {
        uint32_t m = mod_by_name(k->t[i]);
        if (!m) return false;
        c->mods |= m;
    }
    return c->a != GUI_KEY_NONE;
}

static bool shot_name_ok(const char *s)
{
    if (!*s || strlen(s) >= sizeof(((struct cmd *)0)->s)) return false;
    for (; *s; s++) {
        bool alnum = (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9');
        if (!alnum && *s != '_' && *s != '-') return false;
    }
    return true;
}

static bool parse_shot(const struct toks *k, struct cmd *c)
{
    if (!is_op(k, "shot") || !k->t[0] || k->t[1] || !shot_name_ok(k->t[0])) return false;
    *c = (struct cmd){ .kind = C_SHOT };
    snprintf(c->s, sizeof(c->s), "%s", k->t[0]);
    return true;
}

static bool parse_line(char *line, struct cmd *c)
{
    char *save = NULL;
    struct toks k = { .op = strtok_r(line, " \t", &save) };
    if (!k.op) return false;
    for (size_t i = 0; i < 3; i++) k.t[i] = strtok_r(NULL, " \t", &save);
    return parse_simple(&k, c) || parse_pointer(&k, c) || parse_key_cmd(&k, c) || parse_shot(&k, c);
}

/* Drop a trailing CR and a hash comment that starts before any quote. */
static void strip_line(char *line, size_t ll)
{
    if (ll && line[ll - 1] == '\r') line[ll - 1] = 0;
    char *hash = strchr(line, '#');
    char *q = strchr(line, '"');
    if (hash && (!q || hash < q)) *hash = 0;
}

/* text "..." and paste "...": the quoted argument follows the verb. */
static bool parse_quoted_cmd(const char *line, struct cmd *c)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    bool text = !strncmp(p, "text", 4), paste = !strncmp(p, "paste", 5);
    if (!text && !paste) return false;
    p += text ? 4 : 5;
    if (*p != ' ' && *p != '\t') return false;
    *c = (struct cmd){ .kind = text ? C_TEXT : C_PASTE };
    return quoted(p, c->s, sizeof(c->s));
}

static bool has_op(const char *line)
{
    while (*line == ' ' || *line == '\t') line++;
    return *line != 0;
}

/* Parse one source line into s->cmds. Returns false on a bad command. */
static bool load_line(struct gui_script *s, const char *text, size_t ll)
{
    char line[SCRIPT_LINE_MAX + 1], copy[SCRIPT_LINE_MAX + 1];
    memcpy(line, text, ll);
    line[ll] = 0;
    strip_line(line, ll);
    if (!has_op(line)) return true;
    struct cmd *c = &s->cmds[s->n];
    memcpy(copy, line, sizeof(copy));
    if (!parse_quoted_cmd(line, c) && !parse_line(copy, c)) return false;
    s->n++;
    return true;
}

struct gui_script *gui_headless_script_load(const char *text, size_t len,
                                            char *err, size_t err_cap)
{
    struct gui_script *s = zcl_calloc(1, sizeof(*s), "gui_script");
    struct cmd *cmds = zcl_calloc(SCRIPT_LINES, sizeof(*cmds), "gui_script_cmds");
    if (!s || !cmds) {
        free(s);
        free(cmds);
        return NULL;
    }
    s->cmds = cmds;
    size_t pos = 0, lineno = 0;
    while (pos < len) {
        size_t e = pos;
        while (e < len && text[e] != '\n') e++;
        lineno++;
        if (lineno > SCRIPT_LINES || e - pos > SCRIPT_LINE_MAX || !load_line(s, text + pos, e - pos)) {
            if (err && err_cap) snprintf(err, err_cap, "script line %zu: bad or unknown command", lineno);
            gui_headless_script_free(s);
            return NULL;
        }
        pos = e + 1;
    }
    return s;
}

void gui_headless_script_free(struct gui_script *s)
{
    if (!s) return;
    free(s->cmds);
    free(s);
}

static void inject_key(struct gui_window *w, enum gui_key k, uint32_t mods)
{
    struct gui_event e = { .type = GUI_EV_KEY, .mods = mods,
                           .key = { k, 0, true, false } };
    gui_ring_push(w, &e);
    e.key.down = false;
    gui_ring_push(w, &e);
}

static void inject_click(struct gui_window *w, const struct cmd *c, uint8_t clicks)
{
    uint8_t b = c->right ? 2 : 1;
    struct gui_event mv = { .type = GUI_EV_MOUSE_MOVE, .move = { c->a, c->b } };
    gui_ring_push(w, &mv);
    for (uint8_t i = 1; i <= clicks; i++) {
        struct gui_event e = { .type = GUI_EV_MOUSE_BUTTON,
                               .button = { c->a, c->b, b, true, i } };
        gui_ring_push(w, &e);
        e.button.down = false;
        gui_ring_push(w, &e);
    }
}

static void inject_text(struct gui_window *w, const char *s)
{
    size_t n = strlen(s), i = 0;
    while (i < n) {
        uint32_t cp = gui_utf8_next(s, n, &i);
        struct gui_event e = { .type = GUI_EV_TEXT, .text = { cp } };
        gui_ring_push(w, &e);
    }
}

static void inject_pointer(struct gui_window *w, const struct cmd *c)
{
    if (c->kind == C_MOVE) {
        struct gui_event e = { .type = GUI_EV_MOUSE_MOVE, .move = { c->a, c->b } };
        gui_ring_push(w, &e);
    } else if (c->kind == C_WHEEL) {
        struct gui_event e = { .type = GUI_EV_MOUSE_WHEEL, .wheel = { c->a, c->b, 0.0f, c->f } };
        gui_ring_push(w, &e);
    } else {
        inject_click(w, c, c->kind == C_DCLICK ? 2 : 1);
    }
}

static void inject_command(struct gui_window *w, const struct cmd *c)
{
    switch (c->kind) {
    case C_SIZE: gui_headless_set_size(w, c->a, c->b, 0.0f); break;
    case C_SCALE: gui_headless_set_size(w, w->w, w->h, c->f); break;
    case C_KEY: inject_key(w, (enum gui_key)c->a, c->mods); break;
    case C_TEXT: inject_text(w, c->s); break;
    case C_PASTE:
        gui_clipboard_set_text(w, c->s, strlen(c->s));
        inject_key(w, GUI_KEY_V, GUI_MOD_CTRL);
        break;
    case C_WAIT: gui_virtual_clock_advance((uint64_t)c->a * 1000000ull); break;
    default: inject_pointer(w, c); break;
    }
}

enum gui_script_step gui_headless_script_step(struct gui_window *w,
                                              struct gui_script *s,
                                              char *shot_out, size_t shot_cap)
{
    if (!w || !s || s->pos >= s->n) return GUI_SCRIPT_DONE;
    const struct cmd *c = &s->cmds[s->pos++];
    if (c->kind == C_IDLE) return GUI_SCRIPT_IDLE;
    if (c->kind == C_SHOT) {
        if (shot_out && shot_cap) snprintf(shot_out, shot_cap, "%s", c->s);
        return GUI_SCRIPT_SHOT;
    }
    inject_command(w, c);
    return GUI_SCRIPT_RAN;
}
