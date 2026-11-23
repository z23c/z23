/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: window open, the event loop, result drain, action dispatch,
 * poll scheduling, scripted headless sessions, --shot and --bench. The UI
 * thread never blocks on node I/O: it waits on the window with deadlines. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zw.h"

enum { T_POLL = 1, T_BLINK, T_TOAST, T_SHOT, T_QA, T_BENCH };

#define POLL_SYNCED_MS 10000
#define POLL_SYNCING_MS 2000
#define WALLET_REFRESH_MS 30000
#define NET_EVERY_POLLS 3

struct app {
    const struct zw_options *o;
    struct gui_window *win;
    struct gui_tree *tree;
    struct gui_ui *ui;
    struct zw_model model;
    struct zw_worker *worker;
    struct zw_bench bench;
    size_t screen;
    uint32_t key;
    bool blinking, have_key, running, need_wallet, was_online, bench_data, model_dirty;
    int polls;
    int64_t last_height, last_wallet_ns;
    int frames;
    int exit_code;
};

static int64_t now_s(void) { return (int64_t)(gui_now_ns() / 1000000000ull); }

static bool rebuild(struct app *a)
{
    uint32_t key = zw_structure_key(&a->model, a->screen);
    if (a->have_key && key == a->key) return true;
    char err[96];
    zw_shell_build(a->tree, &a->model, a->screen);
    if (!gui_tree_end(a->tree, err, sizeof(err))) {
        zw_log("screen build failed: %s", err);
        return false;
    }
    a->key = key;
    a->have_key = true;
    gui_ui_rebind(a->ui);
    return true;
}

static void render(struct app *a)
{
    if (a->model_dirty) {
        zw_model_publish(&a->model, a->ui, now_s());
        rebuild(a);
        zw_model_publish(&a->model, a->ui, now_s());
        a->model_dirty = false;
    }
    int32_t w, h;
    float sc;
    gui_window_size(a->win, &w, &h, &sc);
    gui_ui_set_scale(a->ui, sc);
    if (a->ui->layout_dirty || a->ui->w != w || a->ui->h != h) gui_ui_layout(a->ui, w, h);
    struct gui_rect dirty[8];
    size_t n = gui_ui_take_dirty(a->ui, dirty, 8);
    if (!n) return;
    struct gui_cpu_frame f;
    if (!gui_cpu_acquire(a->win, &f)) return;
    struct gui_surface s = gui_surface_from_frame(&f);
    gui_ui_paint(a->ui, &s, dirty, n);
    gui_cpu_present(a->win, dirty, n);
    if (a->frames++ == 0) {
        a->bench.first_frame_ms = zw_process_age_ms();
        zw_log("first frame presented");
    }
}

static void enqueue_all(struct app *a)
{
    for (enum zw_query q = 0; q < ZW_Q_COUNT; q++) zw_worker_enqueue(a->worker, q, a->model.generation);
    a->last_wallet_ns = (int64_t)gui_now_ns();
}

static uint32_t poll_delay_ms(const struct app *a)
{
    const struct zw_model *m = &a->model;
    if (m->conn == ZW_CONN_WARMING) return 1000;
    if (m->conn != ZW_CONN_ONLINE) return zw_backoff_s(m->fail_count) * 1000u;
    return m->have_chain && m->chain.blocks + 1 < m->chain.headers ? POLL_SYNCING_MS : POLL_SYNCED_MS;
}

static void poll_tick(struct app *a)
{
    struct zw_model *m = &a->model;
    zw_worker_enqueue(a->worker, ZW_Q_CHAIN, m->generation);
    if (m->conn != ZW_CONN_ONLINE) {
        gui_window_timer_set(a->win, T_POLL, poll_delay_ms(a), false);
        return;
    }
    if (a->polls++ % NET_EVERY_POLLS == 0 || !m->have_net) zw_worker_enqueue(a->worker, ZW_Q_NET, m->generation);
    bool stale = (int64_t)gui_now_ns() - a->last_wallet_ns >= (int64_t)WALLET_REFRESH_MS * 1000000;
    if (a->need_wallet || !m->have_wallet || stale) {
        zw_worker_enqueue(a->worker, ZW_Q_WALLET, m->generation);
        a->last_wallet_ns = (int64_t)gui_now_ns();
        a->need_wallet = false;
    }
    gui_window_timer_set(a->win, T_POLL, poll_delay_ms(a), false);
}

static void drain(struct app *a)
{
    struct zw_result r[16];
    size_t n;
    while ((n = zw_worker_drain(a->worker, r, 16)) > 0)
        for (size_t i = 0; i < n; i++) {
            int64_t before = a->model.chain.blocks;
            if (zw_model_apply(&a->model, &r[i])) a->model_dirty = true;
            if (r[i].err == ZW_OK) {
                a->model.last_update_s = now_s();
                if (r[i].kind == ZW_Q_CHAIN && a->model.chain.blocks != before) a->need_wallet = true;
                if (!a->bench_data) {
                    a->bench_data = true;
                    a->bench.first_data_ms = zw_process_age_ms() - a->bench.first_frame_ms;
                }
            }
            if (r[i].err != ZW_OK) zw_log("query %d failed: kind=%d code=%d", (int)r[i].kind, (int)r[i].err, r[i].rpc.code);
        }
    bool online = a->model.conn == ZW_CONN_ONLINE;
    if (online && !a->was_online) a->need_wallet = true; /* came back: refetch everything */
    if (online && !a->was_online && a->model.have_chain) {
        zw_worker_enqueue(a->worker, ZW_Q_NET, a->model.generation);
    }
    a->was_online = online;
    gui_window_timer_set(a->win, T_POLL, poll_delay_ms(a), false);
}

static void copy_text(struct app *a, const char *s, const char *toast)
{
    if (gui_clipboard_set_text(a->win, s, strlen(s))) gui_ui_toast(a->ui, toast, 3000);
    else gui_ui_toast(a->ui, "Couldn't copy. Try again.", 8000);
    gui_window_timer_set(a->win, T_TOAST, 3100, false);
}

static void set_screen(struct app *a, size_t s)
{
    if (s >= ZW_SCREEN_COUNT || s == a->screen) return;
    a->screen = s;
    a->model_dirty = true;
}

static void refresh_now(struct app *a)
{
    a->model.generation++;
    enqueue_all(a);
}

static void dispatch(struct app *a, const struct gui_action *act)
{
    char buf[1200];
    if (!strcmp(act->name, "nav.home")) set_screen(a, ZW_SCREEN_HOME);
    else if (!strcmp(act->name, "nav.node")) set_screen(a, ZW_SCREEN_NODE);
    else if (!strcmp(act->name, "home.refresh")) refresh_now(a);
    else if (!strcmp(act->name, "connect.retry")) {
        zw_worker_reset_auth(a->worker);
        a->model.fail_count = 0;
        refresh_now(a);
    } else if (!strcmp(act->name, "connect.copy")) {
        buf[0] = 0;
        for (size_t i = 0; i < a->model.ntried; i++) {
            size_t l = strlen(buf);
            snprintf(buf + l, sizeof(buf) - l, "%s\n", a->model.tried[i]);
        }
        copy_text(a, buf, "Copied");
    } else if (!strcmp(act->name, "node.copy")) {
        zw_diagnostics(&a->model, buf, sizeof(buf));
        copy_text(a, buf, "Copied");
    } else {
        zw_log("unhandled action %s", act->name);
    }
}

static void write_shot(struct app *a, const char *path)
{
    render(a);
    struct gui_cpu_frame f;
    if (!gui_cpu_acquire(a->win, &f) || !gui_frame_write_png(&f, path)) {
        zw_log("could not write screenshot %s", path);
        a->exit_code = 4;
        return;
    }
    uint8_t h[32];
    gui_frame_sha3(&f, h);
    zw_log("shot %s %dx%d sha3=%02x%02x%02x%02x%02x%02x%02x%02x", path, f.width, f.height, h[0],
           h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
}

static void on_key(struct app *a, const struct gui_event *ev)
{
    if (!ev->key.down) return;
    if (ev->key.key == GUI_KEY_F5) refresh_now(a);
    else if ((ev->mods & GUI_MOD_CTRL) && ev->key.key == GUI_KEY_1) set_screen(a, ZW_SCREEN_HOME);
    else if ((ev->mods & GUI_MOD_CTRL) && ev->key.key == GUI_KEY_2) set_screen(a, ZW_SCREEN_NODE);
}

static void on_timer(struct app *a, uint32_t id)
{
    switch (id) {
    case T_POLL: poll_tick(a); break;
    case T_BLINK: gui_ui_blink(a->ui); break;
    case T_TOAST: (void)gui_ui_tick(a->ui); break;
    case T_SHOT:
        write_shot(a, a->o->shot);
        if (a->o->exit_after_shot || a->exit_code) a->running = false;
        break;
    case T_QA:
        gui_ui_mark_rect(a->ui, (struct gui_rect){ 0, 0, a->ui->w, a->ui->h });
        if (a->frames >= a->o->qa_frames) a->running = false;
        break;
    case T_BENCH:
        if (a->o->bench[0]) zw_bench_write(a->o->bench, &a->bench);
        break;
    default: break;
    }
}

static void handle_event(struct app *a, const struct gui_event *ev)
{
    struct gui_action act;
    switch (ev->type) {
    case GUI_EV_CLOSE: a->running = false; return;
    case GUI_EV_TIMER: on_timer(a, ev->timer.id); return;
    case GUI_EV_WAKE: drain(a); return;
    case GUI_EV_KEY: on_key(a, ev); break;
    default: break;
    }
    if (gui_ui_event(a->ui, ev, &act)) dispatch(a, &act);
    gui_window_set_cursor(a->win, gui_ui_cursor(a->ui));
    bool blink = gui_ui_wants_blink(a->ui), blinking = a->blinking;
    if (blink && !blinking) gui_window_timer_set(a->win, T_BLINK, 530, true);
    if (!blink && blinking) gui_window_timer_cancel(a->win, T_BLINK);
    a->blinking = blink;
    if (a->ui->toast[0]) gui_window_timer_set(a->win, T_TOAST, 3100, false);
}

/* Run until the worker is idle and no event is queued (headless settling). */
static void settle(struct app *a)
{
    struct gui_event ev;
    for (int guard = 0; guard < 4000; guard++) {
        gui_headless_set_hold(a->win, zw_worker_busy(a->worker));
        bool got = gui_window_wait(a->win, 0, &ev);
        if (got) {
            handle_event(a, &ev);
            render(a);
            continue;
        }
        if (!zw_worker_busy(a->worker)) break;
        if (gui_window_wait(a->win, 5, &ev)) {
            handle_event(a, &ev);
            render(a);
        }
    }
    gui_headless_set_hold(a->win, false);
    render(a);
}

static int run_script(struct app *a)
{
    FILE *f = zw_fopen_read(a->o->script);
    if (!f) { zw_log("cannot open script %s", a->o->script); return 2; }
    char *text = malloc(1 << 20);
    size_t n = text ? fread(text, 1, (1 << 20) - 1, f) : 0;
    fclose(f);
    char err[128] = "";
    struct gui_script *s = text ? gui_headless_script_load(text, n, err, sizeof(err)) : NULL;
    free(text);
    if (!s) { zw_log("%s", err[0] ? err : "script load failed"); return 2; }
    char name[64], path[ZW_PATH + 80];
    settle(a);
    enum gui_script_step st;
    while ((st = gui_headless_script_step(a->win, s, name, sizeof(name))) != GUI_SCRIPT_DONE) {
        settle(a);
        if (st == GUI_SCRIPT_SHOT) {
            snprintf(path, sizeof(path), "%s/%s.png", a->o->shot_dir[0] ? a->o->shot_dir : ".", name);
            write_shot(a, path);
        }
    }
    gui_headless_script_free(s);
    return a->exit_code;
}

static bool open_window(struct app *a, char *err, size_t cap)
{
    struct gui_window_desc d = { .title_utf8 = "Z23 Wallet", .width = a->o->width,
        .height = a->o->height, .min_width = 640, .min_height = 420,
        .flags = GUI_WINDOW_RESIZABLE, .surface = GUI_SURFACE_CPU, .backend = a->o->backend };
    if (!gui_window_open(&d, &a->win, err, cap)) return false;
    if (a->o->backend == GUI_BACKEND_HEADLESS && a->o->scale > 0.0f)
        gui_headless_set_size(a->win, (int32_t)((float)a->o->width * a->o->scale + 0.5f),
                              (int32_t)((float)a->o->height * a->o->scale + 0.5f), a->o->scale);
    return true;
}

static int loop(struct app *a)
{
    struct gui_event ev;
    a->running = true;
    if (a->o->shot[0] && !a->o->script[0]) gui_window_timer_set(a->win, T_SHOT, (uint32_t)a->o->shot_after_ms, false);
    if (a->o->qa_frames > 0) gui_window_timer_set(a->win, T_QA, 30, true);
    if (a->o->bench[0]) gui_window_timer_set(a->win, T_BENCH, 3000, true);
    while (a->running) {
        gui_headless_set_hold(a->win, zw_worker_busy(a->worker));
        if (!gui_window_wait(a->win, -1, &ev)) continue;
        handle_event(a, &ev);
        render(a);
    }
    return a->exit_code;
}

int zw_app_run(const struct zw_options *o)
{
    struct app a;
    memset(&a, 0, sizeof(a));
    a.o = o;
    char err[160];
    zw_model_init(&a.model);
    if (!open_window(&a, err, sizeof(err))) {
        zw_log("cannot open a window: %s", err);
        return 3;
    }
    a.tree = gui_tree_new();
    a.ui = a.tree ? gui_ui_new(a.tree) : NULL;
    a.worker = a.ui ? zw_worker_start(a.win, o) : NULL;
    if (!a.worker) {
        zw_log("cannot start (out of memory or thread failure)");
        gui_ui_free(a.ui);
        gui_tree_free(a.tree);
        gui_window_close(a.win);
        return 3;
    }
    gui_ui_set_window(a.ui, a.win);
    a.model_dirty = true;
    render(&a);
    enqueue_all(&a);
    gui_window_timer_set(a.win, T_POLL, POLL_SYNCED_MS, false);
    int rc = o->script[0] ? run_script(&a) : loop(&a);
    if (o->bench[0]) zw_bench_write(o->bench, &a.bench);
    zw_worker_stop(a.worker);
    gui_ui_free(a.ui);
    gui_tree_free(a.tree);
    gui_window_close(a.win);
    return rc;
}
