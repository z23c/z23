/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: window open, the event loop, result drain, action dispatch,
 * poll scheduling, the first-result watchdog, menus, scripted headless
 * sessions, --shot and --bench. The UI thread never blocks on node I/O: it
 * waits on the window with deadlines. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zw.h"
#include "zw_send.h"

enum { T_POLL = 1, T_BLINK, T_MSG, T_SHOT, T_QA, T_BENCH, T_WATCHDOG };

#define POLL_SYNCED_MS 10000
#define POLL_SYNCING_MS 2000
#define WALLET_REFRESH_MS 30000
#define NET_EVERY_POLLS 3
#define INFO_EVERY_POLLS 6
#define WATCHDOG_MS 6000
#define MSG_MS 3000
#define NARROW_CONTENT_PX 820

struct app {
    const struct zw_options *o;
    struct gui_window *win;
    struct gui_tree *tree;
    struct gui_ui *ui;
    struct zw_model model;
    struct zw_worker *worker;
    struct zw_bench bench;
    size_t screen;
    uint32_t key, send_key;
    bool blinking, have_key, running, need_wallet, was_online, bench_data, model_dirty, watchdog_armed;
    int polls;
    int64_t last_wallet_ns;
    int frames;
    int exit_code;
};

static int64_t wall_s(void) { return (int64_t)time(NULL); }
static void home_shield(struct app *a, const char *issued);
static void set_screen(struct app *a, size_t s);
static bool shield_snapshot(struct app *a);

static bool rebuild(struct app *a)
{
    uint32_t key = zw_structure_key(&a->model, a->screen);
    uint32_t skey = a->screen == ZW_SCREEN_SEND ? zw_send_structure_key(a->model.send) : 0;
    if (a->have_key && key == a->key && skey == a->send_key) return true;
    char err[96];
    zw_shell_build(a->tree, &a->model, a->screen);
    if (!gui_tree_end(a->tree, err, sizeof(err))) {
        zw_log("screen build failed: %s", err);
        return false;
    }
    a->key = key;
    a->send_key = skey;
    a->have_key = true;
    gui_ui_rebind(a->ui);
    return true;
}

/* Groups stack when the page is narrower than 820 logical px. */
static void update_narrow(struct app *a, int32_t w, float sc)
{
    int32_t content = (int32_t)((float)w / (sc > 0.0f ? sc : 1.0f)) - 168 - 24;
    bool narrow = content < NARROW_CONTENT_PX;
    if (narrow != a->model.narrow) {
        a->model.narrow = narrow;
        a->model_dirty = true;
    }
}

static struct zw_send_env send_env(struct app *a)
{
    return (struct zw_send_env){ a->win, a->ui, &a->model, a->o, wall_s() };
}

static void render(struct app *a)
{
    int32_t w, h;
    float sc;
    gui_window_size(a->win, &w, &h, &sc);
    update_narrow(a, w, sc);
    if (a->screen == ZW_SCREEN_SEND && a->model.send) { /* mirror the fields; derive the page */
        struct zw_send_env env = send_env(a);
        a->model.now_s = env.now_s;
        if (zw_send_sync(a->model.send, &env)) a->model_dirty = true;
    }
    if (a->model_dirty) {
        a->model.now_s = wall_s();
        rebuild(a);
        zw_model_publish(&a->model, a->ui, a->model.now_s);
        a->model_dirty = false;
    }
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

static void arm_watchdog(struct app *a)
{
    if (a->watchdog_armed) return;
    gui_window_timer_set(a->win, T_WATCHDOG, WATCHDOG_MS, false);
    a->watchdog_armed = true;
}

static void enqueue(struct app *a, enum zw_query q)
{
    zw_worker_enqueue(a->worker, q, a->model.generation);
    arm_watchdog(a);
}

static void enqueue_all(struct app *a)
{
    for (enum zw_query q = 0; q < ZW_Q_COUNT; q++) enqueue(a, q);
    a->last_wallet_ns = (int64_t)gui_now_ns();
}

static uint32_t poll_delay_ms(const struct app *a)
{
    const struct zw_model *m = &a->model;
    if (m->conn == ZW_CONN_WARMING) return 1000;
    if (m->conn != ZW_CONN_ONLINE) return zw_backoff_s(m->fail_count) * 1000u;
    return m->have_chain && m->chain.blocks + 1 < m->chain.headers ? POLL_SYNCING_MS : POLL_SYNCED_MS;
}

static void page_poll(struct app *a)
{
    switch (a->screen) {
    case ZW_SCREEN_SEND: zw_q_send_poll(a->worker, &a->model); break;
    case ZW_SCREEN_RECEIVE: zw_q_receive_poll(a->worker, &a->model); break;
    case ZW_SCREEN_ACTIVITY: zw_q_activity_poll(a->worker, &a->model); break;
    default: break;
    }
}

static void poll_tick(struct app *a)
{
    struct zw_model *m = &a->model;
    enqueue(a, ZW_Q_CHAIN);
    if (m->conn == ZW_CONN_ONLINE) {
        int k = a->polls++;
        if (k % NET_EVERY_POLLS == 0 || !m->have_net) enqueue(a, ZW_Q_NET);
        if (k % INFO_EVERY_POLLS == 0 || !m->have_info) enqueue(a, ZW_Q_INFO);
        bool stale = (int64_t)gui_now_ns() - a->last_wallet_ns >= (int64_t)WALLET_REFRESH_MS * 1000000;
        if (a->need_wallet || !m->have_wallet || !m->bal || stale) {
            enqueue(a, ZW_Q_WALLET);
            enqueue(a, ZW_Q_BALANCES);
            a->last_wallet_ns = (int64_t)gui_now_ns();
            a->need_wallet = false;
        }
        page_poll(a);
    }
    gui_window_timer_set(a->win, T_POLL, poll_delay_ms(a), false);
}

static void wallet_handover(struct app *a)
{
    free(a->model.rcv.list);
    a->model.rcv.list = NULL;
    a->model.rcv.fresh = false;
    zw_send_cancel_review(a->model.send, a->ui);
}

static void drain_result(struct app *a, struct zw_result *r)
{
    int64_t before = a->model.chain.blocks;
    bool ok = r->err == ZW_OK;
    enum zw_query kind = r->kind;
    bool current = r->generation == a->model.generation;
    uint32_t generation = a->model.generation;
    uint16_t port = a->model.port;
    enum zw_profile profile = a->model.profile;
    char datadir[ZW_PATH];
    snprintf(datadir, sizeof(datadir), "%s", a->model.datadir);
    if (!ok) zw_log("query %d failed: kind=%d code=%d", (int)kind, (int)r->err, r->rpc.code);
    if (zw_model_apply(&a->model, r)) a->model_dirty = true;
    if (generation != a->model.generation || port != a->model.port || profile != a->model.profile ||
        strcmp(datadir, a->model.datadir)) {
        wallet_handover(a);
    }
    if (current && generation == a->model.generation && ok && kind == ZW_Q_BALANCES) {
        a->model.rcv.fresh = true;
        (void)shield_snapshot(a);
    }
    if (!ok) return;
    a->model.last_update_s = wall_s();
    if (kind == ZW_Q_CHAIN && a->model.chain.blocks != before) a->need_wallet = true;
    if (!a->bench_data) {
        a->bench_data = true;
        a->bench.first_data_ms = zw_process_age_ms() - a->bench.first_frame_ms;
    }
}

static void drain(struct app *a)
{
    struct zw_result *r = malloc(16 * sizeof(*r));
    if (!r) { zw_log("drain: out of memory"); return; }
    size_t n, total = 0;
    while ((n = zw_worker_drain(a->worker, r, 16)) > 0)
        for (size_t i = 0; i < n; i++, total++) drain_result(a, &r[i]);
    free(r);
    if (total) { /* a result arrived: the watchdog restarts only if work is still queued */
        gui_window_timer_cancel(a->win, T_WATCHDOG);
        a->watchdog_armed = false;
        if (zw_worker_busy(a->worker)) arm_watchdog(a);
    }
    bool online = a->model.conn == ZW_CONN_ONLINE;
    if (online && !a->was_online) { /* came back: refetch everything */
        a->need_wallet = true;
        enqueue(a, ZW_Q_NET);
        enqueue(a, ZW_Q_INFO);
        enqueue(a, ZW_Q_WALLET);
        enqueue(a, ZW_Q_BALANCES);
    }
    a->was_online = online;
    gui_window_timer_set(a->win, T_POLL, poll_delay_ms(a), false);
}

/* R9: the worker made no progress (no node call finished) for 6 s: a stuck worker or a lost
 * wake. A job of several calls, each with its own 5 s deadline, keeps making progress and
 * is left alone; the timer is re-armed for what remains of the window. */
static void watchdog_fired(struct app *a)
{
    a->watchdog_armed = false;
    if (!zw_worker_busy(a->worker)) return;
    uint32_t left = zw_watchdog_remaining_ms(zw_worker_stall_ms(a->worker), WATCHDOG_MS);
    if (left) {
        gui_window_timer_set(a->win, T_WATCHDOG, left, false);
        a->watchdog_armed = true;
        return;
    }
    char line[160];
    zw_watchdog_line(zw_worker_phase(a->worker), zw_worker_port(a->worker), line, sizeof(line));
    zw_log("%s", line);
    zw_model_watchdog(&a->model, zw_worker_port(a->worker));
    zw_worker_restart(a->worker);
    wallet_handover(a);
    enqueue_all(a);
    a->model_dirty = true;
}

static void show_msg(struct app *a, const char *text)
{
    snprintf(a->model.msg, sizeof(a->model.msg), "%s", text);
    gui_window_timer_set(a->win, T_MSG, MSG_MS, false);
    a->model_dirty = true;
}

static void copy_text(struct app *a, const char *s, const char *msg)
{
    show_msg(a, gui_clipboard_set_text(a->win, s, strlen(s)) ? msg : "Couldn't copy. Try again.");
}

/* What a Send action or send result asks of the window. */
static void send_apply(struct app *a, const struct zw_send_out *out)
{
    if (out->dirty) a->model_dirty = true;
    if (out->msg_set) {
        snprintf(a->model.msg, sizeof(a->model.msg), "%s", out->msg);
        if (out->msg_ms) gui_window_timer_set(a->win, T_MSG, out->msg_ms, false);
        else gui_window_timer_cancel(a->win, T_MSG); /* the message stays */
        a->model_dirty = true;
    }
    if (out->refresh) {
        a->need_wallet = true;
        enqueue(a, ZW_Q_WALLET);
        enqueue(a, ZW_Q_BALANCES);
    }
}

static void send_action(struct app *a, const char *name)
{
    struct zw_send_out out;
    struct zw_send_env env = send_env(a);
    a->model.now_s = env.now_s;
    zw_send_action(a->model.send, &env, name, &out);
    send_apply(a, &out);
}

static void send_wake(struct app *a)
{
    struct zw_send_out out = { .dirty = false };
    struct zw_send_env env = send_env(a);
    zw_send_wake(a->model.send, &env, &out);
    send_apply(a, &out);
}

static bool shield_snapshot(struct app *a)
{
    if (!a->model.rcv.fresh) {
        free(a->model.rcv.list);
        a->model.rcv.list = NULL;
        return false;
    }
    struct zw_balances *list = a->model.bal ? malloc(sizeof(*list)) : NULL;
    if (a->model.bal && !list) {
        free(a->model.rcv.list);
        a->model.rcv.list = NULL;
        return false;
    }
    if (list) *list = *a->model.bal;
    free(a->model.rcv.list);
    a->model.rcv.list = list;
    return list != NULL;
}

static void home_shield(struct app *a, const char *issued)
{
    (void)shield_snapshot(a);
    struct zw_send_env env = send_env(a);
    switch (zw_send_home_shield(a->model.send, &env, issued)) {
    case ZW_SHIELD_READ:
        enqueue(a, ZW_Q_BALANCES);
        show_msg(a, "Loading your shielded addresses. Try shielding again in a moment.");
        break;
    case ZW_SHIELD_WAIT:
        show_msg(a, "ZClassic is still getting ready. Try shielding again in a moment.");
        break;
    case ZW_SHIELD_CREATE:
        show_msg(a, "Shielding needs a Sapling address in the wallet.");
        break;
    case ZW_SHIELD_BUSY:
        show_msg(a, "Finish or clear your existing payment before preparing a shielding draft.");
        break;
    default:
        set_screen(a, ZW_SCREEN_SEND);
        break;
    }
}

static void set_screen(struct app *a, size_t s)
{
    if (s >= ZW_SCREEN_COUNT || s == a->screen) return;
    if (s == ZW_SCREEN_ADVANCED && a->model.conn != ZW_CONN_ONLINE) { /* the rail check snaps back */
        show_msg(a, "Advanced (node stats) opens once you're connected to a node.");
        return;
    }
    if (a->screen == ZW_SCREEN_SEND) zw_send_cancel_review(a->model.send, a->ui);
    a->screen = s;
    a->model.menu = ZW_MENU_NONE;
    a->model_dirty = true;
    page_poll(a);
}

static void refresh_now(struct app *a)
{
    a->model.generation++;
    wallet_handover(a);
    enqueue_all(a);
}

static void set_menu(struct app *a, enum zw_menu m)
{
    a->model.menu = a->model.menu == m ? ZW_MENU_NONE : m;
    a->model_dirty = true;
}

static void copy_details(struct app *a)
{
    char buf[ZW_TRIED_MAX * (ZW_PATH + 64) + 64];
    size_t o = 0;
    buf[0] = 0;
    for (size_t i = 0; i < a->model.report.ntried && o < sizeof(buf); i++)
        o += (size_t)snprintf(buf + o, sizeof(buf) - o, "%s - %s\n", a->model.report.tried[i].path,
                              a->model.report.tried[i].reason);
    if (!o) zw_connect_text(&a->model, buf, sizeof(buf));
    copy_text(a, buf, "Copied to clipboard");
}

static bool dispatch_row(struct app *a, const struct gui_action *act)
{
    char addr[100];
    if (!strcmp(act->name, "home.balances.menu")) {
        if (!zw_home_row_address(&a->model, act->row, addr, sizeof(addr))) return true;
        a->model.menu = ZW_MENU_ROW;
        a->model.menu_row = act->row;
        a->model_dirty = true;
    } else if (!strcmp(act->name, "row.copy")) {
        if (zw_home_row_address(&a->model, a->model.menu_row, addr, sizeof(addr)))
            copy_text(a, addr, "Copied to clipboard");
        a->model.menu = ZW_MENU_NONE;
    } else if (!strcmp(act->name, "row.send") || !strcmp(act->name, "home.balances.open")) {
        int64_t row = !strcmp(act->name, "row.send") ? a->model.menu_row : act->row;
        a->model.menu = ZW_MENU_NONE;
        a->model_dirty = true;
        if (a->model.send && zw_home_row_address(&a->model, row, addr, sizeof(addr)))
            zw_send_prefill_from(a->model.send, addr); /* "Send from <address>" */
        set_screen(a, ZW_SCREEN_SEND);
    } else {
        return false;
    }
    return true;
}

static bool dispatch_menu(struct app *a, const char *name)
{
    if (!strcmp(name, "menu.file")) set_menu(a, ZW_MENU_FILE);
    else if (!strcmp(name, "menu.edit")) set_menu(a, ZW_MENU_EDIT);
    else if (!strcmp(name, "menu.help")) set_menu(a, ZW_MENU_HELP);
    else if (!strcmp(name, "menu.close") || !strcmp(name, "menu.none")) set_menu(a, ZW_MENU_NONE);
    else if (!strcmp(name, "app.exit")) a->running = false;
    else if (!strcmp(name, "help.about")) { a->model.menu = ZW_MENU_NONE; a->model.about_open = true; a->model_dirty = true; }
    else if (!strcmp(name, "about.close")) { a->model.about_open = false; a->model_dirty = true; }
    else return false;
    return true;
}

static void dispatch(struct app *a, const struct gui_action *act)
{
    char buf[1200];
    if (!strncmp(act->name, "nav.", 4)) set_screen(a, zw_screen_by_name(act->name + 4));
    else if (!strncmp(act->name, "send.", 5)) send_action(a, act->name);
    else if (dispatch_menu(a, act->name) || dispatch_row(a, act)) return;
    else if (!strcmp(act->name, "home.send")) set_screen(a, ZW_SCREEN_SEND);
    else if (!strcmp(act->name, "home.receive")) set_screen(a, ZW_SCREEN_RECEIVE);
    else if (!strcmp(act->name, "home.shield")) home_shield(a, NULL);
    else if (!strcmp(act->name, "connect.retry")) {
        zw_worker_reset_auth(a->worker);
        a->model.fail_count = 0;
        refresh_now(a);
    } else if (!strcmp(act->name, "connect.copy")) copy_details(a);
    else if (!strcmp(act->name, "node.copy")) {
        zw_diagnostics(&a->model, buf, sizeof(buf));
        copy_text(a, buf, "Copied to clipboard");
    } else zw_log("unhandled action %s", act->name);
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
    enum gui_key k = ev->key.key;
    if (k == GUI_KEY_F5) refresh_now(a);
    else if ((ev->mods & GUI_MOD_CTRL) && k >= GUI_KEY_1 && k < GUI_KEY_1 + ZW_SCREEN_COUNT)
        set_screen(a, (size_t)(k - GUI_KEY_1));
    else if ((ev->mods & GUI_MOD_ALT) && k == GUI_KEY_F) set_menu(a, ZW_MENU_FILE);
    else if ((ev->mods & GUI_MOD_ALT) && k == GUI_KEY_E) set_menu(a, ZW_MENU_EDIT);
    else if ((ev->mods & GUI_MOD_ALT) && k == GUI_KEY_H) set_menu(a, ZW_MENU_HELP);
}

static void on_timer(struct app *a, uint32_t id)
{
    switch (id) {
    case T_POLL: poll_tick(a); break;
    case T_BLINK: gui_ui_blink(a->ui); break;
    case T_MSG: a->model.msg[0] = 0; a->model_dirty = true; break;
    case T_WATCHDOG: watchdog_fired(a); break;
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
    case GUI_EV_WAKE: drain(a); send_wake(a); return;
    case GUI_EV_KEY: on_key(a, ev); break;
    default: break;
    }
    if (gui_ui_event(a->ui, ev, &act)) dispatch(a, &act);
    gui_window_set_cursor(a->win, gui_ui_cursor(a->ui));
    bool blink = gui_ui_wants_blink(a->ui), blinking = a->blinking;
    if (blink && !blinking) gui_window_timer_set(a->win, T_BLINK, 530, true);
    if (!blink && blinking) gui_window_timer_cancel(a->win, T_BLINK);
    a->blinking = blink;
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
    struct gui_window_desc d = { .title_utf8 = "Z23 Wallet v" ZW_VERSION, .width = a->o->width,
        .height = a->o->height, .min_width = 640, .min_height = 420,
        .flags = GUI_WINDOW_RESIZABLE, .surface = GUI_SURFACE_CPU, .backend = a->o->backend };
    if (!gui_window_open(&d, &a->win, err, cap)) return false;
    if (a->o->backend == GUI_BACKEND_HEADLESS && a->o->scale > 0.0f)
        gui_headless_set_size(a->win, (int32_t)((float)a->o->width * a->o->scale + 0.5f),
                              (int32_t)((float)a->o->height * a->o->scale + 0.5f), a->o->scale);
    return true;
}

/* While Windows owns the thread in its border-drag loop the main loop below does
 * not run; the backend calls this every ~16 ms and on every size change so the
 * window keeps rendering at its live size and the app timers keep firing. */
static void live_tick(void *user)
{
    struct app *a = user;
    struct gui_event ev;
    for (int guard = 0; guard < 64 && a->running && gui_window_wait(a->win, 0, &ev); guard++)
        handle_event(a, &ev);
    render(a);
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

/* One closing line for logs and agents: where the window ended up. Never a
 * balance or an address. */
static void log_exit(const struct app *a)
{
    zw_log("exit: screen=%s conn=%d node=%s status=\"%s\"", zw_screens[a->screen].name, (int)a->model.conn,
           zw_node_kind(&a->model), gui_ui_get(a->ui, "status.label"));
    static const char *const ids[] = { "menubar", "rail", "nav_home", "h_summary", "h_hero", "h_send",
                                       "h_addrs", "h_balances", "statusbar", "status_label" };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        int at = gui_tree_find(a->tree, ids[i]);
        if (at < 0) continue;
        struct gui_rect r = a->tree->nodes[at].frame;
        zw_log("layout: %s %d %d %d %d", ids[i], r.x, r.y, r.w, r.h);
    }
}

int zw_app_run(const struct zw_options *o)
{
    struct app *a = calloc(1, sizeof(*a));
    if (!a) return 3;
    a->o = o;
    char err[160];
    zw_model_init(&a->model, o->profile);
    a->model.send = zw_send_new(); /* NULL: the Send page says it is unavailable */
    if (!open_window(a, err, sizeof(err))) {
        zw_log("cannot open a window: %s", err);
        free(a);
        return 3;
    }
    a->tree = gui_tree_new();
    a->ui = a->tree ? gui_ui_new(a->tree) : NULL;
    a->worker = a->ui ? zw_worker_start(a->win, o) : NULL;
    if (!a->worker) {
        zw_log("cannot start (out of memory or thread failure)");
        gui_ui_free(a->ui);
        gui_tree_free(a->tree);
        gui_window_close(a->win);
        free(a);
        return 3;
    }
    gui_ui_set_window(a->ui, a->win);
    gui_window_set_live_hook(a->win, live_tick, a);
    zw_home_sources(a->ui, &a->model);
    a->model_dirty = true;
    render(a);
    enqueue_all(a);
    gui_window_timer_set(a->win, T_POLL, POLL_SYNCED_MS, false);
    int rc = o->script[0] ? run_script(a) : loop(a);
    if (o->bench[0]) zw_bench_write(o->bench, &a->bench);
    log_exit(a);
    gui_window_set_live_hook(a->win, NULL, NULL);
    zw_worker_stop(a->worker); /* joins: nothing touches the window after this line */
    zw_send_free(a->model.send); /* joins a send runner the same way */
    a->model.send = NULL;
    gui_ui_free(a->ui);
    gui_tree_free(a->tree);
    gui_window_close(a->win);
    free(a->model.rcv.list);
    a->model.rcv.list = NULL;
    zw_model_free(&a->model);
    free(a);
    return rc;
}
