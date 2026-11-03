/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "wallet_send_ui.h"
#include "base/cleanse.h"
#include "controller.h"
#include "device_key.h"
#include "home.h"
#include "jni_util.h"
#include "node_service.h"
#include "scan.h"
#include "send_key.h"
#include "secure_window.h"
#include "setup_field.h"
#include "wallet_send_device.h"
#include "wallet_send_keeper.h"
#include "wallet_reveal.h"
#include "wallet_send_node.h"
#include "wallet_sweep.h"
#include "wallet_view.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#define MATCH (-1)
#define WRAP (-2)
#define WHITE 0xffffffffu
#define SOFT 0xffd0d0d0u
#define AMBER 0xffe8b04cu
#define BUTTON_COLOR 0xff2b2b2bu
#define SEND_COLOR 0xff1f6f3fu
#define MEMO_PANEL 0xff1c2430u
#define INPUT_TYPE_DECIMAL 8194          /* TYPE_CLASS_NUMBER | TYPE_NUMBER_FLAG_DECIMAL */
#define INPUT_TYPE_ADDRESS 0x80001       /* TYPE_CLASS_TEXT | TYPE_TEXT_FLAG_NO_SUGGESTIONS */
#define IME_NO_LEARNING 0x1000000        /* IME_FLAG_NO_PERSONALIZED_LEARNING */
#define GRAVITY_CENTER_HORIZONTAL 1
#define BUTTONS_MAX 8
#define TEXT_CAP (ZAPP_PAY_INPUT_MAX + 1)

enum button { B_SEND, B_CANCEL, B_RETRY, B_DONE, B_SCAN, B_ENTER, B_USE_ADDRESS, B_SET_AMOUNT, B_PAY_AGAIN };

static struct {
    ANativeActivity *activity;
    JavaVM *vm;
    jobject app, key_app, notify_app, container, address_input, amount_input, buttons[BUTTONS_MAX];
    pthread_mutex_t key_lock;   /* guards key_app, which a worker reads while the activity is replaced */
    enum button button_id[BUTTONS_MAX];
    size_t button_count;
    struct wsk keeper;
    void (*changed)(void);
    bool flow;       /* a payment is open on the screen and has not been left */
    bool entering;   /* the address field is shown */
    bool dropped;    /* a tap was dropped because another window covered the app */
    char notice[WSS_LINE];
    char hint[WSS_LINE];
    char final_line[WSS_LINE];   /* the outcome of a payment that ended while the owner was away from this screen */
    bool away;    /* the owner left the screen while the payment was in flight */
    bool moved;   /* the shell was told once to go to the wallet for this payment */
    unsigned version, drawn_version;
    struct wss_view drawn;
    bool is_drawn;
} ui;

/* ---- the host: clock, random bytes and a JVM-attached worker ---- */

static bool host_random(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    size_t got = 0;
    while (got < len) {
        ssize_t n = getrandom(out + got, len - got, 0);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}
static uint64_t host_now(void *ctx)
{
    struct timespec at;
    (void)ctx;
    clock_gettime(CLOCK_MONOTONIC, &at);
    return (uint64_t)at.tv_sec * 1000u + (uint64_t)at.tv_nsec / 1000000u;
}
static int64_t host_wall(void *ctx)
{
    (void)ctx;
    return (int64_t)time(NULL);
}
static void host_redraw(void *ctx)
{
    (void)ctx;
    if (ui.changed) ui.changed();
}

/* The worker's JNIEnv: the keystore calls need the environment of the thread that makes them, and only a worker
 * that this file attached has one. */
static _Thread_local JNIEnv *worker_env;
static _Thread_local struct zapp_devkey_jni worker_key;
struct launch { void (*job)(void *arg); void *arg; };
static void *worker_main(void *raw)
{
    struct launch launch = *(struct launch *)raw;
    JNIEnv *env = NULL;
    free(raw);
    bool attached = ui.vm && (*ui.vm)->AttachCurrentThread(ui.vm, &env, NULL) == JNI_OK;
    worker_env = attached ? env : NULL;
    launch.job(launch.arg);
    worker_env = NULL;
    if (attached) (*ui.vm)->DetachCurrentThread(ui.vm);
    return NULL;
}
static bool host_spawn(void *ctx, void (*job)(void *arg), void *arg)
{
    pthread_t thread;
    struct launch *launch = malloc(sizeof(*launch));
    (void)ctx;
    if (!launch) return false;
    *launch = (struct launch){job, arg};
    if (pthread_create(&thread, NULL, worker_main, launch) != 0) { free(launch); return false; }
    (void)pthread_detach(thread);
    return true;
}
static bool key_ops(void *ctx, struct zapp_devkey_ops *out)
{
    (void)ctx;
    if (!worker_env) return false;
    /* The worker takes its own reference, so replacing the activity cannot free the one it is using. */
    pthread_mutex_lock(&ui.key_lock);
    jobject app = ui.key_app ? (*worker_env)->NewLocalRef(worker_env, ui.key_app) : NULL;
    pthread_mutex_unlock(&ui.key_lock);
    if (!app) return false;
    worker_key = (struct zapp_devkey_jni){worker_env, app};
    zapp_devkey_jni_ops(out, &worker_key);
    return true;
}
static bool node_run(void *ctx, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap)
{
    (void)ctx;
    return zapp_controller_send_run(op, input, timeout_ms, out, cap);
}
static bool node_paused(void *ctx)
{
    (void)ctx;
    return zapp_controller_node_paused();
}

/* Whether the node can prove a payment, re-checked off the UI thread because the check asks the node. The Send button
 * appears only when it says ready; the result reaches the screen through the redraw. */
#define GATE_RECHECK_MS 15000u
static struct { pthread_mutex_t lock; bool known, ready, running; unsigned gen; char why[WSS_LINE]; uint64_t at_ms; } gate = {.lock = PTHREAD_MUTEX_INITIALIZER};
static void gate_job(void *arg)
{
    char why[WSS_LINE] = "";
    bool ready = zapp_controller_prover_ready(why, sizeof(why));
    pthread_mutex_lock(&gate.lock);
    /* An answer asked for before the payment changed is not this payment's answer. */
    gate.known = gate.gen == (unsigned)(uintptr_t)arg;
    gate.ready = ready;
    gate.running = false;
    gate.at_ms = host_now(NULL);
    snprintf(gate.why, sizeof(gate.why), "%s", why);
    pthread_mutex_unlock(&gate.lock);
    host_redraw(NULL);
}
/* Starts a check when the review waits for an answer, or the last one is old. */
static void gate_poll(void)
{
    pthread_mutex_lock(&gate.lock);
    bool start = !gate.running && (!gate.known || !gate.ready || host_now(NULL) - gate.at_ms >= GATE_RECHECK_MS);
    unsigned gen = gate.gen;
    if (start) gate.running = true;
    pthread_mutex_unlock(&gate.lock);
    if (start && !host_spawn(NULL, gate_job, (void *)(uintptr_t)gen)) {
        pthread_mutex_lock(&gate.lock);
        gate.running = false;
        pthread_mutex_unlock(&gate.lock);
    }
}
/* Every payment starts unknown and asks afresh. */
static void gate_reset(void)
{
    pthread_mutex_lock(&gate.lock);
    gate.known = gate.ready = false;
    gate.gen++;
    pthread_mutex_unlock(&gate.lock);
}
static bool gate_ready(void)
{
    pthread_mutex_lock(&gate.lock);
    bool ready = gate.known && gate.ready;
    pthread_mutex_unlock(&gate.lock);
    return ready;
}
static void gate_apply(struct wss_view *v)
{
    pthread_mutex_lock(&gate.lock);
    bool ready = gate.known && gate.ready;
    wss_gate_prover(v, ready, gate.known ? gate.why : "Checking that sending is ready.");
    pthread_mutex_unlock(&gate.lock);
}
/* A payment that reached the node ended: tell the owner, on a thread that may call Java. */
static void notify_job(void *arg)
{
    jobject app = NULL;
    if (!worker_env) return;
    pthread_mutex_lock(&ui.key_lock);
    if (ui.notify_app) app = (*worker_env)->NewLocalRef(worker_env, ui.notify_app);
    pthread_mutex_unlock(&ui.key_lock);
    if (!app) return;
    (void)zapp_payment_notify(worker_env, app, (int)(intptr_t)arg);
    (*worker_env)->DeleteLocalRef(worker_env, app);
}
static void host_outcome(void *ctx, int result)
{
    (void)host_spawn(ctx, notify_job, (void *)(intptr_t)result);
}

/* The ops of one flow live and die with its screen: a retired flow's worker keeps using them after the activity that
 * made them is gone, and a new screen never shares or resets them. */
struct parts {
    struct wsw node;
    struct wsd device;
    struct zapp_send_id id;   /* the wallet id the payment keys derive from */
    bool id_ok;
    struct wss *screen;       /* the flow this ops set serves; set once the screen exists */
};

/* The payment in flight. zapp_send_busy reads it from any thread; the flow's redraw writes it under send_busy_lock, so
 * the last write carries the latest state of the flow. */
static atomic_bool send_busy;
static pthread_mutex_t send_busy_lock = PTHREAD_MUTEX_INITIALIZER;
static void send_busy_update(struct wss *screen)
{
    struct wss_view v;
    pthread_mutex_lock(&send_busy_lock);
    wss_view(screen, &v);
    atomic_store(&send_busy, wss_send_busy(v.state));
    pthread_mutex_unlock(&send_busy_lock);
}
static bool host_derive(void *ctx, const struct zapp_payment *pay, char out[WS_KEY_HEX + 1])
{
    const struct parts *parts = ctx;
    return parts && parts->id_ok && zapp_send_key_derive(&parts->id, pay, out);
}
static void parts_release(void *ctx)
{
    pthread_mutex_lock(&send_busy_lock);
    atomic_store(&send_busy, false);
    pthread_mutex_unlock(&send_busy_lock);
    memory_cleanse(ctx, sizeof(struct parts));
    free(ctx);
}
/* The flow's redraw hook: the flag follows the flow's state, then the flow is drawn. */
static void flow_redraw(void *ctx)
{
    const struct parts *parts = ctx;
    if (parts && parts->screen) send_busy_update(parts->screen);
    host_redraw(ctx);
}
static struct wss *make_screen(void *ctx)
{
    struct wss_deps deps = {.network = ZAPP_SCAN_NETWORK};
    struct parts *parts = calloc(1, sizeof(*parts));
    (void)ctx;
    if (!parts || !ui.activity) { free(parts); return NULL; }
    wsw_init(&parts->node, &(struct wsn_runner){NULL, node_run, node_paused}, ZAPP_SCAN_NETWORK);
    wsw_ops(&parts->node, &deps.node);
    if (!wsd_init(&parts->device, NULL, key_ops, ui.activity->internalDataPath)) { free(parts); return NULL; }
    wsd_ops(&parts->device, &deps.device);
    parts->id_ok = zapp_send_id_load(ui.activity->internalDataPath, &parts->id);
    deps.host = (struct wss_host_ops){parts, host_random, host_now, host_spawn, flow_redraw, host_derive, host_wall, host_outcome};
    zapp_secure_window_ops(&deps.secure, ui.activity);
    deps.release = parts_release;
    deps.release_ctx = parts;
    struct wss *screen = wss_create(&deps);
    if (!screen) free(parts);
    else parts->screen = screen;
    return screen;
}
/* A flow adopted from the replaced activity is bound to this activity's window, and protected, before it is drawn. */
static void bind_screen(void *ctx, struct wss *screen)
{
    struct zapp_secure_ops secure;
    (void)ctx;
    if (!ui.activity) return;
    zapp_secure_window_ops(&secure, ui.activity);
    (void)wss_rebind(screen, &secure);
}
/* ---- the private balance on request ---- */

/* One view for the process, made on the first tap: it outlives the activity that asked, because the lock it owes is asked
 * for on the ticks that follow. It uses the node and the device key as a payment does, with ops of its own. */
static struct { struct wsn node; struct wsd device; struct wrv *view; } reveal;
static bool reveal_busy(void *ctx)
{
    (void)ctx;
    return zapp_send_busy();
}
static struct wrv *reveal_view(void)
{
    struct wrv_deps deps = {0};
    if (reveal.view) return reveal.view;
    if (!ui.activity) return NULL;
    wsn_init(&reveal.node, &(struct wsn_runner){NULL, node_run, node_paused}, ZAPP_SCAN_NETWORK);
    wsn_ops(&reveal.node, &deps.node);
    if (!wsd_init(&reveal.device, NULL, key_ops, ui.activity->internalDataPath)) return NULL;
    wsd_set_purpose(&reveal.device, ZAPP_DEVKEY_PURPOSE_UNLOCK);
    wsd_ops(&reveal.device, &deps.device);
    deps.host = (struct wss_host_ops){.random = host_random, .now_ms = host_now, .spawn = host_spawn, .redraw = host_redraw};
    deps.busy = reveal_busy;
    reveal.view = wrv_create(&deps);
    return reveal.view;
}
bool zapp_reveal_start(void)
{
    struct wrv *view = reveal_view();
    return view && wrv_begin(view);
}
enum wallet_reveal zapp_reveal_state(void) { return reveal.view ? wrv_state(reveal.view) : WALLET_REVEAL_NONE; }
void zapp_reveal_end(void)
{
    if (reveal.view) wrv_end(reveal.view);
}

static void wait_for_lock(void *ctx)
{
    struct timespec step = {.tv_nsec = 250000000L};
    (void)ctx;
    nanosleep(&step, NULL);
}

bool zapp_send_attach(ANativeActivity *activity, void (*changed)(void))
{
    if (!activity || ui.keeper.screen) return false;
    ui.activity = activity;
    ui.vm = activity->vm;
    ui.changed = changed;
    if (!ui.keeper.host.make) wsk_init(&ui.keeper, &(struct wsk_host){NULL, make_screen, wait_for_lock, bind_screen});
    if (!wsk_attach(&ui.keeper)) return false;
    /* A flow kept from the activity that was replaced is shown at once, with its progress or outcome. */
    if (ui.keeper.reshow) ui.flow = true;
    return true;
}
bool zapp_send_ui_take_reshow(void)
{
    bool reshow = ui.keeper.reshow;
    ui.keeper.reshow = false;
    return reshow;
}

void zapp_send_detach(JNIEnv *env)
{
    (void)env;
    wsk_detach(&ui.keeper);
    ui.flow = false;
    ui.activity = NULL;
}

/* ---- widgets ---- */

static bool text_view(JNIEnv *env, const char *text, float sp, uint32_t color)
{
    jobject view = zj_widget(env, "android/widget/TextView", ui.app);
    bool ok = view && zj_typography(env, view, sp, (jint)color) && zj_padding(env, view, 0, 6) && zj_text(env, view, text) &&
              zj_bool_property(env, view, "setTextIsSelectable", false) && zj_bool_property(env, view, "setLongClickable", false) &&
              zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 0, 0, 0) && zj_append(env, ui.container, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
/* Words written by another person, on a panel of their own so they cannot pass for a line the wallet wrote. */
static bool memo_view(JNIEnv *env, const char *text)
{
    jobject view = zj_widget(env, "android/widget/TextView", ui.app);
    bool ok = view && zj_typography(env, view, 14.0f, (jint)SOFT) && zj_pill(env, view, (jint)MEMO_PANEL, 8.0f) &&
              zj_padding(env, view, 12, 10) && zj_text(env, view, text) && zj_bool_property(env, view, "setTextIsSelectable", false) &&
              zj_bool_property(env, view, "setLongClickable", false) && zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 2, 0, 2) &&
              zj_append(env, ui.container, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool input_view(JNIEnv *env, const char *hint, int type, jobject *keep)
{
    jobject view = zj_widget(env, "android/widget/EditText", ui.app);
    bool ok = view && zj_typography(env, view, 18.0f, (jint)WHITE) && zj_int_property(env, view, "setInputType", type) &&
              zj_int_property(env, view, "setImeOptions", IME_NO_LEARNING) && zj_int_property(env, view, "setHintTextColor", (jint)0xff808080u) &&
              zj_char_sequence(env, view, "setHint", hint) && zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 8, 0, 0) &&
              zj_append(env, ui.container, view) && zj_keep(env, keep, view);
    if (view) {
        (void)zj_int_property(env, view, "setImportantForAutofill", ZAPP_FIELD_AUTOFILL_NO);
        (*env)->DeleteLocalRef(env, view);
    }
    return ok;
}
/* Send is the one button that moves money: the platform drops its touches while another window covers it, in addition to
 * the native filter of the shell. */
static bool button_view(JNIEnv *env, enum button id, const char *text, uint32_t color, bool filter_obscured)
{
    jobject view = zj_widget(env, "android/widget/Button", ui.app);
    bool ok = view && ui.button_count < BUTTONS_MAX && zj_typography(env, view, 16.0f, (jint)WHITE) &&
              zj_bool_property(env, view, "setAllCaps", false) && zj_pill(env, view, (jint)color, 24.0f) && zj_flatten(env, view) &&
              zj_text(env, view, text) && zj_margins(env, view, MATCH, WRAP, 0.0f, 4, 4, 4, 4) &&
              (!filter_obscured || zj_bool_property(env, view, "setFilterTouchesWhenObscured", true)) &&
              zj_append(env, ui.container, view) && zj_keep(env, &ui.buttons[ui.button_count], view);
    if (ok) ui.button_id[ui.button_count++] = id;
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static void release_widgets(JNIEnv *env)
{
    jmethodID clear = ui.container ? zj_method(env, ui.container, "removeAllViews", "()V") : NULL;
    if (clear) (*env)->CallVoidMethod(env, ui.container, clear);
    (void)zj_clean(env);
    for (size_t i = 0; i < ui.button_count; ++i) (*env)->DeleteGlobalRef(env, ui.buttons[i]);
    ui.button_count = 0;
    if (ui.address_input) (*env)->DeleteGlobalRef(env, ui.address_input);
    if (ui.amount_input) (*env)->DeleteGlobalRef(env, ui.amount_input);
    ui.address_input = ui.amount_input = NULL;
}

/* ---- drawing ---- */

static void line_if(JNIEnv *env, const char *text, float sp, uint32_t color)
{
    if (text[0]) (void)text_view(env, text, sp, color);
}
/* The review of a sweep: what leaves the public address, what the private balance gains, and what stays behind. */
static void draw_sweep_review(JNIEnv *env, const struct wss_view *v)
{
    (void)text_view(env, v->amount, 40.0f, WHITE);
    (void)text_view(env, v->move, 18.0f, WHITE);
    (void)text_view(env, v->arrives, 16.0f, SOFT);
    line_if(env, v->move_note, 14.0f, AMBER);
    line_if(env, v->fleet, 14.0f, SOFT);
}
static void draw_review(JNIEnv *env, const struct wss_view *v)
{
    char text[WSS_LINE + 32];
    if (v->sweep) { draw_sweep_review(env, v); return; }
    (void)text_view(env, v->amount, 40.0f, WHITE);
    snprintf(text, sizeof(text), "%s payment", v->kind);
    (void)text_view(env, text, 16.0f, SOFT);
    (void)text_view(env, "To", 14.0f, SOFT);
    (void)text_view(env, v->address, 18.0f, WHITE);
    snprintf(text, sizeof(text), "Fee %s", v->fee);
    (void)text_view(env, text, 16.0f, SOFT);
    if (v->remains[0]) {
        snprintf(text, sizeof(text), "%s left after this payment", v->remains);
        (void)text_view(env, text, 16.0f, SOFT);
    }
    line_if(env, v->fleet, 14.0f, SOFT);
    line_if(env, v->warning, 14.0f, AMBER);
    line_if(env, v->note, 14.0f, AMBER);
    if (v->memo[0]) {
        (void)text_view(env, v->memo_label, 14.0f, SOFT);
        (void)memo_view(env, v->memo);
    }
}
/* The earlier payment the node holds: its transaction and when the node confirmed it. */
static void draw_paid(JNIEnv *env, const struct wss_view *v)
{
    char text[WSS_LINE];
    if (v->txid[0]) {
        snprintf(text, sizeof(text), "Transaction %s", v->txid);
        (void)text_view(env, text, 14.0f, SOFT);
    }
    if (v->confirmed[0]) {
        snprintf(text, sizeof(text), "Your node confirmed this payment: %s", v->confirmed);
        (void)text_view(env, text, 14.0f, SOFT);
    }
}
/* The amount can be changed on the review of a payment; a sweep takes what the node names. */
static void draw_amount_edit(JNIEnv *env, const struct wss_view *v)
{
    if (v->sweep) return;
    (void)input_view(env, "Amount in ZCL", INPUT_TYPE_DECIMAL, &ui.amount_input);
    (void)button_view(env, B_SET_AMOUNT, v->state == WS_REVIEW ? "Change amount" : "Set amount", BUTTON_COLOR, false);
}
/* Another code can follow a finished payment, not a sweep and not a payment the node still holds. */
static bool offers_scan(const struct wss_view *v) { return v->can_leave && v->state != WS_BROADCAST && !v->sweep; }
static void draw_flow(JNIEnv *env, const struct wss_view *v)
{
    if (v->review) draw_review(env, v);
    line_if(env, v->status, 16.0f, v->check_history ? AMBER : SOFT);
    if (v->state == WS_PAID) draw_paid(env, v);
    line_if(env, ui.hint, 14.0f, AMBER);
    if (ui.dropped) (void)text_view(env, "Another app is drawing over this screen, so your tap was ignored.", 14.0f, AMBER);
    if (v->state == WS_PARSED || v->state == WS_REVIEW) {
        draw_amount_edit(env, v);
    }
    if (v->can_send) (void)button_view(env, B_SEND, v->sweep ? "Make private" : "Send", SEND_COLOR, true);
    if (v->can_retry) (void)button_view(env, B_RETRY, "Try again", BUTTON_COLOR, false);
    if (v->can_pay_again) (void)button_view(env, B_PAY_AGAIN, "Pay again", BUTTON_COLOR, false);
    if (v->can_cancel) (void)button_view(env, B_CANCEL, "Cancel", BUTTON_COLOR, false);
    if (offers_scan(v)) (void)button_view(env, B_SCAN, "Scan another code", BUTTON_COLOR, false);
    if (v->can_leave) (void)button_view(env, B_DONE, "Done", BUTTON_COLOR, false);
}
/* No payment is open: a notice, and the two ways to name one. */
static void draw_blank(JNIEnv *env)
{
    line_if(env, ui.notice, 16.0f, SOFT);
    (void)button_view(env, B_SCAN, zapp_home_send_scan_label(ui.notice), BUTTON_COLOR, false);
    (void)button_view(env, B_ENTER, "Enter address", BUTTON_COLOR, false);
    if (ui.entering) {
        (void)input_view(env, "Address or payment code", INPUT_TYPE_ADDRESS, &ui.address_input);
        (void)button_view(env, B_USE_ADDRESS, "Use this address", BUTTON_COLOR, false);
    }
    (void)button_view(env, B_DONE, "Back", BUTTON_COLOR, false);
}

void zapp_send_ui_render(JNIEnv *env)
{
    struct wss_view v;
    if (!ui.container) return;
    memset(&v, 0, sizeof(v));
    if (ui.flow && ui.keeper.screen) {
        wss_view(ui.keeper.screen, &v);
        v.elapsed_s = 0;
        gate_apply(&v);
    }
    ui.away = false;
    if (ui.is_drawn && ui.drawn_version == ui.version && !memcmp(&v, &ui.drawn, sizeof(v))) return;
    release_widgets(env);
    (void)text_view(env, v.sweep ? "Make private" : "Send", 24.0f, WHITE);
    if (ui.flow && ui.keeper.screen) draw_flow(env, &v);
    else draw_blank(env);
    /* The phone must not sleep while a payment is built: it takes about two minutes. */
    (void)zj_bool_property(env, ui.container, "setKeepScreenOn", v.busy);
    ui.drawn = v;
    ui.drawn_version = ui.version;
    ui.is_drawn = true;
}
void zapp_send_ui_clear(JNIEnv *env)
{
    release_widgets(env);
    (void)zj_bool_property(env, ui.container, "setKeepScreenOn", false);
    memory_cleanse(&ui.drawn, sizeof(ui.drawn));
    ui.is_drawn = false;
}

/* ---- opening and leaving ---- */

static void say(char *field, const char *text)
{
    snprintf(field, WSS_LINE, "%s", text);
    ui.version++;
}
/* The flow on screen stays there, with its progress or outcome, when a later code is refused or turned away. */
static bool flow_live(void)
{
    struct wss_view v;
    if (!ui.flow || !ui.keeper.screen) return false;
    wss_view(ui.keeper.screen, &v);
    return v.visible;
}
static void flow_started(void)
{
    ui.flow = true;
    ui.moved = false;
    gate_reset();
    ui.final_line[0] = 0;
    ui.notice[0] = ui.hint[0] = 0;
    ui.entering = false;
    ui.dropped = false;
    ui.version++;
}
/* A flow that could not begin: the window could not be protected, or the earlier flow has not ended. */
static void flow_refused(void)
{
    const char *refused = zapp_secure_window_refusal();
    char text[WSS_LINE];
    if (refused) snprintf(text, sizeof(text), "This phone would not let the app %s, so the payment is not shown.", refused);
    else snprintf(text, sizeof(text), "Another payment is still finishing. Try again in a moment.");
    ui.flow = flow_live();
    say(ui.notice, text);
}
static void open_payment(const struct zapp_payment *pay)
{
    if (ui.keeper.screen && wss_begin(ui.keeper.screen, pay)) flow_started();
    else flow_refused();
}
void zapp_send_ui_open_sweep(JNIEnv *env)
{
    ui.entering = false;
    ui.hint[0] = 0;
    say(ui.notice, "");
    if (ui.keeper.screen && wss_begin_sweep(ui.keeper.screen)) flow_started();
    else flow_refused();
    zapp_send_ui_render(env);
}
void zapp_send_ui_open(JNIEnv *env, const struct zapp_payment *pay, const char *notice)
{
    ui.entering = false;
    ui.hint[0] = 0;
    say(ui.notice, notice ? notice : "");
    if (pay) open_payment(pay);
    else ui.flow = flow_live();
    zapp_send_ui_render(env);
}

bool zapp_send_ui_leave(JNIEnv *env)
{
    if (ui.flow && ui.keeper.screen && wss_in_flight(ui.keeper.screen)) {
        /* The commit keeps running in the app process; the owner sees its progress on the wallet screen. */
        ui.away = true;
        ui.entering = false;
        ui.dropped = false;
        zapp_send_ui_clear(env);
        return true;
    }
    if (ui.flow && ui.keeper.screen) {
        if (!wss_end(ui.keeper.screen)) return false;
        ui.flow = false;
    }
    ui.entering = false;
    ui.notice[0] = ui.hint[0] = 0;
    ui.dropped = false;
    ui.version++;
    zapp_send_ui_clear(env);
    return true;
}
void zapp_send_ui_pause(void)
{
    if (ui.flow && ui.keeper.screen) wss_on_pause(ui.keeper.screen);
}
/* A payment that ended while the owner was elsewhere: its outcome is kept for the wallet screen and the flow is closed
 * once the wallet is locked again. */
static void finish_away(void)
{
    struct wss *s = ui.keeper.screen;
    struct wss_view v;
    if (!ui.away || !s || wss_in_flight(s)) return;
    wss_view(s, &v);
    if (!v.can_leave || wss_exposed(s)) return;
    if (!wss_progress(s, ui.final_line, sizeof(ui.final_line))) ui.final_line[0] = 0;
    wss_close(s);
    ui.flow = false;
    ui.away = false;
}
void zapp_send_ui_tick(JNIEnv *env)
{
    struct wss_view v;
    if (ui.flow && ui.keeper.screen) wss_on_tick(ui.keeper.screen);
    if (ui.flow && ui.keeper.screen && !ui.away) {
        wss_view(ui.keeper.screen, &v);
        if (v.can_send) gate_poll();
    }
    finish_away();
    wsk_tick(&ui.keeper);
    if (reveal.view) wrv_tick(reveal.view);
    (void)env;
}
bool zapp_send_ui_take_background(void)
{
    if (ui.moved || !ui.flow || !ui.keeper.screen || !wss_in_flight(ui.keeper.screen)) return false;
    ui.moved = true;
    return true;
}
bool zapp_send_progress(char *line, size_t cap)
{
    struct wss *s = ui.keeper.screen ? ui.keeper.screen : ui.keeper.retired;
    if (s && wss_progress(s, line, cap)) return true;
    if (!ui.final_line[0] || !line || !cap) return false;
    snprintf(line, cap, "%s", ui.final_line);
    return true;
}
void zapp_send_progress_dismiss(void)
{
    struct wss *s = ui.keeper.screen ? ui.keeper.screen : ui.keeper.retired;
    if (s) wss_progress_dismiss(s);
    ui.final_line[0] = 0;
}
bool zapp_send_ui_owes(void) { return ui.flow || wsk_owes(&ui.keeper) || (reveal.view && wrv_owes(reveal.view)); }
bool zapp_send_busy(void) { return atomic_load(&send_busy); }
void zapp_send_ui_dropped(JNIEnv *env)
{
    ui.dropped = true;
    ui.version++;
    zapp_send_ui_render(env);
}

/* ---- input ---- */

bool zapp_send_ui_hit(JNIEnv *env, float x, float y, size_t *button, unsigned *id)
{
    for (size_t i = 0; i < ui.button_count; ++i)
        if (zj_hit(env, ui.buttons[i], x, y)) { *button = i; *id = (unsigned)ui.button_id[i]; return true; }
    return false;
}
/* The text of a field, or false when it cannot be read or does not fit. */
static bool read_input(JNIEnv *env, jobject input, char *out, size_t cap)
{
    bool ok = false;
    out[0] = 0;
    if (!input || (*env)->PushLocalFrame(env, 8) != JNI_OK) { (void)zj_clean(env); return false; }
    jobject text = zj_object_property(env, input, "getText", "()Landroid/text/Editable;");
    jobject string = text ? zj_object_property(env, text, "toString", "()Ljava/lang/String;") : NULL;
    ok = string && zj_copy_utf(env, (jstring)string, out, cap);
    (*env)->PopLocalFrame(env, NULL);
    return ok;
}
/* The same parser as a scanned code: an address typed or pasted is a payment with no amount, a payment code is read whole. */
static void use_address(JNIEnv *env)
{
    char *text = calloc(1, TEXT_CAP);
    struct zapp_payment pay;
    if (!text) return;
    if (!read_input(env, ui.address_input, text, TEXT_CAP)) text[0] = 0;
    wallet_view_trim_address(text);
    enum zapp_pay_refusal why = zapp_scan_payment(text, &pay);
    memory_cleanse(text, TEXT_CAP);
    free(text);
    if (why != ZAPP_PAY_OK) {
        say(ui.notice, zapp_scan_refusal_text(why));
        return;
    }
    ui.entering = false;
    say(ui.notice, "");
    open_payment(&pay);
    memory_cleanse(&pay, sizeof(pay));
}
static void set_amount(JNIEnv *env)
{
    char text[64];
    uint64_t zat = 0;
    bool ok = read_input(env, ui.amount_input, text, sizeof(text)) && zapp_zat_parse(text, &zat) && zat > 0;
    memory_cleanse(text, sizeof(text));
    if (!ok) { say(ui.hint, "That is not an amount. Write it in ZCL, for example 1.5."); return; }
    ui.hint[0] = 0;
    ui.version++;
    wss_edit_amount(ui.keeper.screen, zat);
}

/* The buttons that act on the flow. The first is the only call that starts an authentication: the owner's tap on the
 * Send button of the plan on screen. */
static void press_flow(JNIEnv *env, int id)
{
    if (!ui.flow || !ui.keeper.screen) return;
    if (id == B_SEND) (void)wss_tap_send_ready(ui.keeper.screen, ui.drawn.serial, ui.drawn.can_send && gate_ready());
    else if (id == B_CANCEL) wss_tap_cancel(ui.keeper.screen);
    else if (id == B_RETRY) wss_tap_retry(ui.keeper.screen);
    else if (id == B_PAY_AGAIN) wss_tap_pay_again(ui.keeper.screen);
    else if (id == B_SET_AMOUNT) set_amount(env);
}
enum zapp_send_outcome zapp_send_ui_press(JNIEnv *env, size_t button)
{
    enum zapp_send_outcome outcome = ZAPP_SEND_STAY;
    if (button >= ui.button_count) return outcome;
    ui.dropped = false;
    int id = (int)ui.button_id[button];
    if (id == B_DONE) {
        if (ui.flow && ui.keeper.screen) wss_close(ui.keeper.screen);
        outcome = ZAPP_SEND_LEAVE;
    }
    else if (id == B_SCAN) outcome = ZAPP_SEND_SCAN;
    else if (id == B_ENTER) { ui.entering = true; ui.version++; }
    else if (id == B_USE_ADDRESS) use_address(env);
    else press_flow(env, id);
    if (outcome == ZAPP_SEND_STAY) zapp_send_ui_render(env);
    return outcome;
}

/* ---- lifecycle ---- */

bool zapp_send_ui_create(JNIEnv *env, jobject activity, jobject container)
{
    if (ui.container) return false;
    ui.app = (*env)->NewGlobalRef(env, activity);
    ui.container = (*env)->NewGlobalRef(env, container);
    /* A flow kept from an earlier activity asks the keystore through the newest activity from here on. */
    jobject key_app = (*env)->NewGlobalRef(env, activity);
    /* The notification of a payment that ends while no activity exists uses the application context. */
    jobject context = zj_object_property(env, activity, "getApplicationContext", "()Landroid/content/Context;");
    jobject notify_app = context ? (*env)->NewGlobalRef(env, context) : NULL;
    pthread_mutex_lock(&ui.key_lock);
    jobject old = ui.key_app, old_notify = ui.notify_app;
    ui.key_app = key_app;
    if (notify_app) ui.notify_app = notify_app;
    else old_notify = NULL;
    pthread_mutex_unlock(&ui.key_lock);
    if (old) (*env)->DeleteGlobalRef(env, old);
    if (old_notify) (*env)->DeleteGlobalRef(env, old_notify);
    if (ui.app && ui.container && key_app && zj_int_property(env, ui.container, "setGravity", GRAVITY_CENTER_HORIZONTAL)) return true;
    zapp_send_ui_destroy(env);
    return false;
}
void zapp_send_ui_destroy(JNIEnv *env)
{
    zapp_send_ui_clear(env);
    pthread_mutex_lock(&ui.key_lock);
    jobject key_app = ui.key_app;
    ui.key_app = NULL;
    pthread_mutex_unlock(&ui.key_lock);
    if (key_app) (*env)->DeleteGlobalRef(env, key_app);
    if (ui.app) (*env)->DeleteGlobalRef(env, ui.app);
    ui.app = NULL;
    if (ui.container) (*env)->DeleteGlobalRef(env, ui.container);
    ui.container = NULL;
}
