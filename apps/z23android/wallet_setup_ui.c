/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "wallet_setup_ui.h"
#include "base/cleanse.h"
#include "controller.h"
#include "device_key.h"
#include "jni_util.h"
#include "json/json.h"
#include "secure_window.h"
#include "setup_field.h"
#include "wallet_setup.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
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
#define GO_COLOR 0xff1f6f3fu
#define WORDS_PANEL 0xff1c2430u
_Static_assert(ZAPP_FIELD_PRIVATE(ZAPP_FIELD_INPUT_WORDS | ZAPP_FIELD_FLAG_MULTI_LINE, ZAPP_FIELD_IME_NO_LEARNING), "the word fields must be private");
#define GRAVITY_CENTER_HORIZONTAL 1
#define BUTTONS_MAX 4
#define TYPED_MAX 640
#define SUMMARY_MAX 8192

enum button { B_CREATE, B_RESTORE_FORM, B_RESTORE, B_RESTORE_UNKNOWN, B_SEEN, B_CONFIRM, B_AGAIN, B_BACK, B_CONTINUE, B_RECHECK, B_SAVE_AGAIN, B_NEW_WALLET, B_START_OVER_ASK, B_START_OVER_GO, B_START_OVER_CANCEL };
enum job_kind { JOB_CREATE, JOB_RESTORE, JOB_PROGRESS, JOB_FINISH, JOB_RESUME, JOB_ASIDE, JOB_START_OVER };
struct job { enum job_kind kind; char text[TYPED_MAX]; int64_t height; };

static struct {
    ANativeActivity *activity;
    JavaVM *vm;
    jobject app, key_app, container, words_input, height_input, answers[ZAPP_WORDS_ASKED], buttons[BUTTONS_MAX];
    pthread_mutex_t key_lock;   /* guards key_app, which a worker reads while the activity is replaced */
    enum button button_id[BUTTONS_MAX];
    size_t button_count;
    struct wsu model;
    bool model_ready;
    char blob[512];
    bool dropped;
    atomic_bool progress_busy, resume_busy;
    pthread_mutex_t progress_lock;
    int64_t scanned, tip;
    bool progress_known;
    void (*changed)(void);
    unsigned version, drawn_version;
    struct wsu_view drawn;
    int64_t drawn_scanned, drawn_tip;
    bool is_drawn;
} ui = {.key_lock = PTHREAD_MUTEX_INITIALIZER, .progress_lock = PTHREAD_MUTEX_INITIALIZER};

/* ---- the host: random bytes, a JVM-attached worker, the device key and the node ---- */

static bool host_random(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    for (size_t got = 0; got < len;) {
        ssize_t n = getrandom(out + got, len - got, 0);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}
static _Thread_local JNIEnv *worker_env;
static _Thread_local struct zapp_devkey_jni worker_key;
static void run_job(struct job *job);
static void *worker_main(void *raw)
{
    struct job *job = raw;
    JNIEnv *env = NULL;
    bool attached = ui.vm && (*ui.vm)->AttachCurrentThread(ui.vm, &env, NULL) == JNI_OK;
    worker_env = attached ? env : NULL;
    run_job(job);
    memory_cleanse(job, sizeof(*job));
    free(job);
    worker_env = NULL;
    if (attached) (*ui.vm)->DetachCurrentThread(ui.vm);
    return NULL;
}
static bool spawn_job(enum job_kind kind, const char *text, int64_t height)
{
    pthread_t thread;
    struct job *job = calloc(1, sizeof(*job));
    if (!job) return false;
    job->kind = kind;
    job->height = height;
    if (text) snprintf(job->text, sizeof(job->text), "%s", text);
    if (pthread_create(&thread, NULL, worker_main, job) != 0) { memory_cleanse(job, sizeof(*job)); free(job); return false; }
    (void)pthread_detach(thread);
    return true;
}
static bool key_ops(struct zapp_devkey_ops *out)
{
    if (!worker_env) return false;
    pthread_mutex_lock(&ui.key_lock);
    jobject app = ui.key_app ? (*worker_env)->NewLocalRef(worker_env, ui.key_app) : NULL;
    pthread_mutex_unlock(&ui.key_lock);
    if (!app) return false;
    worker_key = (struct zapp_devkey_jni){worker_env, app};
    zapp_devkey_jni_ops(out, &worker_key);
    return true;
}
static void woken(void)
{
    ui.version++;
    if (ui.changed) ui.changed();
}

static enum zapp_devkey_status env_wrap_new(void *ctx, uint8_t secret[ZAPP_DEVKEY_SECRET])
{
    struct zapp_devkey_ops ops;
    (void)ctx;
    memory_cleanse(secret, ZAPP_DEVKEY_SECRET);
    return key_ops(&ops) ? zapp_devkey_wrap_new(&ops, ui.blob, secret) : ZAPP_DEVKEY_ERROR;
}
static void env_discard(void *ctx)
{
    struct zapp_devkey_ops ops;
    (void)ctx;
    if (key_ops(&ops)) zapp_devkey_discard(&ops, ui.blob);
}
static bool env_running(void *ctx) { (void)ctx; return zapp_controller_node_running(); }
static void env_control(void *ctx, bool start)
{
    (void)ctx;
    (void)zapp_controller_node_control(start);
}
static void env_pause(void *ctx, unsigned ms)
{
    struct timespec step = {.tv_sec = ms / 1000u, .tv_nsec = (long)(ms % 1000u) * 1000000L};
    (void)ctx;
    nanosleep(&step, NULL);
}
/* tip_height and scanned_through_height of `core wallet summary`; the summary works while the wallet is locked. */
static bool env_progress(void *ctx, int64_t *scanned, int64_t *tip)
{
    char text[SUMMARY_MAX];
    struct json_value root = {0};
    (void)ctx;
    text[0] = 0;
    bool ok = zapp_controller_send_run("summary", NULL, 60000, text, sizeof(text));
    const char *json = strchr(text, '{');
    const struct json_value *data = ok && json && json_read(&root, json, strlen(json)) ? json_get(&root, "data") : NULL;
    const struct json_value *s = json_get(data, "scanned_through_height"), *t = json_get(data, "tip_height");
    ok = s && t && s->type == JSON_INT && t->type == JSON_INT && json_get_int(t) > 0;
    if (ok) { *scanned = json_get_int(s); *tip = json_get_int(t); }
    json_free(&root);
    return ok;
}
/* The data object of a node reply, or NULL. */
static const struct json_value *reply_data(struct json_value *root, const char *text)
{
    const char *json = strchr(text, '{');
    return json && json_read(root, json, strlen(json)) ? json_get(root, "data") : NULL;
}
static enum wsu_idle env_idle(void *ctx)
{
    char text[SUMMARY_MAX];
    struct json_value summary = {0}, history = {0};
    (void)ctx;
    text[0] = 0;
    bool ok = zapp_controller_send_run("summary", NULL, 60000, text, sizeof(text));
    int amounts = ok ? wsu_summary_state(reply_data(&summary, text)) : -1;
    text[0] = 0;
    ok = amounts == 1 && zapp_controller_wallet_run("history", "", text, sizeof(text));
    int transactions = ok ? wsu_history_state(reply_data(&history, text)) : -1;
    json_free(&summary);
    json_free(&history);
    if (amounts == 0 || transactions == 0) return WSU_IDLE_FUNDS;
    return amounts == 1 && transactions == 1 ? WSU_IDLE_EMPTY : WSU_IDLE_UNKNOWN;
}
static int64_t env_wall(void *ctx)
{
    (void)ctx;
    return (int64_t)time(NULL);
}
static bool env_protect(void *ctx, bool on)
{
    (void)ctx;
    return ui.activity && zapp_secure_window(ui.activity, on);
}
static bool setup_runner(void *ctx, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap)
{
    (void)ctx;
    return zapp_controller_setup_run(op, input, timeout_ms, out, cap);
}

static void run_job(struct job *job)
{
    if (!ui.model_ready) return;
    if (job->kind == JOB_CREATE) wsu_create_job(&ui.model);
    else if (job->kind == JOB_RESTORE) wsu_restore_job(&ui.model, job->text, job->height);
    else if (job->kind == JOB_FINISH) wsu_finish_job(&ui.model);
    else if (job->kind == JOB_ASIDE) wsu_set_aside_job(&ui.model);
    else if (job->kind == JOB_START_OVER) wsu_start_over_job(&ui.model);
    else if (job->kind == JOB_RESUME) { wsu_resume_job(&ui.model); atomic_store(&ui.resume_busy, false); }
    else {
        int64_t scanned = 0, tip = 0;
        bool known = wsu_reading(&ui.model, &scanned, &tip);
        pthread_mutex_lock(&ui.progress_lock);
        ui.progress_known = known;
        if (known) { ui.scanned = scanned; ui.tip = tip; }
        pthread_mutex_unlock(&ui.progress_lock);
        atomic_store(&ui.progress_busy, false);
    }
    woken();
}

bool zapp_setup_attach(ANativeActivity *activity, void (*changed)(void))
{
    if (!activity) return false;
    ui.activity = activity;
    ui.vm = activity->vm;
    ui.changed = changed;
    return snprintf(ui.blob, sizeof(ui.blob), "%s/wallet_key.blob", activity->internalDataPath) < (int)sizeof(ui.blob);
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
static bool words_view(JNIEnv *env, const char *text)
{
    jobject view = zj_widget(env, "android/widget/TextView", ui.app);
    bool ok = view && zj_typography(env, view, 18.0f, (jint)WHITE) && zj_pill(env, view, (jint)WORDS_PANEL, 8.0f) &&
              zj_padding(env, view, 12, 8) && zj_text(env, view, text) && zj_bool_property(env, view, "setTextIsSelectable", false) &&
              zj_bool_property(env, view, "setLongClickable", false) && zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 2, 0, 2) &&
              zj_append(env, ui.container, view);
    if (view) (*env)->DeleteLocalRef(env, view);
    return ok;
}
static bool input_view(JNIEnv *env, const char *hint, int type, jobject *keep)
{
    jobject view = zj_widget(env, "android/widget/EditText", ui.app);
    bool ok = view && zj_typography(env, view, 18.0f, (jint)WHITE) && zj_int_property(env, view, "setInputType", type) && zj_bool_property(env, view, "setLongClickable", false) && zj_bool_property(env, view, "setCursorVisible", false) &&
              zj_int_property(env, view, "setImeOptions", ZAPP_FIELD_IME_NO_LEARNING) && zj_int_property(env, view, "setHintTextColor", (jint)0xff808080u) &&
              zj_char_sequence(env, view, "setHint", hint) && zj_margins(env, view, MATCH, WRAP, 0.0f, 0, 8, 0, 0) &&
              zj_append(env, ui.container, view) && zj_keep(env, keep, view);
    if (view) {
        (void)zj_int_property(env, view, "setImportantForAutofill", ZAPP_FIELD_AUTOFILL_NO);
        (*env)->DeleteLocalRef(env, view);
    }
    return ok;
}
static bool button_view(JNIEnv *env, enum button id, const char *text, uint32_t color)
{
    jobject view = zj_widget(env, "android/widget/Button", ui.app);
    bool ok = view && ui.button_count < BUTTONS_MAX && zj_typography(env, view, 16.0f, (jint)WHITE) &&
              zj_bool_property(env, view, "setAllCaps", false) && zj_pill(env, view, (jint)color, 24.0f) && zj_flatten(env, view) &&
              zj_text(env, view, text) && zj_margins(env, view, MATCH, WRAP, 0.0f, 4, 4, 4, 4) &&
              zj_bool_property(env, view, "setFilterTouchesWhenObscured", true) && zj_append(env, ui.container, view) &&
              zj_keep(env, &ui.buttons[ui.button_count], view);
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
    for (size_t i = 0; i < ZAPP_WORDS_ASKED; ++i) {
        if (ui.answers[i]) (*env)->DeleteGlobalRef(env, ui.answers[i]);
        ui.answers[i] = NULL;
    }
    if (ui.words_input) (*env)->DeleteGlobalRef(env, ui.words_input);
    if (ui.height_input) (*env)->DeleteGlobalRef(env, ui.height_input);
    ui.words_input = ui.height_input = NULL;
}

/* ---- drawing ---- */

static const struct { enum wsu_failure failure; const char *text; } failure_texts[] = {
    {WSU_DECLINED, "Nothing was changed: the screen lock was not confirmed."},
    {WSU_NO_SCREEN_LOCK, "Set a screen lock (PIN, pattern or password) in the phone's settings first. The wallet is protected by it."},
    {WSU_KEY, "This phone could not make a hardware-protected key for the wallet, so no wallet was made."},
    {WSU_NODE_BUSY, "The node did not stop in time. Nothing was changed. Try again in a minute."},
    {WSU_PRESENT, "This phone already holds a wallet. Nothing was changed."},
    {WSU_BAD_PHRASE, "Those words are not a valid recovery phrase. Check each word and its order."},
    {WSU_BAD_WORDS, "Type all of your recovery words: 12, 15, 18, 21 or 24 words separated by spaces."},
    {WSU_STORAGE, "The node's chain database could not be read. Nothing was changed."},
    {WSU_REFUSED, "The node refused the request. Nothing was changed."},
    {WSU_UNKNOWN, "The node did not give a usable answer. A wallet may have been started; its words cannot be shown again."},
    {WSU_NOT_RECORDED, "The wallet exists but this app could not record that setup finished."},
    {WSU_NO_TIP, "The node has not yet read enough of the chain to give a new wallet a start height, so no wallet was made. Check the connection and try again."},
    {WSU_NO_BIRTHDAY, "Your words were confirmed, but the wallet recorded no start height, so setup is not finished. Check again tries once more. Start over sets this wallet aside, only if the node shows it holds nothing, and begins a new one; nothing is deleted."},
    {WSU_NOT_RUN, "The wallet command could not start. Nothing was changed."},
    {WSU_NOT_CREATE, "Start over is only for a new wallet whose words were not confirmed. This wallet was restored from words."},
    {WSU_NOT_EMPTY, "The node reports funds or transactions in this wallet, so it is not set aside."},
    {WSU_ALREADY_CONFIRMED, "The words of this wallet were confirmed, so it is not set aside."},
    {WSU_COULD_NOT_CHECK, "The node did not say whether this wallet holds transactions, so nothing was changed."},
    {WSU_ASIDE, "Could not set the wallet aside; nothing changed."},
    {WSU_ASIDE_STUCK, "The wallet could not be set aside and some items could not be put back. Do not create a new wallet. These stay moved aside and need their original names back:"},
    {WSU_UNPROTECTED, "This phone would not protect the screen from capture, so no wallet was made."},
};
static const char *failure_text(enum wsu_failure failure)
{
    for (size_t i = 0; i < sizeof(failure_texts) / sizeof(failure_texts[0]); ++i)
        if (failure_texts[i].failure == failure) return failure_texts[i].text;
    return "";
}
static void draw_words(JNIEnv *env, const struct wsu_view *v)
{
    const struct zapp_words *words = &v->words;
    char line[320];
    (void)text_view(env, "Your recovery words", 24.0f, WHITE);
    wsu_words_intro(v, line, sizeof(line));
    (void)text_view(env, line, 15.0f, SOFT);
    (void)text_view(env, WSU_SCREEN_LOCK_NOTICE, 15.0f, AMBER);
    for (size_t i = 0; i < words->count; i += 2) {
        if (i + 1 < words->count) snprintf(line, sizeof(line), "%2zu  %-9s %2zu  %s", i + 1, words->word[i], i + 2, words->word[i + 1]);
        else snprintf(line, sizeof(line), "%2zu  %s", i + 1, words->word[i]);
        (void)words_view(env, line);
    }
    memory_cleanse(line, sizeof(line));
    (void)button_view(env, B_SEEN, "I wrote them down", GO_COLOR);
}
static void draw_confirm(JNIEnv *env, const struct wsu_view *v)
{
    char hint[32];
    (void)text_view(env, "Check your words", 24.0f, WHITE);
    (void)text_view(env, "Type the words you wrote down at these positions.", 15.0f, SOFT);
    for (size_t i = 0; i < ZAPP_WORDS_ASKED; ++i) {
        snprintf(hint, sizeof(hint), "Word %zu", v->asked[i] + 1);
        (void)input_view(env, hint, ZAPP_FIELD_INPUT_WORDS, &ui.answers[i]);
    }
    if (v->mismatches) (void)text_view(env, "Those words do not match. Check your paper.", 15.0f, AMBER);
    (void)button_view(env, B_CONFIRM, "Confirm", GO_COLOR);
    (void)button_view(env, B_AGAIN, "Show the words again", BUTTON_COLOR);
}
static void draw_form(JNIEnv *env, const struct wsu_view *v)
{
    (void)text_view(env, "Restore from words", 24.0f, WHITE);
    (void)text_view(env, "Type your recovery words, separated by spaces.", 15.0f, SOFT);
    (void)input_view(env, "Recovery words", ZAPP_FIELD_INPUT_WORDS | ZAPP_FIELD_FLAG_MULTI_LINE, &ui.words_input);
    (void)text_view(env, "If you know the block height where this wallet began, type it: the wallet then reads the chain from there. Without it the wallet reads the whole chain, which takes longer.", 14.0f, SOFT);
    (void)input_view(env, "Block height (optional)", ZAPP_FIELD_NUMBER, &ui.height_input);
    if (v->failure) (void)text_view(env, failure_text(v->failure), 15.0f, AMBER);
    (void)button_view(env, B_RESTORE, "Restore", GO_COLOR);
    (void)button_view(env, B_RESTORE_UNKNOWN, "I do not know the height", BUTTON_COLOR);
    (void)button_view(env, B_BACK, "Back", BUTTON_COLOR);
}
static void draw_reading(JNIEnv *env, const struct wsu_view *v, bool known, int64_t scanned, int64_t tip)
{
    char line[160];
    (void)text_view(env, "Wallet restored", 24.0f, WHITE);
    (void)text_view(env, "The node is reading the chain for your funds. Balances grow as it goes, and an older wallet can take a long while.", 15.0f, SOFT);
    if (v->birthday_dropped) (void)text_view(env, "Reading from the start of the chain: no starting block was used.", 15.0f, SOFT);
    if (known) snprintf(line, sizeof(line), "Read through block %lld of %lld.", (long long)scanned, (long long)tip);
    else snprintf(line, sizeof(line), "Waiting for the node to start.");
    (void)text_view(env, line, 18.0f, WHITE);
    (void)button_view(env, B_CONTINUE, "Continue", GO_COLOR);
}
/* What the owner can do after a failure: a wallet that may exist is never offered the choice again. */
static void draw_failed_buttons(JNIEnv *env, enum wsu_failure failure)
{
    if (failure == WSU_ASIDE_STUCK) return;
    if (failure == WSU_NOT_RECORDED) {
        (void)button_view(env, B_SAVE_AGAIN, "Save again", GO_COLOR);
    } else if (failure == WSU_UNKNOWN || failure == WSU_NO_BIRTHDAY) {
        (void)button_view(env, B_RECHECK, "Check again", BUTTON_COLOR);
        if (failure == WSU_NO_BIRTHDAY) (void)button_view(env, B_START_OVER_ASK, "Start over", BUTTON_COLOR);
    } else {
        (void)button_view(env, B_BACK, "Try again", BUTTON_COLOR);
    }
}
/* The screens after a restart: no wallet, the start over warning, the check, and a wallet whose words were not confirmed. */
static void draw_interrupted(JNIEnv *env, const struct wsu_view *v)
{
    switch (v->step) {
    case WSU_NO_WALLET:
        (void)text_view(env, "No wallet found", 24.0f, WHITE);
        (void)text_view(env, "No wallet found on this phone. Set up a new one? The saved key from the interrupted setup is kept under a new name, never deleted.", 15.0f, SOFT);
        (void)button_view(env, B_NEW_WALLET, "Set up a new one", GO_COLOR);
        (void)button_view(env, B_RECHECK, "Check again", BUTTON_COLOR);
        break;
    case WSU_START_OVER:
        (void)text_view(env, "Start over?", 24.0f, WHITE);
        (void)text_view(env, "This sets this wallet aside on the phone. Nothing is deleted. If you wrote the words down, they still restore it. The node then downloads the chain again.", 15.0f, AMBER);
        (void)button_view(env, B_START_OVER_GO, "Yes, start over", GO_COLOR);
        (void)button_view(env, B_START_OVER_CANCEL, "Cancel", BUTTON_COLOR);
        break;
    case WSU_CHECKING:
        (void)text_view(env, "Checking this phone's wallet", 24.0f, WHITE);
        (void)text_view(env, "Setup was interrupted. The app is reading what it left behind.", 15.0f, SOFT);
        break;
    default:
        (void)text_view(env, "Setup was interrupted", 24.0f, WHITE);
        (void)text_view(env, v->failure == WSU_UNKNOWN ? "The node did not answer, so the app does not know whether a wallet exists." : "A wallet was started on this phone and its recovery words were not confirmed. The node has no command that shows them again. Receive stays closed until setup is confirmed.", 15.0f, AMBER);
        if (wsu_view_can_recheck(v)) (void)button_view(env, B_RECHECK, "Check again", BUTTON_COLOR);
        if (v->may_start_over && (v->failure == WSU_NO_FAILURE || v->failure == WSU_COULD_NOT_CHECK || v->failure == WSU_NODE_BUSY))
            (void)button_view(env, B_START_OVER_ASK, "Start over", BUTTON_COLOR);
        if (v->failure != WSU_NO_FAILURE && v->failure != WSU_UNKNOWN) (void)text_view(env, failure_text(v->failure), 15.0f, AMBER);
        break;
    }
}

static void draw_model(JNIEnv *env, const struct wsu_view *v, bool known, int64_t scanned, int64_t tip)
{
    switch (v->step) {
    case WSU_CHOICE:
        (void)text_view(env, "Set up your wallet", 24.0f, WHITE);
        (void)text_view(env, "Make a new shielded wallet on this phone, or bring back one you already have from its recovery words.", 15.0f, SOFT);
        (void)button_view(env, B_CREATE, "Create a new wallet", GO_COLOR);
        (void)button_view(env, B_RESTORE_FORM, "Restore from words", BUTTON_COLOR);
        break;
    case WSU_WORKING:
        (void)text_view(env, "Working", 24.0f, WHITE);
        (void)text_view(env, "A new wallet waits for the node to learn the current chain tip, which can take a few minutes. The phone may ask for your screen lock. Keep this screen open.", 15.0f, SOFT);
        break;
    case WSU_WORDS: draw_words(env, v); break;
    case WSU_CONFIRM: draw_confirm(env, v); break;
    case WSU_RESTORE_FORM: draw_form(env, v); break;
    case WSU_READING: draw_reading(env, v, known, scanned, tip); break;
    case WSU_DONE:
        (void)text_view(env, "Your wallet is ready", 24.0f, WHITE);
        (void)button_view(env, B_CONTINUE, "Open wallet", GO_COLOR);
        break;
    case WSU_FAILED:
        (void)text_view(env, "Setup stopped", 24.0f, WHITE);
        (void)text_view(env, failure_text(v->failure), 15.0f, AMBER);
        if (v->failure == WSU_ASIDE_STUCK) (void)text_view(env, v->leftover, 14.0f, SOFT);
        draw_failed_buttons(env, v->failure);
        break;
    default: draw_interrupted(env, v); break;
    }
}

void zapp_setup_ui_render(JNIEnv *env)
{
    struct wsu_view v;
    bool known;
    int64_t scanned, tip;
    if (!ui.container || !ui.model_ready) return;
    wsu_view_read(&ui.model, &v);
    pthread_mutex_lock(&ui.progress_lock);
    known = ui.progress_known; scanned = ui.scanned; tip = ui.tip;
    pthread_mutex_unlock(&ui.progress_lock);
    if (ui.is_drawn && ui.drawn_version == ui.version && !memcmp(&v, &ui.drawn, sizeof(v)) && ui.drawn_scanned == scanned && ui.drawn_tip == tip) {
        memory_cleanse(&v, sizeof(v));
        return;
    }
    release_widgets(env);
    if (!v.protected) {
        (void)text_view(env, "This phone would not protect the screen from capture, so wallet setup cannot show anything here.", 15.0f, AMBER);
    } else if (ui.dropped) {
        (void)text_view(env, "Another window was drawing over this app, so a tap was ignored.", 15.0f, AMBER);
        draw_model(env, &v, known, scanned, tip);
    } else draw_model(env, &v, known, scanned, tip);
    (void)zj_bool_property(env, ui.container, "setKeepScreenOn", v.step == WSU_WORKING || v.step == WSU_WORDS || v.step == WSU_CONFIRM);
    ui.drawn = v;
    ui.drawn_scanned = scanned;
    ui.drawn_tip = tip;
    ui.drawn_version = ui.version;
    ui.is_drawn = true;
    memory_cleanse(&v, sizeof(v));
}
void zapp_setup_ui_clear(JNIEnv *env)
{
    release_widgets(env);
    (void)zj_bool_property(env, ui.container, "setKeepScreenOn", false);
    memory_cleanse(&ui.drawn, sizeof(ui.drawn));
    ui.is_drawn = false;
}

/* ---- lifecycle ---- */

bool zapp_setup_ui_open(JNIEnv *env)
{
    (void)env;
    if (!ui.activity) return false;
    if (!ui.model_ready) {
        struct sun node;
        char datadir[600];
        struct wsu_env host = {NULL, env_wrap_new, env_discard, env_running, env_control, env_pause, host_random, env_progress, env_protect, env_idle, env_wall};
        snprintf(datadir, sizeof(datadir), "%s/node", ui.activity->internalDataPath);
        sun_init(&node, &(struct sun_runner){NULL, setup_runner}, datadir);
        ui.model_ready = wsu_init(&ui.model, &host, &node, ui.activity->internalDataPath);
    }
    bool protected = ui.model_ready && wsu_open(&ui.model);
    ui.dropped = false;
    ui.version++;
    return protected;
}
void zapp_setup_ui_pause(JNIEnv *env)
{
    zapp_setup_ui_clear(env);
}
bool zapp_setup_ui_leave(JNIEnv *env)
{
    if (ui.model_ready && wsu_busy(&ui.model)) return false;
    if (ui.model_ready) wsu_finish_reading(&ui.model);
    ui.dropped = false;
    ui.version++;
    zapp_setup_ui_clear(env);
    if (ui.model_ready) wsu_close(&ui.model);
    return true;
}
void zapp_setup_ui_tick(JNIEnv *env)
{
    struct wsu_view v;
    if (!ui.model_ready) return;
    wsu_view_read(&ui.model, &v);
    if (v.step == WSU_READING && !atomic_exchange(&ui.progress_busy, true) && !spawn_job(JOB_PROGRESS, NULL, 0))
        atomic_store(&ui.progress_busy, false);
    if (v.step == WSU_CHECKING && !atomic_exchange(&ui.resume_busy, true) && !spawn_job(JOB_RESUME, NULL, 0))
        atomic_store(&ui.resume_busy, false);
    memory_cleanse(&v, sizeof(v));
    zapp_setup_ui_render(env);
}
void zapp_setup_ui_dropped(JNIEnv *env)
{
    ui.dropped = true;
    ui.version++;
    zapp_setup_ui_render(env);
}
bool zapp_setup_ui_hit(JNIEnv *env, float x, float y, size_t *button, unsigned *id)
{
    for (size_t i = 0; i < ui.button_count; ++i)
        if (zj_hit(env, ui.buttons[i], x, y)) { *button = i; *id = (unsigned)ui.button_id[i]; return true; }
    return false;
}

/* ---- input ---- */

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
static int64_t typed_height(JNIEnv *env)
{
    char text[24];
    int64_t height = 0;
    if (!read_input(env, ui.height_input, text, sizeof(text)) || !text[0]) return 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9' || height > 100000000) return 0;
        height = height * 10 + (*p - '0');
    }
    return height;
}
static void start_restore(JNIEnv *env, bool with_height)
{
    char typed[TYPED_MAX];
    int64_t height = with_height ? typed_height(env) : 0;
    if (!read_input(env, ui.words_input, typed, sizeof(typed))) typed[0] = 0;
    (void)spawn_job(JOB_RESTORE, typed, height);
    memory_cleanse(typed, sizeof(typed));
}
static bool check_answers(JNIEnv *env)
{
    char typed[ZAPP_WORDS_ASKED][ZAPP_WORD_LETTERS + 2];
    const char *answers[ZAPP_WORDS_ASKED];
    for (size_t i = 0; i < ZAPP_WORDS_ASKED; ++i) {
        if (!read_input(env, ui.answers[i], typed[i], sizeof(typed[i]))) typed[i][0] = 0;
        answers[i] = typed[i];
    }
    bool right = wsu_confirm(&ui.model, answers, ZAPP_WORDS_ASKED);
    memory_cleanse(typed, sizeof(typed));
    return right;
}

/* The buttons of the interrupted-setup screens. */
static void press_interrupted(enum button id)
{
    switch (id) {
    case B_RECHECK: (void)wsu_recheck(&ui.model); break;
    case B_NEW_WALLET: (void)spawn_job(JOB_ASIDE, NULL, 0); break;
    case B_START_OVER_ASK: (void)wsu_ask_start_over(&ui.model); break;
    case B_START_OVER_GO: (void)spawn_job(JOB_START_OVER, NULL, 0); break;
    case B_START_OVER_CANCEL: wsu_cancel_start_over(&ui.model); break;
    default: break;
    }
}

/* The buttons that start a job or move the model. */
static void press_model(JNIEnv *env, enum button id)
{
    switch (id) {
    case B_CREATE: (void)spawn_job(JOB_CREATE, NULL, 0); break;
    case B_RESTORE_FORM: wsu_open_restore(&ui.model); break;
    case B_RESTORE: start_restore(env, true); break;
    case B_RESTORE_UNKNOWN: start_restore(env, false); break;
    case B_SEEN: wsu_words_seen(&ui.model); break;
    case B_CONFIRM: if (check_answers(env)) (void)spawn_job(JOB_FINISH, NULL, 0); break;
    case B_AGAIN: wsu_show_again(&ui.model); break;
    case B_BACK: wsu_back(&ui.model); break;
    case B_SAVE_AGAIN: if (wsu_retry_marker(&ui.model)) (void)spawn_job(JOB_FINISH, NULL, 0); break;
    case B_CONTINUE: break;
    default: press_interrupted(id); break;
    }
}
enum zapp_setup_outcome zapp_setup_ui_press(JNIEnv *env, size_t button)
{
    enum zapp_setup_outcome outcome = ZAPP_SETUP_STAY;
    if (button >= ui.button_count || !ui.model_ready) return outcome;
    ui.dropped = false;
    if (ui.button_id[button] == B_CONTINUE) outcome = ZAPP_SETUP_LEAVE;
    else press_model(env, ui.button_id[button]);
    ui.version++;
    if (outcome == ZAPP_SETUP_STAY) zapp_setup_ui_render(env);
    return outcome;
}

bool zapp_setup_ui_create(JNIEnv *env, jobject activity, jobject container)
{
    if (ui.container) return false;
    ui.app = (*env)->NewGlobalRef(env, activity);
    ui.container = (*env)->NewGlobalRef(env, container);
    jobject key_app = (*env)->NewGlobalRef(env, activity);
    pthread_mutex_lock(&ui.key_lock);
    jobject old = ui.key_app;
    ui.key_app = key_app;
    pthread_mutex_unlock(&ui.key_lock);
    if (old) (*env)->DeleteGlobalRef(env, old);
    if (ui.app && ui.container && key_app && zj_int_property(env, ui.container, "setGravity", GRAVITY_CENTER_HORIZONTAL)) return true;
    zapp_setup_ui_destroy(env);
    return false;
}
void zapp_setup_ui_destroy(JNIEnv *env)
{
    zapp_setup_ui_clear(env);
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
