/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_setup.h"
#include "base/cleanse.h"
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

#define ASIDE_PATH_MAX 512
/* A phone node saves its database before it exits: 50 s measured on a Pixel, the fast-restart save alone 35 s. Three times that
 * bounds the wait for a node to exit, before create or restore and again before the node is started. */
#define STOP_WAIT_MS 180000u
#define STOP_POLL_MS 250u
#define TIP_POLLS 120u
#define TIP_POLL_MS 5000u
#define IDLE_POLLS 24u
#define IDLE_POLL_MS 5000u
#define CONFIRM_TRIES 5u
#define CONFIRM_RETRY_MS 1000u

bool wsu_init(struct wsu *w, const struct wsu_env *env, const struct sun *node, const char *files)
{
    memset(w, 0, sizeof(*w));
    w->env = *env;
    w->node = *node;
    if (!files || snprintf(w->files, sizeof(w->files), "%s", files) >= (int)sizeof(w->files)) return false;
    if (pthread_mutex_init(&w->lock, NULL) != 0) return false;
    switch (zapp_setup_state(files)) {
    case ZAPP_SETUP_NEEDED: w->step = WSU_CHOICE; break;
    case ZAPP_SETUP_INTERRUPTED: w->step = WSU_CHECKING; break;
    default: w->step = WSU_DONE; break;
    }
    w->phase_since_s = w->env.wall_s ? w->env.wall_s(w->env.ctx) : 0;
    return true;
}

/* The words offered at asked position index: the right word and decoys, with the lock held. */
static bool offer_locked(struct wsu *w, size_t index)
{
    return zapp_words_choices(w->held.word[w->asked[index]], w->env.random, w->env.ctx, w->choice[index]);
}
static bool offer_all_locked(struct wsu *w)
{
    bool ok = true;
    memset(w->picked, 0, sizeof(w->picked));
    w->wrong = 0;
    for (size_t i = 0; ok && i < ZAPP_WORDS_ASKED; ++i) ok = offer_locked(w, i);
    return ok;
}
static void forget_choices_locked(struct wsu *w)
{
    memory_cleanse(w->choice, sizeof(w->choice));
    memory_cleanse(w->picked, sizeof(w->picked));
    w->wrong = 0;
}
void wsu_destroy(struct wsu *w)
{
    zapp_words_cleanse(&w->held);
    forget_choices_locked(w);
    pthread_mutex_destroy(&w->lock);
    memset(w, 0, sizeof(*w));
}

static void set_step(struct wsu *w, enum wsu_step step, enum wsu_failure failure)
{
    pthread_mutex_lock(&w->lock);
    w->step = step;
    w->failure = failure;
    w->refusal = WSU_NO_FAILURE;
    pthread_mutex_unlock(&w->lock);
}

/* A job begins, with the lock held: nothing of an earlier step may show, and the clock of seconds since setup began restarts. */
static void work_begins_locked(struct wsu *w)
{
    w->phase = WSU_PHASE_NONE;
    w->tip_blocks = 0;
    w->stage[0] = 0;
    w->phase_since_s = w->env.wall_s ? w->env.wall_s(w->env.ctx) : 0;
}
void wsu_view_read(struct wsu *w, struct wsu_view *out)
{
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&w->lock);
    out->step = w->step;
    out->failure = w->failure;
    out->refusal = w->refusal;
    out->protected = w->protected;
    out->mismatches = w->mismatches;
    out->birthday_unknown = !w->birthday.known;
    out->may_start_over = w->kind == ZAPP_KIND_CREATE && (!w->confirmed || !w->birthday.known);
    out->birthday_dropped = w->step == WSU_READING && !w->birthday_honoured;
    if (w->step == WSU_WORKING || w->step == WSU_CHECKING) {
        int64_t gone = w->env.wall_s && w->phase_since_s ? w->env.wall_s(w->env.ctx) - w->phase_since_s : 0;
        out->phase = w->phase;
        out->elapsed_s = gone > 0 ? gone : 0;
        out->tip_blocks = w->tip_blocks;
        memcpy(out->stage, w->stage, sizeof(out->stage));
    }
    if (w->failure == WSU_ASIDE_STUCK) memcpy(out->leftover, w->leftover, sizeof(out->leftover));
    if (w->step == WSU_WORDS && w->protected) { out->words = w->held; out->start_height = w->birthday.known ? w->birthday.height : 0; }
    if (w->step == WSU_CONFIRM) {
        memcpy(out->asked, w->asked, sizeof(out->asked));
        memcpy(out->choice, w->choice, sizeof(out->choice));
        memcpy(out->picked, w->picked, sizeof(out->picked));
        out->wrong_position = w->wrong ? w->asked[w->wrong - 1] + 1 : 0;
    }
    pthread_mutex_unlock(&w->lock);
}

static void move(struct wsu *w, enum wsu_step from, enum wsu_step to)
{
    pthread_mutex_lock(&w->lock);
    if (w->step == from) { w->step = to; w->failure = WSU_NO_FAILURE; }
    pthread_mutex_unlock(&w->lock);
}
bool wsu_open(struct wsu *w)
{
    bool on = w->env.protect(w->env.ctx, true);
    pthread_mutex_lock(&w->lock);
    w->protected = on;
    pthread_mutex_unlock(&w->lock);
    return on;
}
void wsu_close(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool was = w->protected;
    w->protected = false;
    pthread_mutex_unlock(&w->lock);
    if (was) (void)w->env.protect(w->env.ctx, false);
}
void wsu_open_restore(struct wsu *w) { move(w, WSU_CHOICE, WSU_RESTORE_FORM); }
void wsu_words_seen(struct wsu *w) { move(w, WSU_WORDS, WSU_CONFIRM); }
void wsu_show_again(struct wsu *w)
{
    move(w, WSU_CONFIRM, WSU_WORDS);
    pthread_mutex_lock(&w->lock);
    if (w->step == WSU_WORDS) { memset(w->picked, 0, sizeof(w->picked)); w->wrong = 0; }
    pthread_mutex_unlock(&w->lock);
}
/* After these failures a wallet may exist, so the choice is not offered again. */
static bool wallet_may_exist(enum wsu_failure failure)
{
    return failure == WSU_NOT_RECORDED || failure == WSU_UNKNOWN || failure == WSU_NO_BIRTHDAY || failure == WSU_ASIDE_STUCK;
}
void wsu_back(struct wsu *w)
{
    move(w, WSU_RESTORE_FORM, WSU_CHOICE);
    pthread_mutex_lock(&w->lock);
    /* A file that could not be moved leaves the wallet as it was: back to not knowing, where Check again reads it. */
    if (w->step == WSU_FAILED && w->failure == WSU_ASIDE) { w->step = WSU_BLOCKED; w->failure = WSU_UNKNOWN; }
    else if (w->step == WSU_FAILED && !wallet_may_exist(w->failure)) { w->step = WSU_CHOICE; w->failure = WSU_NO_FAILURE; }
    pthread_mutex_unlock(&w->lock);
}
bool wsu_retry_marker(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool ok = w->step == WSU_FAILED && w->failure == WSU_NOT_RECORDED && w->confirmed;
    if (ok) { w->step = WSU_WORKING; w->failure = WSU_NO_FAILURE; work_begins_locked(w); }
    pthread_mutex_unlock(&w->lock);
    return ok;
}
bool wsu_view_can_recheck(const struct wsu_view *v)
{
    bool failure = v->failure == WSU_UNKNOWN || v->failure == WSU_COULD_NOT_CHECK || v->failure == WSU_NODE_BUSY;
    return failure && (v->step == WSU_BLOCKED || v->failure == WSU_UNKNOWN);
}
void wsu_words_intro(const struct wsu_view *v, char *out, size_t cap)
{
    static const char tail[] = "They are shown once, and they are the only way to recover this wallet. Never type them anywhere else and never share them.";
    if (v->birthday_unknown)
        snprintf(out, cap, "Write down these words, on paper, in this order. The wallet did not record where it starts, so the words are all there is to write. %s", tail);
    else
        snprintf(out, cap, "Write down these words and start height %lld, on paper, in this order. %s", (long long)v->start_height, tail);
}
/* ---- the words of the screens that are not a view ---- */

static const struct { enum wsu_failure failure; const char *text; } failure_texts[] = {
    {WSU_DECLINED, "The screen lock was not confirmed, so nothing was changed. Try again."},
    {WSU_NO_SCREEN_LOCK, "This phone has no screen lock, and the wallet is protected by it. Set one in the phone's settings, then try again."},
    {WSU_KEY, "This phone could not make a protected key, so no wallet was made. Try again."},
    {WSU_NODE_BUSY, "Your node is still stopping. Try again in a minute."},
    {WSU_PRESENT, "This phone already has a wallet. Nothing was changed."},
    {WSU_BAD_PHRASE, "Those words are not a valid recovery phrase. Check each word and its order."},
    {WSU_BAD_WORDS, "Type all of your recovery words, 12, 15, 18, 21 or 24, separated by spaces."},
    {WSU_STORAGE, "Your node's saved data could not be read. Nothing was changed."},
    {WSU_REFUSED, "Your node refused the request. Nothing was changed. Try again."},
    {WSU_UNKNOWN, "Your node gave no clear answer, so a wallet may have been started. Its words cannot be shown again. Tap Check again."},
    {WSU_NOT_RECORDED, "The wallet exists, but the app could not record that setup finished. Tap Save again."},
    {WSU_NO_TIP, "Your node has not caught up enough to start a wallet, so none was made. Check your connection and try again."},
    {WSU_NO_BIRTHDAY, "Your words were confirmed, but the wallet has no start block, so setup is not finished. Tap Check again, or Start over to set it aside; nothing is deleted."},
    {WSU_NOT_RUN, "The wallet could not start, so nothing was changed. Try again."},
    {WSU_NOT_CREATE, "Start over is only for a new wallet. This one was restored from words."},
    {WSU_NOT_EMPTY, "Your node reports funds or transactions in this wallet, so it was not set aside."},
    {WSU_ALREADY_CONFIRMED, "The words of this wallet were confirmed, so it was not set aside."},
    {WSU_COULD_NOT_CHECK, "Your node did not say whether this wallet is empty, so nothing was changed. Try again."},
    {WSU_ASIDE, "The wallet could not be set aside, so nothing was changed."},
    {WSU_ASIDE_STUCK, "Some items could not be put back. Do not create a new wallet. They need their original names back:"},
    {WSU_UNPROTECTED, "This phone would not protect the screen from capture, so no wallet was made."},
};
const char *wsu_failure_text(enum wsu_failure failure)
{
    for (size_t i = 0; i < sizeof(failure_texts) / sizeof(failure_texts[0]); ++i)
        if (failure_texts[i].failure == failure) return failure_texts[i].text;
    return "";
}
void wsu_leave_notice(const struct wsu_view *v, char *out, size_t cap)
{
    bool words = v->step == WSU_WORDS || v->step == WSU_CONFIRM;
    snprintf(out, cap, "%s", words ? "Finish setup first. The recovery words are shown only once." : "Setting up. You can leave the app and come back.");
}
/* The block the node has reached, or what it is doing while it has none. */
static void tip_line(const struct wsu_view *v, char *out, size_t cap)
{
    if (v->tip_blocks > 0)
        snprintf(out, cap, "Waiting for your node to reach the latest block (block %lld)…", (long long)v->tip_blocks);
    else if (v->stage[0])
        snprintf(out, cap, "Waiting for your node to start: %s…", v->stage);
    else
        snprintf(out, cap, "Waiting for your node to start…");
}
void wsu_working_line(const struct wsu_view *v, char *out, size_t cap)
{
    static const char *const fixed[] = {
        [WSU_PHASE_NONE] = "Saving…",
        [WSU_PHASE_KEY] = "Confirm with your screen lock",
        [WSU_PHASE_PAUSE] = "Pausing your node to write the new wallet… (about 30 s)",
        [WSU_PHASE_WRITE] = "Writing your wallet…",
        [WSU_PHASE_RESTART] = "Starting your node again…",
        [WSU_PHASE_CHECK] = "Checking your wallet…"
    };
    if (v->phase == WSU_PHASE_TIP) tip_line(v, out, cap);
    else snprintf(out, cap, "%s", v->phase <= WSU_PHASE_CHECK ? fixed[v->phase] : fixed[WSU_PHASE_NONE]);
}
void wsu_elapsed_text(const struct wsu_view *v, char *out, size_t cap)
{
    if (v->elapsed_s < 60) snprintf(out, cap, "%lld s since setup began", (long long)v->elapsed_s);
    else snprintf(out, cap, "%lld min %02lld s since setup began", (long long)(v->elapsed_s / 60), (long long)(v->elapsed_s % 60));
}
bool wsu_recheck(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool ok = w->step == WSU_BLOCKED || (w->step == WSU_FAILED && (w->failure == WSU_UNKNOWN || w->failure == WSU_NO_BIRTHDAY || w->failure == WSU_ASIDE));
    if (ok) { w->step = WSU_CHECKING; w->failure = WSU_NO_FAILURE; work_begins_locked(w); }
    pthread_mutex_unlock(&w->lock);
    return ok;
}
bool wsu_busy(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool busy = w->step == WSU_WORKING || w->step == WSU_WORDS || w->step == WSU_CONFIRM;
    pthread_mutex_unlock(&w->lock);
    return busy;
}

/* ---- the shared parts of both jobs ---- */

static enum wsu_failure failure_of_key(enum zapp_devkey_status status)
{
    if (status == ZAPP_DEVKEY_DECLINED) return WSU_DECLINED;
    if (status == ZAPP_DEVKEY_NO_SCREEN_LOCK) return WSU_NO_SCREEN_LOCK;
    return WSU_KEY;
}
static enum wsu_failure failure_of_node(enum sun_result result)
{
    switch (result) {
    case SUN_NODE_RUNNING: return WSU_NODE_BUSY;
    case SUN_ALREADY_PRESENT: return WSU_PRESENT;
    case SUN_INVALID_PHRASE: return WSU_BAD_PHRASE;
    case SUN_STORAGE: return WSU_STORAGE;
    case SUN_REFUSED: return WSU_REFUSED;
    case SUN_NOT_RUN: return WSU_NOT_RUN;
    default: return WSU_UNKNOWN;
    }
}
static void hex_of(const uint8_t *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { out[2 * i] = digits[in[i] >> 4]; out[2 * i + 1] = digits[in[i] & 15]; }
    out[2 * n] = 0;
}

/* A wrapped passphrase in hex. The caller cleanses both. */
static enum wsu_failure new_passphrase(struct wsu *w, uint8_t secret[ZAPP_DEVKEY_SECRET], char hex[SUN_PASSPHRASE_HEX + 1])
{
    enum zapp_devkey_status status = w->env.wrap_new(w->env.ctx, secret);
    if (status != ZAPP_DEVKEY_OK) return failure_of_key(status);
    hex_of(secret, ZAPP_DEVKEY_SECRET, hex);
    return WSU_NO_FAILURE;
}
/* Names what the running job does now, so the screen can say it. */
static void phase(struct wsu *w, enum wsu_phase next)
{
    pthread_mutex_lock(&w->lock);
    w->phase = next;
    pthread_mutex_unlock(&w->lock);
}
/* True when no node process holds the files; waits up to STOP_WAIT_MS for one that is exiting. */
static bool wait_exit(struct wsu *w)
{
    for (unsigned waited = 0;; waited += STOP_POLL_MS) {
        if (!w->env.node_running(w->env.ctx)) return true;
        if (waited >= STOP_WAIT_MS) return false;
        w->env.pause_ms(w->env.ctx, STOP_POLL_MS);
    }
}
/* Asks a running node to exit and waits for the process to be gone; true when no node holds the files. */
static bool stop_node(struct wsu *w)
{
    if (!w->env.node_running(w->env.ctx)) return true;
    phase(w, WSU_PHASE_PAUSE);
    w->paused_node = true;
    w->env.node_control(w->env.ctx, false);
    return wait_exit(w);
}
/* Makes the node run: after a pause of setup's, the old process must be gone first, or the start is refused. False when it never
 * exits within the bound; the node is then not started a second time. */
static bool start_node(struct wsu *w)
{
    if (w->env.node_running(w->env.ctx) && !w->paused_node) return true;
    phase(w, WSU_PHASE_RESTART);
    if (!wait_exit(w)) return false;
    w->env.node_control(w->env.ctx, true);
    w->paused_node = false;
    return true;
}
/* A job that ended without a wallet: the key is discarded when nothing was written, and the node runs again if it did. */
static void end_failed(struct wsu *w, enum wsu_failure failure, bool node_was_running)
{
    if (failure != WSU_UNKNOWN) {
        w->env.discard_key(w->env.ctx);
        zapp_setup_kind_forget(w->files);
    }
    if (node_was_running) (void)start_node(w);
    set_step(w, WSU_FAILED, failure);
}

/* ---- create ---- */

/* Takes the job's turn: only an idle screen at step from, with the window protected, starts one. */
static bool begin_job(struct wsu *w, enum wsu_step from)
{
    pthread_mutex_lock(&w->lock);
    bool start = w->step == from;
    if (start && !w->protected) { w->step = WSU_FAILED; w->failure = WSU_UNPROTECTED; start = false; }
    else if (start) { w->step = WSU_WORKING; w->failure = WSU_NO_FAILURE; work_begins_locked(w); }
    pthread_mutex_unlock(&w->lock);
    return start;
}

/* Keeps what the screen shows while it waits: the node's height, or its boot stage while it gives none. */
static void note_tip(struct wsu *w, bool answered, int64_t blocks)
{
    char stage[sizeof(w->stage)] = "";
    if (!answered && w->env.node_stage) w->env.node_stage(w->env.ctx, stage, sizeof(stage));
    pthread_mutex_lock(&w->lock);
    w->tip_blocks = answered ? blocks : 0;
    memcpy(w->stage, stage, sizeof(stage));
    pthread_mutex_unlock(&w->lock);
}
/* The new wallet starts reading at the node's chain tip, and the node records that start only above SUN_BIRTHDAY_MARGIN blocks,
 * so a node that has not reached that height makes no wallet. */
static bool wait_for_tip(struct wsu *w)
{
    for (unsigned i = 0; i < TIP_POLLS; ++i) {
        int64_t headers = 0, blocks = 0;
        bool answered = sun_chain_tip(&w->node, &headers, &blocks);
        note_tip(w, answered, blocks);
        if (answered && headers > SUN_BIRTHDAY_MARGIN && blocks > SUN_BIRTHDAY_MARGIN) return true;
        w->env.pause_ms(w->env.ctx, TIP_POLL_MS);
    }
    return false;
}

static void create_succeeded(struct wsu *w, struct sun_created *created)
{
    pthread_mutex_lock(&w->lock);
    w->held = created->words;
    w->birthday = created->birthday;
    w->mismatches = 0;
    if (!zapp_words_pick(w->held.count, w->env.random, w->env.ctx, ZAPP_WORDS_ASKED, w->asked) || !offer_all_locked(w)) {
        forget_choices_locked(w);
        zapp_words_cleanse(&w->held);
        w->step = WSU_FAILED;
        w->failure = WSU_UNKNOWN;
    } else {
        w->step = WSU_WORDS;
        w->failure = WSU_NO_FAILURE;
    }
    pthread_mutex_unlock(&w->lock);
}

/* Starts the node if needed and waits for a chain tip. False, with the step set, when there is none: no wallet is made. */
static bool tip_ready(struct wsu *w, bool was_running)
{
    phase(w, WSU_PHASE_TIP);
    if (!was_running) (void)start_node(w);
    if (wait_for_tip(w)) return true;
    if (!was_running) (void)stop_node(w);
    set_step(w, WSU_FAILED, WSU_NO_TIP);
    return false;
}
/* Records the kind first, so a restart can tell what was begun, then runs create with no node holding the files. */
static enum sun_result create_run(struct wsu *w, const char *hex, struct sun_created *created)
{
    if (!zapp_setup_kind_write(w->files, ZAPP_KIND_CREATE)) return SUN_REFUSED;
    if (!stop_node(w)) return SUN_NODE_RUNNING;
    phase(w, WSU_PHASE_WRITE);
    return sun_create(&w->node, hex, created);
}

void wsu_create_job(struct wsu *w)
{
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    char hex[SUN_PASSPHRASE_HEX + 1];
    struct sun_created created;
    memset(&created, 0, sizeof(created));
    if (!begin_job(w, WSU_CHOICE)) return;
    bool was_running = w->env.node_running(w->env.ctx);
    if (!tip_ready(w, was_running)) return;
    phase(w, WSU_PHASE_KEY);
    enum wsu_failure failure = new_passphrase(w, secret, hex);
    if (failure != WSU_NO_FAILURE) {
        if (!was_running) (void)stop_node(w);
        set_step(w, WSU_FAILED, failure);
        goto out;
    }
    enum sun_result result = create_run(w, hex, &created);
    if (result != SUN_OK) { end_failed(w, failure_of_node(result), was_running); goto out; }
    create_succeeded(w, &created);
    (void)start_node(w);
out:
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(hex, sizeof(hex));
    memory_cleanse(&created, sizeof(created));
}

bool wsu_confirm(struct wsu *w, const char *const *answers, size_t n)
{
    pthread_mutex_lock(&w->lock);
    bool right = w->step == WSU_CONFIRM && n == ZAPP_WORDS_ASKED && zapp_words_match(&w->held, w->asked, answers, n);
    if (right) {
        forget_choices_locked(w);
        zapp_words_cleanse(&w->held);
        w->confirmed = true;
        w->step = WSU_WORKING;
        w->failure = WSU_NO_FAILURE;
        work_begins_locked(w);
    } else if (w->step == WSU_CONFIRM) {
        ++w->mismatches;
    }
    pthread_mutex_unlock(&w->lock);
    return right;
}

bool wsu_pick(struct wsu *w, size_t index, size_t slot)
{
    pthread_mutex_lock(&w->lock);
    bool live = w->step == WSU_CONFIRM && index < ZAPP_WORDS_ASKED && slot < ZAPP_WORD_CHOICES;
    bool right = live && !strcmp(w->choice[index][slot], w->held.word[w->asked[index]]);
    if (right) {
        memcpy(w->picked[index], w->choice[index][slot], sizeof(w->picked[index]));
        w->wrong = 0;
    } else if (live) {
        ++w->mismatches;
        w->wrong = (unsigned)index + 1;
        memset(w->picked[index], 0, sizeof(w->picked[index]));
        (void)offer_locked(w, index);
    }
    pthread_mutex_unlock(&w->lock);
    return right;
}
bool wsu_confirm_picked(struct wsu *w)
{
    char typed[ZAPP_WORDS_ASKED][ZAPP_WORD_LETTERS + 1];
    const char *answers[ZAPP_WORDS_ASKED];
    pthread_mutex_lock(&w->lock);
    memcpy(typed, w->picked, sizeof(typed));
    pthread_mutex_unlock(&w->lock);
    bool all = true;
    for (size_t i = 0; i < ZAPP_WORDS_ASKED; ++i) {
        answers[i] = typed[i];
        all = all && typed[i][0];
    }
    bool right = all && wsu_confirm(w, answers, ZAPP_WORDS_ASKED);
    memory_cleanse(typed, sizeof(typed));
    return right;
}

/* The confirmation is written on its own, before any later step, and retried: a restart then never offers to start over a confirmed create. */
static bool record_confirmed(struct wsu *w)
{
    for (unsigned i = 0; i < CONFIRM_TRIES; ++i) {
        if (zapp_setup_mark_confirmed(w->files, w->birthday.known)) return true;
        w->env.pause_ms(w->env.ctx, CONFIRM_RETRY_MS);
    }
    return false;
}

void wsu_finish_job(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool go = w->confirmed && w->step == WSU_WORKING;
    bool lacks_start = !w->restored && !w->birthday.known;
    bool restored = w->restored;
    pthread_mutex_unlock(&w->lock);
    if (!go) return;
    if (!record_confirmed(w)) { set_step(w, WSU_FAILED, WSU_NOT_RECORDED); return; }
    if (lacks_start) { set_step(w, WSU_FAILED, WSU_NO_BIRTHDAY); return; }
    bool recorded = zapp_setup_mark_done(w->files);
    if (!recorded) set_step(w, WSU_FAILED, WSU_NOT_RECORDED);
    else set_step(w, restored ? WSU_READING : WSU_DONE, WSU_NO_FAILURE);
}

/* ---- restore ---- */

static struct sun_birthday birthday_at(struct wsu *w, int64_t height)
{
    struct sun_birthday birthday = {0};
    if (height > 0 && w->env.node_running(w->env.ctx) && sun_block_hash(&w->node, height, birthday.hash)) {
        birthday.known = true;
        birthday.height = height;
    }
    return birthday;
}

/* The restore is in the node: the owner typed the words, so setup is complete once the marker is written. */
static void restore_succeeded(struct wsu *w, const struct sun_restored *restored, bool honoured)
{
    pthread_mutex_lock(&w->lock);
    w->birthday_honoured = honoured || (restored && restored->birthday_recorded && !restored->birthday_rejected);
    w->confirmed = true;
    w->restored = true;
    w->step = WSU_WORKING;
    w->failure = WSU_NO_FAILURE;
    pthread_mutex_unlock(&w->lock);
    (void)start_node(w);
    wsu_finish_job(w);
}

static enum sun_result restore_run(struct wsu *w, const struct zapp_words *words, const char *hex,
                                   const struct sun_birthday *birthday, struct sun_restored *restored)
{
    if (!zapp_setup_kind_write(w->files, ZAPP_KIND_RESTORE)) return SUN_REFUSED;
    if (!stop_node(w)) return SUN_NODE_RUNNING;
    phase(w, WSU_PHASE_WRITE);
    return sun_restore(&w->node, words, hex, birthday, restored);
}

void wsu_restore_job(struct wsu *w, const char *text, int64_t birthday_height)
{
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    char hex[SUN_PASSPHRASE_HEX + 1];
    struct zapp_words words;
    struct sun_restored restored;
    memset(&words, 0, sizeof(words));
    if (!begin_job(w, WSU_RESTORE_FORM)) return;
    if (!zapp_words_parse(text, &words)) { set_step(w, WSU_RESTORE_FORM, WSU_BAD_WORDS); goto out; }
    phase(w, WSU_PHASE_KEY);
    enum wsu_failure failure = new_passphrase(w, secret, hex);
    if (failure != WSU_NO_FAILURE) { set_step(w, WSU_RESTORE_FORM, failure); goto out; }
    bool was_running = w->env.node_running(w->env.ctx);
    struct sun_birthday birthday = birthday_at(w, birthday_height);
    pthread_mutex_lock(&w->lock);
    w->birthday = birthday;
    pthread_mutex_unlock(&w->lock);
    enum sun_result result = restore_run(w, &words, hex, &birthday, &restored);
    if (result != SUN_OK) { end_failed(w, failure_of_node(result), was_running); goto out; }
    restore_succeeded(w, &restored, false);
out:
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(hex, sizeof(hex));
    zapp_words_cleanse(&words);
}

bool wsu_reading(struct wsu *w, int64_t *scanned, int64_t *tip)
{
    return w->env.progress(w->env.ctx, scanned, tip);
}
void wsu_finish_reading(struct wsu *w) { move(w, WSU_READING, WSU_DONE); }

/* A create whose words matched and whose setup marker was not written before the app stopped: the confirmation record says so, so
 * the finishing step runs again with the start height the record kept. */
static void confirmed_create_resumes(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    w->confirmed = true;
    w->birthday.known = zapp_setup_confirmed_start(w->files);
    w->step = WSU_WORKING;
    w->failure = WSU_NO_FAILURE;
    pthread_mutex_unlock(&w->lock);
    wsu_finish_job(w);
}

void wsu_resume_job(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool go = w->step == WSU_CHECKING;
    if (go) w->kind = zapp_setup_kind_read(w->files);
    enum zapp_setup_kind kind = w->kind;
    pthread_mutex_unlock(&w->lock);
    if (!go) return;
    /* The status command refuses a datadir a running node holds, so the node is stopped for the read and started again after. */
    bool was_running = w->env.node_running(w->env.ctx);
    if (!stop_node(w)) {
        if (was_running) (void)start_node(w);
        set_step(w, WSU_BLOCKED, WSU_NODE_BUSY);
        return;
    }
    phase(w, WSU_PHASE_CHECK);
    enum sun_probe probe = sun_wallet_probe(&w->node);
    if (was_running && !(probe == SUN_PROBE_PRESENT && kind == ZAPP_KIND_RESTORE)) (void)start_node(w);
    switch (probe) {
    case SUN_PROBE_NONE:
        set_step(w, WSU_NO_WALLET, WSU_NO_FAILURE);
        break;
    case SUN_PROBE_PRESENT:
        if (kind == ZAPP_KIND_RESTORE) restore_succeeded(w, NULL, true);
        else if (kind == ZAPP_KIND_CREATE && zapp_setup_confirmed(w->files)) confirmed_create_resumes(w);
        else set_step(w, WSU_BLOCKED, WSU_NO_FAILURE);
        break;
    default:
        set_step(w, WSU_BLOCKED, WSU_UNKNOWN);
        break;
    }
}

/* One thing set aside: a file or directory under dir. */
struct aside_item { const char *dir; const char *name; };
enum { ASIDE_ITEMS_MAX = 5 };

/* Names the item that stays moved aside, for the message that tells the owner where it is. */
static void note_leftover(struct wsu *w, const struct aside_item *item, int64_t now)
{
    char path[ASIDE_PATH_MAX];
    size_t used = strlen(w->leftover);
    if (!zapp_setup_aside_path(item->dir, item->name, now, path, sizeof(path))) return;
    snprintf(w->leftover + used, sizeof(w->leftover) - used, "%s%s", used ? "\n" : "", path);
}
/* Moves every item aside or none: on a failure the items already moved go back, last first. STUCK when one cannot go back. */
static enum wsu_failure set_aside_items(struct wsu *w, const struct aside_item *items, size_t n, int64_t now, const char *new_dir)
{
    bool moved[ASIDE_ITEMS_MAX] = {false};
    size_t tried = 0;
    bool ok = true;
    for (; ok && tried < n; ++tried) {
        enum zapp_aside r = zapp_setup_set_aside(items[tried].dir, items[tried].name, now);
        ok = r != ZAPP_ASIDE_FAILED;
        moved[tried] = r == ZAPP_ASIDE_MOVED;
    }
    if (ok && new_dir && mkdir(new_dir, 0700) != 0) ok = false;
    if (ok) return WSU_NO_FAILURE;
    pthread_mutex_lock(&w->lock);
    w->leftover[0] = 0;
    pthread_mutex_unlock(&w->lock);
    bool back = true;
    for (size_t i = tried; i-- > 0;) {
        if (!moved[i] || zapp_setup_undo_aside(items[i].dir, items[i].name, now)) continue;
        back = false;
        pthread_mutex_lock(&w->lock);
        note_leftover(w, &items[i], now);
        pthread_mutex_unlock(&w->lock);
    }
    return back ? WSU_ASIDE : WSU_ASIDE_STUCK;
}
/* The wrapped key and the setup records, under one timestamp. */
static enum wsu_failure set_aside_key(struct wsu *w, int64_t now)
{
    const struct aside_item items[] = {{w->files, "wallet_key.blob"}, {w->files, "wallet_setup_kind"}, {w->files, "wallet_setup_confirmed"}};
    return set_aside_items(w, items, sizeof(items) / sizeof(items[0]), now, NULL);
}
/* The whole datadir in one rename, so the database and its journal files cannot be split, then the key and records: all or none. */
static enum wsu_failure set_aside_all(struct wsu *w, int64_t now)
{
    char parent[ASIDE_PATH_MAX];
    const char *slash = strrchr(w->node.datadir, '/');
    if (!slash || slash == w->node.datadir || (size_t)(slash - w->node.datadir) >= sizeof(parent)) return WSU_ASIDE;
    memcpy(parent, w->node.datadir, (size_t)(slash - w->node.datadir));
    parent[slash - w->node.datadir] = 0;
    const struct aside_item items[] = {{parent, slash + 1}, {w->files, "wallet_key.blob"}, {w->files, "wallet_setup_kind"}, {w->files, "wallet_setup_confirmed"}};
    return set_aside_items(w, items, sizeof(items) / sizeof(items[0]), now, w->node.datadir);
}

void wsu_set_aside_job(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool go = w->step == WSU_NO_WALLET;
    if (go) { w->step = WSU_WORKING; work_begins_locked(w); }
    pthread_mutex_unlock(&w->lock);
    if (!go) return;
    enum wsu_failure failure = set_aside_key(w, w->env.wall_s(w->env.ctx));
    set_step(w, failure == WSU_NO_FAILURE ? WSU_CHOICE : WSU_FAILED, failure);
}

/* Whether the owner proved the words of a create. A confirmation record that kept no start height does not count: that wallet has
 * no start to write down, setup cannot finish, and Start over (which still requires an empty wallet) is its way forward. */
static bool words_proved(struct wsu *w)
{
    if (zapp_setup_state(w->files) == ZAPP_SETUP_READY) return true;
    if (zapp_setup_confirmed(w->files)) return zapp_setup_confirmed_start(w->files);
    return w->confirmed;
}

bool wsu_ask_start_over(struct wsu *w)
{
    enum zapp_setup_kind kind = zapp_setup_kind_read(w->files);
    bool proved = words_proved(w);
    pthread_mutex_lock(&w->lock);
    bool blocked = w->step == WSU_BLOCKED && (w->failure == WSU_NO_FAILURE || w->failure == WSU_COULD_NOT_CHECK || w->failure == WSU_NODE_BUSY);
    bool ok = blocked || (w->step == WSU_FAILED && w->failure == WSU_NO_BIRTHDAY);
    enum wsu_failure why = kind != ZAPP_KIND_CREATE ? WSU_NOT_CREATE : proved ? WSU_ALREADY_CONFIRMED : WSU_NO_FAILURE;
    if (ok) { w->step = why == WSU_NO_FAILURE ? WSU_START_OVER : WSU_BLOCKED; w->failure = why; }
    pthread_mutex_unlock(&w->lock);
    return ok && why == WSU_NO_FAILURE;
}
/* Back to the screen the warning came from: a wallet that recorded no start height returns to saying so. */
void wsu_cancel_start_over(struct wsu *w)
{
    bool no_start = zapp_setup_confirmed(w->files) && !zapp_setup_confirmed_start(w->files);
    pthread_mutex_lock(&w->lock);
    if (w->step == WSU_START_OVER) { w->step = no_start ? WSU_FAILED : WSU_BLOCKED; w->failure = no_start ? WSU_NO_BIRTHDAY : WSU_NO_FAILURE; w->refusal = WSU_NO_FAILURE; }
    pthread_mutex_unlock(&w->lock);
}

/* Whether the running node reports an empty wallet; starts the node when needed and waits for an answer. */
static enum wsu_idle wallet_idle(struct wsu *w)
{
    phase(w, WSU_PHASE_CHECK);
    (void)start_node(w);
    for (unsigned i = 0; i < IDLE_POLLS; ++i) {
        enum wsu_idle idle = w->env.wallet_idle(w->env.ctx);
        if (idle != WSU_IDLE_UNKNOWN) return idle;
        w->env.pause_ms(w->env.ctx, IDLE_POLL_MS);
    }
    return WSU_IDLE_UNKNOWN;
}
/* The reason a start over must be refused, or NO_FAILURE: kind, confirmation, then what the node reports. */
static enum wsu_failure start_over_refusal(struct wsu *w)
{
    if (zapp_setup_kind_read(w->files) != ZAPP_KIND_CREATE) return WSU_NOT_CREATE;
    if (words_proved(w)) return WSU_ALREADY_CONFIRMED;
    enum wsu_idle idle = wallet_idle(w);
    if (idle == WSU_IDLE_FUNDS) return WSU_NOT_EMPTY;
    return idle == WSU_IDLE_UNKNOWN ? WSU_COULD_NOT_CHECK : WSU_NO_FAILURE;
}

/* A wallet that recorded no start height returns to saying so, as Cancel does: the blocked screen would describe unconfirmed words. */
static void start_over_refused(struct wsu *w, enum wsu_failure refusal)
{
    bool no_start = zapp_setup_confirmed(w->files) && !zapp_setup_confirmed_start(w->files);
    set_step(w, no_start ? WSU_FAILED : WSU_BLOCKED, no_start ? WSU_NO_BIRTHDAY : refusal);
    pthread_mutex_lock(&w->lock);
    if (no_start) w->refusal = refusal;   /* the screen names it; its own text does not */
    pthread_mutex_unlock(&w->lock);
}

void wsu_start_over_job(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool go = w->step == WSU_START_OVER;
    if (go) { w->step = WSU_WORKING; w->failure = WSU_NO_FAILURE; work_begins_locked(w); }
    pthread_mutex_unlock(&w->lock);
    if (!go) return;
    enum wsu_failure refusal = start_over_refusal(w);
    if (refusal == WSU_NO_FAILURE && !stop_node(w)) refusal = WSU_NODE_BUSY;
    if (refusal != WSU_NO_FAILURE) {
        if (w->paused_node) (void)start_node(w);
        start_over_refused(w, refusal);
        return;
    }
    enum wsu_failure failure = set_aside_all(w, w->env.wall_s(w->env.ctx));
    if (failure == WSU_NO_FAILURE) {
        pthread_mutex_lock(&w->lock);
        w->confirmed = false;
        memset(&w->birthday, 0, sizeof(w->birthday));
        pthread_mutex_unlock(&w->lock);
    }
    if (w->paused_node) (void)start_node(w);
    set_step(w, failure == WSU_NO_FAILURE ? WSU_CHOICE : WSU_FAILED, failure);
}

int wsu_summary_state(const struct json_value *data)
{
    static const char *const keys[] = {"spendable_zat", "pending_zat", "sending_zat", "public_zat", "immature_zat", "pending_notes"};
    int zero = 1;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const struct json_value *v = json_get(data, keys[i]);
        if (!v || v->type != JSON_INT) zero = zero == 0 ? 0 : -1;
        else if (json_get_int(v) != 0) zero = 0;
    }
    if (zero != 1) return zero;
    const struct json_value *current = json_get(data, "current"), *listed = json_get(data, "shielded_keys");
    bool ready = current && current->type == JSON_BOOL && json_get_bool(current) && listed && listed->type == JSON_INT && json_get_int(listed) > 0;
    return ready ? 1 : -1;
}
int wsu_history_state(const struct json_value *data)
{
    int lists = 0;
    for (size_t i = 0; data && i < data->num_children; ++i) {
        if (data->children[i].type != JSON_ARR) continue;
        ++lists;
        if (data->children[i].num_children) return 0;
    }
    return lists ? 1 : -1;
}
