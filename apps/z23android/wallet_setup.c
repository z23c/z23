/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "wallet_setup.h"
#include "base/cleanse.h"
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

#define ASIDE_PATH_MAX 512
/* A phone node saves its database before it exits: 50 s measured on a Pixel, the fast-restart save alone 35 s, and 2 min 40 s on
 * 2026-11-03 while its history catch-up ran. Three times the first bounds the wait for a node to exit, before create or restore and
 * again before the node is started; the screen shows the bound beside the clock of the wait. */
#define STOP_WAIT_MS 180000u
#define STOP_POLL_MS 250u
/* A node that runs may still be starting: a question it cannot answer yet is asked again IDLE_POLL_MS later, IDLE_POLLS times in
 * all. The check after a restart also asks no question IDLE_WAIT_S or more after its first, because one question can take as long
 * as the command line is given; the two minutes are over twice the 50 s a Pixel node took on 2026-11-03 to answer after a start. */
#define IDLE_POLLS 24u
#define IDLE_POLL_MS 5000u
#define IDLE_WAIT_S (IDLE_POLLS * IDLE_POLL_MS / 1000u)
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
bool wsu_receive_address(struct wsu *w, char *out, size_t cap, uint64_t *generation)
{
    if (!out || !cap || !generation) return false;
    out[0] = 0;
    pthread_mutex_lock(&w->lock);
    bool ok = w->confirmed && w->first_shielded_address[0] &&
              zapp_setup_state(w->files) == ZAPP_SETUP_READY && zapp_setup_confirmed(w->files) &&
              strlen(w->first_shielded_address) < cap;
    if (ok) { memcpy(out, w->first_shielded_address, strlen(w->first_shielded_address) + 1); *generation = w->address_generation; }
    pthread_mutex_unlock(&w->lock);
    return ok;
}
void wsu_destroy(struct wsu *w)
{
    zapp_words_cleanse(&w->held);
    zapp_words_cleanse(&w->phrase);
    memory_cleanse(w->write_pass, sizeof(w->write_pass));
    forget_choices_locked(w);
    memory_cleanse(w->form, sizeof(w->form));
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

/* A job or one of its sub-steps begins, with the lock held: the screen names it, and its clock starts again at zero. */
static void work_begins_locked(struct wsu *w, enum wsu_phase first)
{
    w->phase = first;
    w->phase_since_s = w->env.wall_s ? w->env.wall_s(w->env.ctx) : 0;
}
/* A step runs that the screen shows with its live line, with the lock held. */
static bool waiting_locked(const struct wsu *w)
{
    return w->step == WSU_WORKING || w->step == WSU_CHECKING || w->write == WSU_WRITE_RUNNING;
}
bool wsu_waiting(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool waiting = waiting_locked(w);
    pthread_mutex_unlock(&w->lock);
    return waiting;
}
/* The parts of the view that belong to a running job, with the lock held. */
static void view_job_locked(struct wsu *w, struct wsu_view *out)
{
    int64_t gone = w->env.wall_s && w->phase_since_s ? w->env.wall_s(w->env.ctx) - w->phase_since_s : 0;
    out->phase = w->phase;
    out->elapsed_s = gone > 0 ? gone : 0;
}
/* The parts of the view that belong to the words and their check, with the lock held. */
static void view_words_locked(struct wsu *w, struct wsu_view *out)
{
    out->write = w->write;
    out->write_failure = w->write_failure;
    out->start_pending = w->words_first;
    if (w->step == WSU_WORDS && w->protected) { out->words = w->held; out->start_height = w->birthday.known ? w->birthday.height : 0; }
    if (w->step != WSU_CONFIRM) return;
    memcpy(out->asked, w->asked, sizeof(out->asked));
    memcpy(out->choice, w->choice, sizeof(out->choice));
    memcpy(out->picked, w->picked, sizeof(out->picked));
    out->wrong_position = w->wrong ? w->asked[w->wrong - 1] + 1 : 0;
}
/* The restore words stay for the form while it is shown and while its job runs; the view wipes them at every other step. */
static bool form_kept(enum wsu_step step)
{
    return step == WSU_RESTORE_FORM || step == WSU_WORKING;
}
void wsu_view_read(struct wsu *w, struct wsu_view *out)
{
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&w->lock);
    out->step = w->step;
    if (form_kept(w->step)) memcpy(out->form, w->form, sizeof(out->form));
    else memory_cleanse(w->form, sizeof(w->form));
    out->failure = w->failure;
    out->refusal = w->refusal;
    out->bad_word = w->bad_word;
    out->protected = w->protected;
    out->mismatches = w->mismatches;
    out->birthday_unknown = !w->birthday.known;
    out->may_start_over = w->kind == ZAPP_KIND_CREATE && (!w->confirmed || !w->birthday.known);
    out->birthday_dropped = w->step == WSU_READING && !w->birthday_honoured;
    if (waiting_locked(w)) view_job_locked(w, out);
    if (w->failure == WSU_ASIDE_STUCK) memcpy(out->leftover, w->leftover, sizeof(out->leftover));
    if (w->step == WSU_WORDS || w->step == WSU_CONFIRM) view_words_locked(w, out);
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
    if (ok) { w->step = WSU_WORKING; w->failure = WSU_NO_FAILURE; work_begins_locked(w, WSU_PHASE_SAVE); }
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
    if (v->start_pending)
        snprintf(out, cap, "Write down these words, on paper, in this order. %s", tail);
    else if (v->birthday_unknown)
        snprintf(out, cap, "Write down these words, on paper, in this order. The wallet did not record where it starts, so the words are all there is to write. %s", tail);
    else
        snprintf(out, cap, "Write down these words and start height %lld, on paper, in this order. %s", (long long)v->start_height, tail);
}
/* ---- the words of the screens that are not a view ---- */

static const struct { enum wsu_failure failure; const char *text; } failure_texts[] = {
    {WSU_DECLINED, "The screen lock was not confirmed. Wallet setup was not completed."},
    {WSU_NO_SCREEN_LOCK, "This phone has no screen lock, and the wallet is protected by it. Set one in the phone's settings, then try again."},
    {WSU_KEY, "This phone could not make a protected key, so no wallet was made. Try again."},
    {WSU_NO_HARDWARE_KEY, "This phone cannot protect a wallet key in hardware, so the app will not make a wallet here."},
    {WSU_NODE_BUSY, "Your node is still stopping. Try again in a minute."},
    {WSU_PRESENT, "This phone already has a wallet. Nothing was changed."},
    {WSU_BAD_PHRASE, "Those words are not a valid recovery phrase. Check each word and its order."},
    {WSU_BAD_WORDS, "Type all of your recovery words, 12, 15, 18, 21 or 24, separated by spaces."},
    {WSU_STORAGE, "Your node's saved data could not be read. Nothing was changed."},
    {WSU_REFUSED, "Your node refused the request. Nothing was changed. Try again."},
    {WSU_UNKNOWN, "Your node gave no clear answer, so a wallet may have been started. Its words cannot be shown again. Tap Check again."},
    {WSU_NOT_RECORDED, "The wallet exists, but the app could not record that setup finished. Tap Save again."},
    {WSU_NO_BIRTHDAY, "Your words were confirmed, but the wallet has no start block, so setup is not finished. Tap Check again, or Start over to set it aside; nothing is deleted."},
    {WSU_NOT_RUN, "The wallet could not start, so nothing was changed. Try again."},
    {WSU_NOT_CREATE, "Start over is only for a new wallet. This one was restored from words."},
    {WSU_NOT_EMPTY, "Your node reports funds or transactions in this wallet, so it was not set aside."},
    {WSU_ALREADY_CONFIRMED, "The words of this wallet were confirmed, so it was not set aside."},
    {WSU_COULD_NOT_CHECK, "Your node did not say whether this wallet is empty, so nothing was changed. Try again."},
    {WSU_ASIDE, "The wallet could not be set aside, so nothing was changed."},
    {WSU_ASIDE_STUCK, "Some items could not be put back. Do not create a new wallet. They need their original names back:"},
    {WSU_UNPROTECTED, "This phone would not protect the screen from capture, so no wallet was made."},
    {WSU_BAD_WORD, "A recovery word is not on the word list. Check each word's spelling."},
    {WSU_WALLET_THERE, "A wallet is already on this phone. Start over to make a new one, or restore your words."},
};
bool wsu_failure_retries(enum wsu_failure failure)
{
    return failure != WSU_NO_HARDWARE_KEY;
}
const char *wsu_failure_text(enum wsu_failure failure)
{
    for (size_t i = 0; i < sizeof(failure_texts) / sizeof(failure_texts[0]); ++i)
        if (failure_texts[i].failure == failure) return failure_texts[i].text;
    return "";
}
void wsu_bad_word_text(size_t position, char *out, size_t cap)
{
    snprintf(out, cap, "Word %zu is not in the recovery word list. Check its spelling.", position + 1);
}
/* Only a probe that found the wallet says a wallet was started; a busy node or a failed check gets its failure text alone. */
const char *wsu_interrupted_note(enum wsu_failure failure)
{
    if (failure == WSU_UNKNOWN) return "Your node did not answer, so the app cannot tell whether a wallet exists.";
    if (failure == WSU_NO_FAILURE) return "A wallet was started on this phone and its recovery words were not confirmed. The app cannot show these words again. Receive stays closed until setup is confirmed.";
    return "";
}
void wsu_leave_notice(const struct wsu_view *v, char *out, size_t cap)
{
    bool words = v->step == WSU_WORDS || v->step == WSU_CONFIRM;
    snprintf(out, cap, "%s", words ? "Finish setup first. The recovery words are shown only once." : "Setting up. You can leave the app and come back.");
}
/* Each sub-step in plain words, with the most the app waits for it in seconds, or 0 when it has no bound of its own: a node gets
 * STOP_WAIT_MS to exit, and the node command that writes the wallet is stopped at SUN_RESTORE_TIMEOUT_MS. */
static const struct { const char *text; unsigned limit_s; } phase_lines[] = {
    [WSU_PHASE_NONE] = {"Getting ready", 0},
    [WSU_PHASE_KEY] = {"Confirm with your screen lock", 0},
    [WSU_PHASE_PAUSE] = {"Pausing your node so your wallet can be saved safely", STOP_WAIT_MS / 1000u},
    [WSU_PHASE_PAUSE_CHECK] = {"Pausing your node so this phone's wallet can be checked safely", STOP_WAIT_MS / 1000u},
    [WSU_PHASE_PAUSE_ASIDE] = {"Pausing your node so your old wallet can be set aside safely", STOP_WAIT_MS / 1000u},
    [WSU_PHASE_WRITE] = {"Saving your wallet", SUN_RESTORE_TIMEOUT_MS / 1000u},
    [WSU_PHASE_RESTART] = {"Starting your node again", STOP_WAIT_MS / 1000u},
    [WSU_PHASE_CHECK] = {"Checking your wallet", 0},
    [WSU_PHASE_ASIDE] = {"Setting aside your old wallet", 0},
    [WSU_PHASE_SAVE] = {"Finishing setup", 0},
};
void wsu_working_line(const struct wsu_view *v, char *out, size_t cap)
{
    size_t p = (size_t)v->phase < sizeof(phase_lines) / sizeof(phase_lines[0]) ? (size_t)v->phase : WSU_PHASE_NONE;
    long long s = v->elapsed_s > 0 ? (long long)v->elapsed_s : 0, limit = phase_lines[p].limit_s;
    if (s < limit)
        snprintf(out, cap, "%s - %lld:%02lld (up to %lld:%02lld)", phase_lines[p].text, s / 60, s % 60, limit / 60, limit % 60);
    else
        snprintf(out, cap, "%s - %lld:%02lld", phase_lines[p].text, s / 60, s % 60);
}

/* A failed write behind the shown words. The words and their passphrase are kept, so Try again writes the same words again; a
 * failure a new attempt would meet again offers no Try again and says what happens instead. */
static const struct { enum wsu_failure failure; const char *text; } write_failure_texts[] = {
    {WSU_NODE_BUSY, "Your node did not pause in time, so your wallet is not saved yet. Tap Try again."},
    {WSU_STORAGE, "Your node could not read its saved data, so your wallet was not saved, and saving again would fail the same way. "
                  "Your node keeps running. Tap Check wallet."},
    {WSU_NOT_RUN, "Saving your wallet could not start, so nothing was saved. Tap Try again."},
    {WSU_UNKNOWN, "Saving your wallet stopped before your node answered, so the app cannot tell whether it was saved. Tap Try again."},
};
const char *wsu_write_failure_text(enum wsu_failure failure)
{
    if (failure == WSU_NO_FAILURE) return "";
    for (size_t i = 0; i < sizeof(write_failure_texts) / sizeof(write_failure_texts[0]); ++i)
        if (write_failure_texts[i].failure == failure) return write_failure_texts[i].text;
    return "Your node refused to save your wallet, so nothing was saved, and saving again would be refused the same way. "
           "Your node keeps running. Tap Check wallet.";
}
bool wsu_write_retryable(enum wsu_failure failure)
{
    return failure == WSU_NODE_BUSY || failure == WSU_NOT_RUN || failure == WSU_UNKNOWN;
}
static bool all_picked(const struct wsu_view *v)
{
    for (size_t i = 0; i < ZAPP_WORDS_ASKED; ++i)
        if (!v->picked[i][0]) return false;
    return true;
}
bool wsu_view_confirm_ready(const struct wsu_view *v)
{
    return v->step == WSU_CONFIRM && all_picked(v) && (!v->start_pending || v->write == WSU_WRITE_DONE);
}
_Static_assert(ZAPP_WORDS_ASKED == 3u, "the note says three words");
const char *wsu_confirm_note(const struct wsu_view *v)
{
    bool waits = v->step == WSU_CONFIRM && all_picked(v) && !wsu_view_confirm_ready(v) && v->write != WSU_WRITE_FAILED;
    return waits ? "All three words are right. Confirm appears here once your wallet is saved." : "";
}
bool wsu_recheck(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool ok = w->step == WSU_BLOCKED || (w->step == WSU_FAILED && (w->failure == WSU_UNKNOWN || w->failure == WSU_NO_BIRTHDAY || w->failure == WSU_ASIDE));
    if (ok) { w->step = WSU_CHECKING; w->failure = WSU_NO_FAILURE; work_begins_locked(w, WSU_PHASE_NONE); }
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
bool wsu_resume_needed(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool needed = waiting_locked(w) || w->step == WSU_WORDS || w->step == WSU_CONFIRM;
    pthread_mutex_unlock(&w->lock);
    return needed;
}
bool wsu_created(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool created = w->step == WSU_DONE && w->confirmed && !w->restored;
    pthread_mutex_unlock(&w->lock);
    return created;
}

/* ---- the shared parts of both jobs ---- */

static enum wsu_failure failure_of_key(enum zapp_devkey_status status)
{
    if (status == ZAPP_DEVKEY_DECLINED) return WSU_DECLINED;
    if (status == ZAPP_DEVKEY_NO_SCREEN_LOCK) return WSU_NO_SCREEN_LOCK;
    if (status == ZAPP_DEVKEY_NOT_HARDWARE) return WSU_NO_HARDWARE_KEY;
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
/* Names what the running job does now and starts its clock, so the screen can say what it waits for and for how long. */
static void phase(struct wsu *w, enum wsu_phase next)
{
    pthread_mutex_lock(&w->lock);
    work_begins_locked(w, next);
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
/* Asks a running node to exit and waits for the process to be gone; true when no node holds the files. why is the pause the screen
 * names: to save, to check or to set aside the wallet. */
static bool stop_node(struct wsu *w, enum wsu_phase why)
{
    if (!w->env.node_running(w->env.ctx)) return true;
    phase(w, why);
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
/* A job that ended without a wallet: the key is discarded when nothing was written, and the node runs again if it did. The job then
 * moves to step. */
static void end_failed(struct wsu *w, enum wsu_failure failure, bool node_was_running, enum wsu_step step)
{
    if (failure != WSU_UNKNOWN) {
        w->env.discard_key(w->env.ctx);
        zapp_setup_kind_forget(w->files);
    }
    if (node_was_running) (void)start_node(w);
    set_step(w, step, failure);
}

/* ---- create ---- */

/* Takes the job's turn: only an idle screen at step from, with the window protected, starts one. */
static bool begin_job(struct wsu *w, enum wsu_step from)
{
    pthread_mutex_lock(&w->lock);
    bool start = w->step == from;
    if (start && !w->protected) { w->step = WSU_FAILED; w->failure = WSU_UNPROTECTED; start = false; }
    else if (start) { zapp_setup_preload_invalidate(); w->first_shielded_address[0] = 0; ++w->address_generation; w->step = WSU_WORKING; w->failure = WSU_NO_FAILURE; work_begins_locked(w, WSU_PHASE_NONE); }
    pthread_mutex_unlock(&w->lock);
    return start;
}

/* Return a canceled key prompt only if this create still owns the working step. */
static void create_declined(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    if (w->step == WSU_WORKING) { w->step = WSU_CHOICE; w->failure = WSU_NO_FAILURE; w->refusal = WSU_NO_FAILURE; }
    pthread_mutex_unlock(&w->lock);
}

/* ---- create: the words first, the wallet written behind them ---- */

/* A new phrase from the node, which needs no datadir and no stopped node. Nothing is written anywhere. */
static enum wsu_failure phrase_failure(struct wsu *w, struct zapp_words *phrase)
{
    enum sun_result result = sun_new_phrase(&w->node, phrase);
    return result == SUN_OK ? WSU_NO_FAILURE : failure_of_node(result);
}
/* The shown words, the phrase kept for the write and its passphrase are wiped, with the lock held. */
static void close_words_locked(struct wsu *w)
{
    forget_choices_locked(w);
    zapp_words_cleanse(&w->held);
    zapp_words_cleanse(&w->phrase);
    memory_cleanse(w->write_pass, sizeof(w->write_pass));
    w->write = WSU_WRITE_NONE;
    w->words_first = false;
}
/* The phrase is shown, and kept with its passphrase until the wallet is written: a failed write is tried again with the same
 * words, and no second phrase is ever made for one setup. False, nothing kept, when the questions cannot be drawn. */
static bool words_shown(struct wsu *w, const struct zapp_words *phrase, const char *hex)
{
    pthread_mutex_lock(&w->lock);
    w->held = *phrase;
    w->phrase = *phrase;
    memcpy(w->write_pass, hex, SUN_PASSPHRASE_HEX + 1);
    w->words_first = true;
    w->write = WSU_WRITE_PENDING;
    w->write_failure = WSU_NO_FAILURE;
    w->mismatches = 0;
    memset(&w->birthday, 0, sizeof(w->birthday));
    bool ok = zapp_words_pick(w->held.count, w->env.random, w->env.ctx, ZAPP_WORDS_ASKED, w->asked) && offer_all_locked(w);
    if (ok) {
        w->step = WSU_WORDS;
        w->failure = WSU_NO_FAILURE;
    } else {
        close_words_locked(w);
    }
    pthread_mutex_unlock(&w->lock);
    return ok;
}

void wsu_create_job(struct wsu *w)
{
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    char hex[SUN_PASSPHRASE_HEX + 1];
    struct zapp_words phrase;
    memset(&phrase, 0, sizeof(phrase));
    if (!begin_job(w, WSU_CHOICE)) return;
    phase(w, WSU_PHASE_KEY);
    enum wsu_failure failure = new_passphrase(w, secret, hex);
    if (failure == WSU_DECLINED) { create_declined(w); goto out; }
    if (failure != WSU_NO_FAILURE) { set_step(w, WSU_FAILED, failure); goto out; }
    failure = phrase_failure(w, &phrase);
    if (failure == WSU_NO_FAILURE && !words_shown(w, &phrase, hex)) failure = WSU_NOT_RUN;
    if (failure != WSU_NO_FAILURE) end_failed(w, failure, false, WSU_FAILED);
out:
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(hex, sizeof(hex));
    zapp_words_cleanse(&phrase);
}

/* Records the kind first, so a restart can tell what was begun, then restores the phrase with no node holding the files. The wallet
 * uses the fixed release anchor, so a delayed write cannot skip payments after the words were shown. */
static enum sun_result write_once(struct wsu *w, struct sun_restored *restored)
{
    if (!zapp_setup_kind_write(w->files, ZAPP_KIND_CREATE)) return SUN_REFUSED;
    if (!stop_node(w, WSU_PHASE_PAUSE)) return SUN_NODE_RUNNING;
    phase(w, WSU_PHASE_WRITE);
    return sun_restore_at_tip(&w->node, &w->phrase, w->write_pass, restored);
}
/* The write ended: kept as done, with the phrase and passphrase wiped, or as failed with its reason. A wallet found present
 * never counts as this one. */
static void write_ended(struct wsu *w, enum sun_result result, const struct sun_restored *restored)
{
    pthread_mutex_lock(&w->lock);
    if (result == SUN_ALREADY_PRESENT) {
        /* A wallet that is already there is never this one, whatever an earlier attempt did: the shown words may not restore it, so
         * they are closed and the owner goes on by Start over or Restore. */
        close_words_locked(w);
        w->kind = ZAPP_KIND_CREATE;
        w->step = WSU_BLOCKED;
        w->failure = WSU_WALLET_THERE;
    } else if (result == SUN_OK) {
        memcpy(w->first_shielded_address, restored->first_shielded_address, sizeof(w->first_shielded_address));
        w->birthday.known = restored->birthday_recorded && !restored->birthday_rejected;
        w->write = WSU_WRITE_DONE;
        zapp_words_cleanse(&w->phrase);
        memory_cleanse(w->write_pass, sizeof(w->write_pass));
    } else {
        w->write = WSU_WRITE_FAILED;
        w->write_failure = failure_of_node(result);
    }
    pthread_mutex_unlock(&w->lock);
}

void wsu_write_job(struct wsu *w)
{
    struct sun_restored restored;
    memset(&restored, 0, sizeof(restored));
    pthread_mutex_lock(&w->lock);
    bool go = w->write == WSU_WRITE_PENDING;
    if (go) { w->write = WSU_WRITE_RUNNING; work_begins_locked(w, WSU_PHASE_WRITE); }
    pthread_mutex_unlock(&w->lock);
    if (!go) return;
    /* The end is published only once the node is started again, so a screen that offers Try again or a check never races the start. */
    enum sun_result result = write_once(w, &restored);
    (void)start_node(w);
    write_ended(w, result, &restored);
}
bool wsu_retry_write(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool ok = w->write == WSU_WRITE_FAILED && (w->step == WSU_WORDS || w->step == WSU_CONFIRM) && wsu_write_retryable(w->write_failure);
    if (ok) w->write = WSU_WRITE_PENDING;
    pthread_mutex_unlock(&w->lock);
    return ok;
}
bool wsu_give_up_write(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool ok = w->write == WSU_WRITE_FAILED && (w->step == WSU_WORDS || w->step == WSU_CONFIRM);
    if (ok) {
        close_words_locked(w);
        w->step = WSU_CHECKING;
        w->failure = WSU_NO_FAILURE;
        work_begins_locked(w, WSU_PHASE_NONE);
    }
    pthread_mutex_unlock(&w->lock);
    return ok;
}

bool wsu_confirm(struct wsu *w, const char *const *answers, size_t n)
{
    pthread_mutex_lock(&w->lock);
    bool ready = !w->words_first || w->write == WSU_WRITE_DONE;
    bool right = w->step == WSU_CONFIRM && n == ZAPP_WORDS_ASKED && ready && zapp_words_match(&w->held, w->asked, answers, n);
    if (right) {
        forget_choices_locked(w);
        zapp_words_cleanse(&w->held);
        w->confirmed = true;
        w->step = WSU_WORKING;
        w->failure = WSU_NO_FAILURE;
        work_begins_locked(w, WSU_PHASE_SAVE);
    } else if (w->step == WSU_CONFIRM && ready) {
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
        char old[ZAPP_WORD_CHOICES][ZAPP_WORD_LETTERS + 1];
        memcpy(old, w->choice[index], sizeof(old));
        if (!offer_locked(w, index)) memcpy(w->choice[index], old, sizeof(old));   /* the same words again, never blank buttons */
        memory_cleanse(old, sizeof(old));
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

bool wsu_launch_retry_write(struct wsu *w, bool (*launch)(void *), void *ctx)
{
    if (!wsu_retry_write(w)) return false;
    if (launch(ctx)) return true;
    pthread_mutex_lock(&w->lock);
    if (w->write == WSU_WRITE_PENDING) w->write = WSU_WRITE_FAILED;
    pthread_mutex_unlock(&w->lock);
    return false;
}
static bool finish_launch(struct wsu *w, bool (*launch)(void *), void *ctx)
{
    if (launch(ctx)) return true;
    pthread_mutex_lock(&w->lock);
    if (w->confirmed && w->step == WSU_WORKING) { w->step = WSU_FAILED; w->failure = WSU_NOT_RECORDED; }
    pthread_mutex_unlock(&w->lock);
    return false;
}
bool wsu_launch_confirm(struct wsu *w, bool (*launch)(void *), void *ctx)
{
    return wsu_confirm_picked(w) && finish_launch(w, launch, ctx);
}
bool wsu_launch_marker(struct wsu *w, bool (*launch)(void *), void *ctx)
{
    return wsu_retry_marker(w) && finish_launch(w, launch, ctx);
}
bool wsu_parse_height(const char *text, int64_t *height)
{
    int64_t value = 0;
    if (!text || !height) return false;
    if (!*text) { *height = 0; return true; }
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9' || value > (INT64_MAX - (*p - '0')) / 10) return false;
        value = value * 10 + (*p - '0');
    }
    if (!value) return false;
    *height = value; return true;
}

/* ---- restore ---- */

void wsu_set_form(struct wsu *w, const char *text)
{
    pthread_mutex_lock(&w->lock);
    memory_cleanse(w->form, sizeof(w->form));
    if (text) snprintf(w->form, sizeof(w->form), "%s", text);
    pthread_mutex_unlock(&w->lock);
}
void wsu_forget_form(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    memory_cleanse(w->form, sizeof(w->form));
    pthread_mutex_unlock(&w->lock);
}

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
    if (restored) memcpy(w->first_shielded_address, restored->first_shielded_address, sizeof(w->first_shielded_address));
    w->birthday_honoured = honoured || (restored && restored->birthday_recorded && !restored->birthday_rejected);
    memory_cleanse(w->form, sizeof(w->form));
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
    if (!stop_node(w, WSU_PHASE_PAUSE)) return SUN_NODE_RUNNING;
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
    size_t position = 0;
    enum zapp_words_problem problem = zapp_words_check(&words, &position);
    if (problem != ZAPP_WORDS_OK) {
        pthread_mutex_lock(&w->lock);
        w->step = WSU_RESTORE_FORM;
        w->failure = problem == ZAPP_WORDS_OFF_LIST ? WSU_BAD_WORD : WSU_BAD_PHRASE;
        w->bad_word = position;
        w->refusal = WSU_NO_FAILURE;
        pthread_mutex_unlock(&w->lock);
        goto out;
    }
    phase(w, WSU_PHASE_KEY);
    enum wsu_failure failure = new_passphrase(w, secret, hex);
    /* A refusal no retry changes leaves the form, whose Restore would only ask again. */
    if (failure != WSU_NO_FAILURE) { set_step(w, wsu_failure_retries(failure) ? WSU_RESTORE_FORM : WSU_FAILED, failure); goto out; }
    bool was_running = w->env.node_running(w->env.ctx);
    struct sun_birthday birthday = birthday_at(w, birthday_height);
    pthread_mutex_lock(&w->lock);
    w->birthday = birthday;
    pthread_mutex_unlock(&w->lock);
    enum sun_result result = restore_run(w, &words, hex, &birthday, &restored);
    if (result != SUN_OK) {
        /* A refusal wrote nothing, so the owner stays on the form with the words kept. An unknown answer goes to the check. */
        failure = failure_of_node(result);
        end_failed(w, failure, was_running, failure == WSU_UNKNOWN ? WSU_FAILED : WSU_RESTORE_FORM);
        goto out;
    }
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

/* The running node holds the wallet open and answers from it, so nothing is stopped. It is asked until it answers, while it may
 * still be starting; false when no node runs, or it stops, or it gives no answer to the questions asked in the IDLE_WAIT_S after
 * the first by the wall clock, which the screen's clock also reads. IDLE_POLLS also bounds the questions when the clock is set
 * back. */
static bool running_probe(struct wsu *w, enum sun_probe *probe)
{
    if (!w->env.node_running(w->env.ctx)) return false;
    phase(w, WSU_PHASE_CHECK);
    int64_t first_s = w->env.wall_s(w->env.ctx);
    for (unsigned asked = 1;; ++asked) {
        if (w->env.wallet_held(w->env.ctx, probe)) return true;
        int64_t next_s = w->env.wall_s(w->env.ctx) - first_s + IDLE_POLL_MS / 1000u;
        if (asked >= IDLE_POLLS || next_s >= (int64_t)IDLE_WAIT_S) return false;
        w->env.pause_ms(w->env.ctx, IDLE_POLL_MS);
        if (!w->env.node_running(w->env.ctx)) return false;
    }
}
/* The datadir read: the status command refuses a datadir a running node holds, so a node that runs is stopped for the read and
 * started again after, except after a finished restore, which starts it itself. False when the node did not stop. */
static bool offline_probe(struct wsu *w, enum zapp_setup_kind kind, enum sun_probe *probe)
{
    bool was_running = w->env.node_running(w->env.ctx);
    if (!stop_node(w, WSU_PHASE_PAUSE_CHECK)) {
        if (was_running) (void)start_node(w);
        return false;
    }
    phase(w, WSU_PHASE_CHECK);
    *probe = sun_wallet_probe(&w->node);
    if (was_running && !(*probe == SUN_PROBE_PRESENT && kind == ZAPP_KIND_RESTORE)) (void)start_node(w);
    return true;
}

void wsu_resume_job(struct wsu *w)
{
    pthread_mutex_lock(&w->lock);
    bool go = w->step == WSU_CHECKING;
    if (go) w->kind = zapp_setup_kind_read(w->files);
    enum zapp_setup_kind kind = w->kind;
    pthread_mutex_unlock(&w->lock);
    if (!go) return;
    enum sun_probe probe = SUN_PROBE_UNKNOWN;
    if (!running_probe(w, &probe) && !offline_probe(w, kind, &probe)) {
        set_step(w, WSU_BLOCKED, WSU_NODE_BUSY);
        return;
    }
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
    if (go) { w->step = WSU_WORKING; work_begins_locked(w, WSU_PHASE_ASIDE); }
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
    bool blocked = w->step == WSU_BLOCKED && (w->failure == WSU_NO_FAILURE || w->failure == WSU_COULD_NOT_CHECK || w->failure == WSU_NODE_BUSY || w->failure == WSU_WALLET_THERE);
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

/* Whether the running node reports an empty wallet; starts the node when needed and waits for an answer. The screen names the start
 * while it runs and the check while the node is asked. */
static enum wsu_idle wallet_idle(struct wsu *w)
{
    (void)start_node(w);
    phase(w, WSU_PHASE_CHECK);
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
    if (go) { zapp_setup_preload_invalidate(); w->first_shielded_address[0] = 0; ++w->address_generation; w->step = WSU_WORKING; w->failure = WSU_NO_FAILURE; work_begins_locked(w, WSU_PHASE_NONE); }
    pthread_mutex_unlock(&w->lock);
    if (!go) return;
    enum wsu_failure refusal = start_over_refusal(w);
    if (refusal == WSU_NO_FAILURE && !stop_node(w, WSU_PHASE_PAUSE_ASIDE)) refusal = WSU_NODE_BUSY;
    if (refusal != WSU_NO_FAILURE) {
        if (w->paused_node) (void)start_node(w);
        start_over_refused(w, refusal);
        return;
    }
    phase(w, WSU_PHASE_ASIDE);
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
/* true or false, or null for not known; false when the value is absent or of another type. */
static bool held_of(const struct json_value *data, const char *key, int *out)
{
    const struct json_value *v = json_get(data, key);
    if (v && v->type == JSON_BOOL) *out = json_get_bool(v) ? 1 : 0;
    else if (v && v->type == JSON_NULL) *out = -1;
    else return false;
    return true;
}
bool wsu_summary_wallet(const struct json_value *reply, enum sun_probe *out)
{
    const struct json_value *ok = json_get(reply, "ok"), *data = json_get(reply, "data"), *schema = json_get(data, "schema");
    bool summary = ok && ok->type == JSON_BOOL && json_get_bool(ok) && schema && schema->type == JSON_STR &&
                   !strcmp(json_get_str(schema), "zcl.wallet_summary.v1");
    int seed = 0, keys = 0;
    if (!summary || !held_of(data, "seed_present", &seed) || !held_of(data, "keys_present", &keys)) return false;
    *out = seed == 1 || keys == 1 ? SUN_PROBE_PRESENT : seed == 0 && keys == 0 ? SUN_PROBE_NONE : SUN_PROBE_UNKNOWN;
    return true;
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

bool wsu_address_generation(struct wsu *w, uint64_t *generation)
{
    if (!generation) return false;
    pthread_mutex_lock(&w->lock);
    bool ready = w->step == WSU_DONE || w->step == WSU_READING;
    *generation = w->address_generation;
    pthread_mutex_unlock(&w->lock);
    return ready;
}
