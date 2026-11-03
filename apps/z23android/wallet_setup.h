/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SETUP_H
#define ZAPP_WALLET_SETUP_H
#include "device_key.h"
#include "json/json.h"
#include "setup_node.h"
#include "setup_state.h"
#include "setup_words.h"
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* First-run wallet setup: Create a new wallet, or Restore from words.
 *
 * Create asks the system for one authentication that wraps a fresh random passphrase into wallet_key.blob, stops the node
 * if it runs, has the node create a shielded-only wallet encrypted with that passphrase, starts the node, shows the 24
 * words once and then asks for three of them. Setup is finished only when the answers match. Restore takes the owner's
 * words and an optional birthday height, runs the same way and shows how far the node has read.
 *
 * The passphrase exists in memory only between the device key and the node's standard input and is cleansed after each
 * use. The words are held in memory until confirmed and are never written by the app. Nothing here logs.
 *
 * Every step that waits on the device or the node is a blocking call for the caller's worker thread; the model is safe to
 * read from the UI thread meanwhile. */

enum wsu_idle { WSU_IDLE_UNKNOWN, WSU_IDLE_EMPTY, WSU_IDLE_FUNDS };

/* Shown on the words screen: removing the screen lock invalidates the key that wraps the wallet passphrase. */
#define WSU_SCREEN_LOCK_NOTICE "If you remove this phone's screen lock, you will need these words to open the wallet again."

/* What the node's `core wallet summary` data says, for Start over: 1 when the wallet holds nothing, 0 when it holds something,
 * -1 when that is not known. Nothing is known unless the summary is current and lists shielded keys; any amount is something. */
int wsu_summary_state(const struct json_value *data);
/* What the node's history data says: 1 when every list is empty, 0 when one holds an item, -1 when the reply has no list. */
int wsu_history_state(const struct json_value *data);

struct wsu_env {
    void *ctx;
    /* One system authentication; draws and wraps a fresh secret. The secret is zero unless OK. */
    enum zapp_devkey_status (*wrap_new)(void *ctx, uint8_t secret[ZAPP_DEVKEY_SECRET]);
    void (*discard_key)(void *ctx);
    bool (*node_running)(void *ctx);
    /* start=false pauses the node for setup and must keep the owner's on or off choice; only the owner's Stop button changes it. */
    void (*node_control)(void *ctx, bool start);
    void (*pause_ms)(void *ctx, unsigned ms);
    bool (*random)(void *ctx, uint8_t *out, size_t len);
    /* How far the node has read; false until it answers. */
    bool (*progress)(void *ctx, int64_t *scanned, int64_t *tip);
    /* Applies (on) or removes (off) every protection of the window: no capture, no recents thumbnail, no overlay, no
     * accessibility readout. False means one is not in force. */
    bool (*protect)(void *ctx, bool on);
    /* Whether the running node's wallet holds nothing: zero amounts and no transactions. */
    enum wsu_idle (*wallet_idle)(void *ctx);
    /* Seconds since the epoch, for the names of files set aside. */
    int64_t (*wall_s)(void *ctx);
};

enum wsu_step {
    WSU_CHOICE,         /* Create or Restore. */
    WSU_WORKING,        /* A job runs on the worker. */
    WSU_WORDS,          /* The words are on screen, once. */
    WSU_CONFIRM,        /* The owner is asked for some of them. */
    WSU_RESTORE_FORM,   /* Words and birthday. */
    WSU_READING,        /* Restored; the node reads the chain. */
    WSU_DONE,           /* Setup is finished. */
    WSU_FAILED,         /* The last job failed; Try again returns to the choice. */
    WSU_BLOCKED,        /* A wallet exists whose words were never confirmed, or its state is not known yet. */
    WSU_NO_WALLET,      /* The datadir holds no wallet. The wrapped key is kept until the owner taps. */
    WSU_START_OVER,     /* The warning before an unconfirmed create is set aside. */
    WSU_CHECKING        /* After a restart: reading the datadir to learn what the interrupted setup left. */
};
/* What a working screen is doing; each has one plain line (wsu_working_line). */
enum wsu_phase {
    WSU_PHASE_NONE,
    WSU_PHASE_KEY,       /* securing the key; the phone may ask for the screen lock */
    WSU_PHASE_PAUSE,     /* waiting for the node to exit so the wallet files are written safely */
    WSU_PHASE_WRITE,     /* the node writes the wallet */
    WSU_PHASE_RESTART,   /* starting the node again */
    WSU_PHASE_CHECK,     /* reading the wallet files or asking the node about the wallet */
    WSU_PHASE_ASIDE,     /* moving the old wallet aside */
    WSU_PHASE_SAVE       /* the words are confirmed; the setup is recorded */
};
/* The wallet behind the shown words of a create: written in the background while the words and the check are on screen. */
enum wsu_write {
    WSU_WRITE_NONE,      /* no create is under way */
    WSU_WRITE_PENDING,   /* the words are shown and the write has not started */
    WSU_WRITE_RUNNING,
    WSU_WRITE_DONE,
    WSU_WRITE_FAILED     /* write_failure says why; the same words are written again on a retry */
};
enum wsu_failure {
    WSU_NO_FAILURE,
    WSU_DECLINED,       /* The owner did not authenticate. */
    WSU_NO_SCREEN_LOCK,
    WSU_KEY,            /* The device key refused. */
    WSU_NODE_BUSY,      /* The node did not stop. */
    WSU_PRESENT,        /* The node holds a wallet already. */
    WSU_BAD_PHRASE,
    WSU_BAD_WORDS,      /* The words as typed are not 12 to 24 words. */
    WSU_STORAGE,
    WSU_REFUSED,
    WSU_UNKNOWN,        /* No usable answer: a wallet may exist. The key is kept. */
    WSU_NOT_RECORDED,   /* The wallet exists; its setup marker could not be written. */
    WSU_NO_TIP,         /* The node did not learn the chain tip in time: no wallet was made. */
    WSU_NO_BIRTHDAY,    /* The wallet exists and recorded no start height, so setup stays unfinished. */
    WSU_NOT_RUN,        /* The node command was never started. Nothing was written. */
    WSU_NOT_CREATE,     /* Start over is only for a create. */
    WSU_NOT_EMPTY,      /* The wallet holds, or may hold, funds or transactions. */
    WSU_ALREADY_CONFIRMED, /* The words were confirmed. */
    WSU_COULD_NOT_CHECK, /* The node did not say whether the wallet is empty. */
    WSU_ASIDE,          /* The wallet could not be set aside; what had moved was put back and nothing changed. */
    WSU_ASIDE_STUCK,    /* Items moved aside could not be put back: leftover names them, and no new wallet is offered. */
    WSU_UNPROTECTED,    /* The window could not be protected: nothing is shown and no wallet is made. */
    WSU_BAD_WORD,       /* A typed recovery word is not on the list; the form stays and bad_word says which. */
    WSU_WALLET_THERE    /* A create found a wallet already on the phone: the shown words are closed, and Start over or Restore is the way on. */
};

#define WSU_LEFTOVER_MAX 1100
#define WSU_FORM_MAX 640
struct wsu {
    struct wsu_env env;
    struct sun node;
    char files[512];
    pthread_mutex_t lock;
    enum wsu_step step;
    enum wsu_failure failure;
    struct zapp_words held;
    size_t asked[ZAPP_WORDS_ASKED];
    char choice[ZAPP_WORDS_ASKED][ZAPP_WORD_CHOICES][ZAPP_WORD_LETTERS + 1];   /* the words offered for each asked position */
    char picked[ZAPP_WORDS_ASKED][ZAPP_WORD_LETTERS + 1];   /* the right words picked so far, empty for none */
    unsigned wrong;      /* 1 + the index of the asked position of the last wrong pick, or 0 */
    unsigned mismatches;
    struct sun_birthday birthday;
    bool birthday_honoured;
    size_t bad_word;     /* with BAD_WORD: the index of the word, counted from 0 */
    enum wsu_failure refusal;   /* with NO_BIRTHDAY: why the last Start over was refused, or none */
    bool confirmed;      /* the owner proved the words (create) or typed them (restore) */
    bool restored;       /* the setup was a restore */
    bool protected;      /* every window protection is in force */
    enum zapp_setup_kind kind;   /* what the interrupted setup was, read when the datadir is checked */
    char leftover[WSU_LEFTOVER_MAX];   /* with ASIDE_STUCK: the paths that stay moved aside, one per line */
    enum wsu_phase phase;     /* the sub-step of the running job */
    int64_t phase_since_s;
    bool paused_node;         /* setup asked the node to exit and has not started it again */
    struct zapp_words phrase;   /* a create: the words being written, wiped when the write is done */
    char write_pass[SUN_PASSPHRASE_HEX + 1];
    enum wsu_write write;
    enum wsu_failure write_failure;
    bool words_first;           /* the setup is a create whose words were shown before the wallet was written */
    char form[WSU_FORM_MAX];    /* the restore words as typed; the form shows them again after a refusal (wsu_set_form) */
};
bool wsu_init(struct wsu *w, const struct wsu_env *env, const struct sun *node, const char *files);
void wsu_destroy(struct wsu *w);

/* Protects the window and returns whether every protection is in force. Words are withheld, and no wallet is made, while
 * it is not. */
bool wsu_open(struct wsu *w);
void wsu_close(struct wsu *w);

/* What the screen draws. The words are filled only while step is WSU_WORDS; cleanse the copy after drawing. */
struct wsu_view {
    enum wsu_step step;
    enum wsu_failure failure;
    struct zapp_words words;
    size_t asked[ZAPP_WORDS_ASKED];
    char choice[ZAPP_WORDS_ASKED][ZAPP_WORD_CHOICES][ZAPP_WORD_LETTERS + 1];   /* with CONFIRM: the words to pick from */
    char picked[ZAPP_WORDS_ASKED][ZAPP_WORD_LETTERS + 1];
    size_t wrong_position;   /* with CONFIRM: the word number of the last wrong pick, or 0 */
    unsigned mismatches;
    int64_t start_height;   /* with the words: the block the new wallet starts reading at */
    bool protected;
    bool birthday_unknown;
    bool birthday_dropped;
    enum wsu_failure refusal;   /* with NO_BIRTHDAY: why the last Start over was refused, or none */
    bool may_start_over;   /* the setup is a create whose words were not confirmed */
    size_t bad_word;       /* with BAD_WORD: the index of the word, counted from 0 */
    char leftover[WSU_LEFTOVER_MAX];
    enum wsu_phase phase;   /* with WORKING or CHECKING */
    int64_t elapsed_s;      /* seconds since the job began */
    enum wsu_write write;    /* with WORDS or CONFIRM: whether the wallet behind the words is written */
    enum wsu_failure write_failure;
    bool start_pending;      /* with WORDS: a words-first create, before and after the write; the wallet start is the node's own, so no height is shown */
    char form[WSU_FORM_MAX];   /* with RESTORE_FORM and WORKING: the restore words as typed */
};
void wsu_view_read(struct wsu *w, struct wsu_view *out);
/* Whether the interrupted-setup screen offers Check again: the node did not answer, or was busy, or could not say whether the wallet is empty. */
bool wsu_view_can_recheck(const struct wsu_view *v);
/* The sentence above the recovery words. With a recorded start height it names the height; when the wallet recorded none it says so
 * and names no height. */
void wsu_words_intro(const struct wsu_view *v, char *out, size_t cap);
/* The line a working screen shows: the sub-step in plain words. With no sub-step set yet it is "Starting…"; after the words are confirmed it is "Saving…". */
void wsu_working_line(const struct wsu_view *v, char *out, size_t cap);
/* "2 min 05 s since setup began": the seconds of the job so far, so a long wait shows it is alive. */
void wsu_elapsed_text(const struct wsu_view *v, char *out, size_t cap);
/* One plain sentence and the action for a failed job; empty for none. */
const char *wsu_failure_text(enum wsu_failure failure);
/* The sentence above the failure on the interrupted-setup screen: a wallet was started (the probe found it), or the node did not
 * answer. Empty for the other failures, whose failure text says what to do. */
const char *wsu_interrupted_note(enum wsu_failure failure);
/* The restore form's line for a word that is not on the list: the word's number, counted from 1. The word itself is never written. */
void wsu_bad_word_text(size_t position, char *out, size_t cap);
/* What Back says when setup cannot be left now: the words are shown once while they are held, and a running job goes on without the owner. */
void wsu_leave_notice(const struct wsu_view *v, char *out, size_t cap);

/* Navigation on the UI thread. */
void wsu_open_restore(struct wsu *w);   /* CHOICE to RESTORE_FORM */
void wsu_back(struct wsu *w);           /* RESTORE_FORM or FAILED to CHOICE */
void wsu_words_seen(struct wsu *w);     /* WORDS to CONFIRM */
void wsu_show_again(struct wsu *w);     /* CONFIRM to WORDS */
bool wsu_busy(struct wsu *w);           /* A job runs, or words are held: leaving would lose them. */

/* Jobs, for the worker thread. */
/* Asks for the fingerprint, then a new phrase from the node, and shows the words at once: nothing is stopped, started or written yet.
 * wsu_write_job then writes the wallet behind them. */
void wsu_create_job(struct wsu *w);
/* On the worker, after the words are shown (or again after wsu_retry_write): records the kind, waits for the node to exit, restores the
 * phrase into the datadir at its own chain tip and starts the node. The node runs again on every path. */
void wsu_write_job(struct wsu *w);
/* A failed write to a new attempt with the same words, never a second phrase; the caller then runs wsu_write_job. */
bool wsu_retry_write(struct wsu *w);
/* A failed write the owner leaves: the words are closed and wiped, and the setup goes to the check of what the phone holds (the
 * interrupted-setup path), where Start over and Back work. False unless the write has failed. */
bool wsu_give_up_write(struct wsu *w);
/* text is the typed words; birthday_height is 0 when the owner does not know it. */
void wsu_restore_job(struct wsu *w, const char *text, int64_t birthday_height);
/* Keeps the restore words as typed, so the form shows them again after a refusal. They are wiped when the form is left, when
 * setup finishes and when the app leaves the foreground. */
void wsu_set_form(struct wsu *w, const char *text);
/* Wipes the restore words held for the form. */
void wsu_forget_form(struct wsu *w);
/* answers are the typed words for the asked positions. True when they match: the words are wiped and the step is
 * WORKING until wsu_finish_job writes the setup marker. Otherwise the step stays CONFIRM. */
bool wsu_confirm(struct wsu *w, const char *const *answers, size_t n);
/* A tap on one of the words offered for asked position index. True when it is the right word, which is then kept as the answer.
 * A wrong word is counted, clears the answer and offers new decoys for that position. Only while the step is CONFIRM. */
bool wsu_pick(struct wsu *w, size_t index, size_t slot);
/* wsu_confirm with the words picked; false while a position has none. */
bool wsu_confirm_picked(struct wsu *w);
/* After a matching wsu_confirm, on the worker: records that setup finished, or, when the new wallet recorded no start
 * height, leaves setup unfinished. */
void wsu_finish_job(struct wsu *w);
/* FAILED with NOT_RECORDED to WORKING; the caller then runs wsu_finish_job. */
bool wsu_retry_marker(struct wsu *w);
/* BLOCKED, or FAILED after a wallet may exist, to CHECKING; the caller then runs wsu_resume_job. */
bool wsu_recheck(struct wsu *w);
/* After a restart, on the worker: learns from the datadir whether the interrupted setup left a wallet. A finished restore
 * completes setup; a create whose words were not confirmed stays blocked; no wallet frees the choice again. */
void wsu_resume_job(struct wsu *w);

/* NO_WALLET to CHOICE after the owner's tap: the wrapped key is renamed aside, never deleted. */
void wsu_set_aside_job(struct wsu *w);
/* BLOCKED to START_OVER (the warning) when the setup is a create whose words were never confirmed; otherwise stays BLOCKED
 * with the reason. */
bool wsu_ask_start_over(struct wsu *w);
void wsu_cancel_start_over(struct wsu *w);
/* After the warning, on the worker: only for a create whose words were never confirmed and whose wallet the node does not report
 * with funds or transactions. Stops the node and renames the whole datadir (one rename) and the wrapped key aside, never
 * deleting; then the choice returns. */
void wsu_start_over_job(struct wsu *w);
/* Leaves READING for DONE. */
void wsu_finish_reading(struct wsu *w);
/* The node's progress while step is READING. */
bool wsu_reading(struct wsu *w, int64_t *scanned, int64_t *tip);

#endif
