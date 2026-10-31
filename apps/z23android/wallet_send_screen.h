/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SEND_SCREEN_H
#define ZAPP_WALLET_SEND_SCREEN_H
#include "secure_window.h"
#include "wallet_send.h"

/* The review screen and its progress, over the wallet_send state machine. The screen owns the machine,
 * carries out its actions on a worker so the UI thread never waits for the node, the keystore or a
 * proof, and turns the machine into plain text lines for the renderer. It calls nothing of Android
 * itself: the node, the device key, the clock and the worker come in through the typed interfaces
 * below, which the tests fake. No payment field is logged or leaves this module except through the
 * view the renderer draws and the node calls the owner's tap caused.
 *
 * Drawing: Send must be drawn as an Android View. android_main.c reads touches natively before any
 * view, and setFilterTouchesWhenObscured, which drops touches while another window covers the button,
 * works only on Views. A button painted into a surface or a canvas has no such filter. */

#define WSS_AMOUNT 48
#define WSS_ADDRESS 160
#define WSS_LINE 200
#define WSS_UNLOCK_JSON 128
#define WSS_MEMO 4200   /* A memo of ZAPP_PAY_MEMO_MAX bytes with every character written out in full. */

/* What the node is asked to plan or commit. */
struct wss_send_req {
    char address[ZAPP_PAY_ADDRESS_MAX];
    uint64_t amount_zat;
    uint8_t memo[ZAPP_PAY_MEMO_MAX];
    size_t memo_len;
    uint64_t fee_zat;                /* The fee the plan quoted. Zero for a plan; a commit must carry it (the node refuses PLAN_REQUIRED without it). */
    char key[WS_KEY_HEX + 1];        /* The idempotency key of this review. */
    char plan_token[WS_TOKEN_MAX];   /* Empty for a plan. */
};
/* How a commit answer reads. This table is the mapping the node adapter must apply to the commit reply:
 *   committed true (a replay of an earlier commit of the same key included)  -> WSS_COMMITTED
 *   error code SEND_KEY_RELEASED (the node released the key: nothing was sent) -> WSS_KEY_RELEASED
 *   error code FEE_CHANGED (refused before any build)                         -> WSS_FEE_CHANGED
 *   anything else, including WALLET_RPC_ERROR, a timeout and no answer       -> WSS_UNKNOWN
 * WALLET_RPC_ERROR is unknown because it also covers an admitted transaction whose compensation failed and
 * whose row was kept. Only WSS_KEY_RELEASED and WSS_FEE_CHANGED may say "Nothing was sent". */
enum wss_commit_outcome { WSS_COMMITTED, WSS_KEY_RELEASED, WSS_FEE_CHANGED, WSS_UNKNOWN };
enum wss_commit_outcome wss_commit_outcome_of(bool answered, bool committed, const char *error_code);

/* Typed node calls. Each returns false when the node could not be asked. */
struct wss_node_ops {
    void *ctx;
    bool (*validate_address)(void *ctx, const char *address, bool *valid);   /* validateaddress */
    bool (*read_gate)(void *ctx, struct ws_gate *out);                       /* core wallet summary */
    bool (*plan)(void *ctx, const struct wss_send_req *req, struct ws_plan *out);       /* shielded send, no confirm */
    /* core wallet security unlock: json is read from standard input and never put in argv. */
    bool (*unlock)(void *ctx, const char *stdin_json, size_t len, uint32_t seconds);
    bool (*lock)(void *ctx);                                                 /* core wallet security lock */
    enum wss_commit_outcome (*commit)(void *ctx, const struct wss_send_req *req, char token_echo[WS_TOKEN_MAX]);
    bool (*route)(void *ctx, enum ws_route *out);                            /* core wallet broadcast status */
};
/* The device key. unwrap is the only way to the 32 byte wallet secret and it authenticates the owner for
 * this one use: it blocks on the worker while the system shows its prompt and returns the secret or a
 * refusal. It runs only on the worker, never on the UI thread (device_key.h): when the worker cannot be
 * started the flow fails. The Keystore key needs a credential or strong biometric for each use, with a timeout of 0, so
 * no earlier authentication counts and none is remembered here. */
/* The unwrap result as the screen reads it. wss_key_status_of_devkey maps zapp_devkey_status_name() of the
 * device key onto it; a name it does not know is WSS_KEY_ERROR:
 *   ok -> OK                       declined -> DECLINED (the owner chose; Retry offered)
 *   invalidated, not_found, corrupt, old_format, not_hardware, not_per_use -> GONE (restore from the phrase)
 *   no_screen_lock -> NO_SCREEN_LOCK (set one; Retry offered)
 *   exists, strongbox_unavailable, error and anything else -> ERROR (the wallet could not be opened; Retry) */
enum wss_key_status { WSS_KEY_OK, WSS_KEY_DECLINED, WSS_KEY_GONE, WSS_KEY_NO_SCREEN_LOCK, WSS_KEY_ERROR };
enum wss_key_status wss_key_status_of_devkey(const char *status_name);
struct wss_device_ops {
    void *ctx;
    enum wss_key_status (*unwrap)(void *ctx, uint8_t secret[32]);
};
struct wss_host_ops {
    void *ctx;
    bool (*random)(void *ctx, uint8_t *out, size_t len);
    uint64_t (*now_ms)(void *ctx);
    /* Runs job(arg) once on a thread that is not the UI thread. */
    bool (*spawn)(void *ctx, void (*job)(void *arg), void *arg);
    void (*redraw)(void *ctx);
    void (*open_make_private)(void *ctx);
};
struct wss_deps {
    enum zapp_pay_network network;
    struct wss_node_ops node;
    struct wss_device_ops device;
    struct wss_host_ops host;
    struct zapp_secure_ops secure;
};

/* Everything the renderer draws. Fields not in use are empty strings. */
struct wss_view {
    bool visible;                     /* False: show only status; the screen could not be protected. */
    enum ws_state state;
    bool busy;                        /* Show progress. */
    unsigned elapsed_s;               /* Seconds in the current step. */
    bool review;                      /* Draw the review lines. */
    bool can_send;
    bool can_retry;
    bool check_history;               /* The send has an unknown result: say so and point to History. */
    bool can_cancel;
    bool offer_make_private;
    uint32_t serial;                  /* Pass back with the Send tap. */
    char amount[WSS_AMOUNT];
    char address[WSS_ADDRESS];        /* In groups of four. */
    char kind[16];                    /* "Private" or "Public". */
    char fee[WSS_AMOUNT];
    char remains[WSS_AMOUNT];
    char memo_label[24];              /* "Memo", or "Memo (data)" when it is not text. */
    char memo[WSS_MEMO];              /* Data only: control and bidi characters are written as <U+XXXX>. */
    char warning[WSS_LINE];           /* The public destination warning. */
    char note[WSS_LINE];              /* Insufficient private funds. */
    char status[WSS_LINE];
};

struct wss;
struct wss *wss_create(const struct wss_deps *deps);
/* Wipes and frees. Call only when wss_end returned true or the flow never began. Returns false and keeps the
 * screen when the wallet may still be open: the lock is owed and ticks must continue. */
bool wss_destroy(struct wss *screen);

/* Protects the window and opens the review of an accepted payment code. False, with nothing started and
 * the flow in progress untouched, when a send is still in progress or when either protection is not in
 * force. A new code is accepted only once the earlier flow has ended. */
bool wss_begin(struct wss *screen, const struct zapp_payment *pay);
/* Leaves the screen: cancels the flow where it can and removes the window protection. False while the
 * send is past the point of cancelling, and while the wallet is exposed or a lock is owed: keep calling
 * wss_on_tick until it returns true. */
bool wss_end(struct wss *screen);

void wss_tap_send(struct wss *screen, uint32_t serial);
void wss_tap_retry(struct wss *screen);
void wss_tap_cancel(struct wss *screen);
void wss_tap_make_private(struct wss *screen);
void wss_edit_amount(struct wss *screen, uint64_t amount_zat);
void wss_edit_address(struct wss *screen, const char *address);
void wss_edit_memo(struct wss *screen, const char *memo, size_t len);
void wss_on_pause(struct wss *screen);
void wss_on_resume(struct wss *screen);
/* Call about once a second while the screen is up. */
void wss_on_tick(struct wss *screen);

void wss_view(struct wss *screen, struct wss_view *out);
/* True when the passphrase and the unlock request hold no byte: proof that every path cleansed them. */
bool wss_secrets_clear(struct wss *screen);
/* Formats zatoshi as "1.5 ZCL" into out. */
void wss_format_zat(uint64_t zat, char *out, size_t cap);

#endif
