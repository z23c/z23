/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SEND_SCREEN_H
#define ZAPP_WALLET_SEND_SCREEN_H
#include "payment_notice.h"
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
#define WSS_CONFIRMED 16
#define WSS_UNLOCK_JSON 128
#define WSS_MEMO 4200   /* A memo of ZAPP_PAY_MEMO_MAX bytes with every character written out in full. */

/* What the node is asked to plan or commit. A sweep (sweep true) moves public funds into the private balance: it carries
 * no address, no amount and no memo, only the idempotency key and, for a commit, the plan the node quoted. */
struct wss_send_req {
    bool sweep;
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
 *   error code SEND_REFUSED_KEY_RELEASED (the node released the key: nothing was sent) -> WSS_KEY_RELEASED
 *   error code FEE_CHANGED (refused before any build)                         -> WSS_FEE_CHANGED
 *   anything else, including WALLET_RPC_ERROR, a timeout and no answer       -> WSS_UNKNOWN
 *     (SEND_IN_PROGRESS, SEND_OUTCOME_UNKNOWN, IDEMPOTENCY_KEY_REUSED, PLAN_REQUIRED, PLAN_TOKEN_MISMATCH,
 *     MISSING_IDEMPOTENCY_KEY and INVALID_IDEMPOTENCY_KEY are pinned to it by a table test; a key reuse proves
 *     an earlier send exists. The code is WALLET_SEND_ONCE_CODE_RELEASED in wallet_send_once.h.)
 * WALLET_RPC_ERROR is unknown because it also covers an admitted transaction whose compensation failed and
 * whose row was kept. Only WSS_KEY_RELEASED and WSS_FEE_CHANGED may say "Nothing was sent". */
enum wss_commit_outcome { WSS_COMMITTED, WSS_KEY_RELEASED, WSS_FEE_CHANGED, WSS_UNKNOWN };
enum wss_commit_outcome wss_commit_outcome_of(bool answered, bool committed, const char *error_code);
/* What a committed answer adds: whether the node answered from its record of an earlier commit under the same key
 * (replayed true: nothing new was built), and the transaction id it reported. Empty strings when it reported none. */
struct wss_commit_info {
    bool replayed;
    enum ws_why why;   /* A refused sweep commit: the reason, when it is one the app knows. */
    char txid[WS_TXID_MAX];
};

/* What one payment can use now, as `core wallet summary` reports it. known is false until the node reported the private
 * amounts: a locked wallet that hides them has no known balance, never a zero one. */
struct wss_balance {
    bool known;
    uint64_t spendable_zat;
};

/* Typed node calls. Each returns false when the node could not be asked. */
struct wss_node_ops {
    void *ctx;
    bool (*validate_address)(void *ctx, const char *address, bool *valid);   /* validateaddress */
    bool (*read_gate)(void *ctx, struct ws_gate *out);                       /* core wallet summary */
    bool (*plan)(void *ctx, const struct wss_send_req *req, struct ws_plan *out);       /* shielded send, no confirm */
    /* core wallet security unlock: json is read from standard input and never put in argv. */
    bool (*unlock)(void *ctx, const char *stdin_json, size_t len, uint32_t seconds);
    bool (*lock)(void *ctx);                                                 /* core wallet security lock */
    enum wss_commit_outcome (*commit)(void *ctx, const struct wss_send_req *req, char token_echo[WS_TOKEN_MAX],
                                      struct wss_commit_info *info);
    bool (*route)(void *ctx, enum ws_route *out);                            /* core wallet broadcast status */
    bool (*read_balance)(void *ctx, struct wss_balance *out);                /* core wallet summary. Optional. */
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
    /* The key of a payment request (wallet_send.h, ws_env). Optional: without it every review gets a random key. */
    bool (*derive_key)(void *ctx, const struct zapp_payment *pay, char out[WS_KEY_HEX + 1]);
    /* Seconds since the Unix epoch, read when the node's committed answer arrives. Optional. */
    int64_t (*wall_s)(void *ctx);
    /* Called once per payment, off the screen lock, when a payment that reached the node ends: result is an enum
     * zapp_payment_result. Optional. It may run on any thread. */
    void (*outcome)(void *ctx, int result);
};
struct wss_deps {
    enum zapp_pay_network network;
    struct wss_node_ops node;
    struct wss_device_ops device;
    struct wss_host_ops host;
    struct zapp_secure_ops secure;
    /* Called once, after the screen is freed, so the context the ops point to can be released with it. Optional. */
    void (*release)(void *ctx);
    void *release_ctx;
};

/* The field whose keyboard opens when its page opens. */
enum wss_focus { WSS_FOCUS_NONE, WSS_FOCUS_ADDRESS, WSS_FOCUS_AMOUNT };

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
    bool can_leave;                   /* Draw Done: the flow ended, or the node holds the payment and only History can say more. */
    bool can_cancel;
    bool can_pay_again;               /* Draw Pay again: the node holds an earlier payment of this request as committed. */
    bool sweep;                       /* The flow moves public funds into the private balance: draw move and arrives, not a payment. */
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
    char move[WSS_LINE];              /* A sweep: "Move 0.1 ZCL from your public address into your private balance. Fee 0.0001 ZCL." */
    char arrives[WSS_LINE];           /* A sweep: what the private balance gains. */
    char move_note[WSS_LINE];         /* A sweep: coins left for a later move, and coins still maturing. */
    char txid[WS_TXID_MAX];           /* The earlier payment's transaction, in WS_PAID. */
    char confirmed[WSS_CONFIRMED];    /* When the node gave the committed answer, as "Today 14:05", in the phone's time zone; empty when the phone has no clock. */
    char fleet[WSS_LINE];             /* "Checked by your fleet" or "Not checked by your fleet". */
    char status[WSS_LINE];
    enum wss_focus focus;             /* WSS_FOCUS_AMOUNT on the amount page of a payment named without an amount. */
    char available[WSS_LINE];         /* The amount page: "Available: 4.9999 ZCL", once the balance is known. */
    bool can_max;                     /* Draw Max: the amount becomes the spendable balance less the fee a plan quotes. */
};

/* The Send page before a payment is named. With the balance known to be 0 it says so and offers Receive, and asks for no
 * address; otherwise it asks for the address with its keyboard open, and offers Paste address when the clipboard holds an
 * address or a payment code that the parser of scanned codes accepts. */
#define WSS_ZERO_BALANCE "You have 0 ZCL to send. Receive some first."
struct wss_start {
    bool zero;
    bool paste;
    enum wss_focus focus;
    char line[WSS_LINE];
};
void wss_start_page(const struct wss_balance *balance, bool clip_holds_address, struct wss_start *out);
/* Whether clip, trimmed of the spaces and control bytes at its ends, is an address or a payment code of network. */
bool wss_paste_offered(const char *clip, enum zapp_pay_network network);
/* What the Send page knows of the clipboard. Each new clip is read once, whether or not its text could be read (a photo, a
 * file, text longer than a payment code), so the system notice that the app read the clipboard comes once for each clip. */
struct wss_clip {
    bool read;      /* the clip with stamp was read */
    bool address;   /* its text is an address or a payment code (wss_paste_offered) */
    int64_t stamp;
};
/* state and stamp are what the clip's description reports (zapp_clipboard_stamp). An empty clipboard forgets the clip. A
 * held clip not read before is read through read_text, which fills out with the clip's text and returns false when there
 * is none or it does not fit in cap; the text is wiped before this returns. */
void wss_clip_check(struct wss_clip *clip, enum zapp_clip_state state, int64_t stamp,
                    bool (*read_text)(void *ctx, char *out, size_t cap), void *ctx, enum zapp_pay_network network);
/* The most one payment can send: the spendable amount less the fee, 0 when the fee takes it all. */
uint64_t wss_max_amount(uint64_t spendable_zat, uint64_t fee_zat);
/* The keyboard opens once each time a page with a field comes up, not on every redraw of that page: true when focus names
 * a field and the page drawn before asked for another or none. *asked keeps the field of the page last drawn. */
bool wss_keyboard_due(enum wss_focus focus, enum wss_focus *asked);

struct wss;
struct wss *wss_create(const struct wss_deps *deps);
/* Wipes and frees. Call only when wss_end returned true or the flow never began. Returns false and keeps the
 * screen when the wallet may still be open: the lock is owed and ticks must continue. */
bool wss_destroy(struct wss *screen);
/* True while the wallet may be open: the lock is owed and ticks must continue. */
bool wss_exposed(struct wss *screen);
/* The owner pressed Done on the flow's outcome: it is no longer kept for a re-created activity. A later wss_begin
 * reopens it. */
void wss_close(struct wss *screen);
bool wss_closed(struct wss *screen);
/* A flow kept for a re-created activity is bound to the window it was begun on. wss_unbind drops that binding, so no
 * later call can reach a window that may be gone, and hides the payment until it is bound again. wss_rebind binds the
 * flow to the new window's protections and applies them before the flow is drawn; false means a protection is not in
 * force and the payment stays hidden. UI thread only, like wss_begin and wss_end. */
void wss_unbind(struct wss *screen);
bool wss_rebind(struct wss *screen, const struct zapp_secure_ops *secure);

/* Protects the window and opens the review of an accepted payment code. False, with nothing started and
 * the flow in progress untouched, when a send is still in progress or when either protection is not in
 * force. A new code is accepted only once the earlier flow has ended. */
bool wss_begin(struct wss *screen, const struct zapp_payment *pay);
/* The same for a sweep: Make private on Funds. It is refused for the same reasons, and it names no payment. */
bool wss_begin_sweep(struct wss *screen);
/* Leaves the screen: cancels the flow where it can and removes the window protection. False while the
 * send is past the point of cancelling, and while the wallet is exposed or a lock is owed: keep calling
 * wss_on_tick until it returns true. */
bool wss_end(struct wss *screen);

void wss_tap_send(struct wss *screen, uint32_t serial);
/* The Send tap, refused (nothing posted, false) while the prover is not ready: the button is hidden then, and a press
 * that still arrives starts nothing. */
bool wss_tap_send_ready(struct wss *screen, uint32_t serial, bool ready);
void wss_tap_retry(struct wss *screen);
void wss_tap_cancel(struct wss *screen);
/* Pay again, offered only on a payment the node reports as already paid. Starts a full review, and the owner's tap and
 * authentication, under a new random key. */
void wss_tap_pay_again(struct wss *screen);
void wss_edit_amount(struct wss *screen, uint64_t amount_zat);
/* Max. On a review it sets the amount to the reviewed spendable balance less the fee of that review's plan. On the amount
 * page it first asks the node for a plan of the whole spendable balance, which binds nothing and sends nothing, and sets
 * the amount to that balance less the fee the plan quotes. The new amount gets its own review, plan and tap. */
void wss_tap_max(struct wss *screen);
/* Asks the node for the spendable balance on the worker; the redraw follows the answer. A flow named without an amount
 * asks by itself. */
void wss_read_balance(struct wss *screen);
/* Reads the balance again while a page that shows it is on screen: the amount page of a flow, or, with start true, the Send
 * page before a payment is named. A reading is asked for once the last one, answered or not, is half of
 * WSS_BALANCE_FRESH_MS old, so Available, Max and the zero line stay on their page and a hidden balance is not asked for
 * on every tick. Call on the ticks. */
void wss_keep_balance(struct wss *screen, bool start);
/* A reading the wallet screen took from the node moments ago, used until the node answers again. */
void wss_note_balance(struct wss *screen, uint64_t spendable_zat);
/* The latest reading, known only while it is at most WSS_BALANCE_FRESH_MS old. */
#define WSS_BALANCE_FRESH_MS 30000u
void wss_balance(struct wss *screen, struct wss_balance *out);
void wss_edit_address(struct wss *screen, const char *address);
void wss_edit_memo(struct wss *screen, const char *memo, size_t len);
void wss_on_pause(struct wss *screen);
void wss_on_resume(struct wss *screen);
/* Call about once a second for as long as the screen exists, and after it has been left until wss_end returns true:
 * ticks are what ask again for a lock that is owed, so the wallet stays open until the node timer if they stop. */
void wss_on_tick(struct wss *screen);

void wss_view(struct wss *screen, struct wss_view *out);
/* The one-line progress of a payment from the owner's confirmation on:
 *   "Sending X ZCL to <8>…<6>: building the payment (about 2 min)"   the commit runs
 *   "Sending X ZCL to <8>…<6>: waiting to leave the phone"            the node holds it
 *   "Sent X ZCL"                                                      it left the phone
 *   "Already sent X ZCL"                                               the node answered from its record of it
 *   "Payment not sent: <cause>. Your coins were not spent."           the node says nothing was sent
 *   "Payment status unknown: ..."                                     no usable answer; it may have been sent
 * False before the commit starts and after the owner closed the outcome. */
bool wss_progress(struct wss *screen, char *line, size_t cap);
/* The owner dismissed the line of a payment that ended: wss_progress returns false until the next payment begins or runs,
 * whether or not the screen is still open. Does nothing while the payment is in flight. */
void wss_progress_dismiss(struct wss *screen);
/* True while the commit runs or the node holds the payment: the flow must keep running whatever screen is shown. */
bool wss_in_flight(struct wss *screen);
/* True in the states from the owner's confirmation to the outcome of the payment: authentication, the commit and the
 * broadcast. A payment in these states is not stopped. */
bool wss_send_busy(enum ws_state state);
/* Applies the prover check to a view: while it is not ready the review offers no Send and says why. */
void wss_gate_prover(struct wss_view *view, bool ready, const char *why);
/* True when the passphrase and the unlock request hold no byte: proof that every path cleansed them. */
bool wss_secrets_clear(struct wss *screen);
/* The wallet secret and the unlock request of one unlock. wss_unlock_node cleanses both before it returns. */
struct wss_unlock_buf {
    uint8_t secret[32];
    char json[WSS_UNLOCK_JSON];
};
/* What one unlock did: the device key's answer, whether the unlock request was handed to the node (the wallet may be open
 * from then on, whatever the answer), and whether the node said it was unlocked. */
struct wss_unlock_result {
    enum wss_key_status key;
    bool sent, ok;
};
/* Opens the wallet once for the owner. It unwraps the wallet secret with the device key, which shows the system prompt and
 * blocks, and only when the owner authenticated and wanted (optional) still returns true, asks the node to unlock for
 * seconds. The send flow and the private balance view both unlock through this one function. Run it on a worker. */
struct wss_unlock_result wss_unlock_node(const struct wss_device_ops *device, const struct wss_node_ops *node,
                                         struct wss_unlock_buf *buf, uint32_t seconds, bool (*wanted)(void *ctx),
                                         void *wanted_ctx);
void wss_unlock_cleanse(struct wss_unlock_buf *buf);
/* True when buf holds no byte. */
bool wss_unlock_buf_clear(const struct wss_unlock_buf *buf);
/* Formats zatoshi as "1.5 ZCL" into out. */
void wss_format_zat(uint64_t zat, char *out, size_t cap);

#endif
