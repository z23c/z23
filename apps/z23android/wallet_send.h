/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SEND_H
#define ZAPP_WALLET_SEND_H
#include "payment_code.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The send flow of the Android wallet as a pure state machine: no I/O, no clock, no framework call.
 * The caller feeds it events and carries out the typed actions it returns, then feeds the result back
 * as the next event. Every action carries a ticket; an event for any other ticket is stale and ignored.
 *
 * The rule the machine exists to keep: a commit action is produced only after the owner tapped Send on
 * a review of the current plan and the device then authenticated for that use, in that order. One action,
 * WS_ACT_UNLOCK, authenticates the owner and unwraps the wallet secret together; no authentication ever
 * counts for a later use. Any change to the amount, address or memo makes a new review with a new plan
 * serial and a new idempotency key, so an earlier tap never carries over. The key is made before the plan
 * is requested so the node binds it into the plan token. A commit whose answer is missing or does not
 * match is final: it is never retried, because the payment may have been sent. The wallet is unlocked
 * only between the unlock action and a lock action, every path out of the flow that requested an unlock
 * produces a lock action, and no tap is accepted while a lock is owed.
 *
 * The machine stores the payment (an address, an amount and a memo) while the flow lives and writes
 * none of it anywhere: no log, no card, no notification. */

#define WS_KEY_HEX 32
#define WS_TOKEN_MAX 40
#define WS_REASON_MAX 160
#define WS_UNLOCK_SECONDS 300u   /* A phone proof takes about 101 s; the lock right after the answer closes the window. */
#define WS_UNLOCK_WINDOW_MS 300000u
#define WS_LOCK_RETRY_MS 5000u
#define WS_ACTIONS_MAX 4
#define WS_LOCK_ATTEMPTS 3

enum ws_state {
    WS_IDLE,
    WS_PARSED,      /* A payment code was accepted and has no amount yet. */
    WS_VALIDATING,  /* The node is validating the address. */
    WS_GATE,        /* Reading whether the wallet may send now. */
    WS_WAITING,     /* The wallet is behind the chain; sending waits. */
    WS_PLAN,        /* The node is quoting the payment. */
    WS_REVIEW,      /* The owner reads the plan; only a tap on it goes on. */
    WS_AUTH,        /* Device authentication and unlock, one operation. */
    WS_COMMIT,      /* The node builds and sends. This takes minutes on a phone. */
    WS_BROADCAST,   /* Committed; waiting for a private route. */
    WS_DONE,
    WS_FAILED,
    WS_CANCELLED
};

enum ws_fail {
    WS_FAIL_NONE,
    WS_FAIL_ADDRESS,        /* The node does not accept the address. */
    WS_FAIL_BLOCKED,        /* send_allowed is false: send_blocked_reason is shown. */
    WS_FAIL_THERMAL,        /* The phone's thermal pause. */
    WS_FAIL_STATE_UNKNOWN,  /* The wallet state could not be read. */
    WS_FAIL_PLAN,           /* The node refused or garbled the plan. */
    WS_FAIL_AUTH_DECLINED,
    WS_FAIL_KEY_GONE,       /* The device key is gone: only the recovery phrase restores the wallet. */
    WS_FAIL_UNLOCK,
    WS_FAIL_WINDOW,         /* The 120 second unlock window ended. */
    WS_FAIL_COMMIT_REFUSED, /* The node answered that nothing was sent. */
    WS_FAIL_COMMIT_UNKNOWN, /* No usable answer: the payment may have been sent. Final, never retried. */
    WS_FAIL_NO_RANDOM
};

/* What the wallet reports before a send. blocks_behind and spendable come from `core wallet summary`.
 * blocked_reason is the node's send_blocked_reason sentence. */
struct ws_gate {
    bool known;
    bool send_allowed;
    char blocked_reason[WS_REASON_MAX];
    uint32_t blocks_behind;
    bool thermal_paused;      /* The phone's thermal state has paused the node. */
    uint64_t spendable_zat;   /* Private funds the send may use. */
    uint64_t public_zat;      /* Public funds, never drawn on by a private send. */
};

/* The plan the node quotes: the answer of `core wallet shielded send` without confirm. */
struct ws_plan {
    uint64_t amount_zat;
    uint64_t fee_zat;
    uint64_t total_zat;
    char token[WS_TOKEN_MAX];
};

enum ws_auth_result { WS_AUTH_OK, WS_AUTH_DECLINED, WS_AUTH_KEY_GONE };
enum ws_route { WS_ROUTE_WAITING, WS_ROUTE_SENT };

enum ws_event_kind {
    WS_EV_ADDRESS,       /* ticket, ok: the node validated the address (ok false: not valid). */
    WS_EV_GATE,          /* ticket, gate. */
    WS_EV_PLAN,          /* ticket, ok, plan. */
    WS_EV_TAP_SEND,      /* serial: the plan serial the screen was showing. */
    WS_EV_MAKE_PRIVATE,  /* The owner chose Make private on the insufficient funds note. */
    WS_EV_UNLOCK,        /* ticket, ok (authenticated and unlocked), auth (why not). */
    WS_EV_COMMIT,        /* ticket, ok (committed), refused (the node said nothing was sent), plan.token echoed. */
    WS_EV_ROUTE,         /* ticket, route. */
    WS_EV_LOCK,          /* ticket, ok. */
    WS_EV_SET_AMOUNT,    /* amount_zat. */
    WS_EV_SET_ADDRESS,   /* text. */
    WS_EV_SET_MEMO,      /* text; empty clears. */
    WS_EV_RETRY,
    WS_EV_CANCEL,
    WS_EV_BACKGROUND,    /* The app left the foreground. */
    WS_EV_RESUME,
    WS_EV_TICK           /* now_ms. */
};
struct ws_event {
    enum ws_event_kind kind;
    uint32_t ticket;
    uint32_t serial;
    bool ok;
    bool refused;
    enum ws_auth_result auth;
    enum ws_route route;
    struct ws_gate gate;
    struct ws_plan plan;
    uint64_t amount_zat;
    uint64_t now_ms;
    size_t text_len;
    char text[ZAPP_PAY_MEMO_MAX + 1];
};

enum ws_action_kind {
    WS_ACT_NONE,
    WS_ACT_VALIDATE_ADDRESS,  /* Ask the node: validateaddress. */
    WS_ACT_READ_GATE,
    WS_ACT_PLAN,              /* Plan only, confirm false. */
    WS_ACT_UNLOCK,            /* Authenticate the owner for this one use, unwrap the passphrase and unlock for WS_UNLOCK_SECONDS. */
    WS_ACT_COMMIT,            /* Commit the reviewed plan with its idempotency key. */
    WS_ACT_POLL_ROUTE,
    WS_ACT_LOCK,
    WS_ACT_OPEN_MAKE_PRIVATE  /* Leave the flow for the Make private screen. */
};
struct ws_action { enum ws_action_kind kind; uint32_t ticket; };
struct ws_actions { struct ws_action item[WS_ACTIONS_MAX]; size_t count; };

/* The only outside input the machine has: random bytes for the idempotency key. */
struct ws_env {
    enum zapp_pay_network network;
    void *ctx;
    bool (*random)(void *ctx, uint8_t *out, size_t len);
};

struct ws {
    struct ws_env env;
    enum ws_state state;
    enum ws_fail fail;
    struct zapp_payment pay;
    struct ws_gate gate;
    struct ws_plan plan;
    char key[WS_KEY_HEX + 1];
    char blocked[WS_REASON_MAX];
    uint32_t ticket;
    uint32_t serial;          /* Counts reviews; a new plan is a new serial. */
    bool tapped;              /* The owner tapped Send on this serial. */
    bool unlock_requested;    /* An unlock was asked for and its lock is not yet confirmed. */
    bool lock_wanted;
    unsigned lock_attempts;
    uint32_t seq;             /* Issues tickets. */
    uint32_t lock_ticket;
    uint64_t gate_ms;
    uint64_t lock_ms;
    uint64_t unlock_ms;
    uint64_t state_ms;
    uint64_t now_ms;
    bool retry_ok;
    bool insufficient;
};

/* Starts the flow for an accepted payment code. The previous flow, if any, is dropped. A payment with
 * no amount waits in WS_PARSED for WS_EV_SET_AMOUNT. */
void ws_open(struct ws *ws, const struct ws_env *env, const struct zapp_payment *pay, uint64_t now_ms,
             struct ws_actions *out);
/* Feeds one event and returns the actions to carry out. */
void ws_step(struct ws *ws, const struct ws_event *ev, struct ws_actions *out);

bool ws_terminal(const struct ws *ws);
/* True while the flow holds, or may hold, the wallet unlocked. */
bool ws_wallet_exposed(const struct ws *ws);
uint32_t ws_serial(const struct ws *ws);
/* The one-sentence reason of a failure, in plain words; "" while the flow has not failed. */
const char *ws_fail_text(const struct ws *ws);
/* Whether the review can be sent: a plan exists and the private funds cover it. */
bool ws_can_send(const struct ws *ws);
/* The text a waiting wallet shows. */
const char *ws_state_name(enum ws_state state);

#endif
