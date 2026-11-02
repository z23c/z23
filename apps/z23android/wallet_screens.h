/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SCREENS_H
#define ZAPP_WALLET_SCREENS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The wallet's read-only screens: Funds, Receive, History and a transaction's details. This file is the
 * whole behaviour and has no Android API: it turns replies of the wallet commands into a list of items
 * that wallet_ui.c draws, and turns a tap on an item into the next state.
 *
 * Wallet data lives only here. It is never copied to the app's view, a card, a notification, the
 * assistant context or a log, and this file writes to none of them. It is held while a wallet screen is
 * in front and wiped when the owner leaves.
 *
 * Commands run off the calling thread, at most one thread per kind of command: a request made while its
 * kind runs replaces the one waiting, and a New address tap made while an address is being made is
 * ignored. So at most six threads exist, however fast the owner taps. A reply that arrives after the
 * owner moved on is dropped.
 *
 * Opening Receive never creates a key. It shows the most recent address the node reports ("latest");
 * only a tap on New address creates one.
 *
 * Replies are read by exact shape. A field that is missing or of another type reads as unknown, and a
 * reply whose frame is not the documented one is an error, never an empty wallet. Shapes, as the node
 * commands answer them, each inside {"ok":true,"data":{...}}:
 *   summary  zcl.wallet_summary.v1, read by wallet_view.
 *   fleet    zcl.fleet_status.v1: member, verdict (not_member | none_connected | unchecked | agree | disagree),
 *            refuses_send, machines_total, machines_connected, local_tip and machines[] of {name,
 *            connected, agreement (agrees | phone_behind | machine_behind | disagree | unknown)}. The
 *            line says that sending waits only when the node's own refuses_send is true.
 *   latest   {"address":"zs1..." | null} from the read-only node command `core wallet shielded latest`. It names the
 *            most recent address and not whether that address has received a payment, so the screen makes no claim
 *            about reuse. A node without the command is told apart from an error, and Receive offers New address.
 *   receive  {"address":"zs1..."} from `core wallet shielded receive`. A node without the command gets one
 *            sentence saying this build cannot make a new address, and no New address button.
 *   history  zcl.wallet_history.v1: entries[] of {txid, status (confirmed | pending), time, direction
 *            (received | sent | internal | unknown), amount_zat | null,
 *            memo_present, fully_shielded}. An entry is called private only when the node says fully_shielded
 *            is true (every input and output shielded) and public when it says false; null or a missing
 *            field makes no claim of privacy, count and next_cursor (a string, or null on the last page).
 *   detail   zcl.wallet_history.v1 with entry: the same row plus memo (text) or memo_hex. */

#define WALLET_PAGE_ROWS 10u
#define WALLET_ITEMS_MAX 48u
#define WALLET_TEXT_MAX 320u
#define WALLET_CURSOR_MAX 96u
#define WALLET_TXID_LEN 64u
#define WALLET_FLEET_UNCHECKED "Not checked by your fleet"
/* Funds asks the node again this often while it is in front. */
#define WALLET_REFRESH_MS 10000u
/* A reading older than this is no longer shown as current. */
#define WALLET_STALE_MS 30000u

enum wallet_page { WALLET_PAGE_NONE, WALLET_PAGE_FUNDS, WALLET_PAGE_RECEIVE, WALLET_PAGE_HISTORY, WALLET_PAGE_DETAIL };

enum wallet_item_kind {
    WALLET_ITEM_TITLE, WALLET_ITEM_AMOUNT, WALLET_ITEM_TEXT, WALLET_ITEM_NOTE,
    WALLET_ITEM_MEMO,    /* text written by another person, drawn apart from every line the wallet writes */
    WALLET_ITEM_QR,      /* text is the code to draw as a QR code */
    WALLET_ITEM_ADDRESS, /* text is the address in groups of four */
    WALLET_ITEM_INPUT,   /* text is the hint; the draw code reads the field when Set amount is tapped */
    WALLET_ITEM_BUTTON
};
enum wallet_action {
    WALLET_ACT_NONE, WALLET_ACT_RECEIVE, WALLET_ACT_SEND, WALLET_ACT_HISTORY, WALLET_ACT_NEW_ADDRESS,
    WALLET_ACT_SET_AMOUNT, WALLET_ACT_NEWER, WALLET_ACT_OLDER, WALLET_ACT_DETAIL, WALLET_ACT_BACK,
    WALLET_ACT_START_NODE, WALLET_ACT_COPY_ADDRESS
};
enum wallet_outcome {
    WALLET_STAY,  /* the screen changed or nothing happened */
    WALLET_SEND,  /* open the Send screen; the camera starts only from its Scan code button */
    WALLET_LEAVE, /* leave the wallet for Home */
    WALLET_START_NODE /* ask the controller to start the node, and nothing else */
};

struct wallet_item {
    enum wallet_item_kind kind;
    enum wallet_action action;
    unsigned arg; /* the row of a WALLET_ACT_DETAIL button */
    char text[WALLET_TEXT_MAX];
};
struct wallet_screen {
    enum wallet_page page;
    size_t count;
    struct wallet_item items[WALLET_ITEMS_MAX];
};

struct wallet_env {
    void *ctx;
    /* Turns on, or off, the window protection that keeps the wallet out of screenshots, recordings, Recents,
     * overlays and screen readers. Called on the UI thread. Must report true only when every protection is
     * in force: on false nothing is shown and no command runs. */
    bool (*secure)(void *ctx, bool on);
    /* Runs one wallet command and leaves its JSON reply in out: "summary", "fleet", "latest", "receive",
     * "history" with arg the cursor of the page ("" for the newest) or "detail" with
     * arg the transaction id. Called from a worker thread. False when the command failed or does not
     * exist; out then holds the node's error text, which is only searched, never shown. */
    bool (*run)(void *ctx, const char *op, const char *arg, char *out, size_t cap);
    /* Called from a worker thread after a reply changed what the screen shows. */
    void (*changed)(void *ctx);
    /* Milliseconds on a monotonic clock. */
    uint64_t (*now_ms)(void *ctx);
    /* Run each command on its own thread; false runs it in the caller, for tests. */
    bool async;
    /* In plain words, what the protection that was just refused could not do, as the end of "this phone would not
     * let the app ...". Optional (NULL). Called on the UI thread right after secure returned false. */
    const char *(*refusal)(void *ctx);
    /* Whether the node process runs. Optional (NULL: unknown). A node that does not answer is shown as stopped when this says it
     * is not running, and as not answering when it runs or this is unknown. Called on the UI thread. */
    bool (*node_running)(void *ctx);
    /* Puts the address on the clipboard as a sensitive clip that clears itself after a minute. Optional (NULL: copying is
     * refused). Called on the UI thread with the address as the node gave it, without grouping. */
    bool (*copy_address)(void *ctx, const char *address);
    /* The app's private files directory, where the last balance the node gave is kept for the next time Funds opens
     * before the node answers. Optional (NULL: nothing is kept). */
    const char *files_dir;
    /* Seconds since the Unix epoch. Optional (NULL: the system clock). Dates the kept balance. */
    int64_t (*wall_s)(void *ctx);
};

bool wallet_screens_init(const struct wallet_env *env);
/* Leaves any wallet screen and wipes everything. */
void wallet_screens_shutdown(void);

/* Enters a page (Funds from Home) and starts its commands. False, with only a plain notice to show, when
 * the screen protection is not in force. */
bool wallet_screens_open(enum wallet_page page);
/* Leaves the wallet screens: wipes what they hold and removes the screen protection. */
void wallet_screens_close(void);
/* The app goes out of view: wipes what the screens hold and stops their commands, and leaves the screen
 * protection in force, so a capture taken before the next frame still shows nothing. The caller removes it
 * with wallet_screens_close() once a screen that holds no wallet data has been drawn. */
void wallet_screens_pause(void);
/* Call on the UI thread once a screen that holds no wallet data has been drawn after a pause: removes the
 * protection the pause kept. Does nothing when no pause is waiting, the owner went back into the wallet, or the pause is under 250 ms or two ticks old. */
void wallet_screens_settle(void);
/* Back one step inside the wallet; false when already on Funds, where Back leaves for Home. */
bool wallet_screens_back(void);
/* A tap on an item. */
enum wallet_outcome wallet_screens_activate(enum wallet_action action, unsigned arg);
/* The text typed into the amount field, in ZCL; empty clears the amount. False, with a note on the
 * screen, when it is not an amount the parser of payment codes would accept. */
bool wallet_screens_set_amount(const char *text);
/* Call about every two seconds on the UI thread while the app is in front. On Funds it asks the node
 * again every WALLET_REFRESH_MS and marks a reading older than WALLET_STALE_MS as out of date. */
void wallet_screens_tick(void);
/* Taps that were dropped because another window was drawing over the app. The screen then says why nothing
 * happened, until a tap reaches it. Call on the UI thread; the count is of new drops. */
void wallet_screens_dropped(unsigned taps);

/* Words about a scan that began at Send and ended without a payment to review, shown on Funds until the owner leaves
 * it, with the Send button reading "Scan again". Does nothing unless Funds is in front. */
void wallet_screens_scan_notice(const char *text);

/* Copies the current screen. Returns its version, which changes whenever it does. */
unsigned wallet_screens_snapshot(struct wallet_screen *out);
/* Whether a wallet screen is in front. */
bool wallet_screens_active(void);

/* Whether the bytes appear anywhere in the state this file holds. For tests and diagnostics. */
bool wallet_screens_residue(const void *bytes, size_t len);
/* Whether text is a transaction id (64 lower-case hex digits) or a history cursor ("<height or p>:<txid-like
 * 64 hex digits>"). Shared by the screens and by the command layer, which checks them again before they
 * become command-line arguments. */
static inline bool wallet_hex_valid(const char *text, size_t n)
{
    for (size_t i = 0; i < n; ++i) if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return false;
    return true;
}
static inline bool wallet_txid_valid(const char *text)
{
    return text && strlen(text) == WALLET_TXID_LEN && wallet_hex_valid(text, WALLET_TXID_LEN);
}
static inline bool wallet_cursor_valid(const char *text)
{
    size_t colon = 0;
    if (!text) return false;
    while (text[colon] && text[colon] != ':') ++colon;
    bool height = colon >= 1 && colon <= 10;
    for (size_t i = 0; i < colon && height; ++i) height = text[i] >= '0' && text[i] <= '9';
    return text[colon] == ':' && (height || (colon == 1 && text[0] == 'p')) && wallet_txid_valid(text + colon + 1);
}
#endif
