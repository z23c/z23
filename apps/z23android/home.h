/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_HOME_H
#define ZAPP_HOME_H
#include "app.h"
#include "scan.h"
#include <stdbool.h>
#include <stddef.h>

#define ZAPP_APP_LABEL_CAP 96
#define ZAPP_APP_PACKAGE_CAP 256
#define ZAPP_APP_ACTIVITY_CAP 512
/* Room for one app card with every character of its label escaped to six bytes. */
#define ZAPP_APP_CARD_CAP 2048

struct zapp_app_entry {
    char label[ZAPP_APP_LABEL_CAP];
    char package[ZAPP_APP_PACKAGE_CAP];
    char activity[ZAPP_APP_ACTIVITY_CAP]; /* Launcher activity class that the tile starts. */
    bool same_signature;                  /* Signed with the same key as this app. */
};

/* zcl.phone_card.v1: node line, sync status, and pace. It carries nothing else
 * from the view: no fleet token, host plan, pairing offer, key or path. preview marks the voice
 * preview package, which never runs a node. Returns the JSON length, or 0 when cap is too small. */
size_t zapp_home_phone_card(const struct zapp_view *view, bool preview, char *out, size_t cap);
/* One launchable app: zcl.z23_app_card.v1 for an org.z23.* app signed with this app's key, else
 * zcl.app_card.v1. Returns the JSON length or 0. */
size_t zapp_home_app_card(const struct zapp_app_entry *app, char *out, size_t cap);
/* Whether a package is one of the separate Z23 apps (org.z23.*), not the base app org.z23.nativeapp or a
 * voice preview build. */
bool zapp_home_is_z23_app(const char *package);

/* The built-in layouts, as zcl.layout_recipe.v1 documents. */
size_t zapp_home_layout_count(void);
const char *zapp_home_layout_name(size_t index);
/* The document of the named built-in layout, or NULL. */
const char *zapp_home_layout(const char *name);
/* The label of a home action id (scan, assistant, apps, settings), or NULL. */
const char *zapp_home_action_label(const char *id);
/* The Home node button for a snapshot: its label, and the user-intent action it sends ("" while a stop is in progress). */
const char *zapp_home_node_label(const struct zapp_view *view);
const char *zapp_home_node_action(const struct zapp_view *view);
/* Whether a laptop pairing offer must open its review now. seen records that the owner was taken to
 * it: it is set only when this returns true, and cleared when there is no offer, so an offer that
 * arrives while the scan screen is up is not lost. */
bool zapp_home_offer_jump(bool offer, bool on_scan_screen, bool *seen);
/* Where a finished scan takes the owner. */
enum zapp_scan_target { ZAPP_SCAN_TO_HOME, ZAPP_SCAN_TO_FLEET_REVIEW, ZAPP_SCAN_TO_PAIR_REVIEW, ZAPP_SCAN_TO_PAYMENT_REVIEW };
/* A fleet invitation opens its review, and a laptop pairing code opens the pairing review when the
 * controller holds an offer for it, whether or not the owner saw an earlier offer.
 * A payment code, accepted or refused by payment_code.h, goes to the Send screen: an accepted one opens the review and
 * nothing more, a refused one stays there with its reason, Scan again and Enter address. Everything else is shown on
 * Home. */
enum zapp_scan_target zapp_home_scan_target(enum zapp_scan_kind kind, bool pair_offer);
/* Whether a finished scan returns to the wallet screen it began on, with its words there, instead of to Home: when it
 * began on a wallet screen and is not a review (a payment code opens Send). */
bool zapp_home_scan_returns_to_wallet(enum zapp_scan_target target, bool began_in_wallet);
/* Whether a scan that was started on the Send screen and is not a payment, a fleet invitation or a pairing code stays
 * on Send, with Scan code and Enter address, instead of dropping to Home. */
bool zapp_home_scan_stays_on_send(bool started_on_send, enum zapp_scan_target target);
/* The label of the Send screen camera button: Scan code until a scan has ended without a payment, then Scan again. */
const char *zapp_home_send_scan_label(const char *notice);
/* The words the Send screen shows when a scan begun on it ends without a payment to review: the reason a payment code
 * was refused, otherwise what the scan reported, a camera refusal included. */
const char *zapp_home_send_notice(enum zapp_scan_kind kind, const char *scan_text, const char *result);
/* Whether Back from Send returns to the wallet: Send was opened from the wallet, directly or through a scan begun there. A scan
 * begun on Send keeps the place Send was first opened from. */
bool zapp_home_send_opened_from_wallet(bool origin_is_send, bool origin_is_wallet, bool was_from_wallet);
/* Whether a touch released on the control it went down on. Controls are matched by position in the drawn list; on the Send
 * screen and the setup screens the position can hold another button after a redraw, so the button identity must match too. */
bool zapp_home_same_press(size_t index_a, bool by_button_a, unsigned button_a, size_t index_b, bool by_button_b, unsigned button_b);
/* Copies text into out (cap bytes), cutting on a character boundary when it does not fit. */
void zapp_home_fit_label(char *out, size_t cap, const char *text);
#endif
