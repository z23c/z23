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
/* Whether a laptop pairing offer must open its review now. seen records that the owner was taken to
 * it: it is set only when this returns true, and cleared when there is no offer, so an offer that
 * arrives while the scan screen is up is not lost. */
bool zapp_home_offer_jump(bool offer, bool on_scan_screen, bool *seen);
/* Where a finished scan takes the owner. */
enum zapp_scan_target { ZAPP_SCAN_TO_HOME, ZAPP_SCAN_TO_FLEET_REVIEW, ZAPP_SCAN_TO_PAIR_REVIEW };
/* A fleet invitation opens its review, and a laptop pairing code opens the pairing review when the
 * controller holds an offer for it, whether or not the owner saw an earlier offer. Everything else is
 * shown on Home. */
enum zapp_scan_target zapp_home_scan_target(enum zapp_scan_kind kind, bool pair_offer);
/* Copies text into out (cap bytes), cutting on a character boundary when it does not fit. */
void zapp_home_fit_label(char *out, size_t cap, const char *text);
#endif
