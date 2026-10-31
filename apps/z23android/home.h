/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_HOME_H
#define ZAPP_HOME_H
#include "app.h"
#include <stdbool.h>
#include <stddef.h>

#define ZAPP_APP_LABEL_CAP 96
#define ZAPP_APP_PACKAGE_CAP 128

struct zapp_app_entry {
    char label[ZAPP_APP_LABEL_CAP];
    char package[ZAPP_APP_PACKAGE_CAP];
};

/* zcl.phone_card.v1: node line, sync status, balance when known, and pace. It carries nothing else
 * from the view: no fleet token, host plan, pairing offer, key or path. preview marks the voice
 * preview package, which never runs a node. Returns the JSON length, or 0 when cap is too small. */
size_t zapp_home_phone_card(const struct zapp_view *view, bool preview, char *out, size_t cap);
/* The label and package of one launchable app: zcl.z23_app_card.v1 for a Z23 app, else zcl.app_card.v1.
 * Returns the JSON length or 0. */
size_t zapp_home_app_card(const struct zapp_app_entry *app, char *out, size_t cap);
/* Whether a package is one of the separate Z23 apps (org.z23.*), not the base app org.z23.nativeapp or a
 * voice preview build. A test build defining ZAPP_Z23_TEST_PACKAGE also accepts org.z23.voicepreview.clips. */
bool zapp_home_is_z23_app(const char *package);

/* The built-in layouts, as zcl.layout_recipe.v1 documents. */
size_t zapp_home_layout_count(void);
const char *zapp_home_layout_name(size_t index);
/* The document of the named built-in layout, or NULL. */
const char *zapp_home_layout(const char *name);
/* The label of a home action id (assistant, apps, settings), or NULL. */
const char *zapp_home_action_label(const char *id);
#endif
