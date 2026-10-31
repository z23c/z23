/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SURFACE_H
#define ZAPP_SURFACE_H
#include "layout.h"
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>

#define ZAPP_NO_CARD ((size_t)-1)

/* The label of an action id the app knows, or NULL; an action node with no label is not drawn. */
typedef const char *(*zapp_surface_labels)(const char *action_id);

/* Draws one screen of a layout from cards into platform widgets inside host, a FrameLayout. */
bool zapp_surface_create(JNIEnv *env, jobject activity, jobject host);
void zapp_surface_destroy(JNIEnv *env);
/* Shows the named screen. Widgets are rebuilt only when the layout, the screen or the set of cards
 * changes; otherwise only text that differs is updated in place. A false return leaves the host empty. */
bool zapp_surface_show(JNIEnv *env, const struct zapp_layout *layout, const char *screen,
                       const struct json_value *const *cards, size_t count, zapp_surface_labels labels);
/* The action node under a window point: its id and the index of the card it was drawn for, or
 * ZAPP_NO_CARD. The surface performs nothing itself; the app decides what an id does. */
bool zapp_surface_hit(JNIEnv *env, float x, float y, char id[ZAPP_NAME_CAP], size_t *card);
#endif
