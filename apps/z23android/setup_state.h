/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SETUP_STATE_H
#define ZAPP_SETUP_STATE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Where first-run wallet setup stands, read from two files in the app's private files directory:
 *   wallet_key.blob     the wallet passphrase wrapped by the device key, written when setup begins;
 *   wallet_setup_done   written once the owner has proved they hold the recovery words (create) or typed them (restore).
 * Nothing else decides it: the state survives a restart and holds no secret. */
enum zapp_setup_state {
    ZAPP_SETUP_NEEDED,        /* No wrapped passphrase: the owner chooses Create or Restore. */
    ZAPP_SETUP_INTERRUPTED,   /* A wallet was begun and its words were not confirmed. The words cannot be shown again. */
    ZAPP_SETUP_READY          /* Setup finished. */
};
enum zapp_setup_state zapp_setup_state(const char *files);
/* Records that setup finished: a temporary file renamed into place and synced. False when it could not be written. */
bool zapp_setup_mark_done(const char *files);

/* What the owner chose, written before the node command runs and kept beside the wrapped passphrase, so a restart can tell
 * a restore that finished in the node from a create whose words were never confirmed. */
enum zapp_setup_kind { ZAPP_KIND_NONE, ZAPP_KIND_CREATE, ZAPP_KIND_RESTORE };
bool zapp_setup_kind_write(const char *files, enum zapp_setup_kind kind);
enum zapp_setup_kind zapp_setup_kind_read(const char *files);
/* Removes the kind record; the wrapped passphrase is removed by the device key. */
void zapp_setup_kind_forget(const char *files);

/* Moves a file or directory aside under dir as name.unused-<UTC time, ISO 8601 basic>. Nothing is deleted or replaced: a target that exists
 * is a failure. ABSENT when there is nothing to move. */
enum zapp_aside { ZAPP_ASIDE_MOVED, ZAPP_ASIDE_ABSENT, ZAPP_ASIDE_FAILED };
enum zapp_aside zapp_setup_set_aside(const char *dir, const char *name, int64_t now_s);
/* Moves name.unused-<time> back to name, only when the original is absent: nothing is replaced. */
bool zapp_setup_undo_aside(const char *dir, const char *name, int64_t now_s);
/* The path a file set aside at now_s has. */
bool zapp_setup_aside_path(const char *dir, const char *name, int64_t now_s, char *out, size_t cap);

/* Written as soon as the words match, before any later step, so a restart can never offer to start over a confirmed create. The record
 * names the key file it was made for (its SHA3-256): it confirms nothing once that file is set aside or replaced, and cannot be
 * written without one. */
bool zapp_setup_mark_confirmed(const char *files, bool start_known);
bool zapp_setup_confirmed(const char *files);
/* Whether the record says the wallet recorded a start height. */
bool zapp_setup_confirmed_start(const char *files);

#endif
