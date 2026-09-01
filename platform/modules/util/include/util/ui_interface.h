/* Copyright (c) 2010 Satoshi Nakamoto
 * Copyright (c) 2012 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_UI_INTERFACE_H
#define BITCOIN_UI_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

enum change_type {
    CT_NEW,
    CT_UPDATED,
    CT_DELETED
};

enum ui_message_flags {
    UI_ICON_INFORMATION = 0,
    UI_ICON_WARNING     = (1U << 0),
    UI_ICON_ERROR       = (1U << 1),

    UI_BTN_OK           = 0x00000400U,
    UI_BTN_YES          = 0x00004000U,
    UI_BTN_NO           = 0x00010000U,
    UI_BTN_CANCEL       = 0x00400000U,

    UI_MODAL            = 0x10000000U,
    UI_SECURE           = 0x40000000U,

    UI_MSG_INFORMATION  = 0,
    UI_MSG_WARNING      = (UI_ICON_WARNING | UI_BTN_OK | UI_MODAL),
    UI_MSG_ERROR        = (UI_ICON_ERROR | UI_BTN_OK | UI_MODAL)
};

typedef bool (*ui_message_box_fn)(const char *message, const char *caption, unsigned int style);
typedef bool (*ui_question_fn)(const char *message, const char *noninteractive, const char *caption, unsigned int style);
typedef void (*ui_init_message_fn)(const char *message);
typedef void (*ui_progress_fn)(const char *title, int nProgress);
typedef void (*ui_block_tip_fn)(const unsigned char *hash);

/* Decoupling seam between the node core and whatever front-end (if any)
 * is presenting it. The core invokes these callbacks to surface user-
 * facing notices without depending on a concrete UI:
 *   ThreadSafeMessageBox — show an informational/error notice (style is
 *                          a bitwise OR of enum ui_message_flags)
 *   ThreadSafeQuestion   — ask a yes/no question; `noninteractive` is the
 *                          text used when no human can answer
 *   InitMessage          — report a startup progress message
 *   ShowProgress         — report a titled 0..100 progress percentage
 *   NotifyBlockTip       — signal that the active chain tip advanced
 *
 * Lifecycle: the global `uiInterface` is zero-initialized, so every slot
 * is NULL until a front-end installs its handlers. The headless default
 * is noui_connect() (util/noui.h), which wires the message/question/init
 * slots to stderr loggers and leaves the rest NULL. Because slots may be
 * NULL, callers MUST null-check a slot before dispatching through it. */
struct ui_interface {
    ui_message_box_fn  ThreadSafeMessageBox;
    ui_question_fn     ThreadSafeQuestion;
    ui_init_message_fn InitMessage;
    ui_progress_fn     ShowProgress;
    ui_block_tip_fn    NotifyBlockTip;
};

/* Process-wide singleton vtable; zero-initialized at load. */
extern struct ui_interface uiInterface;

#endif
