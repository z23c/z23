/* Copyright (c) 2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "util/noui.h"
#include "util/ui_interface.h"
#include "util/util.h"
#include <stdio.h>

static bool noui_ThreadSafeMessageBox(const char *message, const char *caption, unsigned int style)
{
    bool fSecure = style & UI_SECURE;
    style &= ~(unsigned)UI_SECURE;

    const char *prefix;
    switch (style) {
    case UI_MSG_ERROR:       prefix = "Error"; break;
    case UI_MSG_WARNING:     prefix = "Warning"; break;
    case UI_MSG_INFORMATION: prefix = "Information"; break;
    default:                 prefix = caption; break;
    }

    if (!fSecure)
        LogPrintf("%s: %s\n", prefix, message);
    fprintf(stderr, "%s: %s\n", prefix, message);
    return false;
}

static bool noui_ThreadSafeQuestion(const char *message, const char *noninteractive,
                                    const char *caption, unsigned int style)
{
    (void)noninteractive;
    return noui_ThreadSafeMessageBox(message, caption, style);
}

static void noui_InitMessage(const char *message)
{
    LogPrintf("init message: %s\n", message);
}

void noui_connect(void)
{
    uiInterface.ThreadSafeMessageBox = noui_ThreadSafeMessageBox;
    uiInterface.ThreadSafeQuestion = noui_ThreadSafeQuestion;
    uiInterface.InitMessage = noui_InitMessage;
}
