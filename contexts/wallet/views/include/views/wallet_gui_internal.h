/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Z23 GUI shared internals for the WebKit app and self-test driver.
 *
 * The GTK/WebKit wallet GUI is split across two translation units that
 * both live in contexts/explorer/views/src/ and are compiled only when WebKit + GTK are
 * present:
 *
 *   - wallet_gui.c     — the GTK app: dark-theme CSS, the in-process URI
 *                        scheme handler, navigation, key/policy handlers,
 *                        controller init, and wallet_gui_main.
 *   - wallet_gui_bot.c — the Selenium-like bot driver (g_bot_script and
 *                        the load/JS-result callbacks) used by -self-test.
 *
 * These globals are owned by wallet_gui.c and shared with the bot driver. This
 * header is only meaningful inside the HAVE_WEBKIT/HAVE_GTK guard. */

#ifndef ZCL_VIEWS_WALLET_GUI_INTERNAL_H
#define ZCL_VIEWS_WALLET_GUI_INTERNAL_H

#if defined(HAVE_WEBKIT) && defined(HAVE_GTK)

#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <stdbool.h>

/* Owned by wallet_gui.c. */
extern WebKitWebView *g_webview;
extern bool g_self_test;
extern int g_bot_fail;

/* Navigate the embedded WebView to an in-process path (wallet_gui.c). */
void navigate(const char *path);

/* Bot driver entry point — kicks off the self-test scenario (wallet_gui_bot.c).
 * Matches the GSourceFunc signature for g_idle_add(). */
gboolean start_self_test(gpointer data);

#endif /* HAVE_WEBKIT && HAVE_GTK */

#endif
