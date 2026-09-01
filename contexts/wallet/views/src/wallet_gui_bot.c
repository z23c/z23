/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Z23 GUI bot driver: drives the real GTK WebKit app, navigates wallet
 * pages, executes JS, and asserts DOM text via the g_bot_script scenario.
 * Shares g_webview / g_self_test / g_bot_fail and navigate() with wallet_gui.c
 * through views/wallet_gui_internal.h. */

#if defined(HAVE_WEBKIT) && defined(HAVE_GTK)

#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "views/wallet_gui_internal.h"

/* ── Bot Driver (Selenium-like) ────────────────────────── */
/* g_self_test is owned by wallet_gui.c (extern via the internal header).
 * g_bot_fail is read by wallet_gui_main()'s exit code, so it has external
 * linkage and is defined here. The remaining counters are bot-local. */
int g_bot_fail = 0;
static int g_bot_step = 0;
static int g_bot_pass = 0;
static char g_bot_last_text[32768]; /* last page DOM text */

/* A bot action: navigate, execute JS, check result */
struct bot_action {
    const char *desc;       /* human-readable description */
    const char *navigate;   /* path to navigate to (NULL = stay) */
    const char *js;         /* JS to execute after load */
    const char *expect;     /* string that must appear in result */
    const char *reject;     /* string that must NOT appear (NULL=skip) */
};

/* Full test scenario — every user flow */
static const struct bot_action g_bot_script[] = {
    /* ── Dashboard ── */
    { "Dashboard loads",
      "/wallet", "document.body.innerText",
      "ZCL", "sqlite3" },
    { "Dashboard: balance visible",
      NULL, "document.querySelector('.balance')?.textContent || 'MISSING'",
      "ZCL", NULL },
    { "Dashboard: nav tabs present",
      NULL, "document.querySelectorAll('.nav a').length.toString()",
      "5", NULL },
    { "Dashboard: Send button exists",
      NULL, "document.querySelector('a[href=\"/wallet/send\"]')?.textContent || 'MISSING'",
      "Send", NULL },
    { "Dashboard: Receive button exists",
      NULL, "document.querySelector('a[href=\"/wallet/receive\"]')?.textContent || 'MISSING'",
      "Receive", NULL },
    { "Dashboard: privacy meter exists",
      NULL, "document.getElementById('privacy-meter')?.innerText || 'MISSING'",
      "private", NULL },
    { "Dashboard: no SQL leaks",
      NULL, "document.body.innerText",
      NULL, "SELECT " },

    /* ── Send ── */
    { "Send page loads",
      "/wallet/send", "document.body.innerText",
      "Spendable", "sqlite3" },
    { "Send: active tab correct",
      NULL, "document.querySelector('.nav a.active')?.textContent || 'MISSING'",
      "Send", NULL },
    { "Send: address input exists",
      NULL, "document.querySelector('input[name=\"address\"]') ? 'YES' : 'NO'",
      "YES", NULL },
    { "Send: amount input exists",
      NULL, "document.querySelector('input[name=\"amount\"]') ? 'YES' : 'NO'",
      "YES", NULL },
    { "Send: fee shown",
      NULL, "document.body.innerText",
      "0.000001", NULL },
    { "Send: JS BAL includes shielded balance",
      NULL, "typeof BAL !== 'undefined' ? (BAL > 0.001 ? 'BAL_OK_'+BAL.toFixed(4) : 'BAL_TOO_LOW_'+BAL) : 'NO_BAL'",
      "BAL_OK", NULL },
    { "Send: fill 0.001 ZCL → no 'Insufficient'",
      NULL,
      "var ai=document.querySelector('input[name=\"amount\"]');"
      "if(ai){ai.value='0.001';updateRemaining();"
      "var r=document.getElementById('remaining');"
      "r&&r.textContent.includes('Insufficient')?'INSUFFICIENT':'OK'}"
      "else 'NO_INPUT'",
      "OK", NULL },

    /* ── Receive ── */
    { "Receive page loads",
      "/wallet/receive", "document.body.innerText",
      "recommended", "sqlite3" },
    { "Receive: QR code rendered",
      NULL, "document.querySelector('svg') ? 'HAS_SVG' : 'NO_SVG'",
      "HAS_SVG", NULL },
    { "Receive: z-address shown",
      NULL, "document.body.innerText",
      "zs1", NULL },
    { "Receive: zero-knowledge described",
      NULL, "document.body.innerText",
      "zero-knowledge proof", NULL },
    { "Receive: t-addr pane has on-chain warning",
      NULL, "document.getElementById('pane-t')?.innerHTML || 'MISSING'",
      "on-chain", NULL },

    /* ── History ── */
    { "History page loads",
      "/wallet/history", "document.body.innerText",
      "History", "sqlite3" },
    { "History: active tab correct",
      NULL, "document.querySelector('.nav a.active')?.textContent || 'MISSING'",
      "History", NULL },
    { "History: no raw SQL",
      NULL, "document.body.innerText",
      NULL, "SELECT " },

    /* ── Node ── */
    { "Node page loads",
      "/wallet/node", "document.body.innerText",
      "Command Center", "sqlite3" },
    { "Node: sovereignty statement",
      NULL, "document.body.innerText",
      "sovereign", NULL },
    { "Node: block height shown",
      NULL, "document.body.innerHTML.includes('Block Height') ? 'YES' : 'NO'",
      "YES", NULL },
    { "Node: peer count shown",
      NULL, "document.body.innerHTML.includes('Connected Peers') ? 'YES' : 'NO'",
      "YES", NULL },
    { "Node: version shown",
      NULL, "document.body.innerText",
      "ZClassic23", NULL },

    /* ── Coins ── */
    { "Coins page loads",
      "/wallet/coins", "document.body.innerText",
      "Coin Audit", "sqlite3" },

    /* ── Shield ── */
    { "Shield page loads",
      "/wallet/shield", "document.body.innerText",
      "Shield", "sqlite3" },
    { "Shield: shows form or nothing-to-shield",
      NULL, "document.body.innerText.includes('Nothing to shield') ? 'ALL_SHIELDED' : "
            "(document.querySelector('.send-max') ? 'HAS_FORM' : 'UNKNOWN')",
      NULL, "UNKNOWN" },

    /* ── Send flow: fill form and submit ── */
    { "Send flow: navigate to send",
      "/wallet/send", "document.body.innerText",
      "Spendable", NULL },
    { "Send flow: check spendable shows total",
      NULL, "document.body.innerText",
      "0.97", NULL },

    /* ── Shield flow check ── */
    { "Shield: page renders correctly",
      "/wallet/shield", "document.body.innerText",
      "Shield", NULL },

    /* ── Navigate back to dashboard ── */
    { "Return to dashboard after flows",
      "/wallet", "document.body.innerText",
      "ZCL", NULL },

    /* ── End ── */
    { NULL, NULL, NULL, NULL, NULL }
};

/* JS result callback */
static void on_bot_js_result(GObject *source, GAsyncResult *res, gpointer data);
static void bot_advance(void);

static void on_bot_js_result(GObject *source, GAsyncResult *res, gpointer data)
{
    (void)data;
    const struct bot_action *act = &g_bot_script[g_bot_step];

    WebKitJavascriptResult *js_result =
        webkit_web_view_run_javascript_finish(WEBKIT_WEB_VIEW(source), res, NULL);
    if (js_result) {
        JSCValue *val = webkit_javascript_result_get_js_value(js_result);
        if (jsc_value_is_string(val)) {
            char *text = jsc_value_to_string(val);
            if (text) {
                size_t tlen = strlen(text);
                if (tlen >= sizeof(g_bot_last_text))
                    tlen = sizeof(g_bot_last_text) - 1;
                memcpy(g_bot_last_text, text, tlen);
                g_bot_last_text[tlen] = '\0';

                bool pass = true;
                char reason[256] = "";

                /* Check expect */
                if (act->expect && !strstr(text, act->expect)) {
                    pass = false;
                    snprintf(reason, sizeof(reason),
                        "expected \"%s\" not found", act->expect);
                }
                /* Check reject */
                if (act->reject && strstr(text, act->reject)) {
                    pass = false;
                    snprintf(reason, sizeof(reason),
                        "rejected \"%s\" found", act->reject);
                }

                if (pass) {
                    g_bot_pass++;
                    /* Truncate result for display */
                    char preview[80];
                    snprintf(preview, sizeof(preview), "%.75s", text);
                    printf("  OK   %-40s \"%s\"\n", act->desc, preview);
                } else {
                    g_bot_fail++;
                    printf("  FAIL %-40s %s\n", act->desc, reason);
                    /* Show what we got */
                    printf("       got: \"%.120s\"\n", text);
                }

                g_free(text);
            }
        }
        webkit_javascript_result_unref(js_result);
    }

    g_bot_step++;
    bot_advance();
}

static void on_bot_load_finished(WebKitWebView *v, WebKitLoadEvent ev, gpointer d)
{
    (void)d;
    if (!g_self_test || ev != WEBKIT_LOAD_FINISHED) return;

    const struct bot_action *act = &g_bot_script[g_bot_step];
    if (!act->desc) return;

    if (act->js) {
        webkit_web_view_run_javascript(v, act->js,
            NULL, on_bot_js_result, NULL);
    }
}

static void bot_advance(void)
{
    const struct bot_action *act = &g_bot_script[g_bot_step];

    if (!act->desc) {
        /* Done */
        printf("\n════════════════════════════════════════\n");
        printf("Bot driver: %d passed, %d failed\n",
               g_bot_pass, g_bot_fail);
        if (g_bot_fail)
            printf("SELF-TEST FAILED\n");
        else
            printf("ALL CHECKS PASSED\n");
        printf("════════════════════════════════════════\n");
        gtk_main_quit();
        return;
    }

    if (act->navigate) {
        /* Navigate and wait for load-finished to fire */
        navigate(act->navigate);
    } else {
        /* No navigation — execute JS immediately */
        if (act->js) {
            webkit_web_view_run_javascript(g_webview, act->js,
                NULL, on_bot_js_result, NULL);
        }
    }
}

gboolean start_self_test(gpointer data)
{
    (void)data;
    printf("\n=== Z23 Bot Driver ===\n");
    printf("Navigating real GTK WebKit app, reading DOM, verifying data.\n\n");

    g_signal_connect(g_webview, "load-changed",
        G_CALLBACK(on_bot_load_finished), NULL);

    g_bot_step = 0;
    bot_advance();
    return G_SOURCE_REMOVE;
}

#else
/* Without GTK + WebKit the bot driver compiles to nothing; provide a
 * declaration so this is not an (ISO-C-forbidden) empty translation unit,
 * matching the #else stub in wallet_gui.c. */
typedef int zcl_wallet_gui_bot_unused;
#endif /* HAVE_WEBKIT && HAVE_GTK */
