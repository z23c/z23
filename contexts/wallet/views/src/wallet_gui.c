/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Z23 GUI — WebKit browser with Wallet, Explorer, Store.
 * Launches as the default mode when z23 is run with no arguments.
 * All routing is in-process C function calls — zero network latency. */

#if defined(HAVE_WEBKIT) && defined(HAVE_GTK)

#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "platform/time_compat.h"
#include "models/database.h"
#include "controllers/explorer_controller.h"
#include "controllers/wallet_view_controller.h"
#include "chain/chainparams.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "rpc/zclassicd_port.h"

extern size_t explorer_handle_request(const char *, const char *,
    const uint8_t *, size_t, uint8_t *, size_t);
extern size_t onion_service_handle_request(const char *, const char *,
    const uint8_t *, size_t, uint8_t *, size_t);
extern const char *onion_service_start(const char *);
extern void explorer_set_rpc(const char *, const char *, int);

#include "views/wallet_gui_internal.h"

/* g_webview + g_self_test have external linkage so wallet_gui_bot.c can share
 * them; g_bot_fail is defined there and read by this file's exit code. */
WebKitWebView *g_webview = NULL;
bool g_self_test = false;
static GtkWidget *g_url_bar = NULL;
static GtkWidget *g_nav_buttons[5];
static GtkWidget *g_status_label = NULL;
static uint8_t g_response[1 << 20];

/* ── GTK Dark Theme CSS ───────────────────────────────────── */

static const char *GTK_DARK_CSS =
    "window { background-color: #0c0c0c; }"
    "box { background-color: #0c0c0c; }"
    "#toolbar {"
    "  background: #111;"
    "  border-bottom: 1px solid #1a1a1a;"
    "  padding: 4px 8px;"
    "}"
    "#nav-btn {"
    "  background: transparent;"
    "  border: 1px solid transparent;"
    "  border-radius: 6px;"
    "  color: #888;"
    "  font-size: 13px;"
    "  font-weight: 600;"
    "  padding: 4px 14px;"
    "  min-height: 28px;"
    "  margin: 0 1px;"
    "}"
    "#nav-btn:hover {"
    "  background: #1a1a1a;"
    "  color: #ccc;"
    "  border-color: #333;"
    "}"
    "#nav-btn.active {"
    "  background: #0a1f0a;"
    "  color: #33ff99;"
    "  border-color: #1a3a1a;"
    "}"
    "#arrow-btn {"
    "  background: transparent;"
    "  border: none;"
    "  color: #555;"
    "  font-size: 16px;"
    "  padding: 4px 8px;"
    "  min-height: 28px;"
    "  min-width: 28px;"
    "}"
    "#arrow-btn:hover { color: #33ff99; }"
    "#arrow-btn:disabled { color: #2a2a2a; }"
    "#url-bar {"
    "  background: #0a0a0a;"
    "  border: 1px solid #222;"
    "  border-radius: 6px;"
    "  color: #ccc;"
    "  font-family: 'SF Mono', 'Fira Code', monospace;"
    "  font-size: 13px;"
    "  padding: 4px 12px;"
    "  min-height: 28px;"
    "  caret-color: #33ff99;"
    "}"
    "#url-bar:focus { border-color: #33ff99; background: #0c0c0c; }"
    "#status-bar {"
    "  background: #0a0a0a;"
    "  border-top: 1px solid #1a1a1a;"
    "  padding: 2px 12px;"
    "  min-height: 20px;"
    "}"
    "#status-label {"
    "  color: #444;"
    "  font-size: 11px;"
    "  font-family: 'SF Mono', monospace;"
    "}";

/* ── URI scheme handler ───────────────────────────────────── */

static void on_uri_scheme_request(WebKitURISchemeRequest *request,
                                    gpointer user_data)
{
    (void)user_data;
    const char *uri = webkit_uri_scheme_request_get_uri(request);
    const char *path = "/wallet";
    if (uri) {
        const char *after = strstr(uri, "://");
        if (after) {
            after += 3;
            const char *slash = strchr(after, '/');
            if (slash) path = slash;
        }
    }

    const char *http_method = webkit_uri_scheme_request_get_http_method(request);
    if (!http_method) http_method = "GET";

    uint8_t post_body[4096];
    size_t post_body_len = 0;
    if (strcmp(http_method, "POST") == 0) {
        GInputStream *body_stream = webkit_uri_scheme_request_get_http_body(request);
        if (body_stream) {
            gsize bytes_read = 0;
            g_input_stream_read_all(body_stream, post_body, sizeof(post_body) - 1,
                                    &bytes_read, NULL, NULL);
            post_body[bytes_read] = '\0';
            post_body_len = (size_t)bytes_read;
        }
    }

    int64_t t0 = platform_time_monotonic_us();

    size_t len = 0;
    if (strncmp(path, "/wallet", 7) == 0 ||
        strncmp(path, "/api/wallet/", 12) == 0)
        len = wallet_view_handle_request(http_method, path,
                                          post_body_len ? post_body : NULL,
                                          post_body_len,
                                          g_response, sizeof(g_response));
    else if (strncmp(path, "/explorer", 9) == 0 ||
             strncmp(path, "/api/", 5) == 0 ||
             strstr(path, "style.css") || strstr(path, "favicon"))
        len = explorer_handle_request(http_method, path,
                                       post_body_len ? post_body : NULL,
                                       post_body_len,
                                       g_response, sizeof(g_response));
    if (len == 0)
        len = onion_service_handle_request(http_method, path,
                                            post_body_len ? post_body : NULL,
                                            post_body_len,
                                            g_response, sizeof(g_response));

    int64_t t1 = platform_time_monotonic_us();
    long ms = (long)((t1 - t0) / 1000LL);
    if (g_status_label) {
        char status[128];
        snprintf(status, sizeof(status), "%s  %ldms  %zu bytes", path, ms, len);
        gtk_label_set_text(GTK_LABEL(g_status_label), status);
    }

    if (len == 0) {
        const char *html =
            "<html><body style='background:#0c0c0c;color:#e8e8e8;"
            "font-family:-apple-system,monospace;padding:60px;"
            "text-align:center'>"
            "<div style='font-size:72px;color:#222;margin-bottom:16px'>"
            "&#x2717;</div>"
            "<h2 style='color:#666;font-weight:400'>Page not found</h2>"
            "<p style='margin-top:24px'>"
            "<a href='/wallet' style='color:#33ff99;text-decoration:none;"
            "padding:8px 24px;border:1px solid #33ff99;border-radius:6px'>"
            "Open Wallet</a></p></body></html>";
        GInputStream *s = g_memory_input_stream_new_from_data(
            g_strdup(html), (gssize)strlen(html), g_free);
        webkit_uri_scheme_request_finish(request, s,
            (gint64)strlen(html), "text/html");
        g_object_unref(s);
        return;
    }

    /* Parse HTTP headers without corrupting binary body data */
    const uint8_t *body = g_response;
    size_t blen = len;
    const char *ctype = "text/html; charset=utf-8";

    /* Find header/body boundary — search only the first 4KB for \r\n\r\n */
    size_t search_limit = len < 4096 ? len : 4096;
    const char *hdr_end = NULL;
    for (size_t i = 0; i + 3 < search_limit; i++) {
        if (g_response[i] == '\r' && g_response[i+1] == '\n' &&
            g_response[i+2] == '\r' && g_response[i+3] == '\n') {
            hdr_end = (const char *)&g_response[i];
            break;
        }
    }
    if (hdr_end) {
        /* Extract Content-Type from headers */
        size_t hdr_size = (size_t)(hdr_end - (const char *)g_response);
        g_response[hdr_size] = '\0'; /* NUL-terminate headers only */
        const char *ct = strstr((char *)g_response, "Content-Type: ");
        if (ct) {
            ct += 14;
            static char ct_buf[128];
            size_t i = 0;
            while (ct[i] && ct[i] != '\r' && ct[i] != '\n' && i < 127)
                { ct_buf[i] = ct[i]; i++; }
            ct_buf[i] = '\0';
            ctype = ct_buf;
        }
        body = (const uint8_t *)(hdr_end + 4);
        blen = len - (size_t)(body - g_response);
    }

    /* Copy body — g_memdup2 handles binary data (no strlen truncation) */
    char *body_copy = g_malloc(blen);
    if (!body_copy && blen > 0) {
        /* Allocation failed for a non-empty body: never hand GLib a NULL
         * pointer with non-zero length (undefined behaviour). Return the
         * not-found page the same way as above instead. */
        const char *html =
            "<html><body style='background:#0c0c0c;color:#e8e8e8;"
            "font-family:-apple-system,monospace;padding:60px;"
            "text-align:center'>"
            "<h2 style='color:#666;font-weight:400'>Out of memory</h2>"
            "</body></html>";
        GInputStream *s = g_memory_input_stream_new_from_data(
            g_strdup(html), (gssize)strlen(html), g_free);
        webkit_uri_scheme_request_finish(request, s,
            (gint64)strlen(html), "text/html");
        g_object_unref(s);
        return;
    }
    if (body_copy) memcpy(body_copy, body, blen);
    GInputStream *stream = g_memory_input_stream_new_from_data(
        body_copy, (gssize)blen, g_free);
    webkit_uri_scheme_request_finish(request, stream, (gint64)blen, ctype);
    g_object_unref(stream);
}

/* ── Navigation ───────────────────────────────────────────── */

void navigate(const char *path) {
    if (!path || !path[0]) path = "/wallet";
    char uri[512];
    snprintf(uri, sizeof(uri), "zcl://node%s", path);
    webkit_web_view_load_uri(g_webview, uri);
    const char *sections[] = {"", "", "wallet", "explorer", "store"};
    const char *sec = "wallet";
    if (strncmp(path, "/explorer", 9) == 0) sec = "explorer";
    else if (strncmp(path, "/store", 6) == 0) sec = "store";
    for (int i = 2; i < 5; i++) {
        GtkStyleContext *sc = gtk_widget_get_style_context(g_nav_buttons[i]);
        if (strcmp(sections[i], sec) == 0)
            gtk_style_context_add_class(sc, "active");
        else
            gtk_style_context_remove_class(sc, "active");
    }
}

static gboolean on_decide_policy(WebKitWebView *v, WebKitPolicyDecision *dec,
                                   WebKitPolicyDecisionType type, gpointer d)
{
    (void)v; (void)d;
    if (type == WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION) {
        WebKitNavigationPolicyDecision *nav =
            WEBKIT_NAVIGATION_POLICY_DECISION(dec);
        WebKitNavigationAction *action =
            webkit_navigation_policy_decision_get_navigation_action(nav);
        WebKitURIRequest *req = webkit_navigation_action_get_request(action);
        const char *uri = webkit_uri_request_get_uri(req);
        if (uri && (strncmp(uri, "http://", 7) == 0 ||
                    strncmp(uri, "https://", 8) == 0)) {
            const char *after = strstr(uri, "://");
            if (after) {
                after += 3;
                const char *slash = strchr(after, '/');
                webkit_policy_decision_ignore(dec);
                navigate(slash ? slash : "/wallet");
                return TRUE;
            }
        }
    }
    webkit_policy_decision_use(dec);
    return TRUE;
}

static void on_load_changed(WebKitWebView *v, WebKitLoadEvent ev, gpointer d)
{
    (void)d;
    if (ev == WEBKIT_LOAD_COMMITTED) {
        const char *uri = webkit_web_view_get_uri(v);
        if (uri && g_url_bar) {
            const char *after = strstr(uri, "://");
            if (after) {
                after += 3;
                const char *slash = strchr(after, '/');
                if (slash)
                    gtk_entry_set_text(GTK_ENTRY(g_url_bar), slash);
            }
        }
    }
}

static void on_back(GtkWidget *b, gpointer d) {
    (void)b;(void)d;
    if (webkit_web_view_can_go_back(g_webview)) webkit_web_view_go_back(g_webview);
}
static void on_fwd(GtkWidget *b, gpointer d) {
    (void)b;(void)d;
    if (webkit_web_view_can_go_forward(g_webview)) webkit_web_view_go_forward(g_webview);
}
static void on_wallet(GtkWidget *b, gpointer d)
    { (void)b;(void)d; navigate("/wallet"); }
static void on_explorer(GtkWidget *b, gpointer d)
    { (void)b;(void)d; navigate("/explorer"); }
static void on_store(GtkWidget *b, gpointer d)
    { (void)b;(void)d; navigate("/store"); }

static void on_url_activate(GtkEntry *e, gpointer d) {
    (void)d;
    const char *text = gtk_entry_get_text(e);
    if (!text || !text[0]) return;
    if (text[0] == '/') navigate(text);
    else {
        char path[512];
        snprintf(path, sizeof(path), "/explorer/search?q=%s", text);
        navigate(path);
    }
}

static gboolean on_key_press(GtkWidget *w, GdkEventKey *ev, gpointer d)
{
    (void)w; (void)d;
    if (ev->state & GDK_CONTROL_MASK) {
        switch (ev->keyval) {
        case GDK_KEY_l: case GDK_KEY_L:
            gtk_widget_grab_focus(g_url_bar);
            gtk_editable_select_region(GTK_EDITABLE(g_url_bar), 0, -1);
            return TRUE;
        case GDK_KEY_1: navigate("/wallet"); return TRUE;
        case GDK_KEY_2: navigate("/explorer"); return TRUE;
        case GDK_KEY_3: navigate("/store"); return TRUE;
        case GDK_KEY_r: case GDK_KEY_R:
            webkit_web_view_reload(g_webview); return TRUE;
        case GDK_KEY_Left:
            if (webkit_web_view_can_go_back(g_webview))
                webkit_web_view_go_back(g_webview);
            return TRUE;
        case GDK_KEY_Right:
            if (webkit_web_view_can_go_forward(g_webview))
                webkit_web_view_go_forward(g_webview);
            return TRUE;
        }
    }
    if (ev->keyval == GDK_KEY_F5) {
        webkit_web_view_reload(g_webview); return TRUE;
    }
    return FALSE;
}

/* ── Init controllers ─────────────────────────────────────── */

static void init_controllers(const char *datadir) {
    static struct node_db ndb;
    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    if (!node_db_open_runtime(&ndb, db_path, "wallet_gui.init")) {
        if (sqlite3_open_v2(db_path, &ndb.db,
                SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK) {
            ndb.open = true;
            sqlite3_busy_timeout(ndb.db, 5000);
        }
    }
    if (ndb.open) {
        explorer_set_state(NULL, NULL, NULL, &ndb, datadir);
        char cookie_path[1024], cookie[256] = "";
        snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", datadir);
        FILE *f = fopen(cookie_path, "r");
        if (f) {
            if (fgets(cookie, sizeof(cookie), f)) {
                char *nl = strchr(cookie, '\n'); if (nl) *nl = '\0';
                char *col = strchr(cookie, ':');
                if (col) {
                    *col = '\0';
                    explorer_set_rpc(cookie, col + 1,
                                     ZCLASSICD_RPC_DEFAULT_PORT);
                }
            }
            fclose(f);
        }
    }
    wallet_view_init(datadir);
    wallet_view_enable_sync();
    onion_service_start(datadir);
}

/* ── Main entry ───────────────────────────────────────────── */

static GtkWidget *make_btn(const char *label, const char *name, GCallback cb) {
    GtkWidget *btn = gtk_button_new_with_label(label);
    gtk_widget_set_name(btn, name);
    g_signal_connect(btn, "clicked", cb, NULL);
    gtk_widget_set_can_focus(btn, FALSE);
    return btn;
}

int wallet_gui_main(int argc, char **argv, const char *datadir)
{
    /* Check for --self-test flag */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--self-test") == 0)
            g_self_test = true;
    }

    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr, "Cannot open display (DISPLAY=%s).\n"
                "For headless testing: xvfb-run build/bin/z23 --self-test\n",
            getenv("DISPLAY") ? getenv("DISPLAY") : "unset");
        return 1;
    }

    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();
    init_controllers(datadir);

    /* Dark theme */
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, GTK_DARK_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
    g_object_set(gtk_settings_get_default(),
        "gtk-application-prefer-dark-theme", TRUE, NULL);

    /* Register zcl:// scheme */
    WebKitWebContext *ctx = webkit_web_context_get_default();
    webkit_web_context_register_uri_scheme(ctx, "zcl",
        on_uri_scheme_request, NULL, NULL);
    WebKitSecurityManager *sec = webkit_web_context_get_security_manager(ctx);
    webkit_security_manager_register_uri_scheme_as_local(sec, "zcl");
    webkit_security_manager_register_uri_scheme_as_cors_enabled(sec, "zcl");

    /* Window */
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "Z23");
    gtk_window_set_default_size(GTK_WINDOW(win), 1100, 820);
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(win, "key-press-event", G_CALLBACK(on_key_press), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* Toolbar */
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_name(toolbar, "toolbar");

    g_nav_buttons[0] = make_btn("\xe2\x97\x80", "arrow-btn", G_CALLBACK(on_back));
    g_nav_buttons[1] = make_btn("\xe2\x96\xb6", "arrow-btn", G_CALLBACK(on_fwd));
    gtk_box_pack_start(GTK_BOX(toolbar), g_nav_buttons[0], FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(toolbar), g_nav_buttons[1], FALSE, FALSE, 0);

    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
    gtk_box_pack_start(GTK_BOX(toolbar), sep, FALSE, FALSE, 4);

    g_nav_buttons[2] = make_btn("Wallet", "nav-btn", G_CALLBACK(on_wallet));
    g_nav_buttons[3] = make_btn("Explorer", "nav-btn", G_CALLBACK(on_explorer));
    g_nav_buttons[4] = make_btn("Store", "nav-btn", G_CALLBACK(on_store));
    for (int i = 2; i < 5; i++)
        gtk_box_pack_start(GTK_BOX(toolbar), g_nav_buttons[i], FALSE, FALSE, 0);

    g_url_bar = gtk_entry_new();
    gtk_widget_set_name(g_url_bar, "url-bar");
    gtk_entry_set_placeholder_text(GTK_ENTRY(g_url_bar),
        "Search blocks, txs, addresses...   (Ctrl+L)");
    g_signal_connect(g_url_bar, "activate", G_CALLBACK(on_url_activate), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_url_bar, TRUE, TRUE, 4);
    gtk_box_pack_start(GTK_BOX(vbox), toolbar, FALSE, FALSE, 0);

    /* WebView */
    WebKitSettings *settings = webkit_settings_new();
    webkit_settings_set_enable_smooth_scrolling(settings, TRUE);
    webkit_settings_set_enable_developer_extras(settings, FALSE);
    webkit_settings_set_enable_java(settings, FALSE);
    webkit_settings_set_enable_plugins(settings, FALSE);
    webkit_settings_set_hardware_acceleration_policy(settings,
        WEBKIT_HARDWARE_ACCELERATION_POLICY_ALWAYS);
    webkit_settings_set_default_font_family(settings,
        "SF Pro Display, -apple-system, Segoe UI, Roboto, sans-serif");
    webkit_settings_set_monospace_font_family(settings,
        "SF Mono, Fira Code, JetBrains Mono, monospace");
    webkit_settings_set_default_font_size(settings, 16);
    webkit_settings_set_default_monospace_font_size(settings, 13);

    g_webview = WEBKIT_WEB_VIEW(
        g_object_new(WEBKIT_TYPE_WEB_VIEW, "settings", settings, NULL));
    g_object_unref(settings);
    GdkRGBA bg = { 0.047, 0.047, 0.047, 1.0 };
    webkit_web_view_set_background_color(g_webview, &bg);
    g_signal_connect(g_webview, "decide-policy",
        G_CALLBACK(on_decide_policy), NULL);
    g_signal_connect(g_webview, "load-changed",
        G_CALLBACK(on_load_changed), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), GTK_WIDGET(g_webview), TRUE, TRUE, 0);

    /* Status bar */
    GtkWidget *status_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_name(status_bar, "status-bar");
    g_status_label = gtk_label_new("Ready");
    gtk_widget_set_name(g_status_label, "status-label");
    gtk_label_set_xalign(GTK_LABEL(g_status_label), 0.0);
    gtk_box_pack_start(GTK_BOX(status_bar), g_status_label, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), status_bar, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(win), vbox);
    navigate("/wallet");
    gtk_widget_show_all(win);

    if (g_self_test)
        g_idle_add(start_self_test, NULL);

    gtk_main();
    return g_self_test ? (g_bot_fail > 0 ? 1 : 0) : 0;
}

#elif defined(HAVE_GTK)
/* GTK available but no WebKit — fall back to simple message */
#include <gtk/gtk.h>
#include <stdio.h>
int wallet_gui_main(int argc, char **argv, const char *datadir)
{
    (void)datadir;
    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr, "Cannot open display.\n");
        return 1;
    }
    GtkWidget *d = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_INFO,
        GTK_BUTTONS_OK,
        "Z23 GUI requires WebKit2GTK.\n"
        "Install: pacman -S webkit2gtk-4.1\n\n"
        "Run as node: build/bin/z23 -datadir=~/.zclassic-c23");
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    return 1;
}
#else
#include <stdio.h>
int wallet_gui_main(int argc, char **argv, const char *datadir)
{
    (void)argc; (void)argv; (void)datadir;
    fprintf(stderr, "GUI not available — built without GTK3 + WebKit2.\n"
            "Run as node: build/bin/z23 -datadir=~/.zclassic-c23\n");
    return 1;
}
#endif
