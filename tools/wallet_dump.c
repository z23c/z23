/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_dump — render every wallet page and dump as readable text.
 *
 * Connects to the REAL zclassicd on port 8232, syncs wallet data,
 * then renders every route and strips HTML to show exactly what
 * the user would see.
 *
 * Usage:
 *   make wallet_dump && build/bin/wallet_dump [datadir]
 *
 * Default datadir: ~/.zclassic-c23
 *
 * This tool is the "eyes" for development — run it before any
 * release to see every page as the user sees it. */

#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"
#include "chain/chainparams.h"
#include "keys/key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>

volatile sig_atomic_t g_shutdown_requested = 0;

static uint8_t buf[131072];

/* Track <style> and <script> open/close tags */
static void mark_style_script_state(const uint8_t *html, size_t i, size_t len,
                                    bool *in_style, bool *in_script) {
    if (i + 7 < len && strncmp((char*)html+i, "<style", 6) == 0)
        *in_style = true;
    if (i + 8 < len && strncmp((char*)html+i, "</style", 7) == 0)
        *in_style = false;
    if (i + 8 < len && strncmp((char*)html+i, "<script", 7) == 0)
        *in_script = true;
    if (i + 9 < len && strncmp((char*)html+i, "</script", 8) == 0)
        *in_script = false;
}

/* Decode common HTML entities */
static void decode_html_entity(const uint8_t *html, size_t len,
                               size_t *pos, char *c) {
    size_t i = *pos;
    if (*c == '&' && i + 1 < len) {
        if (strncmp((char*)html+i, "&amp;", 5) == 0) { *c = '&'; *pos += 4; }
        else if (strncmp((char*)html+i, "&lt;", 4) == 0) { *c = '<'; *pos += 3; }
        else if (strncmp((char*)html+i, "&gt;", 4) == 0) { *c = '>'; *pos += 3; }
        else if (strncmp((char*)html+i, "&middot;", 8) == 0) { *c = '.'; *pos += 7; }
        else if (strncmp((char*)html+i, "&mdash;", 7) == 0) { *c = '-'; *pos += 6; }
        else if (strncmp((char*)html+i, "&#x", 3) == 0) {
            /* Skip numeric entity */
            const char *semi = strchr((char*)html+i, ';');
            if (semi && semi - (char*)html - (long)i < 12) {
                *pos = (size_t)(semi - (char*)html);
                *c = ' ';
            }
        }
    }
}

/* Strip HTML tags and collapse whitespace → readable text */
static void dump_text(const uint8_t *html, size_t len) {
    bool in_tag = false;
    bool in_style = false;
    bool in_script = false;
    bool last_was_space = false;
    int col = 0;

    for (size_t i = 0; i < len; i++) {
        char c = (char)html[i];

        /* Detect <style> and <script> blocks */
        if (c == '<') {
            mark_style_script_state(html, i, len, &in_style, &in_script);
            in_tag = true;
            continue;
        }
        if (c == '>') { in_tag = false; continue; }
        if (in_tag || in_style || in_script) continue;

        /* Decode common HTML entities */
        decode_html_entity(html, len, &i, &c);

        /* Collapse whitespace */
        if (isspace((unsigned char)c)) {
            if (!last_was_space) { putchar(' '); col++; }
            last_was_space = true;
            continue;
        }
        last_was_space = false;

        /* Wrap at ~76 chars */
        if (col > 76 && c == ' ') {
            putchar('\n');
            col = 0;
            continue;
        }

        putchar(c);
        col++;
    }
    putchar('\n');
}

static void render_page(const char *method, const char *path,
                         const char *body) {
    memset(buf, 0, sizeof(buf));
    size_t n = wallet_view_handle_request(method, path,
        body ? (const uint8_t *)body : NULL,
        body ? strlen(body) : 0,
        buf, sizeof(buf));

    printf("\n");
    for (int i = 0; i < 72; i++) putchar('=');
    printf("\n%s %s", method, path);
    if (body && body[0]) printf("  [body: %s]", body);
    printf("  (%zu bytes)\n", n);
    for (int i = 0; i < 72; i++) putchar('-');
    printf("\n");

    if (n == 0) {
        printf("(no response — unknown route or error)\n");
        return;
    }

    /* Check for JSON response (pulse API) */
    const char *body_start = strstr((char *)buf, "\r\n\r\n");
    if (!body_start) body_start = (char *)buf;
    else body_start += 4;

    if (body_start[0] == '{') {
        /* JSON — print raw */
        printf("%s\n", body_start);
    } else {
        /* HTML — strip to text */
        dump_text((const uint8_t *)body_start,
                  n - (size_t)(body_start - (char *)buf));
    }
}

int main(int argc, char **argv)
{
    const char *datadir = NULL;
    if (argc > 1) {
        datadir = argv[1];
    } else {
        static char dd[512];
        const char *home = getenv("HOME");
        if (home) {
            snprintf(dd, sizeof(dd), "%s/.zclassic-c23", home);
            datadir = dd;
        }
    }

    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();

    printf("wallet_dump: datadir = %s\n", datadir ? datadir : "(none)");
    printf("Syncing wallet from zclassicd...\n");

    wallet_view_enable_sync();
    wallet_view_init(datadir);
    wv_sync_wallet_from_zclassicd();

    printf("Done. Rendering all pages:\n");

    /* ── Every page a user can visit ── */

    render_page("GET", "/wallet", NULL);
    render_page("GET", "/wallet/send", NULL);
    render_page("GET", "/wallet/receive", NULL);
    render_page("GET", "/wallet/history", NULL);
    render_page("GET", "/wallet/history?page=1", NULL);
    render_page("GET", "/wallet/history?filter=sent", NULL);
    render_page("GET", "/wallet/node", NULL);
    render_page("GET", "/wallet/coins", NULL);
    render_page("GET", "/wallet/shield", NULL);
    render_page("GET", "/wallet/shield?amount=0.5", NULL);
    render_page("GET", "/api/wallet/pulse", NULL);

    /* ── Error paths ── */
    render_page("POST", "/wallet/send/review",
                "address=bad&amount=1.0");
    render_page("POST", "/wallet/send/review",
                "address=t1ExampleAddr123456789012345&amount=999");
    render_page("POST", "/wallet/send/review", "");
    render_page("POST", "/wallet/shield/confirm", "amount=0");

    printf("\n");
    for (int i = 0; i < 72; i++) putchar('=');
    printf("\nDone. %d pages rendered.\n", 15);

    ecc_verify_destroy();
    ecc_stop();
    return 0;
}
