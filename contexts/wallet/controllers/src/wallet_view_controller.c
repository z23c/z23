/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet view router — dispatches URL paths to page handlers.
 * Each page handler lives in its own file (wallet_view_*.c). */

#include "controllers/wallet_view_internal.h"
#include "util/log_macros.h"

/* Copy a query-string value: stop at NUL, '&' or the buffer limit. */
static void copy_query_value(const char *src, char *dst, size_t limit)
{
    size_t i = 0;
    while (src[i] && src[i] != '&' && i < limit)
        { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

/* "/wallet/history" — parse page/filter/search query, then serve. */
static bool serve_history_route(const char *path, uint8_t *response,
                                size_t response_max, size_t *out_len)
{
    if (strncmp(path, "/wallet/history", 15) != 0) return false;
    int page = 0;
    const char *pq = strstr(path, "page=");
    if (pq) page = atoi(pq + 5);
    if (page < 0) page = 0;
    const char *filt = NULL;
    char filt_buf[16] = "";
    const char *fp = strstr(path, "filter=");
    if (fp) {
        copy_query_value(fp + 7, filt_buf, 15);
        filt = filt_buf;
    }
    const char *srch = NULL;
    char srch_buf[65] = "";
    const char *sp = strstr(path, "q=");
    if (sp) {
        copy_query_value(sp + 2, srch_buf, 64);
        srch = srch_buf;
    }
    *out_len = serve_history(response, response_max, page, filt, srch);
    return true;
}

/* Send and shield flow pages. */
static bool route_send_pages(const char *path, const uint8_t *body,
                             size_t body_len, uint8_t *response,
                             size_t response_max, size_t *out_len)
{
    if (strcmp(path, "/wallet/send") == 0) {
        *out_len = serve_send(response, response_max);
        return true;
    }
    if (strcmp(path, "/wallet/send/review") == 0) {
        *out_len = serve_send_review(response, response_max, body, body_len);
        return true;
    }
    if (strcmp(path, "/wallet/send/confirm") == 0) {
        *out_len = serve_send_confirm(response, response_max, body, body_len);
        return true;
    }
    if (strncmp(path, "/wallet/shield/confirm", 22) == 0) {
        *out_len = serve_shield_confirm(response, response_max, body, body_len);
        return true;
    }
    if (strncmp(path, "/wallet/shield", 14) == 0) {
        const char *q = strchr(path, '?');
        *out_len = serve_shield(response, response_max, q);
        return true;
    }
    return false;
}

/* Read-only info pages: receive, history, coins, node, tx detail. */
static bool route_info_pages(const char *path, uint8_t *response,
                             size_t response_max, size_t *out_len)
{
    if (strcmp(path, "/wallet/receive") == 0) {
        *out_len = serve_receive(response, response_max);
        return true;
    }
    if (serve_history_route(path, response, response_max, out_len))
        return true;
    if (strcmp(path, "/wallet/coins") == 0) {
        *out_len = serve_coins(response, response_max);
        return true;
    }
    if (strcmp(path, "/wallet/node") == 0) {
        *out_len = serve_node(response, response_max);
        return true;
    }
    if (strncmp(path, "/wallet/tx/", 11) == 0) {
        const char *txid = path + 11;
        *out_len = serve_tx_detail(response, response_max, txid);
        return true;
    }
    return false;
}

size_t wallet_view_handle_request(const char *method, const char *path,
                                  const uint8_t *body, size_t body_len,
                                  uint8_t *response, size_t response_max)
{
    (void)method;
    if (!path || !response || response_max == 0) return 0;

    /* JSON pulse endpoint — polled every 5s by dashboard JS */
    if (strcmp(path, "/api/wallet/pulse") == 0)
        return serve_pulse(response, response_max);

    if (strcmp(path, "/wallet") == 0 || strcmp(path, "/wallet/") == 0)
        return serve_dashboard(response, response_max);

    size_t len = 0;
    if (route_send_pages(path, body, body_len, response, response_max, &len))
        return len;
    if (route_info_pages(path, response, response_max, &len))
        return len;

    return 0;
}
