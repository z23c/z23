/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet view router — dispatches URL paths to page handlers.
 * Each page handler lives in its own file (wallet_view_*.c). */

#include "controllers/wallet_view_internal.h"
#include "util/log_macros.h"

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
    if (strcmp(path, "/wallet/send") == 0)
        return serve_send(response, response_max);
    if (strcmp(path, "/wallet/send/review") == 0)
        return serve_send_review(response, response_max, body, body_len);
    if (strcmp(path, "/wallet/send/confirm") == 0)
        return serve_send_confirm(response, response_max, body, body_len);
    if (strncmp(path, "/wallet/shield/confirm", 22) == 0)
        return serve_shield_confirm(response, response_max, body, body_len);
    if (strncmp(path, "/wallet/shield", 14) == 0) {
        const char *q = strchr(path, '?');
        return serve_shield(response, response_max, q);
    }
    if (strcmp(path, "/wallet/receive") == 0)
        return serve_receive(response, response_max);
    if (strncmp(path, "/wallet/history", 15) == 0) {
        int page = 0;
        const char *pq = strstr(path, "page=");
        if (pq) page = atoi(pq + 5);
        if (page < 0) page = 0;
        const char *filt = NULL;
        char filt_buf[16] = "";
        const char *fp = strstr(path, "filter=");
        if (fp) {
            fp += 7;
            size_t fi = 0;
            while (fp[fi] && fp[fi] != '&' && fi < 15)
                { filt_buf[fi] = fp[fi]; fi++; }
            filt_buf[fi] = '\0';
            filt = filt_buf;
        }
        const char *srch = NULL;
        char srch_buf[65] = "";
        const char *sp = strstr(path, "q=");
        if (sp) {
            sp += 2;
            size_t si = 0;
            while (sp[si] && sp[si] != '&' && si < 64)
                { srch_buf[si] = sp[si]; si++; }
            srch_buf[si] = '\0';
            srch = srch_buf;
        }
        return serve_history(response, response_max, page, filt, srch);
    }
    if (strcmp(path, "/wallet/coins") == 0)
        return serve_coins(response, response_max);
    if (strcmp(path, "/wallet/node") == 0)
        return serve_node(response, response_max);
    if (strncmp(path, "/wallet/tx/", 11) == 0) {
        const char *txid = path + 11;
        return serve_tx_detail(response, response_max, txid);
    }

    return 0;
}
