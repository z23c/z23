/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Bind explicit user-entered catalog URLs and bare onion endpoints
 * to one onion, optional port and offer. */
#include "command/native_app_network_link.h"
#include "vcs/app_offer.h"
#include <string.h>

/* One bare endpoint token: a 62-char v3 onion hostname, optionally followed
 * by ":port" (1..65535). The signed offer id can never appear here. */
static bool app_network_link_peer(const char *text, size_t n,
                                  struct app_network_link *out)
{
    if (n < 62u || n > 68u || !vcs_app_offer_peer_is_onion(text)) return false;
    memcpy(out->onion, text, 62u);
    if (n == 62u) return true;
    unsigned port = 0;
    for (size_t i = 63u; i < n; i++) {
        if (text[i] < '0' || text[i] > '9') return false;
        port = port * 10u + (unsigned)(text[i] - '0');
        if (port > 65535u) return false;
    }
    if (!port) return false;
    out->port = port;
    return true;
}

bool app_network_link_parse(const char *text, struct app_network_link *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!text) return false;
    static const char prefix[] = "http://";
    static const char path[] = "/board/apps/v1";
    size_t n = strnlen(text, 257u);
    const size_t base = sizeof(prefix) - 1u + 62u + sizeof(path) - 1u;
    bool url = (n == base || n == base + 65u) &&
        !strncmp(text, prefix, sizeof(prefix) - 1u);
    /* A bare v3 onion (optionally host:port) names the whole room; only the
     * exact canonical URL form can carry the offer id. */
    if (!url) return app_network_link_peer(text, n, out);
    char onion[63]; memcpy(onion, text + sizeof(prefix) - 1u, 62u); onion[62] = 0;
    if (!vcs_app_offer_peer_is_onion(onion) ||
        strncmp(text + sizeof(prefix) - 1u + 62u, path, sizeof(path) - 1u)) return false;
    if (n != base) {
        if (text[base] != '/' || !vcs_app_offer_hex_valid(text + base + 1u, 32)) return false;
        memcpy(out->post_id, text + base + 1u, 65u); out->exact = true;
    }
    memcpy(out->onion, onion, sizeof(onion)); return true;
}
