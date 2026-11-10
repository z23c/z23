/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Bind explicit user-entered catalog URLs to one onion and offer. */
#include "command/native_app_network_link.h"
#include "vcs/app_offer.h"
#include <string.h>

bool app_network_link_parse(const char *text, struct app_network_link *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!text) return false;
    static const char prefix[] = "http://";
    static const char path[] = "/board/apps/v1";
    size_t n = strnlen(text, 257u);
    const size_t base = sizeof(prefix) - 1u + 62u + sizeof(path) - 1u;
    if ((n != base && n != base + 65u) || strncmp(text, prefix, sizeof(prefix) - 1u)) return false;
    char onion[63]; memcpy(onion, text + sizeof(prefix) - 1u, 62u); onion[62] = 0;
    if (!vcs_app_offer_peer_is_onion(onion) ||
        strncmp(text + sizeof(prefix) - 1u + 62u, path, sizeof(path) - 1u)) return false;
    if (n != base) {
        if (text[base] != '/' || !vcs_app_offer_hex_valid(text + base + 1u, 32)) return false;
        memcpy(out->post_id, text + base + 1u, 65u); out->exact = true;
    }
    memcpy(out->onion, onion, sizeof(onion)); return true;
}
