/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "node_notice.h"
#include <stdio.h>
#include <string.h>

bool zapp_node_notice_due(struct zapp_node_notice *n, const char *line, int64_t now, char *text, size_t cap)
{
    const char *chosen = line && line[0] ? line : ZAPP_NOTICE_NEUTRAL;
    if (!n || !text || !cap) return false;
    if (n->posted && (!strcmp(n->text, chosen) || now - n->posted_at < ZAPP_NOTICE_INTERVAL_SECS)) return false;
    snprintf(text, cap, "%s", chosen);
    snprintf(n->text, sizeof(n->text), "%s", chosen);
    n->posted = true;
    n->posted_at = now;
    return true;
}
