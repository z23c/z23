/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "util/path_check.h"

#include <stdio.h>
#include <string.h>

static bool has_no_control_chars(const char *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c < 0x20 || c == 0x7F)
            return false;
    }
    return true;
}

bool path_check_fs_arg(const char *p, size_t max_len)
{
    if (!p) return false;
    size_t n = strnlen(p, max_len + 1);
    if (n == 0 || n > max_len) return false;
    return has_no_control_chars(p, n);
}

bool path_check_url_arg(const char *p, size_t max_len)
{
    if (!path_check_fs_arg(p, max_len)) return false;
    if (p[0] != '/') return false;
    /* Reject ".." as a path segment. We do a literal scan rather than
     * full normalization — the onion service router doesn't normalize
     * input, so accepting `/a/../b` would be confusing even if not
     * directly exploitable. */
    const char *seg = p;
    while (seg) {
        const char *next = strchr(seg + 1, '/');
        size_t seg_len = next ? (size_t)(next - seg - 1) : strlen(seg + 1);
        if (seg_len == 2 && seg[1] == '.' && seg[2] == '.')
            return false;
        seg = next;
    }
    return true;
}

const char *zcl_node_db_path(char *buf, size_t bufmax, const char *datadir)
{
    if (!buf || bufmax == 0 || !datadir) return "";
    snprintf(buf, bufmax, "%s/node.db", datadir);
    return buf;
}
