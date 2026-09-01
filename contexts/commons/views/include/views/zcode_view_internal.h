/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal helpers shared by the ZCODE site view translation units
 * (zcode_view.c + zcode_view_pages.c) — the page shell (design-system
 * head + global nav + the ZCODE subnav), the HTTP wrappers, and hex
 * encoding. Not a public surface: only the two zcode view .c files
 * include this. See views/zcode_view.h for the contract. */

#ifndef ZCL_VIEWS_ZCODE_VIEW_INTERNAL_H
#define ZCL_VIEWS_ZCODE_VIEW_INTERNAL_H

#include "base/hex.h"

#include "views/zcode_view.h"
#include "views/site_css.h"    /* site_css (design system) */
#include "views/site_layout.h" /* shared head/nav/footer */

#include <stdio.h>
#include <string.h>

/* Shared document open: head (site_css inlined — one round trip over the
 * onion) + global site nav + the ZCODE section subnav. Close with
 * zcode_body_end(). */
static inline int zcode_body_start(char *buf, size_t max, const char *title)
{
    size_t off = site_emit_head(buf, max, title, site_css, "measure");
    off += site_emit_global_nav(buf + off, max - off, NULL);
    SITE_APPEND(off, buf, max,
        "<nav class='nav' aria-label='ZCODE sections'>"
        "<a href='/zcode'>ZCODE</a>"
        "<a href='/zcode/packages'>Packages</a>"
        "<a href='/zcode/leaderboard'>Rankings</a>"
        "<a href='/zcode/badges'>Badges</a>"
        "</nav>"
        "<main id='content'>");
    return (int)off;
}

static inline int zcode_body_end(char *buf, size_t max)
{
    size_t off = 0;
    SITE_APPEND(off, buf, max, "</main>");
    off += site_emit_footer(buf + off, max - off, NULL);
    return (int)off;
}

#endif /* ZCL_VIEWS_ZCODE_VIEW_INTERNAL_H */
