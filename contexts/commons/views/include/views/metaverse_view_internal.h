/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal helpers shared by the metaverse site view translation units
 * (metaverse_view.c + metaverse_view_pages.c) — the page shell
 * (design-system head + global nav + the metaverse subnav) and the HTTP
 * wrappers. Not a public surface: only the two metaverse view .c files
 * include this. See views/metaverse_view.h for the contract. */

#ifndef ZCL_VIEWS_METAVERSE_VIEW_INTERNAL_H
#define ZCL_VIEWS_METAVERSE_VIEW_INTERNAL_H

#include "base/hex.h"

#include "views/metaverse_view.h"
#include "views/site_css.h"    /* site_css (design system) */
#include "views/site_layout.h" /* shared head/nav/footer */

#include <stdio.h>
#include <string.h>

/* Shared document open: head (site_css inlined — one round trip over the
 * onion) + global site nav (the "metaverse" link active) + the metaverse
 * section subnav. Close with metaverse_body_end(). */
static inline int metaverse_body_start(char *buf, size_t max,
                                       const char *title)
{
    size_t off = site_emit_head(buf, max, title, site_css, "measure");
    off += site_emit_global_nav(buf + off, max - off, "metaverse");
    SITE_APPEND(off, buf, max,
        "<nav class='nav' aria-label='Metaverse sections'>"
        "<a href='/metaverse'>Metaverse</a>"
        "<a href='/metaverse/property'>Property</a>"
        "<a href='/metaverse/space'>Spaces</a>"
        "<a href='/metaverse/commons'>Commons</a>"
        "</nav>"
        "<main id='content'>");
    return (int)off;
}

static inline int metaverse_body_end(char *buf, size_t max)
{
    size_t off = 0;
    SITE_APPEND(off, buf, max, "</main>");
    off += site_emit_footer(buf + off, max - off, NULL);
    return (int)off;
}

#endif /* ZCL_VIEWS_METAVERSE_VIEW_INTERNAL_H */
