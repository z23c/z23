/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet shield-page view: the "nothing to shield" panel for /wallet/shield.
 * The controller decides which panel to show; this file owns the breadcrumb
 * and empty-state HTML. */

#include "views/wallet_view_shield_view.h"
#include "controllers/explorer_internal.h"  /* APPEND macro */
#include "views/wallet_templates_gen.h"
#include "util/template.h"

#include <stdio.h>

void wv_render_shield_nothing(uint8_t *r, size_t max, size_t *off)
{
    struct template_var bv[] = {
        { "parent_href",  "/wallet" },
        { "parent_label", "Home" },
        { "current",      "Shield" },
    };
    *off += template_render(TMPL_BREADCRUMB, bv, 3,
        (char *)r + *off, max - *off);
    APPEND(*off, r, max,
        "<div style='text-align:center;padding:32px 0'>"
        "<div style='font-size:24px;margin-bottom:12px'>"
        "&#x2705;</div>"
        "<div style='color:#34d399;font-size:18px;"
        "font-weight:700'>Nothing to shield</div>"
        "<div style='color:#888;font-size:14px;"
        "margin-top:8px'>"
        "All spendable funds are already in z-addresses."
        "</div>"
        "<div style='margin-top:24px'>"
        "<a href='/wallet' style='color:#34d399'>"
        "Back to Wallet</a></div></div>");
}
