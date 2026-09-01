/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet node-page view: the peer table for /wallet/node. The controller
 * fetches rows through the wallet_view port; this file owns the table HTML
 * and uses TMPL_NODE_PEER_ROW for each peer row. */

#include "views/wallet_view_node_view.h"
#include "views/wallet_templates_gen.h"
#include "util/template.h"

#include <stdio.h>
#include <string.h>

/* The peer addr/subver are escaped here to preserve the prior
 * behaviour. html_escape comes from util/template.h. */
size_t wv_render_peer_table(char *out, size_t outmax,
                            const struct wallet_view_peer_row *peers, int n)
{
    size_t pt = 0;

    int written = snprintf(out, outmax,
        "<div class='overflow-x'>"
        "<table><tr><th>Address</th><th>Dir</th>"
        "<th>Version</th><th>Height</th></tr>");
    if (written > 0) pt = (size_t)written;

    int peer_shown = 0;
    for (int i = 0; peers && i < n && pt + 400 < outmax; i++) {
        char esc_addr[128], esc_sub[64], sh_s[16];
        html_escape(esc_addr, sizeof(esc_addr), peers[i].addr);
        html_escape(esc_sub, sizeof(esc_sub), peers[i].subver);
        snprintf(sh_s, sizeof(sh_s), "%d", peers[i].starting_height);

        struct template_var tv[] = {
            { "addr",      esc_addr },
            { "dir_class", peers[i].inbound ? "pill-z" : "pill-t" },
            { "direction", peers[i].inbound ? "In" : "Out" },
            { "subver",    esc_sub },
            { "height",    sh_s },
        };
        pt += template_render(TMPL_NODE_PEER_ROW, tv, 5,
            out + pt, outmax - pt);
        peer_shown++;
    }
    if (peer_shown == 0) {
        int n2 = snprintf(out + pt, outmax - pt,
            "<tr><td colspan='4' style='color:#888;text-align:center;"
            "padding:16px'>Connecting to network...</td></tr>");
        if (n2 > 0) pt += (size_t)n2;
    }
    int n3 = snprintf(out + pt, outmax - pt, "</table></div>");
    if (n3 > 0) pt += (size_t)n3;
    out[pt] = '\0';
    return pt;
}
