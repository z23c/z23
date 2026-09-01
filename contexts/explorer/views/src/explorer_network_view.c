/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer /network VIEW — the operator's server-rendered window on the banked
 * network census + advertised-address topology (node_census, census_observations
 * under <datadir>/peers_projection.db; topology_edges, topology_sweeps under
 * <datadir>/topology.db). The controller parses
 * the request and passes the datadir; this file assembles the HTML. Read-only
 * and observational: it opens the census store via engine/modules/storage census_read and
 * never touches consensus. Degrades to a bounded "census empty" card when the
 * crawler/indexer lane has not written the store yet, and every table it emits
 * is row-bounded by construction. */

#include "controllers/explorer_internal.h"
#include "views/explorer_pages_view.h"
#include "storage/census_read.h"
#include "util/template.h"

#include <stdint.h>
#include <stdio.h>

size_t explorer_view_network(const char *datadir, uint8_t *r, size_t max)
{
    size_t off = 0;
    char *response = (char *)r;

    APPEND(off, response, max, EXPLORER_HEADER("Network — Z23"));
    off += explorer_emit_nav(response + off, max - off, "network");

    APPEND(off, response, max,
        "<div class='content'><h1>Network</h1>"
        "<p style='color:#888'>Every node the crawler has seen — the banked "
        "census and advertised-address topology. Read-only and "
        "observational; consensus is never affected.</p>");

    census_reader *cr = NULL;
    enum census_read_status st = census_read_open(datadir, &cr);
    if (st != CENSUS_READ_OK || !cr) {
        APPEND(off, response, max,
            "<div class='card'>"
            "<p style='color:#ffd93d;font-size:18px'>census empty: indexer "
            "not yet populated</p>"
            "<p style='color:#888'>The network crawler has not written the "
            "census store (<code>%s</code>, node_census table) yet. This page "
            "populates automatically once the indexer runs.</p></div>",
            CENSUS_PEERS_DB_BASENAME);
        APPEND(off, response, max, EXPLORER_FOOTER);
        return off;
    }

    struct census_graph_stats g;
    census_read_graph(cr, &g);
    int64_t total = census_read_node_total(cr);

    APPEND(off, response, max,
        "<div class='stats-row'>"
        "<div class='stat'><div class='num'>%lld</div>"
        "<div class='lbl'>Nodes seen</div></div>"
        "<div class='stat'><div class='num'>%lld</div>"
        "<div class='lbl'>Topology edges</div></div>"
        "<div class='stat'><div class='num'>%lld</div>"
        "<div class='lbl'>Observations</div></div>"
        "<div class='stat'><div class='num'>%lld</div>"
        "<div class='lbl'>Advertised in census</div></div>"
        "</div>",
        (long long)total, (long long)g.edge_count,
        (long long)g.observation_count, (long long)g.advertised_in_census);

    /* Census freshness — age of the most recently finished crawler sweep. */
    if (g.last_sweep_finished_unix > 0) {
        APPEND(off, response, max,
            "<p style='color:#888;font-size:13px'>Last crawler sweep finished "
            "at unix %lld (%lld sweeps banked).</p>",
            (long long)g.last_sweep_finished_unix, (long long)g.sweeps_total);
    } else {
        APPEND(off, response, max,
            "<p style='color:#888;font-size:13px'>No completed crawler sweep "
            "recorded yet.</p>");
    }

    /* Version distribution. */
    struct census_version_bucket vb[CENSUS_MAX_VERSION_BUCKETS];
    int nv = census_read_versions(cr, vb, CENSUS_MAX_VERSION_BUCKETS);
    APPEND(off, response, max,
        "<h2>Version distribution</h2>"
        "<table><tr><th>User agent</th><th>Nodes</th><th>Share</th>"
        "<th>Max height</th></tr>");
    for (int i = 0; i < nv && off + 512 < max; i++) {
        char safe_ua[256];
        html_escape(safe_ua, sizeof(safe_ua),
                    vb[i].user_agent[0] ? vb[i].user_agent : "(unknown)");
        int64_t share_bp = total > 0 ? (vb[i].count * 10000) / total : 0;
        APPEND(off, response, max,
            "<tr><td style='font-family:monospace;font-size:13px'>%s%s</td>"
            "<td>%lld</td><td>%lld.%02lld%%</td><td>%lld</td></tr>",
            safe_ua, vb[i].ua_truncated ? "\xE2\x80\xA6" : "",
            (long long)vb[i].count,
            (long long)(share_bp / 100), (long long)(share_bp % 100),
            (long long)vb[i].max_reported_height);
    }
    APPEND(off, response, max, "</table>");

    /* Bounded node table (newest last_seen first). */
    struct census_node rows[CENSUS_LIST_HARD_CAP];
    int64_t matched = 0;
    int n = census_read_list(cr, NULL, 0, 25, rows, CENSUS_LIST_HARD_CAP,
                             &matched);
    APPEND(off, response, max,
        "<h2>Nodes (%d of %lld)</h2>"
        "<p style='color:#888;font-size:13px'>Newest observation first. Most "
        "recent last_seen: unix %lld.</p>"
        "<table><tr><th>Endpoint</th><th>User agent</th><th>Proto</th>"
        "<th>Height</th><th>Last seen</th><th>Dials ok/try</th></tr>",
        n, (long long)matched,
        (long long)(n > 0 ? rows[0].last_seen : 0));
    for (int i = 0; i < n && off + 512 < max; i++) {
        char endpoint[CENSUS_ENDPOINT_MAX];
        snprintf(endpoint, sizeof(endpoint), "%s:%d", rows[i].ip, rows[i].port);
        char safe_ep[128], safe_ua[128];
        html_escape(safe_ep, sizeof(safe_ep), endpoint);
        html_escape(safe_ua, sizeof(safe_ua),
                    rows[i].user_agent[0] ? rows[i].user_agent : "(unknown)");
        APPEND(off, response, max,
            "<tr><td style='font-family:monospace;font-size:13px'>%s</td>"
            "<td style='font-family:monospace;font-size:12px'>%s%s</td>"
            "<td>%lld</td><td>%lld</td><td style='font-size:12px;color:#888'>"
            "%lld</td><td>%lld/%lld</td></tr>",
            safe_ep, safe_ua, rows[i].ua_truncated ? "\xE2\x80\xA6" : "",
            (long long)rows[i].protocol_version,
            (long long)rows[i].reported_height,
            (long long)rows[i].last_seen,
            (long long)rows[i].dial_success_count,
            (long long)(rows[i].dial_success_count + rows[i].dial_fail_count));
    }
    APPEND(off, response, max, "</table>");

    /* Top advertised endpoints (topology). */
    if (g.top_count > 0) {
        APPEND(off, response, max,
            "<h2>Most advertised endpoints</h2>"
            "<table><tr><th>Endpoint</th><th>Times seen</th>"
            "<th>Distinct observers</th></tr>");
        for (int i = 0; i < g.top_count && off + 512 < max; i++) {
            char safe_adv[128];
            html_escape(safe_adv, sizeof(safe_adv), g.top[i].advertised);
            APPEND(off, response, max,
                "<tr><td style='font-family:monospace;font-size:13px'>%s</td>"
                "<td>%lld</td><td>%lld</td></tr>",
                safe_adv, (long long)g.top[i].times_seen,
                (long long)g.top[i].distinct_observers);
        }
        APPEND(off, response, max, "</table>");
    }

    APPEND(off, response, max, "</div>");
    census_read_close(cr);
    APPEND(off, response, max, EXPLORER_FOOTER);
    return off;
}
