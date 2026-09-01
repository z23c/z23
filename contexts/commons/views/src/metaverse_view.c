/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Metaverse HTML site views — page shell, HTTP wrappers, the landing page,
 * the sovereign property catalog page, and the honest 404 page. See
 * views/metaverse_view.h for the contract; the space and commons pages
 * live in metaverse_view_pages.c to stay under the file-size ceiling. */

#include "views/metaverse_view_internal.h"
#include "util/template.h" /* html_escape */

/* ── HTTP wrappers ────────────────────────────────────────────────── */

static size_t metaverse_wrap_response(const char *body, size_t body_len,
                                      const char *status, uint8_t *resp,
                                      size_t max)
{
    return (size_t)snprintf((char *)resp, max,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "%.*s",
        status, body_len, (int)body_len, body);
}

size_t metaverse_html_response(const char *body, size_t body_len,
                               uint8_t *resp, size_t max)
{
    return metaverse_wrap_response(body, body_len, "200 OK", resp, max);
}

size_t metaverse_error_response(const char *status_code,
                                const char *body, size_t body_len,
                                uint8_t *resp, size_t max)
{
    return metaverse_wrap_response(body, body_len, status_code, resp, max);
}

/* ── /metaverse — landing ─────────────────────────────────────────── */

size_t metaverse_view_index(const struct metaverse_view_index_input *in,
                            uint8_t *resp, size_t max)
{
    char body[16384];
    size_t off = 0;
    int n = metaverse_body_start(body, sizeof(body), "Metaverse");
    if (n > 0) off = (size_t)n;

    SITE_APPEND(off, body, sizeof(body),
        "<h1>Metaverse</h1>"
        "<p>A metaverse where people and AI create real things together, "
        "and nobody owns the world they build in. This site reads the same "
        "local projections as the <code>metaverse.*</code> and "
        "<code>zcode.commons.*</code> typed commands &mdash; there is no "
        "website database and no second truth.</p>"
        "<div class='grid'>"
        "<div class='card'><h3><a href='/metaverse/property'>Property</a>"
        "</h3>"
        "<div class='kv'><b>properties across all kinds</b>"
        "<span class='val'>%zu</span></div>"
        "<div class='kv'><b>property kinds</b>"
        "<span class='val'>%zu (%zu unavailable)</span></div>"
        "<p>The sovereign property catalog: every kind of sovereign "
        "digital property this node's datadir holds, with its authority "
        "source, evidence grade, and settlement class.</p></div>"
        "<div class='card'><h3><a href='/metaverse/space'>Spaces</a></h3>"
        "<div class='kv'><b>published spaces</b>"
        "<span class='val'>%zu</span></div>"
        "<div class='kv'><b>service descriptors</b>"
        "<span class='val'>%zu</span></div>"
        "<p>Locally known published spaces, re-parsed and re-derived from "
        "the workspace CAS on every read.</p></div>"
        "<div class='card'><h3><a href='/metaverse/commons'>Commons</a>"
        "</h3>"
        "<div class='kv'><b>verification status</b>"
        "<span class='val'>%s</span></div>"
        "<div class='kv'><b>creation objects</b>"
        "<span class='val'>%zu</span></div>"
        "<div class='kv'><b>epochs</b><span class='val'>%zu</span></div>"
        "<p>The ZC23 Living Commons projection &mdash; <b>SIMULATION</b>: "
        "minted and attributed atoms are simulated patronage accounting, "
        "never a balance.</p></div>"
        "</div>",
        in->property_read ? in->property_total : 0,
        in->property_read ? in->property_kinds : 0,
        in->property_read ? in->property_unavailable : 0,
        in->space_read ? in->space_manifests : 0,
        in->space_read ? in->space_services : 0,
        in->commons_built ? in->commons_status : "unknown",
        in->commons_built ? in->commons_creations : 0,
        in->commons_built ? in->commons_epochs : 0);

    if (!in->property_read || !in->space_read || !in->commons_built) {
        SITE_APPEND(off, body, sizeof(body),
            "<p class='meta'>One or more projections could not be read; "
            "the affected counts render as zero here and each section page "
            "names its own failure rather than inventing data.</p>");
    }

    if (in->commons_built) {
        SITE_APPEND(off, body, sizeof(body),
            "<div class='card'><h2>Commons summary (SIMULATION)</h2>"
            "<div class='kv'><b>minted atoms (simulated)</b>"
            "<span class='val'>%llu</span></div>"
            "<div class='kv'><b>attributed atoms (simulated)</b>"
            "<span class='val'>%llu</span></div></div>",
            (unsigned long long)in->commons_minted_atoms,
            (unsigned long long)in->commons_attributed_atoms);
    }

    n = metaverse_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return metaverse_html_response(body, off, resp, max);
}

/* ── /metaverse/property — the sovereign property catalog ─────────── */

size_t metaverse_view_property(const struct property_catalog_page *page,
                               const char *kind_filter,
                               uint8_t *resp, size_t max)
{
    char body[40960];
    size_t off = 0;
    int n = metaverse_body_start(body, sizeof(body), "Sovereign Property");
    if (n > 0) off = (size_t)n;

    char safe_filter[64];
    safe_filter[0] = '\0';
    if (kind_filter && kind_filter[0])
        html_escape(safe_filter, sizeof(safe_filter), kind_filter);

    SITE_APPEND(off, body, sizeof(body),
        "<h1>Sovereign Property</h1>"
        "<p>The property catalog is a projection, not a source of truth: "
        "every read asks each property kind's authoritative model directly. "
        "%zu propert%s across %zu kind%s%s%s%s.</p>",
        page->total_across_kinds,
        page->total_across_kinds == 1 ? "y" : "ies",
        page->kind_count, page->kind_count == 1 ? "" : "s",
        kind_filter && kind_filter[0] ? " (filtered to kind <b>" : "",
        kind_filter && kind_filter[0] ? safe_filter : "",
        kind_filter && kind_filter[0] ? "</b>)" : "");

    if (!page->store_read) {
        char safe_reason[256];
        html_escape(safe_reason, sizeof(safe_reason), page->store_reason);
        SITE_APPEND(off, body, sizeof(body),
            "<p class='bad'>A store under this datadir is present but "
            "unreadable: %s. An empty list below is a failure to look, not "
            "an inventory.</p>", safe_reason);
    }

    /* Per-kind coverage: every kind gets a row, including unavailable
     * ones — a kind that vanished would read as "owns nothing". */
    SITE_APPEND(off, body, sizeof(body),
        "<div class='card'><h2>Property kinds</h2>"
        "<table><thead><tr><th>kind</th><th>authority</th>"
        "<th>settlement class</th><th>status</th><th>total</th>"
        "<th>shown</th></tr></thead><tbody>");
    for (size_t i = 0; i < page->kind_count && off < sizeof(body) - 1024;
         i++) {
        const struct property_catalog_kind_row *k = &page->kinds[i];
        if (k->available) {
            SITE_APPEND(off, body, sizeof(body),
                "<tr><td class='mono'>%s</td><td class='mono'>%s</td>"
                "<td><span class='pill'>%s</span></td>"
                "<td>available%s%s</td><td>%zu</td><td>%zu%s</td></tr>",
                k->kind_name, k->authority_source,
                metaverse_settlement_name(k->settlement),
                k->integrity_checked && !k->integrity_ok
                    ? ", integrity gaps" : "",
                k->truncated ? ", truncated" : "",
                k->total, k->written,
                k->truncated ? "+" : "");
        } else {
            char safe_reason[256];
            html_escape(safe_reason, sizeof(safe_reason),
                        k->unavailable_reason ? k->unavailable_reason : "");
            SITE_APPEND(off, body, sizeof(body),
                "<tr><td class='mono'>%s</td><td class='mono'>%s</td>"
                "<td><span class='pill'>%s</span></td>"
                "<td colspan='3'>unavailable &mdash; %s</td></tr>",
                k->kind_name, k->authority_source,
                metaverse_settlement_name(k->settlement), safe_reason);
        }
    }
    SITE_APPEND(off, body, sizeof(body),
        "</tbody></table></div>");

    /* The bounded property rows: status + evidence grade per property. */
    SITE_APPEND(off, body, sizeof(body),
        "<div class='card'><h2>Properties</h2>");
    if (page->count > 0) {
        SITE_APPEND(off, body, sizeof(body),
            "<table><thead><tr><th>property</th><th>name</th>"
            "<th>status</th><th>evidence grade</th><th>owner</th></tr>"
            "</thead><tbody>");
        for (size_t i = 0; i < page->count && off < sizeof(body) - 1024;
             i++) {
            const struct metaverse_property_view *v = &page->items[i];
            char safe_id[128], safe_name[160], safe_owner[160];
            html_escape(safe_id, sizeof(safe_id), v->id_text);
            html_escape(safe_name, sizeof(safe_name), v->display_name);
            html_escape(safe_owner, sizeof(safe_owner),
                        v->owner_principal[0]
                            ? v->owner_principal
                            : (v->owner_principal_kind
                                   ? v->owner_principal_kind : "none"));
            SITE_APPEND(off, body, sizeof(body),
                "<tr><td class='mono'>%s</td><td>%s</td>"
                "<td>%s</td><td><span class='pill'>%s</span></td>"
                "<td class='mono'>%s</td></tr>",
                safe_id, safe_name[0] ? safe_name : "&mdash;",
                metaverse_property_status_name(v->status),
                metaverse_evidence_name(v->evidence), safe_owner);
        }
        SITE_APPEND(off, body, sizeof(body), "</tbody></table>");
        if (page->total_across_kinds > page->count) {
            SITE_APPEND(off, body, sizeof(body),
                "<p class='meta'>%zu more propert%s not shown (page cap "
                "%u).</p>", page->total_across_kinds - page->count,
                page->total_across_kinds - page->count == 1 ? "y" : "ies",
                METAVERSE_VIEW_MAX_ROWS);
        }
    } else {
        SITE_APPEND(off, body, sizeof(body),
            "<p>No properties projected%s &mdash; an empty catalog renders "
            "empty, never padded.</p>",
            page->store_read ? "" : " (see the store failure above)");
    }
    SITE_APPEND(off, body, sizeof(body),
        "</div><p><a href='/metaverse'>&larr; Metaverse</a></p>");

    n = metaverse_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return metaverse_html_response(body, off, resp, max);
}

/* ── honest 404 ───────────────────────────────────────────────────── */

size_t metaverse_view_route_not_found(const char *path, uint8_t *resp,
                                      size_t max)
{
    char body[16384];
    size_t off = 0;
    int n = metaverse_body_start(body, sizeof(body),
                                 "Metaverse route not found");
    if (n > 0) off = (size_t)n;
    char safe_path[256];
    html_escape(safe_path, sizeof(safe_path), path ? path : "");
    SITE_APPEND(off, body, sizeof(body),
        "<h1>Unknown metaverse route</h1>"
        "<div class='card'>"
        "<p><code>%s</code> is not a metaverse site route.</p>"
        "<p>Routes: <code>/metaverse</code>, "
        "<code>/metaverse/property</code>, <code>/metaverse/space</code>, "
        "<code>/metaverse/commons</code>.</p>"
        "<p><a href='/metaverse'>&larr; Metaverse</a></p></div>",
        safe_path);
    n = metaverse_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return metaverse_error_response("404 Not Found", body, off, resp, max);
}
