/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Metaverse HTML site views — the space page (locally known published
 * spaces) and the ZC23 Living Commons page. See views/metaverse_view.h for
 * the contract; the shell, wrappers, landing, property page, and 404 live
 * in metaverse_view.c. */

#include "views/metaverse_view_internal.h"
#include "util/template.h" /* html_escape */

#include "vcs/zcode_creation_attribution.h"

/* ── /metaverse/space — locally known published spaces ────────────── */

size_t metaverse_view_space(const struct metaverse_view_space_row *rows,
                            size_t shown, size_t total, size_t services,
                            size_t scanned, bool truncated,
                            uint8_t *resp, size_t max)
{
    char body[36864];
    size_t off = 0;
    int n = metaverse_body_start(body, sizeof(body), "Metaverse Spaces");
    if (n > 0) off = (size_t)n;

    SITE_APPEND(off, body, sizeof(body),
        "<h1>Published Spaces</h1>"
        "<p>Every <code>space_manifest.v1</code> record in this node's "
        "workspace CAS, re-parsed and re-derived on this read by the same "
        "<code>metaverse_space_show</code> path the "
        "<code>metaverse space show</code> command uses &mdash; the CAS "
        "bytes are the only space truth. %zu space%s (%zu shown), %zu "
        "service descriptor%s, %zu CAS object%s scanned%s.</p>",
        total, total == 1 ? "" : "s", shown,
        services, services == 1 ? "" : "s",
        scanned, scanned == 1 ? "" : "s",
        truncated ? " (scan or page cap reached)" : "");

    if (shown > 0) {
        SITE_APPEND(off, body, sizeof(body),
            "<table><thead><tr><th>space</th><th>owner</th>"
            "<th>sequence</th><th>validity window</th>"
            "<th>services/objects/portals</th><th>evidence</th></tr>"
            "</thead><tbody>");
        for (size_t i = 0; i < shown && off < sizeof(body) - 1024; i++) {
            const struct metaverse_view_space_row *r = &rows[i];
            char safe_name[160];
            html_escape(safe_name, sizeof(safe_name), r->name);
            SITE_APPEND(off, body, sizeof(body),
                "<tr><td><b>%s</b><br><span class='mono'>%.16s&hellip;"
                "</span></td>"
                "<td class='mono'>%.16s&hellip;</td>"
                "<td>%llu</td>"
                "<td class='mono'>%llu&ndash;%llu%s</td>"
                "<td>%u / %u / %u</td>"
                "<td><span class='pill %s'>%s</span></td></tr>",
                safe_name, r->root_hex, r->owner_hex,
                (unsigned long long)r->sequence,
                (unsigned long long)r->not_before,
                (unsigned long long)r->expiry,
                r->has_admission ? " (admission-gated)" : "",
                r->services, r->objects, r->portals,
                r->currently_active ? "pill-ok" : "",
                r->currently_active ? "local_signature (active)"
                                    : "local_signature (expired/pending)");
        }
        SITE_APPEND(off, body, sizeof(body), "</tbody></table>");
        if (total > shown) {
            SITE_APPEND(off, body, sizeof(body),
                "<p class='meta'>%zu more space%s not shown (page cap "
                "%u).</p>", total - shown, total - shown == 1 ? "" : "s",
                METAVERSE_VIEW_MAX_SPACES);
        }
    } else {
        SITE_APPEND(off, body, sizeof(body),
            "<p>No published spaces known locally yet &mdash; an empty CAS "
            "renders empty, never padded.</p>");
    }

    SITE_APPEND(off, body, sizeof(body),
        "<p><a href='/metaverse'>&larr; Metaverse</a></p>");
    n = metaverse_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return metaverse_html_response(body, off, resp, max);
}

/* ── /metaverse/commons — the ZC23 Living Commons (SIMULATION) ────── */

static const char *mv_commons_status_name(
    enum vcs_zcode_commons_verification_status status)
{
    switch (status) {
    case VCS_ZCODE_COMMONS_PARTIAL:  return "partial";
    case VCS_ZCODE_COMMONS_COMPLETE: return "complete";
    default:                         return "unknown";
    }
}

static const char *mv_commons_category_name(uint16_t category)
{
    switch (category) {
    case VCS_ZCODE_CREATION_PUBLIC_SOURCE:  return "public_source";
    case VCS_ZCODE_CREATION_BORN_RED_FIX:   return "born_red_fix";
    case VCS_ZCODE_CREATION_SECURITY_FIX:   return "security_fix";
    case VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION:
        return "independent_reproduction";
    case VCS_ZCODE_CREATION_COMPATIBILITY:  return "compatibility";
    case VCS_ZCODE_CREATION_PRESERVATION:   return "preservation";
    default:                                return "invalid";
    }
}

size_t metaverse_view_commons(
    const struct vcs_zcode_commons_projection *projection,
    uint8_t *resp, size_t max)
{
    char body[36864];
    size_t off = 0;
    int n = metaverse_body_start(body, sizeof(body), "ZC23 Living Commons");
    if (n > 0) off = (size_t)n;

    enum vcs_zcode_commons_verification_status status =
        vcs_zcode_commons_projection_status(projection);
    uint64_t minted =
        vcs_zcode_commons_projection_minted_atoms(projection);
    uint64_t attributed =
        vcs_zcode_commons_projection_attributed_atoms(projection);
    uint64_t unissued =
        vcs_zcode_commons_projection_unissued_atoms(projection);
    uint64_t unattributed = minted >= attributed ? minted - attributed : 0;
    size_t creations =
        vcs_zcode_commons_projection_creation_count(projection);
    size_t epochs = vcs_zcode_commons_projection_epoch_count(projection);
    uint8_t failed[32];
    const char *failure_reason = NULL;
    bool has_failure = vcs_zcode_commons_projection_first_failure(
        projection, failed, &failure_reason);

    SITE_APPEND(off, body, sizeof(body),
        "<h1>ZC23 Living Commons</h1>"
        "<p><span class='pill'>SIMULATION</span> The Living Commons "
        "projection, rebuilt read-only from the workspace CAS on every "
        "call &mdash; the same data behind <code>zcode commons status</code> "
        "and <code>zcode commons epoch</code>. Minted and attributed atoms "
        "are simulated patronage accounting, <b>never a balance</b>.</p>"
        "<div class='card'><h2>Status</h2>"
        "<div class='kv'><b>verification status</b>"
        "<span class='val'>%s</span></div>"
        "<div class='kv'><b>minted atoms (simulated)</b>"
        "<span class='val'>%llu</span></div>"
        "<div class='kv'><b>attributed atoms (simulated)</b>"
        "<span class='val'>%llu</span></div>"
        "<div class='kv'><b>unattributed atoms</b>"
        "<span class='val'>%llu</span></div>"
        "<div class='kv'><b>unissued atoms</b>"
        "<span class='val'>%llu</span></div>"
        "<div class='kv'><b>creation objects</b>"
        "<span class='val'>%zu</span></div>"
        "<div class='kv'><b>epoch objects</b>"
        "<span class='val'>%zu</span></div>"
        "<div class='kv'><b>structural integrity</b>"
        "<span class='val'>%s</span></div></div>",
        mv_commons_status_name(status),
        (unsigned long long)minted,
        (unsigned long long)attributed,
        (unsigned long long)unattributed,
        (unsigned long long)unissued,
        creations, epochs,
        has_failure ? "FAILED (first failure named below)" : "ok");

    if (has_failure) {
        char root_hex[65];
        zcl_hex_encode(failed, 32, root_hex);
        char safe_reason[256];
        html_escape(safe_reason, sizeof(safe_reason),
                    failure_reason ? failure_reason : "");
        SITE_APPEND(off, body, sizeof(body),
            "<p class='bad'>First integrity failure: <span class='mono'>%s"
            "</span> &mdash; %s</p>", root_hex, safe_reason);
    }

    /* Creation counts by category (the zcode.commons.status summary). */
    if (creations > 0) {
        uint64_t categories[7] = {0};
        for (size_t i = 0; i < creations; i++) {
            uint16_t category =
                vcs_zcode_commons_projection_creation_at(projection, i)
                    ->category;
            if (category < 7)
                categories[category]++;
        }
        SITE_APPEND(off, body, sizeof(body),
            "<div class='card'><h2>Creations by category</h2>"
            "<table><thead><tr><th>category</th><th>creations</th></tr>"
            "</thead><tbody>");
        for (uint16_t c = 1; c < 7 && off < sizeof(body) - 512; c++) {
            if (!categories[c])
                continue;
            SITE_APPEND(off, body, sizeof(body),
                "<tr><td class='mono'>%s</td><td>%llu</td></tr>",
                mv_commons_category_name(c),
                (unsigned long long)categories[c]);
        }
        SITE_APPEND(off, body, sizeof(body),
            "</tbody></table></div>");
    }

    /* The epoch table (the zcode.commons.epoch facts). */
    SITE_APPEND(off, body, sizeof(body),
        "<div class='card'><h2>Epochs</h2>");
    if (epochs > 0) {
        SITE_APPEND(off, body, sizeof(body),
            "<table><thead><tr><th>epoch</th><th>cap atoms</th>"
            "<th>minted atoms</th><th>unissued atoms</th>"
            "<th>attributions</th><th>creation root</th></tr></thead>"
            "<tbody>");
        for (size_t i = 0; i < epochs && off < sizeof(body) - 640; i++) {
            const struct vcs_zcode_commons_epoch_entry *e =
                vcs_zcode_commons_projection_epoch_at(projection, i);
            char root_hex[65];
            zcl_hex_encode(e->root, 32, root_hex);
            SITE_APPEND(off, body, sizeof(body),
                "<tr><td>%llu</td><td>%llu</td><td>%llu</td><td>%llu</td>"
                "<td>%u</td><td class='mono'>%.16s&hellip;</td></tr>",
                (unsigned long long)e->epoch,
                (unsigned long long)e->cap_atoms,
                (unsigned long long)e->minted_atoms,
                (unsigned long long)e->unissued_atoms,
                e->attribution_count, root_hex);
        }
        SITE_APPEND(off, body, sizeof(body),
            "</tbody></table></div>");
    } else {
        SITE_APPEND(off, body, sizeof(body),
            "<p>No epochs in the workspace CAS yet &mdash; an empty "
            "commons renders empty, never padded.</p></div>");
    }

    SITE_APPEND(off, body, sizeof(body),
        "<p><a href='/metaverse'>&larr; Metaverse</a></p>");
    n = metaverse_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return metaverse_html_response(body, off, resp, max);
}
