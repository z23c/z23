/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCODE Library HTML site views (slice 13) — the detail pages: package
 * (release envelope + publisher signature + manifest + attestations +
 * swarm advertisers), publisher (contributor profile + ZCODE Score +
 * rank + badges + packages), leaderboards, and the badge index. See
 * views/zcode_view.h for the contract; the shell, wrappers, landing,
 * search, and 404 pages live in zcode_view.c. */

#include "views/zcode_view_internal.h"
#include "util/template.h" /* html_escape */

/* ── /zcode/package/<root> ────────────────────────────────────────── */

static size_t zcode_emit_release_card(char *buf, size_t max,
                                      const struct vcs_package_index_entry *e,
                                      const struct vcs_package_release *r)
{
    size_t off = 0;
    char safe_name[160], safe_semver[80], safe_license[48];
    char safe_reward[160], safe_znam[80], safe_chain[48];
    html_escape(safe_name, sizeof(safe_name), e->name);
    html_escape(safe_semver, sizeof(safe_semver), e->semver);
    html_escape(safe_license, sizeof(safe_license), e->license);

    SITE_APPEND(off, buf, max,
        "<div class='card'><h2>Signed release envelope</h2>"
        "<div class='kv'><b>name</b><span class='val mono'>%s</span></div>"
        "<div class='kv'><b>semver</b><span class='val mono'>%s</span></div>"
        "<div class='kv'><b>license</b>"
        "<span class='val mono'>%s</span></div>"
        "<div class='kv'><b>release id</b>"
        "<span class='val mono'>%s</span></div>"
        "<div class='kv'><b>package root</b>"
        "<span class='val mono'>%s</span></div>"
        "<div class='kv'><b>publisher</b><span class='val mono'>"
        "<a href='/zcode/publisher/%s'>%s</a></span></div>"
        "<div class='kv'><b>publisher sequence</b>"
        "<span class='val'>%llu</span></div>",
        safe_name, safe_semver, safe_license, e->release_id_hex,
        e->package_root_hex, e->publisher_hex, e->publisher_hex,
        (unsigned long long)e->publisher_sequence);

    if (r) {
        char sig_hex[2 * VCS_PACKAGE_RELEASE_SIGNATURE_BYTES + 1];
        char recipe_hex[65];
        zcl_hex_encode(r->signature, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES, sig_hex);
        zcl_hex_encode(r->recipe_root, 32, recipe_hex);
        html_escape(safe_reward, sizeof(safe_reward), r->reward_address);
        html_escape(safe_chain, sizeof(safe_chain), r->chain_id);
        SITE_APPEND(off, buf, max,
            "<div class='kv'><b>publisher signature</b>"
            "<span class='val mono'>%s</span></div>"
            "<div class='kv'><b>recipe root</b>"
            "<span class='val mono'>%s</span></div>"
            "<div class='kv'><b>chain id</b>"
            "<span class='val mono'>%s</span></div>",
            sig_hex, recipe_hex, safe_chain);
        if (r->reward_address[0])
            SITE_APPEND(off, buf, max,
                "<div class='kv'><b>reward address</b>"
                "<span class='val mono'>%s</span></div>", safe_reward);
        if (r->has_znam) {
            html_escape(safe_znam, sizeof(safe_znam), r->znam);
            SITE_APPEND(off, buf, max,
                "<div class='kv'><b>znam pointer</b>"
                "<span class='val mono'>%s</span></div>", safe_znam);
        }
        if (r->has_parent) {
            char parent_hex[65];
            zcl_hex_encode(r->parent_root, 32, parent_hex);
            SITE_APPEND(off, buf, max,
                "<div class='kv'><b>parent root</b>"
                "<span class='val mono'>%s</span></div>", parent_hex);
        }
    } else {
        SITE_APPEND(off, buf, max,
            "<p class='bad'>The persisted release envelope is unreadable; "
            "signature fields are withheld rather than guessed.</p>");
    }
    SITE_APPEND(off, buf, max, "</div>");
    return off;
}

static size_t zcode_emit_manifest_card(char *buf, size_t max,
                                       const struct zcode_view_package_input *in)
{
    size_t off = 0;
    const struct vcs_package_index_entry *e = in->entry;
    SITE_APPEND(off, buf, max,
        "<div class='card'><h2>Manifest</h2>"
        "<div class='kv'><b>manifest present</b><span class='val'>%s</span></div>"
        "<div class='kv'><b>files</b><span class='val'>%u</span></div>"
        "<div class='kv'><b>total bytes</b><span class='val'>%llu</span></div>"
        "<div class='kv'><b>chunks</b><span class='val'>%u</span></div>"
        "<div class='kv'><b>license file</b><span class='val'>%s</span></div>"
        "<div class='kv'><b>executable files</b><span class='val'>%u</span></div>"
        "<p><a class='btn' href='/zcode/download/%s'>Download manifest "
        "(signed-bytes attachment)</a></p>",
        e->manifest_present ? "yes" : "no", e->file_count,
        (unsigned long long)e->total_bytes, e->chunk_total,
        e->license_present ? "present" : "absent", e->executable_count,
        e->package_root_hex);

    if (in->manifest && in->files_shown > 0) {
        SITE_APPEND(off, buf, max,
            "<table><thead><tr><th>path</th><th>bytes</th><th>chunks</th>"
            "<th>chunk download</th></tr></thead><tbody>");
        for (size_t i = 0; i < in->files_shown &&
                            off < max - 512; i++) {
            const struct vcs_package_file *f = &in->manifest->files[i];
            char safe_path[300];
            html_escape(safe_path, sizeof(safe_path), f->path);
            SITE_APPEND(off, buf, max,
                "<tr><td class='mono'>%s</td><td>%llu</td><td>%u</td><td>",
                safe_path, (unsigned long long)f->size, f->chunk_count);
            for (uint32_t c = 0; c < f->chunk_count && c < 4 &&
                                off < max - 256; c++)
                SITE_APPEND(off, buf, max,
                    "<a href='/zcode/download/%s/%zu/%u'>%u</a> ",
                    e->package_root_hex, i, c, c);
            if (f->chunk_count > 4)
                SITE_APPEND(off, buf, max, "&hellip;");
            SITE_APPEND(off, buf, max, "</td></tr>");
        }
        SITE_APPEND(off, buf, max, "</tbody></table>");
        if (in->manifest->count > in->files_shown)
            SITE_APPEND(off, buf, max,
                "<p class='meta'>%zu more file%s not shown (page cap %u)."
                "</p>",
                in->manifest->count - in->files_shown,
                in->manifest->count - in->files_shown == 1 ? "" : "s",
                ZCODE_VIEW_MAX_FILES);
    }
    SITE_APPEND(off, buf, max, "</div>");
    return off;
}

static size_t zcode_emit_attest_card(char *buf, size_t max,
                                     const struct zcode_view_package_input *in)
{
    size_t off = 0;
    SITE_APPEND(off, buf, max,
        "<div class='card'><h2>Verifier attestations</h2>"
        "<p class='meta'>Attestations are produced by the external "
        "<code>zclassic23-package-verify</code> program &mdash; this node "
        "never compiles or executes downloaded code. %zu attestation "
        "wire%s scanned, %zu naming this package.</p>",
        in->attest_scanned, in->attest_scanned == 1 ? "" : "s",
        in->attest_matching);
    if (in->attest_shown > 0) {
        SITE_APPEND(off, buf, max,
            "<table><thead><tr><th>verifier</th><th>result</th>"
            "<th>tests</th><th>isolation</th></tr></thead><tbody>");
        for (size_t i = 0; i < in->attest_shown && off < max - 512; i++) {
            const struct vcs_package_attest *a = &in->attestations[i];
            char verifier_hex[2 * VCS_PACKAGE_ATTEST_PUBKEY_BYTES + 1];
            zcl_hex_encode(a->verifier_pubkey, VCS_PACKAGE_ATTEST_PUBKEY_BYTES,
                      verifier_hex);
            const char *cls =
                vcs_package_attest_result_string(a->result_class);
            bool pass = vcs_package_attest_result_is_pass(a->result_class);
            SITE_APPEND(off, buf, max,
                "<tr><td class='mono'>%.16s&hellip;</td>"
                "<td><span class='pill %s'>%s</span></td>"
                "<td>%s</td><td>%s</td></tr>",
                verifier_hex, pass ? "pill-ok" : "pill-bad", cls,
                a->test_ran ? "ran" : "not run",
                vcs_package_attest_isolation_string(a->isolation));
        }
        SITE_APPEND(off, buf, max, "</tbody></table>");
        if (in->attest_matching > in->attest_shown)
            SITE_APPEND(off, buf, max,
                "<p class='meta'>%zu more attestation%s not shown (page "
                "cap %u).</p>",
                in->attest_matching - in->attest_shown,
                in->attest_matching - in->attest_shown == 1 ? "" : "s",
                ZCODE_VIEW_MAX_ATTESTS);
    } else {
        SITE_APPEND(off, buf, max,
            "<p>No attestations for this package in the local store.</p>");
    }
    SITE_APPEND(off, buf, max, "</div>");
    return off;
}

size_t zcode_view_package(const struct zcode_view_package_input *in,
                          uint8_t *resp, size_t max)
{
    char body[45056];
    size_t off = 0;
    int n = zcode_body_start(body, sizeof(body), "ZCODE Package");
    if (n > 0) off = (size_t)n;

    char safe_name[160];
    html_escape(safe_name, sizeof(safe_name), in->entry->name);
    char safe_semver[80];
    html_escape(safe_semver, sizeof(safe_semver), in->entry->semver);
    n = snprintf(body + off, sizeof(body) - off,
        "<h1>%s <span class='pill'>%s</span></h1>"
        "<section class='card'><h2>What it does</h2>"
        "<p class='bad'>No human purpose is published for this exact "
        "release. Its name and source paths are not treated as proof of "
        "behavior.</p>"
        "<div class='kv'><b>exact version</b>"
        "<span class='val mono'>%s</span></div></section>"
        "<section class='card'><h2>Try it</h2>"
        "<p>No runnable example is published for this release. Nothing "
        "was executed. A future example must declare bounded input, output, "
        "success, failure, time, and resource limits as package facts.</p>"
        "</section>"
        "<section class='card'><h2>Change it</h2>"
        "<p>This installed compatibility page is read-only. Tell your agent "
        "what you want to change; typed native commands perform the work and "
        "summon bounded native C23 views when you need to inspect, compare, "
        "choose, or confirm something. This page never gains software "
        "authority.</p></section>",
        safe_name, safe_semver, safe_semver);
    if (n > 0) off += (size_t)n;

    n = snprintf(body + off, sizeof(body) - off,
        "<section class='card'><h2>What changed</h2>");
    if (n > 0) off += (size_t)n;
    if (in->entry->has_parent) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='kv'><b>predecessor</b>"
            "<span class='val mono'><a href='/zcode/package/%s'>%s</a>"
            "</span></div>"
            "<p>No behavior comparison is published for this successor; "
            "the exact predecessor link is shown without inventing a "
            "diff.</p>", in->entry->parent_root_hex,
            in->entry->parent_root_hex);
    } else {
        n = snprintf(body + off, sizeof(body) - off,
            "<p>This is the first release in its published lineage. There "
            "is no predecessor to compare.</p>");
    }
    if (n > 0) off += (size_t)n;
    n = snprintf(body + off, sizeof(body) - off, "</section>");
    if (n > 0) off += (size_t)n;

    n = snprintf(body + off, sizeof(body) - off,
        "<section class='card'><h2>Verify</h2>"
        "<div class='kv'><b>exact source identity</b>"
        "<span class='val mono'>%s</span></div>"
        "<p>The package root binds the manifest and its content. Verifier "
        "claims below are local evidence, not guesses or peer counts.</p>",
        in->entry->package_root_hex);
    if (n > 0) off += (size_t)n;
    off += zcode_emit_attest_card(body + off, sizeof(body) - off, in);
    n = snprintf(body + off, sizeof(body) - off, "</section>");
    if (n > 0) off += (size_t)n;

    n = snprintf(body + off, sizeof(body) - off,
        "<section class='card'><h2>Use and share</h2>"
        "<p><a class='btn' href='/zcode/download/%s'>Obtain exact manifest"
        "</a></p>"
        "<p>This attachment is inert package data; the page never compiles "
        "or runs downloaded C. Keep the package root with it so another "
        "node can identify the same release.</p></section>"
        "<details><summary>Technical package details</summary>",
        in->entry->package_root_hex);
    if (n > 0) off += (size_t)n;
    off += zcode_emit_release_card(body + off, sizeof(body) - off,
                                   in->entry, in->release);
    off += zcode_emit_manifest_card(body + off, sizeof(body) - off, in);
    n = snprintf(body + off, sizeof(body) - off,
        "<div class='card'><h2>Swarm availability</h2>");
    if (n > 0) off += (size_t)n;
    if (in->swarm_advertisers >= 0) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='kv'><b>peers advertising this package</b>"
            "<span class='val'>%ld</span></div>"
            "<p class='meta'>The node's local swarm view; anonymous peer "
            "count is never a verifier quorum.</p>",
            in->swarm_advertisers);
    } else {
        n = snprintf(body + off, sizeof(body) - off,
            "<p>The local swarm is not running on this node (one-shot "
            "view), so no advertiser count is available &mdash; reported "
            "honestly rather than zero-filled.</p>");
    }
    if (n > 0) off += (size_t)n;
    n = snprintf(body + off, sizeof(body) - off,
        "</div></details><p><a href='/zcode/packages'>&larr; all packages"
        "</a></p>");
    if (n > 0) off += (size_t)n;

    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_html_response(body, off, resp, max);
}

/* ── /zcode/publisher/<pubkey> ────────────────────────────────────── */

size_t zcode_view_publisher(const struct zcode_view_publisher_input *in,
                            uint8_t *resp, size_t max)
{
    char body[40960];
    size_t off = 0;
    const struct vcs_zcode_contributor *c = in->contributor;
    int n = zcode_body_start(body, sizeof(body), "ZCODE Publisher");
    if (n > 0) off = (size_t)n;

    char safe_name[160], safe_semver[80], safe_license[48];
    char safe_reward[160], safe_znam[80];
    html_escape(safe_name, sizeof(safe_name), c->latest_name);
    html_escape(safe_semver, sizeof(safe_semver), c->latest_semver);
    html_escape(safe_license, sizeof(safe_license), c->latest_license);
    html_escape(safe_reward, sizeof(safe_reward), c->reward_address);

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Publisher <span class='mono'>%.16s&hellip;</span></h1>"
        "<div class='card'><h2>Contributor profile</h2>"
        "<div class='kv'><b>publisher key</b>"
        "<span class='val mono'>%s</span></div>"
        "<div class='kv'><b>releases</b><span class='val'>%u</span></div>"
        "<div class='kv'><b>latest release</b>"
        "<span class='val mono'>%s %s</span></div>"
        "<div class='kv'><b>latest license</b>"
        "<span class='val mono'>%s</span></div>",
        c->publisher_hex, c->publisher_hex, c->release_count,
        safe_name, safe_semver, safe_license);
    if (n > 0) off += (size_t)n;
    if (c->reward_address[0]) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='kv'><b>reward address</b>"
            "<span class='val mono'>%s</span></div>", safe_reward);
        if (n > 0) off += (size_t)n;
    }
    if (c->has_znam_pointer) {
        html_escape(safe_znam, sizeof(safe_znam), c->znam_pointer);
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='kv'><b>znam pointer</b>"
            "<span class='val mono'>%s</span></div>", safe_znam);
        if (n > 0) off += (size_t)n;
    }
    n = snprintf(body + off, sizeof(body) - off, "</div>");
    if (n > 0) off += (size_t)n;

    /* ZCODE Score + rank: earned score, never a token balance. */
    n = snprintf(body + off, sizeof(body) - off,
        "<div class='card'><h2>ZCODE Score</h2>");
    if (n > 0) off += (size_t)n;
    if (in->totals) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='kv'><b>earned score (settled)</b>"
            "<span class='val'>%llu</span></div>"
            "<div class='kv'><b>simulated token rewards received</b>"
            "<span class='val'>%llu</span></div>"
            "<div class='kv'><b>settled entries</b>"
            "<span class='val'>%u</span></div>"
            "<div class='kv'><b>queued entries</b>"
            "<span class='val'>%u</span></div>",
            (unsigned long long)in->totals->earned_score,
            (unsigned long long)in->totals->token_rewards_received,
            in->totals->settled_entries, in->totals->queued_entries);
        if (n > 0) off += (size_t)n;
    } else {
        n = snprintf(body + off, sizeof(body) - off,
            "<p>No reward ledger on this node; no settled score yet.</p>");
        if (n > 0) off += (size_t)n;
    }
    if (in->rank) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='kv'><b>all-time rank</b>"
            "<span class='val'>#%llu</span></div>",
            (unsigned long long)in->rank->rank);
        if (n > 0) off += (size_t)n;
    }
    n = snprintf(body + off, sizeof(body) - off,
        "<p class='meta'>Rankings use earned score only &mdash; a "
        "transferred or purchased balance can never move them (balances "
        "do not exist in the v1 simulation).</p></div>");
    if (n > 0) off += (size_t)n;

    /* Earned badges. */
    n = snprintf(body + off, sizeof(body) - off,
        "<div class='card'><h2>Badges</h2>");
    if (n > 0) off += (size_t)n;
    if (in->badges_shown > 0) {
        n = snprintf(body + off, sizeof(body) - off,
            "<p>%zu earned badge%s%s.</p>", in->badges_total,
            in->badges_total == 1 ? "" : "s",
            in->badge_policy ? "" : " (no badge policy lens configured)");
        if (n > 0) off += (size_t)n;
        for (size_t i = 0; i < in->badges_shown && off < sizeof(body) - 512;
             i++) {
            const struct vcs_badge *b = &in->badges[i];
            n = snprintf(body + off, sizeof(body) - off,
                "<div class='kv'><b>%s</b><span class='val'>sequence "
                "%llu</span></div>",
                vcs_badge_type_string((enum vcs_badge_type)b->type),
                (unsigned long long)b->sequence);
            if (n > 0) off += (size_t)n;
        }
        if (in->badges_total > in->badges_shown) {
            n = snprintf(body + off, sizeof(body) - off,
                "<p class='meta'>%zu more badge%s not shown (page cap %u)."
                "</p>", in->badges_total - in->badges_shown,
                in->badges_total - in->badges_shown == 1 ? "" : "s",
                ZCODE_VIEW_MAX_ROWS);
            if (n > 0) off += (size_t)n;
        }
    } else {
        n = snprintf(body + off, sizeof(body) - off,
            "<p>No earned badges%s.</p>",
            in->badge_policy ? "" : " (no badge policy lens configured)");
        if (n > 0) off += (size_t)n;
    }
    n = snprintf(body + off, sizeof(body) - off, "</div>");
    if (n > 0) off += (size_t)n;

    /* The publisher's packages. */
    n = snprintf(body + off, sizeof(body) - off,
        "<div class='card'><h2>Packages</h2>");
    if (n > 0) off += (size_t)n;
    for (size_t i = 0; i < in->packages_shown && off < sizeof(body) - 1024;
         i++) {
        const struct vcs_package_index_entry *e = in->packages[i];
        char safe_pname[160], safe_psemver[80];
        html_escape(safe_pname, sizeof(safe_pname), e->name);
        html_escape(safe_psemver, sizeof(safe_psemver), e->semver);
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='kv'><b><a href='/zcode/package/%s'>%s</a></b>"
            "<span class='val mono'>%s</span></div>",
            e->package_root_hex, safe_pname, safe_psemver);
        if (n > 0) off += (size_t)n;
    }
    if (in->packages_total > in->packages_shown) {
        n = snprintf(body + off, sizeof(body) - off,
            "<p class='meta'>%zu more release%s not shown (page cap %u)."
            "</p>", in->packages_total - in->packages_shown,
            in->packages_total - in->packages_shown == 1 ? "" : "s",
            ZCODE_VIEW_MAX_ROWS);
        if (n > 0) off += (size_t)n;
    }
    n = snprintf(body + off, sizeof(body) - off,
        "</div><p><a href='/zcode/packages'>&larr; all packages</a></p>");
    if (n > 0) off += (size_t)n;

    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_html_response(body, off, resp, max);
}

/* ── /zcode/leaderboard ───────────────────────────────────────────── */

size_t zcode_view_leaderboard_index(uint8_t *resp, size_t max)
{
    char body[20480];
    size_t off = 0;
    int n = zcode_body_start(body, sizeof(body), "ZCODE Rankings");
    if (n > 0) off = (size_t)n;
    n = snprintf(body + off, sizeof(body) - off,
        "<h1>ZCODE Rankings</h1>"
        "<p>Rankings rank <b>earned</b> ZCODE Score, never a token "
        "balance. Pick a period:</p>"
        "<div class='grid'>"
        "<div class='card'><h3><a href='/zcode/leaderboard/daily'>Daily</a>"
        "</h3><p>The current UTC day.</p></div>"
        "<div class='card'><h3><a href='/zcode/leaderboard/weekly'>Weekly"
        "</a></h3><p>The current ISO-8601 week (Monday&ndash;Sunday).</p>"
        "</div>"
        "<div class='card'><h3><a href='/zcode/leaderboard/monthly'>Monthly"
        "</a></h3><p>The current calendar month.</p></div>"
        "<div class='card'><h3><a href='/zcode/leaderboard/all'>All-time"
        "</a></h3><p>Every settled score fact.</p></div>"
        "</div>");
    if (n > 0) off += (size_t)n;
    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_html_response(body, off, resp, max);
}

size_t zcode_view_leaderboard(enum vcs_rank_period period,
                              const struct vcs_rank_window *window,
                              const struct vcs_rank_entry *rows,
                              size_t shown, size_t total,
                              size_t facts_used, size_t facts_dropped,
                              bool contributors_truncated,
                              uint8_t *resp, size_t max)
{
    char body[28672];
    size_t off = 0;
    int n = zcode_body_start(body, sizeof(body), "ZCODE Rankings");
    if (n > 0) off = (size_t)n;

    char window_desc[96] = "all time";
    if (window->bounded) {
        if (period == VCS_RANK_PERIOD_DAILY)
            snprintf(window_desc, sizeof(window_desc), "%lld-%02u-%02u",
                     (long long)window->year, window->month,
                     window->day_of_month);
        else if (period == VCS_RANK_PERIOD_WEEKLY)
            snprintf(window_desc, sizeof(window_desc), "ISO %lld-W%02u",
                     (long long)window->iso_year, window->iso_week);
        else if (period == VCS_RANK_PERIOD_MONTHLY)
            snprintf(window_desc, sizeof(window_desc), "%lld-%02u",
                     (long long)window->year, window->month);
    }

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>ZCODE Rankings &mdash; %s</h1>"
        "<p>Window: <b>%s</b>. %zu ranked contributor%s (%zu shown; %zu "
        "settled facts used, %zu dropped)%s. Ranked by earned score; "
        "token balances never move this table.</p>",
        vcs_rank_period_string(period), window_desc, total,
        total == 1 ? "" : "s", shown, facts_used, facts_dropped,
        contributors_truncated ? " (contributor cap reached)" : "");
    if (n > 0) off += (size_t)n;

    if (shown > 0) {
        n = snprintf(body + off, sizeof(body) - off,
            "<table><thead><tr><th>rank</th><th>contributor</th>"
            "<th>earned score</th><th>simulated token rewards</th></tr>"
            "</thead><tbody>");
        if (n > 0) off += (size_t)n;
        for (size_t i = 0; i < shown && off < sizeof(body) - 512; i++) {
            char pub_hex[67];
            zcl_hex_encode(rows[i].contributor, 33, pub_hex);
            n = snprintf(body + off, sizeof(body) - off,
                "<tr><td>#%llu</td>"
                "<td class='mono'><a href='/zcode/publisher/%s'>%.16s"
                "&hellip;</a></td><td>%llu</td><td>%llu</td></tr>",
                (unsigned long long)rows[i].rank, pub_hex, pub_hex,
                (unsigned long long)rows[i].earned_score,
                (unsigned long long)rows[i].token_rewards_received);
            if (n > 0) off += (size_t)n;
        }
        n = snprintf(body + off, sizeof(body) - off, "</tbody></table>");
        if (n > 0) off += (size_t)n;
        if (total > shown) {
            n = snprintf(body + off, sizeof(body) - off,
                "<p class='meta'>%zu more contributor%s not shown (page "
                "cap %u).</p>", total - shown,
                total - shown == 1 ? "" : "s", VCS_RANK_MAX_PAGE_ROWS);
            if (n > 0) off += (size_t)n;
        }
    } else {
        n = snprintf(body + off, sizeof(body) - off,
            "<p>No settled score facts in this window yet &mdash; an "
            "empty window renders empty, never padded.</p>");
        if (n > 0) off += (size_t)n;
    }
    n = snprintf(body + off, sizeof(body) - off,
        "<p><a href='/zcode/leaderboard'>&larr; all periods</a></p>");
    if (n > 0) off += (size_t)n;

    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_html_response(body, off, resp, max);
}

/* ── /zcode/badges ────────────────────────────────────────────────── */

size_t zcode_view_badges(const struct vcs_badge *badges, size_t shown,
                         size_t total, bool recognized_lens,
                         uint32_t corrupt, bool truncated,
                         uint8_t *resp, size_t max)
{
    char body[40960];
    size_t off = 0;
    int n = zcode_body_start(body, sizeof(body), "ZCODE Badges");
    if (n > 0) off = (size_t)n;

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>ZCODE Badges</h1>"
        "<p>%zu signature-valid badge wire%s in the local store%s%s%s. "
        "Badges are permanent ZSLP-based achievements; v1 issuance is "
        "owner-reviewed (plan/commit), never automatic.</p>",
        total, total == 1 ? "" : "s",
        recognized_lens ? " (operator policy lens applied &mdash; rows "
                          "are recognized earned badges)"
                        : " (no operator badge policy configured &mdash; "
                          "every signature-valid wire is shown)",
        corrupt ? " (corrupt wires skipped)" : "",
        truncated ? " (scan cap reached)" : "");
    if (n > 0) off += (size_t)n;

    if (shown > 0) {
        n = snprintf(body + off, sizeof(body) - off,
            "<table><thead><tr><th>badge</th><th>recipient</th>"
            "<th>period (civil days)</th><th>sequence</th></tr></thead>"
            "<tbody>");
        if (n > 0) off += (size_t)n;
        for (size_t i = 0; i < shown && off < sizeof(body) - 640; i++) {
            const struct vcs_badge *b = &badges[i];
            char recip_hex[2 * VCS_PACKAGE_BADGE_PUBKEY_BYTES + 1];
            zcl_hex_encode(b->recipient, VCS_PACKAGE_BADGE_PUBKEY_BYTES,
                      recip_hex);
            char period_desc[64];
            if (vcs_badge_is_non_periodic(b))
                snprintf(period_desc, sizeof(period_desc), "non-periodic");
            else
                snprintf(period_desc, sizeof(period_desc), "%lld..%lld",
                         (long long)b->period_first_day,
                         (long long)b->period_last_day);
            n = snprintf(body + off, sizeof(body) - off,
                "<tr><td>%s</td>"
                "<td class='mono'><a href='/zcode/publisher/%s'>%.16s"
                "&hellip;</a></td><td class='mono'>%s</td><td>%llu</td>"
                "</tr>",
                vcs_badge_type_string((enum vcs_badge_type)b->type),
                recip_hex, recip_hex, period_desc,
                (unsigned long long)b->sequence);
            if (n > 0) off += (size_t)n;
        }
        n = snprintf(body + off, sizeof(body) - off, "</tbody></table>");
        if (n > 0) off += (size_t)n;
        if (total > shown) {
            n = snprintf(body + off, sizeof(body) - off,
                "<p class='meta'>%zu more badge%s not shown (page cap "
                "%u).</p>", total - shown,
                total - shown == 1 ? "" : "s", ZCODE_VIEW_MAX_BADGES);
            if (n > 0) off += (size_t)n;
        }
    } else {
        n = snprintf(body + off, sizeof(body) - off,
            "<p>No badges earned yet.</p>");
        if (n > 0) off += (size_t)n;
    }
    n = snprintf(body + off, sizeof(body) - off,
        "<p><a href='/zcode'>&larr; ZCODE Library</a></p>");
    if (n > 0) off += (size_t)n;

    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_html_response(body, off, resp, max);
}
