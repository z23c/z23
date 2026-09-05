/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCODE Library HTML site views (slice 13) — page shell, HTTP wrappers,
 * the landing page, the package search page, and the honest 404 pages.
 * See views/zcode_view.h for the contract; the detail pages (package,
 * publisher, leaderboard, badges) live in zcode_view_pages.c to stay
 * under the file-size ceiling. */

#include "views/zcode_view_internal.h"
#include "util/template.h" /* html_escape */
#include "util/log_macros.h"

#include <limits.h>

/* ── HTTP wrappers ────────────────────────────────────────────────── */

static size_t zcode_wrap_response(const char *body, size_t body_len,
                                  const char *status, uint8_t *resp,
                                  size_t max)
{
    if (!resp || max == 0 || !body || body_len > INT_MAX) {
        LOG_ERROR("zcode.site", "invalid HTML response or body bound");
        return 0;
    }
    int n = snprintf((char *)resp, max,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "%.*s",
        status, body_len, (int)body_len, body);
    if (n < 0 || (size_t)n >= max) {
        LOG_ERROR("zcode.site", "HTML response exceeds transport capacity");
        resp[0] = 0;
        return 0;
    }
    return (size_t)n;
}

size_t zcode_html_response(const char *body, size_t body_len,
                           uint8_t *resp, size_t max)
{
    return zcode_wrap_response(body, body_len, "200 OK", resp, max);
}

size_t zcode_error_response(const char *status_code,
                            const char *body, size_t body_len,
                            uint8_t *resp, size_t max)
{
    return zcode_wrap_response(body, body_len, status_code, resp, max);
}

size_t zcode_download_response(const uint8_t *body, size_t body_len,
                               const char *download_filename,
                               uint8_t *resp, size_t max)
{
    if (!resp || max == 0 || (!body && body_len > 0))
        return 0;

    /* Header-injection guard: keep only [A-Za-z0-9._-] in the filename
     * (the controller only ever passes hex-derived names, but the header
     * must stay well-formed for any caller). */
    char safe_name[80];
    size_t j = 0;
    if (download_filename) {
        for (size_t i = 0; download_filename[i] &&
                            j < sizeof(safe_name) - 1; i++) {
            char c = download_filename[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
                safe_name[j++] = c;
        }
    }
    safe_name[j] = '\0';

    int hdr_len = snprintf((char *)resp, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: engine/application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        safe_name[0] ? safe_name : "zcode-download.bin", body_len);
    if (hdr_len < 0 || (size_t)hdr_len >= max)
        return 0;
    if (body_len > max - (size_t)hdr_len)
        return 0; /* never a truncated payload */
    if (body_len > 0)
        memcpy(resp + hdr_len, body, body_len);
    return (size_t)hdr_len + body_len;
}

/* ── /zcode — landing ─────────────────────────────────────────────── */

size_t zcode_view_index(size_t packages, uint64_t settled_facts,
                        size_t badges, bool swarm_live,
                        uint8_t *resp, size_t max)
{
    char body[16384];
    size_t off = 0;
    int n = zcode_body_start(body, sizeof(body), "Exact C23 software");
    if (n > 0) off = (size_t)n;

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Build, verify, and share exact C23 software</h1>"
        "<p>Open a package, understand the exact version this node has, "
        "inspect its evidence, and decide whether to use or share it. "
        "Runnable examples and change tools appear only when their exact "
        "package facts exist; this site never guesses behavior.</p>"
        "<p><a class='btn' href='/zcode/packages'>Browse exact packages</a>"
        "</p>"
        "<div class='grid'>"
        "<div class='card'><h2><a href='/zcode/packages'>Packages</a></h2>"
        "<div class='kv'><b>published releases</b>"
        "<span class='val'>%zu</span></div>"
        "<p>Understand, verify, obtain, and share content-addressed C23 "
        "releases from this node.</p></div>"
        "<div class='card'><h2>Independent evidence</h2>"
        "<p>Package pages show the exact source identity and every local "
        "verifier attestation. Missing evidence is shown as missing.</p>"
        "</div></div>"
        "<h2>Community signals <span class='pill'>SIMULATION</span></h2>"
        "<p class='meta'>Scores, rankings, and rewards are simulations; no "
        "live ZCODE token exists. They never replace package evidence.</p>"
        "<div class='grid'>"
        "<div class='card'><h3><a href='/zcode/leaderboard'>Rankings</a></h3>"
        "<div class='kv'><b>settled score facts</b>"
        "<span class='val'>%llu</span></div>"
        "<p>Daily, weekly, monthly and all-time ZCODE Rankings &mdash; "
        "earned score, never a token balance.</p></div>"
        "<div class='card'><h3><a href='/zcode/badges'>Badges</a></h3>"
        "<div class='kv'><b>earned badges</b>"
        "<span class='val'>%zu</span></div>"
        "<p>Permanent, signed contributor badges.</p></div>"
        "<div class='card'><h3>Availability</h3>"
        "<div class='kv'><b>local swarm</b><span class='val'>%s</span></div>"
        "<p>Package pages show how many peers currently advertise a "
        "package in this node's local swarm view.</p></div>"
        "</div>",
        packages, (unsigned long long)settled_facts, badges,
        swarm_live ? "running" : "not running (one-shot view)");
    if (n > 0) off += (size_t)n;

    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_html_response(body, off, resp, max);
}

/* ── /zcode/packages — search ─────────────────────────────────────── */

size_t zcode_view_packages(const struct vcs_package_index_entry **rows,
                           size_t rendered, size_t total, size_t scanned,
                           const char *query, uint8_t *resp, size_t max)
{
    char body[36864];
    size_t off = 0;
    int n = zcode_body_start(body, sizeof(body), "ZCODE Packages");
    if (n > 0) off = (size_t)n;

    char safe_query[96];
    safe_query[0] = '\0';
    if (query && query[0])
        html_escape(safe_query, sizeof(safe_query), query);

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Packages</h1>"
        "<form method='get' action='/zcode/packages'>"
        "<input type='text' name='q' value='%s' "
        "placeholder='search package names'>"
        "<button type='submit' class='btn'>Search</button></form>",
        safe_query);
    if (n > 0) off += (size_t)n;

    if (query && query[0]) {
        n = snprintf(body + off, sizeof(body) - off,
            "<p>%zu match%s for <b>%s</b> (%zu shown, %zu packages "
            "scanned).</p>",
            total, total == 1 ? "" : "es", safe_query, rendered, scanned);
    } else {
        n = snprintf(body + off, sizeof(body) - off,
            "<p>%zu published release%s (%zu shown).%s</p>",
            total, total == 1 ? "" : "s", rendered,
            total == 0 ? " Publish your first package: "
                         "`z23 zcode guide`." : "");
    }
    if (n > 0) off += (size_t)n;

    for (size_t i = 0; i < rendered && off < sizeof(body) - 1024; i++) {
        const struct vcs_package_index_entry *e = rows[i];
        char safe_name[160], safe_semver[80], safe_license[48];
        char safe_znam[80];
        html_escape(safe_name, sizeof(safe_name), e->name);
        html_escape(safe_semver, sizeof(safe_semver), e->semver);
        html_escape(safe_license, sizeof(safe_license), e->license);
        safe_znam[0] = '\0';
        if (e->has_znam)
            html_escape(safe_znam, sizeof(safe_znam), e->znam);
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='card'>"
            "<h3><a href='/zcode/package/%s'>%s</a> "
            "<span class='pill'>%s</span></h3>"
            "<div class='kv'><b>license</b>"
            "<span class='val mono'>%s</span></div>"
            "<div class='kv'><b>publisher</b><span class='val mono'>"
            "<a href='/zcode/publisher/%s'>%.16s&hellip;</a></span></div>"
            "<div class='kv'><b>package root</b>"
            "<span class='val mono'>%.16s&hellip;</span></div>"
            "<div class='kv'><b>files</b><span class='val'>%u</span></div>"
            "<div class='kv'><b>bytes</b><span class='val'>%llu</span></div>",
            e->package_root_hex, safe_name, safe_semver, safe_license,
            e->publisher_hex, e->publisher_hex, e->package_root_hex,
            e->file_count, (unsigned long long)e->total_bytes);
        if (n > 0) off += (size_t)n;
        if (e->has_znam) {
            n = snprintf(body + off, sizeof(body) - off,
                "<div class='kv'><b>znam pointer</b>"
                "<span class='val mono'>%s</span></div>", safe_znam);
            if (n > 0) off += (size_t)n;
        }
        n = snprintf(body + off, sizeof(body) - off, "</div>");
        if (n > 0) off += (size_t)n;
    }
    if (total > rendered) {
        n = snprintf(body + off, sizeof(body) - off,
            "<p class='meta'>%zu more match%s not shown (page cap %u).</p>",
            total - rendered, total - rendered == 1 ? "" : "es",
            ZCODE_VIEW_MAX_ROWS);
        if (n > 0) off += (size_t)n;
    }

    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_html_response(body, off, resp, max);
}

/* ── honest 404 pages ─────────────────────────────────────────────── */

size_t zcode_view_route_not_found(const char *path, uint8_t *resp,
                                  size_t max)
{
    char body[16384];
    size_t off = 0;
    int n = zcode_body_start(body, sizeof(body), "ZCODE route not found");
    if (n > 0) off = (size_t)n;
    char safe_path[256];
    html_escape(safe_path, sizeof(safe_path), path ? path : "");
    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Unknown ZCODE route</h1>"
        "<div class='card'>"
        "<p><code>%s</code> is not a ZCODE site route.</p>"
        "<p>Routes: <code>/zcode</code>, <code>/zcode/packages</code>, "
        "<code>/zcode/package/&lt;package-root&gt;</code>, "
        "<code>/zcode/publisher/&lt;publisher-key&gt;</code>, "
        "<code>/zcode/leaderboard/daily|weekly|monthly|all</code>, "
        "<code>/zcode/badges</code>, "
        "<code>/zcode/download/&lt;package-root&gt;</code>.</p>"
        "<p><a href='/zcode'>&larr; ZCODE Library</a></p></div>",
        safe_path);
    if (n > 0) off += (size_t)n;
    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_error_response("404 Not Found", body, off, resp, max);
}

size_t zcode_view_package_not_found(const char *root_hex, uint8_t *resp,
                                    size_t max)
{
    char body[16384];
    size_t off = 0;
    int n = zcode_body_start(body, sizeof(body), "Package not found");
    if (n > 0) off = (size_t)n;
    char safe_root[80];
    html_escape(safe_root, sizeof(safe_root), root_hex ? root_hex : "");
    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Package not found</h1>"
        "<div class='card'>"
        "<p>No published release in this node's package store names "
        "package root <span class='mono'>%s</span>. The store is the only "
        "package truth &mdash; a package this node does not host is "
        "reported as absent, never invented.</p>"
        "<p><a href='/zcode/packages'>&larr; all packages</a></p></div>",
        safe_root);
    if (n > 0) off += (size_t)n;
    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_error_response("404 Not Found", body, off, resp, max);
}

size_t zcode_view_publisher_not_found(const char *publisher_hex,
                                      uint8_t *resp, size_t max)
{
    char body[16384];
    size_t off = 0;
    int n = zcode_body_start(body, sizeof(body), "Publisher not found");
    if (n > 0) off = (size_t)n;
    char safe_pub[80];
    html_escape(safe_pub, sizeof(safe_pub),
                publisher_hex ? publisher_hex : "");
    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Publisher not found</h1>"
        "<div class='card'>"
        "<p>Publisher key <span class='mono'>%s</span> has never published "
        "a release this node hosts.</p>"
        "<p><a href='/zcode/packages'>&larr; all packages</a></p></div>",
        safe_pub);
    if (n > 0) off += (size_t)n;
    n = zcode_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return zcode_error_response("404 Not Found", body, off, resp, max);
}
