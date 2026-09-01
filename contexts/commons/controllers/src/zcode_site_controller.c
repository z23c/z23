/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCODE Library HTML site controller (slice 13). See
 * controllers/zcode_site_controller.h for the route list and the truth /
 * safe-downloading discipline. Rendering lives in
 * contexts/explorer/views/src/zcode_view{,_pages}.c; this file owns routing, the
 * projection reads, and the CAS download path.
 *
 * Every read goes through the SAME contexts/commons/modules/vcs projections the zcode.* typed
 * commands call (package_index, the persisted release/manifest wires, the
 * reward ledger, the rank projection, the badge store, the node-global
 * swarm engine) — a one-shot CLI and this site render the same facts,
 * and there is no website database. */

#include "controllers/zcode_site_controller.h"

#include "views/zcode_view.h"

#include "base/hex.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/template.h" /* html_escape */
#include "util/util.h"     /* GetDataDir */
#include "vcs/package_attest.h"
#include "vcs/package_badge.h"
#include "vcs/package_contributor.h"
#include "vcs/package_index.h"
#include "vcs/package_manifest.h"
#include "vcs/package_rank.h"
#include "vcs/package_release.h"
#include "vcs/package_reward.h"
#include "vcs/package_swarm_node.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZS_LOG "zcode.site"

/* Bounded attestation dir scan (mirrors ZC_VERIFY_MAX_SCAN in
 * tools/command/native_zcode_command.c). */
#define ZS_ATTEST_MAX_SCAN 256u

/* ── small helpers ────────────────────────────────────────────────── */

static bool zs_path_eq(const char *path, const char *want)
{
    return path && strcmp(path, want) == 0;
}

static bool zs_copy_route_segment(char *out, size_t out_size,
                                  const char *input)
{
    size_t len = strcspn(input, "/");
    if (len == 0 || len >= out_size)
        return false;
    memcpy(out, input, len);
    out[len] = '\0';
    return true;
}

/* Percent/`+` decode (the name_site_controller convention). */
static void zs_url_decode(char *dst, size_t dstmax, const char *src,
                          size_t srclen)
{
    size_t di = 0;
    if (!dstmax)
        return;
    for (size_t si = 0; si < srclen && di < dstmax - 1; si++) {
        char c = src[si];
        if (c == '%' && si + 2 < srclen) {
            char h1 = src[si + 1], h2 = src[si + 2];
            int hi = zcl_hex_nibble(h1, true);
            int lo = zcl_hex_nibble(h2, true);
            if (hi >= 0 && lo >= 0) {
                dst[di++] = (char)((hi << 4) | lo);
                si += 2;
                continue;
            }
        }
        dst[di++] = (c == '+') ? ' ' : c;
    }
    dst[di] = '\0';
}

/* Extract the bounded, decoded q= value from a query string ("" when
 * absent). */
static void zs_query_keyword(const char *query, char *out, size_t outmax)
{
    if (outmax)
        out[0] = '\0';
    if (!query || !outmax)
        return;
    const char *p = strstr(query, "q=");
    if (!p)
        return;
    p += 2;
    size_t len = 0;
    while (p[len] && p[len] != '&')
        len++;
    zs_url_decode(out, outmax, p, len);
}

/* Read one bounded file fully (allocates *out; caller frees). False when
 * missing, unreadable, empty, or over cap (trailing bytes = not the exact
 * object) — the zc_read_object discipline from the publish command. */
static bool zs_read_object(const char *path, size_t cap, uint8_t **out,
                           size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    uint8_t *buf = zcl_malloc(cap, "zs_read_object");
    if (!buf) {
        fclose(f);
        return false;
    }
    size_t len = fread(buf, 1, cap, f);
    bool ok = !ferror(f) && feof(f) && len > 0;
    fclose(f);
    if (!ok) {
        free(buf);
        return false;
    }
    *out = buf;
    *out_len = len;
    return true;
}

/* A minimal styled error page for capacity/integrity failures (the named
 * honest failure — never a truncated payload or a silent 0). */
static size_t zs_simple_error(const char *status, const char *title,
                              const char *detail, uint8_t *resp, size_t max)
{
    char safe_title[128], safe_detail[256];
    html_escape(safe_title, sizeof(safe_title), title ? title : "error");
    html_escape(safe_detail, sizeof(safe_detail), detail ? detail : "");
    char body[2048];
    int n = snprintf(body, sizeof(body),
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<title>%s</title></head><body><main id='content'>"
        "<h1>%s</h1><p>%s</p>"
        "<p><a href='/zcode'>&larr; ZCODE Library</a></p>"
        "</main></body></html>",
        safe_title, safe_title, safe_detail);
    if (n < 0)
        n = 0;
    return zcode_error_response(status, body, (size_t)n, resp, max);
}

/* Resolve the datadir: the explicit argument wins; NULL resolves through
 * GetDataDir(true) (the HTTPS listener carries no datadir context). */
static bool zs_datadir(const char *datadir, char out[4400])
{
    if (datadir && datadir[0]) {
        int n = snprintf(out, 4400, "%s", datadir);
        return n > 0 && n < 4400;
    }
    GetDataDir(true, out, 4400);
    return out[0] != '\0';
}

/* ── /zcode ─────────────────────────────────────────────────────────── */

static size_t zs_handle_index(const char *zcode_dir, uint8_t *resp,
                              size_t max)
{
    size_t packages = 0;
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (index) {
        packages = vcs_package_index_count(index);
        vcs_package_index_free(index);
    }
    uint64_t facts = 0;
    struct vcs_reward_ledger *ledger = vcs_reward_ledger_load(zcode_dir);
    if (ledger) {
        facts = (uint64_t)vcs_reward_ledger_fact_count(ledger);
        vcs_reward_ledger_free(ledger);
    }
    size_t badges = 0;
    struct vcs_badge_store *store = vcs_badge_store_load(zcode_dir);
    if (store) {
        badges = vcs_badge_store_badge_count(store);
        vcs_badge_store_free(store);
    }
    return zcode_view_index(packages, facts, badges,
                            vcs_swarm_engine_global() != NULL, resp, max);
}

/* ── /zcode/packages ────────────────────────────────────────────────── */

static size_t zs_handle_packages(const char *zcode_dir, const char *query,
                                 uint8_t *resp, size_t max)
{
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index)
        return zs_simple_error("500 Internal Server Error",
                               "index unavailable",
                               "the package index could not be built",
                               resp, max);
    char keyword[64];
    zs_query_keyword(query, keyword, sizeof(keyword));
    struct vcs_package_search search = {0};
    if (keyword[0])
        search.keyword = keyword;
    const struct vcs_package_index_entry *rows[ZCODE_VIEW_MAX_ROWS];
    size_t total = vcs_package_index_search(index, &search, rows,
                                            ZCODE_VIEW_MAX_ROWS);
    size_t rendered = total < ZCODE_VIEW_MAX_ROWS ? total
                                                  : ZCODE_VIEW_MAX_ROWS;
    size_t scanned = vcs_package_index_count(index);
    size_t n = zcode_view_packages(rows, rendered, total, scanned,
                                   keyword[0] ? keyword : NULL, resp, max);
    vcs_package_index_free(index);
    return n;
}

/* ── /zcode/package/<root> ──────────────────────────────────────────── */

static size_t zs_handle_package(const char *zcode_dir, const char *root_hex,
                                uint8_t *resp, size_t max)
{
    uint8_t root[32];
    if (!zcl_hex_decode(root_hex, root, 32))
        return zcode_view_package_not_found(root_hex, resp, max);

    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index)
        return zs_simple_error("500 Internal Server Error",
                               "index unavailable",
                               "the package index could not be built",
                               resp, max);
    const struct vcs_package_index_entry *entry =
        vcs_package_index_find_root(index, root);
    if (!entry) {
        vcs_package_index_free(index);
        return zcode_view_package_not_found(root_hex, resp, max);
    }
    struct vcs_package_index_entry entry_copy = *entry;
    vcs_package_index_free(index);

    /* The persisted signed envelope (the publisher-signature surface). */
    struct vcs_package_release release;
    bool release_ok = false;
    char path[4500];
    snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir,
             entry_copy.release_id_hex);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (zs_read_object(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &wire,
                       &wire_len)) {
        release_ok = vcs_package_release_parse(wire, wire_len, &release) ==
                     VCS_PACKAGE_RELEASE_OK;
        free(wire);
    }

    /* The persisted manifest (the bounded file page). */
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool manifest_ok = false;
    if (entry_copy.manifest_present) {
        snprintf(path, sizeof(path), "%s/manifests/%s", zcode_dir,
                 entry_copy.package_root_hex);
        wire = NULL;
        wire_len = 0;
        if (zs_read_object(path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire,
                           &wire_len)) {
            manifest_ok = vcs_package_manifest_parse(wire, wire_len,
                                                     &manifest);
            free(wire);
        }
    }

    /* Verifier attestations naming this root (bounded scan; parse, filter
     * by package root — quorum evaluation stays with zcode.package.verify,
     * this page lists the attestation facts). */
    struct vcs_package_attest attests[ZCODE_VIEW_MAX_ATTESTS];
    size_t attest_shown = 0, attest_matching = 0, attest_scanned = 0;
    snprintf(path, sizeof(path), "%s/attestations", zcode_dir);
    DIR *dir = opendir(path);
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            uint8_t scratch[32];
            if (!zcl_hex_decode_lower(ent->d_name, scratch, 32))
                continue;
            if (attest_scanned == ZS_ATTEST_MAX_SCAN)
                break;
            attest_scanned++;
            char apath[4800];
            int an = snprintf(apath, sizeof(apath), "%s/%s", path,
                              ent->d_name);
            if (an < 0 || (size_t)an >= sizeof(apath))
                continue;
            wire = NULL;
            wire_len = 0;
            struct vcs_package_attest a;
            bool parsed = false;
            if (zs_read_object(apath, VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES,
                               &wire, &wire_len)) {
                parsed = vcs_package_attest_parse(wire, wire_len, &a) ==
                         VCS_PACKAGE_ATTEST_OK;
                free(wire);
            }
            if (!parsed || memcmp(a.package_root, root, 32) != 0)
                continue;
            attest_matching++;
            if (attest_shown < ZCODE_VIEW_MAX_ATTESTS)
                attests[attest_shown++] = a;
        }
        closedir(dir);
    }

    /* The local swarm view: how many peers currently advertise the root. */
    long advertisers = -1;
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    if (engine) {
        struct vcs_swarm_download_status st;
        if (vcs_swarm_engine_download_status(engine, root, &st))
            advertisers = (long)st.advertisers;
    }

    struct zcode_view_package_input in = {
        .entry = &entry_copy,
        .release = release_ok ? &release : NULL,
        .manifest = manifest_ok ? &manifest : NULL,
        .files_shown = manifest_ok
            ? (manifest.count < ZCODE_VIEW_MAX_FILES ? manifest.count
                                                     : ZCODE_VIEW_MAX_FILES)
            : 0,
        .attestations = attests,
        .attest_shown = attest_shown,
        .attest_matching = attest_matching,
        .attest_scanned = attest_scanned,
        .swarm_advertisers = advertisers,
    };
    size_t n = zcode_view_package(&in, resp, max);
    vcs_package_manifest_free(&manifest);
    return n;
}

/* ── /zcode/publisher/<pubkey> ──────────────────────────────────────── */

static size_t zs_handle_publisher(const char *zcode_dir,
                                  const char *publisher_hex, uint8_t *resp,
                                  size_t max)
{
    uint8_t pubkey[33];
    if (!zcl_hex_decode(publisher_hex, pubkey, 33))
        return zcode_view_publisher_not_found(publisher_hex, resp, max);

    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index)
        return zs_simple_error("500 Internal Server Error",
                               "index unavailable",
                               "the package index could not be built",
                               resp, max);
    struct vcs_zcode_contributor contributor;
    if (!vcs_zcode_contributor_from_index(index, publisher_hex,
                                          &contributor)) {
        vcs_package_index_free(index);
        return zcode_view_publisher_not_found(publisher_hex, resp, max);
    }
    struct vcs_package_search search = {0};
    search.publisher = publisher_hex;
    const struct vcs_package_index_entry *pkgs[ZCODE_VIEW_MAX_ROWS];
    size_t pkgs_total = vcs_package_index_search(index, &search, pkgs,
                                                 ZCODE_VIEW_MAX_ROWS);
    size_t pkgs_shown = pkgs_total < ZCODE_VIEW_MAX_ROWS
        ? pkgs_total : ZCODE_VIEW_MAX_ROWS;
    /* The search hands back pointers INTO the index's entry array, which
     * the free below releases — take value copies first, the same way
     * zs_handle_package does. The entry struct is fixed arrays and scalars
     * with no owned pointers, so assignment is a complete copy. */
    struct vcs_package_index_entry pkg_rows[ZCODE_VIEW_MAX_ROWS];
    for (size_t i = 0; i < pkgs_shown; i++) {
        pkg_rows[i] = *pkgs[i];
        pkgs[i] = &pkg_rows[i];
    }
    vcs_package_index_free(index);

    /* ZCODE Score: the settled reward-ledger totals (a separate fact from
     * the simulated token tally; never a balance). */
    struct vcs_reward_contributor_totals totals;
    struct vcs_reward_ledger *ledger = vcs_reward_ledger_load(zcode_dir);
    bool have_ledger = ledger != NULL;
    if (ledger)
        vcs_reward_contributor_totals(ledger, pubkey, &totals);

    /* All-time rank (the same projection zcode.leaderboard.all renders). */
    struct vcs_rank_entry rank_entry;
    bool ranked = false;
    if (ledger) {
        struct vcs_rank_window window;
        if (vcs_rank_window_for(VCS_RANK_PERIOD_ALL_TIME,
                                vcs_rank_day_from_unix(
                                    platform_time_wall_unix()),
                                &window)) {
            struct vcs_rank_projection *proj =
                vcs_rank_projection_build(ledger, &window);
            if (proj) {
                ranked = vcs_rank_contributor(proj, VCS_RANK_CATEGORY_OVERALL,
                                              pubkey, &rank_entry);
                vcs_rank_projection_free(proj);
            }
        }
    }
    if (ledger)
        vcs_reward_ledger_free(ledger);

    /* Earned badges (the operator policy lens when configured). */
    struct vcs_badge badges[ZCODE_VIEW_MAX_ROWS];
    size_t badges_total = 0, badges_shown = 0;
    bool policy_ok = false;
    struct vcs_badge_store *bstore = vcs_badge_store_load(zcode_dir);
    if (bstore) {
        struct vcs_badge_policy policy;
        policy_ok = vcs_badge_policy_load(zcode_dir, &policy);
        badges_total = vcs_badge_store_contributor_badges(
            bstore, policy_ok ? &policy : NULL, pubkey, badges,
            ZCODE_VIEW_MAX_ROWS);
        badges_shown = badges_total < ZCODE_VIEW_MAX_ROWS
            ? badges_total : ZCODE_VIEW_MAX_ROWS;
        vcs_badge_store_free(bstore);
    }

    struct zcode_view_publisher_input in = {
        .contributor = &contributor,
        .totals = have_ledger ? &totals : NULL,
        .rank = ranked ? &rank_entry : NULL,
        .badges = badges,
        .badges_shown = badges_shown,
        .badges_total = badges_total,
        .badge_policy = policy_ok,
        .packages = pkgs,
        .packages_shown = pkgs_shown,
        .packages_total = pkgs_total,
    };
    return zcode_view_publisher(&in, resp, max);
}

/* ── /zcode/leaderboard ─────────────────────────────────────────────── */

static size_t zs_handle_leaderboard(const char *zcode_dir,
                                    const char *period_str, uint8_t *resp,
                                    size_t max)
{
    enum vcs_rank_period period;
    if (zs_path_eq(period_str, "daily"))
        period = VCS_RANK_PERIOD_DAILY;
    else if (zs_path_eq(period_str, "weekly"))
        period = VCS_RANK_PERIOD_WEEKLY;
    else if (zs_path_eq(period_str, "monthly"))
        period = VCS_RANK_PERIOD_MONTHLY;
    else if (zs_path_eq(period_str, "all"))
        period = VCS_RANK_PERIOD_ALL_TIME;
    else
        return zcode_view_route_not_found(period_str, resp, max);

    struct vcs_rank_window window;
    if (!vcs_rank_window_for(period,
                             vcs_rank_day_from_unix(
                                 platform_time_wall_unix()),
                             &window))
        return zs_simple_error("500 Internal Server Error",
                               "window unavailable",
                               "the period window could not be computed",
                               resp, max);
    struct vcs_reward_ledger *ledger = vcs_reward_ledger_load(zcode_dir);
    if (!ledger)
        return zs_simple_error("500 Internal Server Error",
                               "ledger unavailable",
                               "the reward ledger could not be replayed",
                               resp, max);
    struct vcs_rank_projection *proj =
        vcs_rank_projection_build(ledger, &window);
    vcs_reward_ledger_free(ledger);
    if (!proj)
        return zs_simple_error("500 Internal Server Error",
                               "projection unavailable",
                               "the rank projection could not be built",
                               resp, max);
    struct vcs_rank_entry rows[VCS_RANK_MAX_PAGE_ROWS];
    size_t total = vcs_rank_table(proj, VCS_RANK_CATEGORY_OVERALL, rows,
                                  VCS_RANK_MAX_PAGE_ROWS);
    size_t shown = total < VCS_RANK_MAX_PAGE_ROWS ? total
                                                  : VCS_RANK_MAX_PAGE_ROWS;
    size_t n = zcode_view_leaderboard(
        period, &window, rows, shown, total,
        vcs_rank_projection_facts_used(proj),
        vcs_rank_projection_facts_dropped(proj),
        vcs_rank_projection_truncated(proj), resp, max);
    vcs_rank_projection_free(proj);
    return n;
}

/* ── /zcode/badges ──────────────────────────────────────────────────── */

static size_t zs_handle_badges(const char *zcode_dir, uint8_t *resp,
                               size_t max)
{
    struct vcs_badge_store *store = vcs_badge_store_load(zcode_dir);
    if (!store)
        return zs_simple_error("500 Internal Server Error",
                               "badge store unavailable",
                               "the badge store could not be replayed",
                               resp, max);
    struct vcs_badge_policy policy;
    bool policy_ok = vcs_badge_policy_load(zcode_dir, &policy);

    /* Rows: recognized badges when the operator policy lens is configured,
     * every signature-valid wire otherwise (the page says which). */
    struct vcs_badge badges[ZCODE_VIEW_MAX_BADGES];
    size_t shown = 0, total = 0;
    size_t count = vcs_badge_store_badge_count(store);
    for (size_t i = 0; i < count; i++) {
        const struct vcs_badge *b = vcs_badge_store_at(store, i);
        if (!b)
            continue;
        if (policy_ok && !vcs_badge_recognized(b, &policy))
            continue;
        total++;
        if (shown < ZCODE_VIEW_MAX_BADGES)
            badges[shown++] = *b;
    }
    size_t n = zcode_view_badges(badges, shown, total, policy_ok,
                                 vcs_badge_store_corrupt_count(store),
                                 vcs_badge_store_truncated(store),
                                 resp, max);
    vcs_badge_store_free(store);
    return n;
}

/* ── /zcode/download ────────────────────────────────────────────────── */

/* Serve the manifest wire as an attachment. */
static size_t zs_download_manifest(const char *zcode_dir,
                                   const char *root_hex, uint8_t *resp,
                                   size_t max)
{
    char path[4500];
    int n = snprintf(path, sizeof(path), "%s/manifests/%s", zcode_dir,
                     root_hex);
    if (n < 0 || (size_t)n >= sizeof(path))
        return zcode_view_package_not_found(root_hex, resp, max);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!zs_read_object(path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire,
                        &wire_len))
        return zcode_view_package_not_found(root_hex, resp, max);
    char filename[96];
    snprintf(filename, sizeof(filename), "zcode-manifest-%s.manifest",
             root_hex);
    size_t written = zcode_download_response(wire, wire_len, filename,
                                             resp, max);
    free(wire);
    if (written == 0)
        return zs_simple_error("503 Service Unavailable",
                               "response capacity exceeded",
                               "the manifest does not fit this transport's "
                               "response budget; nothing was sent",
                               resp, max);
    return written;
}

/* Serve one chunk as an attachment, rehashed against the manifest-
 * committed SHA3-256 before a single byte is emitted (the store's
 * rehash-on-read discipline). */
static size_t zs_download_chunk(const char *zcode_dir, const char *root_hex,
                                const char *file_str,
                                const char *chunk_str, uint8_t *resp,
                                size_t max)
{
    char *end = NULL;
    unsigned long file_index = strtoul(file_str, &end, 10);
    if (!end || *end != '\0' || file_index > 1000000UL)
        return zcode_view_package_not_found(root_hex, resp, max);
    end = NULL;
    unsigned long chunk_index = strtoul(chunk_str, &end, 10);
    if (!end || *end != '\0' || chunk_index > 64UL)
        return zcode_view_package_not_found(root_hex, resp, max);

    /* The manifest is the chunk-hash authority. */
    char path[4500];
    snprintf(path, sizeof(path), "%s/manifests/%s", zcode_dir, root_hex);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool parsed = false;
    if (zs_read_object(path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire,
                       &wire_len)) {
        parsed = vcs_package_manifest_parse(wire, wire_len, &manifest);
        free(wire);
    }
    if (!parsed || file_index >= manifest.count ||
        chunk_index >= manifest.files[file_index].chunk_count) {
        vcs_package_manifest_free(&manifest);
        return zcode_view_package_not_found(root_hex, resp, max);
    }
    const struct vcs_package_file *file = &manifest.files[file_index];
    uint8_t committed[32];
    memcpy(committed, file->chunk_hashes + chunk_index * 32, 32);
    vcs_package_manifest_free(&manifest);

    /* Read the CAS object named by the committed hash. */
    char hash_hex[65];
    zcl_hex_encode(committed, 32, hash_hex);
    snprintf(path, sizeof(path), "%s/cas/sha3/%02x/%s", zcode_dir,
             committed[0], hash_hex);
    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    if (!zs_read_object(path, VCS_PACKAGE_CHUNK_BYTES, &bytes, &bytes_len))
        return zs_simple_error("404 Not Found", "chunk not hosted",
                               "the chunk is committed by the manifest but "
                               "not present in this node's CAS",
                               resp, max);

    /* Rehash-on-read: serve only bytes that hash to the committed value. */
    uint8_t actual[32];
    if (!vcs_package_chunk_hash(bytes, bytes_len, actual) ||
        memcmp(actual, committed, 32) != 0) {
        free(bytes);
        LOG_ERROR(ZS_LOG, "CAS integrity failure serving %s chunk %lu/%lu: "
                "stored bytes do not hash to the committed value",
                root_hex, file_index, chunk_index);
        return zs_simple_error("500 Internal Server Error",
                               "CAS integrity failure",
                               "the stored chunk bytes do not hash to the "
                               "manifest-committed value; nothing was sent",
                               resp, max);
    }

    char filename[112];
    snprintf(filename, sizeof(filename), "zcode-chunk-%.8s-%lu-%lu.bin",
             root_hex, file_index, chunk_index);
    size_t written = zcode_download_response(bytes, bytes_len, filename,
                                             resp, max);
    free(bytes);
    if (written == 0)
        return zs_simple_error("503 Service Unavailable",
                               "response capacity exceeded",
                               "the chunk does not fit this transport's "
                               "response budget; fetch it via the swarm "
                               "instead — nothing was sent",
                               resp, max);
    return written;
}

static size_t zs_handle_download(const char *zcode_dir, const char *rest,
                                 uint8_t *resp, size_t max)
{
    /* rest: "<64hex>" (manifest) or "<64hex>/<file>/<chunk>" (chunk). */
    char root_hex[80];
    if (!zs_copy_route_segment(root_hex, sizeof(root_hex), rest))
        return zcode_view_package_not_found("invalid", resp, max);
    const char *slash = strchr(rest, '/');

    uint8_t root[32];
    if (!zcl_hex_decode(root_hex, root, 32))
        return zcode_view_package_not_found(root_hex, resp, max);

    if (!slash)
        return zs_download_manifest(zcode_dir, root_hex, resp, max);

    /* Chunk form: the remainder must be exactly <file>/<chunk>. */
    const char *file_str = slash + 1;
    char coords[64];
    if (strlen(file_str) >= sizeof(coords))
        return zcode_view_package_not_found(root_hex, resp, max);
    memcpy(coords, file_str, strlen(file_str) + 1);
    char *csep = strchr(coords, '/');
    if (!csep)
        return zcode_view_package_not_found(root_hex, resp, max);
    *csep = '\0';
    const char *chunk_str = csep + 1;
    if (strchr(chunk_str, '/') || !coords[0] || !chunk_str[0])
        return zcode_view_package_not_found(root_hex, resp, max);
    return zs_download_chunk(zcode_dir, root_hex, coords, chunk_str,
                             resp, max);
}

/* ── router ─────────────────────────────────────────────────────────── */

size_t zcode_site_handle_request(const char *method, const char *path,
                                 const uint8_t *body, size_t body_len,
                                 uint8_t *response, size_t response_max,
                                 const char *datadir)
{
    (void)method;  /* read-only surface: GET and HEAD render identically */
    (void)body;
    (void)body_len;
    if (!path || !response)
        return 0;

    /* Split the route from the query string (bounded copy). */
    char route[1024];
    size_t rlen = 0;
    while (path[rlen] && path[rlen] != '?' && rlen < sizeof(route) - 1) {
        route[rlen] = path[rlen];
        rlen++;
    }
    route[rlen] = '\0';
    const char *query = path[rlen] == '?' ? path + rlen + 1 : NULL;

    char dd[4400];
    if (!zs_datadir(datadir, dd))
        return zs_simple_error("500 Internal Server Error",
                               "datadir unavailable",
                               "no data directory is configured",
                               response, response_max);
    char zcode_dir[4400];
    int zn = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);
    if (zn < 0 || (size_t)zn >= sizeof(zcode_dir))
        return zs_simple_error("500 Internal Server Error",
                               "datadir too long",
                               "the datadir path exceeds the route budget",
                               response, response_max);

    if (zs_path_eq(route, "/zcode") || zs_path_eq(route, "/zcode/"))
        return zs_handle_index(zcode_dir, response, response_max);
    if (zs_path_eq(route, "/zcode/packages") ||
        zs_path_eq(route, "/zcode/contexts/commons/packages/"))
        return zs_handle_packages(zcode_dir, query, response, response_max);
    if (strncmp(route, "/zcode/package/", 15) == 0) {
        const char *root_hex = route + 15;
        char rh[80];
        if (!zs_copy_route_segment(rh, sizeof(rh), root_hex))
            return zcode_view_package_not_found("invalid", response,
                                                response_max);
        return zs_handle_package(zcode_dir, rh, response, response_max);
    }
    if (strncmp(route, "/zcode/publisher/", 17) == 0) {
        const char *pub_hex = route + 17;
        char ph[80];
        if (!zs_copy_route_segment(ph, sizeof(ph), pub_hex))
            return zcode_view_route_not_found(route, response, response_max);
        return zs_handle_publisher(zcode_dir, ph, response, response_max);
    }
    if (zs_path_eq(route, "/zcode/leaderboard") ||
        zs_path_eq(route, "/zcode/leaderboard/"))
        return zcode_view_leaderboard_index(response, response_max);
    if (strncmp(route, "/zcode/leaderboard/", 19) == 0) {
        const char *period = route + 19;
        char ps[24];
        if (!zs_copy_route_segment(ps, sizeof(ps), period))
            return zcode_view_route_not_found(route, response, response_max);
        return zs_handle_leaderboard(zcode_dir, ps, response, response_max);
    }
    if (zs_path_eq(route, "/zcode/badges") ||
        zs_path_eq(route, "/zcode/badges/"))
        return zs_handle_badges(zcode_dir, response, response_max);
    if (strncmp(route, "/zcode/download/", 16) == 0)
        return zs_handle_download(zcode_dir, route + 16, response,
                                  response_max);
    return zcode_view_route_not_found(route, response, response_max);
}
