/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Metaverse HTML site controller. See
 * controllers/metaverse_site_controller.h for the route list and the
 * truth / read-only discipline. Rendering lives in
 * contexts/explorer/views/src/metaverse_view{,_pages}.c; this file owns routing and the
 * projection reads — the SAME read paths the metaverse.* and
 * zcode.commons.* typed commands call. */

#include "controllers/metaverse_site_controller.h"

#include "views/metaverse_view.h"

#include "base/hex.h"
#include "command/native_command.h" /* zcl_native_node_db_*_readonly */
#include "models/database.h"        /* struct node_db */
#include "platform/time_compat.h"
#include "services/metaverse_space_service.h"
#include "services/property_catalog.h"
#include "util/log_macros.h"
#include "util/template.h" /* html_escape */
#include "util/util.h"     /* GetDataDir */
#include "vcs/space.h"
#include "vcs/zcode_commons_projection.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MS_LOG "metaverse.site"

/* Bounded workspace-CAS scan for the space page: the number of objects
 * inspected, never the number of objects present. */
#define MS_SPACE_SCAN_MAX 512u

/* ── small helpers ────────────────────────────────────────────────── */

static bool ms_path_eq(const char *path, const char *want)
{
    return path && strcmp(path, want) == 0;
}

/* Extract the bounded, decoded kind= value from a query string ("" when
 * absent). Kind names are lowercase [a-z_], so no percent-decoding is
 * needed: anything outside that alphabet simply fails the lookup. */
static void ms_query_kind(const char *query, char *out, size_t outmax)
{
    if (outmax)
        out[0] = '\0';
    if (!query || !outmax)
        return;
    const char *p = strstr(query, "kind=");
    if (!p)
        return;
    p += 5;
    size_t di = 0;
    while (p[di] && p[di] != '&' && di < outmax - 1) {
        out[di] = p[di];
        di++;
    }
    out[di] = '\0';
}

/* A minimal styled error page for projection failures (the named honest
 * failure — never an empty page that reads as "nothing exists"). */
static size_t ms_simple_error(const char *status, const char *title,
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
        "<p><a href='/metaverse'>&larr; Metaverse</a></p>"
        "</main></body></html>",
        safe_title, safe_title, safe_detail);
    if (n < 0)
        n = 0;
    return metaverse_error_response(status, body, (size_t)n, resp, max);
}

/* Resolve the datadir: the explicit argument wins; NULL resolves through
 * GetDataDir(true) (the HTTPS listener carries no datadir context). */
static bool ms_datadir(const char *datadir, char out[4400])
{
    if (datadir && datadir[0]) {
        int n = snprintf(out, 4400, "%s", datadir);
        return n > 0 && n < 4400;
    }
    GetDataDir(true, out, 4400);
    return out[0] != '\0';
}

/* ── the three shared reads ───────────────────────────────────────── */

/* The property catalog page for `datadir`, with the SAME guarded
 * read-only node.db open the metaverse.property.list command performs
 * (mv_catalog_sources_open in contexts/commons/controllers/src/metaverse_controller.c).
 * Returns true when the projection ran; on false `page` is freed and the
 * reply is the caller's error page. */
static bool ms_property_page(const char *datadir, enum metaverse_kind kind,
                             struct property_catalog_page **page_out,
                             char *err, size_t err_cap)
{
    struct property_catalog_query q;
    struct property_catalog_sources sources;
    struct sqlite3 *sql = NULL;
    struct node_db ndb;
    char source_reason[192];
    char db_path[1200];
    struct property_catalog_page *page;
    struct zcl_result r;

    *page_out = NULL;
    memset(&q, 0, sizeof(q));
    q.kind = kind;
    q.limit = METAVERSE_VIEW_MAX_ROWS;
    memset(&sources, 0, sizeof(sources));
    memset(&ndb, 0, sizeof(ndb));
    sources.chain_height = -1;
    source_reason[0] = '\0';

    enum zcl_node_db_ro_status st = zcl_native_node_db_open_readonly(
        datadir, &sql, &ndb, db_path, sizeof(db_path));
    if (st == ZCL_NODE_DB_RO_OK) {
        sources.node_db = &ndb;
    } else {
        switch (st) {
        case ZCL_NODE_DB_RO_ABSENT:
            snprintf(source_reason, sizeof(source_reason),
                     "no node.db at %.80s; chain-derived property registries "
                     "have not been folded and cannot be reported as empty",
                     db_path);
            break;
        case ZCL_NODE_DB_RO_UNRECOVERED_LOG:
            snprintf(source_reason, sizeof(source_reason),
                     "node.db has an unrecovered WAL and cannot be read "
                     "without creating a wal-index");
            break;
        case ZCL_NODE_DB_RO_PATH_TOO_LONG:
            snprintf(source_reason, sizeof(source_reason),
                     "node.db path is too long");
            break;
        case ZCL_NODE_DB_RO_UNREADABLE:
            snprintf(source_reason, sizeof(source_reason),
                     "node.db exists but is not readable as a SQLite "
                     "database");
            break;
        case ZCL_NODE_DB_RO_NO_DATADIR:
        default:
            snprintf(source_reason, sizeof(source_reason),
                     "no datadir resolved for node.db");
            break;
        }
        sources.node_db_unavailable_reason = source_reason;
    }

    page = property_catalog_page_new();
    if (!page) {
        zcl_native_node_db_close_readonly(&sql, &ndb);
        snprintf(err, err_cap, "the catalog page could not be allocated");
        LOG_FAIL(MS_LOG, "catalog page allocation for %s", datadir);
    }
    r = property_catalog_list_with_sources(datadir, &q, &sources, page);
    zcl_native_node_db_close_readonly(&sql, &ndb);
    if (!r.ok) {
        snprintf(err, err_cap,
                 "the property catalog projection failed: %.200s",
                 r.message[0] ? r.message : "unknown");
        property_catalog_page_free(page);
        LOG_ERROR(MS_LOG, "catalog projection failed for %s: %s", datadir,
                  r.message[0] ? r.message : "unknown");
        return false;
    }
    *page_out = page;
    return true;
}

/* One CAS object candidate under <workspace>/.zvcs/objects, asked through
 * the exact metaverse_space_show read path (re-parse + root re-derive). */
static bool ms_space_show(const char *workspace, const char *root_hex,
                          struct metaverse_space_object *out)
{
    struct zcl_result shown = metaverse_space_show(workspace, root_hex, out);
    return shown.ok;
}

struct ms_space_scan {
    struct metaverse_view_space_row rows[METAVERSE_VIEW_MAX_SPACES];
    size_t shown;
    size_t manifests;   /* total space_manifest.v1 objects identified */
    size_t services;    /* total service_descriptor.v1 objects */
    size_t scanned;
    bool truncated;
};

static int ms_space_row_cmp(const void *a, const void *b)
{
    const struct metaverse_view_space_row *ra = a, *rb = b;
    return strcmp(ra->root_hex, rb->root_hex);
}

/* Scan <workspace>/.zvcs/objects/<2-hex>/<62-hex>, bounded. Every
 * candidate goes through metaverse_space_show — the same read path the
 * metaverse.space.show command uses — so a wire that does not re-derive
 * its own address is simply not a space record. Rows are sorted by root
 * before rendering: readdir order is filesystem-dependent, and a page
 * that reshuffles between identical reads is unusable. */
static void ms_space_scan(const char *workspace, struct ms_space_scan *scan)
{
    char objects[4400];
    memset(scan, 0, sizeof(*scan));
    int n = snprintf(objects, sizeof(objects), "%s/.zvcs/objects",
                     workspace);
    if (n <= 0 || (size_t)n >= sizeof(objects)) {
        scan->truncated = true;
        return;
    }
    DIR *top = opendir(objects);
    if (!top)
        return; /* no store yet: honestly empty */
    uint64_t now = (uint64_t)platform_time_wall_unix();
    struct dirent *shard;
    while ((shard = readdir(top)) != NULL) {
        uint8_t hi;
        if (strlen(shard->d_name) != 2 ||
            !zcl_hex_decode_lower(shard->d_name, &hi, 1))
            continue;
        char shard_path[4400];
        n = snprintf(shard_path, sizeof(shard_path), "%s/%s", objects,
                     shard->d_name);
        if (n <= 0 || (size_t)n >= sizeof(shard_path))
            continue;
        DIR *dir = opendir(shard_path);
        if (!dir)
            continue;
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            uint8_t lo[31];
            if (strlen(ent->d_name) != 62 ||
                !zcl_hex_decode_lower(ent->d_name, lo, 31))
                continue;
            if (scan->scanned == MS_SPACE_SCAN_MAX) {
                scan->truncated = true;
                break;
            }
            scan->scanned++;
            char root_hex[65];
            snprintf(root_hex, sizeof(root_hex), "%s%s", shard->d_name,
                     ent->d_name);
            struct metaverse_space_object object;
            if (!ms_space_show(workspace, root_hex, &object))
                continue; /* some other CAS citizen, or corrupt: not a space */
            if (object.kind == METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR) {
                scan->services++;
                continue;
            }
            if (object.kind != METAVERSE_SPACE_OBJECT_MANIFEST)
                continue;
            scan->manifests++;
            if (scan->shown == METAVERSE_VIEW_MAX_SPACES) {
                scan->truncated = true;
                continue;
            }
            const struct vcs_space_manifest_v1 *m = &object.as.manifest;
            struct metaverse_view_space_row *row =
                &scan->rows[scan->shown++];
            memset(row, 0, sizeof(*row));
            snprintf(row->root_hex, sizeof(row->root_hex), "%s", root_hex);
            snprintf(row->name, sizeof(row->name), "%s", m->name);
            zcl_hex_encode(m->delegation.doc.master_pubkey, 32,
                           row->owner_hex);
            row->sequence = m->sequence;
            row->not_before = m->not_before;
            row->expiry = m->expiry;
            row->services = m->service_count;
            row->objects = m->object_count;
            row->portals = m->portal_count;
            row->has_admission = m->has_admission;
            /* The same activity probe metaverse.space.show runs (the
             * chain-authorization lens stays with the typed command; the
             * site reports the local-signature grade only). */
            row->currently_active = vcs_space_manifest_validate_at(
                m, m->delegation.network_genesis, now) == VCS_SPACE_OK;
        }
        closedir(dir);
        if (scan->truncated && scan->scanned == MS_SPACE_SCAN_MAX)
            break;
    }
    closedir(top);
    if (scan->shown > 1)
        qsort(scan->rows, scan->shown, sizeof(scan->rows[0]),
              ms_space_row_cmp);
}

static const char *ms_commons_status_name(
    enum vcs_zcode_commons_verification_status status)
{
    switch (status) {
    case VCS_ZCODE_COMMONS_PARTIAL:  return "partial";
    case VCS_ZCODE_COMMONS_COMPLETE: return "complete";
    default:                         return "unknown";
    }
}

/* ── /metaverse ─────────────────────────────────────────────────────── */

static size_t ms_handle_index(const char *datadir, const char *workspace,
                              uint8_t *resp, size_t max)
{
    struct metaverse_view_index_input in;
    memset(&in, 0, sizeof(in));
    in.commons_status = "unknown";

    struct property_catalog_page *page = NULL;
    char err[256];
    in.property_read = ms_property_page(datadir, METAVERSE_KIND_UNKNOWN,
                                        &page, err, sizeof(err));
    if (in.property_read) {
        in.property_total = page->total_across_kinds;
        in.property_kinds = page->kind_count;
        in.property_unavailable = page->unavailable_kinds;
        property_catalog_page_free(page);
    }

    struct ms_space_scan scan;
    ms_space_scan(workspace, &scan);
    in.space_read = true;
    in.space_manifests = scan.manifests;
    in.space_services = scan.services;

    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(workspace);
    if (projection) {
        in.commons_built = true;
        in.commons_status = ms_commons_status_name(
            vcs_zcode_commons_projection_status(projection));
        in.commons_creations =
            vcs_zcode_commons_projection_creation_count(projection);
        in.commons_epochs =
            vcs_zcode_commons_projection_epoch_count(projection);
        in.commons_minted_atoms =
            vcs_zcode_commons_projection_minted_atoms(projection);
        in.commons_attributed_atoms =
            vcs_zcode_commons_projection_attributed_atoms(projection);
        vcs_zcode_commons_projection_free(projection);
    }
    return metaverse_view_index(&in, resp, max);
}

/* ── /metaverse/property ──────────────────────────────────────────── */

static size_t ms_handle_property(const char *datadir, const char *query,
                                 uint8_t *resp, size_t max)
{
    char kind_name[64];
    ms_query_kind(query, kind_name, sizeof(kind_name));
    enum metaverse_kind kind = METAVERSE_KIND_UNKNOWN;
    if (kind_name[0]) {
        kind = metaverse_kind_from_name(kind_name);
        if (!metaverse_kind_valid(kind))
            return ms_simple_error("400 Bad Request", "unknown kind",
                                   "kind must be one of the property kinds "
                                   "the catalog enumerates",
                                   resp, max);
    }
    struct property_catalog_page *page = NULL;
    char err[256];
    if (!ms_property_page(datadir, kind, &page, err, sizeof(err)))
        return ms_simple_error("500 Internal Server Error",
                               "catalog unavailable", err, resp, max);
    size_t n = metaverse_view_property(page,
                                       kind_name[0] ? kind_name : NULL,
                                       resp, max);
    property_catalog_page_free(page);
    return n;
}

/* ── /metaverse/space ─────────────────────────────────────────────── */

static size_t ms_handle_space(const char *workspace, uint8_t *resp,
                              size_t max)
{
    struct ms_space_scan scan;
    ms_space_scan(workspace, &scan);
    return metaverse_view_space(scan.rows, scan.shown, scan.manifests,
                                scan.services, scan.scanned, scan.truncated,
                                resp, max);
}

/* ── /metaverse/commons ───────────────────────────────────────────── */

static size_t ms_handle_commons(const char *workspace, uint8_t *resp,
                                size_t max)
{
    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(workspace);
    if (!projection)
        return ms_simple_error("500 Internal Server Error",
                               "commons projection unavailable",
                               "the read-only CAS projection rebuild failed",
                               resp, max);
    size_t n = metaverse_view_commons(projection, resp, max);
    vcs_zcode_commons_projection_free(projection);
    return n;
}

/* ── router ─────────────────────────────────────────────────────────── */

size_t metaverse_site_handle_request(const char *method, const char *path,
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
    if (!ms_datadir(datadir, dd))
        return ms_simple_error("500 Internal Server Error",
                               "datadir unavailable",
                               "no data directory is configured",
                               response, response_max);
    char workspace[4400];
    int wn = snprintf(workspace, sizeof(workspace), "%s/zcode", dd);
    if (wn < 0 || (size_t)wn >= sizeof(workspace))
        return ms_simple_error("500 Internal Server Error",
                               "datadir too long",
                               "the datadir path exceeds the route budget",
                               response, response_max);

    if (ms_path_eq(route, "/metaverse") || ms_path_eq(route, "/metaverse/"))
        return ms_handle_index(dd, workspace, response, response_max);
    if (ms_path_eq(route, "/metaverse/property") ||
        ms_path_eq(route, "/metaverse/property/"))
        return ms_handle_property(dd, query, response, response_max);
    if (ms_path_eq(route, "/metaverse/space") ||
        ms_path_eq(route, "/metaverse/space/"))
        return ms_handle_space(workspace, response, response_max);
    if (ms_path_eq(route, "/metaverse/commons") ||
        ms_path_eq(route, "/metaverse/commons/"))
        return ms_handle_commons(workspace, response, response_max);
    return metaverse_view_route_not_found(route, response, response_max);
}
