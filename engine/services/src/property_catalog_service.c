/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The property catalog projection. See services/property_catalog.h for the
 * contract and the three rules it enforces (projection not truth, read-only
 * including on open, no silent omissions).
 *
 * Layout: context construction, then the per-kind sweep over the adapter
 * registry, then the JSON rendering. The kind list appears nowhere in this
 * file — it is walked through metaverse_adapter_at(), so a kind added to
 * METAVERSE_KIND_TABLE shows up here automatically (as an unavailable row
 * until its adapter is wired) and can never be forgotten. */

#include "services/property_catalog.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "models/zslp.h"
#include "models/znam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PC_LOG "services.property_catalog"
#define PC_ZCODE_DIR_MAX 4400

struct property_catalog_page *property_catalog_page_new(void)
{
    struct property_catalog_page *page =
        zcl_calloc(1, sizeof(*page), "property_catalog_page");

    if (!page)
        LOG_NULL(PC_LOG, "catalog page of %zu bytes", sizeof(*page));
    return page;
}

void property_catalog_page_free(struct property_catalog_page *page)
{
    free(page);
}

/* Build the adapter context.  Offline native commands supply a guarded
 * read-only node.db handle, while a live in-process caller may additionally
 * supply its tip height/work.  This service never discovers either on its
 * own: when the tip is absent ZNAM still projects the registration height,
 * and metaverse_work_measure() states `no_tip` rather than manufacturing a
 * confirmation count. */
static enum metaverse_source_lookup pc_znam_find(void *opaque,
    const uint8_t registration_root[METAVERSE_ROOT_BYTES],
    struct metaverse_znam_record *out)
{
    struct znam_entry entry;
    int found;

    if (!opaque || !registration_root || !out)
        return METAVERSE_SOURCE_ERROR;
    memset(&entry, 0, sizeof(entry));
    found = db_znam_find_by_reg_txid(opaque, registration_root, &entry);
    if (found < 0)
        return METAVERSE_SOURCE_ERROR;
    if (found == 0)
        return METAVERSE_SOURCE_ABSENT;
    memset(out, 0, sizeof(*out));
    snprintf(out->name, sizeof(out->name), "%s", entry.name);
    snprintf(out->owner, sizeof(out->owner), "%s", entry.owner_address);
    memcpy(out->registration_root, entry.reg_txid,
           sizeof(out->registration_root));
    memcpy(out->last_update_root, entry.last_update_txid,
           sizeof(out->last_update_root));
    out->registration_height = entry.reg_height;
    out->expiry_height = entry.expiry_height;
    return METAVERSE_SOURCE_FOUND;
}

static bool pc_znam_list(void *opaque, struct metaverse_znam_record *out,
                         size_t out_cap, size_t *written_out,
                         size_t *total_out, bool *truncated_out)
{
    struct node_db *ndb = opaque;
    struct znam_entry entries[PROPERTY_CATALOG_PAGE_MAX];
    size_t total = 0;
    size_t want;
    int got;

    if (written_out)
        *written_out = 0;
    if (total_out)
        *total_out = 0;
    if (truncated_out)
        *truncated_out = false;
    if (!ndb || !written_out || !total_out || !truncated_out ||
        (!out && out_cap > 0) || out_cap > PROPERTY_CATALOG_PAGE_MAX)
        LOG_FAIL(PC_LOG, "ZNAM list source received invalid bounds/outputs");
    if (!db_znam_count(ndb, &total))
        LOG_FAIL(PC_LOG, "canonical ZNAM registry count failed");
    *total_out = total;
    if (out_cap == 0) {
        *truncated_out = total > 0;
        return true;
    }
    want = total < out_cap ? total : out_cap;
    got = db_znam_list(ndb, entries, want);
    if (got < 0 || (size_t)got != want) {
        *truncated_out = true;
        return false;
    }
    for (size_t i = 0; i < (size_t)got; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        snprintf(out[i].name, sizeof(out[i].name), "%s", entries[i].name);
        snprintf(out[i].owner, sizeof(out[i].owner), "%s",
                 entries[i].owner_address);
        memcpy(out[i].registration_root, entries[i].reg_txid,
               sizeof(out[i].registration_root));
        memcpy(out[i].last_update_root, entries[i].last_update_txid,
               sizeof(out[i].last_update_root));
        out[i].registration_height = entries[i].reg_height;
        out[i].expiry_height = entries[i].expiry_height;
    }
    *written_out = (size_t)got;
    *truncated_out = (size_t)got < total;
    return true;
}

static bool pc_zslp_copy(const struct db_zslp_token_info *token,
                         struct metaverse_zslp_record *out)
{
    if (!token || !out ||
        !zcl_hex_decode(token->token_id, out->genesis_root,
                        sizeof(out->genesis_root)))
        return false;
    snprintf(out->ticker, sizeof(out->ticker), "%s", token->ticker);
    snprintf(out->name, sizeof(out->name), "%s", token->name);
    out->genesis_height = token->genesis_height;
    out->decimals = token->decimals;
    out->total_minted = token->total_minted;
    return true;
}

static enum metaverse_source_lookup pc_zslp_find(
    void *opaque, const uint8_t genesis_root[METAVERSE_ROOT_BYTES],
    struct metaverse_zslp_record *out)
{
    struct db_zslp_token_info token;
    int found;

    if (!opaque || !genesis_root || !out)
        return METAVERSE_SOURCE_ERROR;
    memset(&token, 0, sizeof(token));
    memset(out, 0, sizeof(*out));
    found = db_zslp_asset_lookup(opaque, genesis_root, &token);
    if (found < 0)
        return METAVERSE_SOURCE_ERROR;
    if (found == 0)
        return METAVERSE_SOURCE_ABSENT;
    return pc_zslp_copy(&token, out) ? METAVERSE_SOURCE_FOUND
                                     : METAVERSE_SOURCE_ERROR;
}

static bool pc_zslp_list(void *opaque, struct metaverse_zslp_record *out,
                         size_t out_cap, size_t *written_out,
                         size_t *total_out, bool *truncated_out)
{
    struct node_db *ndb = opaque;
    struct db_zslp_token_info tokens[PROPERTY_CATALOG_PAGE_MAX];
    size_t total = 0;
    size_t want;
    int got;

    if (written_out)
        *written_out = 0;
    if (total_out)
        *total_out = 0;
    if (truncated_out)
        *truncated_out = false;
    if (!ndb || !written_out || !total_out || !truncated_out ||
        (!out && out_cap > 0) || out_cap > PROPERTY_CATALOG_PAGE_MAX)
        LOG_FAIL(PC_LOG, "ZSLP list source received invalid bounds/outputs");
    if (!db_zslp_asset_count(ndb, &total))
        LOG_FAIL(PC_LOG, "canonical ZSLP asset count failed");
    *total_out = total;
    if (out_cap == 0) {
        *truncated_out = total > 0;
        return true;
    }
    want = total < out_cap ? total : out_cap;
    got = db_zslp_asset_list(ndb, tokens, want);
    if (got < 0 || (size_t)got != want) {
        *truncated_out = true;
        return false;
    }
    for (size_t i = 0; i < (size_t)got; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        if (!pc_zslp_copy(&tokens[i], &out[i])) {
            *truncated_out = true;
            return false;
        }
    }
    *written_out = (size_t)got;
    *truncated_out = (size_t)got < total;
    return true;
}

static bool pc_ctx_init(struct metaverse_adapter_ctx *ctx, const char *datadir,
                        char *zcode_dir, size_t zcode_dir_cap,
                        const struct property_catalog_sources *sources,
                        struct metaverse_znam_source *znam_source,
                        struct metaverse_zslp_source *zslp_source)
{
    int n = snprintf(zcode_dir, zcode_dir_cap, "%s/zcode", datadir);

    if (n < 0 || (size_t)n >= zcode_dir_cap)
        return false;
    memset(ctx, 0, sizeof(*ctx));
    ctx->datadir      = datadir;
    ctx->zcode_dir    = zcode_dir;
    ctx->chain_height = sources ? sources->chain_height : -1;
    ctx->chain_work   = sources ? sources->chain_work : NULL;
    memset(znam_source, 0, sizeof(*znam_source));
    if (sources && sources->node_db) {
        znam_source->opaque = sources->node_db;
        znam_source->find_registration = pc_znam_find;
        znam_source->list = pc_znam_list;
    } else {
        znam_source->unavailable_reason =
            sources && sources->node_db_unavailable_reason
                ? sources->node_db_unavailable_reason
                : "no safe read-only node.db handle was supplied for ZNAM";
    }
    ctx->znam = znam_source;
    memset(zslp_source, 0, sizeof(*zslp_source));
    if (sources && sources->node_db) {
        zslp_source->opaque = sources->node_db;
        zslp_source->find_genesis = pc_zslp_find;
        zslp_source->list = pc_zslp_list;
    } else {
        zslp_source->unavailable_reason =
            sources && sources->node_db_unavailable_reason
                ? sources->node_db_unavailable_reason
                : "no safe read-only node.db handle was supplied for ZSLP";
    }
    ctx->zslp = zslp_source;
    return true;
}

static void pc_row_begin(struct property_catalog_kind_row *row,
                         const struct metaverse_adapter *adapter)
{
    memset(row, 0, sizeof(*row));
    row->kind             = adapter->kind;
    row->kind_name        = metaverse_kind_name(adapter->kind);
    row->authority_source = metaverse_kind_authority(adapter->kind);
    row->settlement       = metaverse_kind_settlement(adapter->kind);
    row->available        = metaverse_adapter_ready(adapter);
    row->unavailable_reason =
        row->available ? "" : (adapter->unavailable_reason
                                   ? adapter->unavailable_reason
                                   : "adapter row has no reader and no reason");
}

struct zcl_result property_catalog_list_with_sources(
    const char *datadir, const struct property_catalog_query *q,
    const struct property_catalog_sources *sources,
    struct property_catalog_page *out)
{
    struct metaverse_adapter_ctx ctx;
    struct metaverse_znam_source znam_source;
    struct metaverse_zslp_source zslp_source;
    char zcode_dir[PC_ZCODE_DIR_MAX];
    enum metaverse_kind filter = METAVERSE_KIND_UNKNOWN;
    size_t limit = PROPERTY_CATALOG_PAGE_MAX;
    size_t rows;

    if (!out)
        return ZCL_ERR(-1, "property_catalog_list: NULL out");
    memset(out, 0, sizeof(*out));
    out->store_read = true;
    out->integrity_ok = true;
    if (!datadir || !*datadir)
        return ZCL_ERR(-2, "property_catalog_list: datadir is %s",
                       datadir ? "empty" : "NULL");
    if (q) {
        if (q->kind != METAVERSE_KIND_UNKNOWN &&
            !metaverse_kind_valid(q->kind))
            return ZCL_ERR(-3, "property_catalog_list: kind %d is not a "
                               "property kind", (int)q->kind);
        filter = q->kind;
        if (q->limit && q->limit < limit)
            limit = q->limit;
    }
    if (!pc_ctx_init(&ctx, datadir, zcode_dir, sizeof(zcode_dir), sources,
                     &znam_source, &zslp_source))
        return ZCL_ERR(-4, "property_catalog_list: datadir path too long "
                           "(%zu bytes)", strlen(datadir));

    rows = metaverse_adapter_count();
    for (size_t i = 0; i < rows; i++) {
        const struct metaverse_adapter *adapter = metaverse_adapter_at(i);
        struct property_catalog_kind_row *row;
        size_t room;
        struct metaverse_adapter_list_report report;

        if (!adapter)
            return ZCL_ERR(-5, "property_catalog_list: adapter row %zu is "
                               "missing — a kind may not drop out of the "
                               "catalog silently", i);
        if (out->kind_count >= METAVERSE_KIND_COUNT)
            return ZCL_ERR(-6, "property_catalog_list: more adapter rows "
                               "than property kinds");
        row = &out->kinds[out->kind_count++];
        pc_row_begin(row, adapter);

        /* A filtered-out kind still gets its row, marked as not scanned:
         * the reader must be able to tell "we did not look" from "there is
         * nothing there". */
        if (filter != METAVERSE_KIND_UNKNOWN && adapter->kind != filter) {
            row->available = false;
            row->unavailable_reason = "not scanned: excluded by the kind "
                                      "filter";
            continue;
        }
        if (!row->available)
            continue;

        /* Ask whether the authority can be READ before asking what it
         * holds. A store that is present and unopenable must not come
         * back through the counting path, because every count there is
         * zero and zero is the same number an empty node reports. */
        if (adapter->store_ready) {
            char ready_reason[sizeof(row->unavailable_reason_buf)];

            if (!adapter->store_ready(&ctx, ready_reason,
                                      sizeof(ready_reason))) {
                snprintf(row->unavailable_reason_buf,
                         sizeof(row->unavailable_reason_buf), "%s",
                         ready_reason);
                row->available = false;
                row->unavailable_reason = row->unavailable_reason_buf;
                /* The top-level disclosure is necessarily a summary when
                 * several independent authorities fail.  Preserve the first
                 * precise failure; each kind row always keeps its own. */
                if (out->store_read)
                    snprintf(out->store_reason, sizeof(out->store_reason),
                             "%s", ready_reason);
                out->store_read = false;
                continue;
            }
        }

        room = limit > out->count ? limit - out->count : 0;
        memset(&report, 0, sizeof(report));
        if (room == 0) {
            /* The page is full but the inventory question is still owed an
             * honest answer, so ask for the total with a zero-width page. */
            (void)adapter->list(&ctx, NULL, 0, &report);
            row->total     = report.total;
            row->written   = 0;
            row->truncated = report.total > 0 || report.truncated;
            row->integrity_checked = true;
            row->integrity_ok = report.integrity_ok;
            row->integrity_gap_count = report.integrity_gap_count;
            snprintf(row->integrity_reason,
                     sizeof(row->integrity_reason), "%s",
                     report.integrity_reason);
            out->total_across_kinds += report.total;
            if (row->truncated)
                out->truncated = true;
        } else {
            row->written = adapter->list(
                &ctx, &out->items[out->count], room, &report);
            row->total = report.total;
            row->truncated = report.truncated;
            row->integrity_checked = true;
            row->integrity_ok = report.integrity_ok;
            row->integrity_gap_count = report.integrity_gap_count;
            snprintf(row->integrity_reason,
                     sizeof(row->integrity_reason), "%s",
                     report.integrity_reason);
            out->count += row->written;
            out->total_across_kinds += report.total;
            if (report.truncated)
                out->truncated = true;
        }
        if (!row->integrity_ok) {
            out->integrity_ok = false;
            out->integrity_gap_count += row->integrity_gap_count;
            if (out->integrity_reason[0] == '\0')
                snprintf(out->integrity_reason,
                         sizeof(out->integrity_reason), "%s: %s",
                         row->kind_name, row->integrity_reason[0]
                                             ? row->integrity_reason
                                             : "source integrity failed");
        }
    }

    for (size_t i = 0; i < out->kind_count; i++) {
        if (!out->kinds[i].available)
            out->unavailable_kinds++;
    }
    if (out->kind_count != rows)
        return ZCL_ERR(-7, "property_catalog_list: %zu of %zu kinds produced "
                           "a row", out->kind_count, rows);
    return ZCL_OK;
}

struct zcl_result property_catalog_list(const char *datadir,
                                        const struct property_catalog_query *q,
                                        struct property_catalog_page *out)
{
    return property_catalog_list_with_sources(datadir, q, NULL, out);
}

struct zcl_result property_catalog_show_with_sources(
    const char *datadir, const struct metaverse_property_id *id,
    const struct property_catalog_sources *sources,
    struct metaverse_property_view *out)
{
    struct metaverse_adapter_ctx ctx;
    struct metaverse_znam_source znam_source;
    struct metaverse_zslp_source zslp_source;
    char zcode_dir[PC_ZCODE_DIR_MAX];
    const struct metaverse_adapter *adapter;

    if (!out)
        return ZCL_ERR(-1, "property_catalog_show: NULL out");
    memset(out, 0, sizeof(*out));
    if (!datadir || !*datadir)
        return ZCL_ERR(-2, "property_catalog_show: datadir is %s",
                       datadir ? "empty" : "NULL");
    if (!metaverse_property_id_valid(id))
        return ZCL_ERR(-3, "property_catalog_show: property id is not "
                           "well-formed (kind and non-zero root required)");
    adapter = metaverse_adapter_for(id->kind);
    if (!adapter)
        return ZCL_ERR(-4, "property_catalog_show: kind '%s' has no adapter "
                           "row", metaverse_kind_name(id->kind));
    if (!metaverse_adapter_ready(adapter))
        return ZCL_ERR(-5, "property_catalog_show: kind '%s' is not "
                           "projectable: %s", metaverse_kind_name(id->kind),
                       adapter->unavailable_reason
                           ? adapter->unavailable_reason
                           : "no reader wired");
    if (!pc_ctx_init(&ctx, datadir, zcode_dir, sizeof(zcode_dir), sources,
                     &znam_source, &zslp_source))
        return ZCL_ERR(-6, "property_catalog_show: datadir path too long "
                           "(%zu bytes)", strlen(datadir));

    /* An unreadable store must refuse here rather than reach the adapter,
     * whose honest "the authority holds nothing at this root" would be
     * indistinguishable from "we could not open the authority". */
    if (adapter->store_ready) {
        char reason[192];

        if (!adapter->store_ready(&ctx, reason, sizeof(reason)))
            return ZCL_ERR(-9, "property_catalog_show: %s", reason);
    }

    if (!adapter->show(&ctx, id, out))
        return ZCL_ERR(-7, "property_catalog_show: the '%s' adapter refused "
                           "the request", metaverse_kind_name(id->kind));
    /* An adapter that returned true without writing anything would emit a
     * silent all-zero view. Refuse it instead. */
    if (!out->populated)
        return ZCL_ERR(-8, "property_catalog_show: the '%s' adapter wrote no "
                           "view", metaverse_kind_name(id->kind));
    return ZCL_OK;
}

struct zcl_result property_catalog_show(const char *datadir,
                                        const struct metaverse_property_id *id,
                                        struct metaverse_property_view *out)
{
    return property_catalog_show_with_sources(datadir, id, NULL, out);
}

struct zcl_result property_catalog_page_to_json(
    const struct property_catalog_page *page, struct json_value *out)
{
    struct json_value arr;

    if (!page || !out)
        return ZCL_ERR(-1, "property_catalog_page_to_json: NULL %s",
                       page ? "out" : "page");
    json_set_object(out);

    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < page->count; i++) {
        struct json_value row;

        json_init(&row);
        if (metaverse_view_to_json(&page->items[i], &row))
            (void)json_push_back(&arr, &row);
        json_free(&row);
    }
    (void)json_push_kv(out, "properties", &arr);
    json_free(&arr);

    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < page->kind_count; i++) {
        const struct property_catalog_kind_row *k = &page->kinds[i];
        struct json_value row;

        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "kind", k->kind_name);
        (void)json_push_kv_str(&row, "authority_source",
                               k->authority_source);
        /* Beside the authority, what kind of answer it gives. A kind whose
         * reader is not wired still states this — the class is a property
         * of the mechanism, knowable without reading a single record. */
        (void)json_push_kv_str(&row, "settlement",
                               metaverse_settlement_name(k->settlement));
        (void)json_push_kv_str(&row, "settlement_means",
                               metaverse_settlement_means(k->settlement));
        (void)json_push_kv_bool(&row, "available", k->available);
        (void)json_push_kv_str(&row, "unavailable_reason",
                               k->unavailable_reason ? k->unavailable_reason
                                                     : "");
        (void)json_push_kv_int(&row, "total", (int64_t)k->total);
        (void)json_push_kv_int(&row, "rendered", (int64_t)k->written);
        (void)json_push_kv_bool(&row, "items_truncated", k->truncated);
        (void)json_push_kv_bool(&row, "integrity_checked",
                                k->integrity_checked);
        (void)json_push_kv_bool(&row, "integrity_ok", k->integrity_ok);
        (void)json_push_kv_int(&row, "integrity_gap_count",
                               (int64_t)k->integrity_gap_count);
        (void)json_push_kv_str(&row, "integrity_reason",
                               k->integrity_reason);
        (void)json_push_back(&arr, &row);
        json_free(&row);
    }
    (void)json_push_kv(out, "kinds", &arr);
    json_free(&arr);

    (void)json_push_kv_int(out, "rendered", (int64_t)page->count);
    (void)json_push_kv_int(out, "total", (int64_t)page->total_across_kinds);
    (void)json_push_kv_bool(out, "items_truncated", page->truncated);
    (void)json_push_kv_int(out, "kinds_scanned", (int64_t)page->kind_count);
    (void)json_push_kv_int(out, "kinds_unavailable",
                           (int64_t)page->unavailable_kinds);
    (void)json_push_kv_bool(out, "integrity_ok", page->integrity_ok);
    (void)json_push_kv_int(out, "integrity_gap_count",
                           (int64_t)page->integrity_gap_count);
    (void)json_push_kv_str(out, "integrity_reason",
                           page->integrity_reason);

    /* The disclosure section. "read": false says the emptiness above is a
     * failure to look, not an inventory — a distinction an operator
     * cannot recover from the item array alone. */
    {
        struct json_value store;

        json_init(&store);
        json_set_object(&store);
        (void)json_push_kv_bool(&store, "read", page->store_read);
        (void)json_push_kv_str(&store, "reason",
                               page->store_read ? "" : page->store_reason);
        (void)json_push_kv(out, "store", &store);
        json_free(&store);
    }
    return ZCL_OK;
}
