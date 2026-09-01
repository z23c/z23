/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZSLP asset-definition property adapter.  The immutable property root is
 * the GENESIS transaction id already owned by the canonical ZSLP model.
 * SQL stays in the application model; this library consumes bounded,
 * database-neutral facts through metaverse_zslp_source.
 *
 * A fungible asset definition has no single owner in the current model.
 * Holders own quantities, while the mint baton/controller is not indexed.
 * Reporting the genesis recipient or any holder as owner would manufacture
 * title, so owner_principal_kind is deliberately "none" and no mutating
 * action is advertised.  The catalog remains useful: it identifies the
 * asset, its name, its genesis height, and the measurable PoW depth behind
 * the indexed definition. */

#include "metaverse_priv.h"

#include "metaverse/property_adapter.h"

#include <stdio.h>
#include <string.h>

static bool zslp_ready(const struct metaverse_adapter_ctx *ctx, char *reason,
                       size_t reason_cap)
{
    size_t written = 0;
    size_t total = 0;
    bool truncated = false;

    if (!reason || reason_cap == 0)
        return false;
    reason[0] = '\0';
    if (!ctx || !ctx->zslp || !ctx->zslp->find_genesis ||
        !ctx->zslp->list) {
        snprintf(reason, reason_cap, "%s",
                 ctx && ctx->zslp && ctx->zslp->unavailable_reason
                     ? ctx->zslp->unavailable_reason
                     : "no safe read-only ZSLP source was supplied");
        return false;
    }
    if (!ctx->zslp->list(ctx->zslp->opaque, NULL, 0, &written, &total,
                         &truncated)) {
        snprintf(reason, reason_cap,
                 "the canonical ZSLP asset registry could not be counted");
        return false;
    }
    return true;
}

static void zslp_fill(const struct metaverse_adapter_ctx *ctx,
                      const struct metaverse_zslp_record *record,
                      struct metaverse_property_view *out)
{
    if (record->ticker[0] && record->name[0])
        snprintf(out->display_name, sizeof(out->display_name), "%s (%s)",
                 record->ticker, record->name);
    else if (record->ticker[0])
        snprintf(out->display_name, sizeof(out->display_name), "%s",
                 record->ticker);
    else if (record->name[0])
        snprintf(out->display_name, sizeof(out->display_name), "%s",
                 record->name);
    else
        snprintf(out->display_name, sizeof(out->display_name), "(unnamed)");

    out->owner_principal[0] = '\0';
    out->owner_principal_kind = "none";
    out->status = METAVERSE_STATUS_PRESENT;
    out->actions = 0u;
    out->has_freshness_height = record->genesis_height >= 0;
    out->freshness_height = record->genesis_height;
    snprintf(out->provenance, sizeof(out->provenance),
             "on-chain ZSLP GENESIS indexed from node.db; fungible holders "
             "own quantities and no mint-baton controller is indexed");
    (void)metaverse_view_determined(
        out, METAVERSE_EVIDENCE_CHAIN_INDEXED_UNVALIDATED,
        "db_zslp_asset_lookup");
    (void)metaverse_work_measure(
        METAVERSE_KIND_ZSLP_ASSET, record->genesis_height, NULL,
        ctx->chain_height, ctx->chain_work, &out->work);
    if (!out->work.has_depth)
        snprintf(out->reason, sizeof(out->reason), "%s",
                 metaverse_work_gap_reason(out->work.gap));
}

static bool zslp_show(const struct metaverse_adapter_ctx *ctx,
                      const struct metaverse_property_id *id,
                      struct metaverse_property_view *out)
{
    struct metaverse_zslp_record record;
    enum metaverse_source_lookup found;

    if (!ctx || !id || !out || id->kind != METAVERSE_KIND_ZSLP_ASSET ||
        !ctx->zslp || !ctx->zslp->find_genesis)
        return false;
    if (!metaverse_view_begin(out, id))
        return false;
    memset(&record, 0, sizeof(record));
    found = ctx->zslp->find_genesis(ctx->zslp->opaque, id->root, &record);
    if (found == METAVERSE_SOURCE_ERROR) {
        metaverse_view_undetermined(
            out, "the canonical ZSLP asset lookup failed");
        return true;
    }
    if (found == METAVERSE_SOURCE_ABSENT) {
        out->status = METAVERSE_STATUS_ABSENT;
        out->actions = 0u;
        out->owner_principal_kind = "none";
        snprintf(out->provenance, sizeof(out->provenance),
                 "no chain-derived ZSLP GENESIS with this transaction id "
                 "is present in the canonical overlay");
        snprintf(out->reason, sizeof(out->reason),
                 "ZSLP GENESIS transaction id not found");
        (void)metaverse_view_determined(
            out, METAVERSE_EVIDENCE_CHAIN_INDEXED_UNVALIDATED,
            "db_zslp_asset_lookup");
        return true;
    }
    if (memcmp(record.genesis_root, id->root, sizeof(id->root)) != 0) {
        metaverse_view_undetermined(
            out, "ZSLP source returned a different GENESIS root");
        return true;
    }
    zslp_fill(ctx, &record, out);
    return true;
}

static size_t zslp_list(const struct metaverse_adapter_ctx *ctx,
                        struct metaverse_property_view *out, size_t out_cap,
                        struct metaverse_adapter_list_report *report)
{
    struct metaverse_zslp_record records[32];
    size_t written = 0;
    size_t total = 0;
    size_t rendered = 0;
    bool truncated = false;

    if (report)
        memset(report, 0, sizeof(*report));
    if (!ctx || !ctx->zslp || !ctx->zslp->list ||
        !report || (!out && out_cap > 0) || out_cap > 32)
        return 0;
    if (!ctx->zslp->list(ctx->zslp->opaque, records, out_cap, &written,
                         &total, &truncated)) {
        report->total = total;
        report->truncated = true;
        report->integrity_gap_count = 1;
        snprintf(report->integrity_reason,
                 sizeof(report->integrity_reason),
                 "canonical ZSLP source failed during enumeration");
        return 0;
    }
    for (size_t i = 0; i < written; i++) {
        struct metaverse_property_id id;

        if (!metaverse_property_id_make(METAVERSE_KIND_ZSLP_ASSET,
                                        records[i].genesis_root, &id) ||
            !metaverse_view_begin(&out[rendered], &id)) {
            report->integrity_gap_count++;
            if (report->integrity_reason[0] == '\0')
                snprintf(report->integrity_reason,
                         sizeof(report->integrity_reason),
                         "ZSLP row %zu could not be rendered", i);
            continue;
        }
        zslp_fill(ctx, &records[i], &out[rendered]);
        rendered++;
    }
    report->total = total;
    report->truncated = truncated || rendered < total;
    report->integrity_ok = report->integrity_gap_count == 0;
    return rendered;
}

const struct metaverse_adapter *metaverse_adapter_zslp(void)
{
    static const struct metaverse_adapter adapter = {
        .kind = METAVERSE_KIND_ZSLP_ASSET,
        .unavailable_reason = NULL,
        .list = zslp_list,
        .show = zslp_show,
        .store_ready = zslp_ready,
    };
    return &adapter;
}
