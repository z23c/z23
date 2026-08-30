/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZNAM property adapter.  The immutable property root is the REGISTER
 * transaction hash already carried by the canonical znam model.  This file
 * knows no SQL: the application supplies bounded, database-neutral facts
 * through metaverse_znam_source.
 *
 * Reading a row from node.db proves that the chain overlay indexed it, but
 * not that this particular caller validated the carrying block.  Therefore
 * the evidence grade is deliberately CHAIN_INDEXED_UNVALIDATED.  A future
 * live-node source may upgrade that only after it proves local block
 * validation and supplies the anchor/tip chainwork facts. */

#include "metaverse_priv.h"

#include "base/bytes.h"
#include "metaverse/property_adapter.h"

#include <stdio.h>
#include <string.h>

#define MV_ZNAM_ACTIONS_PRESENT                                              \
    (METAVERSE_ACTION_UPDATE_POINTER | METAVERSE_ACTION_LIST_FOR_SALE |      \
     METAVERSE_ACTION_SELL | METAVERSE_ACTION_TRANSFER)

static bool znam_ready(const struct metaverse_adapter_ctx *ctx, char *reason,
                       size_t reason_cap)
{
    size_t written = 0;
    size_t total = 0;
    bool truncated = false;

    if (!reason || reason_cap == 0)
        return false;
    reason[0] = '\0';
    if (!ctx || !ctx->znam || !ctx->znam->find_registration ||
        !ctx->znam->list) {
        snprintf(reason, reason_cap, "%s",
                 ctx && ctx->znam && ctx->znam->unavailable_reason
                     ? ctx->znam->unavailable_reason
                     : "no safe read-only ZNAM source was supplied");
        return false;
    }
    if (!ctx->znam->list(ctx->znam->opaque, NULL, 0, &written, &total,
                         &truncated)) {
        snprintf(reason, reason_cap,
                 "the canonical ZNAM registry could not be counted");
        return false;
    }
    return true;
}

static void znam_fill(const struct metaverse_adapter_ctx *ctx,
                      const struct metaverse_znam_record *record,
                      struct metaverse_property_view *out)
{
    snprintf(out->display_name, sizeof(out->display_name), "%s",
             record->name);
    snprintf(out->owner_principal, sizeof(out->owner_principal), "%s",
             record->owner);
    out->owner_principal_kind = "zcl_address";
    out->status = METAVERSE_STATUS_PRESENT;
    out->actions = MV_ZNAM_ACTIONS_PRESENT;
    out->has_freshness_height = record->registration_height >= 0;
    out->freshness_height = record->registration_height;

    /* The update transaction is a useful immutable description of current
     * state when present.  It is not called a revision number: ZNAM stores
     * no monotonic revision counter, and inventing one from a height would
     * become a second truth. */
    if (zcl_bytes_any_set(record->last_update_root,
                      sizeof(record->last_update_root))) {
        out->has_descriptor_root = true;
        memcpy(out->descriptor_root, record->last_update_root,
               sizeof(out->descriptor_root));
    }

    snprintf(out->provenance, sizeof(out->provenance),
             "on-chain ZNAM registration indexed from node.db; this read "
             "does not itself prove local block validation");
    (void)metaverse_view_determined(
        out, METAVERSE_EVIDENCE_CHAIN_INDEXED_UNVALIDATED,
        "db_znam_find_by_reg_txid");

    (void)metaverse_work_measure(
        METAVERSE_KIND_ZNAM_NAME, record->registration_height, NULL,
        ctx->chain_height, ctx->chain_work, &out->work);
    if (!out->work.has_depth)
        snprintf(out->reason, sizeof(out->reason), "%s",
                 metaverse_work_gap_reason(out->work.gap));
}

static bool znam_show(const struct metaverse_adapter_ctx *ctx,
                      const struct metaverse_property_id *id,
                      struct metaverse_property_view *out)
{
    struct metaverse_znam_record record;
    enum metaverse_source_lookup found;

    if (!ctx || !id || !out || id->kind != METAVERSE_KIND_ZNAM_NAME ||
        !ctx->znam || !ctx->znam->find_registration)
        return false;
    if (!metaverse_view_begin(out, id))
        return false;
    memset(&record, 0, sizeof(record));
    found = ctx->znam->find_registration(ctx->znam->opaque, id->root,
                                         &record);
    if (found == METAVERSE_SOURCE_ERROR) {
        metaverse_view_undetermined(
            out, "the canonical ZNAM registration lookup failed");
        return true;
    }
    if (found == METAVERSE_SOURCE_ABSENT) {
        out->status = METAVERSE_STATUS_ABSENT;
        out->actions = 0;
        snprintf(out->provenance, sizeof(out->provenance),
                 "no ZNAM registration with this transaction hash is "
                 "present in the canonical overlay");
        snprintf(out->reason, sizeof(out->reason),
                 "registration transaction hash not found");
        (void)metaverse_view_determined(
            out, METAVERSE_EVIDENCE_CHAIN_INDEXED_UNVALIDATED,
            "db_znam_find_by_reg_txid");
        return true;
    }
    if (memcmp(record.registration_root, id->root,
               sizeof(id->root)) != 0) {
        metaverse_view_undetermined(
            out, "ZNAM source returned a different registration root");
        return true;
    }
    znam_fill(ctx, &record, out);
    return true;
}

static size_t znam_list(const struct metaverse_adapter_ctx *ctx,
                        struct metaverse_property_view *out, size_t out_cap,
                        struct metaverse_adapter_list_report *report)
{
    struct metaverse_znam_record records[32];
    size_t written = 0;
    size_t total = 0;
    size_t rendered = 0;
    bool truncated = false;

    if (report)
        memset(report, 0, sizeof(*report));
    if (!ctx || !ctx->znam || !ctx->znam->list ||
        !report || (!out && out_cap > 0) || out_cap > 32)
        return 0;
    if (!ctx->znam->list(ctx->znam->opaque, records, out_cap, &written,
                         &total, &truncated)) {
        report->total = total;
        report->truncated = true;
        report->integrity_gap_count = 1;
        snprintf(report->integrity_reason,
                 sizeof(report->integrity_reason),
                 "canonical ZNAM source failed during enumeration");
        return 0;
    }
    for (size_t i = 0; i < written; i++) {
        struct metaverse_property_id id;

        if (!metaverse_property_id_make(METAVERSE_KIND_ZNAM_NAME,
                                        records[i].registration_root, &id) ||
            !metaverse_view_begin(&out[rendered], &id)) {
            report->integrity_gap_count++;
            if (report->integrity_reason[0] == '\0')
                snprintf(report->integrity_reason,
                         sizeof(report->integrity_reason),
                         "ZNAM row %zu could not be rendered", i);
            continue;
        }
        znam_fill(ctx, &records[i], &out[rendered]);
        rendered++;
    }
    report->total = total;
    report->truncated = truncated || rendered < total;
    report->integrity_ok = report->integrity_gap_count == 0;
    return rendered;
}

const struct metaverse_adapter *metaverse_adapter_znam(void)
{
    static const struct metaverse_adapter adapter = {
        .kind = METAVERSE_KIND_ZNAM_NAME,
        .unavailable_reason = NULL,
        .list = znam_list,
        .show = znam_show,
        .store_ready = znam_ready,
    };
    return &adapter;
}
