/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * property_view — view lifecycle, honest naming, and JSON rendering. See
 * metaverse/property_view.h for the two rules and the evidence-grade
 * contract this file enforces mechanically:
 *   - metaverse_view_determined() refuses an UNKNOWN grade or a nameless
 *     source, so a view cannot claim to be answered without saying what
 *     was checked;
 *   - metaverse_view_undetermined() clears status, evidence AND actions
 *     together, so a gap can never leave a stale action set behind. */

#include "metaverse/property_view.h"

#include "base/hex.h"
#include "json/json.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void root_to_hex(const uint8_t root[METAVERSE_ROOT_BYTES],
                        char out[METAVERSE_ROOT_HEX_MAX])
{
    zcl_hex_encode(root, METAVERSE_ROOT_BYTES, out);
}

const char *metaverse_evidence_name(enum metaverse_evidence evidence)
{
    switch (evidence) {
    case METAVERSE_EVIDENCE_LOCAL_STORE_READ:
        return "local_store_read";
    case METAVERSE_EVIDENCE_LOCAL_MANIFEST_HASH:
        return "local_manifest_hash";
    case METAVERSE_EVIDENCE_LOCAL_CONTENT_HASH:
        return "local_content_hash";
    case METAVERSE_EVIDENCE_LOCAL_SIGNATURE:
        return "local_signature";
    case METAVERSE_EVIDENCE_CHAIN_VALIDATED_LOCAL:
        return "chain_validated_local";
    case METAVERSE_EVIDENCE_CHAIN_INDEXED_UNVALIDATED:
        return "chain_indexed_unvalidated";
    case METAVERSE_EVIDENCE_PEER_REPORTED:
        return "peer_reported";
    case METAVERSE_EVIDENCE_UNKNOWN:
        break;
    }
    return "unknown";
}

const char *metaverse_property_status_name(enum metaverse_property_status s)
{
    switch (s) {
    case METAVERSE_STATUS_ABSENT:     return "absent";
    case METAVERSE_STATUS_INCOMPLETE: return "incomplete";
    case METAVERSE_STATUS_PRESENT:    return "present";
    case METAVERSE_STATUS_UNKNOWN:    break;
    }
    return "unknown";
}

bool metaverse_view_begin(struct metaverse_property_view *out,
                          const struct metaverse_property_id *id)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->kind_name           = metaverse_kind_name(METAVERSE_KIND_UNKNOWN);
    out->authority_source    = metaverse_kind_authority(METAVERSE_KIND_UNKNOWN);
    out->owner_principal_kind = "none";
    /* Even a failed begin leaves a coherent work block, so a caller that
     * ignores the return renders "unknown", never an all-zero measurement
     * that reads as depth 0. */
    out->settlement = metaverse_kind_settlement(METAVERSE_KIND_UNKNOWN);
    metaverse_work_none(&out->work, out->settlement);
    if (!metaverse_property_id_valid(id))
        return false;

    out->id = *id;
    if (!metaverse_property_id_format(id, out->id_text, sizeof(out->id_text)))
        return false;
    out->kind_name        = metaverse_kind_name(id->kind);
    out->authority_source = metaverse_kind_authority(id->kind);
    /* From the KIND, not from the adapter: an adapter may report what it
     * measured, never what class of thing it is measuring. */
    out->settlement = metaverse_kind_settlement(id->kind);
    metaverse_work_none(&out->work, out->settlement);
    memcpy(out->immutable_root, id->root, METAVERSE_ROOT_BYTES);
    return true;
}

bool metaverse_view_determined(struct metaverse_property_view *view,
                              enum metaverse_evidence evidence,
                              const char *evidence_source)
{
    if (!view)
        return false;
    /* A determined view must name the work it did. Refusing here is what
     * makes "verified" unclaimable by omission. */
    if (evidence == METAVERSE_EVIDENCE_UNKNOWN || !evidence_source ||
        !*evidence_source)
        return false;
    view->determined     = true;
    view->evidence       = evidence;
    view->evidence_source = evidence_source;
    view->populated      = true;
    return true;
}

void metaverse_view_undetermined(struct metaverse_property_view *view,
                                 const char *fmt, ...)
{
    va_list ap;

    if (!view)
        return;
    view->determined      = false;
    view->status          = METAVERSE_STATUS_UNKNOWN;
    view->evidence        = METAVERSE_EVIDENCE_UNKNOWN;
    view->evidence_source = NULL;
    view->actions         = 0;
    view->populated       = true;
    /* Same reason the action set is cleared: a view that could not
     * determine the record must not keep a depth or chainwork measured
     * against it. The settlement CLASS survives — it is a fact about the
     * kind, not about this read. */
    metaverse_work_none(&view->work, view->settlement);

    if (!fmt) {
        view->reason[0] = '\0';
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(view->reason, sizeof(view->reason), fmt, ap);
    va_end(ap);
}

bool metaverse_view_to_json(const struct metaverse_property_view *view,
                            struct json_value *out)
{
    char hex[METAVERSE_ROOT_HEX_MAX];
    char actions[METAVERSE_ACTION_LIST_MAX];
    struct json_value arr;

    if (!view || !out)
        return false;
    json_set_object(out);

    (void)json_push_kv_str(out, "property_id", view->id_text);
    (void)json_push_kv_str(out, "kind",
                           view->kind_name ? view->kind_name : "unknown");
    (void)json_push_kv_str(out, "authority_source",
                           view->authority_source ? view->authority_source
                                                  : "unknown");
    /* Settlement rides beside authority_source because the two answer
     * different questions: WHO to ask, and WHAT KIND OF ANSWER they give.
     * `settlement_means` is emitted in full rather than left to a lookup
     * table on the consumer's side — a local_declaration property must say
     * out loud that nothing outside this node has agreed to it, in the same
     * document that lists it as owned. */
    (void)json_push_kv_str(out, "settlement",
                           metaverse_settlement_name(view->settlement));
    (void)json_push_kv_str(out, "settlement_means",
                           metaverse_settlement_means(view->settlement));
    (void)json_push_kv_bool(out, "determined", view->determined);
    (void)json_push_kv_str(out, "reason", view->reason);
    (void)json_push_kv_str(out, "status",
                           metaverse_property_status_name(view->status));

    (void)json_push_kv_str(out, "evidence_grade",
                           metaverse_evidence_name(view->evidence));
    (void)json_push_kv_str(out, "evidence_source",
                           view->evidence_source ? view->evidence_source : "");
    /* Chain-bound is a separate bit from the grade name so a consumer can
     * gate on it without parsing strings, and so the FALSE case is loud. */
    (void)json_push_kv_bool(
        out, "chain_bound",
        view->evidence == METAVERSE_EVIDENCE_CHAIN_VALIDATED_LOCAL);

    root_to_hex(view->immutable_root, hex);
    (void)json_push_kv_str(out, "immutable_root", hex);
    if (view->has_content_root) {
        root_to_hex(view->content_root, hex);
        (void)json_push_kv_str(out, "content_root", hex);
    } else {
        (void)json_push_kv_str(out, "content_root", "");
    }
    if (view->has_descriptor_root) {
        root_to_hex(view->descriptor_root, hex);
        (void)json_push_kv_str(out, "descriptor_root", hex);
    } else {
        (void)json_push_kv_str(out, "descriptor_root", "");
    }

    (void)json_push_kv_str(out, "display_name", view->display_name);
    (void)json_push_kv_str(out, "owner_principal", view->owner_principal);
    (void)json_push_kv_str(out, "owner_principal_kind",
                           view->owner_principal_kind
                               ? view->owner_principal_kind : "none");
    (void)json_push_kv_bool(out, "has_revision", view->has_revision);
    (void)json_push_kv_int(out, "revision", (int64_t)view->revision);
    (void)json_push_kv_str(out, "provenance", view->provenance);

    (void)json_push_kv_bool(out, "has_freshness_height",
                            view->has_freshness_height);
    (void)json_push_kv_int(out, "freshness_height",
                           view->has_freshness_height ? view->freshness_height
                                                      : -1);

    /* The measurement, in its own object so "no numbers here" is a shape a
     * consumer can see rather than a set of keys it has to notice are
     * missing. */
    {
        struct json_value work;

        json_init(&work);
        if (metaverse_work_to_json(&view->work, &work))
            (void)json_push_kv(out, "work", &work);
        json_free(&work);
    }

    if (!metaverse_action_mask_format(view->actions, actions, sizeof(actions)))
        actions[0] = '\0';
    (void)json_push_kv_str(out, "actions_csv", actions);
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < (size_t)METAVERSE_ACTION_COUNT; i++) {
        uint32_t bit = metaverse_action_at(i);
        const char *name = metaverse_action_name(bit);
        struct json_value row;

        if (!name || (view->actions & bit) == 0)
            continue;
        json_init(&row);
        json_set_str(&row, name);
        (void)json_push_back(&arr, &row);
        json_free(&row);
    }
    (void)json_push_kv(out, "actions", &arr);
    json_free(&arr);

    (void)json_push_kv_int(out, "total_bytes", (int64_t)view->total_bytes);
    (void)json_push_kv_int(out, "file_count", (int64_t)view->file_count);
    (void)json_push_kv_int(out, "chunk_total", (int64_t)view->chunk_total);
    (void)json_push_kv_int(out, "chunks_present",
                           (int64_t)view->chunks_present);
    (void)json_push_kv_bool(out, "manifest_root_verified",
                            view->manifest_root_verified);
    (void)json_push_kv_int(out, "chunks_verified",
                           (int64_t)view->chunks_verified);
    (void)json_push_kv_int(out, "bytes_verified",
                           (int64_t)view->bytes_verified);
    (void)json_push_kv_bool(out, "verification_complete",
                            view->verification_complete);
    (void)json_push_kv_str(out, "verification_gap",
                           view->verification_gap);
    return true;
}
