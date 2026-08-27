/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The CONTENT adapter: generic content/blob property over lib/vcs's
 * blob_store shape. Authority source: vcs.blob_store.
 *
 * WHAT A BLOB PROVES, AND WHAT IT DOES NOT. A blob root is the manifest
 * root of the frozen one-file/one-chunk package shape, so it commits the
 * length and the SHA3-256 of the bytes and NOTHING ELSE: no publisher, no
 * signature, no chain anchor. blob_store.h calls this the authentication
 * split and preserves it deliberately. This adapter preserves it too:
 *
 *   evidence grade  local_content_hash — this node re-derived the manifest
 *                   root and byte-verified every committed chunk in this
 *                   call. Byte identity only. A missing/corrupt/budgeted
 *                   chunk earns only local_manifest_hash.
 *   owner principal "" with owner_principal_kind = "none", because the
 *                   authority records none. That is a FACT about content,
 *                   not a failed lookup, and it is why TRANSFER and
 *                   PUBLISH_REVISION are absent from the action set: there
 *                   is no title to move and no signed descriptor to
 *                   supersede. A caller who wants those wants a ZCODE
 *                   package.
 *   freshness       none. Content has no chain anchor, so stamping a tip
 *                   height beside it would be a false freshness claim.
 *
 * SELL/DELIVER are offered when the bytes are present because what is sold
 * is delivery of bytes the seller holds, not title to them — and only then,
 * because a seller that cannot produce the bytes cannot deliver. */

#include "metaverse_priv.h"

#include "metaverse/property_adapter.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "vcs/blob_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One fully byte-verified blob supports these. Availability, not authority.
 * Inspection is absent because it is no longer an action: reading is a
 * QUERY (metaverse/property_action.h), always available to a principal the
 * grant lets look, and never gated on the object's state. */
#define MV_CONTENT_ACTIONS_PRESENT                                           \
    (METAVERSE_ACTION_HOST | METAVERSE_ACTION_LIST_FOR_SALE |                \
     METAVERSE_ACTION_SELL | METAVERSE_ACTION_DELIVER |                      \
     METAVERSE_ACTION_LEASE | METAVERSE_ACTION_ACCEPT_PAYMENT)

/* The manifest is known but its byte is not in the CAS. Nothing can be
 * hosted, sold, or delivered from an object whose bytes are absent, and an
 * empty action set says exactly that. Inspecting it is still possible; that
 * is a query, and queries do not appear in this mask. */
#define MV_CONTENT_ACTIONS_INCOMPLETE (0u)

static const char k_content_provenance[] = /* hotswap-static-ok: immutable provenance string */
    "blob root commits length+SHA3-256 of the bytes only; no publisher, "
    "signature, or chain anchor";

/* Fill a view from a successfully read blob-shaped manifest. */
static void content_fill(struct metaverse_property_view *out,
                         const struct mv_manifest_read *m)
{
    bool complete = m->verification_complete;

    out->has_content_root = true;
    memcpy(out->content_root, m->manifest.files[0].chunk_hashes, 32);
    out->has_descriptor_root  = false; /* content carries no descriptor */
    out->owner_principal[0]   = '\0';
    out->owner_principal_kind = "none";
    out->has_revision         = false;
    out->has_freshness_height = false;
    out->total_bytes          = m->total_bytes;
    out->file_count           = m->file_count;
    out->chunk_total          = m->chunk_total;
    out->chunks_present       = m->chunks_present;
    out->manifest_root_verified = m->manifest_root_verified;
    out->chunks_verified      = m->chunks_verified;
    out->bytes_verified       = m->bytes_verified;
    out->verification_complete = m->verification_complete;
    snprintf(out->verification_gap, sizeof(out->verification_gap), "%s",
             m->verification_gap);
    out->status = complete ? METAVERSE_STATUS_PRESENT
                           : METAVERSE_STATUS_INCOMPLETE;
    out->actions = complete ? MV_CONTENT_ACTIONS_PRESENT
                            : MV_CONTENT_ACTIONS_INCOMPLETE;
    snprintf(out->provenance, sizeof(out->provenance), "%s",
             k_content_provenance);
    (void)metaverse_view_determined(
        out, complete ? METAVERSE_EVIDENCE_LOCAL_CONTENT_HASH
                      : METAVERSE_EVIDENCE_LOCAL_MANIFEST_HASH,
        complete ? "mv_manifest_verify_possession"
                 : "vcs_package_manifest_root");
    if (!complete)
        snprintf(out->reason, sizeof(out->reason),
                 "possession not proven: %s (%u/%u chunks and %llu/%llu "
                 "bytes verified)",
                 m->verification_gap[0] ? m->verification_gap : "incomplete",
                 m->chunks_verified, m->chunk_total,
                 (unsigned long long)m->bytes_verified,
                 (unsigned long long)m->total_bytes);
}

static bool content_show(const struct metaverse_adapter_ctx *ctx,
                         const struct metaverse_property_id *id,
                         struct metaverse_property_view *out)
{
    char root_hex[65];
    struct mv_manifest_read m;
    enum mv_manifest_read_status read_status;

    if (!ctx || !id || !out || id->kind != METAVERSE_KIND_CONTENT)
        return false;
    if (!metaverse_view_begin(out, id))
        return false;

    zcl_hex_encode(id->root, 32, root_hex);
    read_status = mv_manifest_read(ctx->zcode_dir, root_hex, &m);
    if (read_status == MV_MANIFEST_READ_ABSENT) {
        /* Asked and answered: the authority holds nothing here. ABSENT is
         * a determined verdict, not a gap. No ACTION is available on an
         * object the authority does not hold; re-asking is a query. */
        out->status  = METAVERSE_STATUS_ABSENT;
        out->actions = 0u;
        snprintf(out->provenance, sizeof(out->provenance), "%s",
                 k_content_provenance);
        snprintf(out->reason, sizeof(out->reason),
                 "no manifest at this root in the local content store");
        (void)metaverse_view_determined(
            out, METAVERSE_EVIDENCE_LOCAL_STORE_READ, "mv_manifest_read");
        return true;
    }
    if (read_status != MV_MANIFEST_READ_OK) {
        metaverse_view_undetermined(
            out, "manifest at this root is %s; refusing to report corrupt "
                 "or unreadable content as absent",
            mv_manifest_read_status_name(read_status));
        return true;
    }
    if (!m.root_matches_name) {
        metaverse_view_undetermined(
            out, "stored manifest re-derives a different root than its own "
                 "filename; refusing to project it");
        mv_manifest_free(&m);
        return true;
    }
    if (!mv_manifest_is_blob(&m.manifest)) {
        /* A real object, just not this kind. Saying "absent" would be a
         * lie; the bytes exist as a zcode_package. */
        metaverse_view_undetermined(
            out, "root is a %u-file package, not the frozen one-file blob "
                 "shape; ask for kind zcode_package",
            m.file_count);
        mv_manifest_free(&m);
        return true;
    }
    mv_manifest_verify_possession(ctx->zcode_dir, &m,
                                  MV_PROPERTY_VERIFY_BYTES,
                                  MV_PROPERTY_SHOW_VERIFY_OPS, NULL, NULL);
    content_fill(out, &m);
    mv_manifest_free(&m);
    return true;
}

static size_t content_list(const struct metaverse_adapter_ctx *ctx,
                           struct metaverse_property_view *out,
                           size_t out_cap,
                           struct metaverse_adapter_list_report *report)
{
    char (*names)[65];
    size_t seen = 0;
    size_t scanned;
    size_t written = 0;
    size_t matched = 0;
    bool scan_truncated = false;
    uint64_t verify_bytes_left = MV_PROPERTY_VERIFY_BYTES;
    uint32_t verify_operations_left = MV_PROPERTY_LIST_VERIFY_OPS;

    if (report)
        memset(report, 0, sizeof(*report));
    /* out_cap == 0 is the legal count-only call; `out` is then unused. */
    if (!ctx || !report || (!out && out_cap > 0))
        return 0;

    names = zcl_malloc(MV_MANIFEST_SCAN_MAX * sizeof(*names),
                       "mv_content_names");
    if (!names) {
        report->integrity_gap_count = 1;
        snprintf(report->integrity_reason,
                 sizeof(report->integrity_reason),
                 "manifest name scan allocation failed");
        return 0;
    }
    if (!mv_manifest_names(ctx->zcode_dir, names, MV_MANIFEST_SCAN_MAX,
                           &scanned, &seen, &scan_truncated)) {
        free(names);
        report->integrity_gap_count = 1;
        snprintf(report->integrity_reason,
                 sizeof(report->integrity_reason),
                 "manifest directory scan failed after readiness check");
        return 0;
    }

    for (size_t i = 0; i < scanned; i++) {
        struct mv_manifest_read m;
        struct metaverse_property_id id;
        enum mv_manifest_read_status read_status;

        read_status = mv_manifest_read(ctx->zcode_dir, names[i], &m);
        if (read_status != MV_MANIFEST_READ_OK) {
            report->integrity_gap_count++;
            if (report->integrity_reason[0] == '\0')
                snprintf(report->integrity_reason,
                         sizeof(report->integrity_reason),
                         "manifest %.64s became %s during enumeration",
                         names[i], mv_manifest_read_status_name(read_status));
            continue;
        }
        if (!m.root_matches_name) {
            report->integrity_gap_count++;
            if (report->integrity_reason[0] == '\0')
                snprintf(report->integrity_reason,
                         sizeof(report->integrity_reason),
                         "manifest %.64s re-derives a different root",
                         names[i]);
            mv_manifest_free(&m);
            continue;
        }
        if (!mv_manifest_is_blob(&m.manifest)) {
            mv_manifest_free(&m);
            continue;
        }
        matched++;
        if (written >= out_cap) {
            mv_manifest_free(&m);
            continue; /* keep counting: `total` must be the real inventory */
        }
        if (metaverse_property_id_make(METAVERSE_KIND_CONTENT, m.root, &id) &&
            metaverse_view_begin(&out[written], &id)) {
            uint64_t bytes_used = 0;
            uint32_t operations_used = 0;

            mv_manifest_verify_possession(
                ctx->zcode_dir, &m, verify_bytes_left,
                verify_operations_left, &bytes_used, &operations_used);
            verify_bytes_left -= bytes_used;
            verify_operations_left -= operations_used;
            content_fill(&out[written], &m);
            written++;
        } else {
            report->integrity_gap_count++;
            if (report->integrity_reason[0] == '\0')
                snprintf(report->integrity_reason,
                         sizeof(report->integrity_reason),
                         "valid blob %.64s could not be rendered", names[i]);
        }
        mv_manifest_free(&m);
    }
    free(names);

    report->total = matched;
    report->truncated = scan_truncated || written < matched;
    report->integrity_ok = report->integrity_gap_count == 0;
    return written;
}

const struct metaverse_adapter *metaverse_adapter_content(void)
{
    static const struct metaverse_adapter k_adapter = {
        .kind = METAVERSE_KIND_CONTENT,
        .unavailable_reason = NULL,
        .list = content_list,
        .show = content_show,
        .store_ready = mv_zcode_store_ready,
    };
    return &k_adapter;
}
