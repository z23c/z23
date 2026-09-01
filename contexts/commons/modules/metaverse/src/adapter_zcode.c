/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The ZCODE_PACKAGE adapter. Authority source: vcs.package_store — the
 * signed release envelope under releases/ plus the content.v2 manifest
 * under manifests/, both canonical bytes, projected through
 * contexts/commons/modules/vcs/package_index (itself a rebuildable projection, never a truth).
 *
 * THE EVIDENCE GRADE IS EARNED IN THIS CALL, NOT INHERITED.
 * package_index.h states plainly that the index "never verifies signatures
 * (publication did)". A view built from the index alone therefore could
 * only claim local_manifest_hash. So this adapter re-reads the persisted
 * envelope and runs vcs_package_release_verify() — full field validation,
 * release-id recomputation, low-S check, secp256k1 ECDSA verify — during
 * the read, and only then reports local_signature. If that verify fails or
 * the envelope is unreadable, the grade is local_content_hash only when all
 * chunks verify; otherwise it drops to local_manifest_hash. It is never
 * silently kept.
 *
 * Still not chain-bound. A publisher signature proves authorship of exactly
 * those bytes. It is not a consensus fact, so chain_bound stays false and
 * no freshness height is reported — a ZCODE release has no chain anchor for
 * the node to be fresh against. (An envelope may carry a `znam` POINTER;
 * that is a claim inside signed bytes, not a resolved on-chain name, and it
 * is reported as the pointer it is.)
 *
 * Owner/controller principal is the release's publisher pubkey — the key
 * whose signature this call verified. Revision is publisher_sequence, the
 * publisher's own monotonic counter. */

#include "metaverse_priv.h"

#include "metaverse/property_adapter.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/text_fit.h"
#include "vcs/package_index.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A complete package whose publisher signature verified here. TRANSFER is
 * absent on purpose: a ZCODE release records authorship, and there is no
 * on-chain title for this node to move. PUBLISH_REVISION is present
 * because the publisher's own sequence is how a successor is named. */
#define MV_ZCODE_ACTIONS_SIGNED_PRESENT                                      \
    (METAVERSE_ACTION_HOST | METAVERSE_ACTION_PUBLISH_REVISION |             \
     METAVERSE_ACTION_LIST_FOR_SALE | METAVERSE_ACTION_SELL |                \
     METAVERSE_ACTION_DELIVER | METAVERSE_ACTION_LEASE |                     \
     METAVERSE_ACTION_ACCEPT_PAYMENT)

/* Complete bytes, but the authorship claim did not verify in this call.
 * Hosting bytes is still meaningful; selling or delivering them under an
 * unverified publisher claim is not. */
#define MV_ZCODE_ACTIONS_UNSIGNED_PRESENT (METAVERSE_ACTION_HOST)

/* Bytes missing: nothing can be hosted or delivered, so the action set is
 * empty. Inspecting the package is still possible; that is a QUERY
 * (metaverse/property_action.h) and queries never appear in this mask. */
#define MV_ZCODE_ACTIONS_INCOMPLETE (0u)

struct mv_zcode_facts {
    bool have_manifest;
    enum mv_manifest_read_status manifest_status;
    struct mv_manifest_read m;
    bool signature_verified;
    struct vcs_package_release release;
};

/* Fill a view from one index entry, re-verifying the envelope. */
static bool zcode_fill(const struct metaverse_adapter_ctx *ctx,
                       const struct vcs_package_index_entry *e,
                       struct metaverse_property_view *out,
                       uint64_t verify_byte_budget,
                       uint32_t verify_operation_budget,
                       uint64_t *verify_bytes_used,
                       uint32_t *verify_operations_used)
{
    struct mv_zcode_facts f;
    bool complete;
    bool manifest_integrity_ok;
    uint8_t release_id[VCS_PACKAGE_RELEASE_ID_BYTES];

    memset(&f, 0, sizeof(f));
    snprintf(out->display_name, sizeof(out->display_name), "%s", e->name);
    f.manifest_status = mv_manifest_read(ctx->zcode_dir, e->package_root_hex,
                                         &f.m);
    f.have_manifest = f.manifest_status == MV_MANIFEST_READ_OK;
    manifest_integrity_ok = f.have_manifest
                                ? f.m.root_matches_name
                                : f.manifest_status == MV_MANIFEST_READ_ABSENT;
    f.signature_verified = mv_release_read_verified(ctx->zcode_dir,
                                                    e->release_id_hex,
                                                    &f.release);
    if (verify_bytes_used)
        *verify_bytes_used = 0;
    if (verify_operations_used)
        *verify_operations_used = 0;
    if (f.have_manifest && f.m.root_matches_name)
        mv_manifest_verify_possession(
            ctx->zcode_dir, &f.m, verify_byte_budget,
            verify_operation_budget, verify_bytes_used,
            verify_operations_used);

    /* The immutable root is the manifest root. Claim it re-derived only
     * when we actually re-derived it from the stored wire. */
    if (f.have_manifest && f.m.root_matches_name) {
        out->has_content_root = true;
        memcpy(out->content_root, f.m.root, 32);
        out->total_bytes    = f.m.total_bytes;
        out->file_count     = f.m.file_count;
        out->chunk_total    = f.m.chunk_total;
        out->chunks_present = f.m.chunks_present;
        out->manifest_root_verified = f.m.manifest_root_verified;
        out->chunks_verified = f.m.chunks_verified;
        out->bytes_verified = f.m.bytes_verified;
        out->verification_complete = f.m.verification_complete;
        snprintf(out->verification_gap, sizeof(out->verification_gap), "%s",
                 f.m.verification_gap);
        complete = f.m.verification_complete;
    } else {
        /* No manifest wire: the release names a root whose bytes this node
         * does not hold. The index summary would report zeros here, and a
         * zero byte-count must not read as an empty package. */
        out->file_count = e->file_count;
        out->total_bytes = e->total_bytes;
        out->chunk_total = e->chunk_total;
        snprintf(out->verification_gap, sizeof(out->verification_gap), "%s",
                 f.manifest_status == MV_MANIFEST_READ_ABSENT
                     ? "manifest_absent"
                     : "manifest_unavailable");
        complete = false;
    }

    /* The signed envelope IS the descriptor; its release id is that
     * descriptor's root. Only claimed when the signature verified in this
     * call — an unverified envelope is not a descriptor we vouch for. */
    if (f.signature_verified &&
        vcs_package_release_id(&f.release, release_id) ==
            VCS_PACKAGE_RELEASE_OK) {
        out->has_descriptor_root = true;
        memcpy(out->descriptor_root, release_id, 32);
    }

    snprintf(out->owner_principal, sizeof(out->owner_principal), "%s",
             e->publisher_hex);
    out->owner_principal_kind = "publisher_pubkey";
    out->has_revision = true;
    out->revision     = e->publisher_sequence;

    /* No chain anchor exists for a ZCODE release: see the file header. */
    out->has_freshness_height = false;

    if (!complete) {
        out->status  = METAVERSE_STATUS_INCOMPLETE;
        out->actions = MV_ZCODE_ACTIONS_INCOMPLETE;
    } else if (f.signature_verified) {
        out->status  = METAVERSE_STATUS_PRESENT;
        out->actions = MV_ZCODE_ACTIONS_SIGNED_PRESENT;
    } else {
        out->status  = METAVERSE_STATUS_PRESENT;
        out->actions = MV_ZCODE_ACTIONS_UNSIGNED_PRESENT;
    }

    if (f.signature_verified) {
        char provenance[256];
        snprintf(provenance, sizeof(provenance),
                 "publisher signature over the release id verified in this "
                 "call; authorship only, not chain-anchored%s%s",
                 e->has_znam ? "; znam pointer claim: " : "",
                 e->has_znam ? e->znam : "");
        (void)zcl_text_fit(out->provenance, sizeof(out->provenance),
                           provenance, "metaverse", "provenance");
        (void)metaverse_view_determined(out,
                                        METAVERSE_EVIDENCE_LOCAL_SIGNATURE,
                                        "vcs_package_release_verify");
    } else if (f.have_manifest && f.m.root_matches_name) {
        snprintf(out->provenance, sizeof(out->provenance),
                 "manifest root re-derived locally; publisher signature NOT "
                 "verified in this call");
        (void)metaverse_view_determined(
            out, complete ? METAVERSE_EVIDENCE_LOCAL_CONTENT_HASH
                          : METAVERSE_EVIDENCE_LOCAL_MANIFEST_HASH,
            "vcs_package_manifest_root");
    } else {
        snprintf(out->provenance, sizeof(out->provenance),
                 "neither a verified release signature nor a matching "
                 "locally re-derived manifest root is available");
        metaverse_view_undetermined(
            out, "manifest is %s and the release signature did not verify; "
                 "refusing to claim local_content_hash evidence",
            f.have_manifest ? "root_mismatched"
                            : mv_manifest_read_status_name(f.manifest_status));
    }

    /* Reason carries whichever caveat applies; a determined view may still
     * have one, and the sharp cases must not be silent. */
    if (!out->determined) {
        /* metaverse_view_undetermined() already installed the precise
         * fail-closed reason; do not overwrite it with a lesser caveat. */
    } else if (!f.have_manifest &&
               f.manifest_status == MV_MANIFEST_READ_ABSENT)
        snprintf(out->reason, sizeof(out->reason),
                 "no manifest wire stored for this root: byte counts are the "
                 "release's own claim, not measured");
    else if (!f.have_manifest &&
             f.manifest_status != MV_MANIFEST_READ_ABSENT)
        snprintf(out->reason, sizeof(out->reason),
                 "manifest wire is %s: byte counts are the release's own "
                 "claim, not measured",
                 mv_manifest_read_status_name(f.manifest_status));
    else if (!f.m.root_matches_name)
        snprintf(out->reason, sizeof(out->reason),
                 "stored manifest re-derives a different root than its "
                 "filename");
    else if (!complete) {
        char reason[384];
        snprintf(reason, sizeof(reason),
                 "possession not proven: %s (%u/%u chunks and %llu/%llu "
                 "bytes verified)",
                 out->verification_gap[0] ? out->verification_gap
                                          : "incomplete",
                 out->chunks_verified, out->chunk_total,
                 (unsigned long long)out->bytes_verified,
                 (unsigned long long)out->total_bytes);
        (void)zcl_text_fit(out->reason, sizeof(out->reason), reason,
                           "metaverse", "reason");
    }
    else if (!f.signature_verified)
        snprintf(out->reason, sizeof(out->reason),
                 "release envelope absent or its signature failed to verify: "
                 "evidence grade reduced to local_content_hash");

    if (f.have_manifest)
        mv_manifest_free(&f.m);
    return manifest_integrity_ok;
}

static bool zcode_show(const struct metaverse_adapter_ctx *ctx,
                       const struct metaverse_property_id *id,
                       struct metaverse_property_view *out)
{
    struct vcs_package_index *index;
    const struct vcs_package_index_entry *e;

    if (!ctx || !id || !out || id->kind != METAVERSE_KIND_ZCODE_PACKAGE)
        return false;
    if (!metaverse_view_begin(out, id))
        return false;

    index = vcs_package_index_build(ctx->zcode_dir);
    if (!index) {
        metaverse_view_undetermined(
            out, "the package index projection could not be built over %s",
            ctx->zcode_dir);
        return true;
    }
    e = vcs_package_index_find_root(index, id->root);
    if (!e) {
        out->status  = METAVERSE_STATUS_ABSENT;
        out->actions = 0u;
        snprintf(out->provenance, sizeof(out->provenance),
                 "no persisted release envelope names this package root");
        snprintf(out->reason, sizeof(out->reason),
                 "no published release names this package root");
        (void)metaverse_view_determined(
            out, METAVERSE_EVIDENCE_LOCAL_STORE_READ,
            "vcs_package_index_find_root");
        vcs_package_index_free(index);
        return true;
    }
    (void)zcode_fill(ctx, e, out, MV_PROPERTY_VERIFY_BYTES,
                     MV_PROPERTY_SHOW_VERIFY_OPS, NULL, NULL);
    vcs_package_index_free(index);
    return true;
}

static size_t zcode_list(const struct metaverse_adapter_ctx *ctx,
                         struct metaverse_property_view *out, size_t out_cap,
                         struct metaverse_adapter_list_report *report)
{
    struct vcs_package_index *index;
    size_t total;
    size_t written = 0;
    uint64_t verify_bytes_left = MV_PROPERTY_VERIFY_BYTES;
    uint32_t verify_operations_left = MV_PROPERTY_LIST_VERIFY_OPS;

    if (report)
        memset(report, 0, sizeof(*report));
    /* out_cap == 0 is the legal count-only call; `out` is then unused. */
    if (!ctx || !report || (!out && out_cap > 0))
        return 0;

    index = vcs_package_index_build(ctx->zcode_dir);
    if (!index) {
        report->integrity_gap_count = 1;
        snprintf(report->integrity_reason,
                 sizeof(report->integrity_reason),
                 "package index could not be built over the release store");
        return 0;
    }
    total = vcs_package_index_count(index);
    for (size_t i = 0; i < total; i++) {
        const struct vcs_package_index_entry *e =
            vcs_package_index_at(index, i);
        struct metaverse_property_id id;
        struct metaverse_property_view scratch;
        struct metaverse_property_view *view =
            written < out_cap ? &out[written] : &scratch;
        uint8_t root[32];

        if (!e || !zcl_hex_decode_lower(e->package_root_hex, root, 32)) {
            report->integrity_gap_count++;
            if (report->integrity_reason[0] == '\0')
                snprintf(report->integrity_reason,
                         sizeof(report->integrity_reason),
                         "package index row %zu has an invalid root", i);
            continue;
        }
        if (!metaverse_property_id_make(METAVERSE_KIND_ZCODE_PACKAGE, root,
                                        &id) ||
            !metaverse_view_begin(view, &id)) {
            report->integrity_gap_count++;
            if (report->integrity_reason[0] == '\0')
                snprintf(report->integrity_reason,
                         sizeof(report->integrity_reason),
                         "package index row %zu could not be rendered", i);
            continue;
        }
        uint64_t bytes_used = 0;
        uint32_t operations_used = 0;
        uint64_t byte_budget = written < out_cap ? verify_bytes_left : 0;
        uint32_t operation_budget =
            written < out_cap ? verify_operations_left : 0;

        if (!zcode_fill(ctx, e, view, byte_budget, operation_budget,
                        &bytes_used, &operations_used)) {
            report->integrity_gap_count++;
            if (report->integrity_reason[0] == '\0')
                snprintf(report->integrity_reason,
                         sizeof(report->integrity_reason),
                         "package %.64s has a corrupt or root-mismatched "
                         "manifest",
                         e->package_root_hex);
        }
        verify_bytes_left -= bytes_used;
        verify_operations_left -= operations_used;
        if (written < out_cap)
            written++;
    }
    vcs_package_index_free(index);

    report->total = total;
    report->truncated = written < total;
    report->integrity_ok = report->integrity_gap_count == 0;
    return written;
}

const struct metaverse_adapter *metaverse_adapter_zcode_package(void)
{
    static const struct metaverse_adapter k_adapter = {
        .kind = METAVERSE_KIND_ZCODE_PACKAGE,
        .unavailable_reason = NULL,
        .list = zcode_list,
        .show = zcode_show,
        .store_ready = mv_zcode_store_ready,
    };
    return &k_adapter;
}
