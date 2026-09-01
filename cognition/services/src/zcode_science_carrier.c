/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: G1 carrier — science CAS objects over the blob swarm.
 * Publishes committed science wires into the package store as one-chunk
 * content.v2 blobs (transport address = blob root) and admits fetched
 * blobs back into CAS, re-deriving the science root from the bytes —
 * never trusting a claimed root. Split out of zcode_science_service.c
 * for the file-size ceiling (E1). */

#include "services/zcode_science_service.h"

#include "base/hex.h"
#include "vcs/blob_store.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_dht.h"
#include "vcs/zcode_science.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Identify a science wire by exact (magic, length): parse + validate +
 * re-derive the canonical root. At most one kind can match — every parse
 * checks its own magic and exact length first. Votes are addressed by
 * vote id (their canonical root form). Returns false for anything that
 * is not a known, valid science wire. */
static bool science_identify_wire(const uint8_t *wire, size_t len,
                                  uint8_t root_out[32],
                                  const char **kind_out)
{
    if (!wire || !root_out || !kind_out)
        return false;
    if (len == VCS_ZCODE_STUDY_SPEC_WIRE_BYTES) {
        struct vcs_zcode_study_spec_v1 o;
        if (vcs_zcode_study_spec_parse(wire, len, &o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_study_spec_validate(&o) == VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_study_spec_root(&o, root_out) == VCS_ZCODE_SCIENCE_OK) {
            *kind_out = ZCODE_SCIENCE_KIND_STUDY;
            return true;
        }
    }
    if (len == VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES) {
        struct vcs_zcode_benchmark_result_v2 o;
        if (vcs_zcode_benchmark_result_v2_parse(wire, len, &o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_v2_validate(&o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_v2_root(&o, root_out) ==
                VCS_ZCODE_SCIENCE_OK) {
            *kind_out = ZCODE_SCIENCE_KIND_RESULT_V2;
            return true;
        }
    }
    if (len == VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES) {
        struct vcs_zcode_benchmark_result_v1 o;
        if (vcs_zcode_benchmark_result_parse(wire, len, &o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_validate(&o) == VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_result_root(&o, root_out) ==
                VCS_ZCODE_SCIENCE_OK) {
            *kind_out = ZCODE_SCIENCE_KIND_RESULT_V1;
            return true;
        }
    }
    if (len == VCS_ZCODE_REPRODUCTION_WIRE_BYTES) {
        struct vcs_zcode_reproduction_v1 o;
        if (vcs_zcode_reproduction_parse(wire, len, &o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_reproduction_validate(&o) == VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_reproduction_root(&o, root_out) ==
                VCS_ZCODE_SCIENCE_OK) {
            *kind_out = ZCODE_SCIENCE_KIND_REPRODUCTION;
            return true;
        }
    }
    if (len == VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES) {
        struct vcs_zcode_science_findings_v1 o;
        if (vcs_zcode_science_findings_parse(wire, len, &o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_science_findings_validate(&o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_science_findings_root(&o, root_out) ==
                VCS_ZCODE_SCIENCE_OK) {
            *kind_out = ZCODE_SCIENCE_KIND_FINDINGS;
            return true;
        }
    }
    if (len == VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES) {
        struct vcs_zcode_hardware_profile_v1 o;
        if (vcs_zcode_hardware_profile_parse(wire, len, &o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_hardware_profile_validate(&o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_hardware_profile_root(&o, root_out) ==
                VCS_ZCODE_SCIENCE_OK) {
            *kind_out = ZCODE_SCIENCE_KIND_PROFILE;
            return true;
        }
    }
    if (len == VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES) {
        struct vcs_zcode_benchmark_method_v1 o;
        if (vcs_zcode_benchmark_method_parse(wire, len, &o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_method_validate(&o) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_benchmark_method_root(&o, root_out) ==
                VCS_ZCODE_SCIENCE_OK) {
            *kind_out = ZCODE_SCIENCE_KIND_METHOD;
            return true;
        }
    }
    if (len == VCS_ZCODE_REVIEW_WIRE_BYTES) {
        /* review and curation_vote share a length; the magics differ and
         * each parse refuses the other's. */
        struct vcs_zcode_review_v1 review;
        if (vcs_zcode_review_parse(wire, len, &review) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_review_validate(&review) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_review_root(&review, root_out) == VCS_ZCODE_DEV_OK) {
            *kind_out = ZCODE_SCIENCE_KIND_REVIEW;
            return true;
        }
        struct vcs_zcode_curation_vote_v1 vote;
        if (vcs_zcode_curation_vote_parse(wire, len, &vote) ==
                VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_curation_vote_validate(&vote) == VCS_ZCODE_SCIENCE_OK &&
            vcs_zcode_curation_vote_id(&vote, root_out) ==
                VCS_ZCODE_SCIENCE_OK) {
            *kind_out = ZCODE_SCIENCE_KIND_VOTE;
            return true;
        }
    }
    return false;
}

struct zcl_result zcode_science_publish(
    struct vcs_package_store *store, const char *workspace,
    const char *science_root_hex,
    char out_blob_root[65], char out_kind[ZCODE_SCIENCE_KIND_CAP])
{
    if (!store || !workspace || !science_root_hex || !out_blob_root ||
        !out_kind)
        return ZCL_ERR(-1, "science-publish-input-invalid");
    uint8_t root[32];
    if (strlen(science_root_hex) != 64u ||
        !zcl_hex_decode_lower(science_root_hex, root, 32))
        return ZCL_ERR(-1, "science-publish-root-invalid");
    uint8_t *wire = NULL;
    size_t len = 0;
    if (vcs_object_load_raw(workspace, root, &wire, &len) != 0)
        return ZCL_ERR(-1, "science-publish-not-in-cas");
    uint8_t derived[32];
    const char *kind = NULL;
    bool ok = science_identify_wire(wire, len, derived, &kind);
    if (ok && memcmp(derived, root, 32) != 0)
        ok = false; /* CAS object does not re-derive its address: corrupt */
    if (!ok) {
        free(wire);
        return ZCL_ERR(-1, "science-publish-cas-corrupt");
    }
    uint8_t blob_root[32];
    enum vcs_blob_result br = vcs_blob_put_to(store, wire, len, blob_root);
    if (br == VCS_BLOB_OK) {
        zcl_hex_encode(blob_root, 32, out_blob_root);
        (void)snprintf(out_kind, ZCODE_SCIENCE_KIND_CAP, "%s", kind);
    }
    free(wire);
    if (br != VCS_BLOB_OK)
        return ZCL_ERR(-1, "science-publish-store-refused: %s",
                       vcs_blob_result_string(br));
    return ZCL_OK;
}

struct zcl_result zcode_science_admit(
    struct vcs_package_store *store, struct node_db *ndb,
    const char *workspace, const char *blob_root_hex, int64_t now,
    char out_science_root[65], char out_kind[ZCODE_SCIENCE_KIND_CAP],
    bool *out_new)
{
    if (!store || !ndb || !ndb->open || !workspace || !blob_root_hex ||
        !out_science_root || !out_kind || !out_new)
        return ZCL_ERR(-1, "science-admit-input-invalid");
    uint8_t blob_root[32];
    if (strlen(blob_root_hex) != 64u ||
        !zcl_hex_decode_lower(blob_root_hex, blob_root, 32))
        return ZCL_ERR(-1, "science-admit-root-invalid");
    uint8_t wire[VCS_BLOB_MAX_BYTES];
    size_t len = 0;
    enum vcs_blob_result br = vcs_blob_get_from(store, blob_root, wire,
                                                sizeof(wire), &len);
    if (br == VCS_BLOB_ERR_ABSENT || br == VCS_BLOB_ERR_FETCH)
        return ZCL_ERR(-1, "science-admit-blob-absent: fetch it first");
    if (br != VCS_BLOB_OK)
        return ZCL_ERR(-1, "science-admit-blob-read: %s",
                       vcs_blob_result_string(br));
    uint8_t root[32];
    const char *kind = NULL;
    if (!science_identify_wire(wire, len, root, &kind))
        return ZCL_ERR(-1, "science-admit-not-science");
    *out_new = !vcs_object_has(workspace, root);
    if (*out_new && !vcs_object_put_addressed(workspace, root, wire, len))
        return ZCL_ERR(-1, "science-admit-cas-store-failed");
    struct zcode_science_rebuild_out rebuilt;
    ZCL_CHECK(zcode_science_rebuild(ndb, workspace, now, &rebuilt));
    zcl_hex_encode(root, 32, out_science_root);
    (void)snprintf(out_kind, ZCODE_SCIENCE_KIND_CAP, "%s", kind);
    return ZCL_OK;
}

struct zcl_result zcode_science_admit_candidates(
    struct vcs_package_store *store, struct node_db *ndb,
    const char *workspace, const char *expected_science_root,
    const char *const *blob_roots, size_t blob_count, int64_t now,
    char out_blob_root[65], char out_kind[ZCODE_SCIENCE_KIND_CAP],
    bool *out_new, size_t *out_attempts)
{
    if (!store || !ndb || !workspace || !expected_science_root ||
        !blob_roots || !blob_count || blob_count > VCS_ZCODE_DHT_K ||
        !out_blob_root ||
        !out_kind || !out_new || !out_attempts)
        return ZCL_ERR(-1, "science-candidates-input-invalid");
    *out_attempts = 0;
    out_blob_root[0] = '\0';
    for (size_t i = 0; i < blob_count; i++) {
        uint8_t transport[32], wire[VCS_BLOB_MAX_BYTES], derived_root[32];
        size_t wire_len = 0;
        const char *identified_kind = NULL;
        if (!blob_roots[i] || strlen(blob_roots[i]) != 64 ||
            !zcl_hex_decode_lower(blob_roots[i], transport, 32)) {
            (*out_attempts)++;
            continue;
        }
        (*out_attempts)++;
        if (vcs_blob_get_from(store, transport, wire, sizeof(wire),
                              &wire_len) != VCS_BLOB_OK ||
            !science_identify_wire(wire, wire_len, derived_root,
                                   &identified_kind))
            continue;
        char verified_root[65];
        zcl_hex_encode(derived_root, 32, verified_root);
        if (strcmp(verified_root, expected_science_root) != 0)
            continue;
        char derived[65], kind[ZCODE_SCIENCE_KIND_CAP];
        bool is_new = false;
        struct zcl_result admitted = zcode_science_admit(
            store, ndb, workspace, blob_roots[i], now, derived, kind,
            &is_new);
        if (!admitted.ok || strcmp(derived, expected_science_root) != 0)
            continue;
        memcpy(out_blob_root, blob_roots[i], 65);
        snprintf(out_kind, ZCODE_SCIENCE_KIND_CAP, "%s", kind);
        *out_new = is_new;
        return ZCL_OK;
    }
    return ZCL_ERR(-1, "science-candidates-no-verified-provider");
}
