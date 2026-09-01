/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: CAS-authoritative ZCODE science write/read services.
 *
 * Every write is an exact, expiring plan followed by a confirm:true commit.
 * The plan row (zcode_science_plans) is the durable idempotency ledger: it
 * persists the request identity hash (sha3-256 over the request domain,
 * kind, exact wire, and auxiliary roots), the exact wire, the expiry, and
 * the result root once committed. Committing the same request twice returns
 * the same result root and stores one CAS object. Expiry gates NEW
 * submissions only — stored evidence revalidates forever.
 *
 * The SQL projection tables are rebuildable lookup keys over the canonical
 * CAS wires; zcode_science_rebuild() drops and re-derives them from the
 * workspace CAS via vcs/zcode_science_index.h. */

#ifndef ZCL_SERVICES_ZCODE_SCIENCE_SERVICE_H
#define ZCL_SERVICES_ZCODE_SCIENCE_SERVICE_H

#include "base/result.h"
#include "models/zcode_science.h"
#include "vcs/build_action.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCODE_SCIENCE_PLAN_TTL_SECONDS 600

struct zcode_science_plan_out {
    char plan_root[65];
    char request_hash[65];
    int64_t expires_unix;
    bool already_planned; /* idempotent re-plan of the same request */
};

struct zcode_science_commit_out {
    char result_root[65];
    bool already_committed; /* durable idempotent reattach */
};

/* study.plan: validate the study_spec.v1 wire (structural + the submission
 * window must hold at now) and persist the exact expiring plan. */
struct zcl_result zcode_science_study_plan(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, int64_t now,
    struct zcode_science_plan_out *out);

/* study.commit: confirm:true + unexpired plan + exact-wire agreement;
 * idempotent reattach returns the committed root. Writes the wire to CAS
 * addressed by root and updates the projection. */
struct zcl_result zcode_science_study_commit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, bool confirm, int64_t now,
    struct zcode_science_commit_out *out);

/* Projection reads for study.show / study.list. show returns false via
 * *found when the root is not projected. */
struct zcl_result zcode_science_study_show(
    struct node_db *ndb, const char *study_root_hex,
    struct db_zcode_science_entry *out, bool *found);
struct zcl_result zcode_science_study_list(
    struct node_db *ndb, struct db_zcode_science_entry *out, int max,
    int *count);

/* work.plan/commit: the wire is benchmark_result.v2 (magic "ZCBEN2") or
 * reproduction.v1 (magic "ZCREPR"). For a v2 result the caller also
 * supplies the method/profile wires (stored to CAS at plan, addressed by
 * their canonical roots) and the executed fixed action; commit re-runs the
 * hardened S1 cross-validator incl. the canonical action binding. */
struct zcl_result zcode_science_work_plan(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len,
    const uint8_t *method_wire, size_t method_len,
    const uint8_t *profile_wire, size_t profile_len,
    const struct vcs_build_action_v1 *action,
    int64_t now, struct zcode_science_plan_out *out);
struct zcl_result zcode_science_work_commit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len,
    const struct vcs_build_action_v1 *action,
    bool confirm, int64_t now, struct zcode_science_commit_out *out);

/* work.status / work.receipt: projection reads by result or reproduction
 * root. receipt additionally re-loads the canonical CAS wire and verifies
 * the projection row against it; *kind is "result" or "reproduction". */
struct zcl_result zcode_science_work_status(
    struct node_db *ndb, const char *root_hex,
    struct db_zcode_science_entry *out, const char **kind, bool *found);
struct zcl_result zcode_science_work_receipt(
    struct node_db *ndb, const char *workspace, const char *root_hex,
    struct db_zcode_science_entry *out, const char **kind);

/* review.submit: PLAN_COMMIT contract in one leaf — without confirm the
 * call validates and persists the expiring plan; with confirm:true it
 * commits. Commit requires the findings wire in CAS and
 * review.created_unix >= findings.created_unix (H1). */
struct zcl_result zcode_science_review_submit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, bool confirm, int64_t now,
    struct zcode_science_plan_out *plan_out,
    struct zcode_science_commit_out *commit_out);

/* vote.submit: PLAN_COMMIT contract in one leaf. Commit seals nothing —
 * the wire arrives sealed; it runs curation_vote_verify against the
 * expected network genesis, voter zid, and signer (cross-network identity
 * rejection), rejects voter+sequence replay, and is idempotent by vote id. */
struct zcl_result zcode_science_vote_submit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_network_genesis[32],
    const uint8_t expected_voter_zid[32],
    const uint8_t expected_signer[32],
    bool confirm, int64_t now,
    struct zcode_science_plan_out *plan_out,
    struct zcode_science_commit_out *commit_out);

/* findings.plan/commit: the findings wire (science_findings.v1) binds the
 * study, task, candidate, result, and proof-set roots it discusses (plus
 * methods/limitations/conflicts documents and an optional retraction
 * target). plan validates the wire structurally; commit is confirm:true +
 * unexpired plan + exact-wire agreement, stores the wire to CAS addressed
 * by its canonical root, and updates the findings projection. Findings
 * carry no submission window — expiry gates plans, never stored evidence. */
struct zcl_result zcode_science_findings_plan(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, int64_t now,
    struct zcode_science_plan_out *out);
struct zcl_result zcode_science_findings_commit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, bool confirm, int64_t now,
    struct zcode_science_commit_out *out);

/* Shared plan/commit helpers — internal to the science service translation
 * units (zcode_science_service.c, zcode_science_findings.c,
 * zcode_science_carrier.c), not public API. See the file-top contract. */
struct zcl_result science_plan_open(
    struct node_db *ndb, const char *kind, const uint8_t *wire,
    size_t wire_len, const uint8_t *aux, size_t aux_len, int64_t now,
    struct zcode_science_plan_out *out);
struct zcl_result science_commit_prelude(
    struct node_db *ndb, const char *kind, const uint8_t *wire,
    size_t wire_len, const uint8_t *aux, size_t aux_len, bool confirm,
    int64_t now, struct db_zcode_science_plan *plan, bool *done,
    struct zcode_science_commit_out *out);
struct zcl_result science_plan_mark_committed(
    struct node_db *ndb, struct db_zcode_science_plan *plan,
    const char *result_root_hex);

/* Drop the six projection tables and rebuild them from the workspace CAS.
 * Rebuild-equivalence proof: output after rebuild is identical to output
 * before the drop. Plans are not touched. */
struct zcode_science_rebuild_out {
    size_t studies, results, reproductions, findings, votes, reviews;
};
struct zcl_result zcode_science_rebuild(
    struct node_db *ndb, const char *workspace, int64_t now,
    struct zcode_science_rebuild_out *out);

/* ── G1 carrier: science objects over the blob swarm ───────────────── */

struct vcs_package_store;

/* The wire kinds science_identify/publish/admit recognise, as stable
 * operator-visible tokens. */
#define ZCODE_SCIENCE_KIND_STUDY        "study"
#define ZCODE_SCIENCE_KIND_RESULT_V1    "result_v1"
#define ZCODE_SCIENCE_KIND_RESULT_V2    "result_v2"
#define ZCODE_SCIENCE_KIND_REPRODUCTION "reproduction"
#define ZCODE_SCIENCE_KIND_FINDINGS     "findings"
#define ZCODE_SCIENCE_KIND_REVIEW       "review"
#define ZCODE_SCIENCE_KIND_VOTE         "vote"
#define ZCODE_SCIENCE_KIND_PROFILE      "hardware_profile"
#define ZCODE_SCIENCE_KIND_METHOD       "benchmark_method"
#define ZCODE_SCIENCE_KIND_CAP 24

/* publish: mirror a committed science wire from the workspace CAS into
 * the package store as a one-chunk blob (vcs/blob_store.h), so the
 * package swarm carries it to peers. The wire is re-parsed, re-validated,
 * and its canonical root re-derived and compared against the requested
 * science root BEFORE mirroring — a corrupted or non-science CAS object
 * fails by name, never publishes. Returns the blob transport root in
 * out_blob_root (the science root stays the semantic address) and the
 * kind token in out_kind. Dual addressing is deliberate: blob root =
 * transport, science root = meaning, re-derived at admit time. */
struct zcl_result zcode_science_publish(
    struct vcs_package_store *store, const char *workspace,
    const char *science_root_hex,
    char out_blob_root[65], char out_kind[ZCODE_SCIENCE_KIND_CAP]);

/* admit: the receive half of the G1 carrier. Loads a blob from the
 * package store (fetch it first — vcs_blob_fetch / the swarm), identifies
 * the science wire by exact (magic, length), re-derives its canonical
 * root FROM THE BYTES (never trusted from any claim), stores it in the
 * workspace CAS addressed by that root, and refreshes the SQL projection
 * through the proven rebuild path. Idempotent: admitting an object the
 * CAS already holds succeeds with *out_new=false. Structural validation
 * only — first-party cryptographic identity checks (vote seals against
 * an EXPECTED network/zid/signer) stay at submit time; consumers
 * re-verify at read. Expiry gates first-party submission, never the
 * admission of valid historical evidence. */
struct zcl_result zcode_science_admit(
    struct vcs_package_store *store, struct node_db *ndb,
    const char *workspace, const char *blob_root_hex, int64_t now,
    char out_science_root[65], char out_kind[ZCODE_SCIENCE_KIND_CAP],
    bool *out_new);

/* Bounded dishonest-provider fallback: tries at most the DHT K shortlist of
 * transport objects in caller order. Every candidate crosses the same byte
 * verifier and must re-derive expected_science_root before admission. */
struct zcl_result zcode_science_admit_candidates(
    struct vcs_package_store *store, struct node_db *ndb,
    const char *workspace, const char *expected_science_root,
    const char *const *blob_roots, size_t blob_count, int64_t now,
    char out_blob_root[65], char out_kind[ZCODE_SCIENCE_KIND_CAP],
    bool *out_new, size_t *out_attempts);

#endif /* ZCL_SERVICES_ZCODE_SCIENCE_SERVICE_H */
