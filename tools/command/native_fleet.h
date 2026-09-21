/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet` leaves' handlers — the owner's private fleet ledger.
 * Each answers from local files under the datadir and contacts no peer. */

#ifndef ZCL_NATIVE_FLEET_H
#define ZCL_NATIVE_FLEET_H

#include <stdbool.h>
#include <stddef.h>

struct zcl_command_request;
struct zcl_command_reply;
struct json_value;

void zcl_native_handle_fleet_ledger_add(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_ledger_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_usage(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply);
void zcl_native_handle_fleet_vitals_sample(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_experiment_predict(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_experiment_result(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_experiment_stats(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_experiment_export(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_roles_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_roles_grant(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_roles_revoke(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_link_probe(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_roles_check(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* fleet.steer.* — the thin remote-STEER adapter over mail, queue, board and
 * receipts (tools/command/native_fleet_steer.c). Brief/send/evidence compose
 * sibling leaves in-process; the grant leaf mints and revokes the
 * adapter's own scoped bearer grants. */
void zcl_native_handle_fleet_steer_brief(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_steer_send(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_steer_evidence(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_fleet_steer_grant(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* A sender binding: 32 lowercase hex, the public stamp of one grant.
 * Never the grant id — the id IS the bearer secret. */
#define ZCL_FLEET_STEER_BINDING_HEX 32

/* Derive the binding a sender holding `grant_id` stamps rows with under
 * `label`. Deterministic, one-way, and computable only by a holder of the
 * grant id, which is why a receiver can treat it as proof that the row came
 * from that grant. False when an argument is missing or `cap` is short. The
 * grant id is consumed and never echoed, logged, or stored by this call. */
bool zcl_fleet_steer_sender_binding(const char *grant_id, const char *label,
                                    char *out, size_t cap);

/* The one shared admission reader of <state>/steer/grants.jsonl. Returns
 * NULL when a live (not revoked, not expired) grant carries `label` with
 * `scope` AND stamps exactly `binding`, otherwise the fail-closed
 * STEER_GRANT_* reason for the closest matching row ("STEER_GRANT_UNKNOWN"
 * when no row carries the label at all, including when there is no store
 * yet; "STEER_GRANT_BINDING" when a live row carries the label but did not
 * write this stamp — someone else's credential claiming this name). The
 * store is re-read on every call, so a revoke takes effect immediately.
 *
 * The LABEL alone is not authority and never was: it is a name the owner
 * minted a grant under, and anything may write any name into a row. The
 * binding is what ties the row to the credential that actually carried it,
 * so an admission asks for both. An empty binding is refused here rather
 * than treated as "not applicable": an unattributable row is refused, not
 * admitted. Callers that must not write anything are safe — this never
 * creates the steer directory. Implemented in
 * tools/command/native_fleet_steer.c beside the store it reads, so no
 * second permission system can drift away from it. */
const char *zcl_fleet_steer_grant_binding_live(const char *label,
                                               const char *binding,
                                               const char *scope);

/* The expiry timestamp of the authority carrying `label` with `scope`,
 * read from the SAME grants.jsonl store under the SAME liveness rule as
 * the binding admission above: 0 when a live grant never expires,
 * otherwise the longest live expiry. No new format, no new scope.
 * Returns false when no live grant carries the label with the scope (or
 * on a bad argument), so the caller fails closed. Implemented in
 * tools/command/native_fleet_steer.c beside the store it reads. */
bool zcl_fleet_steer_grant_expiry(const char *label, const char *scope,
                                  long long *out);

/* The admission reader for a row that came over the signed fleet board
 * from the enrolled box `peer` (a roster name). Returns NULL when a live
 * grant minted with peer=<peer> carries `label` with `scope`, otherwise the
 * fail-closed STEER_GRANT_* reason ("STEER_GRANT_PEER" when the label is
 * granted, but not to that box). A local grant never answers here and a
 * peer grant never answers zcl_fleet_steer_grant_binding_live: a board row
 * is admitted on its verified signer, an unsigned row on its binding, and
 * neither can borrow the other's grant. Re-reads the store on every call
 * and never creates the steer directory. */
const char *zcl_fleet_steer_grant_peer_live(const char *label,
                                            const char *peer,
                                            const char *scope);


/* ── fleet.steer.brief candidate registry ────────────────────────────────
 *
 * One row per candidate keyed by its ref, which is the stable identity: the
 * same ref seen in mail AND on the board AND in the queue is ONE candidate
 * with three sources. Each row carries the strongest state its evidence
 * supports, so an operator can tell a handover from a proof from a landing
 * instead of reading four different facts as one bare string.
 *
 * Unknown is never zero here. `evidence_age_s` and `candidates_total` emit
 * null when they could not be measured, and `landed` stays null until
 * something attests it. Implemented in
 * tools/command/native_fleet_steer_candidates.c; it opens no file, takes no
 * lock and spawns nothing, so assembling a brief cannot mutate work. */

#define ZCL_FMC_CAND_CAP 32u
#define ZCL_FMC_CAND_ID_CAP 129u
#define ZCL_FMC_CAND_AGENT_CAP 65u
#define ZCL_FMC_CAND_ATTESTERS 4u

#define ZCL_FMC_CAND_SRC_MAIL 0x1u
#define ZCL_FMC_CAND_SRC_BOARD 0x2u
#define ZCL_FMC_CAND_SRC_QUEUE 0x4u

struct zcl_fmc_cand {
    char id[ZCL_FMC_CAND_ID_CAP];
    char attester[ZCL_FMC_CAND_ATTESTERS][ZCL_FMC_CAND_AGENT_CAP];
    long long age_s;
    unsigned sources;
    unsigned attesters; /* Stored distinct names, bounded by the array. */
    bool attesters_incomplete;
    unsigned state;
    bool age_known;
    bool age_unparsable;
    bool landed_attested;
    bool proven;
};

struct zcl_fmc_cand_reg {
    struct zcl_fmc_cand row[ZCL_FMC_CAND_CAP];
    size_t count;
    size_t dropped; /* Omitted sightings; their distinct total is unknown. */
    bool mail_ok;
    bool board_ok;
    bool queue_ok;
};

/* Zero the registry. Every source starts UNREAD, not empty: a caller that
 * never reports a source leaves the total unknown rather than asserting
 * one it did not measure. */
void zcl_fmc_cand_init(struct zcl_fmc_cand_reg *reg);

/* Declare that `source` (a ZCL_FMC_CAND_SRC_* bit, or several) was read to
 * completion. Only this call can make candidates_total a number. */
void zcl_fmc_cand_source_ok(struct zcl_fmc_cand_reg *reg, unsigned source);

/* One sighting of `id` from `source`, vouched for by `attester`. A sighting
 * from anything but the queue is a handover, so it reaches `delivered`.
 * Sender names never establish remote verification. age_known false records the
 * age as unparsable instead of pinning it to 0. */
void zcl_fmc_cand_note(struct zcl_fmc_cand_reg *reg, const char *id,
                       unsigned source, const char *attester,
                       long long age_s, bool age_known);

/* A passing outcome report for `id`, without receipt verification. */
void zcl_fmc_cand_note_proven(struct zcl_fmc_cand_reg *reg, const char *id,
                              long long age_s, bool age_known);

/* An explicit landing report, without publication verification. */
void zcl_fmc_cand_note_landed(struct zcl_fmc_cand_reg *reg, const char *id,
                              const char *attester, long long age_s,
                              bool age_known);

/* Append one object per candidate to `out`, the counts to `summary`, and a
 * {source, reason, age_ms} row to `missing` for each source never read. */
void zcl_fmc_cand_emit(const struct zcl_fmc_cand_reg *reg,
                       struct json_value *out, struct json_value *summary,
                       struct json_value *missing);

#endif /* ZCL_NATIVE_FLEET_H */
