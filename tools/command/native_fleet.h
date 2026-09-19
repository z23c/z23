/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet` leaves' handlers — the owner's private fleet ledger.
 * Each answers from local files under the datadir and contacts no peer. */

#ifndef ZCL_NATIVE_FLEET_H
#define ZCL_NATIVE_FLEET_H

#include <stdbool.h>
#include <stddef.h>

struct zcl_command_request;
struct zcl_command_reply;

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

#endif /* ZCL_NATIVE_FLEET_H */
