/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_AGENT_OPERATOR_CONTRACTS_H
#define ZCL_CONTROLLERS_AGENT_OPERATOR_CONTRACTS_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;
struct legacy_mirror_sync_stats;

/* ── The public status contract version ────────────────────────────────
 *
 * ONE definition shared by every producer (the `agent` RPC, /api/status,
 * /api/node/summary) and by the CLI reader that validates their output
 * (status_brief_native_handler.c), so a bump can never leave a producer and
 * a consumer naming different versions.
 *
 * v3 adds the readiness facts below. v2 remains a FULLY SUPPORTED read: the
 * v3 additions are optional on the read side, so a v2 document from an older
 * node still passes strict validation and still produces a complete brief —
 * only the new facts are absent from it. Anything else in the family (v1, or
 * a future v4) is version skew and degrades to the lenient best-effort
 * path. */
#define ZCL_PUBLIC_STATUS_SCHEMA_FAMILY "zcl.public_status."
#define ZCL_PUBLIC_STATUS_SCHEMA "zcl.public_status.v3"
#define ZCL_PUBLIC_STATUS_SCHEMA_V2 "zcl.public_status.v2"

struct agent_operator_latch_contract_view {
    bool active;
    bool operator_action_required;
    bool recovered_this_call;
    bool suppressed_by_mirror_contract;
    int64_t since_unix;
    const char *detail;
};

struct agent_condition_summary_contract_view {
    int active_count;
    int unresolved_count;
    int unresolved_critical_count;
};

bool agent_operator_latch_suppressed_by_mirror(
    bool active,
    const char *detail,
    const struct legacy_mirror_sync_stats *mirror);

void agent_push_operator_latch_contract_json(
    struct json_value *out,
    const struct agent_operator_latch_contract_view *view);

void agent_push_condition_summary_contract_json(
    struct json_value *out,
    const struct agent_condition_summary_contract_view *view);

/* ── Separately named readiness facts ──────────────────────────────────
 *
 * One blurry "are you ready?" verdict answered four different operator
 * questions at once. These name them apart, each read from the surface
 * that already computes it.
 *
 * archive_complete is deliberately INDEPENDENT of tip_follow. A complete
 * block archive is ~13 GB; the cold-sync budget can only move a couple of
 * hundred MB, so requiring a complete archive before a node may call
 * itself tip-following would turn a reachable target into an impossible
 * one. `incomplete` coexisting with `tip_follow: true` is the normal,
 * healthy shape of a freshly synced node — not a fault. */
enum status_archive_completeness {
    /* Fail-closed default: nobody has established an answer. A failed or
     * never-run census lands here — never on `complete`. */
    STATUS_ARCHIVE_UNKNOWN = 0,
    STATUS_ARCHIVE_INCOMPLETE,
    STATUS_ARCHIVE_COMPLETE,
};

/* "unknown" | "incomplete" | "complete"; out-of-range → "unknown". */
const char *status_archive_completeness_name(enum status_archive_completeness c);

struct status_readiness_facts_view {
    /* Keeping up with the network tip. agent_tip_follow() — the node's proven
     * height measured against the network tip, NOT the sync FSM's at_tip
     * flag, and never gated on archive completeness. */
    bool tip_follow;
    /* Wallet readable (keys loaded, canary passed). A node in NO-SPEND mode
     * still reaches this: viewing is never gated. */
    bool wallet_view_ready;
    /* Wallet may SPEND. False on a keyless no-spend boot (no passphrase and
     * no plaintext opt-in — see wallet_at_rest_boot_decision()) and false on
     * borrowed, not-yet-self-folded state. Both are SAFE states that sync
     * normally; neither is a failure. */
    bool wallet_spend_allowed;
    enum status_archive_completeness archive_complete;
    /* History verified by replay (agent_security_posture.
     * full_history_validation_complete). */
    bool full_replay_verified;
};

struct agent_security_posture;

/* Collect the facts. Cheap + reentrant: atomic/in-memory reads plus one
 * TTL-cached, trylock-only trust-tier collection. `tip_gap`/`log_head_gap`
 * and `posture` come from the caller's already-collected snapshot — nothing
 * is re-read. A NULL out is a no-op; a NULL posture leaves
 * full_replay_verified at its fail-closed false. */
void status_readiness_facts_collect(int tip_gap, int log_head_gap,
                                    const struct agent_security_posture *posture,
                                    struct status_readiness_facts_view *out);

/* Emit the facts as flat keys on `out` (tip_follow, wallet_view_ready,
 * wallet_spend_allowed, archive_complete, full_replay_verified). This is the
 * v3 addition to zcl.public_status. */
void status_push_readiness_facts_json(
    struct json_value *out, const struct status_readiness_facts_view *view);

#endif /* ZCL_CONTROLLERS_AGENT_OPERATOR_CONTRACTS_H */
