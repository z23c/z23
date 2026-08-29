/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Owner-facing local pairing ceremony: plan/commit.
 *
 * This is the local half of machine pairing: it exposes the existing
 * mesh_pairing_service accept authority to the operator without
 * creating a way to bypass it. plan and commit re-derive EVERYTHING live —
 * the established v2 Noise session, the held ZID delegation, the current
 * time — and commit additionally requires the peer's Noise fingerprint
 * compared out of band (read from `ops mesh pair plan` here and `ops mesh
 * identity` on the other machine). The granted capability is status-read
 * only. Inspection and revocation live in the mesh pairing controller
 * (`ops mesh pair list` / `ops mesh pair revoke`).
 * There is no two-sided wire ceremony yet: each host pairs the other
 * independently, and no dial is ever performed — a peer with no live
 * session is PEER_NOT_CONNECTED.
 */

#ifndef ZCL_CONFIG_BOOT_MESH_PAIRING_H
#define ZCL_CONFIG_BOOT_MESH_PAIRING_H

#include "models/mesh_pairing.h"
#include "services/mesh_pairing_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct rpc_table;

#define BOOT_MESH_PAIRING_DEFAULT_DAYS 7
#define BOOT_MESH_PAIRING_MAX_DAYS \
    (MESH_PAIRING_MAX_LIFETIME_SECONDS / 86400)

/* What commit would record, rendered from a live re-derivation. */
struct boot_mesh_pairing_plan {
    char peer_addr[256];
    uint8_t peer_noise_static[32];
    uint8_t peer_noise_fingerprint[32];
    uint8_t peer_master_pubkey[32];
    uint64_t delegation_not_before;
    uint64_t delegation_expiry; /* zid doc expiry, unix seconds */
    uint64_t delegation_sequence;
    uint32_t delegation_beacon_height;
    uint64_t capability_mask; /* always MESH_PAIRING_CAP_STATUS_READ */
    int64_t now;
    int64_t default_expires_at; /* now + BOOT_MESH_PAIRING_DEFAULT_DAYS */
    char pairing_id[MESH_PAIRING_ID_HEX + 1]; /* id commit would derive */
    /* "active"/"expired"/"revoked" when a durable record already exists,
     * empty when none (or when the node db cannot be read — advisory only;
     * commit re-checks authority from scratch). */
    char existing_state[9];
};

enum boot_mesh_pairing_plan_result {
    MESH_PAIR_PLAN_OK = 0,
    MESH_PAIR_PLAN_BAD_ARGUMENT,
    MESH_PAIR_PLAN_UNAVAILABLE, /* composition not wired */
    MESH_PAIR_PLAN_V2_DISABLED,
    MESH_PAIR_PLAN_PEER_NOT_CONNECTED,
    MESH_PAIR_PLAN_AMBIGUOUS_PEER,
    MESH_PAIR_PLAN_DELEGATION_UNAVAILABLE,
};

const char *boot_mesh_pairing_plan_result_string(
    enum boot_mesh_pairing_plan_result result);

enum boot_mesh_pairing_commit_result {
    MESH_PAIR_COMMIT_OK = 0,
    MESH_PAIR_COMMIT_BAD_ARGUMENT, /* includes out-of-range days */
    MESH_PAIR_COMMIT_UNAVAILABLE,
    MESH_PAIR_COMMIT_V2_DISABLED,
    MESH_PAIR_COMMIT_PEER_NOT_CONNECTED,
    MESH_PAIR_COMMIT_AMBIGUOUS_PEER,
    MESH_PAIR_COMMIT_DELEGATION_UNAVAILABLE,
    MESH_PAIR_COMMIT_SERVICE_REFUSED, /* service_reason_out carries why */
};

const char *boot_mesh_pairing_commit_result_string(
    enum boot_mesh_pairing_commit_result result);

/* ── Pure helpers (no sockets, no db, no locks) ──────────────────────── */

/* Commit lifetimes: days must be in [1, BOOT_MESH_PAIRING_MAX_DAYS]; the
 * default applies when the operator did not pass --days. */
bool boot_mesh_pairing_days_valid(int64_t days);
int64_t boot_mesh_pairing_expiry(int64_t now, int64_t days);

/* Durable record state derived from now: revocation is sticky and wins
 * over expiry. */
const char *boot_mesh_pairing_state(const struct db_mesh_pairing *row,
                                    int64_t now);

/* Peer selector: substring match on the peer's address, or lowercase prefix
 * match on its Noise fingerprint hex. Empty/NULL selector matches every
 * session peer (the caller then requires exactly one). */
bool boot_mesh_pairing_selector_matches(const char *selector,
                                        const char *addr_name,
                                        const char fingerprint_hex[65]);

/* 64 canonical lowercase hex chars -> 32 bytes (the out-of-band compared
 * Noise fingerprint). */
bool boot_mesh_pairing_decode_fingerprint(const char *hex, uint8_t out[32]);

/* Uppercase command-result code for one service refusal reason. */
const char *boot_mesh_pairing_reason_code(enum mesh_pairing_reason reason);

/* ── Live layer (wired svc; never dials) ─────────────────────────────── */

void boot_mesh_pairing_wire(struct boot_svc_ctx *svc);
void boot_mesh_pairing_shutdown(void);
void boot_mesh_pairing_register_rpc(struct rpc_table *table);

enum boot_mesh_pairing_plan_result boot_mesh_pairing_plan(
    const char *selector, struct boot_mesh_pairing_plan *out);

/* expected_fingerprint is the MANDATORY out-of-band compared value. days of
 * zero with days_given=false selects the default. On MESH_PAIR_COMMIT_OK the
 * durable record (new or identical-existing) is in out. */
enum boot_mesh_pairing_commit_result boot_mesh_pairing_commit(
    const char *selector, const uint8_t expected_fingerprint[32],
    int64_t days, bool days_given, struct db_mesh_pairing *out,
    enum mesh_pairing_reason *service_reason_out);

#endif /* ZCL_CONFIG_BOOT_MESH_PAIRING_H */
