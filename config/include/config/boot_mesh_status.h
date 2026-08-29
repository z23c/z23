/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Authenticated machine status request/receipt lane on zpkgswm.
 *
 * The mesh status protocol multiplexes on the frozen "zpkgswm" P2P message
 * with a "ZMSTAT" prefix, exactly like ZCDHTM/ZSR1/ZCWS: no new wire message,
 * no listener, no port. It inherits the v2 Noise session, the onion path, and
 * connman session management. Every request is answered with a signed
 * mesh_status_receipt_v1 (OK or a named refusal) only when the session is an
 * established v2 Noise session bound to a live ZID delegation; anything less
 * is dropped quietly without a receipt, so no responder key material ever
 * crosses an unauthenticated channel.
 *
 * Session binding note: v2_transport_snapshot's transcript_hash and
 * connection_generation are transcript-derived and identical on both sides;
 * the wire binds only that shared session evidence (the process-local
 * per-side connection_serial left the protocol in 2114f5257). The responder
 * verifies transcript/generation/remote-static against its live snapshot,
 * and the requester verifies the receipt's echoed pair against the CURRENT
 * snapshot of the sending node. A receipt arriving on a newer or different
 * connection fails that check and never completes the pending entry. */

#ifndef ZCL_CONFIG_BOOT_MESH_STATUS_H
#define ZCL_CONFIG_BOOT_MESH_STATUS_H

#include "session/mesh_status_proto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct db_service;
struct json_value;
struct msg_processor;
struct node_db;
struct node_db_status;
struct p2p_node;
struct rpc_table;
struct v2_transport_snapshot;
struct vcs_zcode_dht_delegation;

#define MESH_STATUS_FRAME_PREFIX "ZMSTAT"
#define MESH_STATUS_FRAME_PREFIX_LEN 6u
#define MESH_STATUS_FRAME_KIND_REQUEST 0x01u
#define MESH_STATUS_FRAME_KIND_RECEIPT 0x02u
#define MESH_STATUS_FRAME_MAX \
    (MESH_STATUS_FRAME_PREFIX_LEN + 1u + MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES)

/* Bounded request lifetime issued by the requester lane (protocol ceiling is
 * MESH_STATUS_MAX_LIFETIME_SECONDS = 60). */
#define MESH_STATUS_REQUEST_LIFETIME_SECONDS 30u
#define MESH_STATUS_PENDING_MAX 16u
#define MESH_STATUS_RESULT_RETENTION_S 30u

/* msg_zcode_swarm_frame_fn adapter: returns true only when the ZMSTAT
 * namespace matched and the frame was consumed (answered, completed, or
 * dropped by policy). Unknown prefixes return false so later swarm
 * dispatchers see the frame unchanged. */
bool boot_mesh_status_frame(struct msg_processor *mp, struct p2p_node *node,
                            const uint8_t *payload, size_t payload_len,
                            struct boot_svc_ctx *svc);

/* Records the composition context the requester lane needs (msg_processor,
 * datadir). Called from boot_zcode_swarm_wire; shutdown clears it and every
 * pending request. */
void boot_mesh_status_wire(struct boot_svc_ctx *svc);
void boot_mesh_status_shutdown(void);
void boot_mesh_status_register_rpc(struct rpc_table *table,
                                   struct node_db *ndb,
                                   struct db_service *dbsvc);

/* Advance the bounded owner-status refresh lane from the supervised network
 * clock. Completed receipts enter the serialized writer before their slot is
 * reused. New work is admitted only at chain tip; no connection is created. */
void boot_mesh_status_refresh_start(struct boot_svc_ctx *svc);
void boot_mesh_status_refresh_shutdown(void);

/* Store one already-verified receipt through the serialized DB writer. */
bool boot_mesh_status_receipt_persist(
    struct db_service *dbsvc,
    const struct mesh_status_receipt_v1 *receipt);

enum boot_mesh_status_begin_result {
    MESH_STATUS_BEGIN_OK = 0,
    MESH_STATUS_BEGIN_BAD_ARGUMENT,
    MESH_STATUS_BEGIN_UNAVAILABLE,       /* composition not wired */
    MESH_STATUS_BEGIN_V2_DISABLED,       /* -v2transport=0: no Noise sessions */
    MESH_STATUS_BEGIN_NOT_PAIRED,
    MESH_STATUS_BEGIN_REVOKED,
    MESH_STATUS_BEGIN_EXPIRED,
    MESH_STATUS_BEGIN_PEER_NOT_CONNECTED,
    MESH_STATUS_BEGIN_IDENTITY_UNAVAILABLE,
    MESH_STATUS_BEGIN_PEER_IDENTITY_UNAVAILABLE,
    MESH_STATUS_BEGIN_BUSY,              /* pending table full */
    MESH_STATUS_BEGIN_SEND_FAILED,
};

const char *boot_mesh_status_begin_result_string(
    enum boot_mesh_status_begin_result result);

/* Begin one bounded status request to the paired peer. On OK,
 * request_id_out carries the random 32-byte request id. No dial is ever
 * performed: a paired peer without a live established v2 session is
 * PEER_NOT_CONNECTED. */
enum boot_mesh_status_begin_result boot_mesh_status_begin(
    const char *pairing_id_hex, uint8_t request_id_out[32]);

enum boot_mesh_status_poll_state {
    MESH_STATUS_POLL_UNKNOWN = 0,   /* no such request, or service restarted */
    MESH_STATUS_POLL_PENDING,
    MESH_STATUS_POLL_OK,            /* receipt_out: status OK + capsule */
    MESH_STATUS_POLL_REFUSED,       /* receipt_out: named refusal receipt */
    MESH_STATUS_POLL_EXPIRED,       /* entry cancelled on expiry */
};

enum boot_mesh_status_poll_state boot_mesh_status_poll(
    const uint8_t request_id[32], struct mesh_status_receipt_v1 *receipt_out);

/* Pure responder decision: no sockets, no locks, no I/O beyond the pairing
 * reads on ndb. `delegations` is the held-delegation snapshot; `session` must
 * be an established v2 snapshot. revocation_generation_out is set on OK.
 * Exported (not static) so the wire group test drives the exact production
 * decision without sockets. */
enum mesh_status_receipt_status boot_mesh_status_decide(
    struct node_db *ndb, const struct mesh_status_request_v1 *request,
    const struct v2_transport_snapshot *session,
    const struct vcs_zcode_dht_delegation *delegations,
    size_t delegation_count, const uint8_t network_genesis[32],
    uint64_t now_unix, uint64_t *revocation_generation_out);

/* Pure receipt composition + online-key signature. Capsule bytes are
 * required iff status is OK. */
bool boot_mesh_status_compose_receipt(
    const struct mesh_status_request_v1 *request,
    const struct v2_transport_snapshot *session,
    enum mesh_status_receipt_status status, const uint8_t network_genesis[32],
    const uint8_t responder_master_pubkey[32],
    const uint8_t responder_online_pubkey[32],
    const uint8_t responder_noise_static[32], uint64_t revocation_generation,
    uint64_t now_unix, const uint8_t *capsule, size_t capsule_len,
    const uint8_t responder_online_seed[32],
    struct mesh_status_receipt_v1 *out);

/* Pure requester-side acceptance of an already decoded (signature-verified)
 * receipt against the pending request and the CURRENT session snapshot of
 * the sending node. */
bool boot_mesh_status_receipt_accept(
    const struct mesh_status_receipt_v1 *receipt,
    const struct mesh_status_request_v1 *request,
    const struct v2_transport_snapshot *session,
    const uint8_t expected_responder_master[32],
    const uint8_t expected_responder_online[32]);

/* Durable-evidence handoff, synchronous: persist one verified terminal
 * receipt (OK or a named refusal) as the pairing's latest machine
 * observation, directly on the caller's node_db. The store refuses older or
 * same-time equivocal evidence and treats an exact-root replay as
 * idempotent. Production writers (status poll, fleet refresh, background
 * refresh scheduler) instead go through boot_mesh_status_receipt_persist,
 * which runs this same store write on the serialized db_service lane; this
 * direct variant serves tests that own the only writer. */
bool boot_mesh_status_persist_observation(
    struct node_db *ndb, const struct mesh_status_receipt_v1 *receipt);

/* Domain-separated SHA3-256 fingerprint of a public key, lowercase hex
 * (65-byte out). Shared by every mesh operator surface so rendered
 * fingerprints never drift between views. */
void boot_mesh_status_key_fingerprint(const char *domain,
                                      const uint8_t key[32], char out[65]);

#ifdef ZCL_TESTING
void boot_mesh_status_receipt_test_render(
    struct json_value *result,
    const struct mesh_status_receipt_v1 *receipt);
void boot_mesh_status_machines_test_render(
    struct node_db *ndb, int64_t now, struct json_value *result);
bool boot_mesh_status_test_responder_admit(
    const struct mesh_status_request_v1 *request,
    const struct v2_transport_snapshot *session, uint64_t now_mono_ms);
bool boot_mesh_status_refresh_test_gate(
    bool running, int sync_state, int disk_level, int memory_level,
    bool long_db_operation, bool db_service_started,
    const struct node_db_status *db_status);
#endif

#endif /* ZCL_CONFIG_BOOT_MESH_STATUS_H */
