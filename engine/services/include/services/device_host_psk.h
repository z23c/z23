/* purpose: Define owner-bound PSK handshake, records and borrowed guarded release spans. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_HOST_PSK_H
#define ZCL_SERVICES_DEVICE_HOST_PSK_H
#include "base/result.h"
#include "models/device_pairing.h"
#include "sha3/shake_wrap.h"
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#define DEVICE_HOST_PSK_HEADER 24u
#define DEVICE_HOST_PSK_WIRE 4184u
#define DEVICE_HOST_PSK_TRANSCRIPT 526u
#define DEVICE_HOST_PSK_FRAME_LIMIT UINT64_C(1048576)
enum device_host_psk_phase {
    DEVICE_HOST_PSK_FRESH, DEVICE_HOST_PSK_CLIENT_SEND_HELLO, DEVICE_HOST_PSK_CLIENT_WAIT_HELLO,
    DEVICE_HOST_PSK_CLIENT_SEND_CONFIRM, DEVICE_HOST_PSK_CLIENT_WAIT_READY,
    DEVICE_HOST_PSK_SERVER_WAIT_HELLO, DEVICE_HOST_PSK_SERVER_SEND_HELLO,
    DEVICE_HOST_PSK_SERVER_WAIT_CONFIRM, DEVICE_HOST_PSK_NEED_TARGET,
    DEVICE_HOST_PSK_SERVER_SEND_READY, DEVICE_HOST_PSK_ESTABLISHED,
    DEVICE_HOST_PSK_FINISHED, DEVICE_HOST_PSK_FAILED
};
enum device_host_psk_result {
    DEVICE_HOST_PSK_PROGRESS, DEVICE_HOST_PSK_WAIT, DEVICE_HOST_PSK_TARGET_REQUIRED,
    DEVICE_HOST_PSK_READY, DEVICE_HOST_PSK_EOF, DEVICE_HOST_PSK_REFUSED,
    DEVICE_HOST_PSK_DEADLINE, DEVICE_HOST_PSK_CANCELLED, DEVICE_HOST_PSK_BUSY
};
struct device_host_psk_spec {
    struct device_pairing_store *store;
    uint8_t peer[32], approved_root[32];
    enum device_pairing_host_direction direction;
    uint16_t port;
    int64_t deadline_ns;
    const atomic_bool *cancelled;
};
struct device_host_psk_session {
    struct device_host_psk_spec spec;
    struct device_pairing_psk_snapshot snapshot;
    struct device_pairing_guard_cache authority; /* Owned revalidation memo; wiped with the session. */
    struct shake_wrap_state send, receive;
    uint8_t transcript[DEVICE_HOST_PSK_TRANSCRIPT], t0[64], t1[64], prk[32];
    uint8_t client[32], server[32], nonce[32];
    uint8_t pending[DEVICE_HOST_PSK_WIRE], incoming[DEVICE_HOST_PSK_WIRE], plaintext[4096];
    size_t pending_used, pending_sent, incoming_used, incoming_expected, plaintext_used, plaintext_sent;
    uint64_t send_sequence, receive_sequence, send_total, receive_total;
    enum device_host_psk_phase phase;
    enum device_host_psk_result terminal;
    struct device_pairing_guard *borrowed_guard;
    bool client_role, send_fin, receive_fin, borrowing_plaintext;
};
/* Fixed reviewed application profile, not an independently proved protocol.
 * Owner-private backend2 snapshot is acquired internally; no raw-secret entry.
 * Canonical credential A/B differs from ordered actual wire client/server roles.
 * No sockets, target dial, provisioning, forward secrecy or production rollout
 * is supplied here. Production nonces use qualified rng_host_fill.
 * One owner serializes every call and keeps borrowed store/cancel/guard storage
 * alive. Fresh context only; do not copy, serialize, log or concurrently access.
 * All caller buffers/length storage must be disjoint from live session and
 * each other. Protocol/buffer-geometry/authority refusal permanently wipes
 * context; invalid new status-output storage instead refuses unchanged below.
 * no valid frame can revive FAILED. Destroy all contexts on every exit.
 * Network deadlines are monotonic; filesystem lock acquisition is not a
 * whole-call wall bound. Terminal result remains stable until destruction. */
void device_host_psk_init(struct device_host_psk_session *session);
struct zcl_result device_host_psk_start(struct device_host_psk_session *session,
    const struct device_host_psk_spec *spec, enum device_host_psk_result *status);
struct zcl_result device_host_psk_receive_bytes(struct device_host_psk_session *session,
    const uint8_t *bytes, size_t length, size_t *consumed, enum device_host_psk_result *status);
struct zcl_result device_host_psk_queue_data(struct device_host_psk_session *session,
    const uint8_t *plaintext, size_t length, enum device_host_psk_result *status);
struct zcl_result device_host_psk_queue_fin(struct device_host_psk_session *session, enum device_host_psk_result *status);
/* Internal IO rail: zero-initialized unheld guard, output metadata independent. Success
 * returns current suffix while retaining exact current root/binding/port guard.
 * Caller performs only an immediate nonblocking write, then calls *_written /
 * *_released (count0 for EAGAIN) BEFORE any poll/wait. While span borrowed all
 * other calls refuse BUSY. Error invokes fail; no pending frame is regenerated. */
struct zcl_result device_host_psk_pending_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length, enum device_host_psk_result *status);
struct zcl_result device_host_psk_pending_written(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, size_t count, enum device_host_psk_result *status);
struct zcl_result device_host_psk_plaintext_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length, enum device_host_psk_result *status);
struct zcl_result device_host_psk_plaintext_released(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, size_t count, enum device_host_psk_result *status);
/* Carried-authority rail: the caller already holds ONE guard (exact current root,
 * binding and port) that was acquired for this record under the shared authority
 * lock. queue_data_held seals under it; the *_acquire_held calls borrow it for the
 * immediate write, and the usual *_written / *_released release it. The caller must
 * not reuse a guard across records: each record needs a check that started after
 * the previous record's release. Same BUSY/refusal rules as the acquiring forms. */
struct zcl_result device_host_psk_queue_data_held(struct device_host_psk_session *session,
    const struct device_pairing_guard *guard, const uint8_t *plaintext, size_t length, enum device_host_psk_result *status);
struct zcl_result device_host_psk_pending_acquire_held(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length, enum device_host_psk_result *status);
struct zcl_result device_host_psk_plaintext_acquire_held(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length, enum device_host_psk_result *status);
/* Server NEED_TARGET only after valid mutual confirmation. Trusted integration
 * calls this only after actual fixed-loopback target admission under THIS fresh
 * retained guard; hook verifies local authority and queues S_READY, never dials
 * or claims connectedness. Guard remains caller-owned/held; release before wait.
 * Server established only once all S_READY bytes are written under fresh guard. */
struct zcl_result device_host_psk_target_admitted(struct device_host_psk_session *session,
    const struct device_pairing_guard *guard, enum device_host_psk_result *status);
/* Raw EOF before authenticated receive FIN is truncation; no implicit FIN. */
struct zcl_result device_host_psk_transport_eof(struct device_host_psk_session *session, enum device_host_psk_result *status);
void device_host_psk_fail(struct device_host_psk_session *session, enum device_host_psk_result result);
void device_host_psk_destroy(struct device_host_psk_session *session);
#ifdef ZCL_TESTING
/* One-shot thread-local deterministic PUBLIC vector nonce / entropy refusal.
 * Never compiled into public binary; no runtime configuration counterpart. */
void device_host_psk_test_nonce(const uint8_t nonce[32], bool refuse);
#endif
/* Fallible public operations return canonical zcl_result; domain states are
 * explicit outputs, never result codes. Normal WAIT/PROGRESS/READY/TARGET/EOF
 * have successful code zero; refusal/deadline/cancellation/BUSY are failures.
 * Status output storage is required, independent of the complete context,
 * specifications, guards, input bytes and other output/length storage.
 * Checked direct-argument/status overlaps refuse unchanged before effects or
 * guard release. Disjointness from indirectly borrowed store/cancellation
 * storage is a caller precondition, not a recursive alias-detection claim.
 * Existing buffer/guard preconditions and terminal behavior remain unchanged. */
#endif
