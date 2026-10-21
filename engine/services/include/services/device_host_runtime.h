/* purpose: Define finite selected-route HOST client and receiver process lifetimes. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_HOST_RUNTIME_H
#define ZCL_SERVICES_DEVICE_HOST_RUNTIME_H
#include "base/result.h"
#include "services/device_host_bridge.h"

#define DEVICE_HOST_RUNTIME_ACTIVE_MAX 4u
#define DEVICE_HOST_RUNTIME_ACCEPT_MAX 64u
/* Receiver closes its listener after this many unauthenticated connections fail. */
#define DEVICE_HOST_RUNTIME_PREAUTH_MAX 256u
/* Hard maxima for the supervised hub (24 h receiver, 8 h session, 30 min idle).
 * Grant expiry, revocation and per-record authority still end a session earlier. */
#define DEVICE_HOST_RUNTIME_LIFETIME_MS_MAX 86400000u
#define DEVICE_HOST_RUNTIME_SESSION_MS_MAX 28800000u
#define DEVICE_HOST_RUNTIME_IDLE_MS_MAX 1800000u
struct device_host_runtime_common {
    struct device_pairing_store *store;
    uint8_t peer[32], approved_root[32];
    uint16_t target_port;
    uint32_t handshake_ms, session_ms, idle_ms;
    const atomic_bool *cancelled;
};
struct device_host_runtime_observation {
    enum device_host_bridge_result result;
    int error_number;
    uint16_t listen_port;
    bool io_taken, cleanup_complete;
    uint32_t accepted, completed, refused;
    uint32_t preauth_refused; /* Subset of refused that never authenticated; accepted counts only authenticated sessions. */
    uint64_t plaintext_read_bytes, plaintext_written_bytes;
    uint64_t carrier_read_bytes, carrier_written_bytes;
};
struct device_host_runtime_client_spec {
    struct device_host_runtime_common common;
    uint32_t route_address_be; /* Explicit literal unicast IPv4, network order. */
    uint16_t route_port;
    uint32_t connect_ms;
    int input_fd, output_fd;
    /* Trusted caller-only lock-free request, never a peer/JSON input. Before
     * establishment cancels; afterwards admits ordinary EOF/FIN drain within
     * a nonrefreshable one-second bound capped by existing admitted deadlines. */
    const atomic_bool *graceful_close_requested;
};
struct device_host_runtime_receiver_spec {
    struct device_host_runtime_common common;
    uint32_t listen_address_be;
    uint16_t listen_port; /* Zero explicitly requests an observed ephemeral port. */
    bool allow_external;
    uint32_t lifetime_ms, max_sessions, max_active;
    void (*ready)(void *context, const struct device_host_runtime_observation *observation);
    void *ready_context;
};
/* Foreground, Linux client/receiver, macOS outbound client and macOS
 * loopback-only receiver, one serialized owner. A macOS receiver refuses
 * allow_external by name and any non-loopback listen address; it forks no
 * children, so strict descendant cleanup stays vacuous until anything execs.
 * Borrowed store/cancellation
 * and callback storage remain alive through return. Caller establishes trusted
 * owner-private profile/key-label binding and owner-approved current grant.
 * No secret constructor, DNS, shell, child process, automatic backup or service.
 * No application/framing/diagnostic writes to supplied streams except qualified
 * decrypted bytes. Existing authority refusals may log to independent stderr.
 * Caller keeps stderr open and separate from every stream throughout the call.
 * Client app FDs must be independently owned nonblocking pipes/connected stream
 * sockets >=3, distinct unless a single duplex socket. Before io_taken refusal,
 * caller retains them; after io_taken bridge closes each once on terminal return.
 * Receiver owns all created listener/carriers/targets; cleanup_complete means
 * those local contexts/descriptors were closed, not remote process containment.
 * Guards cover actual connect/bind/listen/accept initiation and readiness. They
 * never span polling. Qualified IO exclusively owns confirmation-before-target,
 * per-release guards, authenticated FIN and ciphertext/plaintext cleanup.
 * Network/partial-IO connect, handshake, idle, session and listener lifetime
 * are independently finite; filesystem/lock/callback/diagnostic latency is not
 * whole-call wall bounded. Already initiated effects cannot be recalled.
 * Signal cancellation must use a lock-free atomic_bool supplied by caller;
 * runtime installs no handlers. A reused physical slot always creates a NEW
 * context/nonces. Restored/emulated guests must not resume cryptographic state:
 * fresh entropy after restore is a separate qualification, not established here.
 * Functions initialize independent public observation even on refusal.
 * Null or directly overlapping observation/specification storage instead
 * refuses unchanged before effects. Observation must also be disjoint from
 * indirectly borrowed store/cancellation/callback storage (caller precondition).
 * The observation carries the domain result; zcl_result success uses code zero,
 * including normal EOF, while refusal/deadline/cancel/IO/unsupported fail. */
struct zcl_result device_host_runtime_client_run(
    const struct device_host_runtime_client_spec *spec,
    struct device_host_runtime_observation *observation);
struct zcl_result device_host_runtime_receiver_run(
    const struct device_host_runtime_receiver_spec *spec,
    struct device_host_runtime_observation *observation);
#endif
