/* purpose: Define guard-held HOST byte release and authenticated PSK socket composition. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_HOST_BRIDGE_H
#define ZCL_SERVICES_DEVICE_HOST_BRIDGE_H
#include "base/result.h"
#include "models/device_pairing.h"
#include "services/device_host_psk.h"
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define DEVICE_HOST_BRIDGE_BUFFER 4096u
enum device_host_bridge_result {
    DEVICE_HOST_BRIDGE_READY, DEVICE_HOST_BRIDGE_WAIT, DEVICE_HOST_BRIDGE_PROGRESS,
    DEVICE_HOST_BRIDGE_EOF, DEVICE_HOST_BRIDGE_REFUSED, DEVICE_HOST_BRIDGE_DEADLINE,
    DEVICE_HOST_BRIDGE_IO_ERROR, DEVICE_HOST_BRIDGE_CANCELLED, DEVICE_HOST_BRIDGE_UNSUPPORTED
};
struct device_host_bridge_spec {
    struct device_pairing_store *store;
    uint8_t peer[32], approved_root[32];
    struct device_pairing_host_binding authenticated_binding;
    enum device_pairing_host_direction direction;
    uint16_t port;
    int input_fd, output_fd, outbound_fd;
    int64_t deadline_ns;
    const atomic_bool *cancelled;
};
struct device_host_bridge_observation {
    enum device_host_bridge_result result;
    int error_number;
    bool io_taken, target_connected;
    uint64_t to_target_bytes, from_target_bytes;
};
struct device_host_bridge_buffer {
    uint8_t bytes[DEVICE_HOST_BRIDGE_BUFFER];
    size_t used, sent;
    bool eof, half_closed;
};
struct device_host_bridge {
    struct device_host_bridge_spec spec;
    struct device_host_bridge_observation observation;
    struct device_host_bridge_buffer forward, reverse;
    int transport_fd;
    bool active, output_socket;
};
/* Linux/macOS raw service, no framing/diagnostic writes to supplied descriptors.
 * Existing pairing refusals may log contextual diagnostics to stderr.
 * Caller independently
 * verifies handshake possession and exclusive-key engine context; roots alone
 * are not authentication. Exact root and local directional grant are required.
 * Fresh initialized state and independently owned nonblocking descriptors.
 * Input/output may be pipes or stream sockets. Same input/output FD is allowed
 * only for a duplex stream socket. Outbound is an already connected stream
 * socket, distinct from stdio; this service does not qualify its connection.
 * BEFORE admission failure, caller keeps all FDs. Once io_taken is true, service
 * owns input/output and outbound FD (or its newly opened inbound loopback FD),
 * closes each exactly once, and caller must not close/reuse them. On admission
 * it holds the guard through nonblocking inbound connect initiation, never wait.
 * Normal EOF drains only under fresh authority, then propagates half-close;
 * refusal/cancel/error discards both buffers and closes owned transport/stdio.
 * Previously initiated connect or released bytes cannot be recalled.
 * Pipe writes suppress SIGPIPE only on the calling thread. Unexpected signal
 * drain/mask-restoration failure returns IO_ERROR and may retain SIGPIPE blocked;
 * caller owns signal-state recovery and must not assume the prior mask restored.
 * Network/partial-I/O waits obey absolute platform monotonic deadline. File
 * lock/filesystem guard acquisition may block: no whole-call wall bound claimed.
 * step performs one bounded pass; run polls at most20ms between idle rechecks.
 * Caller serializes state and keeps store/cancellation storage alive. */
void device_host_bridge_init(struct device_host_bridge *bridge);
struct zcl_result device_host_bridge_open(struct device_host_bridge *bridge,
    const struct device_host_bridge_spec *spec, enum device_host_bridge_result *status);
struct zcl_result device_host_bridge_step(struct device_host_bridge *bridge, enum device_host_bridge_result *status);
struct zcl_result device_host_bridge_run(struct device_host_bridge *bridge, enum device_host_bridge_result *status);
void device_host_bridge_close(struct device_host_bridge *bridge,
    enum device_host_bridge_result result);

struct device_host_psk_bridge_spec {
    struct device_host_psk_spec session;
    int carrier_input_fd, carrier_output_fd;
    int input_fd, output_fd;
    /* Optional: called once after PSK authentication and BEFORE the target connect;
     * returning false refuses the session with no target socket ever opened. */
    bool (*reserve_target)(void *context);
    void *reserve_context;
};
struct device_host_psk_bridge_observation {
    enum device_host_bridge_result result;
    int error_number;
    bool io_taken, target_connect_started, target_connected;
    uint64_t plaintext_read_bytes, plaintext_written_bytes;
    uint64_t carrier_read_bytes, carrier_written_bytes;
    uint64_t data_records_sealed, data_records_opened; /* verified DATA records; FIN excluded */
};
struct device_host_psk_bridge {
    struct device_host_psk_bridge_spec spec;
    struct device_host_psk_session session;
    struct device_host_psk_bridge_observation observation;
    uint8_t unread[DEVICE_HOST_PSK_WIRE_MAX], local[DEVICE_HOST_PSK_RECORD_MAX];
    size_t unread_used, unread_sent, local_used;
    int64_t hard_deadline_ns; /* Immutable initial session ceiling. */
    int target_fd;
    bool active, started, connect_pending, carrier_eof, local_eof;
    bool output_half_closed, carrier_half_closed, carrier_output_socket, output_socket;
    int poll_hangup_fds[5]; size_t poll_hangup_count;
    bool poll_error;
};
enum device_host_bridge_poll_bits {
    DEVICE_HOST_BRIDGE_POLL_READ = 1, DEVICE_HOST_BRIDGE_POLL_WRITE = 2,
    DEVICE_HOST_BRIDGE_POLL_HANGUP = 4, DEVICE_HOST_BRIDGE_POLL_ERROR = 8
};
struct device_host_bridge_poll_entry { int fd; unsigned events; };
struct device_host_bridge_poll_plan {
    struct device_host_bridge_poll_entry entries[5]; size_t count;
    int64_t deadline_ns; bool immediate;
};
/* Linux/macOS backend2 over one selected, potentially untrusted carrier. No
 * automatic fallback/dial of carriers. Caller explicitly selects fresh carrier
 * and NEW context after failure; old cryptographic state is never reused.
 * All caller descriptors are independent nonblocking pipes/connected stream
 * sockets. Carrier input/output may share FD only for duplex stream socket;
 * likewise client plaintext input/output. Carrier and plaintext never alias.
 * Numerical descriptor distinctness is checked; caller must independently
 * exclude duplicated underlying open descriptions. Stderr and its underlying
 * description must be independent of all streams; descriptor2 is refused.
 * Caller keeps stderr open and separate throughout the context lifetime;
 * preflight refuses closed stderr before private admission or target creation.
 * Client supplies plaintext FDs. Server must supply -1/-1: its exact literal
 * IPv4 loopback target is opened only after mutual confirmation under current
 * guard, and S_READY follows actual successful connection, never inspection.
 * Caller retains FDs on preflight/open refusal. io_taken transfers all supplied
 * FDs; target FD is internal. Terminal close deduplicates every owned FD once,
 * discards/cleanses buffers and session, and retains only public observation.
 * Fresh init, one serialized owner, borrowed store/cancel lifetime through close.
 * step never polls with a held guard; run waits at most20ms between idle checks.
 * Fresh current guards cover actual nonblocking reads, writes, target connect
 * initiation/completion and half-close. Filesystem locks are not whole-call
 * wall-bounded. SIGPIPE suppression reuses the legacy thread-local rail and
 * retains its documented exceptional mask-recovery boundary. No diagnostics
 * to supplied streams. Local EOF yields authenticated FIN; raw carrier EOF
 * before FIN is truncation; reverse direction drains after a normal FIN.
 * No provisioning, CLI, process spawning, network listener or deployment. */
void device_host_psk_bridge_init(struct device_host_psk_bridge *bridge);
struct zcl_result device_host_psk_bridge_open(struct device_host_psk_bridge *bridge,
    const struct device_host_psk_bridge_spec *spec, enum device_host_bridge_result *status);
struct zcl_result device_host_psk_bridge_step(struct device_host_psk_bridge *bridge, enum device_host_bridge_result *status);
/* Serialized owner may tighten any active context, or lengthen only an
 * ESTABLISHED context while still inside its OLD effective deadline. One
 * monotonic sample checks old expiry first; expiry/cancel permanently closes.
 * New deadline must be future and <=immutable initial session ceiling.
 * Synchronizes both copied specifications; never revives terminal contexts.
 * A borrowed span refuses unchanged: caller retains and releases its guard. */
struct zcl_result device_host_psk_bridge_set_deadline(
    struct device_host_psk_bridge *bridge, int64_t deadline_ns, enum device_host_bridge_result *status);
/* Serialized owner snapshots readiness metadata only: no IO, allocation,
 * authority acquisition or secret spans. Output unchanged on refusal/BUSY.
 * FDs remain valid only until the next owner operation; identical numeric FDs
 * are merged, no zero-event descriptors or ordinary idle writable sockets.
 * Poll results are hints, never permission. Owner reports HUP/ERR before the
 * next guarded step. HUP never means authenticated FIN: stalled HUP entries
 * are suppressed until progress, with <=20ms bounded retry/authority checks. */
struct zcl_result device_host_psk_bridge_poll_interest(
    const struct device_host_psk_bridge *bridge, struct device_host_bridge_poll_plan *out, enum device_host_bridge_result *status);
struct zcl_result device_host_psk_bridge_poll_observed(
    struct device_host_psk_bridge *bridge, int fd, unsigned events, enum device_host_bridge_result *status);
struct zcl_result device_host_psk_bridge_run(struct device_host_psk_bridge *bridge, enum device_host_bridge_result *status);
void device_host_psk_bridge_close(struct device_host_psk_bridge *bridge,
    enum device_host_bridge_result result);
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
