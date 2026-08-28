/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_EVENT_H
#define ZCL_EVENT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>

/* ── Event types ─────────────────────────────────────────────
 * Every observable event in the system. Grouped by subsystem.
 * Adding a new event: add the enum, add the name string in
 * event.c event_type_name(), done. */

enum event_type {
    /* ── Network / TCP ──────────────────────────────── */
    EV_TCP_CONNECT_ATTEMPT = 0,  /* reserved (connected/failed cover this) */
    EV_TCP_CONNECTED,            /* payload: ip[16] + port(u16) */
    EV_TCP_CONNECT_FAILED,       /* payload: ip[16] + port(u16) + errno(i32) */
    EV_TCP_ACCEPTED,             /* payload: ip[16] + port(u16) */
    EV_TCP_DISCONNECTED,         /* payload: reason string */
    EV_TCP_TIMEOUT,              /* payload: seconds(i64) */

    /* ── P2P Messages ───────────────────────────────── */
    EV_MSG_RECEIVED,             /* payload: cmd[12] + size(u32) */
    EV_MSG_SENT,                 /* payload: cmd[12] + size(u32) */
    EV_MSG_CHECKSUM_FAIL,        /* payload: cmd[12] + expected(u32) + got(u32) */
    EV_MSG_DESERIALIZATION_FAIL, /* payload: cmd[12] */

    /* ── Peer state machine ─────────────────────────── */
    EV_PEER_STATE_CHANGE,        /* payload: from(u8) + to(u8) + reason string */
    EV_PEER_MISBEHAVE,           /* payload: score(i32) + total(i32) + reason */
    EV_PEER_BANNED,              /* payload: duration(i64) */
    EV_PEER_VERSION,             /* payload: proto(i32) + height(i32) + subver */
    EV_PEER_HANDSHAKE_ATTEMPT,   /* payload: addr/source/version-sent details */
    EV_PEER_HANDSHAKE_SUCCESS,   /* payload: addr/duration/services/subver */
    EV_PEER_HANDSHAKE_FAILURE,   /* payload: addr/state/reason */
    EV_PEER_CONNECT_TIMEOUT,     /* payload: addr/state/reason */
    EV_PEER_CACHE_SKIPPED,       /* payload: advisory peer cache write skipped */

    /* ── Sync state machine ─────────────────────────── */
    EV_SYNC_STATE_CHANGE,        /* payload: from(u8) + to(u8) + reason string */
    EV_HEADERS_RECEIVED,         /* payload: count(u32) + from_h(i32) + to_h(i32) */
    EV_HEADERS_REJECTED,         /* payload: count(u32) + reason string */
    EV_BLOCK_REQUESTED,          /* payload: queued/assigned/timeout string */
    EV_TIP_STALE,                /* payload: "state=... since=N peers=N max_peer=N" — sync state has not advanced for STALL_DEADLINE_SECS in any non-tip state; emitted once per stall episode (reset on state change or block-connect). Pairs with the existing STATE_STUCK watchdog so absence-of-progress is a first-class structured signal, not just stdout. */
    EV_SYNC_HEARTBEAT,           /* payload: "state=... h=N max_peer=N tip_age=N" — periodic (60s) liveness emit from sync_watchdog_periodic_tick; silence > 2 ticks implies process wedge separate from sync wedge */

    /* ── Long-operation heartbeat contract (util/long_op.h) ────── */
    EV_LONG_OP_BEGIN,            /* payload: "label=... begin_us=..." — long_op_scope opened around a >600s code path (snapshot import, bulk copy, wallet rescan) */
    EV_LONG_OP_TICK,             /* payload: "label=... age_us=... tick=N" — periodic (>=30s rate-limited) liveness from inside the scope */
    EV_LONG_OP_END,              /* payload: "label=... duration_us=... ticks=N ok=..." — scope closed, work complete */

    /* ── Validation pipeline ────────────────────────── */
    EV_BLOCK_CONNECTED,          /* payload: height string */
    EV_BLOCK_REJECTED,           /* payload: dos + reason string */
    EV_SELF_HEAL_SCAN_HIT,       /* payload: "tx=... h=N depth=N" */
    EV_SELF_HEAL_SCAN_EXHAUSTED, /* payload: "tx=... tip_h=N depth=N" */

    /* ── Chain ──────────────────────────────────────── */
    EV_TIP_UPDATED,              /* payload: hash[32] + height(i32) */
    EV_REORG_START,              /* payload: fork_height(i32) + new_height(i32) */
    EV_REORG_DISCONNECT_FAILED,  /* payload: "stuck_h=N fork_h=N" */
    EV_REORG_RECOVERY_COMPLETE,  /* payload: "fork_h=N cache_cleared=true" */
    EV_COINS_FLUSH,              /* payload: entries(u64) + blocks_batched(u32) */
    EV_COINS_FLUSH_FAILED,       /* payload: reason string */
    EV_UTXO_AUDIT_OK,            /* payload: "sha3=... height=N source=..." */
    EV_UTXO_DRIFT_DETECTED,      /* payload: "local_sha3=... remote_sha3=..." */
    EV_CHAIN_TIP_COMMIT,         /* payload: "from=H to=H reason=..." */
    EV_CHAIN_TIP_REJECTED,       /* payload: "code=... from=H to=H reason=..." */
    EV_RECOVERY_POLICY_ALLOW,    /* payload: "op=... amount=N reason=..." */
    EV_RECOVERY_POLICY_REFUSED,  /* payload: "op=... code=... amount=N cap=N reason=..." */
    EV_RECOVERY_POLICY_PROMPT,   /* payload: "op=... amount=N ack=... reason=..." */
    EV_DB_TXN_BEGIN,             /* payload: "label=..." */
    EV_DB_TXN_COMMIT,            /* payload: "label=... elapsed_us=N" */
    EV_DB_TXN_ROLLBACK,          /* payload: "label=... reason=..." */
    EV_DB_TXN_REJECTED,          /* payload: "label=... reason=..." */
    EV_DB_TXN_LEAKED,            /* payload: "label=..." */

    /* ── Transaction ────────────────────────────────── */
    EV_TX_ACCEPTED,              /* payload: txid[32] */
    EV_TX_REJECTED,              /* payload: txid[32] */

    /* ── Fast sync / snapshot ───────────────────────── */
    EV_SNAPSHOT_OFFER_SENT,      /* payload: height(i32) + utxos(u64) */
    EV_SNAPSHOT_OFFER_RECEIVED,  /* payload: height(i32) + utxos(u64) */
    EV_SNAPSHOT_COMPLETE,        /* payload: total_utxos string */

    /* (Wallet and RPC events reserved for future use) */

    /* ── Boot phases ────────────────────────────────── */
    EV_BOOT_PHASE,               /* payload: phase name + status */
    EV_BOOT_DB_OPEN,             /* payload: "schema=N tip=H" */
    EV_BOOT_COINS_OPEN,          /* payload: "dedicated=true|false" */
    EV_BOOT_UTXO_IMPORT,         /* payload: "start|done count=N elapsed=Xms" */
    EV_BOOT_BLOCK_INDEX,         /* payload: "loaded entries=N elapsed=Xs" */
    EV_BOOT_CHAIN_RESTORED,      /* payload: "height=N" */
    EV_BOOT_ACTIVATE,            /* payload: "tip=N most_work=N" or "FAILED ..." */
    EV_BOOT_VALIDATION_FAILED,   /* payload: "coins_chain_mismatch ..." */

    /* ── Validation pipeline (detailed) ────────────── */
    EV_BLOCK_CHECK_PASSED,       /* payload: "height=N checks=header,merkle,txns" */
    EV_BLOCK_CONNECT_START,      /* payload: "height=N ntx=N" */
    EV_BLOCK_CONNECT_DONE,       /* payload: "height=N fee=N sigops=N elapsed=Nms" */
    EV_TX_INPUTS_CHECKED,        /* payload: "tx=N value_in=N fee=N" */
    EV_TURNSTILE_CHECK,          /* payload: "sprout=N sapling=N height=N" */
    EV_SCRIPT_VERIFIED,          /* payload: "height=N tx=N inputs=N" */
    EV_UTXO_CHECKPOINT_PASS,     /* payload: "height=N count=N" */
    EV_UTXO_CHECKPOINT_FAIL,     /* payload: "height=N expected=X got=Y" */

    /* ── ActiveRecord model lifecycle ──────────────── */
    EV_MODEL_SAVED,              /* payload: "model=block height=N" */
    EV_MODEL_DESTROYED,          /* payload: "model=utxo txid=..." */
    EV_MODEL_VALIDATION_FAILED,  /* payload: "model=peer errors=..." */
    EV_UTXO_SAVED,               /* payload: "height=N value=N" */
    EV_BLOCK_SAVED,              /* payload: "height=N ntx=N" */
    EV_WALLET_KEY_SAVED,         /* payload: "kind=transparent|sapling addr_hash=..." */
    EV_SAPLING_KEY_SAVED,        /* payload: "fvk_hash=..." */
    EV_WALLET_TX_SAVED,          /* payload: "txid=... category=..." */
    EV_WALLET_UTXO_SAVED,        /* payload: "vout=N value=N" */

    /* ── Recovery actions ──────────────────────────── */
    EV_RECOVERY_ACTION,          /* payload: "action=... reason=..." */

    /* ── System ─────────────────────────────────────── */
    EV_NODE_STARTING,            /* payload: version string */
    EV_NODE_READY,               /* payload: height(i32) + peers(u32) */
    EV_NODE_SHUTDOWN,            /* payload: reason string */
    EV_CRASH,                    /* payload: signal(i32) */
    EV_CRASH_RECOVERY_START,     /* payload: "wal_size=N clean_marker=missing" */
    EV_CRASH_RECOVERY_COMPLETE,  /* payload: "actions_taken=N chain_height=N" */
    EV_DB_ERROR,                 /* payload: operation + errmsg */

    /* ── MMB / FlyClient ───────────────────────────── */
    EV_MMB_APPEND,               /* payload: "h=N peaks=N leaves=N" */
    EV_MMB_PROOF_VERIFIED,       /* payload: "leaf=N valid=true|false" */
    EV_FC_SAMPLE_VERIFIED,       /* payload: "h=N pow=ok proof=ok" */
    EV_FC_CHAIN_VERIFIED,        /* payload: "samples=N all_valid=true|false" */

    /* ── Snapshot sync service ─────────────────────── */
    EV_SNAPSYNC_STATE_CHANGE,    /* payload: "idle->receiving: reason" */
    EV_SNAPSYNC_PROGRESS,        /* payload: "received=N/N rate=N/s" */
    EV_SNAPSYNC_VERIFIED,        /* payload: "sha3=PASSED mmb=PASSED utxos=N" */

    /* ── Chain activation controller ──────────────────── */
    EV_ACTIVATION_STATE_CHANGE,  /* payload: "idle->boot_pending: reason" */

    /* Retired transport event slot; retained to keep later ordinals stable. */
    EV_RESERVED_TRANSPORT_REQUEST,

    /* ── Block index integrity ─────────────────────── */
    EV_BLOCK_INDEX_CORRUPT,      /* payload: "verdict=NAME body_size=N ..." */
    EV_BLOCK_INDEX_REPAIR,       /* payload: "repaired=N elapsed_ms=N" */

    /* ── Wallet backup service ─────────────────────── */
    EV_WALLET_BACKUP,            /* payload: "path=... bytes=N keys=N" */
    EV_WALLET_BACKUP_FAILED,     /* payload: "path=... reason=..." */

    /* ── Disk monitor ──────────────────────────────── */
    EV_DISK_LOW,                 /* payload: "path=... free=N warn_thr=N" */
    EV_DISK_CRITICAL,            /* payload: "path=... free=N refuse_thr=N" */
    EV_DISK_OK,                  /* payload: "path=... free=N (recovered)"  */

    /* ── Database maintenance ──────────────────────── */
    EV_DB_MAINTENANCE_START,     /* payload: "op=wal|analyze|vacuum" */
    EV_DB_MAINTENANCE_DONE,      /* payload: "op=... elapsed_ms=N ..." */
    EV_DB_MAINTENANCE_FAILED,    /* payload: "op=... reason=..." */

    /* ── Mempool limits ────────────────────────────── */
    EV_MEMPOOL_EVICT,            /* payload: "reason=size|count evicted=N bytes_before=N bytes_after=N" */
    EV_MEMPOOL_EXPIRE,           /* payload: "expired=N cutoff_unix=N" */

    /* ── Addrman integrity ─────────────────────────── */
    EV_ADDRMAN_CORRUPT,          /* payload: "verdict=NAME body_size=N ..." */

    /* ── Peer bandwidth ────────────────────────────── */
    EV_PEER_THROTTLED,           /* payload: "peer=N dir=up|down bytes=N bucket=N/N" */

    /* ── IBD throttle ──────────────────────────────── */
    EV_IBD_THROTTLED,            /* payload: "blocked=N total_wait_ms=N rate=N burst=N" */

    /* ── Consensus rejects ─────────────────────────── */
    EV_CONSENSUS_REJECT_TX,      /* payload: "hash=<64hex> reason=... dos=N" */
    EV_CONSENSUS_REJECT_BLOCK,   /* payload: "hash=<64hex> reason=... dos=N" */

    /* ── HTTP RPC request timeout ──────────────────── */
    EV_RPC_TIMEOUT,              /* payload: "method=NAME elapsed_ms=N ip=A.B.C.D" */

    /* ── Block pruning ────────────────────────────────── */
    EV_BLOCK_PRUNING_DONE,       /* payload: "file=N max_height=N freed=N blocks=N" */

    /* ── Net backpressure watchdog ─────────────── */
    EV_BACKPRESSURE_ACTIVE,      /* payload: "tip_stalled drained=N" — once on entry */
    EV_BACKPRESSURE_REJECT,      /* payload: "cmd=inv|block" — per dropped message; peer_id set */
    EV_BACKPRESSURE_CLEAR,       /* payload: "reason=tip_advanced|cooldown_elapsed held_ms=N" */
    EV_SAPLING_PERSIST_FAIL,     /* payload: "fails=N" */

    /* ── zclassicd oracle (independent-impl drift detection) ─ */
    EV_ORACLE_AGREE,             /* payload: "h=N hash=<64hex>" */
    EV_ORACLE_DISAGREE,          /* payload: "h=N our=<hex> their=<hex>" */

    /* ── Oracle policy escalations (T2.1) ──────────────────────── */
    EV_FORK_SUSPECTED,           /* payload: "distinct_heights=N within_secs=N first_h=N last_h=N" */
    EV_ANCHOR_PANIC,             /* payload: "h=N our=<hex> their=<hex>" — evidence prefix violated */
    EV_CHAIN_HALTED,             /* payload: "reason=... distinct_heights=N" — chain_advance refusing */

    /* ── Chain advance coordinator ──────────────────────────────── */
    EV_CHAIN_ADVANCE_DECISION,   /* payload: "source=... decision=... reason=... local=N target=N" */
    EV_MIRROR_CONSENSUS_DECISION,/* payload: "op=override|blocker auth=local mir=advisory reason=..." */
    EV_CHAIN_ADVANCE_RESERVED,   /* reserved legacy guard slot; do not emit */

    /* ── Lag SLO + peer floor (redundancy guarantees) ───────────── */
    EV_PEER_FLOOR_BREACH,        /* payload: "healthy=N min=N since=Ns" — < floor peers for too long; loud on every cycle while breached */
    EV_LAG_SLO_BREACH,           /* payload: "lag=N legacy_height=N local_height=N since=Ns severity=warn|critical|fatal" — zclassic23 behind zclassicd past SLO; one emission per breach episode per severity */
    EV_MIRROR_CONCURRENT_CATCHUP,/* payload: "applied=N target=N source=mirror reason=..." — mirror running concurrently with P2P, not gated on local exhaustion */
    EV_COORDINATOR_LEGACY_RESERVED,/* reserved legacy coordinator event slot; do not emit */
    EV_CONDITION_DETECTED,       /* payload: "name=... severity=..." */
    EV_CONDITION_REMEDY_ATTEMPTED,/* payload: "name=... attempt=N result=..." */
    EV_CONDITION_CLEARED,        /* payload: "name=... cleared_count=N" */
    EV_OPERATOR_NEEDED,          /* payload: "condition=... attempts=N" */

    EV_NUM_TYPES                 /* sentinel — must be last */
};

/* ── Peer state machine ─────────────────────────────────── */

enum peer_state {
    PEER_DISCONNECTED = 0,
    PEER_CONNECTING,           /* TCP SYN sent (outbound) */
    PEER_CONNECTED,            /* TCP established, no version yet */
    PEER_VERSION_SENT,         /* we sent our version message */
    PEER_VERSION_RECEIVED,     /* we got their version message */
    PEER_HANDSHAKE_COMPLETE,   /* version+verack exchanged both ways */
    PEER_ACTIVE,               /* fully operational, relay mode */
    PEER_SYNCING_HEADERS,      /* downloading headers from this peer */
    PEER_SYNCING_BLOCKS,       /* downloading blocks from this peer */
    PEER_SNAPSHOT_SERVING,     /* streaming UTXO snapshot to this peer */
    PEER_SNAPSHOT_RECEIVING,   /* receiving UTXO snapshot from this peer */
    PEER_STALE,                /* no useful data for a while */
    PEER_DISCONNECTING,        /* graceful disconnect in progress */
    PEER_BANNED,               /* IP banned */
    PEER_NUM_STATES            /* sentinel */
};

/* Sync state machines live in lib/sync/. Files that use sync or snapshot
 * state APIs must include "sync/sync_state.h" directly; event.h owns only
 * the event bus and peer state machine. */

/* ── Event structure ────────────────────────────────────── */

#define EVENT_PAYLOAD_SIZE 256

struct event {
    _Atomic uint64_t  sequence;      /* monotonic, publish marker */
    int64_t           timestamp_us;  /* microseconds since epoch */
    enum event_type   type;
    uint32_t          peer_id;       /* 0 if not peer-related */
    uint32_t          payload_len;
    uint8_t           payload[EVENT_PAYLOAD_SIZE];
};

/* ── Ring buffer ────────────────────────────────────────── */

#define EVENT_LOG_SIZE 65536         /* must be power of 2 */
#define EVENT_LOG_MASK (EVENT_LOG_SIZE - 1)

struct event_log {
    _Atomic uint64_t  write_pos;
    struct event      ring[EVENT_LOG_SIZE];
    _Atomic bool      initialized;
};

/* ── API ────────────────────────────────────────────────── */

/* Initialize the global event log. Call once at startup. */
void event_log_init(void);

/* Emit an event. Lock-free, O(1). Safe from any thread.
 * peer_id = 0 for non-peer events. payload can be NULL. */
void event_emit(enum event_type type, uint32_t peer_id,
                const void *payload, uint32_t payload_len);

/* Convenience: emit with a format string as payload. */
void event_emitf(enum event_type type, uint32_t peer_id,
                 const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Dump last `count` events to stderr. For crash handlers. */
void event_dump_recent(size_t count);

/* Dump last `count` events as JSON to a buffer.
 * Returns bytes written, or required size if buf is too small. */
size_t event_dump_json(char *buf, size_t buf_size, size_t count);

/* Get event type name as string. */
const char *event_type_name(enum event_type type);

/* Dump events filtered by type prefix. Returns bytes written.
 * prefix="" matches all. "peer." matches peer events. "val." matches validation.
 * Useful for targeted monitoring: event_dump_json_filtered(buf, sz, 50, "val.") */
size_t event_dump_json_filtered(char *buf, size_t buf_size, size_t count,
                                 const char *type_prefix);

/* Monotonic sequence number that will be assigned to the next emitted event.
 * Existing event objects expose their own `seq`; this helper gives timeline
 * callers a cheap cursor upper bound without reading the ring internals. */
uint64_t event_log_head_sequence(void);

/* Install crash signal handlers (SIGSEGV, SIGABRT, SIGBUS).
 * On crash, dumps last 200 events to stderr before exit. */
void event_install_crash_handler(void);

/* ── Peer state machine API ─────────────────────────────── */

/* Validate and execute a peer state transition.
 * Returns false if the transition is illegal (bug).
 *
 * `current` is _Atomic because the live peer field (p2p_node.state) is
 * transitioned from multiple threads. Internally this does an atomic load
 * (relaxed), validates, then an atomic store (relaxed) — the read and write
 * are NOT a single CAS, so two concurrent transitions can still race the
 * validate step (mis-print / lose one transition). That residual race is
 * benign: it never corrupts memory and never changes which transitions are
 * legal. The atomicity here only removes the torn read that produced
 * spurious "BUG: illegal transition" stderr. */
bool peer_set_state_checked(uint32_t peer_id, _Atomic enum peer_state *current,
                            enum peer_state new_state, const char *reason);

/* Get peer state name as string. */
const char *peer_state_name(enum peer_state state);

/* Check if a transition is legal without executing it. */
bool peer_transition_valid(enum peer_state from, enum peer_state to);

/* ── Event observers ───────────────────────────────────── */

/* Observer callback — called synchronously from event_emit().
 * Must be fast (no blocking I/O). For heavy work, queue internally. */
typedef void (*event_observer_fn)(enum event_type type, uint32_t peer_id,
                                   const void *payload, uint32_t payload_len,
                                   void *ctx);

#define EVENT_MAX_OBSERVERS 8

/* Register an observer for a specific event type.
 * Returns false if observer table is full. */
bool event_observe(enum event_type type, event_observer_fn fn, void *ctx);

/* Remove all observers for a specific event type. */
void event_clear_observers(enum event_type type);

/* Remove all observers for all event types. */
void event_clear_all_observers(void);

/* ── Async observers ───────────────────────────────────── */

/* Async observer — fires on a background thread, never blocks emit().
 * Use for logging, metrics, persistence that can tolerate brief delay.
 * Same callback signature as sync observers. */
bool event_observe_async(enum event_type type, event_observer_fn fn, void *ctx);

/* Start/stop the async observer dispatch thread.
 * Call event_async_start() after registering async observers.
 * Call event_async_stop() during shutdown (drains pending events). */
bool event_async_start(void);
void event_async_stop(void);

/* ── Error accumulator ─────────────────────────────────── */

/* Captures last N errors for instant health queries.
 * Register as async observer on EV_DB_ERROR, EV_BLOCK_REJECTED, etc. */
#define ERROR_RING_SIZE 10

struct error_entry {
    int64_t timestamp_us;
    enum event_type type;
    char message[EVENT_PAYLOAD_SIZE];
};

struct error_ring {
    struct error_entry entries[ERROR_RING_SIZE];
    _Atomic int write_pos;
    _Atomic int total_count;
};

/* Initialize error ring (call once at startup). */
void error_ring_init(struct error_ring *r);

/* Observer callback — register with event_observe_async(). */
void error_ring_observer(enum event_type type, uint32_t peer_id,
                         const void *payload, uint32_t payload_len, void *ctx);

/* Query: total errors since startup. */
int error_ring_total(const struct error_ring *r);

/* Query: most recent error (NULL if none). */
const struct error_entry *error_ring_last(const struct error_ring *r);

/* Dump as JSON into buf. Returns bytes written. */
size_t error_ring_dump_json(const struct error_ring *r, char *buf, size_t sz);

/* Global error ring (initialized in event_log_init). */
struct error_ring *error_ring_global(void);

#endif /* ZCL_EVENT_H */
