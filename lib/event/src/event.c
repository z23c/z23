/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#define _GNU_SOURCE  /* sigaltstack / SA_ONSTACK in the crash handler */

#include "platform/time_compat.h"
#include "event/event.h"
#include "util/safe_alloc.h"
#include "util/signal_handler.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>
#include <time.h>

/* ── Global event log ─────────────────────────────────────
 * Single instance. Lock-free ring buffer. Every thread writes
 * here via atomic fetch-add on write_pos. Readers use the
 * sequence field as a publish marker. */

static struct event_log g_log;
static struct error_ring g_error_ring;  /* forward decl for event_log_init */

/* ── Event observers ─────────────────────────────────────── */

struct event_observer_entry {
    event_observer_fn fn;
    void *ctx;
};

static struct {
    struct event_observer_entry observers[EVENT_MAX_OBSERVERS];
    int count;
} g_observers[EV_NUM_TYPES];

bool event_observe(enum event_type type, event_observer_fn fn, void *ctx)
{
    if ((int)type < 0 || type >= EV_NUM_TYPES) return false;
    if (g_observers[type].count >= EVENT_MAX_OBSERVERS) {
        fprintf(stderr, "event_observe: observer table full for %s "
                "(max %d) — observer dropped\n",
                event_type_name(type), EVENT_MAX_OBSERVERS);
        return false;
    }
    int idx = g_observers[type].count++;
    g_observers[type].observers[idx].fn = fn;
    g_observers[type].observers[idx].ctx = ctx;
    return true;
}

void event_clear_observers(enum event_type type)
{
    if ((int)type >= 0 && type < EV_NUM_TYPES)
        g_observers[type].count = 0;
}

void event_clear_all_observers(void)
{
    for (int i = 0; i < EV_NUM_TYPES; i++)
        g_observers[i].count = 0;
}

/* ── Async observer dispatch ─────────────────────────────── */

#include <pthread.h>

/* Async queue entry — snapshot of event data for deferred dispatch */
struct async_event {
    enum event_type type;
    uint32_t peer_id;
    uint8_t  payload[EVENT_PAYLOAD_SIZE];
    uint32_t payload_len;
    int observer_count;
    struct event_observer_entry observers[EVENT_MAX_OBSERVERS];
};

#define ASYNC_QUEUE_SIZE 4096
#define ASYNC_QUEUE_MASK (ASYNC_QUEUE_SIZE - 1)

static struct {
    struct event_observer_entry observers[EVENT_MAX_OBSERVERS];
    int count;
} g_async_observers[EV_NUM_TYPES];

static struct {
    struct async_event ring[ASYNC_QUEUE_SIZE];
    _Atomic uint64_t   write_pos;
    _Atomic uint64_t   read_pos;
    pthread_t          thread;
    _Atomic bool       running;
    bool               thread_started;
    bool               wake_initialized;
    pthread_mutex_t    wake_mutex;
    pthread_cond_t     wake_cond;
} g_async;

bool event_observe_async(enum event_type type, event_observer_fn fn, void *ctx)
{
    if ((int)type < 0 || type >= EV_NUM_TYPES) return false;
    if (g_async_observers[type].count >= EVENT_MAX_OBSERVERS) {
        fprintf(stderr, "event_observe_async: observer table full for %s "
                "(max %d) — observer dropped\n",
                event_type_name(type), EVENT_MAX_OBSERVERS);
        return false;
    }
    int idx = g_async_observers[type].count++;
    g_async_observers[type].observers[idx].fn = fn;
    g_async_observers[type].observers[idx].ctx = ctx;
    return true;
}

static void notify_async_observers(const struct async_event *ae)
{
    enum event_type t = ae->type;
    if ((int)t < 0 || t >= EV_NUM_TYPES) return;
    for (int i = 0; i < ae->observer_count; i++)
        ae->observers[i].fn(t, ae->peer_id, ae->payload, ae->payload_len,
                            ae->observers[i].ctx);
}

/* Enqueue event for async dispatch. Producers serialize on the wake mutex so
 * write_pos is published only after the selected ring slot is fully populated.
 * Publishing before the copy lets the dispatcher race ahead and read stale
 * slot contents under parallel test load. */
static void async_enqueue(enum event_type type, uint32_t peer_id,
                          const void *payload, uint32_t payload_len)
{
    /* Check if any async observers exist for this type */
    if ((int)type < 0 || type >= EV_NUM_TYPES) return;
    int observer_count = g_async_observers[type].count;
    if (observer_count == 0) return;

    if (!atomic_load_explicit(&g_async.running, memory_order_acquire) ||
        !g_async.wake_initialized)
        return;

    pthread_mutex_lock(&g_async.wake_mutex);
    uint64_t wp = atomic_load_explicit(&g_async.write_pos,
                                       memory_order_relaxed);
    struct async_event *ae = &g_async.ring[wp & ASYNC_QUEUE_MASK];
    ae->type = type;
    ae->peer_id = peer_id;
    ae->observer_count = observer_count;
    for (int i = 0; i < observer_count; i++)
        ae->observers[i] = g_async_observers[type].observers[i];
    ae->payload_len = payload_len < EVENT_PAYLOAD_SIZE
                      ? payload_len : EVENT_PAYLOAD_SIZE;
    if (payload && ae->payload_len > 0)
        memcpy(ae->payload, payload, ae->payload_len);
    else
        ae->payload_len = 0;

    atomic_store_explicit(&g_async.write_pos, wp + 1u,
                          memory_order_release);
    pthread_cond_signal(&g_async.wake_cond);
    pthread_mutex_unlock(&g_async.wake_mutex);
}

/* Supervisor liveness: the dispatcher wakes at least every 1 s (its
 * timed condwait), so a heartbeat at the loop head keeps a deadline=60 s
 * contract honest even when idle. Progress marker = events consumed
 * (read_pos); no-progress gate disabled because an idle queue legitimately
 * leaves read_pos unchanged. See util/thread_liveness.h. */
static struct thread_liveness_child g_async_child = {
    .id = SUPERVISOR_INVALID_ID
};

static void *async_dispatch_thread(void *arg)
{
    (void)arg;
    while (atomic_load(&g_async.running)) {
        thread_liveness_beat(&g_async_child,
            (int64_t)atomic_load_explicit(&g_async.read_pos,
                                          memory_order_acquire));
        uint64_t rp = atomic_load_explicit(&g_async.read_pos,
                                           memory_order_acquire);
        uint64_t wp = atomic_load_explicit(&g_async.write_pos,
                                           memory_order_acquire);

        if (rp >= wp) {
            /* Nothing to process — wait for signal. Timed wait so the
             * dispatch thread never blocks past event_async_stop() if
             * the cond_signal is missed (the stop path signals after
             * setting running=false; this is belt-and-suspenders for
             * any path that bypasses event_async_stop). 1 s is well
             * below human-noticeable latency for event delivery. */
            pthread_mutex_lock(&g_async.wake_mutex);
            if (atomic_load_explicit(&g_async.read_pos,
                                     memory_order_acquire) >=
                atomic_load_explicit(&g_async.write_pos,
                                     memory_order_acquire)) {
                struct timespec deadline;
                platform_time_realtime_timespec(&deadline);
                deadline.tv_sec += 1;
                pthread_cond_timedwait(&g_async.wake_cond,
                                       &g_async.wake_mutex, &deadline);
            }
            pthread_mutex_unlock(&g_async.wake_mutex);
            continue;
        }

        /* Process all pending events */
        while (rp < wp) {
            struct async_event *ae = &g_async.ring[rp & ASYNC_QUEUE_MASK];
            notify_async_observers(ae);
            rp++;
        }
        atomic_store_explicit(&g_async.read_pos, rp, memory_order_release);
    }

    /* Drain remaining events on shutdown */
    uint64_t rp = atomic_load_explicit(&g_async.read_pos,
                                       memory_order_acquire);
    uint64_t wp = atomic_load_explicit(&g_async.write_pos,
                                       memory_order_acquire);
    while (rp < wp) {
        struct async_event *ae = &g_async.ring[rp & ASYNC_QUEUE_MASK];
        notify_async_observers(ae);
        rp++;
    }
    atomic_store_explicit(&g_async.read_pos, rp, memory_order_release);

    return NULL;
}

bool event_async_start(void)
{
    if (atomic_load(&g_async.running))
        return true;

    atomic_store(&g_async.write_pos, 0);
    atomic_store(&g_async.read_pos, 0);
    if (pthread_mutex_init(&g_async.wake_mutex, NULL) != 0)
        return false;
    if (pthread_cond_init(&g_async.wake_cond, NULL) != 0) {
        pthread_mutex_destroy(&g_async.wake_mutex);
        return false;
    }
    g_async.wake_initialized = true;
    atomic_store(&g_async.running, true);
    // supervised:zcl_event_async (thread_liveness_register below)
    if (thread_registry_spawn("zcl_event_async", async_dispatch_thread,
                                  NULL, &g_async.thread) != 0) {
        atomic_store(&g_async.running, false);
        pthread_cond_destroy(&g_async.wake_cond);
        pthread_mutex_destroy(&g_async.wake_mutex);
        g_async.wake_initialized = false;
        return false;
    }
    (void)thread_liveness_register(&g_async_child, "zcl_event_async",
                                   /*deadline_secs=*/60,
                                   /*progress_quiet_us=*/0);
    g_async.thread_started = true;
    return true;
}

void event_async_stop(void)
{
    if (!g_async.wake_initialized && !g_async.thread_started) {
        atomic_store(&g_async.running, false);
        return;
    }
    atomic_store(&g_async.running, false);
    if (g_async.wake_initialized) {
        pthread_mutex_lock(&g_async.wake_mutex);
        pthread_cond_signal(&g_async.wake_cond);
        pthread_mutex_unlock(&g_async.wake_mutex);
    }
    if (g_async.thread_started) {
        pthread_join(g_async.thread, NULL);
        g_async.thread_started = false;
    }
    thread_liveness_retire(&g_async_child);
    if (g_async.wake_initialized) {
        pthread_mutex_destroy(&g_async.wake_mutex);
        pthread_cond_destroy(&g_async.wake_cond);
        g_async.wake_initialized = false;
    }
}

static void notify_observers(enum event_type type, uint32_t peer_id,
                              const void *payload, uint32_t payload_len)
{
    if ((int)type < 0 || type >= EV_NUM_TYPES) return;
    for (int i = 0; i < g_observers[type].count; i++)
        g_observers[type].observers[i].fn(type, peer_id, payload, payload_len,
                                           g_observers[type].observers[i].ctx);
}

void event_log_init(void)
{
    memset(&g_log, 0, sizeof(g_log));
    atomic_store(&g_log.write_pos, 0);
    atomic_store(&g_log.initialized, true);
    event_clear_all_observers();
    error_ring_init(&g_error_ring);
}

static int64_t now_us(void)
{
    return platform_time_realtime_us();
}

void event_emit(enum event_type type, uint32_t peer_id,
                const void *payload, uint32_t payload_len)
{
    if (!atomic_load(&g_log.initialized))
        return;

    uint64_t seq = atomic_fetch_add(&g_log.write_pos, 1);
    struct event *ev = &g_log.ring[seq & EVENT_LOG_MASK];

    /* Write fields (sequence written last as publish barrier) */
    ev->timestamp_us = now_us();
    ev->type = type;
    ev->peer_id = peer_id;
    ev->payload_len = payload_len < EVENT_PAYLOAD_SIZE
                      ? payload_len : EVENT_PAYLOAD_SIZE;
    if (payload && ev->payload_len > 0)
        memcpy(ev->payload, payload, ev->payload_len);
    else
        ev->payload_len = 0;

    /* Publish: readers check sequence matches expected slot */
    atomic_store_explicit(&ev->sequence, seq + 1, memory_order_release);

    /* Notify sync observers immediately */
    notify_observers(type, peer_id, payload, payload_len);

    /* Enqueue for async observers (non-blocking) */
    if (atomic_load(&g_async.running))
        async_enqueue(type, peer_id, payload, payload_len);
}

void event_emitf(enum event_type type, uint32_t peer_id,
                 const char *fmt, ...)
{
    char buf[EVENT_PAYLOAD_SIZE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    event_emit(type, peer_id, buf, (uint32_t)n);
}

/* ── Event type names ────────────────────────────────────── */

const char *event_type_name(enum event_type type)
{
    static const char *names[] = {
        [EV_TCP_CONNECT_ATTEMPT]     = "tcp.connect_attempt",
        [EV_TCP_CONNECTED]           = "tcp.connected",
        [EV_TCP_CONNECT_FAILED]      = "tcp.connect_failed",
        [EV_TCP_ACCEPTED]            = "tcp.accepted",
        [EV_TCP_DISCONNECTED]        = "tcp.disconnected",
        [EV_TCP_TIMEOUT]             = "tcp.timeout",
        [EV_MSG_RECEIVED]            = "msg.received",
        [EV_MSG_SENT]                = "msg.sent",
        [EV_MSG_CHECKSUM_FAIL]       = "msg.checksum_fail",
        [EV_MSG_DESERIALIZATION_FAIL]= "msg.deser_fail",
        [EV_PEER_STATE_CHANGE]       = "peer.state_change",
        [EV_PEER_MISBEHAVE]          = "peer.misbehave",
        [EV_PEER_BANNED]             = "peer.banned",
        [EV_PEER_VERSION]            = "peer.version",
        [EV_PEER_HANDSHAKE_ATTEMPT]  = "peer.handshake_attempt",
        [EV_PEER_HANDSHAKE_SUCCESS]  = "peer.handshake_success",
        [EV_PEER_HANDSHAKE_FAILURE]  = "peer.handshake_failure",
        [EV_PEER_CONNECT_TIMEOUT]    = "peer.connect_timeout",
        [EV_PEER_CACHE_SKIPPED]      = "peer.cache_skipped",
        [EV_SYNC_STATE_CHANGE]       = "sync.state_change",
        [EV_HEADERS_RECEIVED]        = "sync.headers_received",
        [EV_HEADERS_REJECTED]        = "sync.headers_rejected",
        [EV_BLOCK_REQUESTED]         = "sync.block_requested",
        [EV_TIP_STALE]               = "sync.tip_stale",
        [EV_SYNC_HEARTBEAT]          = "sync.heartbeat",
        [EV_LONG_OP_BEGIN]           = "long_op.begin",
        [EV_LONG_OP_TICK]            = "long_op.tick",
        [EV_LONG_OP_END]             = "long_op.end",
        [EV_BLOCK_CONNECTED]         = "val.block_connected",
        [EV_BLOCK_REJECTED]          = "val.block_rejected",
        [EV_SELF_HEAL_SCAN_HIT]      = "val.self_heal_scan_hit",
        [EV_SELF_HEAL_SCAN_EXHAUSTED]= "val.self_heal_scan_exhausted",
        [EV_TIP_UPDATED]             = "chain.tip_updated",
        [EV_REORG_START]             = "chain.reorg_start",
        [EV_REORG_DISCONNECT_FAILED] = "chain.reorg_disconnect_failed",
        [EV_REORG_RECOVERY_COMPLETE] = "chain.reorg_recovery_complete",
        [EV_COINS_FLUSH]             = "chain.coins_flush",
        [EV_COINS_FLUSH_FAILED]      = "chain.coins_flush_fail",
        [EV_UTXO_AUDIT_OK]           = "chain.utxo_audit_ok",
        [EV_UTXO_DRIFT_DETECTED]     = "chain.utxo_drift_detected",
        [EV_CHAIN_TIP_COMMIT]        = "chain.tip_commit",
        [EV_CHAIN_TIP_REJECTED]      = "chain.tip_rejected",
        [EV_RECOVERY_POLICY_ALLOW]   = "recovery.policy_allow",
        [EV_RECOVERY_POLICY_REFUSED] = "recovery.policy_refused",
        [EV_RECOVERY_POLICY_PROMPT]  = "recovery.policy_prompt",
        [EV_DB_TXN_BEGIN]            = "db.txn_begin",
        [EV_DB_TXN_COMMIT]           = "db.txn_commit",
        [EV_DB_TXN_ROLLBACK]         = "db.txn_rollback",
        [EV_DB_TXN_REJECTED]         = "db.txn_rejected",
        [EV_DB_TXN_LEAKED]           = "db.txn_leaked",
        [EV_TX_ACCEPTED]             = "tx.accepted",
        [EV_TX_REJECTED]             = "tx.rejected",
        [EV_SNAPSHOT_OFFER_SENT]     = "snap.offer_sent",
        [EV_SNAPSHOT_OFFER_RECEIVED] = "snap.offer_received",
        [EV_SNAPSHOT_COMPLETE]       = "snap.complete",
        /* Boot phases */
        [EV_BOOT_PHASE]              = "boot.phase",
        [EV_BOOT_DB_OPEN]            = "boot.db_open",
        [EV_BOOT_COINS_OPEN]         = "boot.coins_open",
        [EV_BOOT_UTXO_IMPORT]        = "boot.utxo_import",
        [EV_BOOT_BLOCK_INDEX]        = "boot.block_index",
        [EV_BOOT_CHAIN_RESTORED]     = "boot.chain_restored",
        [EV_BOOT_ACTIVATE]           = "boot.activate",
        [EV_BOOT_VALIDATION_FAILED]  = "boot.validation_failed",
        /* Validation pipeline (detailed) */
        [EV_BLOCK_CHECK_PASSED]      = "val.check_passed",
        [EV_BLOCK_CONNECT_START]     = "val.connect_start",
        [EV_BLOCK_CONNECT_DONE]      = "val.connect_done",
        [EV_TX_INPUTS_CHECKED]       = "val.tx_inputs",
        [EV_TURNSTILE_CHECK]         = "val.turnstile",
        [EV_SCRIPT_VERIFIED]         = "val.script_verified",
        [EV_UTXO_CHECKPOINT_PASS]    = "val.utxo_cp_pass",
        [EV_UTXO_CHECKPOINT_FAIL]    = "val.utxo_cp_fail",
        /* ActiveRecord model lifecycle */
        [EV_MODEL_SAVED]             = "model.saved",
        [EV_MODEL_DESTROYED]         = "model.destroyed",
        [EV_MODEL_VALIDATION_FAILED] = "model.validation_failed",
        [EV_UTXO_SAVED]              = "model.utxo_saved",
        [EV_BLOCK_SAVED]             = "model.block_saved",
        [EV_WALLET_KEY_SAVED]        = "model.wallet_key_saved",
        [EV_SAPLING_KEY_SAVED]       = "model.sapling_key_saved",
        [EV_WALLET_TX_SAVED]         = "model.wallet_tx_saved",
        [EV_WALLET_UTXO_SAVED]       = "model.wallet_utxo_saved",
        [EV_RECOVERY_ACTION]         = "recovery.action",
        /* System */
        [EV_NODE_STARTING]           = "sys.starting",
        [EV_NODE_READY]              = "sys.ready",
        [EV_NODE_SHUTDOWN]           = "sys.shutdown",
        [EV_CRASH]                   = "sys.crash",
        [EV_CRASH_RECOVERY_START]    = "sys.crash_recovery_start",
        [EV_CRASH_RECOVERY_COMPLETE] = "sys.crash_recovery_complete",
        [EV_DB_ERROR]                = "sys.db_error",
        [EV_MMB_APPEND]              = "mmb.append",
        [EV_MMB_PROOF_VERIFIED]      = "mmb.proof_verified",
        [EV_FC_SAMPLE_VERIFIED]      = "fc.sample_verified",
        [EV_FC_CHAIN_VERIFIED]       = "fc.chain_verified",
        [EV_SNAPSYNC_STATE_CHANGE]   = "snapsync.state",
        [EV_SNAPSYNC_PROGRESS]       = "snapsync.progress",
        [EV_SNAPSYNC_VERIFIED]       = "snapsync.verified",
        [EV_RESERVED_TRANSPORT_REQUEST] = "reserved.transport_request",
        [EV_BLOCK_INDEX_CORRUPT]     = "boot.block_index_corrupt",
        [EV_WALLET_BACKUP]           = "wallet.backup",
        [EV_WALLET_BACKUP_FAILED]    = "wallet.backup_failed",
        [EV_DISK_LOW]                = "disk.low",
        [EV_DISK_CRITICAL]           = "disk.critical",
        [EV_DISK_OK]                 = "disk.ok",
        [EV_DB_MAINTENANCE_START]    = "db.maint_start",
        [EV_DB_MAINTENANCE_DONE]     = "db.maint_done",
        [EV_DB_MAINTENANCE_FAILED]   = "db.maint_failed",
        [EV_MEMPOOL_EVICT]           = "mempool.evict",
        [EV_MEMPOOL_EXPIRE]          = "mempool.expire",
        [EV_ADDRMAN_CORRUPT]         = "addrman.corrupt",
        [EV_PEER_THROTTLED]          = "peer.throttled",
        [EV_IBD_THROTTLED]           = "ibd.throttled",
        [EV_CONSENSUS_REJECT_TX]     = "consensus.reject_tx",
        [EV_CONSENSUS_REJECT_BLOCK]  = "consensus.reject_block",
        [EV_RPC_TIMEOUT]             = "rpc.timeout",
        [EV_BLOCK_PRUNING_DONE]      = "block.pruning_done",
        [EV_BACKPRESSURE_ACTIVE]     = "net.backpressure_active",
        [EV_BACKPRESSURE_REJECT]     = "net.backpressure_reject",
        [EV_BACKPRESSURE_CLEAR]      = "net.backpressure_clear",
        [EV_SAPLING_PERSIST_FAIL]    = "val.sapling_persist_fail",
        [EV_ORACLE_AGREE]            = "oracle.agree",
        [EV_ORACLE_DISAGREE]         = "oracle.disagree",
        /* Oracle-policy escalations: emitted by the chain-advance guard but
         * previously absent from this table, so they serialized as "unknown"
         * in eventlog and could not be filtered by name. They are the loudest
         * operator-action signals (a suspected fork, a violated anchor prefix,
         * a halted chain), so name them explicitly. */
        [EV_FORK_SUSPECTED]          = "oracle.fork_suspected",
        [EV_ANCHOR_PANIC]            = "oracle.anchor_panic",
        [EV_CHAIN_HALTED]            = "oracle.chain_halted",
        [EV_CHAIN_ADVANCE_DECISION]  = "chain.advance_decision",
        [EV_MIRROR_CONSENSUS_DECISION] = "mirror.consensus_decision",
        [EV_CHAIN_ADVANCE_RESERVED]  = "chain.advance_reserved",
        [EV_PEER_FLOOR_BREACH]       = "peer.floor_breach",
        [EV_LAG_SLO_BREACH]          = "mirror.lag_slo_breach",
        [EV_MIRROR_CONCURRENT_CATCHUP] = "mirror.concurrent_catchup",
        [EV_COORDINATOR_LEGACY_RESERVED] = "coordinator.legacy_reserved",
        [EV_CONDITION_DETECTED]      = "condition.detected",
        [EV_CONDITION_REMEDY_ATTEMPTED] = "condition.remedy_attempted",
        [EV_CONDITION_CLEARED]       = "condition.cleared",
        [EV_OPERATOR_NEEDED]         = "condition.operator_needed",
    };
    if (type >= 0 && type < EV_NUM_TYPES && names[type])
        return names[type];
    return "unknown";
}

/* ── Dump to stderr ──────────────────────────────────────── */

/* A payload renders as a quoted string when every byte is printable
 * (>= 0x20) or a NUL; any other control byte forces the hex fallback. */
static bool payload_is_text(const uint8_t *payload, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        if (payload[i] < 0x20 && payload[i] != 0)
            return false;
    }
    return true;
}

static void format_event(FILE *f, const struct event *ev)
{
    int64_t sec = ev->timestamp_us / 1000000;
    int64_t usec = ev->timestamp_us % 1000000;

    fprintf(f, "[%lld.%06lld] %-28s peer=%-4u ",
            (long long)sec, (long long)usec,
            event_type_name(ev->type), ev->peer_id);

    /* Print payload as string if it looks like text, else hex */
    if (ev->payload_len > 0) {
        bool is_text = payload_is_text(ev->payload, ev->payload_len);
        if (is_text) {
            fprintf(f, "\"%.*s\"", (int)ev->payload_len,
                    (const char *)ev->payload);
        } else {
            for (uint32_t i = 0; i < ev->payload_len && i < 32; i++)
                fprintf(f, "%02x", ev->payload[i]);
            if (ev->payload_len > 32)
                fprintf(f, "...");
        }
    }
    fprintf(f, "\n");
}

void event_dump_recent(size_t count)
{
    if (!atomic_load(&g_log.initialized))
        return;

    uint64_t end = atomic_load(&g_log.write_pos);
    if (count > EVENT_LOG_SIZE) count = EVENT_LOG_SIZE;
    uint64_t start = end > count ? end - count : 0;

    fprintf(stderr, "\n═══ EVENT LOG (last %zu of %llu total) ═══\n",  // obs-ok:crash-dump-banner
            count, (unsigned long long)end);

    for (uint64_t i = start; i < end; i++) {
        const struct event *ev = &g_log.ring[i & EVENT_LOG_MASK];
        uint64_t seq = atomic_load_explicit(&ev->sequence,
                                             memory_order_acquire);
        if (seq != i + 1) {
            fprintf(stderr, "[%llu] <overwritten>\n", (unsigned long long)i);  // obs-ok:crash-dump-banner
            continue;
        }
        format_event(stderr, ev);
    }
    fprintf(stderr, "═══ END EVENT LOG ═══\n\n");  // obs-ok:crash-dump-banner
    /* the crash handler invokes us on SIGABRT just before
     * _exit(); stderr is fully-buffered under systemd's file-
     * redirected StandardError, so any fprintf we did above sits in
     * the FILE* buffer and gets dropped by _exit (which bypasses
     * libc cleanup).  Flush now so the dump reaches node.log even
     * on the crash path.  In non-crash contexts this is cheap and
     * matches what an fclose would do on shutdown. */
    fflush(stderr);
}

/* ── JSON dump ───────────────────────────────────────────── */

static size_t json_escape(char *out, size_t out_size,
                           const char *s, size_t len)
{
    size_t w = 0;
    for (size_t i = 0; i < len && w + 6 < out_size; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"')       { out[w++] = '\\'; out[w++] = '"'; }
        else if (c == '\\') { out[w++] = '\\'; out[w++] = '\\'; }
        else if (c == '\n') { out[w++] = '\\'; out[w++] = 'n'; }
        else if (c == '\r') { out[w++] = '\\'; out[w++] = 'r'; }
        else if (c == '\t') { out[w++] = '\\'; out[w++] = 't'; }
        else if (c < 0x20)  { w += (size_t)snprintf(out + w, out_size - w,
                                                     "\\u%04x", c); }
        else                { out[w++] = (char)c; }
    }
    return w;
}

/* Render a payload into `out` for the JSON "data" field: printable
 * payloads pass through json_escape, binary payloads become a bounded
 * hex string. Returns the number of bytes written. */
static size_t format_payload_escaped(char *out, size_t out_size,
                                     const uint8_t *payload, uint32_t len)
{
    size_t elen = 0;
    if (len == 0)
        return 0;
    if (payload_is_text(payload, len)) {
        elen = json_escape(out, out_size, (const char *)payload, len);
    } else {
        for (uint32_t j = 0; j < len && elen + 2 < out_size; j++)
            elen += (size_t)snprintf(out + elen, out_size - elen,
                                     "%02x", payload[j]);
    }
    return elen;
}

size_t event_dump_json(char *buf, size_t buf_size, size_t count)
{
    if (!atomic_load(&g_log.initialized))
        return 0;

    uint64_t end = atomic_load(&g_log.write_pos);
    if (count > EVENT_LOG_SIZE) count = EVENT_LOG_SIZE;
    uint64_t start = end > count ? end - count : 0;

    size_t w = 0;
    if (w < buf_size) buf[w++] = '[';

    bool first = true;
    for (uint64_t i = start; i < end && w + 256 < buf_size; i++) {
        const struct event *ev = &g_log.ring[i & EVENT_LOG_MASK];
        uint64_t seq = atomic_load_explicit(&ev->sequence,
                                             memory_order_acquire);
        if (seq != i + 1) continue;

        if (!first && w < buf_size) buf[w++] = ',';
        first = false;

        /* Payload as escaped string */
        char escaped[256];
        size_t elen = format_payload_escaped(escaped, sizeof(escaped),
                                             ev->payload, ev->payload_len);

        w += (size_t)snprintf(buf + w, buf_size - w,
            "{\"seq\":%llu,\"ts\":%lld,\"type\":\"%s\","
            "\"peer\":%u,\"data\":\"%.*s\"}",
            (unsigned long long)(i),
            (long long)ev->timestamp_us,
            event_type_name(ev->type),
            ev->peer_id,
            (int)elen, escaped);
    }

    if (w < buf_size) buf[w++] = ']';
    if (w < buf_size) buf[w] = '\0';
    return w;
}

size_t event_dump_json_filtered(char *buf, size_t buf_size, size_t count,
                                 const char *type_prefix)
{
    if (!atomic_load(&g_log.initialized) || !type_prefix)
        return event_dump_json(buf, buf_size, count);

    size_t prefix_len = strlen(type_prefix);
    if (prefix_len == 0)
        return event_dump_json(buf, buf_size, count);
    if (count > EVENT_LOG_SIZE)
        count = EVENT_LOG_SIZE;
    if (count == 0) {
        if (buf_size > 0) buf[0] = '[';
        if (buf_size > 1) buf[1] = ']';
        if (buf_size > 2) buf[2] = '\0';
        return 2;
    }

    uint64_t end = atomic_load(&g_log.write_pos);
    uint64_t start = end > EVENT_LOG_SIZE ? end - EVENT_LOG_SIZE : 0;
    uint64_t *matches = zcl_malloc(count * sizeof(*matches),
                                   "event_dump_json_filtered/matches");
    if (!matches)
        return 0;

    size_t matched = 0;
    for (uint64_t i = end; i > start && matched < count; i--) {
        uint64_t seqno = i - 1;
        const struct event *ev = &g_log.ring[seqno & EVENT_LOG_MASK];
        uint64_t seq = atomic_load_explicit(&ev->sequence,
                                             memory_order_acquire);
        if (seq != seqno + 1) continue;

        const char *name = event_type_name(ev->type);
        if (strncmp(name, type_prefix, prefix_len) != 0)
            continue;

        matches[matched++] = seqno;
    }

    size_t w = 0;
    if (w < buf_size) buf[w++] = '[';

    bool first = true;
    for (size_t j = matched; j > 0 && w + 256 < buf_size; j--) {
        uint64_t seqno = matches[j - 1];
        const struct event *ev = &g_log.ring[seqno & EVENT_LOG_MASK];
        uint64_t seq = atomic_load_explicit(&ev->sequence,
                                             memory_order_acquire);
        if (seq != seqno + 1) continue;

        if (!first && w < buf_size) buf[w++] = ',';
        first = false;

        char escaped[256];
        size_t elen = format_payload_escaped(escaped, sizeof(escaped),
                                             ev->payload, ev->payload_len);

        w += (size_t)snprintf(buf + w, buf_size - w,
            "{\"seq\":%llu,\"ts\":%lld,\"type\":\"%s\","
            "\"peer\":%u,\"data\":\"%.*s\"}",
            (unsigned long long)(seqno),
            (long long)ev->timestamp_us,
            event_type_name(ev->type), ev->peer_id,
            (int)elen, escaped);
    }

    if (w < buf_size) buf[w++] = ']';
    if (w < buf_size) buf[w] = '\0';
    free(matches);
    return w;
}

uint64_t event_log_head_sequence(void)
{
    if (!atomic_load(&g_log.initialized))
        return 0;
    return atomic_load_explicit(&g_log.write_pos, memory_order_acquire);
}

/* ── Crash handler ───────────────────────────────────────── */

/* async-signal-safe stderr write. When systemd has StandardError
 * redirected to node.log (fully-buffered FILE*), fprintf() output
 * silently dies on _exit because libc's atexit handlers don't run.
 * backtrace_symbols_fd() writes straight to STDERR_FILENO via write(2)
 * which bypasses the FILE buffer and therefore always lands. So
 * everything this handler emits goes through write(2) directly, and we
 * flush+fsync before _exit so event_dump_recent's fprintf output lands too. */
static void crash_write_fd(int fd, const char *s, size_t n)
{
    ssize_t w = write(fd, s, n);
    (void)w;  /* best-effort — nothing we can do if the fd is gone */
}

/* Emit header + backtrace to one fd. Reused for stderr and the durable
 * crash log so a crash is recorded in BOTH places (the durable file
 * survives even when systemd's stderr routing loses the buffer). */
static void crash_emit_to(int fd, int sig, void *const *frames, int nframes)
{
    char buf[160];
    /* snprintf is technically not POSIX async-signal-safe but glibc's
     * bounded numeric variant is lock-free; the alternative (hand-rolled
     * itoa) doesn't meaningfully improve safety here. Trade-off acknowledged. */
    int n = snprintf(buf, sizeof(buf),
                     "\n\n*** FATAL SIGNAL %d (pid=%d t=%ld) ***\n",
                     sig, (int)getpid(),
                     (long)time(NULL));  // platform-ok:async-signal-safe-crash-handler (platform.clock may lock)
    if (n > 0) crash_write_fd(fd, buf, (size_t)n);
    n = snprintf(buf, sizeof(buf),
                 "=== STACK BACKTRACE (%d frames) ===\n", nframes);
    if (n > 0) crash_write_fd(fd, buf, (size_t)n);
    backtrace_symbols_fd(frames, nframes, fd);  /* -rdynamic for symbol names */
    static const char end_bt[] = "=== END BACKTRACE ===\n\n";
    crash_write_fd(fd, end_bt, sizeof(end_bt) - 1);
}

static void crash_signal_handler(int sig)
{
    signal_handler_run_crash_hook(sig, NULL, NULL);

    void *frames[64];
    int nframes = backtrace(frames, 64);

    crash_emit_to(STDERR_FILENO, sig, frames, nframes);

    /* Durable, fsync'd copy independent of stderr routing. */
    int cfd = signal_handler_crash_log_fd();
    if (cfd >= 0) {
        crash_emit_to(cfd, sig, frames, nframes);
        fsync(cfd);
    }

    event_emitf(EV_CRASH, 0, "signal %d", sig);
    event_dump_recent(200);  /* fprintf-based; flushes stderr at end */

    /* Belt-and-suspenders flush: event_dump_recent already flushes on
     * its way out, but a caller that emits more output after this
     * handler runs (SA_RESETHAND one-shot still lets the default
     * disposition produce its own output) would want the buffer
     * drained.  fsync drives the kernel page cache down to the
     * journald/journal-file so the log line is durable. */
    fflush(stderr);
    fsync(STDERR_FILENO);
    _exit(128 + sig);
}

void event_install_crash_handler(void)
{
    /* Alternate signal stack: without SA_ONSTACK + a registered alt stack a
     * stack-overflow SIGSEGV cannot run this handler at all (the thread stack
     * is already exhausted). The static buffer lives for the process lifetime. */
    static char alt_stack[64 * 1024];
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = alt_stack;
    ss.ss_size = sizeof(alt_stack);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);  /* best-effort; safe at boot (single-threaded) */

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_signal_handler;
    /* one-shot (avoid infinite recursion) + run on the alt stack. */
    sa.sa_flags = SA_RESETHAND | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}
/* ── Peer state machine ──────────────────────────────────── */

const char *peer_state_name(enum peer_state state)
{
    static const char *names[] = {
        [PEER_DISCONNECTED]      = "disconnected",
        [PEER_CONNECTING]        = "connecting",
        [PEER_CONNECTED]         = "connected",
        [PEER_VERSION_SENT]      = "version_sent",
        [PEER_VERSION_RECEIVED]  = "version_received",
        [PEER_HANDSHAKE_COMPLETE]= "handshake_complete",
        [PEER_ACTIVE]            = "active",
        [PEER_SYNCING_HEADERS]   = "syncing_headers",
        [PEER_SYNCING_BLOCKS]    = "syncing_blocks",
        [PEER_SNAPSHOT_SERVING]  = "snapshot_serving",
        [PEER_SNAPSHOT_RECEIVING]= "snapshot_receiving",
        [PEER_STALE]             = "stale",
        [PEER_DISCONNECTING]     = "disconnecting",
        [PEER_BANNED]            = "banned",
    };
    if (state >= 0 && state < PEER_NUM_STATES)
        return names[state];
    return "unknown";
}

/* Transition table: [from][to] = legal.
 * Only transitions explicitly listed here are allowed.
 * Anything else is a bug that gets caught immediately. */
static const bool g_peer_transitions[PEER_NUM_STATES][PEER_NUM_STATES] = {
    /* DISCONNECTED can go to CONNECTING or CONNECTED (inbound) */
    [PEER_DISCONNECTED][PEER_CONNECTING]         = true,
    [PEER_DISCONNECTED][PEER_CONNECTED]          = true,

    /* CONNECTING goes to CONNECTED or VERSION_SENT (outbound shortcut) */
    [PEER_CONNECTING][PEER_CONNECTED]            = true,
    [PEER_CONNECTING][PEER_VERSION_SENT]         = true,
    [PEER_CONNECTING][PEER_DISCONNECTED]         = true,
    [PEER_CONNECTING][PEER_DISCONNECTING]        = true,

    /* CONNECTED: send or receive version */
    [PEER_CONNECTED][PEER_VERSION_SENT]          = true,
    [PEER_CONNECTED][PEER_VERSION_RECEIVED]      = true,
    [PEER_CONNECTED][PEER_DISCONNECTING]         = true,

    /* VERSION_SENT: receive their version */
    [PEER_VERSION_SENT][PEER_VERSION_RECEIVED]   = true,
    [PEER_VERSION_SENT][PEER_HANDSHAKE_COMPLETE] = true,
    [PEER_VERSION_SENT][PEER_DISCONNECTING]      = true,

    /* VERSION_RECEIVED: handshake completes */
    [PEER_VERSION_RECEIVED][PEER_VERSION_SENT]   = true,
    [PEER_VERSION_RECEIVED][PEER_HANDSHAKE_COMPLETE] = true,
    [PEER_VERSION_RECEIVED][PEER_DISCONNECTING]  = true,

    /* HANDSHAKE_COMPLETE: transition to active or sync */
    [PEER_HANDSHAKE_COMPLETE][PEER_ACTIVE]       = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_SYNCING_HEADERS] = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_SYNCING_BLOCKS]  = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_SNAPSHOT_SERVING] = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_SNAPSHOT_RECEIVING] = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_DISCONNECTING]= true,

    /* ACTIVE: can start syncing or snapshot */
    [PEER_ACTIVE][PEER_SYNCING_HEADERS]          = true,
    [PEER_ACTIVE][PEER_SYNCING_BLOCKS]           = true,
    [PEER_ACTIVE][PEER_SNAPSHOT_SERVING]          = true,
    [PEER_ACTIVE][PEER_SNAPSHOT_RECEIVING]        = true,
    [PEER_ACTIVE][PEER_STALE]                    = true,
    [PEER_ACTIVE][PEER_DISCONNECTING]            = true,

    /* SYNCING_HEADERS: done → blocks or active, or fail */
    [PEER_SYNCING_HEADERS][PEER_SYNCING_BLOCKS]  = true,
    [PEER_SYNCING_HEADERS][PEER_ACTIVE]          = true,
    [PEER_SYNCING_HEADERS][PEER_SNAPSHOT_RECEIVING] = true,
    [PEER_SYNCING_HEADERS][PEER_SNAPSHOT_SERVING]   = true,
    [PEER_SYNCING_HEADERS][PEER_STALE]           = true,
    [PEER_SYNCING_HEADERS][PEER_DISCONNECTING]   = true,

    /* SYNCING_BLOCKS: done → active, or fail */
    [PEER_SYNCING_BLOCKS][PEER_ACTIVE]           = true,
    [PEER_SYNCING_BLOCKS][PEER_SYNCING_HEADERS]  = true,
    [PEER_SYNCING_BLOCKS][PEER_SNAPSHOT_RECEIVING] = true,
    [PEER_SYNCING_BLOCKS][PEER_SNAPSHOT_SERVING]   = true,
    [PEER_SYNCING_BLOCKS][PEER_STALE]            = true,
    [PEER_SYNCING_BLOCKS][PEER_DISCONNECTING]    = true,

    /* SNAPSHOT states: complete → active, or fail */
    [PEER_SNAPSHOT_SERVING][PEER_ACTIVE]          = true,
    [PEER_SNAPSHOT_SERVING][PEER_DISCONNECTING]   = true,
    [PEER_SNAPSHOT_RECEIVING][PEER_ACTIVE]         = true,
    [PEER_SNAPSHOT_RECEIVING][PEER_DISCONNECTING]  = true,

    /* STALE: can recover or disconnect */
    [PEER_STALE][PEER_ACTIVE]                    = true,
    [PEER_STALE][PEER_SYNCING_HEADERS]           = true,
    [PEER_STALE][PEER_DISCONNECTING]             = true,

    /* DISCONNECTING always goes to DISCONNECTED */
    [PEER_DISCONNECTING][PEER_DISCONNECTED]      = true,

    /* BANNED always goes to DISCONNECTED */
    [PEER_BANNED][PEER_DISCONNECTED]             = true,

    /* Any state can be banned or disconnect */
    [PEER_ACTIVE][PEER_BANNED]                   = true,
    [PEER_SYNCING_HEADERS][PEER_BANNED]          = true,
    [PEER_SYNCING_BLOCKS][PEER_BANNED]           = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_BANNED]       = true,
    [PEER_SNAPSHOT_SERVING][PEER_BANNED]          = true,
    [PEER_SNAPSHOT_RECEIVING][PEER_BANNED]        = true,
};

bool peer_transition_valid(enum peer_state from, enum peer_state to)
{
    if (from >= PEER_NUM_STATES || to >= PEER_NUM_STATES)
        return false;
    return g_peer_transitions[from][to];
}

bool peer_set_state_checked(uint32_t peer_id, _Atomic enum peer_state *current,
                            enum peer_state new_state, const char *reason)
{
    /* Relaxed atomic read removes the torn read that produced spurious
     * "BUG: illegal transition" spam. The read-validate-write below is not a
     * single CAS, so two concurrent transitions can still race the validate
     * (documented-benign: mis-print / lost transition only, no memory
     * corruption, no change to which transitions are legal). */
    enum peer_state old = atomic_load_explicit(current, memory_order_acquire);

    if (!peer_transition_valid(old, new_state)) {
        /* Illegal transition — this is always a bug */
        char buf[EVENT_PAYLOAD_SIZE];
        int n = snprintf(buf, sizeof(buf), "ILLEGAL %s->%s: %s",
                         peer_state_name(old), peer_state_name(new_state),
                         reason ? reason : "");
        event_emit(EV_PEER_STATE_CHANGE, peer_id, buf, (uint32_t)(n > 0 ? n : 0));
        fprintf(stderr, "BUG: peer %u illegal transition %s -> %s (%s)\n",
                peer_id, peer_state_name(old),
                peer_state_name(new_state),
                reason ? reason : "");
        return false;
    }

    /* Release-publish immutable version/handshake metadata written before the
     * transition; diagnostic readers acquire-load state before copying it. */
    atomic_store_explicit(current, new_state, memory_order_release);

    char buf[EVENT_PAYLOAD_SIZE];
    int n = snprintf(buf, sizeof(buf), "%s->%s: %s",
                     peer_state_name(old), peer_state_name(new_state),
                     reason ? reason : "");
    event_emit(EV_PEER_STATE_CHANGE, peer_id, buf, (uint32_t)(n > 0 ? n : 0));
    return true;
}


/* ── Error accumulator ──────────────────────────────────── */

void error_ring_init(struct error_ring *r)
{
    memset(r, 0, sizeof(*r));
    atomic_store(&r->write_pos, 0);
    atomic_store(&r->total_count, 0);
}

void error_ring_observer(enum event_type type, uint32_t peer_id,
                         const void *payload, uint32_t payload_len, void *ctx)
{
    (void)peer_id;
    struct error_ring *r = (struct error_ring *)ctx;
    int pos = atomic_fetch_add(&r->write_pos, 1) % ERROR_RING_SIZE;
    struct error_entry *e = &r->entries[pos];

    e->timestamp_us = platform_time_realtime_us();
    e->type = type;
    if (payload && payload_len > 0) {
        size_t copy = payload_len < sizeof(e->message) - 1
                      ? payload_len : sizeof(e->message) - 1;
        memcpy(e->message, payload, copy);
        e->message[copy] = '\0';
    } else {
        e->message[0] = '\0';
    }
    atomic_fetch_add(&r->total_count, 1);
}

int error_ring_total(const struct error_ring *r)
{
    return atomic_load(&r->total_count);
}

const struct error_entry *error_ring_last(const struct error_ring *r)
{
    int total = atomic_load(&r->total_count);
    if (total == 0) return NULL;
    int pos = (atomic_load(&r->write_pos) - 1 + ERROR_RING_SIZE) % ERROR_RING_SIZE;
    return &r->entries[pos];
}

size_t error_ring_dump_json(const struct error_ring *r, char *buf, size_t sz)
{
    int total = atomic_load(&r->total_count);
    int count = total < ERROR_RING_SIZE ? total : ERROR_RING_SIZE;
    int wp = atomic_load(&r->write_pos);

    size_t off = 0;
    off += (size_t)snprintf(buf + off, sz - off,
        "{\"total\":%d,\"errors\":[", total);

    for (int i = 0; i < count && off < sz - 2; i++) {
        int idx = (wp - count + i + ERROR_RING_SIZE) % ERROR_RING_SIZE;
        const struct error_entry *e = &r->entries[idx];
        if (i > 0) off += (size_t)snprintf(buf + off, sz - off, ",");
        off += (size_t)snprintf(buf + off, sz - off,
            "{\"type\":\"%s\",\"time\":%lld,\"msg\":\"%s\"}",
            event_type_name(e->type),
            (long long)(e->timestamp_us / 1000000),
            e->message);
    }
    off += (size_t)snprintf(buf + off, sz - off, "]}");
    return off;
}

struct error_ring *error_ring_global(void)
{
    return &g_error_ring;
}
