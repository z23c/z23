/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * event_log — append-only durable event stream primitive.
 *
 * The event log is the durable source for reducer/projection replay.
 * This file ships only the primitive; boot/runtime code wires concrete
 * producers and projections. See `docs/FRAMEWORK.md` for the current
 * reducer authority model.
 *
 * Wire format (per event)
 * -----------------------
 *   [ 4B  payload_length  (LE) ]
 *   [ 4B  event_type      (LE) ]
 *   [ 4B  flags           (LE) ]   <- reserved (0)
 *   [ 4B  payload_crc32c  (LE) ]   <- Castagnoli polynomial 0x1EDC6F41
 *   [ NB  payload              ]
 *   [ 16B fsync_sentinel       ]   <- 8B magic + 8B event_start_offset
 *
 * The fsync sentinel is the load-bearing design choice: it makes torn
 * writes recoverable without ambiguity.
 *
 *   1. Write the header + payload (16 + N bytes).
 *   2. fsync(fd).
 *   3. Write the sentinel (16 bytes: magic + start_offset).
 *   4. fsync(fd).
 *
 * On replay/recovery:
 *   - Scan from end-of-file backward.
 *   - The last event must end with the magic sentinel whose embedded
 *     offset equals the event's start position.
 *   - If the sentinel is absent or wrong (torn write at step 3 or 4 or
 *     somewhere mid-payload), TRUNCATE the file at the start of the
 *     partial event.
 *   - Result: no torn writes are ever observable to readers.
 *
 * Threading
 * ----------
 * The implementation takes a per-log mutex around append; reads use
 * pread and are safe under concurrent readers + a single appender.
 *
 * The append backend may change, but the wire format is frozen and must
 * remain stable. */

#ifndef ZCL_STORAGE_EVENT_LOG_H
#define ZCL_STORAGE_EVENT_LOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct event_log event_log_t;

/* Event types for the event log. The tag is `event_log_type` (NOT
 * `event_type`) to avoid colliding with `engine/modules/event/event.h`'s system-
 * wide event taxonomy, which is for in-memory observability, not the
 * persistent log. The two namespaces are intentionally separate. */
enum event_log_type {
    EV_BLOCK_HEADER         = 1,
    EV_BLOCK_BODY           = 2,
    EV_TX_ADMIT_MEMPOOL     = 3,
    EV_TX_REMOVE_MEMPOOL    = 4,
    /* Tags 5/6 fed the event-sourced UTXO projection removed in Program H1
     * (the kernel coins store is the one UTXO ledger). The wire format is
     * frozen, so the numeric slots are RESERVED — never reuse them; old event
     * logs may still contain these frames and consumers ignore unknown tags.
     * The tokens survive only for the rebuild_recent tool + event-log tests. */
    EV_UTXO_ADD             = 5,
    EV_UTXO_SPEND           = 6,
    EV_PEER_OBSERVED        = 7,
    EV_PEER_DROPPED         = 8,
    EV_WALLET_KEY_ADD       = 9,
    EV_WALLET_TX_SEEN       = 10,
    EV_STAGE_CURSOR_ADVANCE = 11,
    /* ZNAM projection events. */
    EV_ZNAM_REGISTER        = 12,
    EV_ZNAM_UPDATE          = 13,
    EV_ZNAM_TRANSFER        = 14,
    EV_ZNAM_RENEW           = 15,
    EV_ZNAM_EXPIRE          = 16,
    /* Wallet-view projection public-only events. */
    EV_WALLET_ADDR_DERIVED  = 17,
    EV_WALLET_NOTE_DECRYPTED = 18,
    EV_WALLET_UTXO_SEEN     = 19,
    /* Small-batch projection events. */
    EV_CONTACT_SET          = 20,
    EV_CONTACT_TOUCHED      = 21,
    EV_CONTACT_DELETE       = 22,
    EV_ONION_ANNOUNCEMENT   = 23,
    EV_HODL_SNAPSHOT        = 24,
    /* ZVCS (contexts/commons/modules/vcs) commit log — appended by vcs_snapshot(). */
    EV_VCS_COMMIT           = 25,
    /* Durable network-truth session ledger (peers_projection). A peer
     * session closes → its final bandwidth/latency/delivery reputation +
     * transfer totals. Folded into peer_sessions + addresses reputation. */
    EV_PEER_SESSION_CLOSED  = 26,
    /* A fork observation (two peer clusters at one height): the durable
     * append-only record of network disagreement. Folded into fork_events. */
    EV_NET_FORK_OBSERVED    = 27,
    /* A node-identity observation from a version handshake — real peer OR
     * crawler contact. Carries the pedantically bounded user-agent, protocol
     * version, services bits, and best height. Folded into the durable
     * node_census + census_observations tables (peers_projection). */
    EV_NODE_CENSUS_OBSERVED = 28,
    /* A durable bridge copy of the in-memory EV_OPERATOR_NEEDED bus event
     * (engine/modules/event/event.h — reset-on-restart namespace). Written by
     * engine/services/src/blocker_history.c's observer so an operator page
     * survives restart; payload is "ts=<unix> <original EV_OPERATOR_NEEDED
     * payload>". Folded into the blocker_history aggregate (id -> fire
     * count, first/last fired). */
    EV_OPERATOR_ALERT       = 29,
    /* Lightweight status-only update for a block_index entry that ALREADY
     * has a durable EV_BLOCK_HEADER row from first admit (header_admit
     * stage). body_persist / script_validate bump BLOCK_HAVE_DATA /
     * BLOCK_VALID_SCRIPTS (+ nFile/nDataPos/nUndoPos/nTx) without ever
     * touching the immutable header fields (hash, hashPrev, version,
     * merkle/sapling roots, time, bits, nonce, Equihash solution) — carrying
     * only the mutable fields (52 bytes fixed, storage/event_log_payloads.h)
     * avoids re-serializing the full ~1.5KB header + up-to-1344B solution on
     * every status bump. block_index_projection consumes these against the
     * row the prior EV_BLOCK_HEADER created (storage/block_index_projection.c). */
    EV_BLOCK_STATUS         = 30,
    /* ZVCS proof-to-publication queue. Payload is one immutable 32-byte
     * VCS_TAG_PUBLICATION_JOB root; job state advances in separate receipts. */
    EV_VCS_PUBLICATION_JOB  = 31,
    /* Append-only scheduler progress. Payload is one immutable 32-byte
     * VCS_TAG_PUBLICATION_RECEIPT root; authoritative package/workspace/P2P
     * objects remain under their existing signed owners. */
    EV_VCS_PUBLICATION_RECEIPT = 32,
    /* Optional mirror evidence. Payload is one immutable 32-byte
     * VCS_TAG_DEV_MIRROR_RECEIPT root. It never gates or advances the
     * authoritative proof-to-P2P publication receipt chain. */
    EV_VCS_DEV_MIRROR_RECEIPT = 33,
    /* Add cautiously — every entry is a permanent wire surface. */
};

/* On-disk magic for the fsync sentinel — printable mnemonic
 * "ZCLEVTLG" (0x5A434C45_56544C47, big-endian); we store little-endian
 * on disk so the byte sequence on disk reads "ZCLEVTLG". */
#define EVENT_LOG_SENTINEL_MAGIC UINT64_C(0x474C5456454C435A)

/* Per-event framing overhead: 16B header (len/type/flags/crc, see wire
 * format above) + 16B fsync sentinel. Given a stream callback's
 * (offset, len), the next event begins at offset + EVENT_LOG_FRAME_OVERHEAD
 * + len. */
#define EVENT_LOG_FRAME_OVERHEAD 32u

/* Maximum payload length (defensive cap — 256 MiB). Larger payloads
 * indicate a bug in the caller and are rejected. */
#define EVENT_LOG_MAX_PAYLOAD ((size_t)(256u * 1024u * 1024u))

/* Open or create the event log at `path`. On open, the file is scanned
 * from the tail to detect and TRUNCATE any partial trailing event
 * (recovery from torn writes). Returns NULL if `path` is NULL or empty,
 * if the file cannot be opened, if recovery fails, or on allocation
 * failure. */
event_log_t *event_log_open(const char *path);

/* Close the log. Flushes any pending data. NULL-safe. */
void event_log_close(event_log_t *log);

/* Append one event. Returns the absolute byte offset at which the
 * event was written (suitable as a stable event id) on success, or
 * UINT64_MAX on error. The on-disk format is fully durable (fsync x2)
 * before this call returns. Errors (all return UINT64_MAX): `log` NULL;
 * `payload` NULL with `payload_len > 0`; `payload_len` exceeds
 * EVENT_LOG_MAX_PAYLOAD; or any pwrite/fsync failure (the lock is
 * released before returning). `payload_len == 0` is valid. */
uint64_t event_log_append(event_log_t *log,
                          enum event_log_type type,
                          const void *payload, size_t payload_len);

/* Read one event at `offset` (which must have been returned by a prior
 * append or stream callback). The payload CRC and fsync sentinel are
 * always verified. On a verified event the true payload length is
 * written to `*out_len` and the type to `*type_out` (both optional —
 * pass NULL to skip), then the payload is copied into `buf` only if
 * `buf` is non-NULL and `buf_cap >= payload_len`. Returns 0 on success,
 * -1 on error: `log` NULL; `offset` out of range or the framed event
 * extends past end-of-log; corrupt length; pread failure; CRC mismatch;
 * bad sentinel; allocation failure; or `buf_cap < payload_len` (caller
 * must size the buffer correctly — note `*out_len`/`*type_out` may have
 * been set before this -1). */
int event_log_read(event_log_t *log, uint64_t offset,
                   enum event_log_type *type_out,
                   void *buf, size_t buf_cap, size_t *out_len);

/* Callback for event_log_stream. Return `true` to continue iteration,
 * `false` to stop. `payload` is owned by the streamer and only valid
 * for the duration of the call. */
typedef bool (*event_log_cb)(uint64_t offset, enum event_log_type type,
                              const void *payload, size_t len,
                              void *user);

/* Stream events starting at `start_offset` (0 = beginning). Stops at
 * EOF or when `cb` returns false. Returns 0 on success, -1 on error.
 * Does not call `cb` for partial trailing events (those are truncated
 * at open). */
int event_log_stream(event_log_t *log, uint64_t start_offset,
                     event_log_cb cb, void *user);

/* SHA3-256 over the on-disk payload bytes of every event in order —
 * excludes per-event headers, CRCs, and sentinels (framing only).
 * Identical content → identical fingerprint. Returns 0 on success. */
int event_log_fingerprint(event_log_t *log, uint8_t out[32]);

/* Current size of the log file in bytes (post-recovery). For tests
 * and observability. */
uint64_t event_log_size(event_log_t *log);

/* ── Deferred durability (batched to a drain boundary) ─────────────────
 * event_log_append() normally fsync()s TWICE per event (once after the
 * header+payload, once after the sentinel) — two ext4 journal-commit
 * barriers per append. On the reducer fold / catch-up drain each block
 * emits one EV_BLOCK_HEADER event ON the fold thread, so that is ~2
 * fsync() barriers per block: the drive thread parks in
 * jbd2_log_wait_commit while the CPU is otherwise idle — the measured fold
 * bottleneck.
 *
 * In deferred mode event_log_append() assembles complete
 * header+payload+sentinel records in a bounded buffer. event_log_flush() writes
 * that span and fdatasync()s the file ONCE; the reader-visible end advances
 * only after the bytes are written. The syscall/fsync cadence therefore drops
 * from per-event to once-per-drain-batch.
 *
 * Crash consistency is UNCHANGED. The tail-scan recovery at event_log_open()
 * walks forward from the start and stops at the first event whose CRC or
 * sentinel does not validate, truncating everything from there on. So a crash
 * before a flush recovers to a consistent PREFIX (some whole trailing events
 * are lost, never a torn event exposed), regardless of page-cache writeback
 * order. The reducer wires event_log_flush() into the stage_batch_end
 * pre-commit hook (util/stage.h) so the progress.kv cursor never becomes
 * durable ahead of the event_log bytes it implies — a failed flush VETOES the
 * commit, identical to the block-body fdatasync contract (storage/disk_block_io.h).
 *
 * Deferred mode is a per-handle flag; the reducer drive turns it on for the
 * fold and off at tip (event_log_set_deferred_sync(log, false)), so at tip and
 * for every non-reducer caller (import, tests, vcs) the per-append durability
 * is exactly as before. Kill switch: ZCL_EVENTLOG_SYNC_PER_APPEND=1 forces the
 * per-append fsync even while deferred mode is on (restores the pre-batch
 * behavior for A/B measurement). */
void event_log_set_deferred_sync(event_log_t *log, bool enabled);
bool event_log_deferred_sync_enabled(event_log_t *log);

/* ── Which append path did the fold actually take? ────────────────────
 * The two counters above (event_log_deferred, fsync_flush_count) say what mode
 * the log is in RIGHT NOW and how many batched flushes happened — neither
 * answers how many appends paid the per-append two-barrier price anyway,
 * because deferred mode is armed and disarmed per drain scope and every
 * non-reducer thread appends through the same handle. Without that split, a
 * per-call-site timer (e.g. reducer_stage_profile's header_event_emission_us)
 * shows a large number with no way to tell a slow barrier from a slow buffer
 * copy, and "the fold is fsync-bound" stays an inference instead of a reading.
 *
 * barrier_appends counts appends that took the pwrite+fsync+pwrite+fsync path;
 * barrier_us_total is the wall time spent inside those two fsync() calls only
 * (not the pwrites, not the mutex wait), so barrier_us_total/(2*barrier_appends)
 * is this filesystem's measured per-barrier cost. deferred_appends counts
 * appends that only copied into the pending buffer. Process-wide across every
 * handle (the node opens one), monotonic since start: difference two samples to
 * attribute an interval. Any pointer may be NULL. */
void event_log_append_stats(uint64_t *barrier_appends,
                            uint64_t *deferred_appends,
                            uint64_t *barrier_us_total);

/* fdatasync the log once iff a deferred append is pending, then clear the
 * dirty flag. Returns true on success (or when nothing is pending — cheap to
 * call on every commit), false if the fdatasync failed (the dirty flag is
 * KEPT so a retry re-attempts it; the caller MUST NOT let a durable marker
 * commit on a false return). NULL-safe (returns true). */
bool event_log_flush(event_log_t *log);

#ifdef ZCL_TESTING
const char *event_log_crc32c_impl(void);
uint32_t event_log_crc32c_test_sw(const void *data, size_t len);
uint32_t event_log_crc32c_test_active(const void *data, size_t len);
bool event_log_crc32c_hw_available(void);

/* Deferred-mode test hooks (deterministic coverage of the kill-switch and the
 * flush-failure veto path, which are otherwise env-cached / hard to fault). */
bool event_log_test_dirty(event_log_t *log);        /* current dirty flag */
void event_log_test_reset_append_stats(void);       /* zero the three counters */
void event_log_test_set_force_per_append(int v);    /* -1=env, 0=off, 1=forced */
int  event_log_test_fd(event_log_t *log);           /* raw fd (for fault inject) */
void event_log_test_set_fd(event_log_t *log, int fd);
#endif

#endif /* ZCL_STORAGE_EVENT_LOG_H */
