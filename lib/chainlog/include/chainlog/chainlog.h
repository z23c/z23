/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chainlog — an append-only file whose history cannot be edited quietly.
 *
 * WHY THIS EXISTS, AND WHY IT IS NOT lib/storage/event_log
 * -------------------------------------------------------
 * This tree already has a durable append-only event stream:
 * storage/event_log.h, with a CRC32C per frame and a two-fsync sentinel that
 * makes torn writes unambiguous. It is the right primitive for the job it
 * does — replaying reducers after a crash — and its wire format is frozen.
 *
 * It is not tamper-evident, and it does not claim to be. A CRC answers "did
 * the disk mangle this?" Anyone who edits a record can recompute the CRC in
 * a line of code, so it cannot answer "has anyone edited this?" Those are
 * different questions and only the second one matters for evidence a node
 * quotes to another node.
 *
 *   Every frame here carries chain = SHA3-256(previous chain || frame body),
 *   seeded from the file header itself. Editing, deleting, reordering or
 *   splicing anything breaks every link after it, and the break is localised:
 *   opening the log names the first sequence number that does not verify.
 *
 * That is the shape metaverse/property_receipt.h already proves for a single
 * grant's receipts — canonical bytes, SHA3-256 links, a named first bad
 * sequence number. It is held in a fixed RAM array that a restart empties.
 * This module is the same discipline on disk.
 *
 * TORN IS NOT TAMPERED
 * --------------------
 * A crash mid-append and a forged record must never be confused, so the two
 * are separated structurally rather than by judgement:
 *
 *   append = write the frame, fsync, write a 16-byte commit sentinel that
 *            names the frame's own start offset, fsync.
 *
 * A frame is committed only when the sentinel that follows it names its
 * start. So an interrupted append always leaves an UNCOMMITTED tail, which
 * open() discards and reports as `torn_bytes`. A missing or wrong sentinel
 * anywhere BUT the tail means a committed frame follows an uncommitted one,
 * which no crash can produce; that refuses. A committed frame whose chain
 * does not verify refuses too, and is never truncated: dropping it would
 * destroy the evidence that something was altered. Recovery discards only
 * what was never committed.
 *
 * The two-phase sentinel is not invented here — it is storage/event_log's
 * design, which has carried this tree's durability for a long time. Only the
 * integrity half is new.
 *
 * ON-DISK FORMAT (all integers big-endian, no locale, no float, no padding)
 * ------------------------------------------------------------------------
 *   header, 64 bytes, written once at creation
 *     0   magic[8]      "Z23CHLOG"
 *     8   version u32   1
 *    12   reserved u32  0 — must be zero; a set bit refuses rather than
 *                       being ignored, so this cannot become a silent
 *                       side channel
 *    16   stream[32]    caller's stream id: what this log is a log OF
 *    48   digest[16]    first 16 bytes of SHA3-256(bytes 0..47), so even an
 *                       EMPTY log detects a header edit
 *
 *   frame, repeated
 *     0   kind    u32   caller-defined record kind
 *     4   seq     u64   1-based, dense; a gap refuses
 *    12   len     u32   payload bytes, <= ZCL_CHAINLOG_PAYLOAD_MAX
 *    16   payload
 *    16+len  chain[32]  SHA3-256(prev_chain || bytes 0..16+len-1)
 *    48+len  sentinel[16]  "Z23CMIT\0" || start_offset u64
 *
 *   chain for the first frame is seeded with SHA3-256(header, 64), so every
 *   link depends on the header and no frame can be lifted from another log.
 *
 * The sentinel is deliberately NOT part of the chain. It is a statement
 * about durability, not about history, and a log copied by a tool that
 * rewrote offsets would otherwise fail as tampered when it is merely moved.
 *
 * WHAT THIS DOES NOT DO
 * ---------------------
 * It does not sign. A chain proves nothing was edited SINCE it was written;
 * it says nothing about who wrote it. A caller that needs authorship signs
 * the head hash with its own key (lib/zid) and stores that elsewhere — this
 * module holds no key material and takes none.
 *
 * It grants nothing. A record in this log is evidence, never permission.
 */

#ifndef ZCL_CHAINLOG_H
#define ZCL_CHAINLOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_CHAINLOG_MAGIC          "Z23CHLOG"
#define ZCL_CHAINLOG_SENTINEL_MAGIC "Z23CMIT"
#define ZCL_CHAINLOG_VERSION        1u

#define ZCL_CHAINLOG_HEADER_BYTES   64u
#define ZCL_CHAINLOG_STREAM_BYTES   32u
#define ZCL_CHAINLOG_HASH_BYTES     32u
#define ZCL_CHAINLOG_PREFIX_BYTES   16u   /* kind + seq + len */
#define ZCL_CHAINLOG_SENTINEL_BYTES 16u
#define ZCL_CHAINLOG_PAYLOAD_MAX    65536u

/* Every way this can refuse. There is no generic failure: a caller that has
 * to tell a person what went wrong can always name it. */
enum zcl_chainlog_status {
    ZCL_CHAINLOG_OK = 0,
    ZCL_CHAINLOG_ARGUMENT,        /* a NULL, an oversize payload, a bad seq */
    ZCL_CHAINLOG_IO,              /* the file system said no */
    ZCL_CHAINLOG_FORMAT,          /* not a chainlog, or not this version */
    ZCL_CHAINLOG_STREAM_MISMATCH, /* a log of something else */
    ZCL_CHAINLOG_BROKEN_CHAIN,    /* a committed frame was altered */
    ZCL_CHAINLOG_SEQUENCE,        /* sequence numbers are not dense */
    ZCL_CHAINLOG_UNCOMMITTED_GAP, /* an uncommitted frame with data after it */
    ZCL_CHAINLOG_NOT_FOUND,       /* no such sequence number */
    ZCL_CHAINLOG_TRUNCATED        /* the caller's buffer is too small */
};

const char *zcl_chainlog_status_label(enum zcl_chainlog_status s);

/* What an open or a verify actually found. Filled on success AND on refusal,
 * because "it refused" without saying where is not a diagnosis. */
struct zcl_chainlog_report {
    enum zcl_chainlog_status status;
    uint64_t records;       /* frames accepted before the outcome above */
    uint64_t first_bad_seq; /* 0 when nothing was bad */
    uint64_t torn_bytes;    /* uncommitted tail bytes discarded by open() */
    uint8_t  head[ZCL_CHAINLOG_HASH_BYTES]; /* chain after the last accept */
};

struct zcl_chainlog;

/* Open for append, creating the file when absent. `stream` identifies what
 * the log is a log of; opening an existing log with a different one is
 * ZCL_CHAINLOG_STREAM_MISMATCH, not a silent append to someone else's
 * history. `report` is required and is filled even when this returns NULL.
 *
 * An uncommitted tail is truncated here, and only here: this is the one
 * entry point that may shorten the file, it may only remove bytes that were
 * never committed, and it says how many in `report->torn_bytes`. */
struct zcl_chainlog *zcl_chainlog_open(const char *path,
                                       const uint8_t stream[32],
                                       struct zcl_chainlog_report *report);

void zcl_chainlog_close(struct zcl_chainlog *log);

/* Append one record durably. On success `*out_seq` is its sequence number
 * and `out_chain` the new head. Both are optional.
 *
 * Returns only after both fsyncs, so a success here means the record
 * survives the machine losing power on the next instruction. */
enum zcl_chainlog_status zcl_chainlog_append(struct zcl_chainlog *log,
                                             uint32_t kind,
                                             const void *payload, size_t len,
                                             uint64_t *out_seq,
                                             uint8_t out_chain[32]);

/* Read record `seq` back. `*len` always receives the record's true size, so
 * a ZCL_CHAINLOG_TRUNCATED tells the caller exactly how big a buffer to
 * bring. The frame's chain is re-verified on the way out. */
enum zcl_chainlog_status zcl_chainlog_read(struct zcl_chainlog *log,
                                           uint64_t seq, uint32_t *kind,
                                           void *buf, size_t cap, size_t *len);

uint64_t zcl_chainlog_count(const struct zcl_chainlog *log);
bool zcl_chainlog_head(const struct zcl_chainlog *log, uint8_t out[32]);

/* Walk a log without opening it for append and WITHOUT ever writing to it.
 * This is what an auditor runs: it reports an uncommitted tail rather than
 * removing one, so a log under examination is left exactly as found. */
enum zcl_chainlog_status zcl_chainlog_verify(const char *path,
                                             const uint8_t stream[32],
                                             struct zcl_chainlog_report *report);

#endif /* ZCL_CHAINLOG_H */
