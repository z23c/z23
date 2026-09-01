/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * telemetry_watch — the resumable change feed's RING and its diff.
 *
 * WHAT THIS IS. `ops.telemetry.watch` is a CURSOR POLL, not a stream: one call
 * returns the bounded batch of changes recorded after `since` and exits, and
 * the agent re-invokes with the last sequence it saw. This header owns the two
 * mechanisms that makes that safe — a bounded in-memory ring of change records
 * with monotone sequence numbers, and a generic snapshot differ that decides
 * WHICH leaves changed by walking a domain's own descriptor table.
 *
 * THE FAILURE MODE THIS EXISTS TO PREVENT, and it is the whole design:
 *
 *     an agent that cannot tell a MISSED WINDOW from a QUIET PERIOD will
 *     confidently report "nothing changed" about a node that changed
 *     everything.
 *
 * So the two are made structurally different, three ways over:
 *
 *   a quiet period    -> count == 0, gap == false, dropped_count == 0
 *   a missed window   -> count >= 1 (NEVER empty), gap == true,
 *                        dropped_count == how many records were lost, and the
 *                        loss is stamped on the FIRST returned record as well
 *                        as on the batch, so a reader consuming records one at
 *                        a time sees it too
 *   a restart         -> epoch differs. The sequence is process-local and is
 *                        NOT persisted; without an epoch a restarted feed
 *                        (sequence back to 0) is indistinguishable from a feed
 *                        that has simply stopped moving.
 *
 * `telemetry_watch_read()` is the only place those three are decided, so they
 * cannot drift apart across callers.
 *
 * WHAT THIS IS NOT. It is not a second renderer, a second evaluator, or a
 * second registry: the record carries a HEALTH ENUM that the caller obtained
 * from telemetry_evaluate(), and CHANGED FIELD NAMES that came out of the
 * domain's own `struct telemetry_leaf` rows. No field name is spelled here.
 *
 * Layering: platform/modules/util, over the telemetry render layer's descriptor tables.
 * Reads no node state, opens no store, performs no I/O. The ring takes one
 * short mutex (publish and read are both O(batch) memcpy work under it) and
 * never calls out while holding it.
 */
#ifndef ZCL_UTIL_TELEMETRY_WATCH_H
#define ZCL_UTIL_TELEMETRY_WATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/telemetry_render.h"

/* How many change records the feed remembers. A resume older than the oldest
 * held record is the GAP case above — reported, never silently skipped. */
#define TELEMETRY_WATCH_RING_CAP 64

/* Per-record changed-field list. A record names at most this many leaves and
 * always reports how many the diff actually found, so a wide change is
 * TRUNCATED-and-counted rather than misreported as a narrow one. */
#define TELEMETRY_WATCH_FIELDS_MAX 8
#define TELEMETRY_WATCH_FIELD_MAX 56

/* The command path a record points a reader at ("ops.telemetry.sync.summary").
 * Bounded here because a record is a fixed-size ring slot. */
#define TELEMETRY_WATCH_PATH_MAX 64

/* The most records one read() may return. The command layer caps LOWER than
 * this from its own byte budget; this only bounds the caller's buffer. */
#define TELEMETRY_WATCH_BATCH_MAX 16

/* A worst-case record rendered as JSON, in bytes.
 *
 * WHY A STATIC NUMBER AND NOT A MEASUREMENT. An over-budget reply is written
 * by the kernel as an EMPTY document (write_bounded_json,
 * engine/modules/kernel/src/command_registry.c) — not a truncated one — so a batch that
 * does not fit is not "shorter", it is GONE, and the reader is told nothing.
 * The command layer therefore divides its data frame by this constant to get
 * a maximum record count BEFORE it builds anything. Derivation, at the caps
 * declared above:
 *     fixed keys and punctuation                  ~ 210
 *     canonical_path                              <=  64 + 4
 *     changed_fields: 8 x (56 + 3 quoting/comma)  =   472
 *                                                   -----
 *                                                   ~ 750  -> 768
 * Raising any cap above means raising this. The command layer additionally
 * MEASURES the built document and drops records if the estimate was ever
 * wrong, so this constant being slightly off degrades the batch size rather
 * than emptying the reply. */
#define TELEMETRY_WATCH_RECORD_MAX_JSON 768

/* The group every domain's field table declares for "how and when this
 * snapshot itself was taken" (`TL_GROUP(meta, ...)`, present verbatim in all
 * eight `<domain>_fields.def` tables).
 *
 * Its leaves describe the SAMPLE, not the node: `collected_unix` moves on
 * every tick by construction. Diffing them would make every sample a "change"
 * and the feed would be pure noise — "emits only changes" would be false. This
 * is a GROUP name declared once by the table grammar, not a field name, and
 * the exclusion is published in the reply so no reader has to infer it. */
#define TELEMETRY_WATCH_SELF_GROUP "meta"

/* One change record.
 *
 * `dropped_count` is the number of records lost immediately BEFORE this one
 * from the READER's point of view. It is therefore filled by
 * telemetry_watch_read(), on the first record of a gapped batch only; a stored
 * record always carries 0. Publishing it per-record is deliberate: an agent
 * that consumes the array one line at a time must be able to see the gap
 * without also parsing the envelope. */
struct telemetry_watch_record {
    uint64_t sequence;   /* assigned by publish; strictly increasing per epoch */
    int64_t captured_at; /* wall-clock second the sample was taken; -1 unknown */
    char canonical_path[TELEMETRY_WATCH_PATH_MAX];
    char changed_fields[TELEMETRY_WATCH_FIELDS_MAX][TELEMETRY_WATCH_FIELD_MAX];
    uint32_t changed_count;   /* names carried in changed_fields */
    uint32_t changed_total;   /* names the diff FOUND; > changed_count when cut */
    bool changed_truncated;
    enum telemetry_health health; /* from telemetry_evaluate — never authored */
    uint64_t dropped_count;
};

/* What one read() answered, and why it looks the way it does. Every flag here
 * is set by telemetry_watch_read(); a caller decides nothing. */
struct telemetry_watch_batch {
    struct telemetry_watch_record records[TELEMETRY_WATCH_BATCH_MAX];
    size_t count;
    uint64_t epoch;           /* this feed's identity; changes on restart */
    uint64_t since;           /* echoed, so a reply is self-describing */
    uint64_t next_since;      /* pass this back on the next poll */
    uint64_t last_sequence;   /* newest record the ring holds (0 = none) */
    uint64_t oldest_sequence; /* oldest record still held  (0 = none) */
    uint64_t dropped_count;   /* records the caller missed; > 0 iff `gap` */
    uint64_t published_total; /* records ever published in this epoch */
    bool gap;                 /* the resume fell behind the ring */
    bool epoch_changed;       /* the caller's epoch is not this feed's */
    bool since_ahead;         /* the caller's cursor is past the newest record */
    bool more;                /* records remain after this batch */
    const char *reason;       /* static token; never NULL */
};

/* Arm the feed. Idempotent: the first call mints an epoch, later calls do
 * nothing. Safe to call from any thread and before boot. */
void telemetry_watch_init(void);

/* Mint a NEW epoch and empty the ring — what a process restart does to a feed
 * that is not persisted, made callable so the restart path is testable without
 * a restart. Sequence numbering restarts at 1. */
void telemetry_watch_restart(void);

uint64_t telemetry_watch_epoch(void);
uint64_t telemetry_watch_last_sequence(void);
uint64_t telemetry_watch_published_total(void);

/* Append one record. `rec->sequence` and `rec->dropped_count` are IGNORED on
 * input and assigned here; everything else is copied verbatim. Returns the
 * assigned sequence, or 0 when `rec` is NULL. Evicting the oldest record when
 * the ring is full is normal and is what a later reader reports as a gap. */
uint64_t telemetry_watch_publish(const struct telemetry_watch_record *rec);

/* Read the bounded batch of records after `since`.
 *
 * `since_epoch` is the epoch the caller believes it is resuming within; pass 0
 * for "I did not check", which is honest and is reported back as such rather
 * than assumed to match. A non-zero epoch that does not match this feed's sets
 * `epoch_changed` and restarts the read from the oldest held record, because a
 * sequence minted by a dead feed cannot address anything here.
 *
 * `max_records` is clamped to [1, TELEMETRY_WATCH_BATCH_MAX]: a gapped batch
 * must never come back empty, so zero is not an accepted request.
 *
 * Returns false only on a NULL `out`. Every other outcome — including no
 * records, a gap, and a restarted feed — is a successful read that states its
 * own shape. */
bool telemetry_watch_read(uint64_t since, uint64_t since_epoch,
                          size_t max_records,
                          struct telemetry_watch_batch *out);

/* Which leaves of `schema` differ between two snapshots of the same domain.
 *
 * Fills `rec->changed_fields`, `changed_count`, `changed_total` and
 * `changed_truncated`, and returns changed_total. Leaves in
 * TELEMETRY_WATCH_SELF_GROUP are skipped (see that macro). A leaf counts as
 * changed when its PRESENCE changed or its VALUE changed — presence included,
 * because "the store went busy so this is no longer readable" is a change an
 * operator must see, and comparing values alone would hide it.
 *
 * Knows no domain: every name it writes is a `struct telemetry_leaf`'s own
 * `key`, read out of the descriptor table. `prev` and `cur` must both be
 * snapshots of `schema`'s domain. */
size_t telemetry_watch_diff(const struct telemetry_domain_schema *schema,
                            const void *prev, const void *cur,
                            struct telemetry_watch_record *rec);

#endif /* ZCL_UTIL_TELEMETRY_WATCH_H */
