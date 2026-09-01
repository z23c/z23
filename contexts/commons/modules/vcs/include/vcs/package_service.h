/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_service — the ZCODE local service book (slice 11): the durable
 * per-contributor-key accounting the slice-11 policy (contexts/commons/modules/vcs/
 * package_policy.*) decides over. LOCAL facts only: verified bytes THIS
 * node verifiably served to / received from each contributor key,
 * publication events, no-credit events, and named offence tallies. The
 * ratio (verified up / max(verified down, 1)) is a LOCAL service fact —
 * there is NO global ZCODE mint for bandwidth anywhere in this layer:
 * the book never writes the reward ledger, and earned score enters tier
 * resolution only as an input the caller reads from the reward ledger.
 *
 * PERSISTENCE CONVENTION (the package_reward discipline — durable wires
 * under <datadir>/zcode, NOT SQLite/AR):
 *
 *   <datadir>/zcode/service/events/<event-id-hex>   one fixed-size wire
 *                                                  per service fact
 *
 * Event kinds: upload-credit, download-credit, publish, offence,
 * no-credit. The event id is a domain-separated SHA3-256 over the
 * canonical wire, so redelivery is always a dedup no-op. Every write is
 * temp + fsync + atomic rename; the whole book is replayed (sorted by
 * event id) on every load, so a one-shot CLI and a node agree. Corrupt or
 * oversize wires are skipped, logged, and counted; over-bound directories
 * stop the scan and set the truncated flag (under-reporting is the safe
 * direction — it denies credit, never grants it).
 *
 * CREDIT DISCIPLINE (owner directive — peers NEVER earn credit for
 * announcements, unverified bytes, repeated copies of the same request,
 * bytes not requested, invalid chunks, or incomplete staging data):
 * credit_upload/credit_download require a distinct nonzero request id;
 * a request id already seen is a REPLAYED REQUEST — no credit, and the
 * result names it (the caller records the duplicate-request offence).
 * Only bytes the caller has ALREADY SHA3-verified may be offered — the
 * book trusts the caller's verification exactly as the store trusts its
 * own verify-before-store; everything else goes through
 * vcs_service_record_no_credit so the denial is visible in status.
 *
 * DETERMINISM: the caller passes civil day numbers everywhere. Window
 * arithmetic (ISO weeks) is pure. Sequence numbers inside offence /
 * no-credit event ids are the per-(key, kind) running count, so replaying
 * the same history yields the same ids. */

#ifndef ZCL_VCS_PACKAGE_SERVICE_H
#define ZCL_VCS_PACKAGE_SERVICE_H

#include "vcs/package_policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── bounds (frozen; every wire and account is bounded) ─────────────── */

#define VCS_SERVICE_MAX_EVENTS 65536u        /* durable event wires */
#define VCS_SERVICE_MAX_KEYS 4096u           /* distinct contributor keys */
#define VCS_SERVICE_MAX_REQUESTS 32768u      /* distinct request ids, book-wide */
#define VCS_SERVICE_MAX_PUBLISHES_PER_KEY 256u /* distinct releases / key */
#define VCS_SERVICE_DOWNLOAD_WEEKS 16u       /* weekly download buckets / key */
#define VCS_SERVICE_WIRE_BYTES 96u           /* fixed event wire size */

/* ── the book (rebuilt in memory from the durable wires) ────────────── */

struct vcs_service_book;

/* Load and replay <zcode_dir>/service. Missing directories are an empty
 * book, never an error. NULL only on allocation failure (logged). */
struct vcs_service_book *vcs_service_book_load(const char *zcode_dir);
void vcs_service_book_free(struct vcs_service_book *book);

size_t vcs_service_book_event_count(const struct vcs_service_book *book);
uint32_t vcs_service_book_corrupt_count(const struct vcs_service_book *book);
bool vcs_service_book_truncated(const struct vcs_service_book *book);
size_t vcs_service_book_key_count(const struct vcs_service_book *book);

/* Contributor keys in ascending (lexicographic) order — deterministic
 * enumeration for status surfaces. False when index is out of range. */
bool vcs_service_book_key_at(const struct vcs_service_book *book,
                             size_t index, uint8_t out[33]);

/* ── credit recording (verified, requested, non-duplicate bytes only) ── */

enum vcs_service_credit_result {
    VCS_SERVICE_CREDIT_OK = 0,   /* credited; the durable fact is written */
    VCS_SERVICE_CREDIT_DUPLICATE,/* identical event redelivered: dedup no-op */
    VCS_SERVICE_CREDIT_REPLAYED_REQUEST, /* request id already seen: NO
                                    credit (duplicate-request-replay) */
    VCS_SERVICE_CREDIT_BAD_INPUT,/* null/zero key, request id, or bytes */
    VCS_SERVICE_CREDIT_FULL,     /* a frozen bound was reached (no credit) */
    VCS_SERVICE_CREDIT_IO,       /* durable write failed (logged) */
    VCS_SERVICE_CREDIT_UNVERIFIED, /* dual-signed receipt failed verify */
    VCS_SERVICE_CREDIT_NOT_PARTY,  /* local key is neither receipt endpoint */
    VCS_SERVICE_CREDIT_WINDOW,     /* civil day outside the receipt window */
};

const char *vcs_service_credit_result_string(
    enum vcs_service_credit_result result);

/* Credit verified bytes this node SERVED to a contributor (upload side of
 * the local ratio). `request_id` is the 32-byte id of the DISTINCT chunk
 * request the bytes answered (the transport, slice 12, derives it from
 * the wire); `day` is the civil day. Only call AFTER the chunk passed
 * SHA3 verification — unverified bytes must go through
 * vcs_service_record_no_credit(VCS_POLICY_NO_CREDIT_UNVERIFIED, ...). */
enum vcs_service_credit_result vcs_service_credit_upload(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t request_id[32], uint64_t bytes, int64_t day);

/* Credit verified bytes this node RECEIVED from a contributor (download
 * side of the local ratio). Same request-id and verification discipline
 * as the upload side. */
enum vcs_service_credit_result vcs_service_credit_download(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t request_id[32], uint64_t bytes, int64_t day);

/* Admit one dual-signed verified-byte receipt (vcs/service_receipt.h) as
 * a LOCAL service fact. The receipt is advisory reputation, never
 * consensus: verify both signatures, require `local_pubkey` to be exactly
 * one endpoint, require `day` inside [day_start, day_end], then credit
 * the counterpart using the receipt id as the request id.
 *
 * Uploader local  -> credit_upload(downloader, receipt_id, bytes)
 * Downloader local -> credit_download(uploader, receipt_id, bytes)
 *
 * Replay of the same receipt is CREDIT_DUPLICATE. A third-party key,
 * a failed verify, or a day outside the window is refused by name and
 * writes nothing. */
enum vcs_service_credit_result vcs_service_book_accept_receipt(
    struct vcs_service_book *book, const uint8_t *wire, size_t len,
    const uint8_t local_pubkey[33], int64_t day);

/* ── publication / offence / no-credit recording ────────────────────── */

enum vcs_service_record_result {
    VCS_SERVICE_RECORD_OK = 0,   /* new durable fact */
    VCS_SERVICE_RECORD_DUPLICATE,/* idempotent redelivery / republish of the
                                    same release id: dedup no-op (republishing
                                    the same package earns no new event) */
    VCS_SERVICE_RECORD_BAD_INPUT,/* null/zero required field */
    VCS_SERVICE_RECORD_FULL,     /* a frozen bound was reached */
    VCS_SERVICE_RECORD_IO,       /* durable write failed (logged) */
};

const char *vcs_service_record_result_string(
    enum vcs_service_record_result result);

/* Record a publication event (one per DISTINCT release id per key; the
 * publish-frequency policy counts these per ISO week). Re-recording the
 * same release id is a dedup DUPLICATE — republishing the same package
 * never mints a second event. */
enum vcs_service_record_result vcs_service_record_publish(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t release_id[32], int64_t day);

/* Record one named offence (duplicate-request, unrequested-bytes,
 * invalid-chunk, announce-flood, request-flood). Offences accumulate per
 * key; the transport (slice 12) disconnects at
 * VCS_POLICY_OFFENCE_DISCONNECT_THRESHOLD. */
enum vcs_service_record_result vcs_service_record_offence(
    struct vcs_service_book *book, const uint8_t contributor[33],
    enum vcs_policy_offence kind, int64_t day);

/* Record bytes/events that earned NO credit (the frozen no-credit list:
 * announcement bytes, unverified bytes, duplicate request replays,
 * unrequested bytes, invalid chunks, incomplete staging data). Recording
 * makes the denial visible in status; it never moves either side of the
 * ratio. */
enum vcs_service_record_result vcs_service_record_no_credit(
    struct vcs_service_book *book, const uint8_t contributor[33],
    enum vcs_policy_no_credit kind, uint64_t bytes, int64_t day);

/* ── queries (the facts the policy decisions and status surfaces read) ── */

struct vcs_service_key_totals {
    bool present; /* the key has any recorded fact */
    uint64_t verified_bytes_uploaded;
    uint64_t verified_bytes_downloaded;
    uint64_t downloaded_this_week;   /* set when day >= 0 (ISO week of day) */
    uint64_t ratio_milli;            /* vcs_policy_ratio_milli */
    uint32_t publish_events;         /* distinct releases, all time */
    uint32_t publishes_this_week;    /* set when day >= 0 */
    uint32_t offences[VCS_POLICY_OFFENCE_COUNT];
    uint32_t offence_total;
    uint64_t no_credit_events[VCS_POLICY_NO_CREDIT_COUNT];
    uint64_t no_credit_bytes;
};

/* Snapshot one contributor's local facts. `day` selects the current ISO
 * week for the windowed fields; pass a negative day to skip windowed
 * fields (they report zero). False (logged) on NULL inputs; an unknown
 * key yields present:false, not an error. */
bool vcs_service_key_totals(const struct vcs_service_book *book,
                            const uint8_t contributor[33], int64_t day,
                            struct vcs_service_key_totals *out);

struct vcs_service_book_totals {
    uint64_t verified_bytes_uploaded;   /* summed over every key */
    uint64_t verified_bytes_downloaded;
    uint64_t offence_total;
    uint64_t no_credit_bytes;
};

void vcs_service_book_totals(const struct vcs_service_book *book,
                             struct vcs_service_book_totals *out);

#endif /* ZCL_VCS_PACKAGE_SERVICE_H */
