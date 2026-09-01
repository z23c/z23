/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * authority_receipt — the reusable Law-7 privileged-transition idiom.
 *
 * The contract, stated once: a self-asserted artifact never authorizes a
 * privileged state change. Authority requires a receipt that a prior pass
 * derived INDEPENDENTLY and bound to {artifact digest, context anchor, the
 * EXACT running-binary image, an issuer/domain tag}, re-checked fail-closed at
 * use time through a datadir capability fd (pathnames are locators, never
 * authority).
 *
 * This header owns the transition-agnostic mechanics: the race-free running-
 * binary digest, the atomic keyed-file write, the exact-length dirfd read, and
 * a fixed canonical HEADER + verify skeleton future consumers (safe hotload,
 * signed off-chain contracts, deploy generation publish) bind onto. A consumer
 * with a rich typed payload (e.g. consensus_state_replay_receipt) folds its
 * fields into `detail_digest` and keeps its own field codec; the generic
 * contract binds that digest, so this header layout never changes.
 *
 * NOTE: engine/composition/src/consensus_state_replay_receipt.c is the original, still-live
 * instance of this idiom (the sovereign-cure ACTIVATE gate). It is intentionally
 * NOT rewired onto this primitive — its 344-byte payload + binding digest are
 * behaviorally frozen. This module generalizes the SHAPE so new privileged
 * transitions do not re-derive it by hand. */
#ifndef ZCL_UTIL_AUTHORITY_RECEIPT_H
#define ZCL_UTIL_AUTHORITY_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Idiom primitives (the three pieces any receipt consumer re-uses) ── */

/* SHA3-256 of the running executable image (/proc/self/exe), race-free direct
 * open (a path readlink reintroduces TOCTOU). false on any read/close error. */
bool authority_receipt_running_binary_digest(uint8_t out[32]);

/* Atomic keyed write under `datadir`: tmp -> fsync(file) -> rename -> fsync(dir).
 * Writes exactly `len` bytes to `<datadir>/<name>` (0600). On success copies the
 * final absolute path into final_out when non-NULL. Fail-closed bool. */
bool authority_receipt_write_atomic(const char *datadir, const char *name,
                                    const uint8_t *payload, size_t len,
                                    char *final_out, size_t final_cap);

/* Read EXACTLY `len` bytes of `<datadir_fd>/<name>` through the capability fd
 * (openat O_RDONLY|O_CLOEXEC|O_NOFOLLOW). Reads up to len+1 and returns true iff
 * precisely `len` bytes were present (a longer OR shorter file is rejected).
 * Does NOT interpret the bytes. Fail-closed bool. */
bool authority_receipt_read_fixed(int datadir_fd, const char *name,
                                  uint8_t *out, size_t len);

/* ── Canonical HEADER for NEW consumers (hot-swap / deploy / contracts) ── */

#define AUTHORITY_RECEIPT_SCHEMA_FIELD 48u
/* schema[48] + artifact[32] + anchor[32] + detail[32] + verifier[32] + digest[32] */
#define AUTHORITY_RECEIPT_HEADER_BYTES 208u

/* Pinned byte offsets so a consumer/verifier agree exactly; a hand-built raw
 * buffer (or a targeted tamper test) can index a field without guessing. */
#define AUTHORITY_RECEIPT_OFF_SCHEMA   0u
#define AUTHORITY_RECEIPT_OFF_ARTIFACT 48u
#define AUTHORITY_RECEIPT_OFF_ANCHOR   80u
#define AUTHORITY_RECEIPT_OFF_DETAIL   112u
#define AUTHORITY_RECEIPT_OFF_VERIFIER 144u
#define AUTHORITY_RECEIPT_OFF_RECEIPT  176u

struct authority_receipt_header {
    char    schema[AUTHORITY_RECEIPT_SCHEMA_FIELD]; /* NUL-terminated issuer tag */
    uint8_t artifact_digest[32];         /* WHAT is being authorized */
    uint8_t context_anchor[32];          /* WHERE it sits (chain anchor / epoch) */
    uint8_t detail_digest[32];           /* SHA3 of the independent derivation */
    uint8_t verifier_binary_digest[32];  /* the exact image that verified */
    uint8_t receipt_digest[32];          /* domain-bound over the 5 fields above */
};

/* Domain-separated binding over {schema,artifact,anchor,detail,verifier};
 * domain = header->schema followed by the literal "/binding". */
void authority_receipt_header_digest(const struct authority_receipt_header *h,
                                     uint8_t out[32]);

/* Serialize the header into the fixed AUTHORITY_RECEIPT_HEADER_BYTES layout at
 * the pinned offsets (memset 0, then the six fields). No integer fields, so no
 * endianness concern. */
void authority_receipt_header_serialize(
    const struct authority_receipt_header *h,
    uint8_t buf[AUTHORITY_RECEIPT_HEADER_BYTES]);

/* Parse a fixed buffer and verify its self-binding receipt_digest. Byte-level
 * tampering fails here. Returns false (fail-closed) on schema/self-binding
 * failure. */
bool authority_receipt_header_deserialize(
    const uint8_t buf[AUTHORITY_RECEIPT_HEADER_BYTES],
    struct authority_receipt_header *h);

/* Producer: caller has filled schema/artifact_digest/context_anchor/
 * detail_digest. Fills verifier_binary_digest (running image) + receipt_digest,
 * serializes the fixed header, writes it atomically under `datadir`/`name`. */
bool authority_receipt_header_seal_and_write(struct authority_receipt_header *h,
                                             const char *datadir,
                                             const char *name, char *final_out,
                                             size_t final_cap);

/* Consumer (use-time authority), fail-closed. Reads the fixed header through
 * datadir_fd, re-verifies its self-binding receipt_digest, requires the running
 * binary to equal verifier_binary_digest, then requires schema/artifact/anchor/
 * detail to equal the caller's expected values. Any missing/tampered/foreign/
 * different-binary receipt -> false (the transition stays contained). */
bool authority_receipt_header_authority_available(
    int datadir_fd, const char *name, const char *expect_schema,
    const uint8_t expect_artifact[32], const uint8_t expect_context_anchor[32],
    const uint8_t expect_detail_digest[32]);

#endif /* ZCL_UTIL_AUTHORITY_RECEIPT_H */
