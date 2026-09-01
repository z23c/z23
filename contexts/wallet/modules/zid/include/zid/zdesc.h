/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZDESC — the onion-service descriptor body of the sovereign identity
 * layer (docs/spec/sovereign-identity-layer.md, "A1 — Onion service
 * descriptors"). A service's introduction-point set becomes a SIGNED
 * DOCUMENT distributed as content, not a record handed to a directory
 * authority: the publisher signs, anyone can verify, and rotation is a
 * new seq and a new signature — no transaction, no fee, no naming CA.
 *
 * A descriptor is a zid_doc BODY with its own 4-byte tag "ZIDD", exactly
 * as the release record uses "ZIDR". The doc around it (version,
 * master_pubkey, seq, expiry, signature) is unchanged — the identity
 * layer already answers "who signed this, is it fresh, is it newer than
 * what I hold". This file answers only "what does the body say".
 *
 * Frozen body wire (a WIRE CONTRACT from the first publish):
 *
 *   "ZIDD"              4
 *   onion               62   the service's v3 hostname (fixed length)
 *   not_before          8    LE unix seconds; validity OPENS here
 *   intro_count         1    0 .. ZDESC_INTRO_MAX
 *   intro_count × {          94 bytes each
 *       onion           62   the introduction point's v3 hostname
 *       auth_key        32   its ed25519 introduction key
 *   }
 *
 * No length prefix on a hostname: the validity rule fixes a v3 onion at
 * exactly 62 bytes, so a length byte would be a second writable copy of
 * a constant. Likewise the body carries not_before ONLY — not_after is
 * zid_doc.expiry, already signed; storing it twice would be two copies
 * of one fact.
 *
 * SIZE, and why this is content rather than an OP_RETURN.
 * ZDESC_BODY_MAX is 827, under ZID_BODY_MAX (1024), so the signed doc
 * is at most 51 + 827 + 64 = 942 bytes — one swarm chunk with room to
 * spare. At the other end, a USABLE descriptor (one introduction point;
 * with none it names no way to reach the service) is already 284 bytes,
 * past the 223-byte OP_RETURN relay cap, and every additional
 * introduction point adds 94. So descriptors are carried as content by
 * the content-addressed swarm and the chain carries only the identity
 * anchor. Rotation is therefore free: a new seq and a new signature,
 * no transaction, no fee.
 *
 * ANTI-ENUMERATION. A descriptor is addressed by the BLINDED key for a
 * time period, never by the master key — see the period contract below.
 * Only someone who already knows the master key can derive the address
 * of the record, so an index of record keys is not a directory of
 * services. This is the Tor v3 blinded-pubkey pattern, and it is what
 * kills HSDir address harvesting.
 *
 * WHAT THIS FILE DOES NOT DO. It touches no store, no network, and no
 * chain: it is a pure codec (contexts/wallet/modules/zid is rank 10, below net and vcs).
 * Publishing and fetching live in contexts/commons/modules/vcs (vcs/zdesc_swarm.h). Whether
 * the signing key is chain-anchored is a question this layer cannot ask
 * and does not pretend to answer — zdesc_verify checks a signature
 * against a key the CALLER supplies. */

#ifndef ZCL_ZID_ZDESC_H
#define ZCL_ZID_ZDESC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zid_doc;

/* A Tor v3 hostname: 56 base32 chars + ".onion". */
#define ZDESC_ONION_LEN 62
#define ZDESC_INTRO_MAX 8
#define ZDESC_INTRO_WIRE (ZDESC_ONION_LEN + 32)
#define ZDESC_BODY_MIN (4 + ZDESC_ONION_LEN + 8 + 1)
#define ZDESC_BODY_MAX (ZDESC_BODY_MIN + ZDESC_INTRO_MAX * ZDESC_INTRO_WIRE)

struct zdesc_intro {
    char onion[ZDESC_ONION_LEN + 1];
    uint8_t auth_key[32];
};

struct zdesc {
    char onion[ZDESC_ONION_LEN + 1];
    uint64_t not_before;   /* unix seconds; descriptor invalid before */
    uint8_t intro_count;
    struct zdesc_intro intro[ZDESC_INTRO_MAX];
};

/* Exactly the rule enforced in core/modules/net (onion_hostname_valid,
 * core/modules/net/src/onion_service.c): 62 chars, ".onion" suffix, and the v3
 * base32 alphabet a-z2-7 for the leading 56. Reimplemented here rather
 * than shared because contexts/wallet/modules/zid is ranked BELOW core/modules/net and may not
 * include it (engine/composition/lib_module_order.def); the two copies are twins by
 * construction and test_zdesc pins this one against the same vectors.
 * A hostname that fails here is REJECTED, never sanitized. */
bool zdesc_onion_valid(const char *host);

/* Encode the body. Returns the encoded size, or 0 on error (NULL args,
 * bad hostname anywhere, intro_count over ZDESC_INTRO_MAX, undersized
 * buffer). */
size_t zdesc_encode_body(uint8_t *out, size_t out_len,
                         const struct zdesc *desc);

/* Bounds-strict decode: exact "ZIDD" tag, a length that matches the
 * declared intro_count EXACTLY (no trailing bytes), and every hostname
 * re-validated after the copy. */
bool zdesc_decode_body(struct zdesc *desc, const uint8_t *body,
                       uint16_t body_len);

/* Encode desc as the body and zid_doc_sign it. Refuses expiry <=
 * desc->not_before (a window that never opens is a publisher bug, not a
 * verifier's problem). */
bool zdesc_sign(struct zid_doc *doc, const struct zdesc *desc, uint64_t seq,
                uint64_t expiry, const uint8_t seed[32]);

/* zid_doc_verify (signature + version + expiry) against now_unix, then
 * decode the ZIDD body, then enforce now_unix >= not_before. desc_out
 * may be NULL to verify without decoding out.
 *
 * The key checked is doc->master_pubkey — whatever the doc CARRIES.
 * Deciding whether that key is the right one is the caller's job and
 * the chain-binding seam; see vcs/zdesc_swarm.h. */
bool zdesc_verify(const struct zid_doc *doc, struct zdesc *desc_out,
                  uint64_t now_unix);

/* ── The period contract (publisher and fetcher MUST agree) ─────────
 *
 * A PERIOD is a whole UTC day: floor(unix_seconds / 86400), i.e. days
 * since the epoch. Wall clock, not block height — contexts/wallet/modules/zid is rank 10
 * and has no chain access, and a zid_doc's expiry is already unix
 * seconds, so this uses the clock the format already trusts. 24h is
 * Tor v3's own rotation cadence.
 *
 * Publisher: stores under zdesc_record_key(pk, zdesc_period_at(now)).
 * Fetcher:   derives the SAME key from its own clock. Clocks differ, so
 *            a fetcher MUST also try zdesc_period_prev() of the current
 *            period on a miss — otherwise a publisher a few seconds the
 *            other side of midnight is unfindable for a day. That
 *            fallback is implemented in the fetch path (contexts/commons/modules/vcs), not
 *            left to callers to remember.
 *
 * Frozen by golden vector in tests/harness/src/test_zdesc.c: the vector
 * hashes a hand-built "ZIDB" ‖ pk ‖ period_le64 preimage, so it pins
 * the derivation rather than snapshotting whatever the code returned. */
#define ZDESC_PERIOD_SECONDS 86400u

uint64_t zdesc_period_at(uint64_t now_unix);
/* The period before `period`; period 0 has no predecessor and returns 0. */
uint64_t zdesc_period_prev(uint64_t period);

/* The record key a descriptor is addressed by: zid_blinded_key under a
 * name that says what it is for. Same bytes, same tag ("ZIDB"), forever. */
void zdesc_record_key(uint8_t out[32], const uint8_t master_pubkey[32],
                      uint64_t period);

#endif /* ZCL_ZID_ZDESC_H */
