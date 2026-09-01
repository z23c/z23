/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Strong one-field wrapper types for the sync/artifact surface.
 *
 * Purpose: give the four duplicated raw `uint8_t[32]` hash/root clusters and
 * the scalar height/byte/index/peer counters a distinct COMPILE-TIME identity
 * so a chunk_root can never be passed where a whole_sha3 is wanted, without
 * changing a single wire byte. Every 32-byte wrapper is `sizeof == 32` and
 * layout-identical to a bare `uint8_t[32]` (a `_Static_assert` proves it), so
 * `memcpy(dst.bytes, src, 32)` at a wire boundary stays valid — the wrappers
 * are an ADDITIVE alias layer, not a re-encode.
 *
 * Included as "core/zcl_ids.h" (the same token as core/amount.h et al., via
 * -Icore/modules/core/include). It is deliberately NOT under the top-level core/ tree:
 * that directory is consensus-sealed (make check-core-seal), and these pure
 * wrapper types are not consensus code. Header-only: every helper is
 * `static inline`, so there is no external linkage and no LTO symbol.
 * Pure/deterministic: no clock, RNG, or IO. Mirrors the core/uint256.h house
 * style. */

#ifndef ZCL_CORE_ZCL_IDS_H
#define ZCL_CORE_ZCL_IDS_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ── 32-byte content-digest / root / work wrappers ──────────────────── */

/* A block hash (double-SHA256 header id). */
struct zcl_block_hash { uint8_t bytes[32]; };
/* A SHA3-256 content digest (whole-file / generic). */
struct zcl_sha3_digest { uint8_t bytes[32]; };
/* A transparent UTXO-set root. */
struct zcl_utxo_root { uint8_t bytes[32]; };
/* An MMB (Merkle Mountain Belt) root. */
struct zcl_mmb_root { uint8_t bytes[32]; };
/* The SHA3 fold over an artifact's per-chunk digests — its content identity. */
struct zcl_chunk_root { uint8_t bytes[32]; };
/* A ROM artifact identity (today == its chunk_root). */
struct zcl_artifact_id { uint8_t bytes[32]; };
/* Cumulative chain work, big-endian 256-bit. */
struct zcl_chainwork_be256 { uint8_t bytes[32]; };

/* ── Scalar counters ────────────────────────────────────────────────── */

/* A block height. Signed so the -1 "none/unknown" sentinel is representable,
 * matching the node's pervasive `int` height convention. */
struct zcl_height { int32_t value; };
/* A byte count / size. */
struct zcl_byte_count { uint64_t value; };
/* A zero-based chunk index within an artifact. */
struct zcl_chunk_index { uint32_t value; };
/* An opaque peer identity. */
struct zcl_peer_id { uint64_t value; };
/* A snapshot/artifact fast-sync SESSION identity. Deliberately DISTINCT from a
 * peer id: one sync session is bound to a peer at a point in time, but a peer
 * can be re-selected across sessions and a session precedes/outlives any single
 * peer binding — so the two must never be confused. `0` is the "no active
 * session" sentinel (the kernel's stale-session guard treats a zero state
 * session as "not yet gating"). Minted owner-side via zcl_sync_session_id_mint;
 * not a consensus value and not a wire-protocol field. */
struct zcl_sync_session_id { uint64_t value; };

/* ── Layout guards: wire-compat is the whole point ──────────────────── */

_Static_assert(sizeof(struct zcl_block_hash) == 32, "zcl_block_hash must be 32 bytes");
_Static_assert(sizeof(struct zcl_sha3_digest) == 32, "zcl_sha3_digest must be 32 bytes");
_Static_assert(sizeof(struct zcl_utxo_root) == 32, "zcl_utxo_root must be 32 bytes");
_Static_assert(sizeof(struct zcl_mmb_root) == 32, "zcl_mmb_root must be 32 bytes");
_Static_assert(sizeof(struct zcl_chunk_root) == 32, "zcl_chunk_root must be 32 bytes");
_Static_assert(sizeof(struct zcl_artifact_id) == 32, "zcl_artifact_id must be 32 bytes");
_Static_assert(sizeof(struct zcl_chainwork_be256) == 32, "zcl_chainwork_be256 must be 32 bytes");
_Static_assert(sizeof(struct zcl_height) == sizeof(int32_t), "zcl_height must wrap int32_t");
_Static_assert(sizeof(struct zcl_byte_count) == sizeof(uint64_t), "zcl_byte_count must wrap uint64_t");
_Static_assert(sizeof(struct zcl_chunk_index) == sizeof(uint32_t), "zcl_chunk_index must wrap uint32_t");
_Static_assert(sizeof(struct zcl_peer_id) == sizeof(uint64_t), "zcl_peer_id must wrap uint64_t");
_Static_assert(sizeof(struct zcl_sync_session_id) == sizeof(uint64_t), "zcl_sync_session_id must wrap uint64_t");

/* ── eq / copy helpers (static inline, no external linkage) ──────────── */

/* Generate the identical byte-equality + copy pair for each 32-byte wrapper.
 * `copy` is a byte copy of exactly 32 bytes (keeps the memcpy(…,32) contract
 * the wire boundary relies on). */
#define ZCL_ID_DEFINE_HASH_HELPERS(T)                                          \
    static inline bool T##_eq(const struct T *a, const struct T *b)            \
    { return memcmp(a->bytes, b->bytes, 32) == 0; }                            \
    static inline void T##_copy(struct T *dst, const struct T *src)           \
    { memcpy(dst->bytes, src->bytes, 32); }

ZCL_ID_DEFINE_HASH_HELPERS(zcl_block_hash)
ZCL_ID_DEFINE_HASH_HELPERS(zcl_sha3_digest)
ZCL_ID_DEFINE_HASH_HELPERS(zcl_utxo_root)
ZCL_ID_DEFINE_HASH_HELPERS(zcl_mmb_root)
ZCL_ID_DEFINE_HASH_HELPERS(zcl_chunk_root)
ZCL_ID_DEFINE_HASH_HELPERS(zcl_artifact_id)
ZCL_ID_DEFINE_HASH_HELPERS(zcl_chainwork_be256)

#undef ZCL_ID_DEFINE_HASH_HELPERS

/* Generate the value-equality + copy pair for each scalar wrapper. */
#define ZCL_ID_DEFINE_SCALAR_HELPERS(T)                                        \
    static inline bool T##_eq(struct T a, struct T b)                          \
    { return a.value == b.value; }                                             \
    static inline void T##_copy(struct T *dst, struct T src)                   \
    { dst->value = src.value; }

ZCL_ID_DEFINE_SCALAR_HELPERS(zcl_height)
ZCL_ID_DEFINE_SCALAR_HELPERS(zcl_byte_count)
ZCL_ID_DEFINE_SCALAR_HELPERS(zcl_chunk_index)
ZCL_ID_DEFINE_SCALAR_HELPERS(zcl_peer_id)
ZCL_ID_DEFINE_SCALAR_HELPERS(zcl_sync_session_id)

#undef ZCL_ID_DEFINE_SCALAR_HELPERS

/* ── Session-id minting (owner-side, pure) ──────────────────────────────
 *
 * The session owner (the impure sync shell) draws a monotonic `tick` from a
 * caller-owned counter and mints a session id from it. The mint is pure — it
 * takes the tick by value and touches no clock/RNG/global — so the OWNER, not
 * the kernel, decides when a new session begins. Two guarantees the "0 == no
 * session" sentinel relies on:
 *   - the result is ALWAYS nonzero (a live session id is never the sentinel);
 *   - distinct ticks below 2^63 mint distinct ids (`(tick<<1)|1` is injective
 *     over that range), so a stale session can never alias a fresh one. */
static inline struct zcl_sync_session_id zcl_sync_session_id_mint(uint64_t tick)
{
    return (struct zcl_sync_session_id){ .value = (tick << 1) | 1u };
}

/* True iff this id is the "no active session" sentinel. */
static inline bool zcl_sync_session_id_is_none(struct zcl_sync_session_id s)
{
    return s.value == 0;
}

#endif /* ZCL_CORE_ZCL_IDS_H */
