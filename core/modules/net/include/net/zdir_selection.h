/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZDIR selection — per-client relay preference derivation.
 *
 * THE PROBLEM THIS SOLVES. Tor picks guards per-client at random and
 * remembers them; the *directory* that lists the candidates is signed by ~10
 * hardcoded authorities. Replacing that committee with a chain-anchored
 * directory is only an improvement if the SELECTION stays per-client. A
 * single deterministic guard set that every node computes identically would
 * be an anonymity monoculture: one target serves every client, and knowing
 * the block hash tells you every node's preferred peers. So the derivation
 * mixes a chain value nobody can grind cheaply with a node-local secret:
 *
 *     seed = SHA3-256(0x01 ‖ "ZDIR" ‖ block_hash ‖ client_key)
 *
 * Reproducible for one client (both inputs are stable and locally known),
 * different for every client (client_key never leaves the node), and not
 * steerable by an attacker (block_hash costs a block to move).
 *
 * ADVISORY, NEVER EXCLUSIVE. Nothing in this header can express "do not
 * dial X". The only output that touches peer selection is a weight in
 * [ZDIR_WEIGHT_NEUTRAL_MILLI, ZDIR_WEIGHT_MAX_MILLI] = [1000, 4000], i.e. a
 * [1.0, 4.0] multiplier for addrman_publish_reputation_weights(), which itself
 * clamps to >= 1.0 and only ever RAISES a dial chance. A candidate the
 * directory dislikes, a candidate it has never heard of, and a candidate
 * excluded by the per-owner cap all receive exactly
 * ZDIR_WEIGHT_NEUTRAL_MILLI — byte-identical behaviour to a node with no
 * directory at all. Hardcoded seeds, addr gossip, and anchors.dat remain
 * independent discovery roots that this module cannot see or suppress. The
 * bound is a property of the type, not of caller discipline.
 *
 * PURITY. Every function here is a pure, total function of its arguments:
 * no clock read, no allocation, no I/O, no globals, no locks. That is what
 * makes "reproducible" a testable claim (see the frozen golden vectors in
 * tests/harness/src/test_zdir_selection.c) rather than a description.
 *
 * DOMAIN SEPARATION. Four sub-domains under one 4-byte uppercase
 * lokad-style tag "ZDIR", matching the identity layer's ZIDB/ZIDL/ZIDD
 * convention (zid.h) and the on-chain ZNAM/ZANC lokads: a leading
 * discriminant byte then the tag, so a digest minted here can never be
 * replayed as another protocol's digest and the four stages can never
 * collide with each other.
 *
 * Spec: docs/spec/sovereign-identity-layer.md §A3 (ZDIR relay directory).
 */

#ifndef ZCL_NET_ZDIR_SELECTION_H
#define ZCL_NET_ZDIR_SELECTION_H

#include "net/anchor_peers.h"
#include "net/netaddr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 4-byte uppercase lokad-style domain tag (see header comment). */
#define ZDIR_SELECTION_TAG      "ZDIR"
#define ZDIR_SELECTION_TAG_LEN  4

/* Sub-domain discriminants. Prefixed to the tag exactly as zid.h's tree
 * does (0x00 ‖ "ZIDL" ‖ …). Never renumber: these are frozen wire bytes. */
#define ZDIR_DOMAIN_CLIENT_KEY  0x00
#define ZDIR_DOMAIN_SEED        0x01
#define ZDIR_DOMAIN_CANDIDATE   0x02
#define ZDIR_DOMAIN_ENDPOINT    0x03

/* Preferred-slot cap. Deliberately ANCHOR_PEERS_MAX (net/anchor_peers.h),
 * which is itself MAX_OUTBOUND_CONNECTIONS: preferring more relays than the
 * node has outbound slots is dead weight, and reusing the existing anchor
 * cap keeps this from becoming a parallel notion of "how many peers matter".
 * There is no separate guard/entry store — anchors.dat is the persistence
 * mechanism and this module only ORDERS. */
#define ZDIR_PREFERRED_MAX      ANCHOR_PEERS_MAX

/* Bound on one selection call. Caps the O(want × count) hashing below so a
 * gossip flood cannot turn selection into a stall. */
#define ZDIR_CANDIDATES_MAX     4096u

/* Weight range, in thousandths of an addrman dial-chance multiplier.
 * NEUTRAL == "no opinion" == today's behaviour. There is no value below
 * NEUTRAL, by construction. */
#define ZDIR_WEIGHT_NEUTRAL_MILLI  1000u
#define ZDIR_WEIGHT_MAX_MILLI      4000u

/* One directory candidate. `id` and `owner_id` are opaque 32-byte digests
 * so this module never needs to know whether a relay is identified by an
 * endpoint, a master pubkey, or a ZNAM record — the caller commits to one
 * and stays consistent (zdir_endpoint_id() is the endpoint flavour). */
struct zdir_candidate {
    uint8_t  id[32];               /* stable relay identity digest */
    uint8_t  owner_id[32];         /* owner digest — feeds the per-owner cap */
    uint32_t registration_height;  /* seniority origin (chain height) */
    uint8_t  bandwidth_score;      /* 0..255 advisory measurement; 0 = unmeasured */
};

/* Selection inputs. Everything the result depends on is in here — that is
 * the purity contract. */
struct zdir_params {
    uint8_t  block_hash[32];           /* the agreed-on chain value */
    uint8_t  client_key[32];           /* this node's secret (zdir_client_key) */
    uint32_t chain_height;             /* for seniority age */
    uint32_t seniority_full_blocks;    /* age at which seniority saturates;
                                        * 0 = seniority ignored (full credit) */
    uint32_t per_owner_cap;            /* max preferred slots per owner_id;
                                        * 0 is treated as 1 */
    uint32_t want;                     /* preferred slots; clamped to
                                        * ZDIR_PREFERRED_MAX */
};

/* Selection output. `preferred` holds candidate INDICES into the caller's
 * array, best first; `score` is the matching per-client digest (kept so a
 * test or an operator dump can re-derive the ordering by hand). */
struct zdir_selection {
    uint8_t  seed[32];
    uint32_t preferred[ZDIR_PREFERRED_MAX];
    uint8_t  score[ZDIR_PREFERRED_MAX][32];
    uint32_t preferred_count;
};

/* ── Derivation primitives ──────────────────────────────────────────── */

/* client_key = SHA3-256(0x00 ‖ "ZDIR" ‖ node_secret).
 *
 * `node_secret` is the node's addrman salt (struct addr_man.nKey — 32 bytes
 * from GetRandBytes at first init, serialized into peers.dat and reloaded
 * verbatim on every boot). It has exactly the two properties the selection
 * needs: STABLE across restarts (it lives in peers.dat, so the preference
 * set does not reshuffle every boot, which is what makes a guard set worth
 * having at all) and UNLEARNABLE by a remote peer (it is only ever used as
 * an internal hash salt for addrman bucket placement and is never placed in
 * any P2P message, descriptor, or on-chain record).
 *
 * The one-way step is not decoration: it keeps the two uses independent, so
 * an adversary who somehow inferred selection behaviour still cannot recover
 * the addrman bucket salt (and vice versa). Callers must pass nKey, not a
 * fresh random per boot. */
bool zdir_client_key(uint8_t out[32], const uint8_t node_secret[32]);

/* THE derivation: seed = SHA3-256(0x01 ‖ "ZDIR" ‖ block_hash ‖ client_key).
 * Advancing block_hash rotates the whole preference ordering; changing
 * client_key by one bit reorders it independently of every other node. */
bool zdir_epoch_seed(uint8_t out[32], const uint8_t block_hash[32],
                     const uint8_t client_key[32]);

/* score = SHA3-256(0x02 ‖ "ZDIR" ‖ seed ‖ candidate_id) — the per-client
 * rendezvous digest a candidate is ranked by. */
bool zdir_candidate_score(uint8_t out[32], const uint8_t seed[32],
                          const uint8_t candidate_id[32]);

/* Endpoint flavour of a candidate id:
 * SHA3-256(0x03 ‖ "ZDIR" ‖ ip[16] ‖ torv3[32] ‖ has_torv3:1 ‖ port LE16).
 * Covers the onion bytes so an onion relay and an IPv6 relay that happen to
 * share the ip[16] field can never collide. */
bool zdir_endpoint_id(uint8_t out[32], const struct net_addr *addr,
                      uint16_t port);

/* ── Weighting ──────────────────────────────────────────────────────── */

/* Integer, exact, allocation-free weight in [1000, 4000].
 *
 * Combines a measured bandwidth score with seniority (spec §A3: "10,000
 * freshly-registered relays buy ~zero selection weight"): a relay younger
 * than `seniority_full_blocks` earns a proportional fraction of whatever its
 * bandwidth score would otherwise be worth, so Sybil registration is cheap
 * but buys nothing until it has aged. Deliberately integer arithmetic — the
 * golden vectors would be fragile if this returned a double. */
uint16_t zdir_weight_milli(uint8_t bandwidth_score, uint32_t age_blocks,
                           uint32_t seniority_full_blocks);

/* Convert to the addrman dial-chance multiplier. Clamped into
 * [1.0, ADDRMAN_REPUTATION_MAX_MULT]; the return value can never be < 1.0,
 * so feeding it to addrman_publish_reputation_weights() cannot lower any peer's
 * chance and cannot exclude a peer. */
double zdir_weight_multiplier(uint16_t weight_milli);

/* ── Selection ──────────────────────────────────────────────────────── */

/* Pure, total selection.
 *
 *   params           inputs; `want` is clamped to ZDIR_PREFERRED_MAX
 *   candidates       caller array, `count` entries (0 is valid,
 *                    > ZDIR_CANDIDATES_MAX is rejected)
 *   weight_milli_out optional; when non-NULL, receives `count` entries.
 *                    Every entry is >= ZDIR_WEIGHT_NEUTRAL_MILLI. Preferred
 *                    candidates get their earned weight, everyone else gets
 *                    exactly NEUTRAL — the non-exclusion property, expressed
 *                    in the type rather than trusted to the caller.
 *   out              seed + ordered preferred indices + their score digests
 *
 * Ranking is weighted rendezvous: candidate i sorts by score_i / weight_i
 * (compared cross-multiplied in 64-bit integers — no floating point, no
 * platform drift), ties broken by the full 32-byte score digest, then by id.
 * A total order, so the result is invariant under permutation of the input
 * array. Owners are capped at params->per_owner_cap preferred slots.
 *
 * Cost: at most `want` × `count` SHA3-256 calls over 69 bytes each, no
 * allocation. Returns false (logged) only on NULL args or count overflow. */
bool zdir_select(const struct zdir_params *params,
                 const struct zdir_candidate *candidates, size_t count,
                 uint16_t *weight_milli_out, struct zdir_selection *out);

/* ── anchors.dat adapter ────────────────────────────────────────────── */

/* Build candidates from the existing anchor set (net/anchor_peers.h) rather
 * than introducing a second peer store. Each anchor becomes its own owner
 * (an anchor is a peer we personally proved healthy, not a directory claim),
 * registration_height comes from the anchor's last_height, and
 * bandwidth_score is 0 — anchors carry no directory measurement, so their
 * weights all land on NEUTRAL and the ordering is purely per-client. Writes
 * at most out_cap entries; *out_count receives how many. */
bool zdir_candidates_from_anchors(const struct anchor_peer_set *set,
                                  struct zdir_candidate *out, size_t out_cap,
                                  size_t *out_count);

#endif /* ZCL_NET_ZDIR_SELECTION_H */
