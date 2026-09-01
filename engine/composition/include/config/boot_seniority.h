/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_seniority — the ONE advisory influence path into peer selection, and
 * the address binding that finally makes it do something.
 *
 * Everything behind this header feeds exactly one function,
 * addrman_publish_reputation_weights() (net/addrman.h), which clamps every
 * row to [1.0, ADDRMAN_REPUTATION_MAX_MULT] and STRUCTURALLY CANNOT exclude a
 * peer. Nothing here drops, bans, refuses or deprioritises an address: the
 * worst a hostile input can do is fail to earn a boost and leave the address
 * on the unweighted baseline it would have had if this file did not exist.
 *
 * A WEIGHT IS NOT STORED ON AN ADDRESS. Each rebuild computes the whole
 * table and publishes it as one unit; an address that stops earning a boost
 * simply stops appearing in it, and absence reads exactly 1.0. There is no
 * "clear this address's weight" call to forget to make — which is precisely
 * the bug the per-address setter had: a relay boosted to 2.5x that later
 * recomputed to 1.0 hit the "no opinion, return early" branch and kept the
 * dead 2.5x for the life of the process, and the rebuild never enumerated
 * addrman, so an address that fell out of both input feeds was never even
 * revisited.
 *
 * WHERE THE ADDRESS BINDING COMES FROM, AND WHERE IT DOES NOT.
 *
 * It comes from SIGNED ENDPOINT RECORDS (vcs/zendp_swarm.h): a document the
 * identity signed with its own master key, saying "you can reach me at these
 * endpoints until this expiry", accepted only when that key resolves to an
 * ACTIVE anchor in the on-chain zid_identities projection. The claim is
 * therefore made by the key holder and vouched for by the chain, so seniority
 * cannot be borrowed by asserting somebody else's key.
 *
 * It does NOT come from the on-chain node directory (models/onion_directory.h),
 * and that is a deliberate refusal rather than an omission. That table has no
 * address column at all — it maps a v3 onion hostname to a registration
 * height — and its master_pubkey field is, in its own header's words, "NOT
 * verified here … binding a key on-chain is a claim". Letting an unverified
 * claim gate a signature-verified record would hand anyone a denial lever for
 * the price of one OP_RETURN: register the victim's hostname naming a
 * different key, and the victim's correctly signed record stops earning its
 * boost. An unverified field may not be given authority over a verified one,
 * so the directory table informs discovery ORDER (which it already does, via
 * db_onion_directory_list_active) and is kept out of the weighting.
 *
 * ROTATION IS HONOURED HERE. zid_seniority.h rate-limits the per-client
 * favourite set to one re-key per ZID_SENIORITY_EPOCH_BLOCKS; a table built
 * once at boot pins one favourite set for the life of the process, which is
 * the grinding-and-churn tradeoff that constant exists to balance. The
 * refresh worker below rebuilds when — and only when — the ranking epoch
 * rolls.
 *
 * THREADING. The rebuild reads node.db and takes cs_main, so it runs on its
 * OWN thread and never on the shared supervisor tick runner: a blocking read
 * parked behind a long fold commit on that thread freezes the sweep heartbeat
 * for every other child. The worker heartbeats itself
 * (period_secs == 0, deadline_secs > 0) and its progress policy is ARMED. */

#ifndef ZCL_CONFIG_BOOT_SENIORITY_H
#define ZCL_CONFIG_BOOT_SENIORITY_H

#include "net/addrman.h"
#include "storage/peers_projection.h"
#include "vcs/zendp_swarm.h"
#include "zid/zid_seniority.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── The address binding ───────────────────────────────────────────── */

/* One dialable address resolved to the relay identity that SIGNED for it.
 * `port` is the port the record advertised for this transport; 0 means the
 * record named none. */
struct boot_relay_binding {
    uint8_t  ip[16];
    uint16_t port;
    uint8_t  relay_id[32];   /* the record's ed25519 master public key */
};

/* A record may name a clearnet v4 and a clearnet v6 endpoint, so the table is
 * at most two rows per tracked identity. Onion endpoints are carried by the
 * record but produce NO binding: addrman holds no torv3 entries on this
 * build, so a torv3 row would be a lookup nothing could ever hit. */
#define BOOT_RELAY_BINDINGS_MAX (2u * (unsigned)ZENDP_DIR_MAX)

/* Flatten verified endpoint records into the binding table, ascending by
 * (ip, port) so a lookup is a binary search and two nodes holding the same
 * records build byte-comparable tables. Returns the number of rows written.
 *
 * Nothing is invented: a record with no clearnet endpoint contributes no row,
 * an all-zero address contributes no row (0.0.0.0 and :: reach nobody), and
 * an over-capacity input is truncated at `cap` rather than overflowing.
 * Records arrive already signature-checked and ACTIVE-anchored — this
 * function performs no verification of its own and must never be handed
 * unverified input. */
size_t boot_relay_bindings_build(const struct zendp_record_view *views,
                                 size_t n_views,
                                 struct boot_relay_binding *out, size_t cap);

/* Resolve one dialable address to its relay identity.
 *
 * Matches on ip[16] — addrman's own address identity, which does not include
 * the port (net_addr_eq) — and additionally refuses a match when BOTH sides
 * name a port and the ports differ. Returns false when the address has no
 * registration, which is a legitimate negative answer and NOT an error: an
 * unregistered peer keeps multiplier 1.0, never a penalty. */
bool boot_relay_binding_find(const struct boot_relay_binding *table, size_t n,
                             const uint8_t ip[16], uint16_t port,
                             uint8_t relay_id_out[32]);

/* ── The single weighting pass ─────────────────────────────────────── */

/* Upper bound on rows one rebuild can emit: the banked-reputation sweep is
 * capped at 4096 addresses and the directory sweep at one row per binding. */
#define BOOT_SENIORITY_ROWS_MAX (4096u + BOOT_RELAY_BINDINGS_MAX)

/* Everything one weighting pass needs. `seen` tracks which bindings the
 * reputation feed already covered so the directory sweep that follows cannot
 * emit a second row for the same address. Zero-initialise, then fill.
 *
 * `rows`/`rows_cap` are the table being built. A pass with no row array is
 * legal and computes nothing but the counters — that is how the arithmetic
 * is proven without an addrman. */
struct boot_seniority_pass {
    struct addr_man *am;
    const struct zid_seniority_weight *table;   /* sorted by relay_id */
    size_t table_n;
    const struct boot_relay_binding *bindings;  /* sorted by (ip, port) */
    size_t bindings_n;
    bool   seen[BOOT_RELAY_BINDINGS_MAX];
    struct addrman_weight_row *rows;   /* the table under construction */
    size_t rows_cap;
    size_t rows_n;
    size_t applied;      /* rows emitted (a weight above baseline) */
    size_t boosted;      /* of those, how many consumed a seniority boost */
    size_t dropped;      /* rows the capacity could not hold */
};

/* Weight ONE address: merge its banked bandwidth reputation with its on-chain
 * seniority into a single bounded value and emit at most one row for it.
 * `rep` may be NULL (no banked session). Fail-open throughout — any missing
 * input degrades to "no opinion", which emits NO row, which reads 1.0. */
void boot_seniority_weigh_address(struct boot_seniority_pass *pass,
                                  const uint8_t ip[16], uint16_t port,
                                  const struct peer_reputation *rep);

/* Weight every bound address the reputation feed did NOT already cover — a
 * senior relay this node has never dialled is exactly the one worth dialling,
 * and it has no session row to be found by. Returns how many were weighted. */
size_t boot_seniority_weigh_unseen_bindings(struct boot_seniority_pass *pass);

/* ── Rotation ──────────────────────────────────────────────────────── */

/* What the refresh worker must do on this poll. */
enum boot_seniority_action {
    BOOT_SENIORITY_IDLE = 0,  /* the ranking epoch has not rolled */
    BOOT_SENIORITY_REBUILD,   /* it has (or nothing has been applied yet) */
};

/* The rotation decision, as a pure function so it can be proven without a
 * clock, a chain or a thread. `applied_epoch` is what this node last
 * published (INT32_MIN before the first build, which always rebuilds).
 * *epoch_out receives the epoch containing `tip_height`.
 *
 * This is where ZID_SENIORITY_EPOCH_BLOCKS stops being decoration: a node
 * whose table is built once at boot pins one favourite set for the life of
 * the process, which is exactly the churn-versus-grinding tradeoff that
 * constant exists to balance. */
enum boot_seniority_action boot_seniority_next_action(int32_t tip_height,
                                                      int32_t applied_epoch,
                                                      int32_t *epoch_out);

/* ── Lifecycle ─────────────────────────────────────────────────────── */

/* Build the table for the current ranking epoch and seed addrman from it,
 * then register the supervised refresh child and spawn its worker. Called
 * once from app_log_bootstrap_sources(); idempotent. Never blocks boot and
 * never fails it. The worker is a long-running daemon: it exits on
 * thread_registry_shutdown_requested() and is swept by
 * thread_registry_join_all(), so there is no stop entry point to forget to
 * call. */
void boot_seniority_start(struct addr_man *am);

/* Rebuild the whole weight table for `epoch_height` and publish it to
 * addrman, replacing the previous epoch's table entirely. Every address that
 * earned a boost last epoch and does not earn one now is back at exactly 1.0
 * the moment this returns, because it is simply not in the new table.
 *
 * Both inputs are re-derived every time: the banked BANDWIDTH multiplier and
 * the on-chain SENIORITY multiplier are merged by zid_seniority_combine into
 * one value per address (see the top of this file for why they are never two
 * calls), so a bandwidth-only peer keeps its boost across a seniority epoch
 * roll and a seniority-only peer loses its when it leaves the ranking.
 *
 * True when the pass completed (including the legitimate "no anchored
 * identities" outcome, and including a publish withheld by degraded mode —
 * the node did look, and the previous table deliberately stands); false when
 * it could not run at all — no addrman, or no open node.db. A false return
 * must never be reported to the supervisor as idle: "I could not look" is
 * the state the stall detector exists to catch. */
bool boot_seniority_refresh_once(struct addr_man *am, int32_t epoch_height);

/* The ranking epoch this node has actually applied, or INT32_MIN before the
 * first successful rebuild. Lock-free; safe from any thread. */
int32_t boot_seniority_applied_epoch(void);

/* Completed rebuilds this process — the supervisor progress marker. */
uint64_t boot_seniority_rebuild_count(void);

#endif /* ZCL_CONFIG_BOOT_SENIORITY_H */
