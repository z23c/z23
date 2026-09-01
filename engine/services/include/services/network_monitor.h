/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_monitor — the node's "eyes on the game". The node is always trying
 * to be on the best (highest-work valid) zclassic chain; it cannot play a game
 * it cannot see, so a supervised sampler continuously observes every reachable
 * peer's advertised chain (best height, learnable tip hash, version, latency),
 * retains that history (peer_chain_observations model), and folds the latest
 * per-peer sample into a CONSENSUS VIEW: the modal tip, the max advertised
 * height, fork clusters (peers grouped by tip hash at one height), and OUR
 * delta from the best advertised chain.
 *
 * OBSERVATIONAL ONLY. This never changes chain selection — find_most_work_chain
 * stays authoritative. It adds no P2P message types (peer heights arrive on
 * existing handshake/header paths). Its value is redundant, always-loud
 * detection of "are we falling behind / is there a fork / are we partitioned".
 */

#ifndef ZCL_SERVICES_NETWORK_MONITOR_H
#define ZCL_SERVICES_NETWORK_MONITOR_H

#include "models/peer_chain_observation.h"
#include "util/result.h"
#include <stdbool.h>
#include <stdint.h>

struct node_db;
struct json_value;

enum {
    NM_MAX_PEERS = 256,          /* bounded per-sample peer cap */
    NM_MAX_FORK_CLUSTERS = 16,   /* bounded distinct (height,tip_hash) clusters */
    NM_MAX_HEADER_VOTES = 256    /* bounded peer_id -> latest (height,hash) map */
};

/* Minimum peers agreeing on each of two distinct tip hashes at the same height
 * before it is called a fork (not one lagging/lying peer). */
#define NM_FORK_MIN_CLUSTER 2

struct network_fork_cluster {
    int64_t height;
    char tip_hash[PEER_OBS_TIP_HEX + 1];
    int peer_count;
};

/* A folded snapshot of what the reachable network says the chain is. */
struct network_consensus_view {
    bool ready;                 /* false until the first sample completes */
    int64_t computed_at;        /* unix secs of this fold */
    int num_peers;              /* peers in the sample */
    int peers_with_height;      /* peers advertising a valid best height */
    int64_t modal_height;       /* most common advertised best height (-1 none) */
    int modal_height_count;     /* peers at modal_height */
    int64_t max_height;         /* max advertised best height (-1 none) */
    int64_t our_height;         /* our active-chain height */
    int64_t delta;              /* max_height - our_height (0 if unknown) */

    int num_clusters;           /* distinct (height,tip_hash) clusters observed */
    struct network_fork_cluster clusters[NM_MAX_FORK_CLUSTERS];

    bool fork_detected;         /* two clusters at one height, each >= min size */
    int64_t fork_height;        /* height of the detected fork (-1 none) */
    char fork_hash_a[PEER_OBS_TIP_HEX + 1];
    char fork_hash_b[PEER_OBS_TIP_HEX + 1];
    int fork_count_a;
    int fork_count_b;
};

/* ── Pure fold (unit-testable with synthetic observations) ──────────────
 * Compute the consensus view from an array of per-peer observations (one per
 * peer — the latest sample). our_height is our active-chain height (-1 if
 * unknown). Deterministic; no clock/IO except stamping computed_at from the
 * caller-independent `now_unix`. */
void network_monitor_compute_view(const struct db_peer_chain_observation *obs,
                                  int n, int64_t our_height, int64_t now_unix,
                                  struct network_consensus_view *out);

/* ── Partition (netsplit) detection ─────────────────────────────────────
 *
 * docs/spec/sovereign-identity-layer.md names three signals that together
 * mean "we may be on the wrong side of a network split":
 *
 *   1. peer tip disagreement at the same-or-greater height,
 *   2. block-arrival rate divergence vs difficulty (the minority-side tell),
 *   3. tip staleness beyond expected variance.
 *
 * (3) already exists in five places as a fixed block-time threshold and is
 * REUSED here (see NM_TIP_STALE_SECS), not rebuilt. (1) and (2) are new.
 *
 * (1) is not the same thing as `fork_detected` above. `fork_detected` is a
 * peer-vs-peer observation: two clusters of peers disagree with each other,
 * and OUR tip is nowhere in the fold. The partition fold injects our own
 * (height, tip hash) as a synthetic observation, so it can see the case
 * `fork_detected` is structurally blind to: every peer agrees on hash X at
 * our height and we hold Y.
 *
 * Neither is it the same thing as the `net_partition_suspected` condition
 * (engine/conditions/src/net_partition_suspected.c), which fires on peer-count
 * collapse or on being frozen-behind. That one asks "can we still see the
 * network?"; this one asks "we can see it fine — is it telling us we are on
 * a different chain?".
 *
 * NO SINGLE SOURCE DECIDES. Modelled on core/modules/net/include/net/header_corroboration.h,
 * which holds a deep best-header switch until >= 2 DISTINCT ADDRESS GROUPS
 * vouch for the branch (onion and clearnet carry distinct group keys and so
 * count as distinct). Here:
 *   - the peer signal requires >= NM_NETSPLIT_MIN_RIVAL_GROUPS distinct
 *     address groups AND >= NM_NETSPLIT_MIN_RIVAL_PEERS peers behind the
 *     rival tip, so one peer — or one address group running many peers —
 *     can never raise it;
 *   - the composite verdict additionally requires a LOCAL, peer-independent
 *     corroborator (signal 2 or 3). Peer testimony alone is never enough.
 *
 * Observational only, exactly like the rest of this service: nothing here
 * changes chain selection.
 */

/* Distinct address groups / peers required behind a rival tip before peer
 * testimony counts at all. Mirrors header_corroboration's >= 2 distinct
 * groups rule. */
#define NM_NETSPLIT_MIN_RIVAL_GROUPS 2
#define NM_NETSPLIT_MIN_RIVAL_PEERS  2

/* Block-arrival window (signal 2). Below MIN_WINDOW_BLOCKS the fold refuses
 * to judge: Poisson variance on a short window is larger than the effect.
 * At 12 blocks the standard error of the mean interval is ~29%, so the
 * 0.40x floor below sits ~5 sigma out from normal variance. */
#define NM_ARRIVAL_MIN_WINDOW_BLOCKS 12
#define NM_ARRIVAL_MAX_WINDOW_BLOCKS 48

/* Implied network hashrate, in thousandths of the hashrate the window's
 * opening difficulty was calibrated for. 1000 == exactly on calibration.
 * Below this floor the chain we are following is being mined by a small
 * fraction of the hashpower its own difficulty was set by — the classic
 * minority-side-of-a-split signature. */
#define NM_ARRIVAL_LOW_RATIO_MILLI 400

/* Tip staleness (signal 3): the SAME 600 s block-time threshold
 * engine/services/src/node_health_service.c:315 uses for node_health_snapshot
 * .tip_stale. Reused deliberately — one number, not a sixth copy. */
#define NM_TIP_STALE_SECS 600

/* Address-group key: hex of net_addr_get_group() output (NET_ADDR_GROUP_MAX
 * bytes), or any caller-chosen opaque string in tests. */
enum { NM_GROUP_KEY_MAX = 31 };
typedef char nm_group_key_t[NM_GROUP_KEY_MAX + 1];

/* One block of the arrival-rate window, OLDEST FIRST. */
struct nm_arrival_sample {
    int64_t  height;
    int64_t  time_unix;   /* block header nTime */
    uint32_t nbits;       /* compact difficulty target */
};

struct network_arrival_rate {
    bool     ready;                        /* enough blocks to judge at all */
    int      window_blocks;
    int64_t  span_secs;                    /* newest.time - oldest.time */
    int64_t  observed_interval_milli;      /* mean seconds x1000 per block */
    int64_t  expected_interval_milli;      /* target spacing x1000 */
    int64_t  difficulty_ratio_milli;       /* mean(window) / oldest, x1000 */
    int64_t  implied_hashrate_ratio_milli; /* 1000 == calibrated hashrate */
    bool     rate_below_floor;             /* signal 2 firing */
};

struct network_partition_view {
    bool     ready;              /* false until the first partition fold ran */
    int64_t  computed_at;

    /* signal 1 — peer tip disagreement, our own tip injected */
    bool     peer_tip_disagreement;
    int64_t  at_height;          /* height the disagreement is measured at */
    char     our_tip_hash[PEER_OBS_TIP_HEX + 1];
    char     rival_tip_hash[PEER_OBS_TIP_HEX + 1];
    int      rival_peers;        /* peers holding rival_tip_hash at at_height */
    int      rival_groups;       /* DISTINCT address groups among those peers */
    int      agreeing_peers;     /* peers holding OUR hash at at_height */
    int      agreeing_groups;    /* distinct address groups among those */
    int      peers_considered;   /* peers at at_height with a usable hash */
    int      peers_ahead;        /* peers above at_height — see the note below */

    /* signal 2 — block arrival rate vs nBits-implied difficulty */
    struct network_arrival_rate arrival;

    /* signal 3 — tip staleness (reused threshold) */
    bool     tip_stale;
    int64_t  tip_age_secs;

    int      signals_firing;     /* 0..3 */
    bool     netsplit_suspected; /* the SUSPECTED_NETSPLIT verdict */
    /* AUDITED for silent truncation: no zcl_text_fit guard needed. All four
     * writers (network_monitor_netsplit.c) use fixed literals with %.16s-bounded
     * hashes; the longest, SUSPECTED_NETSPLIT, measures 212 bytes at worst-case
     * arguments, leaving 44 bytes of margin. Re-measure if a writer grows. */
    char     reason[256];
};

/* ── Pure folds (unit-testable; no clock, no IO, no globals) ────────────
 *
 * Signal 1. Folds peers at `our_height` into (tip hash -> peers, distinct
 * address groups), with our own tip injected as a synthetic observation, and
 * fills the signal-1 fields of *out. `group_keys` is a parallel array of
 * per-peer address-group keys (obs[i] <-> group_keys[i]); pass NULL to fall
 * back to the peer's addr string, and an empty key falls back the same way.
 * Peers with no learnable tip hash, and a missing or malformed `our_tip_hash`,
 * are excluded (the fold then reports nothing rather than guessing).
 *
 * ONLY peers at EXACTLY `our_height` vote. A lagging peer trivially holds a
 * different tip and proves nothing; a peer strictly AHEAD of us also holds a
 * different tip, and a tip hash alone cannot say whether its chain descends
 * from ours or from a rival branch — so those are counted in `peers_ahead`
 * for context and deliberately do not vote. The case this closes is exactly
 * the one the peer-vs-peer `fork_detected` fold is structurally blind to:
 * every peer agrees on hash X at our height and we hold Y.
 *
 * Does NOT touch the other signals or the verdict. */
void network_monitor_fold_tip_disagreement(
    const struct db_peer_chain_observation *obs, int n,
    const nm_group_key_t *group_keys,
    int64_t our_height, const char *our_tip_hash,
    struct network_partition_view *out);

/* Signal 2. `win` is the arrival window OLDEST FIRST, `target_spacing_secs`
 * the consensus target block spacing at the tip (150 s on ZClassic mainnet).
 * Implied hashrate is proportional to difficulty / interval, so
 *
 *   implied_ratio = (mean_difficulty / opening_difficulty)
 *                 * (target_spacing / observed_interval)
 *
 * is 1.0 when the chain is arriving exactly as its own difficulty predicts,
 * and collapses toward 0 when we are following a chain that lost most of the
 * hashpower its difficulty was calibrated against. Refuses to judge
 * (ready=false) on a short window, a non-positive span, non-monotonic
 * timestamps, or a zero opening difficulty. */
void network_monitor_fold_arrival_rate(const struct nm_arrival_sample *win,
                                       int win_n, int64_t target_spacing_secs,
                                       struct network_arrival_rate *out);

/* Combine the already-filled signals into the verdict + reason string.
 * SUSPECTED = signal 1 AND (signal 2 OR signal 3): the peer signal names the
 * rival chain, a local signal corroborates that we are the ones in trouble.
 * `tip_age_secs` < 0 means unknown (signal 3 then never fires). */
void network_monitor_partition_verdict(int64_t tip_age_secs, int64_t now_unix,
                                       struct network_partition_view *out);

/* ── Live surface ───────────────────────────────────────────────────────
 * THE exported predicate. Returns true iff the node currently suspects it is
 * on the minority side of a network split (the SUSPECTED_NETSPLIT signal).
 * `out` may be NULL; when non-NULL it always receives the latest evidence,
 * including when the return is false. Returns false when no partition fold
 * has completed yet. Reentrant-safe; takes only the monitor's own lock. */
bool network_monitor_netsplit_suspected(struct network_partition_view *out);

/* Publish a freshly folded partition view as the standing verdict, and log
 * the ONSET (a false->true transition) once. The sampler calls this once per
 * sample; tests call it directly to arm a verdict without peers or a chain.
 * Marks the stored view ready. NULL is a no-op. */
void network_monitor_netsplit_publish(const struct network_partition_view *v);

/* ── Runtime lifecycle ──────────────────────────────────────────────── */
struct network_monitor_config {
    int sample_interval_secs;   /* default 30 */
    int retain_rows;            /* default 10000 */
};
void network_monitor_config_defaults(struct network_monitor_config *cfg);

/* Start/stop the supervised sampler thread. db owns the retained history. */
struct zcl_result network_monitor_start(const struct network_monitor_config *cfg,
                                        struct node_db *db);
void network_monitor_stop(void);

/* Copy the latest folded view. Returns false if no sample has completed yet. */
bool network_monitor_get_view(struct network_consensus_view *out);

/* Feed a per-peer (height, tip hash) learned from an EXISTING message path
 * (an accepted-headers batch — see engine/composition/src/boot_msg_callbacks.c). Bounded
 * map; no new wire message. hash_hex is 64 hex chars + NUL. */
void network_monitor_note_peer_header(uint32_t peer_id, int height,
                                      const char hash_hex[65]);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool network_monitor_dump_state_json(struct json_value *out, const char *key);
bool network_monitor_netsplit_dump_state_json(struct json_value *out,
                                              const char *key);

#ifdef ZCL_TESTING
/* Force a single sample+fold now (uses the live connman), for tests that have
 * a running connman. Returns false if the monitor is not started. */
/* Reset the in-RAM header-vote map and last view. */
/* Inject a folded view (marks it ready) so condition detectors can be unit
 * tested without a live connman. */
void network_monitor_test_set_view(const struct network_consensus_view *v);
#endif

#endif /* ZCL_SERVICES_NETWORK_MONITOR_H */
