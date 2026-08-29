/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the simnet_wire observation layer — the node-under-test readouts
 * (tip hash, coins digest, capsule save), the per-tick invariant monitors
 * (bounded recv/send queues, no unexpected permanent blocker, unchanged
 * consensus baseline, ban expectations) and the scripted partition timeline
 * they are judged against.
 *
 * Split out of simnet_wire.c along the file-size ceiling seam: that file
 * keeps the transport engine (rings, event queue, framing, delivery, tick
 * loop, lifecycle). Every symbol crossing the seam was already declared —
 * the public ones in sim/simnet_wire.h, the private ones in
 * simnet_wire_internal.h — so this split promotes nothing new.
 */

#include "simnet_wire_internal.h"

#include "net/peer_scoring.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

bool simnet_wire_tip_hash(const struct simnet_wire *wire, struct uint256 *out)
{
    if (!wire || !out)
        LOG_FAIL("simnet.wire", "invalid tip hash request");
    struct block_index *tip = active_chain_tip(&wire->ms.chain_active);
    if (tip)
        *out = tip->hashBlock;
    else
        uint256_set_null(out);
    return true;
}
bool simnet_wire_coins_digest(const struct simnet_wire *wire,
                              struct utxo_commitment *out)
{
    if (!wire || !out)
        LOG_FAIL("simnet.wire", "invalid coins digest request");
    coins_view_cache_recompute_commitment(&wire->coins_tip, out);
    return true;
}

bool simnet_wire_save_capsule(const struct simnet_wire *wire,
                              const char *path)
{
    if (!wire || !wire->tape || !path || !*path)
        LOG_FAIL("simnet.wire", "invalid capsule save request");
    int rc = seed_tape_save(wire->tape, path);
    if (rc != 0)
        LOG_FAIL("simnet.wire", "seed_tape_save failed rc=%d path=%s",
                 rc, path);
    return true;
}

void simnet_wire_mark_monitor_failed(struct simnet_wire *wire,
                                     const char *reason)
{
    if (!wire)
        return;
    wire->monitor.failed = true;
    if (!wire->monitor.saved_capsule && wire->tape) {
        char path[96];
        snprintf(path, sizeof(path),
                 "/tmp/simnet_wire_%016llx.tape",
                 (unsigned long long)wire->master_seed);
        if (seed_tape_save(wire->tape, path) == 0)
            wire->monitor.saved_capsule = true;
    }
    if (reason && *reason)
        LOG_WARN("simnet.wire", "monitor violation: %s", reason);
}

static void simnet_wire_monitor_track_memory(struct simnet_wire *wire)
{
    if (!wire)
        return;
    struct simnet_wire_monitor *m = &wire->monitor;
    /* D2: every peer is now its own connection — the bounded-memory /
     * no-silent-halt guarantees must hold across ALL of them, so track the
     * max over each node, not just peer 0. */
    for (size_t i = 0; i < wire->peer_count; i++) {
        struct p2p_node *node = wire->peers[i].node;
        if (!node)
            continue;
        if (node->recv_msg_count > m->max_recv_msg_count)
            m->max_recv_msg_count = node->recv_msg_count;
        if (node->send_size > m->max_send_size)
            m->max_send_size = node->send_size;
        if (node->inventory_to_send_count > m->max_inventory_to_send)
            m->max_inventory_to_send = node->inventory_to_send_count;
        if (node->addr_to_send_count > m->max_addr_to_send)
            m->max_addr_to_send = node->addr_to_send_count;

        if (node->recv_msg_count > MAX_RECV_MESSAGES) {
            m->recv_queue_bounded = false;
            simnet_wire_mark_monitor_failed(wire, "recv queue exceeded cap");
        }
        if (node->send_size > net_send_peer_bytes_cap() ||
            node->inventory_to_send_count > MAX_INVENTORY_KNOWN ||
            node->addr_to_send_count > MAX_ADDR_TO_SEND) {
            m->memory_plateau_ok = false;
            if (!m->warned_memory_growth) {
                m->warned_memory_growth = true;
                LOG_WARN("simnet.wire",
                         "memory plateau warning peer=%zu send=%zu inv=%zu "
                         "addr=%zu", i, node->send_size,
                         node->inventory_to_send_count,
                         node->addr_to_send_count);
            }
        }
    }
}

static bool simnet_wire_monitor_blockers(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL blocker monitor");
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (snaps[i].class != (int)BLOCKER_PERMANENT)
            continue;
        if (simnet_wire_byzantine_expected_blocker(
                wire, snaps[i].id, snaps[i].class))
            continue;
        wire->monitor.no_unexpected_permanent_blocker = false;
        simnet_wire_mark_monitor_failed(wire,
                                        "unexpected permanent blocker");
        return false;
    }
    return true;
}

static bool simnet_wire_monitor_consensus(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL consensus monitor");
    struct uint256 tip;
    struct utxo_commitment coins;
    if (!simnet_wire_tip_hash(wire, &tip) ||
        !simnet_wire_coins_digest(wire, &coins))
        return false;
    if (!uint256_eq(&tip, &wire->monitor.baseline_tip) ||
        !utxo_commitment_equal(&coins, &wire->monitor.baseline_coins)) {
        wire->monitor.consensus_unchanged = false;
        simnet_wire_mark_monitor_failed(wire, "consensus baseline changed");
        return false;
    }
    return true;
}

static bool simnet_wire_monitor_ban_expectations(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "invalid ban monitor");
    /* D2: check each ban-expecting peer against its OWN node — a node that
     * crossed the ban threshold must be disconnected and its address banned,
     * independently of the other connections. */
    for (size_t i = 0; i < wire->peer_count; i++) {
        struct wire_peer *peer = &wire->peers[i];
        if (!peer->ban_expected || !peer->node ||
            !peer_scoring_should_ban(peer->node))
            continue;
        if (!peer->node->disconnect ||
            !is_banned(&wire->nm, &peer->node->addr.svc.addr)) {
            simnet_wire_mark_monitor_failed(
                wire, "ban threshold did not disconnect");
            return false;
        }
    }
    return true;
}

bool simnet_wire_monitor_after_tick(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL monitor tick");
    simnet_wire_monitor_track_memory(wire);
    simnet_wire_byzantine_after_tick(wire);
    return simnet_wire_monitor_blockers(wire) &&
           simnet_wire_monitor_consensus(wire) &&
           simnet_wire_monitor_ban_expectations(wire) &&
           !wire->monitor.failed;
}

bool simnet_wire_monitor_finish(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL monitor finish");
    return simnet_wire_monitor_after_tick(wire);
}

bool simnet_wire_scenario_partitions_pending(const struct simnet_wire *wire)
{
    if (!wire)
        return false;
    for (size_t i = 0; i < wire->partition_count; i++) {
        const struct wire_scenario_partition_state *p = &wire->partitions[i];
        if (!p->closed_fired)
            return true;
        if (p->duration_ticks > 0 && !p->reopened_fired)
            return true;
    }
    return false;
}

/* Fires scripted CLOSE/OPEN events (Step D1's wire_scenario.partitions[])
 * once the tick counter reaches each entry's at_tick /
 * at_tick+duration_ticks. Tick-keyed, not wall-clock, so replay stays
 * deterministic for a given seed. Routed through simnet_wire_partition_peer
 * so scripted and manually-triggered partitions share one code path. */
bool simnet_wire_apply_scenario_partitions(struct simnet_wire *wire,
                                           bool *progress)
{
    if (!wire || !progress)
        LOG_FAIL("simnet.wire", "invalid partition timeline args");
    for (size_t i = 0; i < wire->partition_count; i++) {
        struct wire_scenario_partition_state *p = &wire->partitions[i];
        if (!p->closed_fired && wire->ticks >= p->at_tick) {
            if (!simnet_wire_partition_peer(wire, p->peer_id, true))
                return false;
            p->closed_fired = true;
            *progress = true;
        }
        if (p->closed_fired && !p->reopened_fired && p->duration_ticks > 0 &&
            wire->ticks >= p->at_tick + p->duration_ticks) {
            if (!simnet_wire_partition_peer(wire, p->peer_id, false))
                return false;
            p->reopened_fired = true;
            *progress = true;
        }
    }
    return true;
}
