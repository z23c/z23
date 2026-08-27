/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: DHT-frame culpability model — reject-reason to peer-offence
 * mapping and the verdict classifier that decides which rejected frames
 * are evidence about the sender rather than about this node.
 *
 * PRODUCER CENSUS: the promoted table below governs ONLY the DHT frame
 * lane, whose single call site is the "zcode dht" prefix handler in
 * boot_zcode_dht.c. Other surfaces have their own mappers and are
 * deliberately NOT governed here:
 *   - boot_zcode_swarm.c work-node refusals (engine penalty events),
 *   - boot_zcode_swarm_membership.c's swarm-penalty mapper,
 *   - net.c message-framing offences on the plain lane.
 * Session-open capacity bumps and tick-time outbound failures have no
 * reject channel at all and stay off the scoring path. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_FRAME_AUTH_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_FRAME_AUTH_H

#include <stdbool.h>
#include <stdint.h>

#include <net/peer_scoring.h>
#include <vcs/zcode_dht_service.h>

enum boot_zcode_dht_frame_verdict {
    /* The service accepted the frame; nothing to score. */
    BOOT_FRAME_AUTHORIZED = 0,
    /* Deterministic wire or crypto evidence against the sender. */
    BOOT_FRAME_REFUTED,
    /* The rejection itself names the sender's behaviour deterministically,
     * but the mapped offence weight (not this enum) decides severity. */
    BOOT_FRAME_DECODE_DETERMINISTIC,
    /* This node could not produce a meaningful answer — service absent,
     * disabled, generation-stale, or no session snapshot yet. Never
     * evidence about the peer; counted locally, never scored. */
    BOOT_FRAME_INFRA_NON_ANSWER
};

/* Which offence a DHT reject reason maps to. Weights live in
 * peer_offence_weight(); PLAINTEXT probes and BACKPRESSURE map to NONE so
 * peer_scoring_record ignores them. */
enum peer_offence
boot_zcode_dht_offence(enum vcs_zcode_dht_reject_reason reason);

/* Classify one un-accepted frame for the scoring decision. When
 * `handled_ok` is true everything else is ignored. Presence and enabled
 * are separate: a live-but-disabled service must not lend its stale
 * rejections to the scorer either. On INFRA_NON_ANSWER the local-drop
 * counter advances as a side effect. */
enum boot_zcode_dht_frame_verdict boot_zcode_dht_frame_classify(
    bool handled_ok, bool service_present, bool service_enabled,
    bool have_session, enum vcs_zcode_dht_reject_reason reason);

/* Composition-root visibility for frames that were dropped without ever
 * becoming scoring evidence. The service struct cannot see these (its
 * counters start only once it exists and accepts frames), which is exactly
 * why the counter lives beside the composition root; the classifier's
 * INFRA_NON_ANSWER verdict is what advances it. */
uint64_t boot_zcode_dht_frame_auth_local_drops(void);

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_FRAME_AUTH_H */
