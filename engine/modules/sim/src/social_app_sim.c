/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "sim/social_app_sim.h"

#include "framework/app_platform.h"

#include <stddef.h>
#include <string.h>

enum { SOCIAL_NODES = 5, SOCIAL_VALID_EVENT = 0, SOCIAL_INVALID_EVENT = 1 };

struct social_node {
    bool online;
    bool seen[2];
};

struct social_run {
    uint64_t rng;
    uint64_t transcript;
    uint32_t deliveries;
    uint32_t rejected;
    struct social_node nodes[SOCIAL_NODES];
    struct zcl_app_signed_event_v1 events[2];
};

static const uint8_t g_social_chain_id[ZCL_APP_EVENT_CHAIN_ID_SIZE] = {
    0x02, 0x06, 0x26, 0x01, 0x43, 0x83, 0x8b, 0x5f,
    0xf5, 0x2d, 0xc2, 0xeb, 0x7b, 0x4b, 0x80, 0x99,
    0xd4, 0xe4, 0xc9, 0x9d, 0xc3, 0xef, 0x19, 0x79,
    0x42, 0x89, 0xa2, 0xcd, 0x4c, 0x10, 0x07, 0x00,
};

static const uint8_t g_social_pubkey[ZCL_APP_EVENT_PUBKEY_SIZE] = {
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
    0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
    0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
};

static const uint8_t g_social_key_id[ZCL_APP_EVENT_KEY_ID_SIZE] = {
    0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
    0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
    0xf1, 0x43, 0x3b, 0xd6,
};

static const uint8_t g_social_event_id[32] = {
    0xd2, 0xbf, 0x68, 0xe3, 0x05, 0xf1, 0xe5, 0x8a,
    0x02, 0xb0, 0x09, 0x43, 0x23, 0xd8, 0xfd, 0x8a,
    0xca, 0x29, 0x76, 0xe8, 0xa6, 0xdd, 0xaf, 0xe8,
    0x7a, 0x34, 0x59, 0x9d, 0xe3, 0xe4, 0xe3, 0xf8,
};

static const uint8_t g_social_signature[] = {
    0x30, 0x44, 0x02, 0x20, 0x2c, 0x27, 0x65, 0xc3,
    0x93, 0x17, 0xd3, 0x3a, 0xb0, 0x6e, 0x69, 0x6c,
    0x0a, 0x93, 0x4a, 0xff, 0xb0, 0xe6, 0x6b, 0xa5,
    0x2e, 0x80, 0x0f, 0xd6, 0x85, 0x3f, 0x8f, 0x10,
    0x5d, 0xd0, 0xe1, 0xb4, 0x02, 0x20, 0x7b, 0x15,
    0x9d, 0xaf, 0xa6, 0x76, 0x9f, 0x85, 0x94, 0x19,
    0xd8, 0x82, 0x18, 0x81, 0x8e, 0x08, 0x65, 0xd7,
    0xac, 0x7e, 0xca, 0x81, 0xb7, 0xca, 0x32, 0x7d,
    0x0e, 0x1a, 0xde, 0x8f, 0x58, 0x41,
};

static const uint8_t g_social_payload[] = "hello zclassic23";
static const uint8_t g_social_tampered_payload[] = "jello zclassic23";

static struct zcl_app_event_scope_v1 social_scope(void)
{
    struct zcl_app_event_scope_v1 scope;
    memset(&scope, 0, sizeof(scope));
    scope.struct_size = sizeof(scope);
    memcpy(scope.app_id, "social", sizeof("social"));
    memcpy(scope.topic, "social.events.v1", sizeof("social.events.v1"));
    memcpy(scope.chain_id, g_social_chain_id, sizeof(scope.chain_id));
    scope.max_event_bytes = 65536;
    return scope;
}

static bool social_make_events(struct social_run *run)
{
    struct zcl_app_signed_event_v1 *event =
        &run->events[SOCIAL_VALID_EVENT];
    memset(event, 0, sizeof(*event));
    event->struct_size = sizeof(*event);
    event->version = ZCL_APP_SIGNED_EVENT_V1;
    memcpy(event->app_id, "social", sizeof("social"));
    memcpy(event->topic, "social.events.v1", sizeof("social.events.v1"));
    event->kind = 1;
    event->sequence = 1;
    event->created_at = UINT64_C(1700000000);
    memcpy(event->chain_id, g_social_chain_id, sizeof(event->chain_id));
    memcpy(event->author_key_id, g_social_key_id,
           sizeof(event->author_key_id));
    memcpy(event->author_pubkey, g_social_pubkey,
           sizeof(event->author_pubkey));
    event->payload.data = g_social_payload;
    event->payload.len = sizeof(g_social_payload) - 1;
    memcpy(event->signature, g_social_signature, sizeof(g_social_signature));
    event->signature_len = sizeof(g_social_signature);
    memcpy(event->event_id, g_social_event_id, sizeof(event->event_id));

    run->events[SOCIAL_INVALID_EVENT] = *event;
    run->events[SOCIAL_INVALID_EVENT].payload.data =
        g_social_tampered_payload;
    if (!zcl_app_signed_event_v1_id(
            &run->events[SOCIAL_INVALID_EVENT],
            run->events[SOCIAL_INVALID_EVENT].event_id, NULL, 0))
        return false;
    return memcmp(run->events[SOCIAL_VALID_EVENT].event_id,
                  run->events[SOCIAL_INVALID_EVENT].event_id, 32) != 0;
}

static uint64_t mix(uint64_t hash, uint64_t value)
{
    hash ^= value;
    hash *= UINT64_C(1099511628211);
    return hash;
}

static uint64_t next_random(struct social_run *run)
{
    uint64_t x = run->rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    run->rng = x;
    return x;
}

static bool linked(size_t a, size_t b, bool partitioned)
{
    static const bool edges[SOCIAL_NODES][SOCIAL_NODES] = {
        { false, true,  true,  false, false },
        { true,  false, false, true,  false },
        { true,  false, false, true,  false },
        { false, true,  true,  false, true  },
        { false, false, false, true,  false },
    };
    if (partitioned && ((a == 2 && b == 3) || (a == 3 && b == 2)))
        return false;
    return edges[a][b];
}

enum social_delivery_decision {
    SOCIAL_ACCEPT,
    SOCIAL_REJECT_INVALID,
    SOCIAL_REJECT_CENSOR,
};

static enum social_delivery_decision accepts(const struct social_run *run,
                                             size_t node, size_t event)
{
    struct zcl_app_event_scope_v1 scope = social_scope();
    if (!zcl_app_signed_event_v1_verify(&run->events[event], &scope,
                                        NULL, 0))
        return SOCIAL_REJECT_INVALID;
    /* Node 1 models a relay attempting to censor Alice's valid post. */
    if (node == 1)
        return SOCIAL_REJECT_CENSOR;
    return SOCIAL_ACCEPT;
}

static bool deliver_round(struct social_run *run, size_t event,
                          bool partitioned)
{
    struct { uint8_t from, to; } pending[64];
    size_t count = 0;
    for (size_t from = 0; from < SOCIAL_NODES; from++) {
        if (!run->nodes[from].online || !run->nodes[from].seen[event])
            continue;
        for (size_t to = 0; to < SOCIAL_NODES; to++) {
            if (from == to || !run->nodes[to].online ||
                run->nodes[to].seen[event] || !linked(from, to, partitioned))
                continue;
            pending[count].from = (uint8_t)from;
            pending[count].to = (uint8_t)to;
            count++;
        }
    }
    bool progressed = false;
    while (count > 0) {
        size_t pick = (size_t)(next_random(run) % count);
        uint8_t from = pending[pick].from;
        uint8_t to = pending[pick].to;
        pending[pick] = pending[--count];
        run->transcript = mix(run->transcript,
                              ((uint64_t)event << 24) |
                              ((uint64_t)from << 8) | to);
        run->deliveries++;
        enum social_delivery_decision decision = accepts(run, to, event);
        if (decision != SOCIAL_ACCEPT) {
            if (decision == SOCIAL_REJECT_INVALID)
                run->rejected++;
            run->transcript = mix(run->transcript, UINT64_C(0xdead0000) | to);
            continue;
        }
        if (!run->nodes[to].seen[event]) {
            run->nodes[to].seen[event] = true;
            progressed = true;
        }
    }
    return progressed;
}

static void converge(struct social_run *run, size_t event, bool partitioned)
{
    for (size_t round = 0; round < 16; round++) {
        if (!deliver_round(run, event, partitioned))
            break;
    }
}

bool zcl_social_app_sim_run(uint64_t seed,
                            struct zcl_social_sim_report *out)
{
    if (!out || seed == 0)
        return false;
    struct social_run run;
    memset(&run, 0, sizeof(run));
    run.rng = seed;
    run.transcript = mix(UINT64_C(1469598103934665603), seed);
    if (!social_make_events(&run)) {
        memset(out, 0, sizeof(*out));
        out->seed = seed;
        return false;
    }
    for (size_t event = 0; event < 2; event++) {
        for (size_t i = 0; i < sizeof(run.events[event].event_id); i++)
            run.transcript = mix(run.transcript,
                                 run.events[event].event_id[i]);
    }

    struct zcl_app_event_scope_v1 scope = social_scope();
    bool real_signature = zcl_app_signed_event_v1_verify(
        &run.events[SOCIAL_VALID_EVENT], &scope, NULL, 0);
    bool tampered_rejected = !zcl_app_signed_event_v1_verify(
        &run.events[SOCIAL_INVALID_EVENT], &scope, NULL, 0);
    struct zcl_app_signed_event_v1 wrong_author =
        run.events[SOCIAL_VALID_EVENT];
    wrong_author.author_key_id[0] ^= 1;
    bool wrong_author_rejected = !zcl_app_signed_event_v1_verify(
        &wrong_author, &scope, NULL, 0);

    /* Alice and the initial relays are online. A partition isolates honest
     * relay 2 from relay 3; censor 1 refuses Alice's event. */
    for (size_t i = 0; i < 4; i++)
        run.nodes[i].online = true;
    run.nodes[0].seen[SOCIAL_VALID_EVENT] = true;
    converge(&run, SOCIAL_VALID_EVENT, true);

    /* Partition heals and a brand-new peer joins after publication. Honest
     * anti-entropy must carry the event around the refusing relay. */
    run.nodes[4].online = true;
    converge(&run, SOCIAL_VALID_EVENT, false);

    /* A forged event enters at the late joiner. Every attempted receiver must
     * reject it; it can never become accepted state on an honest node. */
    run.nodes[4].seen[SOCIAL_INVALID_EVENT] = true;
    converge(&run, SOCIAL_INVALID_EVENT, false);

    memset(out, 0, sizeof(*out));
    out->seed = seed;
    out->transcript = run.transcript;
    out->deliveries = run.deliveries;
    out->rejected_invalid = run.rejected;
    out->censorship_bypassed = !run.nodes[1].seen[SOCIAL_VALID_EVENT] &&
        run.nodes[2].seen[SOCIAL_VALID_EVENT] &&
        run.nodes[3].seen[SOCIAL_VALID_EVENT];
    out->partition_rejoin_converged =
        run.nodes[0].seen[SOCIAL_VALID_EVENT] &&
        run.nodes[2].seen[SOCIAL_VALID_EVENT] &&
        run.nodes[3].seen[SOCIAL_VALID_EVENT] &&
        run.nodes[4].seen[SOCIAL_VALID_EVENT];
    out->late_joiner_caught_up = run.nodes[4].seen[SOCIAL_VALID_EVENT];
    out->invalid_signature_rejected =
        !run.nodes[0].seen[SOCIAL_INVALID_EVENT] &&
        !run.nodes[1].seen[SOCIAL_INVALID_EVENT] &&
        !run.nodes[2].seen[SOCIAL_INVALID_EVENT] &&
        !run.nodes[3].seen[SOCIAL_INVALID_EVENT];
    out->real_secp256k1_verified = real_signature;
    out->tampered_payload_rejected = tampered_rejected;
    out->wrong_author_rejected = wrong_author_rejected;
    out->forged_event_id_distinct = memcmp(
        run.events[SOCIAL_VALID_EVENT].event_id,
        run.events[SOCIAL_INVALID_EVENT].event_id, 32) != 0;
    return out->censorship_bypassed && out->partition_rejoin_converged &&
           out->late_joiner_caught_up && out->invalid_signature_rejected &&
           out->real_secp256k1_verified &&
           out->tampered_payload_rejected && out->wrong_author_rejected &&
           out->forged_event_id_distinct;
}
