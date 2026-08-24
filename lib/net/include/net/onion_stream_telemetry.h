/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal bounded telemetry ownership for onion_stream.c. */

#ifndef ZCL_NET_ONION_STREAM_TELEMETRY_H
#define ZCL_NET_ONION_STREAM_TELEMETRY_H

#include "net/onion_stream.h"

struct onion_stream_dial_record;

enum onion_stream_dial_stage {
    ONION_DIAL_STREAM_QUEUED = 0,
    ONION_DIAL_CIRCUIT_READY,
    ONION_DIAL_BRIDGE_UP,
    ONION_DIAL_OPEN_REFUSED,
    ONION_DIAL_CIRCUIT_TIMEOUT,
    ONION_DIAL_CIRCUIT_TORN_DOWN,
    ONION_DIAL_BRIDGE_CLOSED,
    ONION_DIAL_BYTES_TO_PEER,
    ONION_DIAL_BYTES_FROM_PEER,
    ONION_DIAL_PEERS_ANSWERED,
    ONION_DIAL_STAGE_COUNT,
};

struct onion_stream_dial_record *onion_stream_dial_begin(
    const struct net_service *svc);
void onion_stream_dial_bump(struct onion_stream_dial_record *record,
                            enum onion_stream_dial_stage stage, uint64_t by);
void onion_stream_dial_end(struct onion_stream_dial_record *record);
void onion_stream_dial_poison(struct onion_stream_dial_record *record);

#endif
