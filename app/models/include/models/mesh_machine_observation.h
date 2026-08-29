/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Durable latest signed status evidence for one paired machine. */

#ifndef ZCL_MODELS_MESH_MACHINE_OBSERVATION_H
#define ZCL_MODELS_MESH_MACHINE_OBSERVATION_H

#include "models/mesh_pairing.h"
#include "session/mesh_status_proto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct db_mesh_machine_observation {
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    uint8_t receipt_wire[MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES];
    size_t receipt_len;
    uint8_t receipt_root[32];
    enum mesh_status_receipt_status status;
    int64_t observed_unix;
    int64_t expires_unix;
    int64_t received_unix;
};

struct db_mesh_machine_view {
    struct db_mesh_pairing pairing;
    bool has_observation;
    struct db_mesh_machine_observation observation;
};

struct ar_callbacks *db_mesh_machine_observation_callbacks(void);

/* The exact wire must decode as a valid signed receipt, hash to receipt_root,
 * and repeat every projected field. Pairing identity is checked by save(). */
bool db_mesh_machine_observation_validate(
    const struct db_mesh_machine_observation *row, struct ar_errors *errors);

/* Insert or replace the latest evidence for one pairing. Older evidence and
 * same-time equivocation are refused; an exact-root replay is idempotent. */
bool db_mesh_machine_observation_save(
    struct node_db *ndb, const struct db_mesh_machine_observation *row);

/* List every pairing with its latest durable observation when present.
 * Expired evidence remains visible: callers derive freshness from `now` and
 * the pairing state instead of confusing stale evidence with no evidence.
 * Returns the row count, or -1 when the projection cannot be read safely. */
int db_mesh_machine_observation_list(
    struct node_db *ndb, struct db_mesh_machine_view *out, size_t max,
    int64_t now);

#endif /* ZCL_MODELS_MESH_MACHINE_OBSERVATION_H */
