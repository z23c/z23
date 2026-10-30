/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: state-only read of the snapshot sync service. Periodic condition
 * polls decide on the service state here before any staged-row count, which
 * reads snapshot_staging_utxos. This is not the global snapsync_get_state()
 * in core/, which can diverge from the service own state.
 */

#ifndef ZCL_SERVICES_SNAPSHOT_SYNC_STATE_H
#define ZCL_SERVICES_SNAPSHOT_SYNC_STATE_H

#include "sync/sync_state.h"

struct snapshot_sync_service;

/* Reads svc->state under the service lock. Never touches the staging table. */
enum snapshot_sync_state snapsync_get_service_state(
    const struct snapshot_sync_service *svc);

#endif /* ZCL_SERVICES_SNAPSHOT_SYNC_STATE_H */
