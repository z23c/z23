/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Cached driver for the two build-epoch compile probes. */

#ifndef ZCL_BUILD_EPOCH_INTEGRITY_H
#define ZCL_BUILD_EPOCH_INTEGRITY_H

/* repo is the checkout whose probe inputs form the cache key.
 * Returns 0 when the cached verdict matches or both probes pass,
 * 1 when a probe fails, 2 when repo is missing or the host cannot run. */
int zcl_build_epoch_integrity(const char *repo);

#endif
