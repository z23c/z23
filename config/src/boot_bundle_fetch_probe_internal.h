/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_bundle_fetch_probe_internal — bounded bootstrap seed fan-out seam. */

#ifndef ZCL_CONFIG_BOOT_BUNDLE_FETCH_PROBE_INTERNAL_H
#define ZCL_CONFIG_BOOT_BUNDLE_FETCH_PROBE_INTERNAL_H

#include "config/boot_bundle_fetch.h"

/* Probe every bounded seed concurrently. `bodies` contains `np` slots of
 * `stride` bytes; `responded[i]` says whether slot i contains a verified,
 * NUL-terminated directory body. Returns the number of responses. */
size_t bbf_probe_directories(const struct rom_fetch_peer *peers, size_t np,
                             char *bodies, size_t stride, bool *responded,
                             bbf_directory_fetch_fn fetch);

#endif
