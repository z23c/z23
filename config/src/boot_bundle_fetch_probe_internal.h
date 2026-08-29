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

/* Probe every bounded seed CONCURRENTLY for the per-chunk ("RMF") manifest of
 * `chunk_root`, and copy out the LOWEST-INDEXED seed's answer whose chunk
 * count equals `want_chunks` — the same seed the old serial loop would have
 * settled on, so seed ordering stays policy and concurrency changes only
 * wall-clock latency.
 *
 * Why this is fanned out rather than walked: one seed that accepts and then
 * says nothing costs the connect budget plus the probe budget, and walking
 * the set serially multiplied that by the number of seeds — on a Tor circuit,
 * where both budgets are deliberately 4x their clearnet values because a
 * circuit is genuinely slower, into many minutes before boot could give up.
 * Running the sweep at once makes the worst case ONE seed's budget instead of
 * every seed's, with no budget shortened and no honest slow seeder graded any
 * differently than before.
 *
 * Every candidate answer is chunk-root-verified inside `fetch` before it can
 * be returned, so which seed replies first has no bearing on trust. Returns
 * true and fills out_chunk_sha3/out_num_chunks on a match, false otherwise. */
bool bbf_probe_manifest(const struct rom_fetch_peer *peers, size_t np,
                        const uint8_t chunk_root[32], uint32_t want_chunks,
                        uint8_t (*out_chunk_sha3)[32], uint32_t out_cap,
                        uint32_t *out_num_chunks, bbf_manifest_fetch_fn fetch);

#endif
