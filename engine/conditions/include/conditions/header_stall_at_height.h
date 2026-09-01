/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_HEADER_STALL_AT_HEIGHT_H
#define ZCL_CONDITIONS_HEADER_STALL_AT_HEIGHT_H

/* SYMPTOM: in SYNC_HEADERS_DOWNLOAD/SYNC_BLOCKS_DOWNLOAD, peer_max exceeds
 *   our best header but pindex_best_header->nHeight has not changed for
 *   >= 300s (header download wedged below the peers' tip).
 * REMEDY: action=kick_headers — reset every outbound peer's getheaders
 *   timers, force SYNC_HEADERS_DOWNLOAD, header_probe_pull_range(h+1, 2000).
 * WITNESSED: pindex_best_header->nHeight advanced past header_h_at_detect.
 * COND_CRITICAL; poll_secs=5 (backoff 300s, max_attempts 3). */
void register_header_stall_at_height(void);

#ifdef ZCL_TESTING
void header_stall_at_height_test_reset(void);
int header_stall_at_height_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_HEADER_STALL_AT_HEIGHT_H */
