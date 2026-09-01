/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_SNAPSHOT_OFFER_READY_H
#define ZCL_CONDITIONS_SNAPSHOT_OFFER_READY_H

/* SYMPTOM: a snapsync offer is active (NEGOTIATING/RECEIVING/VERIFYING) with
 *   offered_height/offered_count set, our local height is >= SNAPSHOT_OFFER_
 *   READY_MIN_GAP (1000) behind it, and the SYNC FSM can receive a snapshot.
 * REMEDY: action=set_snapshot_receive — sync_set_state(SYNC_SNAPSHOT_RECEIVE);
 *   failure to enter that state returns COND_REMEDY_FAILED.
 * WITNESSED: SYNC FSM is in SYNC_SNAPSHOT_RECEIVE AND the snapsync offer is
 *   genuinely active with staged_row_count >= the detect baseline.
 * COND_WARN; poll_secs=5 (backoff 60s, max_attempts 2). */
void register_snapshot_offer_ready(void);

#ifdef ZCL_TESTING
struct snapshot_sync_service;
void snapshot_offer_ready_test_reset(void);
void snapshot_offer_ready_test_set_service(struct snapshot_sync_service *svc);
int snapshot_offer_ready_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_SNAPSHOT_OFFER_READY_H */
