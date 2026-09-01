/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * parity_slo_breach — promotes consensus parity vs the co-located zclassicd
 * oracle from an ad-hoc, transient mirror.rpc-unreachable /
 * mirror.hash-disagreement blocker into a standing measured SLO. SYMPTOM,
 * either: (A) the oracle is reachable and a same-height hash comparison
 * disagrees, sustained for PARITY_SLO_DISAGREE_WINDOW_SECS, or (B) the
 * oracle is unreachable while the mirror is configured/enabled, sustained
 * for PARITY_SLO_UNREACHABLE_WINDOW_SECS. Both read the mirror's own live
 * comparison state (legacy_mirror_sync_stats_cached_snapshot) — no new
 * oracle config, this condition reuses the mirror's. REMEDY: names it with
 * a typed BLOCKER_TRANSIENT ("consensus.parity_slo_breach") and logs;
 * non-destructive, no self-heal (COND_REMEDY_FAILED) — recovery is the
 * mirror's own reconnect/re-agree path. WITNESSED: clears on one clean
 * agreeing sample (oracle reachable AND a same-height hash match). */

#ifndef ZCL_CONDITIONS_PARITY_SLO_BREACH_H
#define ZCL_CONDITIONS_PARITY_SLO_BREACH_H

#include <stdbool.h>
#include <stdint.h>

void register_parity_slo_breach(void);

#ifdef ZCL_TESTING
void parity_slo_breach_test_reset(void);
/* Override the wall clock (unix secs) this detector samples. -1 = real clock. */
void parity_slo_breach_test_set_now(int64_t now_unix);
bool parity_slo_breach_test_detect(void);
#endif

#endif /* ZCL_CONDITIONS_PARITY_SLO_BREACH_H */
