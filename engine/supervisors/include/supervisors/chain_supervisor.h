/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain domain supervisor children — declarative liveness registration.
 *
 * Owns the chain.coord_escalation child: after 900 s of fatal mirror-lag
 * breach + frozen local height, it tries evidence-based revalidation of the
 * next-child block and reports the named stall if revalidation cannot help.
 * Registered in the `chain` domain (g_chain_sup). */

#ifndef ZCL_CHAIN_SUPERVISOR_H
#define ZCL_CHAIN_SUPERVISOR_H

struct main_state;

/* Register the chain-domain supervisor children. Idempotent — a second
 * call is a no-op. `ms` is the live chainstate the escalation child reads. */
void chain_supervisor_register(struct main_state *ms);

#endif /* ZCL_CHAIN_SUPERVISOR_H */
