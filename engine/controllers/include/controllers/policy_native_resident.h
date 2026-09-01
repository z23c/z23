/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * RESIDENT half of the hot-swappable package-policy projection.
 *
 * This translation unit is deliberately NOT eligible, NOT swappable, and NOT
 * an island member. It is the sibling trampoline named by
 * engine/composition/hotswap_eligible.def's check-hotswap-static-state contract: the ONE
 * place the mutable process state for this surface lives.
 *
 * Its counterpart, engine/controllers/src/policy_native_handlers.c, is the pure
 * decision leaf that a generation .so recompiles. Because the state lives
 * here and here only, the swappable half holds no copy of it — the module .so
 * imports these four symbols from the -rdynamic host at dlopen (they are
 * absent from the module, so -Wl,-Bsymbolic cannot bind them internally) and
 * therefore reads and writes the SAME counters the resident process owns.
 * That is the whole trampoline thesis, and it is what makes this NOT a cloned
 * ledger: there is exactly one copy of the state, and the half that can be
 * swapped holds none of it.
 */

#ifndef ZCL_CONTROLLERS_POLICY_NATIVE_RESIDENT_H
#define ZCL_CONTROLLERS_POLICY_NATIVE_RESIDENT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Called once by the resident command layer (tools/command/native_command.c)
 * BEFORE any hot-swap module is dlopen'd. A module that had its own zeroed
 * copy of this flag would report false. */
void zcl_native_policy_resident_mark_boot(void);

/* True iff the resident process marked boot. Read by the swappable leaf. */
bool zcl_native_policy_resident_booted(void);

/* Count one policy projection and return the new total. */
uint64_t zcl_native_policy_resident_note_dispatch(void);

/* Total projections served by THIS process across every generation. */
uint64_t zcl_native_policy_resident_dispatches(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_POLICY_NATIVE_RESIDENT_H */
