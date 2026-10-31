/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Seam between hotswap_activate.c and hotswap_activate_gate.c. */
#ifndef ZCL_HOTSWAP_ACTIVATE_INTERNAL_H
#define ZCL_HOTSWAP_ACTIVATE_INTERNAL_H

/* True when ZCL_HOTSWAP_ACTIVATE=1 is set in the environment. */
bool hotswap_env_opt_in(void);

#endif
