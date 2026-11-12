/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Launch the installed Arena product journey. Sets the Commons
 *          beta label, hook, and arena-runner install flag, then execs the
 *          existing acceptance script in script_dir. */

#ifndef ZCL_ARENA_PRODUCT_JOURNEY_H
#define ZCL_ARENA_PRODUCT_JOURNEY_H

/* Does not return on success. 2 when script_dir is missing. 127 when bash
 * cannot be exec'd. */
int zcl_arena_product_journey_launch(const char *script_dir);

#endif
