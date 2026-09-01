/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CHAIN_RESTORE_REPAIR_INTERNAL_H
#define ZCL_CHAIN_RESTORE_REPAIR_INTERNAL_H

struct active_chain;

int chain_restore_repair_active_projection(struct active_chain *c, int tip_h);

#endif /* ZCL_CHAIN_RESTORE_REPAIR_INTERNAL_H */
