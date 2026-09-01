/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SUPERVISOR_DOMAINS_H
#define ZCL_SUPERVISOR_DOMAINS_H

#include "util/supervisor.h"

extern supervisor_domain_t *g_chain_sup;
extern supervisor_domain_t *g_net_sup;
extern supervisor_domain_t *g_op_sup;

/* Lazily create the three top-level supervisor domains
 * (`g_chain_sup`, `g_net_sup`, `g_op_sup`) if they do not already exist.
 * Idempotent — safe to call from each child registrar before it places
 * itself in a domain. */
void supervisor_domains_init(void);

#endif /* ZCL_SUPERVISOR_DOMAINS_H */
