/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "supervisors/domains.h"

supervisor_domain_t *g_chain_sup;
supervisor_domain_t *g_net_sup;
supervisor_domain_t *g_op_sup;

void supervisor_domains_init(void)
{
    if (!g_chain_sup)   g_chain_sup   = supervisor_create_domain("chain");
    if (!g_net_sup)     g_net_sup     = supervisor_create_domain("net");
    if (!g_op_sup)      g_op_sup      = supervisor_create_domain("op");
}
