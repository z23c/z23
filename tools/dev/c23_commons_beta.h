/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Install an ordinary C23 Commons prefix and run the stranger journey. */

#ifndef ZCL_C23_COMMONS_BETA_H
#define ZCL_C23_COMMONS_BETA_H

/* Installs the ordinary product under a private prefix in repo and runs
 * tools/dev/zcode_dht_acceptance.sh from outside the checkout. The host
 * entry resolves the checkout; a NULL or empty repo returns 2. Returns 0
 * when the journey passes. */
int zcl_c23_commons_beta(const char *repo);

#endif
