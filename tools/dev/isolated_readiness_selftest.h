/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove isolated-node readiness checks against the real library. */

#ifndef ZCL_ISOLATED_READINESS_SELFTEST_H
#define ZCL_ISOLATED_READINESS_SELFTEST_H

/* Sources tools/scripts/isolated_node_env.sh and drives its readiness
 * functions. 0 and the PASS line when every check holds. 1 otherwise.
 * jsonq is the executable the library's JSON reads use. */
int zcl_isolated_readiness_selftest(const char *env_sh, const char *jsonq);

#endif
