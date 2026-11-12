/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove the secure-release Makefile group list and the canonical
 *          regression manifest name one exact catalog set. */

#ifndef ZCL_SECURE_RELEASE_REGRESSIONS_H
#define ZCL_SECURE_RELEASE_REGRESSIONS_H

/* 0 when make_groups, the manifest, and the catalog agree. 1 when they
 * drift. Prints the PASS line or a FAIL line. */
int zcl_secure_release_regressions_check(const char *make_groups,
                                        const char *manifest_path,
                                        const char *catalog_path);

#endif
