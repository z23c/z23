/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Build the z23-lint argv for stable-publish containment.
 *          The Makefile still says --self-test; z23-lint says --selftest. */

#ifndef ZCL_STABLE_PUBLISH_CONTAINMENT_H
#define ZCL_STABLE_PUBLISH_CONTAINMENT_H

/* Write the exec vector for `lint_bin check-stable-publish-contained`
 * into out, including the terminating NULL. A leading --self-test is
 * rewritten to --selftest. Returns the number of slots used, including
 * NULL, or -1 when the vector does not fit. */
int zcl_stable_publish_exec_args(const char *lint_bin, int argc, char **argv,
                                 const char **out, int cap);

#endif
