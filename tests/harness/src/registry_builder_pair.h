/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef REGISTRY_BUILDER_PAIR_H
#define REGISTRY_BUILDER_PAIR_H
#include <stdbool.h>
#include <stdint.h>

/* Run two isolated registry builders. Only the Linux parallel runner supports
 * the supervised mode; callers retain the serial path elsewhere. */
bool registry_builder_pair_available(void);
bool registry_builder_build_one(const char *datadir, const char *root, int64_t now);
void registry_builder_pair_enable(void);
bool registry_builder_pair_run(const char *a, const char *b,
                               const char *root, int64_t now);
bool registry_builder_pair_cleanup_test(const char *a, const char *b);
void registry_builder_exit_if_requested(int argc, char **argv);
#endif
