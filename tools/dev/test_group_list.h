/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Public API of the test-group list and registry report. It is the
 *          one body behind the standalone build/bin/test-group-list host
 *          tool (Make parse time, agent_fast_ci, the selector tests) and the
 *          `z23-dev dev test-groups` leaf. */

#ifndef ZCL_TEST_GROUP_LIST_H
#define ZCL_TEST_GROUP_LIST_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TGL_DEFAULT_REGISTRY "tools/dev/test_group_catalog.def"
#define TGL_DEFAULT_RUNNER "tests/harness/src/test_parallel.c"
#define TGL_DEFAULT_FAMILIES "tools/dev/test_proof_families.def"
#define TGL_DEFAULT_UMBRELLAS "tools/dev/test_group_umbrellas.def"
#define TGL_DEFAULT_TIMING ".cache/test-timing/last-run.json"
#define TGL_DEFAULT_RULES \
    "cognition/controllers/include/controllers/agent_impact_rules.def"

/* The files a call reads. Every path is relative to the current directory
 * (the repository root) unless it is absolute. */
struct tgl_sources {
    const char *registry;
    const char *runner;
    const char *families;
    const char *umbrellas;
    const char *timing;
};

/* The defaults above, each replaced by its environment override when set:
 * ZCL_TEST_REGISTRY_SRC, ZCL_TEST_RUNNER_SRC, ZCL_TEST_PROOF_FAMILIES_SRC,
 * ZCL_TEST_UMBRELLAS_SRC and ZCL_TEST_TIMING_JSON. */
void tgl_sources_from_env(struct tgl_sources *s);

/* One invocation. argv[0..argc) is the mode and its operands (no program
 * name): none or `list`, --count, --match S, --resolve-exact ID...,
 * --resolve-proof ID..., --resolve-exact-set CSV, --check-impact-rules
 * [FILE], --suggest S, --params-gated, --report. Results go to `out`,
 * diagnostics to `err`. Returns the process status: 0, 1 (no match or a
 * refusal) or 2 (missing proof source or bad usage). */
int tgl_run(const struct tgl_sources *s, int argc, const char *const *argv,
            FILE *out, FILE *err);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TEST_GROUP_LIST_H */
