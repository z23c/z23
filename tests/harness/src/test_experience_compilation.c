/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: registered public boundary tests for experience compilation. */
#include "services/experience_compilation_service.h"

#include <stdio.h>
#include <string.h>

#define EC_CHECK(name_, expression_) do {                              \
    if (expression_) {                                                 \
        printf("  experience_compilation: %s... OK\n", (name_));    \
    } else {                                                           \
        printf("  experience_compilation: %s... FAIL\n", (name_));  \
        failures++;                                                    \
    }                                                                  \
} while (0)

int test_experience_compilation(void)
{
    int failures = 0;
    struct zcl_experience_compilation_v1 output;
    struct zcl_experience_compilation_v1 zero = {0};
    memset(&output, 0xa5, sizeof(output));
    enum zcl_experience_compilation_error null_error =
        zcl_experience_compile(NULL, &output);
    EC_CHECK("null-episode-zeros-output",
             null_error == ZCL_EXPERIENCE_COMPILATION_NULL &&
             memcmp(&output, &zero, sizeof(output)) == 0);

    union {
        struct zcl_experience_episode_v1 episode;
        struct zcl_experience_compilation_v1 output;
    } aliased = {0};
    struct zcl_experience_episode_v1 before = aliased.episode;
    enum zcl_experience_compilation_error alias_error =
        zcl_experience_compile(&aliased.episode, &aliased.output);
    EC_CHECK("episode-output-alias-refuses-without-write",
             alias_error == ZCL_EXPERIENCE_COMPILATION_ALIAS &&
             memcmp(&aliased.episode, &before, sizeof(before)) == 0);

    char unbounded_workspace[4098];
    memset(unbounded_workspace, 'x', sizeof(unbounded_workspace));
    unbounded_workspace[sizeof(unbounded_workspace) - 1u] = '\0';
    struct zcl_experience_episode_v1 unbounded = {
        .workspace = unbounded_workspace,
    };
    memset(&output, 0xa5, sizeof(output));
    EC_CHECK("unbounded-workspace-refuses-before-input-dereference",
             zcl_experience_compile(&unbounded, &output) ==
                 ZCL_EXPERIENCE_COMPILATION_NULL &&
             memcmp(&output, &zero, sizeof(output)) == 0);
    EC_CHECK("public-error-contract-is-total",
             strcmp(zcl_experience_compilation_error_string(
                        ZCL_EXPERIENCE_COMPILATION_OK), "ok") == 0 &&
             strcmp(zcl_experience_compilation_error_string(
                        ZCL_EXPERIENCE_COMPILATION_ALIAS),
                    "input-output-alias") == 0 &&
             strcmp(zcl_experience_compilation_error_string(
                        ZCL_EXPERIENCE_COMPILATION_REPLICATION),
                    "replication-acceptance-invalid") == 0 &&
             strcmp(zcl_experience_compilation_error_string(
                        (enum zcl_experience_compilation_error)255),
                    "unknown") == 0);
    return failures;
}
