/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded non-authoritative repair feedback from fixed C23 workers. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_WORKER_FEEDBACK_H
#define ZCL_SERVICES_BUILD_FABRIC_WORKER_FEEDBACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BUILD_FABRIC_FEEDBACK_STAGE_MAX 15u
#define BUILD_FABRIC_FEEDBACK_COMPILER_MAX 15u
#define BUILD_FABRIC_FEEDBACK_PATH_MAX 255u
#define BUILD_FABRIC_FEEDBACK_MESSAGE_MAX 191u

/* This helps the next candidate turn; it is not a receipt, proof, or
 * acceptance authority. */
struct build_fabric_worker_feedback {
    bool present;
    char stage[BUILD_FABRIC_FEEDBACK_STAGE_MAX + 1u];
    char compiler[BUILD_FABRIC_FEEDBACK_COMPILER_MAX + 1u];
    char path[BUILD_FABRIC_FEEDBACK_PATH_MAX + 1u];
    uint32_t line;
    uint32_t column;
    char message[BUILD_FABRIC_FEEDBACK_MESSAGE_MAX + 1u];
};

void build_fabric_worker_feedback_capture(
    struct build_fabric_worker_feedback *out, const char *capture,
    const char *source_root);

#endif /* ZCL_SERVICES_BUILD_FABRIC_WORKER_FEEDBACK_H */
