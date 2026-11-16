/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: capture and guard candidate paths against live worktree claims.
 */
#ifndef ZCL_NATIVE_SUBMIT_CLAIM_GUARD_H
#define ZCL_NATIVE_SUBMIT_CLAIM_GUARD_H

#include <stdbool.h>
#include <stddef.h>

struct zcl_command_reply;
struct zcl_submit_claim_guard;

/* Capture complete bounded Git stdout, including embedded NUL bytes. */
bool zcl_submit_git_capture(const char *const argv[], char *bytes,
                            size_t cap, size_t *length);
/* Paths are the submitting Git worktree and common directory facts. */
struct zcl_submit_claim_guard *zcl_submit_claim_prepare(
    const char *worktree, const char *top, const char *common, const char *tip,
    struct zcl_command_reply *reply);
bool zcl_submit_claim_lock(struct zcl_submit_claim_guard *guard,
                           struct zcl_command_reply *reply);
bool zcl_submit_claim_check(struct zcl_submit_claim_guard *guard,
                            struct zcl_command_reply *reply);
void zcl_submit_claim_free(struct zcl_submit_claim_guard *guard);
#endif
