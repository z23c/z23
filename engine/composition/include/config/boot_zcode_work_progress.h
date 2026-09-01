/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Signed progress telemetry on the existing ZCODE work swarm. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_WORK_PROGRESS_H
#define ZCL_CONFIG_BOOT_ZCODE_WORK_PROGRESS_H

#include <stdint.h>

struct db_build_action;
struct node_db;
struct vcs_zcode_work_node;
struct vcs_zcode_work_request_v1;
struct vcs_zcode_work_result_v1;

void boot_zcode_work_progress_context_ready(
    struct vcs_zcode_work_node *work, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const uint8_t secret[32], const uint8_t pubkey[32], int64_t now);
void boot_zcode_work_progress_execution_started(
    struct vcs_zcode_work_node *work, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct db_build_action *action,
    const uint8_t secret[32], const uint8_t pubkey[32]);
void boot_zcode_work_progress_observe(
    struct vcs_zcode_work_node *work, int64_t now);
bool boot_zcode_work_result_observe(
    struct node_db *ndb, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result,
    const char *fallback_workspace, int64_t now, char receipt_id[65]);

#endif /* ZCL_CONFIG_BOOT_ZCODE_WORK_PROGRESS_H */
