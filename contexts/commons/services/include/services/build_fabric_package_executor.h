/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Closed recipe-derived package execution boundary for ZBuild workers. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_PACKAGE_EXECUTOR_H
#define ZCL_SERVICES_BUILD_FABRIC_PACKAGE_EXECUTOR_H

#include "util/result.h"
#include "vcs/package_build.h"
#include "vcs/package_deps.h"
#include "vcs/zcode_dev.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BUILD_FABRIC_PACKAGE_PATH_MAX 4096

struct build_fabric_package_execution {
    struct vcs_package_lock lock;
    char dep_dirs[VCS_PACKAGE_BUILD_MAX_DEPS][BUILD_FABRIC_PACKAGE_PATH_MAX];
    size_t dep_count;
    const char *argv[12u + VCS_PACKAGE_BUILD_MAX_DEPS];
    char source_root_hex[65];
    char source_arg[BUILD_FABRIC_PACKAGE_PATH_MAX + 32];
    char recipe_arg[BUILD_FABRIC_PACKAGE_PATH_MAX + 32];
    char name_arg[VCS_PACKAGE_RELEASE_NAME_MAX + 32u];
    char profile_arg[64];
    char cpu_arg[64];
    char emit_arg[BUILD_FABRIC_PACKAGE_PATH_MAX + 16];
    char lock_arg[96];
    char dep_args[VCS_PACKAGE_BUILD_MAX_DEPS]
                 [BUILD_FABRIC_PACKAGE_PATH_MAX + 96u];
};

struct zcl_result build_fabric_package_prepare(
    const char *workspace, const char *datadir, const char *worker,
    const char *source_dir, const char *emit_dir, const char *recipe_path,
    const char *profile,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    struct build_fabric_package_execution *out);

struct zcl_result build_fabric_package_report_parse(
    const uint8_t *wire, size_t wire_len, const char *emit_dir,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct build_fabric_package_execution *execution,
    uint8_t *work_status, int *exit_status);

#endif /* ZCL_SERVICES_BUILD_FABRIC_PACKAGE_EXECUTOR_H */
