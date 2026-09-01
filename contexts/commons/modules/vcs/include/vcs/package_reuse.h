/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_reuse — pure, deterministic reuse ranking over package-index facts.
 * It owns no store, network, task, model, build, or acceptance authority. */

#ifndef ZCL_VCS_PACKAGE_REUSE_H
#define ZCL_VCS_PACKAGE_REUSE_H

#include "vcs/package_index.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_REUSE_MAX_INPUTS 256u
#define VCS_PACKAGE_REUSE_MAX_SELECTED 4u
#define VCS_PACKAGE_REUSE_MAX_APIS 16u

struct vcs_package_reuse_input {
    const struct vcs_package_index_entry *package;
    const char *apis[VCS_PACKAGE_REUSE_MAX_APIS];
    size_t api_count;
    bool locked;
    bool installed;
    bool compatible;
};

struct vcs_package_reuse_selection {
    size_t input_index;
    uint32_t score;
};

enum vcs_package_reuse_disposition {
    VCS_PACKAGE_REUSE_NONE = 0,
    VCS_PACKAGE_REUSE_PARTIAL,
    VCS_PACKAGE_REUSE_COMPLETE,
    VCS_PACKAGE_REUSE_AMBIGUOUS,
    VCS_PACKAGE_REUSE_INCOMPATIBLE,
};

struct vcs_package_reuse_plan {
    struct vcs_package_reuse_selection
        selected[VCS_PACKAGE_REUSE_MAX_SELECTED];
    size_t selected_count;
    size_t packages_scanned;
    size_t compatible_matches;
    size_t incompatible_matches;
    bool exact_request;
    bool requested_version;
    bool new_code_required;
    enum vcs_package_reuse_disposition disposition;
};

/* Rank exact local package/API facts against one plain-language goal. Inputs
 * may be in any order; output ties are byte-stable by package identity.
 * "use <package>[@version]" (or the exact package/basename alone) is the
 * deliberately narrow grammar that may prove COMPLETE reuse. Broader text is
 * advisory PARTIAL reuse and never claims that arbitrary behavior exists. */
bool vcs_package_reuse_plan_build(
    const char *goal, const struct vcs_package_reuse_input *inputs,
    size_t input_count, struct vcs_package_reuse_plan *out);

const char *vcs_package_reuse_disposition_string(
    enum vcs_package_reuse_disposition disposition);

#endif /* ZCL_VCS_PACKAGE_REUSE_H */
