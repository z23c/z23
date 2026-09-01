/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_repo_priv — private declarations shared between vcs.c and
 * vcs_revert.c. NOT a public header: only these two translation units
 * include it. Holds the concrete struct vcs_repo definition (opaque in the
 * public vcs/vcs.h) and the two manifest/commit loaders vcs_revert() needs
 * that stay defined in vcs.c because vcs_tree_load(), tree_capture_from(),
 * and vcs_status() also call them from there. */
#ifndef ZCL_VCS_REPO_PRIV_H
#define ZCL_VCS_REPO_PRIV_H

#include "vcs/vcs_commit.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_manifest.h"

#include "storage/event_log.h"

#include <stdbool.h>
#include <stdint.h>

#define VCS_FA_PATH_MAX 4096

struct vcs_repo {
    char              root[VCS_FA_PATH_MAX];
    struct vcs_index *idx;
    event_log_t      *log;
};

/* Defined in vcs.c. Loads the manifest object addressed by tree_hash and
 * rederives tree_hash from its parsed content before returning it
 * (recompute-never-trust); a mismatch is treated as store corruption. */
bool manifest_load(const char *repo, const uint8_t tree_hash[32],
                   struct vcs_manifest *out);

/* Defined in vcs.c. Loads and parses the commit preimage object addressed by
 * commit_id. */
bool load_commit_by_id(const char *repo, const uint8_t commit_id[32],
                       struct vcs_commit *out);

#endif /* ZCL_VCS_REPO_PRIV_H */
