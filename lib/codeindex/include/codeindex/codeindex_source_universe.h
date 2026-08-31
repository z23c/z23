/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Read-only, fail-closed observation of source-universe evidence. */
#ifndef ZCL_CODEINDEX_SOURCE_UNIVERSE_H
#define ZCL_CODEINDEX_SOURCE_UNIVERSE_H

#include "ontology/ontology.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum ci_source_universe_component_id {
    CI_SOURCE_COMPONENT_VCS_MANIFEST = 0,
    CI_SOURCE_COMPONENT_CODE_MERKLE = 1,
    CI_SOURCE_COMPONENT_CAPABILITY_INVENTORY = 2,
    CI_SOURCE_COMPONENT_SCIENCE_CENSUS = 3,
    CI_SOURCE_COMPONENT_COUNT = 4,
};

enum ci_source_universe_root_domain {
    CI_SOURCE_ROOT_NONE = 0,
    CI_SOURCE_ROOT_VCS_MANIFEST_V1 = 1,
    CI_SOURCE_ROOT_CODE_MERKLE_V1 = 2,
    CI_SOURCE_ROOT_CAPABILITY_INVENTORY_V1 = 3,
};

enum ci_source_universe_refusal {
    CI_SOURCE_UNIVERSE_REFUSAL_NONE = 0,
    CI_SOURCE_UNIVERSE_REFUSAL_CAPTURE_FAILED = 1,
    CI_SOURCE_UNIVERSE_REFUSAL_EVIDENCE_DISAGREES = 2,
    CI_SOURCE_UNIVERSE_REFUSAL_INVENTORY_STALE = 3,
    CI_SOURCE_UNIVERSE_REFUSAL_PROJECTIONS_UNPROVEN = 4,
    CI_SOURCE_UNIVERSE_REFUSAL_PROJECTIONS_MISSING = 5,
};

struct ci_source_universe_component {
    bool observed;
    bool scope_complete;
    bool whole_scan_stable;
    bool root_available;
    bool byte_count_available;
    enum ci_source_universe_root_domain root_domain;
    uint64_t path_count;
    uint64_t total_bytes;
    uint8_t root[32];
};

struct ci_source_universe_reconcile_input {
    struct ci_source_universe_component components[CI_SOURCE_COMPONENT_COUNT];
    bool inventory_artifact_present;
    uint64_t inventory_artifact_files;
    bool inventory_artifact_root_available;
    enum ci_source_universe_root_domain inventory_artifact_root_domain;
    uint8_t inventory_artifact_root[32];
    uint32_t projection_observed_mask;
    uint32_t projection_unavailable_mask;
};

struct ci_source_universe_observation {
    struct ci_source_universe_component components[CI_SOURCE_COMPONENT_COUNT];
    bool all_components_observed;
    bool evidence_nonempty;
    bool evidence_counts_agree;
    bool evidence_bytes_agree;
    bool component_roots_well_formed;
    bool same_domain_roots_compared;
    bool same_domain_roots_agree;
    bool inventory_artifact_present;
    bool inventory_artifact_count_agrees;
    bool inventory_artifact_root_agrees;
    bool inventory_fresh;
    uint32_t projection_observed_mask;
    uint32_t projection_proven_mask;
    uint32_t projection_unavailable_mask;
    uint32_t projection_missing_mask;
    bool projection_masks_consistent;
    bool complete;
    bool verified;
    enum ci_source_universe_refusal refusal;
};

/* Reconcile already-observed evidence. Same-domain roots may prove a
 * contradiction, but equality is diagnostic and never proves an exact path
 * projection. This API accepts no proof bit or projection root, so it cannot
 * mint or verify a zcl.source_universe.v1 object. */
bool ci_source_universe_reconcile(
    const struct ci_source_universe_reconcile_input *input,
    struct ci_source_universe_observation *out);

/* Capture four live, independent candidate readings without a VCS index,
 * codeindex snapshot, shell command, or source-universe root. The scanners
 * have different scopes and no whole-scan mutation token, so live components
 * report scope_complete=false and whole_scan_stable=false. No exact
 * projection is reported observed. Unsupported capture returns false with
 * `out` zeroed. `inventory_path` may be NULL or absent. */
bool ci_source_universe_observe(
    const char *root, const char *inventory_path,
    struct ci_source_universe_observation *out);

const char *ci_source_universe_component_name(
    enum ci_source_universe_component_id component);
const char *ci_source_universe_component_scope_name(
    enum ci_source_universe_component_id component);
const char *ci_source_universe_root_domain_name(
    enum ci_source_universe_root_domain domain);
const char *ci_source_universe_projection_name(uint32_t projection_bit);
const char *ci_source_universe_refusal_name(
    enum ci_source_universe_refusal refusal);

#endif /* ZCL_CODEINDEX_SOURCE_UNIVERSE_H */
