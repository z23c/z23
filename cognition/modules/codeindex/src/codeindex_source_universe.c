/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Read-only reconciliation of independent source-universe evidence. */

#include "codeindex/codeindex_source_universe.h"

#include "base/log_macros.h"
#include "codeindex/codeindex_inventory.h"
#include "codeindex/codeindex_merkle.h"
#include "science/science_corpus.h"
#include "vcs/vcs_manifest.h"

#include <limits.h>
#include <string.h>

static bool universe_root_nonzero(const uint8_t root[32])
{
    if (!root) return false;
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

static bool universe_root_domain_valid(
    enum ci_source_universe_root_domain domain)
{
    return domain >= CI_SOURCE_ROOT_NONE &&
           domain <= CI_SOURCE_ROOT_CAPABILITY_INVENTORY_V1;
}

static bool universe_components_observed(
    const struct ci_source_universe_reconcile_input *input)
{
    for (size_t i = 0; i < CI_SOURCE_COMPONENT_COUNT; i++)
        if (!input->components[i].observed) return false;
    return true;
}

static bool universe_counts_agree(
    const struct ci_source_universe_reconcile_input *input)
{
    const uint64_t expected = input->components[0].path_count;
    for (size_t i = 1; i < CI_SOURCE_COMPONENT_COUNT; i++)
        if (input->components[i].path_count != expected) return false;
    return true;
}

static bool universe_evidence_nonempty(
    const struct ci_source_universe_reconcile_input *input)
{
    for (size_t i = 0; i < CI_SOURCE_COMPONENT_COUNT; i++)
        if (input->components[i].path_count == 0) return false;
    return true;
}

static bool universe_bytes_agree(
    const struct ci_source_universe_reconcile_input *input)
{
    bool have_expected = false;
    uint64_t expected = 0;
    for (size_t i = 0; i < CI_SOURCE_COMPONENT_COUNT; i++) {
        const struct ci_source_universe_component *component =
            &input->components[i];
        if (!component->byte_count_available) continue;
        if (!have_expected) {
            expected = component->total_bytes;
            have_expected = true;
        } else if (component->total_bytes != expected) {
            return false;
        }
    }
    return have_expected;
}

static bool universe_roots_well_formed(
    const struct ci_source_universe_reconcile_input *input)
{
    for (size_t i = 0; i < CI_SOURCE_COMPONENT_COUNT; i++) {
        const struct ci_source_universe_component *component =
            &input->components[i];
        const bool described = component->root_domain != CI_SOURCE_ROOT_NONE;
        const bool nonzero = universe_root_nonzero(component->root);
        if (!universe_root_domain_valid(component->root_domain) ||
            component->root_available != described || described != nonzero ||
            (!component->byte_count_available && component->total_bytes != 0))
            return false;
    }
    return true;
}

struct universe_root_comparison {
    bool compared;
    bool agree;
};

static struct universe_root_comparison universe_compare_same_domain_roots(
    const struct ci_source_universe_reconcile_input *input)
{
    struct universe_root_comparison result = { false, true };
    for (size_t i = 0; i < CI_SOURCE_COMPONENT_COUNT; i++) {
        const struct ci_source_universe_component *left =
            &input->components[i];
        if (!left->root_available) continue;
        for (size_t j = i + 1; j < CI_SOURCE_COMPONENT_COUNT; j++) {
            const struct ci_source_universe_component *right =
                &input->components[j];
            if (!right->root_available ||
                left->root_domain != right->root_domain)
                continue;
            result.compared = true;
            if (memcmp(left->root, right->root, 32) != 0)
                result.agree = false;
        }
    }
    return result;
}

static enum ci_source_universe_refusal universe_refusal(
    const struct ci_source_universe_observation *out)
{
    if (!out->all_components_observed)
        return CI_SOURCE_UNIVERSE_REFUSAL_CAPTURE_FAILED;
    if (!out->evidence_nonempty || !out->evidence_counts_agree ||
        !out->evidence_bytes_agree || !out->component_roots_well_formed ||
        !out->projection_masks_consistent ||
        (out->same_domain_roots_compared && !out->same_domain_roots_agree))
        return CI_SOURCE_UNIVERSE_REFUSAL_EVIDENCE_DISAGREES;
    if (!out->inventory_fresh)
        return CI_SOURCE_UNIVERSE_REFUSAL_INVENTORY_STALE;
    if (out->projection_unavailable_mask != 0)
        return CI_SOURCE_UNIVERSE_REFUSAL_PROJECTIONS_MISSING;
    if (out->projection_missing_mask != 0)
        return CI_SOURCE_UNIVERSE_REFUSAL_PROJECTIONS_UNPROVEN;
    return CI_SOURCE_UNIVERSE_REFUSAL_NONE;
}

bool ci_source_universe_reconcile(
    const struct ci_source_universe_reconcile_input *input,
    struct ci_source_universe_observation *out)
{
    if (!out)
        LOG_FAIL("codeindex.source_universe", "reconcile needs output");
    memset(out, 0, sizeof(*out));
    if (!input)
        LOG_FAIL("codeindex.source_universe", "reconcile needs input");

    memcpy(out->components, input->components, sizeof(out->components));
    out->all_components_observed = universe_components_observed(input);
    out->evidence_nonempty = out->all_components_observed &&
                             universe_evidence_nonempty(input);
    out->evidence_counts_agree = out->all_components_observed &&
                                 universe_counts_agree(input);
    out->evidence_bytes_agree = out->all_components_observed &&
                                universe_bytes_agree(input);
    out->component_roots_well_formed = out->all_components_observed &&
                                       universe_roots_well_formed(input);
    const struct universe_root_comparison roots =
        universe_compare_same_domain_roots(input);
    out->same_domain_roots_compared = roots.compared;
    out->same_domain_roots_agree = roots.compared && roots.agree;

    out->inventory_artifact_present = input->inventory_artifact_present;
    const struct ci_source_universe_component *inventory =
        &input->components[CI_SOURCE_COMPONENT_CAPABILITY_INVENTORY];
    out->inventory_artifact_count_agrees =
        input->inventory_artifact_present && inventory->observed &&
        input->inventory_artifact_files == inventory->path_count;
    out->inventory_artifact_root_agrees =
        input->inventory_artifact_root_available && inventory->root_available &&
        input->inventory_artifact_root_domain == inventory->root_domain &&
        universe_root_nonzero(input->inventory_artifact_root) &&
        universe_root_nonzero(inventory->root) &&
        memcmp(input->inventory_artifact_root, inventory->root, 32) == 0;
    out->inventory_fresh = out->inventory_artifact_count_agrees &&
                           out->inventory_artifact_root_agrees;

    out->projection_observed_mask =
        input->projection_observed_mask & ZCL_SOURCE_COVER_ALL;
    /* This observer has no canonical producer for any of the seven exact
     * projection roots. Never accept a Boolean assertion as proof. */
    out->projection_proven_mask = 0;
    out->projection_unavailable_mask =
        input->projection_unavailable_mask & ZCL_SOURCE_COVER_ALL;
    out->projection_missing_mask = ZCL_SOURCE_COVER_ALL;
    out->projection_masks_consistent =
        ((input->projection_observed_mask |
          input->projection_unavailable_mask) & ~ZCL_SOURCE_COVER_ALL) == 0 &&
        (out->projection_observed_mask & out->projection_unavailable_mask) == 0;

    out->refusal = universe_refusal(out);
    out->complete = false;
    out->verified = false;
    return true;
}

static bool universe_capture_vcs(
    const char *root, struct ci_source_universe_component *component)
{
    struct vcs_manifest manifest;
    if (!vcs_manifest_build(root, NULL, &manifest))
        LOG_FAIL("codeindex.source_universe", "VCS manifest capture failed");
    bool ok = vcs_manifest_tree_hash(&manifest, component->root);
    uint64_t bytes = 0;
    for (size_t i = 0; ok && i < manifest.count; i++) {
        if (manifest.entries[i].size > UINT64_MAX - bytes) {
            ok = false;
            break;
        }
        bytes += manifest.entries[i].size;
    }
    if (ok) {
        component->observed = true;
        component->root_available = true;
        component->byte_count_available = true;
        component->root_domain = CI_SOURCE_ROOT_VCS_MANIFEST_V1;
        component->path_count = (uint64_t)manifest.count;
        component->total_bytes = bytes;
    }
    vcs_manifest_free(&manifest);
    if (!ok)
        LOG_FAIL("codeindex.source_universe", "VCS manifest identity failed");
    return true;
}

static bool universe_capture_merkle(
    const char *root, struct ci_source_universe_component *component)
{
    struct ci_merkle_cost cost;
    struct ci_merkle *merkle = ci_merkle_build_cold(root, &cost);
    if (!merkle)
        LOG_FAIL("codeindex.source_universe", "cold code Merkle capture failed");
    struct ci_merkle_node node;
    const bool ok = ci_merkle_root(merkle, &node);
    if (ok) {
        component->observed = true;
        component->root_available = true;
        component->byte_count_available = true;
        component->root_domain = CI_SOURCE_ROOT_CODE_MERKLE_V1;
        component->path_count = node.file_count;
        component->total_bytes = node.total_bytes;
        memcpy(component->root, node.digest.bytes, 32);
    }
    ci_merkle_free(merkle);
    if (!ok)
        LOG_FAIL("codeindex.source_universe", "cold code Merkle root failed");
    return true;
}

static bool universe_capture_inventory(
    const char *root, struct ci_source_universe_component *component)
{
    struct ci_inventory_report *inventory =
        codeindex_inventory_analyze(root);
    if (!inventory)
        LOG_FAIL("codeindex.source_universe", "capability inventory failed");
    if (inventory->files_scanned < 0) {
        codeindex_inventory_free(inventory);
        LOG_FAIL("codeindex.source_universe", "negative inventory file count");
    }
    component->observed = true;
    component->root_available = true;
    component->root_domain = CI_SOURCE_ROOT_CAPABILITY_INVENTORY_V1;
    component->path_count = (uint64_t)inventory->files_scanned;
    memcpy(component->root, inventory->source_root_sha3, 32);
    codeindex_inventory_free(inventory);
    return true;
}

static bool universe_capture_census(
    const char *root, const char *inventory_path,
    struct ci_source_universe_component *component,
    struct science_corpus_report *report)
{
    if (!science_corpus_measure(root, inventory_path, report))
        LOG_FAIL("codeindex.source_universe", "science census failed");
    component->observed = true;
    component->byte_count_available = true;
    component->path_count = report->files_walked;
    component->total_bytes = report->bytes;
    return true;
}

bool ci_source_universe_observe(
    const char *root, const char *inventory_path,
    struct ci_source_universe_observation *out)
{
    if (!out)
        LOG_FAIL("codeindex.source_universe", "observe needs output");
    memset(out, 0, sizeof(*out));
    if (!root || !root[0])
        LOG_FAIL("codeindex.source_universe", "observe needs source root");

    struct ci_source_universe_reconcile_input input;
    memset(&input, 0, sizeof(input));
    if (!universe_capture_vcs(
            root, &input.components[CI_SOURCE_COMPONENT_VCS_MANIFEST]) ||
        !universe_capture_merkle(
            root, &input.components[CI_SOURCE_COMPONENT_CODE_MERKLE]) ||
        !universe_capture_inventory(
            root,
            &input.components[CI_SOURCE_COMPONENT_CAPABILITY_INVENTORY]))
        LOG_FAIL("codeindex.source_universe", "source evidence capture failed");

    struct science_corpus_report census;
    if (!universe_capture_census(
            root, inventory_path,
            &input.components[CI_SOURCE_COMPONENT_SCIENCE_CENSUS], &census))
        LOG_FAIL("codeindex.source_universe", "census evidence capture failed");

    input.inventory_artifact_present = census.inventory_present;
    input.inventory_artifact_files = census.inventory_files_scanned;
    /* science_corpus deliberately exposes only the artifact's count. A count
     * match is not exact freshness, so the artifact root remains unavailable
     * and reconcile refuses rather than upgrading count equality to proof. */
    input.inventory_artifact_root_available = false;
    /* Each scan is useful candidate evidence, but none implements a canonical
     * source-universe projection or a whole-scan atomicity contract. */
    input.projection_observed_mask = 0;
    input.projection_unavailable_mask =
        ZCL_SOURCE_COVER_ALL;
    return ci_source_universe_reconcile(&input, out);
}

const char *ci_source_universe_component_name(
    enum ci_source_universe_component_id component)
{
    switch (component) {
    case CI_SOURCE_COMPONENT_VCS_MANIFEST: return "vcs_manifest";
    case CI_SOURCE_COMPONENT_CODE_MERKLE: return "code_merkle";
    case CI_SOURCE_COMPONENT_CAPABILITY_INVENTORY:
        return "capability_inventory";
    case CI_SOURCE_COMPONENT_SCIENCE_CENSUS: return "science_census";
    case CI_SOURCE_COMPONENT_COUNT: break;
    }
    return "unknown";
}

const char *ci_source_universe_component_scope_name(
    enum ci_source_universe_component_id component)
{
    switch (component) {
    case CI_SOURCE_COMPONENT_VCS_MANIFEST:
        return "vcs_walk_regular_files_with_ignores.candidate.v1";
    case CI_SOURCE_COMPONENT_CODE_MERKLE:
        return "codeindex_c23_enumeration.candidate.v1";
    case CI_SOURCE_COMPONENT_CAPABILITY_INVENTORY:
        return "capability_inventory_c_h_plus_aux.candidate.v1";
    case CI_SOURCE_COMPONENT_SCIENCE_CENSUS:
        return "science_c_h_census.candidate.v1";
    case CI_SOURCE_COMPONENT_COUNT: break;
    }
    return "unknown";
}

const char *ci_source_universe_root_domain_name(
    enum ci_source_universe_root_domain domain)
{
    switch (domain) {
    case CI_SOURCE_ROOT_NONE: return "unavailable";
    case CI_SOURCE_ROOT_VCS_MANIFEST_V1: return "vcs_manifest_tree_hash";
    case CI_SOURCE_ROOT_CODE_MERKLE_V1:
        return "zcl.codeindex.merkle.node.v1";
    case CI_SOURCE_ROOT_CAPABILITY_INVENTORY_V1:
        return "zcl.code_capability_inventory.source.v1";
    }
    return "unknown";
}

const char *ci_source_universe_projection_name(uint32_t projection_bit)
{
    switch (projection_bit) {
    case ZCL_SOURCE_COVER_GOVERNED: return "governed";
    case ZCL_SOURCE_COVER_GENERATED: return "generated";
    case ZCL_SOURCE_COVER_VENDOR: return "vendor";
    case ZCL_SOURCE_COVER_METADATA: return "metadata";
    case ZCL_SOURCE_COVER_PUBLISHABLE: return "publishable";
    case ZCL_SOURCE_COVER_CONSENSUS: return "consensus";
    case ZCL_SOURCE_COVER_INDEXED: return "indexed";
    default: return "unknown";
    }
}

const char *ci_source_universe_refusal_name(
    enum ci_source_universe_refusal refusal)
{
    switch (refusal) {
    case CI_SOURCE_UNIVERSE_REFUSAL_NONE: return "none";
    case CI_SOURCE_UNIVERSE_REFUSAL_CAPTURE_FAILED: return "capture_failed";
    case CI_SOURCE_UNIVERSE_REFUSAL_EVIDENCE_DISAGREES:
        return "evidence_disagrees";
    case CI_SOURCE_UNIVERSE_REFUSAL_INVENTORY_STALE:
        return "inventory_stale_or_unproved";
    case CI_SOURCE_UNIVERSE_REFUSAL_PROJECTIONS_UNPROVEN:
        return "projections_unproven";
    case CI_SOURCE_UNIVERSE_REFUSAL_PROJECTIONS_MISSING:
        return "projections_missing";
    }
    return "unknown";
}
