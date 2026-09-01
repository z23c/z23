/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic named-profile expansion for the C23 product loop. */

#include "vcs/zcode_dev_product.h"

#include <string.h>

static void zdev_product_base(struct vcs_zcode_dev_profile *out,
                              const char *name)
{
    memset(out, 0, sizeof(*out));
    out->name = name;
    out->policy.schema_version = VCS_ZCODE_DEV_VERSION;
    out->policy.maximum_proof_age_seconds = 86400;
}

static void zdev_product_quick(struct vcs_zcode_dev_profile *out)
{
    zdev_product_base(out, "quick");
    out->policy.required_proofs =
        VCS_ZCODE_PROOF_COMPILE | VCS_ZCODE_PROOF_TEST;
    out->policy.minimum_compile_receipts = 1;
    out->policy.minimum_test_receipts = 1;
    out->policy.minimum_matching_receipts = 1;
    out->policy.maximum_proof_age_seconds = 3600;
}

static void zdev_product_standard(struct vcs_zcode_dev_profile *out)
{
    zdev_product_base(out, "standard");
    out->policy.required_proofs =
        VCS_ZCODE_PROOF_COMPILE | VCS_ZCODE_PROOF_TEST;
    out->policy.minimum_compile_receipts = 2;
    out->policy.minimum_test_receipts = 2;
    out->policy.minimum_matching_receipts = 1;
    out->warning_fatal = true;
    out->sanitizers = true;
}

static void zdev_product_strong(struct vcs_zcode_dev_profile *out)
{
    zdev_product_standard(out);
    out->name = "strong";
    out->policy.required_proofs |=
        VCS_ZCODE_PROOF_FUZZ | VCS_ZCODE_PROOF_LOCAL_REPRODUCTION;
    out->policy.minimum_fuzz_receipts = 1;
    out->policy.minimum_matching_receipts = 2;
    out->policy.deterministic_fuzz_seeds = 64;
    out->policy.audit_basis_points = 100;
    out->deterministic_fuzz = true;
    out->local_reproduction = true;
}

static void zdev_product_release(struct vcs_zcode_dev_profile *out)
{
    zdev_product_strong(out);
    out->name = "release";
    out->policy.required_proofs |= VCS_ZCODE_PROOF_REVIEW;
    out->policy.minimum_reviews = 1;
    out->policy.flags = VCS_ZCODE_POLICY_INDEPENDENT_SIGNERS |
                        VCS_ZCODE_POLICY_RELEASE_BYTE_IDENTITY;
    out->policy.audit_basis_points = 1000;
    out->policy.maximum_proof_age_seconds = 604800;
    out->separate_review = true;
    out->approved_reproduction = true;
}

bool vcs_zcode_dev_profile_expand(
    const char *name, struct vcs_zcode_dev_profile *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!name) return false;
    if (strcmp(name, "quick") == 0)
        zdev_product_quick(out);
    else if (strcmp(name, "standard") == 0)
        zdev_product_standard(out);
    else if (strcmp(name, "strong") == 0)
        zdev_product_strong(out);
    else if (strcmp(name, "release") == 0)
        zdev_product_release(out);
    else
        return false;
    if (vcs_zcode_proof_policy_validate(&out->policy) == VCS_ZCODE_DEV_OK)
        return true;
    memset(out, 0, sizeof(*out));
    return false;
}
