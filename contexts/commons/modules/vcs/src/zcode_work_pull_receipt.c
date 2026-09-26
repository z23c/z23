/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Durable signed receipt for one independently verified work pull. */

#include "vcs/zcode_work_pull_receipt.h"

#include "base/bytes.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

const char *vcs_zcode_work_pull_receipt_result_string(
    enum vcs_zcode_work_pull_receipt_result result)
{
    switch (result) {
    case VCS_ZCODE_WORK_PULL_RECEIPT_OK: return "ok";
    case VCS_ZCODE_WORK_PULL_RECEIPT_NULL: return "null-argument";
    case VCS_ZCODE_WORK_PULL_RECEIPT_NOT_VERIFIED: return "not-verified";
    case VCS_ZCODE_WORK_PULL_RECEIPT_NO_POINTER: return "no-pointer-root";
    case VCS_ZCODE_WORK_PULL_RECEIPT_NO_OBSERVER: return "no-observer-key";
    case VCS_ZCODE_WORK_PULL_RECEIPT_TIME: return "bad-observation-time";
    case VCS_ZCODE_WORK_PULL_RECEIPT_SEAL: return "seal-refused";
    case VCS_ZCODE_WORK_PULL_RECEIPT_STORE: return "store-failed";
    case VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND: return "not-found";
    case VCS_ZCODE_WORK_PULL_RECEIPT_CODEC: return "not-canonical";
    case VCS_ZCODE_WORK_PULL_RECEIPT_ROOT_MISMATCH: return "root-mismatch";
    case VCS_ZCODE_WORK_PULL_RECEIPT_SIGNATURE: return "signature-refused";
    case VCS_ZCODE_WORK_PULL_RECEIPT_NOT_PULL: return "not-a-pull-receipt";
    case VCS_ZCODE_WORK_PULL_RECEIPT_NOT_HELD: return "package-not-held";
    case VCS_ZCODE_WORK_PULL_RECEIPT_CONTRADICTED: return "contradicted";
    }
    return "unknown";
}

bool vcs_zcode_work_pull_action_root(const uint8_t task_root[32],
                                     const uint8_t package_root[32],
                                     uint8_t out[32])
{
    if (!task_root || !package_root || !out)
        return false;
    static const char domain[] = VCS_ZCODE_WORK_PULL_ACTION_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, task_root, 32);
    sha3_256_write(&sha, package_root, 32);
    sha3_256_finalize(&sha, out);
    return true;
}

static void pull_confinement_root(uint8_t out[32])
{
    static const char statement[] = VCS_ZCODE_WORK_PULL_CONFINEMENT;
    sha3_256((const uint8_t *)statement, sizeof(statement) - 1u, out);
}

/* Every bound root plus the observer key; never the times or signature,
 * so the same observer verifying the same roots finds its first receipt. */
static void pull_locator(const struct vcs_zcode_work_receipt_v1 *r,
                         uint8_t out[32])
{
    static const char domain[] = VCS_ZCODE_WORK_PULL_LOCATOR_DOMAIN;
    const uint8_t *roots[] = {
        r->task_root, r->candidate_root, r->action_root, r->input_root,
        r->output_root, r->proof_policy_root, r->toolchain_capsule_root,
        r->lease_id, r->evidence_root, r->confinement_root,
        r->signer_pubkey,
    };
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        sha3_256_write(&sha, roots[i], 32);
    sha3_256_finalize(&sha, out);
}

enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_receipt_check(
    const struct vcs_zcode_work_receipt_v1 *r)
{
    if (!r)
        return VCS_ZCODE_WORK_PULL_RECEIPT_NULL;
    if (vcs_zcode_work_receipt_verify(r, r->signer_pubkey) !=
        VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_WORK_PULL_RECEIPT_SIGNATURE;
    uint8_t action[32], confinement[32];
    (void)vcs_zcode_work_pull_action_root(r->task_root, r->input_root,
                                          action);
    pull_confinement_root(confinement);
    bool shape = r->work_kind == VCS_ZCODE_WORK_REPRODUCE &&
        r->status == VCS_ZCODE_WORK_PASS && r->exit_status == 0 &&
        memcmp(r->action_root, action, 32) == 0 &&
        memcmp(r->confinement_root, confinement, 32) == 0;
    return shape ? VCS_ZCODE_WORK_PULL_RECEIPT_OK
                 : VCS_ZCODE_WORK_PULL_RECEIPT_NOT_PULL;
}

enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_receipt_decode(
    const uint8_t *wire, size_t wire_len, const uint8_t expected_root[32],
    struct vcs_zcode_work_receipt_v1 *out, uint8_t root_out[32])
{
    if (!wire || !out || !root_out)
        return VCS_ZCODE_WORK_PULL_RECEIPT_NULL;
    memset(root_out, 0, 32);
    struct vcs_zcode_work_receipt_v1 parsed;
    uint8_t root[32];
    enum vcs_zcode_work_pull_receipt_result result =
        VCS_ZCODE_WORK_PULL_RECEIPT_CODEC;
    if (vcs_zcode_work_receipt_parse(wire, wire_len, &parsed) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_id(&parsed, root) == VCS_ZCODE_DEV_OK)
        result = expected_root && memcmp(root, expected_root, 32) != 0
            ? VCS_ZCODE_WORK_PULL_RECEIPT_ROOT_MISMATCH
            : vcs_zcode_work_pull_receipt_check(&parsed);
    if (result != VCS_ZCODE_WORK_PULL_RECEIPT_OK) {
        memset(out, 0, sizeof(*out));
        return result;
    }
    *out = parsed;
    memcpy(root_out, root, 32);
    return VCS_ZCODE_WORK_PULL_RECEIPT_OK;
}

/* Raw bounded read at any address, then decode. The address is either the
 * receipt root itself or its locator; the caller supplies what to expect. */
static enum vcs_zcode_work_pull_receipt_result pull_read(
    const char *workspace, const uint8_t address[32],
    const uint8_t expected_root[32], struct vcs_zcode_work_receipt_v1 *out,
    uint8_t root_out[32])
{
    uint8_t *wire = NULL;
    size_t len = 0;
    memset(out, 0, sizeof(*out));
    memset(root_out, 0, 32);
    if (!vcs_object_has(workspace, address))
        return VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND;
    if (vcs_object_load_raw_bounded(
            workspace, address, VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES, &wire,
            &len) != 0)
        return VCS_ZCODE_WORK_PULL_RECEIPT_CODEC;
    enum vcs_zcode_work_pull_receipt_result result =
        vcs_zcode_work_pull_receipt_decode(wire, len, expected_root, out,
                                           root_out);
    free(wire);
    return result;
}

enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_receipt_load(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_work_receipt_v1 *out)
{
    if (!workspace || !workspace[0] || !root || !out)
        return VCS_ZCODE_WORK_PULL_RECEIPT_NULL;
    uint8_t checked[32];
    return pull_read(workspace, root, root, out, checked);
}

enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_receipt_reverify(
    struct vcs_package_store *store,
    const struct vcs_zcode_work_receipt_v1 *r)
{
    if (!store || !r)
        return VCS_ZCODE_WORK_PULL_RECEIPT_NULL;
    uint8_t source[32], accepted[32];
    struct vcs_source_package_checkout_metrics metrics;
    enum vcs_zcode_work_admit_result admit =
        vcs_zcode_work_solution_admit_metrics(
            store, r->input_root, r->task_root, source, accepted, &metrics);
    if (admit == VCS_ZCODE_WORK_ADMIT_NOT_RECONSTRUCTIBLE ||
        admit == VCS_ZCODE_WORK_ADMIT_NULL)
        return VCS_ZCODE_WORK_PULL_RECEIPT_NOT_HELD;
    bool same = admit == VCS_ZCODE_WORK_ADMIT_OK &&
        memcmp(source, r->output_root, 32) == 0 &&
        memcmp(accepted, r->evidence_root, 32) == 0 &&
        memcmp(metrics.candidate_root, r->candidate_root, 32) == 0 &&
        memcmp(metrics.proof_policy_root, r->proof_policy_root, 32) == 0 &&
        memcmp(metrics.toolchain_capsule_root, r->toolchain_capsule_root,
               32) == 0;
    return same ? VCS_ZCODE_WORK_PULL_RECEIPT_OK
                : VCS_ZCODE_WORK_PULL_RECEIPT_CONTRADICTED;
}

/* The receipt body every observation of these roots shares; times and the
 * signature are added only when a new receipt is minted. */
static void pull_template(const struct vcs_zcode_work_pull_observation *io,
                          const struct vcs_source_package_checkout_metrics *m,
                          const uint8_t observer_pubkey[32],
                          struct vcs_zcode_work_receipt_v1 *r)
{
    memset(r, 0, sizeof(*r));
    r->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(r->task_root, io->task_root, 32);
    memcpy(r->candidate_root, m->candidate_root, 32);
    (void)vcs_zcode_work_pull_action_root(io->task_root, io->package_root,
                                          r->action_root);
    memcpy(r->input_root, io->package_root, 32);
    memcpy(r->output_root, io->source_root, 32);
    memcpy(r->proof_policy_root, m->proof_policy_root, 32);
    memcpy(r->toolchain_capsule_root, m->toolchain_capsule_root, 32);
    memcpy(r->lease_id, io->pointer_root, 32);
    memcpy(r->evidence_root, io->accepted_work_root, 32);
    pull_confinement_root(r->confinement_root);
    r->work_kind = VCS_ZCODE_WORK_REPRODUCE;
    r->status = VCS_ZCODE_WORK_PASS;
    r->exit_status = 0;
    memcpy(r->signer_pubkey, observer_pubkey, 32);
}

/* A stored receipt at the locator answers for this observation only when
 * it verifies and binds exactly the template's roots and observer. */
static bool pull_matches(const struct vcs_zcode_work_receipt_v1 *stored,
                         const uint8_t locator[32])
{
    uint8_t derived[32];
    pull_locator(stored, derived);
    return memcmp(derived, locator, 32) == 0;
}

static enum vcs_zcode_work_pull_receipt_result pull_attach(
    const char *workspace, const uint8_t locator[32],
    struct vcs_zcode_work_pull_observation *io, bool *locator_invalid)
{
    struct vcs_zcode_work_receipt_v1 stored;
    uint8_t root[32], wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    enum vcs_zcode_work_pull_receipt_result read =
        pull_read(workspace, locator, NULL, &stored, root);
    *locator_invalid = read != VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND &&
        (read != VCS_ZCODE_WORK_PULL_RECEIPT_OK ||
         !pull_matches(&stored, locator));
    if (read != VCS_ZCODE_WORK_PULL_RECEIPT_OK || *locator_invalid)
        return VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND;
    /* Keep the canonical copy addressable by its own root. */
    struct vcs_zcode_work_receipt_v1 canonical;
    if (vcs_zcode_work_receipt_serialize(&stored, wire) !=
            VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(workspace, root, wire, sizeof(wire)) ||
        vcs_zcode_work_pull_receipt_load(workspace, root, &canonical) !=
            VCS_ZCODE_WORK_PULL_RECEIPT_OK)
        return VCS_ZCODE_WORK_PULL_RECEIPT_STORE;
    io->receipt = stored;
    memcpy(io->receipt_root, root, 32);
    return VCS_ZCODE_WORK_PULL_RECEIPT_OK;
}

static enum vcs_zcode_work_pull_receipt_result pull_mint(
    const char *workspace, const uint8_t locator[32], bool locator_invalid,
    const uint8_t observer_secret[32],
    struct vcs_zcode_work_pull_observation *io,
    struct vcs_zcode_work_receipt_v1 *r)
{
    r->started_unix = io->started_unix;
    r->finished_unix = io->observed_unix;
    uint8_t root[32], wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    uint8_t pubkey[32];
    memcpy(pubkey, r->signer_pubkey, 32);
    if (vcs_zcode_work_receipt_seal(r, observer_secret, pubkey) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_pull_receipt_check(r) !=
            VCS_ZCODE_WORK_PULL_RECEIPT_OK ||
        vcs_zcode_work_receipt_serialize(r, wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_id(r, root) != VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_WORK_PULL_RECEIPT_SEAL;
    static const char statement[] = VCS_ZCODE_WORK_PULL_CONFINEMENT;
    bool repaired = false;
    struct vcs_zcode_work_receipt_v1 checked;
    bool stored =
        vcs_object_put_addressed(workspace, r->confinement_root,
                                 (const uint8_t *)statement,
                                 sizeof(statement) - 1u) &&
        vcs_object_put_addressed(workspace, root, wire, sizeof(wire)) &&
        vcs_zcode_work_pull_receipt_load(workspace, root, &checked) ==
            VCS_ZCODE_WORK_PULL_RECEIPT_OK &&
        (locator_invalid
             ? vcs_object_put_addressed_repair(workspace, locator, wire,
                                               sizeof(wire), &repaired)
             : vcs_object_put_addressed(workspace, locator, wire,
                                        sizeof(wire)));
    if (!stored)
        return VCS_ZCODE_WORK_PULL_RECEIPT_STORE;
    /* A concurrent pull may have won the locator: adopt its receipt so
     * every caller reports the one observation the locator names. */
    bool invalid = false;
    if (pull_attach(workspace, locator, io, &invalid) ==
            VCS_ZCODE_WORK_PULL_RECEIPT_OK) {
        io->attached = memcmp(io->receipt_root, root, 32) != 0;
        return VCS_ZCODE_WORK_PULL_RECEIPT_OK;
    }
    return VCS_ZCODE_WORK_PULL_RECEIPT_STORE;
}

static enum vcs_zcode_work_pull_receipt_result pull_observe_clear(
    struct vcs_zcode_work_pull_observation *io,
    enum vcs_zcode_work_pull_receipt_result result)
{
    memset(&io->receipt, 0, sizeof(io->receipt));
    memset(io->receipt_root, 0, 32);
    io->attached = false;
    return result;
}

enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_observe(
    struct vcs_package_store *store, const char *workspace,
    const uint8_t observer_secret[32], const uint8_t observer_pubkey[32],
    struct vcs_zcode_work_pull_observation *io)
{
    if (!io)
        return VCS_ZCODE_WORK_PULL_RECEIPT_NULL;
    (void)pull_observe_clear(io, VCS_ZCODE_WORK_PULL_RECEIPT_OK);
    struct vcs_source_package_checkout_metrics metrics;
    io->admit = vcs_zcode_work_solution_admit_metrics(
        store, io->package_root, io->task_root, io->source_root,
        io->accepted_work_root, &metrics);
    if (io->admit != VCS_ZCODE_WORK_ADMIT_OK)
        return VCS_ZCODE_WORK_PULL_RECEIPT_NOT_VERIFIED;
    if (!observer_secret || !observer_pubkey || !workspace || !workspace[0])
        return VCS_ZCODE_WORK_PULL_RECEIPT_NO_OBSERVER;
    if (!zcl_bytes_any_set(io->pointer_root, 32))
        return VCS_ZCODE_WORK_PULL_RECEIPT_NO_POINTER;
    if (io->started_unix <= 0 || io->observed_unix < io->started_unix)
        return VCS_ZCODE_WORK_PULL_RECEIPT_TIME;
    struct vcs_zcode_work_receipt_v1 r;
    pull_template(io, &metrics, observer_pubkey, &r);
    uint8_t locator[32];
    pull_locator(&r, locator);
    if (!vcs_object_store_init(workspace))
        return VCS_ZCODE_WORK_PULL_RECEIPT_STORE;
    bool locator_invalid = false;
    enum vcs_zcode_work_pull_receipt_result result =
        pull_attach(workspace, locator, io, &locator_invalid);
    if (result == VCS_ZCODE_WORK_PULL_RECEIPT_OK) {
        io->attached = true;
        return result;
    }
    if (result != VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND)
        return pull_observe_clear(io, result);
    result = pull_mint(workspace, locator, locator_invalid, observer_secret,
                       io, &r);
    return result == VCS_ZCODE_WORK_PULL_RECEIPT_OK
        ? result : pull_observe_clear(io, result);
}
