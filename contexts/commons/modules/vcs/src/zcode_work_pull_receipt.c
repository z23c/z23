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
    static const char *const names[] = {
        [VCS_ZCODE_WORK_PULL_RECEIPT_OK] = "ok",
        [VCS_ZCODE_WORK_PULL_RECEIPT_NULL] = "null-argument",
        [VCS_ZCODE_WORK_PULL_RECEIPT_NOT_VERIFIED] = "not-verified",
        [VCS_ZCODE_WORK_PULL_RECEIPT_NO_POINTER] = "no-usable-pointer",
        [VCS_ZCODE_WORK_PULL_RECEIPT_POINTER_MISMATCH] =
            "pointer-names-other-roots",
        [VCS_ZCODE_WORK_PULL_RECEIPT_NO_OBSERVER] = "no-observer-key",
        [VCS_ZCODE_WORK_PULL_RECEIPT_TIME] = "bad-observation-time",
        [VCS_ZCODE_WORK_PULL_RECEIPT_SEAL] = "seal-refused",
        [VCS_ZCODE_WORK_PULL_RECEIPT_STORE] = "store-failed",
        [VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND] = "not-found",
        [VCS_ZCODE_WORK_PULL_RECEIPT_CODEC] = "not-canonical",
        [VCS_ZCODE_WORK_PULL_RECEIPT_ROOT_MISMATCH] = "root-mismatch",
        [VCS_ZCODE_WORK_PULL_RECEIPT_SIGNATURE] = "signature-refused",
        [VCS_ZCODE_WORK_PULL_RECEIPT_NOT_PULL] = "not-a-pull-receipt",
        [VCS_ZCODE_WORK_PULL_RECEIPT_NOT_HELD] = "package-not-held",
        [VCS_ZCODE_WORK_PULL_RECEIPT_CONTRADICTED] = "contradicted",
    };
    size_t index = (size_t)result;
    return index < sizeof(names) / sizeof(names[0]) && names[index]
        ? names[index] : "unknown";
}

bool vcs_zcode_work_pull_action_root(const uint8_t task_root[32],
                                     const uint8_t package_root[32],
                                     const uint8_t pointer_root[32],
                                     uint8_t out[32])
{
    if (!task_root || !package_root || !pointer_root || !out)
        return false;
    static const char domain[] = VCS_ZCODE_WORK_PULL_ACTION_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, task_root, 32);
    sha3_256_write(&sha, package_root, 32);
    sha3_256_write(&sha, pointer_root, 32);
    sha3_256_finalize(&sha, out);
    return true;
}

static void pull_confinement_root(uint8_t out[32])
{
    static const char statement[] = VCS_ZCODE_WORK_PULL_CONFINEMENT;
    sha3_256((const uint8_t *)statement, sizeof(statement) - 1u, out);
}

bool vcs_zcode_work_pull_receipt_claims_pull(
    const struct vcs_zcode_work_receipt_v1 *r)
{
    if (!r)
        return false;
    uint8_t action[32], confinement[32];
    (void)vcs_zcode_work_pull_action_root(r->task_root, r->input_root,
                                          r->lease_id, action);
    pull_confinement_root(confinement);
    return memcmp(r->confinement_root, confinement, 32) == 0 ||
        memcmp(r->action_root, action, 32) == 0;
}

/* Every bound root plus the observer key; never the times or signature,
 * so the same observer verifying the same roots finds its first receipt. */
void vcs_zcode_work_pull_locator_address(
    const struct vcs_zcode_work_receipt_v1 *r, uint8_t out[32])
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
                                          r->lease_id, action);
    pull_confinement_root(confinement);
    bool shape = r->work_kind == VCS_ZCODE_WORK_REPRODUCE &&
        r->status == VCS_ZCODE_WORK_PASS && r->exit_status == 0 &&
        zcl_bytes_any_set(r->lease_id, 32) &&
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

enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_receipt_load(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_work_receipt_v1 *out)
{
    if (!workspace || !workspace[0] || !root || !out)
        return VCS_ZCODE_WORK_PULL_RECEIPT_NULL;
    memset(out, 0, sizeof(*out));
    if (!vcs_object_has(workspace, root))
        return VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND;
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    if (vcs_object_load_raw_bounded(workspace, root,
                                    VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES, &wire,
                                    &len) != 0)
        return VCS_ZCODE_WORK_PULL_RECEIPT_CODEC;
    enum vcs_zcode_work_pull_receipt_result result =
        vcs_zcode_work_pull_receipt_decode(wire, len, root, out, checked);
    free(wire);
    return result;
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
                                          io->pointer_root, r->action_root);
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

static void pull_locator_wire(const uint8_t receipt_root[32],
                              uint8_t wire[VCS_ZCODE_WORK_PULL_LOCATOR_BYTES])
{
    static const char magic[] = VCS_ZCODE_WORK_PULL_LOCATOR_MAGIC;
    memcpy(wire, magic, sizeof(magic));
    memcpy(wire + sizeof(magic), receipt_root, 32);
}

/* The locator answers for this observation only when it is one exact
 * locator object naming a receipt that loads at its own root, verifies,
 * and binds exactly the template's roots and observer. Anything else at
 * the locator address is invalid and is repaired by the next mint. */
static enum vcs_zcode_work_pull_receipt_result pull_attach(
    const char *workspace, const uint8_t locator[32],
    struct vcs_zcode_work_pull_observation *io, bool *locator_invalid)
{
    *locator_invalid = false;
    if (!vcs_object_has(workspace, locator))
        return VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND;
    uint8_t *wire = NULL, expect[VCS_ZCODE_WORK_PULL_LOCATOR_BYTES];
    uint8_t root[32] = {0}, derived[32];
    size_t len = 0;
    bool read = vcs_object_load_raw_bounded(
                    workspace, locator, VCS_ZCODE_WORK_PULL_LOCATOR_BYTES,
                    &wire, &len) == 0 &&
        len == VCS_ZCODE_WORK_PULL_LOCATOR_BYTES;
    if (read) {
        memcpy(root, wire + sizeof(VCS_ZCODE_WORK_PULL_LOCATOR_MAGIC), 32);
        pull_locator_wire(root, expect);
        read = memcmp(wire, expect, sizeof(expect)) == 0;
    }
    free(wire);
    struct vcs_zcode_work_receipt_v1 stored;
    bool ok = read &&
        vcs_zcode_work_pull_receipt_load(workspace, root, &stored) ==
            VCS_ZCODE_WORK_PULL_RECEIPT_OK;
    if (ok) {
        vcs_zcode_work_pull_locator_address(&stored, derived);
        ok = memcmp(derived, locator, 32) == 0;
    }
    if (!ok) {
        *locator_invalid = true;
        return VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND;
    }
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
    uint8_t pubkey[32], pointer[VCS_ZCODE_WORK_PULL_LOCATOR_BYTES];
    memcpy(pubkey, r->signer_pubkey, 32);
    if (vcs_zcode_work_receipt_seal(r, observer_secret, pubkey) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_pull_receipt_check(r) !=
            VCS_ZCODE_WORK_PULL_RECEIPT_OK ||
        vcs_zcode_work_receipt_serialize(r, wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_id(r, root) != VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_WORK_PULL_RECEIPT_SEAL;
    pull_locator_wire(root, pointer);
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
             ? vcs_object_put_addressed_repair(workspace, locator, pointer,
                                               sizeof(pointer), &repaired)
             : vcs_object_put_addressed(workspace, locator, pointer,
                                        sizeof(pointer)));
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

/* What must hold, beyond a verified admit, before anything is recorded. */
static enum vcs_zcode_work_pull_receipt_result pull_preconditions(
    const char *workspace, const uint8_t observer_secret[32],
    const uint8_t observer_pubkey[32],
    const struct vcs_zcode_work_pull_observation *io)
{
    if (!observer_secret || !observer_pubkey || !workspace || !workspace[0])
        return VCS_ZCODE_WORK_PULL_RECEIPT_NO_OBSERVER;
    if (!zcl_bytes_any_set(io->pointer_root, 32))
        return VCS_ZCODE_WORK_PULL_RECEIPT_NO_POINTER;
    if (memcmp(io->pointer_task_root, io->task_root, 32) != 0 ||
        memcmp(io->pointer_package_root, io->package_root, 32) != 0)
        return VCS_ZCODE_WORK_PULL_RECEIPT_POINTER_MISMATCH;
    if (io->started_unix <= 0 || io->observed_unix < io->started_unix)
        return VCS_ZCODE_WORK_PULL_RECEIPT_TIME;
    return VCS_ZCODE_WORK_PULL_RECEIPT_OK;
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
    enum vcs_zcode_work_pull_receipt_result result = pull_preconditions(
        workspace, observer_secret, observer_pubkey, io);
    if (result != VCS_ZCODE_WORK_PULL_RECEIPT_OK)
        return result;
    struct vcs_zcode_work_receipt_v1 r;
    pull_template(io, &metrics, observer_pubkey, &r);
    uint8_t locator[32];
    vcs_zcode_work_pull_locator_address(&r, locator);
    if (!vcs_object_store_init(workspace))
        return VCS_ZCODE_WORK_PULL_RECEIPT_STORE;
    bool locator_invalid = false;
    result = pull_attach(workspace, locator, io, &locator_invalid);
    if (result == VCS_ZCODE_WORK_PULL_RECEIPT_OK) {
        io->attached = true;
        return result;
    }
    result = pull_mint(workspace, locator, locator_invalid, observer_secret,
                       io, &r);
    return result == VCS_ZCODE_WORK_PULL_RECEIPT_OK
        ? result : pull_observe_clear(io, result);
}
