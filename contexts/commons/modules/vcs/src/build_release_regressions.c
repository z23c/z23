/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical requested intent for the secure-release regression lane. */

#include "vcs/build_release_regressions.h"

#include "crypto/sha3.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

/* Keep this byte representation deliberately boring and reviewable. Group
 * identifiers are exact test_parallel catalog ids; the action executes the
 * candidate-bound test binary without selector arguments, so every listed
 * group must participate in its all-groups success verdict. */
static const uint8_t k_manifest[] =
    "zcl.build_release_regressions.v1\n"
    "runner=test_parallel:all-groups:uncached\n"
    "stale_wal_ownership=test_sqlite,test_boot_stale_locks\n"
    "lease_takeover=test_build_fabric\n"
    "mempool_generation=test_coins,test_accept_to_mempool\n"
    "provider_reconnect=test_zcode_dht_service,test_zcode_swarm\n"
    "utxo_mirror_storm=test_utxo_mirror_sync\n"
    "diagnostic_teardown=test_addrman_shutdown_race\n"
    "rollback=test_dev_activation,test_wallet_flush_rollback,test_reorg_safety\n";

void vcs_build_release_regression_manifest_v1_bytes(
    const uint8_t **bytes, size_t *len)
{
    if (bytes) *bytes = k_manifest;
    if (len) *len = sizeof(k_manifest) - 1u;
}

void vcs_build_release_regression_manifest_v1_root(uint8_t out[32])
{
    if (!out) return;
    sha3_256(k_manifest, sizeof(k_manifest) - 1u, out);
}

bool vcs_build_release_regression_manifest_v1_store(
    const char *workspace, uint8_t out[32])
{
    if (!workspace || !workspace[0] || !out) return false;
    vcs_build_release_regression_manifest_v1_root(out);
    return vcs_object_put_addressed(
        workspace, out, k_manifest, sizeof(k_manifest) - 1u);
}

bool vcs_build_release_regression_manifest_v1_verify_cas(
    const char *workspace, const uint8_t expected_root[32])
{
    if (!workspace || !workspace[0] || !expected_root) return false;
    uint8_t canonical_root[32], *stored = NULL;
    size_t stored_len = 0;
    vcs_build_release_regression_manifest_v1_root(canonical_root);
    bool exact = memcmp(canonical_root, expected_root, 32) == 0 &&
        vcs_object_load_raw_bounded(
            workspace, expected_root, sizeof(k_manifest) - 1u,
            &stored, &stored_len) == 0 &&
        stored_len == sizeof(k_manifest) - 1u &&
        memcmp(stored, k_manifest, stored_len) == 0;
    free(stored);
    return exact;
}
