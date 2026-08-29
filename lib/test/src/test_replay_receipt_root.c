/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves a replay receipt written under a datadir is read beneath
 * its trusted root and binds its height, utxo, anchor and nullifier counts to
 * the bundle digest, and that flipping a single digest bit makes the binding
 * refuse to verify.
 *
 * Rehomed from tools/tests/test_replay_receipt_root.c. The old manifest
 * classified it `linkblocked`: portable and meaningful, but with no source
 * list that links it as a standalone program, so nothing ever built it. In
 * the suite its whole closure is already linked, so the assertions finally
 * execute. The probe body is the original verbatim; its zcl_log_level_get()
 * link stub is gone because the production definition is present. */
#include "test/test_core.h"

#include "config/consensus_state_replay_receipt.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"

#include <string.h>

static int replay_receipt_root_probe(const char *datadir)
{
    if (!platform_private_directory_ensure(datadir))
        return 2;
    uint8_t digest[32];
    memset(digest, 0x5a, sizeof(digest));
    char path[512];
    if (!consensus_state_replay_receipt_write_for_test(
            datadir, digest, 42, 100, 2, 3, path, sizeof(path)))
        return 3;
    struct consensus_state_replay_receipt_binding binding;
    if (!consensus_state_replay_receipt_bundle_binding_verified_root(
            datadir, digest, &binding) || binding.height != 42 ||
        binding.utxo_count != 100 || binding.anchor_count != 2 ||
        binding.nullifier_count != 3)
        return 4;
    digest[0] ^= 1;
    if (consensus_state_replay_receipt_bundle_binding_verified_root(
            datadir, digest, &binding))
        return 5;
    return platform_private_file_unlink_missing_ok(path) ? 0 : 6;
}

int test_replay_receipt_root(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "replay_receipt_root", "binding");
    printf("replay_receipt_root: receipt binds counts to the bundle digest "
           "and refuses a flipped bit... ");
    int rc = replay_receipt_root_probe(dir);
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }
    test_rm_rf_recursive(dir);
    return failures;
}
