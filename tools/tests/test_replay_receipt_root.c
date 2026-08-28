/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves a replay receipt written under argv[1] binds its height,
 * utxo, anchor and nullifier counts to the bundle digest, and that flipping
 * a single digest bit makes the binding refuse to verify. */
#include "config/consensus_state_replay_receipt.h"
#include "base/log_level.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"

#include <string.h>

enum zcl_log_level zcl_log_level_get(void) { return ZCL_LOG_ALL; }

int main(int argc, char **argv)
{
    if (argc != 2 || !platform_private_directory_ensure(argv[1]))
        return 2;
    uint8_t digest[32];
    memset(digest, 0x5a, sizeof(digest));
    char path[512];
    if (!consensus_state_replay_receipt_write_for_test(
            argv[1], digest, 42, 100, 2, 3, path, sizeof(path)))
        return 3;
    struct consensus_state_replay_receipt_binding binding;
    if (!consensus_state_replay_receipt_bundle_binding_verified_root(
            argv[1], digest, &binding) || binding.height != 42 ||
        binding.utxo_count != 100 || binding.anchor_count != 2 ||
        binding.nullifier_count != 3)
        return 4;
    digest[0] ^= 1;
    if (consensus_state_replay_receipt_bundle_binding_verified_root(
            argv[1], digest, &binding))
        return 5;
    return platform_private_file_unlink_missing_ok(path) ? 0 : 6;
}
