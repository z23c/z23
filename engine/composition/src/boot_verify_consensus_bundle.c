/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_verify_consensus_bundle.c — the -verify-consensus-bundle=PATH verb: the
 * offline replay verifier that produces the independent receipt ACTIVATE
 * requires. Kept in its own file with one focused responsibility: admit a
 * consensus-state bundle read-only, re-derive its component digests from THIS
 * datadir's own folded progress store, and write the fsync'd replay receipt on
 * a full match. TERMINAL — every path _exit()s. Contract declared in
 * config/boot.h; derivation + threat model in
 * config/consensus_state_replay_receipt.h. */

#include "config/boot.h"

#include "config/consensus_state_replay_receipt.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define VCB_SUBSYS "verify_consensus_bundle"

void boot_verify_consensus_bundle(const char *bundle_path, const char *datadir)
{
    if (!bundle_path || !bundle_path[0] || !datadir || !datadir[0]) {
        fprintf(stderr, "REFUSED: -verify-consensus-bundle: empty bundle path "
                        "or datadir\n");
        LOG_WARN(VCB_SUBSYS, "empty bundle path or datadir");
        _exit(EXIT_FAILURE);
    }

    struct consensus_state_replay_result result;
    bool ok = consensus_state_replay_verify_and_write_receipt(
        progress_store_db(), bundle_path, datadir, &result);
    if (!ok) {
        fprintf(stderr, "REFUSED: -verify-consensus-bundle: %s\n",
                result.reason);
        LOG_WARN(VCB_SUBSYS, "%s", result.reason);
        _exit(EXIT_FAILURE);
    }

    fprintf(stderr,
            "VERIFIED: -verify-consensus-bundle: %s\n"
            "  the independent replay receipt now authorizes "
            "-install-consensus-bundle for this exact bundle on this datadir.\n",
            result.reason);
    LOG_INFO(VCB_SUBSYS, "%s", result.reason);
    _exit(EXIT_SUCCESS);
}
