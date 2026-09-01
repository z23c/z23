/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_install_consensus_bundle.c — the -install-consensus-bundle=PATH terminal
 * verb (lane A2 of the sovereign shielded-state cure). TERMINAL — every path
 * _exit()s. The install pipeline itself is the NON-TERMINAL
 * consensus_state_install_from_bundle() core (engine/composition/src/
 * consensus_state_install_runtime.c); this file is now a thin wrapper that maps
 * that core's returned result onto the verb's named terminal (INSTALLED + H*
 * reported, or a typed REFUSED) and _exit()s. Keeping the two apart lets the
 * same atomic installer run inside a live boot (the zero-flag autodetect + the
 * durable install-on-next-boot request) without _exit()ing.
 *
 * Contract declared in config/boot.h. */

#include "config/boot.h"

#include "config/consensus_state_install_runtime.h"
#include "util/log_macros.h"
#include "util/result.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ICB_SUBSYS "install_consensus_bundle"

void boot_install_consensus_bundle(struct node_db *ndb, struct main_state *ms,
                                   const char *bundle_path, const char *datadir)
{
    struct consensus_state_install_runtime_result rr;
    struct zcl_result r =
        consensus_state_install_from_bundle(ndb, ms, bundle_path, datadir, &rr);

    if (!r.ok) {
        /* The runtime core already LOG_WARN'd the reason with context; here we
         * only print the operator-facing terminal banner and exit non-zero. A
         * distinct COMMIT_OUTCOME_UNKNOWN (state may be on disk) is carried in
         * rr.status/reason — the core never guesses rollback. */
        fprintf(stderr, "REFUSED: -install-consensus-bundle: %s\n", rr.reason);
        _exit(EXIT_FAILURE);
    }

    fprintf(stderr,
            "INSTALLED: -install-consensus-bundle: %s\n"
            "  reboot normally; the reducer folds forward from H*=%d to tip.\n",
            rr.reason, rr.hstar);
    LOG_INFO(ICB_SUBSYS, "consensus bundle activated: %s", rr.reason);
    _exit(EXIT_SUCCESS);
}
