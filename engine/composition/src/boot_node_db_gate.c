/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_node_db_gate — names a typed blocker when node.db fails to open.
 * See config/boot_internal.h for the declaration.
 *
 * Every other boot-storage gate (crypto_params_missing, coins_view_integrity,
 * progress_kv_open) names a typed blocker when its storage fails to open.
 * An unopenable node.db is a PERMANENT blocker: a bounded retry cannot fix it,
 * it needs an operator to look at disk/permissions/corruption.
 *
 * This gate fires at stage crypto_ready: no RPC bound, serving=false,
 * boot_status.json blocker=node_db_unopened. A parked process there answers
 * nothing and sends no READY=, so it REFUSES rather than parks: close the open
 * "db.open_migrate" step as `failed` (the only producer of verdict=failure),
 * then exit non-zero naming the one command the operator runs. systemd reports
 * failed and Restart= owns the retry.
 *
 * THE REPAIR RUNS FIRST. A malformed node.db does not reach this gate:
 * models/database.c quarantines the SQLite family and rebuilds fresh (see
 * db_build_schema there). Reaching this gate means the store could not be
 * opened even after that repair. */

#include "config/boot_internal.h"

#include "event/event.h"
#include "util/blocker.h"
#include "util/boot_phase.h"
#include "util/log_macros.h"

#include <stdio.h>

bool boot_node_db_open_failed_gate(const char *datadir)
{
    const char *dd = datadir ? datadir : "(unset)";
    char inspect[1100];
    char retry[1100];
    char evidence[1200];

    fprintf(stderr, "Warning: SQLite database unavailable\n");
    event_emitf(EV_DB_ERROR, 0, "SQLite open failed at %s/node.db", dd);

    struct blocker_record rec;
    if (blocker_init(&rec, "node_db_unopened", "boot.node_db",
                     BLOCKER_PERMANENT,
                     "node.db failed to open — continuing would run "
                     "RAM-only with no persistence for wallet keys, "
                     "chain state, or progress") &&
        blocker_set(&rec) == 0)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "check=node_db_unopened datadir=%s", dd);

    LOG_WARN("boot.node_db",
             "[boot] node.db failed to open at %s/node.db — NOT continuing "
             "RAM-only and NOT parking; refusing the boot so the unit exits",
             dd);

    /* Close the step BEFORE the refusal renders: this is the one record that
     * says verdict=failure, and it must not be sequenced behind anything. */
    (void)boot_step_fail("node_db_unopened");

    (void)snprintf(inspect, sizeof(inspect),
                   "ls -l %s/node.db %s/node.db-wal %s/node.db.corrupt-*",
                   dd, dd, dd);
    (void)snprintf(retry, sizeof(retry),
                   "mv %s/node.db %s/node.db.unopenable-$(date -u +%%Y%%m%%dT%%H%%M%%SZ) "
                   "&& systemctl --user restart z23-node", dd, dd);
    (void)snprintf(evidence, sizeof(evidence),
                   "datadir=%s store=node.db stage=db.open_migrate", dd);

    const struct boot_error_next next[] = {
        { inspect,
          "look at the store first: a permission/ownership change, a full or "
          "read-only filesystem, and an already-quarantined "
          "node.db.corrupt-<UTC> each point at a different cause" },
        { retry,
          "move the unopenable store aside (nothing is deleted) and restart. "
          "The node rebuilds node.db from the chain it already has on disk" },
    };
    return boot_refuse_at_permanent_gate(
        "node_db_unopened",
        "node.db could not be opened and the bounded rebuild did not recover "
        "it. The node is NOT running: booting on would mean no persistence "
        "for wallet keys, chain state, or the progress cursor",
        next, 2, evidence);
}

/* The node.db open step reports progress while it runs.
 *
 * Its cost tracks the size of the WAL left by an unclean shutdown. Two
 * legs, both single blocking libsqlite3 calls with no seam to report from:
 * WAL recovery inside the open itself, and `PRAGMA quick_check`.
 *
 * boot_step_enter gets the heartbeat sweeper reporting it from a thread this
 * one does not own, and buys an immediate start-timeout extension; the
 * process-I/O probe lets each subsequent 30 s window earn another while the
 * disk is visibly working. The probe is scoped to this step and cleared when
 * it closes, including on the exit(1) / early-return paths in app_init, which
 * is why this is boot_step_enter and not boot_phase_begin (see boot_phase.h). */
void boot_node_db_open_step_begin(void)
{
    boot_step_enter("db.open_migrate");
    boot_step_set_evidence_probe(boot_evidence_probe_process_io, NULL);
}
