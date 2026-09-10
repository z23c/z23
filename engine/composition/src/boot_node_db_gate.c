/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_node_db_gate — the #7 supervision-coverage fix, split out of
 * boot.c (E1 file-size ceiling) so app_init's node.db-open branch stays a
 * short call site. See config/boot_internal.h for the declaration.
 *
 * Every other boot-storage gate (crypto_params_missing, coins_view_integrity,
 * progress_kv_open) names a typed blocker and parks alive-degraded when its
 * storage fails to open. node.db failing to open used to log
 * "Warning: SQLite database unavailable" and CONTINUE booting RAM-only —
 * every wallet key, chain-state write, and progress cursor silently vanishes
 * on the next restart with no operator page. This closes that hole: name a
 * PERMANENT blocker (an unopenable node.db is not something a bounded retry
 * fixes — it needs an operator to look at disk/permissions/corruption).
 *
 * WHAT IT DOES INSTEAD OF PARKING, and why (measured, fleet node,
 * 2026-09-09/10). This gate fires at stage crypto_ready: no RPC bound,
 * serving=false, boot_status.json blocker=node_db_unopened. A parked process
 * there answers nothing an operator can ask, and it sends no READY=, so under
 * the unit's Type=notify systemd showed `activating (start)` for 15.9 h
 * (TimeoutStartSec) before a watchdog SIGABRT — with `systemctl status` never
 * once saying failed. Worse, the open "db.open_migrate" step was never closed,
 * so the boot-step reporter printed 1,909 records reading
 *
 *   [boot-step] step=db.open_migrate state=stuck verdict=telemetry
 *               elapsed_ms=57432288 budget_ms=30000 progress_delta=0
 *
 * for a step that had actually FAILED 29 s into the boot. So: close the step
 * as `failed` (the only producer of verdict=failure — one record, greppable,
 * and the sweeper stops), then REFUSE rather than park, naming the one command
 * the operator runs. The unit exits non-zero, systemd says failed within
 * seconds, and Restart= owns the retry.
 *
 * THE REPAIR RUNS FIRST. node.db being malformed no longer reaches this gate
 * at all: models/database.c quarantines the SQLite family and rebuilds fresh
 * (see db_build_schema there). Reaching this gate now means the store could
 * not be opened even after that repair — genuinely an operator's problem. */

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
                   "&& systemctl --user restart zclassic23", dd, dd);
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

/* Why the node.db open step reports progress.
 *
 * This is the single most expensive uninstrumented step in boot, and
 * until now it reported NOTHING while it ran. Measured from this
 * node's own node.log over 33 boots: `sqlite_open_migrate` cost
 * 12 ms when the last shutdown was clean, and 214_354-985_360 ms when
 * it was not — the cost tracking the size of the WAL left behind
 * (27.6-115.8 GB) at roughly 8 s per GB on NVMe. Two legs, both
 * single blocking calls inside libsqlite3 with no seam to report
 * from: WAL recovery inside the open itself (311_483-435_727 ms
 * measured on the two boots that skipped quick_check entirely) and
 * `PRAGMA quick_check` (59_512-550_868 ms). During that window the
 * process printed nothing at all and renewed no clock.
 *
 * boot_step_enter gets the heartbeat sweeper reporting it from a
 * thread this one does not own, and buys an immediate start-timeout
 * extension; the process-I/O probe is what lets each subsequent
 * 30 s window earn another one while the disk is visibly working,
 * so a slow box is never killed for being honest. The probe is
 * scoped to this step and cleared when it closes — including on the
 * exit(1) / early-return paths in app_init, which is why this is
 * boot_step_enter and not boot_phase_begin (see boot_phase.h). */
void boot_node_db_open_step_begin(void)
{
    boot_step_enter("db.open_migrate");
    boot_step_set_evidence_probe(boot_evidence_probe_process_io, NULL);
}
