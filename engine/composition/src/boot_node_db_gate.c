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
 * fixes — it needs an operator to look at disk/permissions/corruption) and
 * park like the sibling gates instead of degrading silently. */

#include "config/boot_internal.h"

#include "event/event.h"
#include "util/blocker.h"
#include "util/boot_phase.h"
#include "util/log_macros.h"

#include <stdio.h>

bool boot_node_db_open_failed_gate(const char *datadir)
{
    fprintf(stderr, "Warning: SQLite database unavailable\n");
    event_emitf(EV_DB_ERROR, 0, "SQLite open failed at %s/node.db",
                datadir ? datadir : "(unset)");

    struct blocker_record rec;
    if (blocker_init(&rec, "node_db_unopened", "boot.node_db",
                     BLOCKER_PERMANENT,
                     "node.db failed to open — continuing would run "
                     "RAM-only with no persistence for wallet keys, "
                     "chain state, or progress") &&
        blocker_set(&rec) == 0)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "check=node_db_unopened datadir=%s",
                    datadir ? datadir : "(unset)");

    LOG_WARN("boot.node_db",
             "[boot] node.db failed to open at %s/node.db — NOT continuing "
             "RAM-only; parking alive-degraded after paging the operator",
             datadir ? datadir : "(unset)");
    return boot_park_until_shutdown("node_db_unopened");
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
