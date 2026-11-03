/* loop_tick_gate.h - is a zgate run's log still being written?
 *
 * zgate --detach hands the loop only a log path, so the loop cannot waitpid
 * the run. The run's stdout and stderr ARE that log, so a live run is any
 * process of this user holding the log open. A log that exists, has no
 * "rc=" line and is held by nobody belongs to a run that died unreported.
 */
#ifndef LOOP_TICK_GATE_H
#define LOOP_TICK_GATE_H

#include <stdbool.h>

/* True when the file at `log` exists and no process has it open. */
bool lt_log_orphaned(const char *log);

#endif
