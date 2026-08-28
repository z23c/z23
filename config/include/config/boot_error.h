/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_error — the ONE operator/agent-facing failure surface for code that
 * runs BEFORE the typed command registry exists.
 *
 * Why this exists
 * ---------------
 * Every failure that reaches an agent through `zcl_command_reply` carries a
 * contract: {code, phase, message, evidence, next[]} (see
 * lib/kernel/include/kernel/command_registry.h). Pre-dispatch code — argv
 * handling in src/main.c, the datadir lock, app_init — could not reach that
 * contract, so it degraded to bare lines like "Initialization failed." A bare
 * line is unactionable: it names no code to match on, no measurement, and no
 * next move.
 *
 * This module is NOT a second error format. It renders the SAME five fields,
 * under the same names, to stderr — the only channel a pre-registry failure
 * has. A machine reader splits on the same keys it already knows; a human
 * reads the same shape it already sees from `zclassic23 <command>`.
 *
 *   FATAL boot: <message>
 *     code:     <CODE>
 *     phase:    <phase>
 *     evidence: <measured facts, key=value>
 *     next[1]:  <command to run, copy-pasteable as typed>
 *               why: <what running it establishes>
 *
 * Rules for callers
 * -----------------
 *   - `code` is a stable, greppable identifier. Never reword one in place;
 *     add a new code instead. Agents match on it.
 *   - `evidence` holds MEASUREMENTS (paths, errno text, pids, counts), never
 *     a restatement of the message.
 *   - every `next` entry must be a command that actually runs in the state
 *     the failure leaves behind. A next step that cannot work is worse than
 *     no next step at all — it costs the reader a round trip and teaches
 *     them to distrust the surface. Verify before adding one.
 *   - report ONCE per failure. `boot_error_reported()` lets a caller further
 *     up the stack tell whether the failure already explained itself, so the
 *     outer layer adds context instead of repeating.
 *
 * Dependencies: libc only, deliberately. These call sites run before the
 * event log, the blocker registry, the log file, and the command registry
 * are live, so this module must be callable from the first instruction of
 * main().
 *
 * Threading: boot is single-threaded through app_init, and every call site is
 * on that path. The latch is a plain static; do not call from a worker.
 */

#ifndef ZCL_CONFIG_BOOT_ERROR_H
#define ZCL_CONFIG_BOOT_ERROR_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum boot_error_level {
    BOOT_ERROR_FATAL = 0,  /* the process is stopping because of this */
    BOOT_ERROR_WARN  = 1,  /* degraded, boot continues — say so in `message` */
};

/* One suggested next move. `command` is copy-pasteable as typed; `reason`
 * says what it establishes. Both must be non-NULL to render. */
struct boot_error_next {
    const char *command;
    const char *reason;
};

#define BOOT_ERROR_MAX_NEXT 4
#define BOOT_ERROR_CODE_MAX 64
/* Sized so a report carrying two next[] commands built from a long absolute
 * datadir path plus their reasons renders whole rather than truncating the
 * remedy — the part a reader most needs. */
#define BOOT_ERROR_RENDER_MAX 4096

/* Render one pre-dispatch failure. `evidence_fmt` is printf-style and may be
 * NULL/"" when there is genuinely nothing measured to report. `next` may be
 * NULL with next_count 0 when no command would help (say why in `message`
 * rather than inventing a step). FATAL reports latch: see
 * boot_error_reported(). */
void boot_error_report(enum boot_error_level level, const char *code,
                       const char *phase, const char *message,
                       const struct boot_error_next *next, size_t next_count,
                       const char *evidence_fmt, ...)
    __attribute__((format(printf, 7, 8)));

/* True once a FATAL has been rendered in this process. WARN does not set it. */
bool boot_error_reported(void);

/* The code of the FIRST FATAL rendered ("" when none). First-wins: the first
 * failure is the root cause; later ones are consequences of not stopping. */
const char *boot_error_first_code(void);

/* Copy the most recently rendered block (FATAL or WARN) into `out`. Returns
 * the number of bytes written, excluding the terminator. Exists so tests can
 * assert on exact operator-visible text without capturing stderr. */
size_t boot_error_last_render(char *out, size_t cap);

#ifdef ZCL_TESTING
/* Test-only: clear the latch + last render so one test process can exercise
 * several failures. Production code must not call this — the first-wins latch
 * is the whole point. */
void boot_error_reset_for_testing(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_ERROR_H */
