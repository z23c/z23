/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_tor_watch — the engine-side watch over the embedded Tor thread.
 *
 * tor_integration_start() spawns `zcl_tor` and returns true the moment the
 * thread exists. When Tor's own config parse fails (the classic case: its
 * bootstrap SocksPort is still held by an outgoing instance) the thread runs
 * tor_run_main, gets -1 back, prints "Tor: exited with code -1" and returns.
 * Nothing in the tree noticed: tor_integration_is_requested() stayed true,
 * tor_integration_is_enabled() went false, and the node ran on with no onion
 * and no retry until a human restarted it (node1, 2026-09-08 03:07-03:35Z).
 *
 * This watch turns that silence into a named, retried condition:
 *
 *   - FAILED is an OBSERVATION, not a flag somebody sets: Tor was requested
 *     and is not running. Both halves come from core's own predicates, so a
 *     thread that dies at minute 40 is seen exactly like one that dies at
 *     second 1.
 *   - The reason is CLASSIFIED into a closed vocabulary
 *     (enum boot_tor_fault) read from this boot's tor.log. A closed
 *     vocabulary is what makes the systemd status line safe to print: it
 *     can never carry an onion hostname, no matter what Tor logged. The
 *     full (redacted) warn line goes to the blocker record and the log,
 *     which are operator surfaces, not the process title.
 *   - The retry runs through the SAME engine-side wrapper that boots Tor
 *     (boot_onion_tor_start_early), on an exponential schedule that never
 *     gives up while the node runs.
 *
 * Threading: everything the sd-watchdog pet thread touches is a lock-free
 * atomic load (boot_tor_watch_status). The file scan and the retry run on
 * the health/condition ring only.
 */

#ifndef ZCL_CONFIG_BOOT_TOR_WATCH_H
#define ZCL_CONFIG_BOOT_TOR_WATCH_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The typed blocker raised while Tor is requested but not running. Dotted,
 * like every other typed blocker id (util/blocker.h). */
#define BOOT_TOR_START_FAILED_BLOCKER "tor.start_failed"
#define BOOT_TOR_START_FAILED_OWNER   "onion_tor"

/* Retry schedule: 5s, 15s, 45s, 135s, then the 300s cap, forever. Forever is
 * deliberate — the fault that produced it (a port held by an outgoing
 * process, a torrc a human is fixing) clears on its own timescale, and a
 * node that stops trying is a node that needs a human. */
#define BOOT_TOR_RETRY_FIRST_US (5LL * 1000000LL)
#define BOOT_TOR_RETRY_GROWTH   3
#define BOOT_TOR_RETRY_CAP_US   (300LL * 1000000LL)

/* Longest tail of tor.log scanned for the failure reason. */
#define BOOT_TOR_LOG_TAIL_BYTES 8192
/* Reason text handed to the blocker record. */
#define BOOT_TOR_REASON_MAX 192

/* Closed reason vocabulary. Anything Tor can say maps into one of these, so
 * no free text ever reaches the systemd status line.
 *
 * ORDERED BY SPECIFICITY, and that ordering is load-bearing: one failed Tor
 * start logs several warnings, and the LAST one is the vaguest. The node1
 * incident logged, in this order,
 *     [warn] Could not bind to 127.0.0.1:PORT: Address already in use.
 *     [warn] Failed to parse/validate config: Failed to bind one of the ...
 *     [err]  Reading config failed--see warnings above.
 * so quoting the last line would have told the operator "bad config" about a
 * config that was fine. The scan therefore keeps the LOWEST non-NONE class it
 * sees, and quotes the line that produced it. */
enum boot_tor_fault {
    BOOT_TOR_FAULT_NONE = 0,
    BOOT_TOR_FAULT_PORT_IN_USE,      /* "Could not bind to ...: Address already in use" */
    BOOT_TOR_FAULT_DATADIR,          /* permissions / lock under tor_data */
    BOOT_TOR_FAULT_CONFIG_INVALID,   /* "Failed to parse/validate config" */
    BOOT_TOR_FAULT_EXITED            /* thread returned, cause not recognised */
};

/* One retry attempt through the engine-side Tor wrapper. */
typedef bool (*boot_tor_restart_fn)(void *ctx);

/* Lives in the owning service context (struct boot_svc_ctx), never at file
 * scope. boot_tor_watch_current() publishes the armed instance for the
 * condition, the same registry-pointer shape app_runtime_set_current() uses. */
struct boot_tor_watch {
    _Atomic bool armed;
    _Atomic int  attempts;            /* consecutive failed starts */
    _Atomic int  fault;               /* enum boot_tor_fault */
    _Atomic int64_t next_attempt_us;  /* monotonic; 0 = due immediately */
    _Atomic int64_t last_attempt_us;
    char datadir[512];                /* immutable after arm */
    boot_tor_restart_fn restart;      /* immutable after arm */
    void *restart_ctx;                /* immutable after arm */
};

/* Arm/disarm. Arming records the retry entry point and publishes the
 * instance; disarming (shutdown) unpublishes it first so no ring callback
 * can reach freed storage. */
void boot_tor_watch_arm(struct boot_tor_watch *w, const char *datadir,
                        boot_tor_restart_fn restart, void *restart_ctx);
void boot_tor_watch_disarm(struct boot_tor_watch *w);
struct boot_tor_watch *boot_tor_watch_current(void);

/* ── Pure helpers (no clock, no I/O — directly unit tested) ────────── */

/* Delay before attempt number `attempts` (0-based): 5s, 15s, 45s, 135s,
 * then the 300s cap. Never zero, never past the cap, never overflows. */
int64_t boot_tor_watch_delay_us(int attempts);

/* Classify ONE Tor log line. NULL/unrecognised -> BOOT_TOR_FAULT_EXITED. */
enum boot_tor_fault boot_tor_fault_classify(const char *line);

/* Stable short token for a fault, safe to print anywhere. */
const char *boot_tor_fault_name(enum boot_tor_fault fault);

/* Copy `line` into `out`, replacing every onion hostname with "<onion>".
 * Applied to any Tor text that leaves this module: a warn line can name the
 * service Tor was registering, and an operator surface must not publish it.
 * Returns false only when out/cap cannot hold a NUL. */
bool boot_tor_redact_onion(const char *line, char *out, size_t cap);

/* Classify every [warn]/[err] line at/after `scan_from` in the file at
 * `path`, keep the most specific class (see the enum), and copy that line —
 * redacted — into `out`. Returns BOOT_TOR_FAULT_NONE with an empty `out`
 * when the file is unreadable or carries no warning. */
enum boot_tor_fault boot_tor_log_scan_fault(const char *path, long scan_from,
                                            char *out, size_t cap);

/* ── Observation + retry (health/condition ring) ───────────────────── */

/* Tor was requested by this boot and is not running now. */
bool boot_tor_watch_failed(const struct boot_tor_watch *w);

/* Read this boot's tor.log, publish the classified fault on the watch, and
 * copy the redacted reason text into `out`. Falls back to the fault token
 * when the log has no warning to quote. */
void boot_tor_watch_capture_fault(struct boot_tor_watch *w,
                                  char *out, size_t cap);

/* True when the backoff has elapsed and a retry should run now. */
bool boot_tor_watch_due(const struct boot_tor_watch *w, int64_t now_us);

/* Run one retry through the wrapper and re-arm the backoff. Returns what
 * the wrapper returned; "Tor is up again" is proved by
 * boot_tor_watch_failed() going false, never by this return. */
bool boot_tor_watch_retry(struct boot_tor_watch *w, int64_t now_us);

/* Tor bootstrapped: clear the fault and reset the schedule. */
void boot_tor_watch_note_up(struct boot_tor_watch *w);

/* ── Status leg for the sd-watchdog READY line ─────────────────────── */

/* Writes one of: "tor=off", "tor=ok", "tor=starting",
 * "tor=failed(<token>)". Lock-free atomic loads only — safe from the pet
 * thread, which must never touch a node lock or the filesystem. */
void boot_tor_watch_status(const struct boot_tor_watch *w,
                           char *out, size_t cap);

#endif /* ZCL_CONFIG_BOOT_TOR_WATCH_H */
