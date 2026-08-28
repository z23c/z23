/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * signal_handler — capture fatal signals (SIGABRT/SIGSEGV/SIGBUS/SIGFPE)
 * with an async-signal-safe backtrace, and ignore SIGPIPE process-wide.
 *
 * Without this, a SIGABRT exits the process with status=134 and nothing
 * in node.log explains where the abort came from — every crash becomes
 * a fresh archaeology task. The handler:
 *
 *   1. Writes one `[fatal-signal]` marker line to stderr (which systemd
 *      routes to ~/.zclassic-c23/node.log).
 *   2. Writes a `backtrace_symbols_fd` dump of up to 64 frames.
 *   3. Restores the default handler and re-raises so systemd still
 *      sees the original exit status and (if LimitCORE permits) the
 *      kernel still drops a core file.
 *
 * Must be installed BEFORE any pthread is spawned so the handler is
 * inherited by all threads (sigaction defaults are process-wide).
 *
 * Async-signal-safe only: no printf, no malloc, no mutex. Build with
 * -rdynamic (already in our LDFLAGS) so backtrace_symbols resolves
 * function names rather than just addresses. */

#ifndef ZCL_SIGNAL_HANDLER_H
#define ZCL_SIGNAL_HANDLER_H

#include <signal.h>

#if defined(_WIN32)
/* Windows console and exception handlers do not expose POSIX siginfo_t.
 * Keep the hook ABI explicit and opaque on that platform; the native crash
 * backend supplies exception detail through its own durable report. */
typedef struct zcl_signal_info {
    int code;
    void *address;
} zcl_signal_info_t;
#else
typedef siginfo_t zcl_signal_info_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*signal_handler_crash_hook_fn)(int sig,
                                             zcl_signal_info_t *info,
                                             void *ucontext,
                                             void *ctx);

/* Install fatal-process diagnostics. POSIX uses SIGABRT/SIGSEGV/SIGBUS/
 * SIGFPE on an alternate stack and ignores SIGPIPE. Windows installs the
 * unhandled-exception filter plus the C runtime's fatal-signal handlers;
 * Winsock writes already report errors rather than raising SIGPIPE. Idempotent.
 * Returns 0 on success and -1 when a required handler cannot be installed. */
int signal_handler_install(void);

/* Install the node owner's persistent termination callback. Embedded
 * runtimes (notably Tor) may install process-wide termination handlers while
 * they initialize, so the composition root calls this once before boot and
 * once after all embedded runtimes have started to reclaim signal ownership.
 * Windows maps console Ctrl-C/Break to SIGINT and close/logoff/shutdown events
 * to SIGTERM through SetConsoleCtrlHandler.
 * `handler` must be non-NULL. Returns 0 on success, -1 on invalid input or
 * sigaction failure. */
int signal_handler_install_termination(void (*handler)(int));

/* Open a durable, append-only crash log at `path` (best-effort, idempotent).
 * Both this module's handler and the event-log crash handler mirror their
 * backtrace there in addition to stderr, then fsync — so a crash leaves a
 * forensic record even when stderr routing is lost. Call once the datadir
 * is known. */
void signal_handler_set_crash_log(const char *path);

/* The durable crash-log fd opened by signal_handler_set_crash_log(), or -1
 * if none. For other fatal handlers that want to mirror their output there. */
int signal_handler_crash_log_fd(void);

/* Register one best-effort callback to run before the fatal handler
 * emits diagnostics or re-raises. The callback executes inside the
 * signal path, so it must avoid locks and other unsafe process-global
 * state. */
void signal_handler_set_crash_hook(signal_handler_crash_hook_fn fn,
                                   void *ctx);
void signal_handler_clear_crash_hook(void);

/* Shared hook entry point for other fatal handlers that own the active
 * sigaction chain, such as the event-log crash dumper. */
void signal_handler_run_crash_hook(int sig, zcl_signal_info_t *info,
                                   void *ucontext);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIGNAL_HANDLER_H */
