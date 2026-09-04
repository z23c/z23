/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * spawn — no-shell process-launch primitives (Rung 0 of the os-substrate
 * plan, docs/work/os-substrate-plan.md §1). Every popen()/system("... &")
 * site in the tree is designed to be migrated onto these two calls: no
 * `/bin/sh -c` is ever invoked by either — argv[0] is resolved via execvp's
 * own PATH search (or used as-is if it contains a '/'), so a caller-supplied
 * string never passes through shell metacharacter expansion.
 *
 * `zcl_spawn_detached()` — fire-and-forget launch (double-fork + setsid),
 * for the sites that today do `system("nohup ... &")` /
 * `fork()+execlp()+return-without-waiting`.
 *
 * `zcl_spawn_detached_input()` — the same detached launch, with one bounded
 * byte string delivered to the child's stdin. Sensitive presentation payloads
 * belong here rather than argv, where process listings can expose them.
 *
 * `zcl_spawn_capture()` — synchronous launch that captures stdout, for the
 * sites that today do `popen(cmd, "r")`.
 *
 * ── SA_NOCLDWAIT ─────────────────────────────────────────────────────────
 * platform/modules/util/src/alerts.c:287-291 (`alerts_init()`) installs SIGCHLD with
 * `SA_NOCLDWAIT` process-wide, to suppress zombies from its own
 * fire-and-forget `curl` launch (alerts.c:77-95, sink_webhook()). That
 * disposition affects every fork() in the process, including the ones
 * below: once installed, this process's zombies are auto-reaped by the
 * kernel and a subsequent `waitpid()` call legitimately fails `ECHILD`
 * ("no such child") even though the child ran and produced output. Both
 * functions below tolerate that: they treat a captured/logged result as
 * valid on `ECHILD` and document "exit status unknown under SA_NOCLDWAIT"
 * rather than treating it as a launch failure. Once every `system()`/
 * `popen()` site in the tree (including alerts.c itself) has migrated onto
 * this header, alerts.c's SA_NOCLDWAIT install goes away and this
 * tolerance becomes dead-but-harmless defensive code — that migration is a
 * later lane's job, not this file's.
 *
 * ── fork() in a threaded process ────────────────────────────────────────
 * The node is multi-threaded. Per POSIX, after fork() the child has only
 * ONE thread (a clone of the caller) and any lock held by another thread
 * at fork time is never released in the child — so only async-signal-safe
 * calls are safe between fork() and exec()/_exit(). Both functions below
 * keep that contract: the only calls made in the child before exec (or
 * before _exit() on exec failure) are async-signal-safe ones — dup2(),
 * open(), close(), setsid(), execvp(), _exit(). No malloc, no fprintf, no
 * mutex, no LOG_* macro runs in the child. Keep it that way when editing
 * this file.
 */

#ifndef ZCL_UTIL_SPAWN_H
#define ZCL_UTIL_SPAWN_H

#include "util/result.h"

#include <stddef.h>

/* Launch argv[0] detached from the current process: double-fork + setsid()
 * so the grandchild is reparented to init/subreaper and can NEVER become a
 * zombie of this process, regardless of this process's SIGCHLD disposition
 * (SIG_DFL, SA_NOCLDWAIT, or a handler). No shell is invoked — argv[0] is
 * resolved via execvp() (PATH search if it contains no '/').
 *
 * argv       — NULL-terminated argument vector; argv[0] is the program.
 *              Must not be NULL and must have at least one element.
 * log_path   — if non-NULL, the grandchild's stdout+stderr are opened
 *              O_APPEND onto this path (created 0600 if missing); if NULL,
 *              both are redirected to /dev/null. Stdin is always /dev/null.
 *
 * Returns ZCL_OK once the grandchild has been launched (its own exit
 * status is never observable by design — that is the point of "detached").
 * Returns a ZCL_ERR on a failure that is detected before the fire-and-
 * forget hand-off completes (bad argv, fork() failure, or a confirmed
 * grandchild exec failure relayed back through a pipe).
 *
 * The intermediate (first) child is reaped by an immediate waitpid() in
 * the caller; that waitpid() tolerates ECHILD (see file header). */
struct zcl_result zcl_spawn_detached(const char *const argv[],
                                      const char *log_path);

/* Upper bound for zcl_spawn_detached_input()'s one-shot stdin payload. */
#define ZCL_SPAWN_INPUT_MAX (64u * 1024u)

/* Launch exactly like zcl_spawn_detached(), but connect the grandchild's stdin
 * to a private local stream and deliver input[0..input_len) before returning.
 * The bytes are never placed in argv, an environment variable, or the log.
 * A socketpair plus MSG_NOSIGNAL is used so a child that exits before reading
 * cannot terminate the parent with SIGPIPE. input_len is bounded by
 * ZCL_SPAWN_INPUT_MAX; input may be NULL only when input_len is zero. */
struct zcl_result zcl_spawn_detached_input(const char *const argv[],
                                            const void *input,
                                            size_t input_len,
                                            const char *log_path);

/* Launch argv[0], capture its stdout into buf, and wait for it to exit or
 * for timeout_ms to elapse. No shell is invoked — same argv[0]/execvp()
 * contract as zcl_spawn_detached(). Stdin is /dev/null; stderr is NOT
 * captured (redirected to /dev/null) so buf holds stdout only, matching
 * popen(cmd, "r")'s contract at every site this replaces.
 *
 * argv       — NULL-terminated argument vector; argv[0] is the program.
 * buf/cap    — output buffer; always NUL-terminated on return (truncated
 *              at cap-1 bytes if the child writes more). cap must be >= 1.
 * timeout_ms — if > 0, the child is killed (SIGKILL) and reaped if it has
 *              not exited by the deadline; the bytes captured so far are
 *              still returned in buf. <= 0 means no timeout (wait
 *              indefinitely for EOF on the pipe).
 *
 * Returns the child's exit status (0-255) when a trustworthy waitpid()
 * result was obtained. Returns 0 when waitpid() fails ECHILD (see the
 * SA_NOCLDWAIT note in the file header) — the captured output is still
 * valid in that case; the caller simply cannot distinguish "exit 0" from
 * "exit status unknown". Returns -1 on a launch failure detected before
 * any output could be captured (bad argv, fork() failure, pipe() failure)
 * — buf is set to an empty string in that case. */
int zcl_spawn_capture(const char *const argv[], char *buf, size_t cap,
                       int timeout_ms);

/* The same bounded capture with the deadline outcome preserved separately
 * from the child's status. `timed_out` is always initialized when non-NULL
 * and is true only when this function killed the process group because the
 * supplied deadline elapsed. This is the form for callers whose protocol
 * distinguishes an incomplete timed-out action from a completed child that
 * happened to exit with 128 + SIGKILL. */
int zcl_spawn_capture_observed(const char *const argv[], char *buf, size_t cap,
                               int timeout_ms, bool *timed_out);

/* The same bounded, no-shell capture, except the child's stderr is
 * interleaved into the SAME pipe as stdout instead of being discarded to
 * /dev/null. Use this — not zcl_spawn_capture()/zcl_spawn_capture_observed()
 * — for any caller whose diagnostics matter on failure: a compiler writes
 * its errors to stderr, and `make`'s own "*** [target] Error N" lines go to
 * stderr too, so a stdout-only capture of a failing build silently returns
 * a log that stops at the last successful line with no indication anything
 * went wrong. `timed_out` has the same contract as
 * zcl_spawn_capture_observed(). Windows returns -1 (unimplemented, matching
 * every other capture primitive in this header on that platform). */
int zcl_spawn_capture_merged_observed(const char *const argv[], char *buf,
                                      size_t cap, int timeout_ms,
                                      bool *timed_out);

/* The same bounded, no-shell capture with stdin/stdout/stderr attached to a
 * fresh controlling PTY. This is for installed local CLIs that explicitly
 * require terminal-backed stdio even in their single-turn mode. It inherits
 * the caller's environment and filesystem authority; unlike the separately
 * confined mesh_terminal_worker, it is NOT a sandbox and must never execute
 * fetched or otherwise untrusted programs. Output may contain terminal
 * control bytes and CRLF line endings. Timeout kills the whole child process
 * group and is preserved separately in `timed_out`. Windows refuses with -1. */
int zcl_spawn_pty_capture_observed(const char *const argv[], char *buf,
                                   size_t cap, int timeout_ms,
                                   bool *timed_out);

/* Cancellable capture for long fixed actions. The parent polls
 * `should_cancel` at most every 100 ms and, when it returns true, kills the
 * child's whole process group so compiler/test/fuzz descendants cannot
 * outlive the cancelled lease. `cancelled` is always initialized when
 * non-NULL. The callback runs only in the parent and may inspect durable
 * lifecycle state. All other semantics match zcl_spawn_capture(). */
typedef bool (*zcl_spawn_cancel_fn)(void *ctx);
int zcl_spawn_capture_cancelable(
    const char *const argv[], char *buf, size_t cap, int timeout_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx, bool *cancelled);

/* Split `str` in place into whitespace-separated tokens (space/tab/CR/LF),
 * writing a pointer to each into argv[0..n-1] and argv[n] = NULL. `str` is
 * modified (strtok_r). At most `max`-1 tokens are stored (argv must hold
 * `max` entries including the NULL terminator). This is a plain whitespace
 * split for turning a trusted, simple command string into an execvp() argv —
 * NO shell: no quote, escape, or glob handling. A NULL/empty `str` yields 0.
 * Returns the number of tokens stored. */
size_t zcl_argv_split(char *str, const char *argv[], size_t max);

#endif /* ZCL_UTIL_SPAWN_H */
