/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Live self-backtrace surface: answer "what is every thread doing right now"
 * on a RUNNING node, without perf/gdb/ptrace (which are blocked on hardened
 * hosts: perf_event_paranoid and yama ptrace_scope prevent non-child attach).
 *
 * self_backtrace_install() arms an async-signal-safe SIGRTMIN+2 handler at
 * boot (alongside the fatal-signal crash handler). self_backtrace_dump_all()
 * then walks the thread registry, pthread_kill()s each thread so it writes its
 * own tid/name + backtrace into a shared <datadir>/backtrace-<ts>.log fd, and
 * the calling thread dumps itself directly. A per-thread timeout guarantees a
 * blocked or signal-masked thread cannot hang the dump.
 *
 * The handler is strictly async-signal-safe (write(2)/backtrace only); it
 * reuses the audited crash-handler emit path via util/async_safe_write.h. */

#ifndef ZCL_SELF_BACKTRACE_H
#define ZCL_SELF_BACKTRACE_H

#include <stdbool.h>
#include <stddef.h>

/* Install the SIGRTMIN+2 self-backtrace handler process-wide. Call once at
 * boot before worker threads spawn so every thread inherits it. Idempotent.
 * Returns true on success. */
bool self_backtrace_install(void);

/* Dump a backtrace for every registered thread into a freshly created
 * <datadir>/backtrace-<unixts>.log (O_CREAT|O_EXCL|O_APPEND). On success
 * writes the chosen path into `path_out` (bounded by `cap`) and returns the
 * number of threads dumped (>=1: the caller always dumps itself). Returns -1
 * on error (handler not installed, datadir unresolved, or file-open failure).
 * Safe to call from any ordinary (non-signal) thread. */
int self_backtrace_dump_all(char *path_out, size_t cap);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. Exposes the last
 * completed dump: { installed, dump_count, last_path, last_thread_count,
 * last_unix_ts }. */
struct json_value;
bool self_backtrace_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SELF_BACKTRACE_H */
