/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Async-signal-safe fd writers factored out of signal_handler.c so both the
 * fatal-signal crash handler and the live self-backtrace surface
 * (self_backtrace.c) share one audited implementation instead of duplicating
 * it. Every function here is strictly async-signal-safe: it calls only
 * write(2) (and strlen, which touches no global state), never malloc, stdio,
 * or locks. Safe to call from inside a signal handler. */

#ifndef ZCL_ASYNC_SAFE_WRITE_H
#define ZCL_ASYNC_SAFE_WRITE_H

/* Write an unsigned decimal. Returns bytes written (best-effort). */
int asw_write_uint(int fd, unsigned long v);

/* Write a lowercase hex value, no 0x prefix. Returns bytes written. */
int asw_write_hex(int fd, unsigned long v);

/* Write a NUL-terminated string. Returns bytes written. */
int asw_write_str(int fd, const char *s);

#endif /* ZCL_ASYNC_SAFE_WRITE_H */
