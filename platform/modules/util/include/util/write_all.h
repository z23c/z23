/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcl_write_all — the one full-write loop.
 *
 * write(2) is allowed to transfer fewer bytes than asked for, and two of the
 * ways it does so are reachable here, both measured:
 *
 *   - a socket carrying SO_SNDTIMEO returns the partial count when the timeout
 *     expires. https_server.c sets a 15s SO_SNDTIMEO on every accepted HTTPS
 *     client fd, so one stalled peer is enough. Measured on a socketpair with
 *     a 200ms send timeout: write() of 4 MiB returned 219264.
 *   - a signal arriving mid-write on a blocking fd with a non-restarting
 *     handler returns what was already transferred. Measured on a pipe with
 *     SIGALRM: write() of 4 MiB returned 65536 with errno left at 0 — so an
 *     `if (n < 0)` check does NOT catch this one. Only the count does.
 *
 * A regular file adds a third: a partial write when the filesystem fills.
 *
 * Because glibc marks write() warn_unused_result, an ignored return is exactly
 * the shape the C23 [[nodiscard]] discipline exists to catch.
 *
 * Callers with a correctness stake in delivery (a response body, a request
 * body another process reads back) must branch on the result. Callers that are
 * genuinely best-effort — a courtesy status line on a connection that is being
 * closed regardless — may discard it, but should say why at the call site:
 * this function is NOT attributed warn_unused_result precisely so that a
 * deliberate `(void)` reads as a decision rather than an oversight.
 *
 * NOT async-signal-safe in the strict sense used by util/async_safe_write.h
 * (it is signal-safe in practice — write/errno only — but the crash handler
 * has its own audited copy and should keep using it). */

#ifndef ZCL_UTIL_WRITE_ALL_H
#define ZCL_UTIL_WRITE_ALL_H

#include <stdbool.h>
#include <stddef.h>

/* Write all `len` bytes of `buf` to `fd`. Retries on EINTR and on short
 * writes. Returns true only when every byte was accepted; on false, errno
 * holds the failure from the last write() (and is left untouched by this
 * function on the "wrote zero bytes with no error" path, which is treated as
 * a failure because it cannot make progress). A NULL `buf` with a non-zero
 * `len` returns false; `len == 0` is a successful no-op. */
bool zcl_write_all(int fd, const void *buf, size_t len);

#endif /* ZCL_UTIL_WRITE_ALL_H */
