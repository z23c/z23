/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * _shim.c — the one process-global symbol every example needs but none of
 * them defines: `g_shutdown_requested`.
 *
 * In the real node it's defined once in engine/entry/main.c (and, for the test
 * harness, once in tests/harness/src/test_parallel.c / tests/harness/src/test.c) and
 * declared `extern` by a handful of library TUs that check it during a
 * graceful-shutdown-aware loop (see core/modules/validation/src/process_block_internal.h,
 * core/modules/net/src/msg_headers.c, engine/services/src/node_db_catchup_service.c,
 * etc). The examples link against the library object tree but deliberately
 * exclude tests/harness/src/test_parallel.o (it owns its own main(), which would
 * collide with each example's main()) — so this shim provides the same
 * definition, in the same never-set state (0 == "no shutdown requested"),
 * for every example binary. This file is examples-only; it is not part of
 * the node or test build.
 */

#include <signal.h>
#include <stdio.h>

volatile sig_atomic_t g_shutdown_requested = 0;

/* Force stdout to line-buffer even when it isn't a tty (piped into `make
 * run`, `tail`, a log file, ...). glibc's default for a non-tty stdout is
 * fully-buffered, which only flushes at exit — meanwhile stderr (where the
 * node's LOG_FAIL/LOG_ERR diagnostics land, see util/log_macros.h) is always
 * unbuffered. Without this, an example's own narration can appear AFTER a
 * library log line that was actually emitted much later in the run, which
 * reads as a fault before the task even started. A constructor runs before
 * main() in every example that links this shim, so no per-example edit is
 * needed. */
__attribute__((constructor))
static void examples_line_buffer_stdout(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
}
