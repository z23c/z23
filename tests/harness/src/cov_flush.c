/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Coverage flush on crash.  Only compiled into `test_zcl_cov` because
 * the Makefile passes `-DCOVERAGE_BUILD` for that target; in a normal
 * test_zcl build this file becomes an empty translation unit with no
 * runtime cost.
 *
 * The existence of this file is what makes `make coverage` actually
 * usable on a codebase with pre-existing -O0/-O1 crashes: gcov
 * normally only writes .gcda files on clean exit, so one SIGSEGV in
 * the test binary wipes coverage data for everything that DID run.
 * We install an __attribute__((constructor)) signal handler that
 * calls __gcov_dump() before the crash propagates, so partial runs
 * still produce useful coverage data.
 */

#ifdef COVERAGE_BUILD

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/* Provided by libgcov when -fprofile-arcs is on. */
extern void __gcov_dump(void);

static volatile sig_atomic_t g_in_handler = 0;

static void cov_flush_handler(int sig)
{
    /* Re-entrant guard: if __gcov_dump itself crashes (shouldn't but
     * we're already in a bad state), don't loop. */
    if (g_in_handler) {
        _exit(128 + sig);
    }
    g_in_handler = 1;

    __gcov_dump();

    /* We exit via _exit() instead of re-raising the signal because
     * libgcov also registers an atexit-like cleanup that writes the
     * same .gcda files; if we let the SIGSEGV propagate to the default
     * handler and then back through libc teardown, libgcov tries to
     * write the data a SECOND time with slightly different internal
     * state (we've just run the handler's own counters) and prints
     * "overwriting an existing profile data with a different checksum"
     * for every translation unit.  _exit bypasses atexit handlers so
     * the first write is the only write. */
    _exit(128 + sig);
}

__attribute__((constructor))
static void install_cov_flush(void)
{
    struct sigaction sa;
    sa.sa_handler = cov_flush_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
}

#else /* !COVERAGE_BUILD */

/* ISO C forbids an empty translation unit and the main build runs
 * with -Werror=pedantic, so leave a single no-op declaration here. */
typedef int cov_flush_no_op_placeholder;

#endif /* COVERAGE_BUILD */
