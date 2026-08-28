/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Emit durable diagnostics and terminate after fatal signals. */
#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "event/event.h"
#include "util/signal_handler.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <process.h>
#include <windows.h>
#else
#include <execinfo.h>
#include <unistd.h>
#endif

static void crash_write_fd(int fd, const char *s, size_t n)
{
#if defined(_WIN32)
    int written = _write(fd, s, (unsigned int)(n > UINT_MAX ? UINT_MAX : n));
#else
    ssize_t written = write(fd, s, n);
#endif
    (void)written;
}

static void crash_emit_to(int fd, int sig, void *const *frames, int nframes)
{
    char buf[160];
    int n = snprintf(buf, sizeof(buf),
                     "\n\n*** FATAL SIGNAL %d (pid=%d t=%ld) ***\n", sig,
#if defined(_WIN32)
                     _getpid(),
#else
                     (int)getpid(),
#endif
                     (long)time(NULL)); // platform-ok:async-signal-safe-crash-handler
    if (n > 0) crash_write_fd(fd, buf, (size_t)n);
    n = snprintf(buf, sizeof(buf),
                 "=== STACK BACKTRACE (%d frames) ===\n", nframes);
    if (n > 0) crash_write_fd(fd, buf, (size_t)n);
#if defined(_WIN32)
    for (int i = 0; i < nframes; i++) {
        n = snprintf(buf, sizeof(buf), "  #%d %p\n", i, frames[i]);
        if (n > 0) crash_write_fd(fd, buf, (size_t)n);
    }
#else
    backtrace_symbols_fd(frames, nframes, fd);
#endif
    static const char end_bt[] = "=== END BACKTRACE ===\n\n";
    crash_write_fd(fd, end_bt, sizeof(end_bt) - 1);
}

static void crash_signal_handler(int sig)
{
    signal_handler_run_crash_hook(sig, NULL, NULL);
    void *frames[64];
#if defined(_WIN32)
    int nframes = (int)CaptureStackBackTrace(0, 64, frames, NULL);
#else
    int nframes = backtrace(frames, 64);
#endif
    crash_emit_to(2, sig, frames, nframes);
    int cfd = signal_handler_crash_log_fd();
    if (cfd >= 0) {
        crash_emit_to(cfd, sig, frames, nframes);
#if defined(_WIN32)
        _commit(cfd);
#else
        fsync(cfd);
#endif
    }
    event_emitf(EV_CRASH, 0, "signal %d", sig);
    event_dump_recent(200);
    fflush(stderr);
#if defined(_WIN32)
    _commit(2);
#else
    fsync(STDERR_FILENO);
#endif
    _exit(128 + sig);
}

void event_install_crash_handler(void)
{
#if defined(_WIN32)
    SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS |
                 SEM_NOGPFAULTERRORBOX);
    signal(SIGSEGV, crash_signal_handler);
    signal(SIGABRT, crash_signal_handler);
    signal(SIGFPE, crash_signal_handler);
    signal(SIGILL, crash_signal_handler);
#else
    static char alt_stack[64 * 1024];
    stack_t ss = {.ss_sp = alt_stack, .ss_size = sizeof(alt_stack),
                  .ss_flags = 0};
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_signal_handler;
    sa.sa_flags = SA_RESETHAND | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
#endif
}
