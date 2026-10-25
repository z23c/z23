/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Async-signal-safe fatal-signal handler. See signal_handler.h. */

#define _GNU_SOURCE
#include "util/signal_handler.h"
#include "util/async_safe_write.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static signal_handler_crash_hook_fn g_crash_hook;
static void *g_crash_hook_ctx;
static volatile LONG g_crash_hook_running;
static void (*g_termination_handler)(int);
static INIT_ONCE g_exception_once = INIT_ONCE_STATIC_INIT;
static INIT_ONCE g_console_once = INIT_ONCE_STATIC_INIT;

void signal_handler_set_crash_log(const char *path)
{
    /* The POSIX integer-fd crash-log ABI cannot safely represent a Win32
     * HANDLE. Native crash persistence remains disabled until the event/crash
     * reporters share an opaque durable handle. */
    (void)path;
}

int signal_handler_crash_log_fd(void) { return -1; }

void signal_handler_set_crash_hook(signal_handler_crash_hook_fn fn, void *ctx)
{
    g_crash_hook_ctx = ctx;
    g_crash_hook = fn;
}

void signal_handler_clear_crash_hook(void)
{
    g_crash_hook = NULL;
    g_crash_hook_ctx = NULL;
    InterlockedExchange(&g_crash_hook_running, 0);
}

void signal_handler_run_crash_hook(int sig, zcl_signal_info_t *info,
                                   void *ucontext)
{
    signal_handler_crash_hook_fn fn = g_crash_hook;
    if (!fn || InterlockedCompareExchange(&g_crash_hook_running, 1, 0) != 0)
        return;
    fn(sig, info, ucontext, g_crash_hook_ctx);
    InterlockedExchange(&g_crash_hook_running, 0);
}

static LONG CALLBACK windows_exception_handler(EXCEPTION_POINTERS *exception)
{
    zcl_signal_info_t info = {
        .code = exception && exception->ExceptionRecord
                    ? (int)exception->ExceptionRecord->ExceptionCode : 0,
        .address = exception && exception->ExceptionRecord
                       ? exception->ExceptionRecord->ExceptionAddress : NULL,
    };
    signal_handler_run_crash_hook(info.code, &info,
                                  exception ? exception->ContextRecord : NULL);
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL WINAPI windows_console_handler(DWORD event)
{
    void (*handler)(int) = g_termination_handler;
    if (!handler)
        return FALSE;
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT ||
        event == CTRL_CLOSE_EVENT || event == CTRL_LOGOFF_EVENT ||
        event == CTRL_SHUTDOWN_EVENT) {
        handler(event == CTRL_C_EVENT ? SIGINT : SIGTERM);
        return TRUE;
    }
    return FALSE;
}

static BOOL CALLBACK windows_exception_install_once(PINIT_ONCE once,
                                                    PVOID parameter,
                                                    PVOID *context)
{
    (void)once;
    (void)parameter;
    (void)context;
    SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX |
                 SEM_FAILCRITICALERRORS);
    return AddVectoredExceptionHandler(1, windows_exception_handler) != NULL;
}

static BOOL CALLBACK windows_console_install_once(PINIT_ONCE once,
                                                  PVOID parameter,
                                                  PVOID *context)
{
    (void)once;
    (void)parameter;
    (void)context;
    return SetConsoleCtrlHandler(windows_console_handler, TRUE);
}

int signal_handler_install(void)
{
    /* Prevent Windows Error Reporting UI; the supervisor observes the real
     * exception because the vectored handler always continues the search. */
    return InitOnceExecuteOnce(&g_exception_once,
                               windows_exception_install_once, NULL, NULL)
               ? 0 : -1;
}

int signal_handler_install_termination(void (*handler)(int))
{
    if (!handler)
        return -1;
    g_termination_handler = handler;
    return InitOnceExecuteOnce(&g_console_once, windows_console_install_once,
                               NULL, NULL) ? 0 : -1;
}

#else
#include <execinfo.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <pthread.h>
#include <sys/ucontext.h>
#include <errno.h>
#include <stdatomic.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

struct signal_thread_state {
    uintptr_t low, high;
    unsigned long tid;
    unsigned char alternate[64 * 1024];
};
static _Thread_local struct signal_thread_state g_thread_state;
static pthread_key_t g_signal_key;
static pthread_once_t g_signal_key_once = PTHREAD_ONCE_INIT;
static int g_signal_key_error;
static _Atomic unsigned g_signal_key_ready;
static_assert(ATOMIC_INT_LOCK_FREE == 2);

static void signal_key_create(void)
{
    g_signal_key_error = pthread_key_create(&g_signal_key, NULL);
    if (!g_signal_key_error)
        atomic_store_explicit(&g_signal_key_ready, 1, memory_order_release);
}

/* Darwin-specific implementation evidence: Apple's libpthread
 * src/pthread_tsd.c implements pthread_getspecific solely through
 * _pthread_getspecific_direct(key). It neither allocates nor takes a lock.
 * Never access C TLS or pthread_once from a signal, including foreign threads.
 * https://github.com/apple-oss-distributions/libpthread/blob/main/src/pthread_tsd.c */
static struct signal_thread_state *signal_thread_current(void)
{
    if (!atomic_load_explicit(&g_signal_key_ready, memory_order_acquire))
        return NULL;
    return pthread_getspecific(g_signal_key);
}

int signal_handler_thread_prepare(void)
{
    int error = pthread_once(&g_signal_key_once, signal_key_create);
    if (!error)
        error = g_signal_key_error;
    if (error) {
        errno = error;
        return -1;
    }
    struct signal_thread_state *state = &g_thread_state;
    pthread_t self = pthread_self();
    uintptr_t high = (uintptr_t)pthread_get_stackaddr_np(self);
    size_t bytes = pthread_get_stacksize_np(self);
    uint64_t tid = 0;
    state->low = state->high = 0;
    state->tid = 0;
    if (pthread_threadid_np(NULL, &tid) == 0)
        state->tid = (unsigned long)tid;
    if (bytes > 0 && high >= bytes) {
        state->low = high - bytes;
        state->high = high;
    }
    error = pthread_setspecific(g_signal_key, state);
    if (error) {
        errno = error;
        return -1;
    }
    stack_t current;
    if (sigaltstack(NULL, &current) != 0)
        return -1;
    if (!(current.ss_flags & SS_DISABLE))
        return 0;
    stack_t alternate = {.ss_sp = state->alternate,
                         .ss_size = sizeof(state->alternate), .ss_flags = 0};
    return sigaltstack(&alternate, NULL);
}

/* Arm defaults and unblock secondary faults BEFORE any frame dereference.
 * Damaged/unmapped stack memory must kill the process, never recurse through
 * an unwinder while retaining a database/allocator lock. */
int signal_handler_reset_fatal(void)
{
    const int sigs[] = {SIGABRT, SIGSEGV, SIGBUS, SIGFPE, SIGILL};
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigset_t unblock;
    if (sigemptyset(&action.sa_mask) != 0 || sigemptyset(&unblock) != 0)
        return -1;
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        if (sigaction(sigs[i], &action, NULL) != 0 ||
            sigaddset(&unblock, sigs[i]) != 0)
            return -1;
    }
    return sigprocmask(SIG_UNBLOCK, &unblock, NULL);
}

static uintptr_t signal_code_address(uintptr_t address)
{
#if __has_feature(ptrauth_calls)
    return (uintptr_t)ptrauth_strip((void *)address, ptrauth_key_return_address);
#else
    return address;
#endif
}

static size_t signal_walk_frames(const struct signal_thread_state *state,
                                 uintptr_t fp, void **frames, size_t cap,
                                 size_t count)
{
    while (count < cap && fp >= state->low && fp < state->high &&
           state->high - fp >= 2 * sizeof(uintptr_t) &&
           fp % (2 * sizeof(uintptr_t)) == 0) {
        const volatile uintptr_t *record = (const volatile uintptr_t *)fp;
        uintptr_t next = record[0];
        uintptr_t returned = signal_code_address(record[1]);
        if (!returned)
            break;
        frames[count++] = (void *)returned;
        if (next <= fp)
            break;
        fp = next;
    }
    return count;
}

size_t signal_handler_capture_frames(void *context, void **frames, size_t cap)
{
    if (!context || !frames || cap == 0)
        return 0;
    ucontext_t *uc = context;
    if (!uc->uc_mcontext)
        return 0;
    uintptr_t pc = 0, fp = 0;
#if defined(__aarch64__)
    pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    fp = (uintptr_t)__darwin_arm_thread_state64_get_fp(uc->uc_mcontext->__ss);
#elif defined(__x86_64__)
    pc = (uintptr_t)uc->uc_mcontext->__ss.__rip;
    fp = (uintptr_t)uc->uc_mcontext->__ss.__rbp;
#endif
    size_t count = 0;
    if (pc)
        frames[count++] = (void *)signal_code_address(pc);
    if (cap > 64)
        cap = 64;
    if (count >= cap)
        return count;
    struct signal_thread_state *state = signal_thread_current();
    if (!state)
        return count;
    return signal_walk_frames(state, fp, frames, cap, count);
}

void signal_handler_write_frames(int fd, void *const *frames, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        (void)asw_write_str(fd, "frame 0x");
        (void)asw_write_hex(fd, (unsigned long)(uintptr_t)frames[i]);
        (void)asw_write_str(fd, "\n");
    }
}

#else
#include <sys/syscall.h>
#endif
#include <sys/types.h>

/* Linux reads the kernel tid directly; Darwin uses normal-thread setup's
 * cached identity without calling pthread APIs in the signal path. */
static unsigned long signal_handler_tid(void)
{
#if defined(__APPLE__)
    struct signal_thread_state *state = signal_thread_current();
    return state ? state->tid : 0;
#else
    return (unsigned long)syscall(SYS_gettid);
#endif
}

static signal_handler_crash_hook_fn g_crash_hook = NULL;
static void *g_crash_hook_ctx = NULL;
static volatile sig_atomic_t g_crash_hook_running = 0;

/* Durable, append-only crash log (best-effort). Opened once the datadir is
 * known via signal_handler_set_crash_log(). Both this module's handler and
 * the event-log crash handler mirror their backtrace here and fsync, so a
 * crash leaves a forensic record even when stderr routing is lost. */
static volatile int g_crash_fd = -1;

void signal_handler_set_crash_log(const char *path)
{
    if (g_crash_fd >= 0 || !path || !*path) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd >= 0) g_crash_fd = fd;
}

int signal_handler_crash_log_fd(void)
{
    return g_crash_fd;
}

void signal_handler_set_crash_hook(signal_handler_crash_hook_fn fn,
                                   void *ctx)
{
    g_crash_hook_ctx = ctx;
    g_crash_hook = fn;
}

void signal_handler_clear_crash_hook(void)
{
    g_crash_hook = NULL;
    g_crash_hook_ctx = NULL;
    g_crash_hook_running = 0;
}

void signal_handler_run_crash_hook(int sig, zcl_signal_info_t *info,
                                   void *ucontext)
{
    signal_handler_crash_hook_fn fn = g_crash_hook;
    if (!fn || g_crash_hook_running) return;
    g_crash_hook_running = 1;
    fn(sig, info, ucontext, g_crash_hook_ctx);
    g_crash_hook_running = 0;
}

/* Async-signal-safe fd writers now live in util/async_safe_write.c so the live
 * self-backtrace handler (self_backtrace.c) reuses the exact same audited code
 * rather than duplicating it. These thin aliases keep emit_report() unchanged
 * and preserve crash-handler behavior byte-for-byte. */
static int write_uint(int fd, unsigned long v) { return asw_write_uint(fd, v); }
static int write_hex(int fd, unsigned long v)  { return asw_write_hex(fd, v); }
static int write_s(int fd, const char *s)      { return asw_write_str(fd, s); }

/* Emit the marker + backtrace to one fd. Async-signal-safe throughout. */
static void emit_marker(int fd, int sig, siginfo_t *info)
{
    /* [fatal-signal] sig=N code=M addr=0x... pid=P tid=T time=T */
    write_s(fd, "[fatal-signal] sig=");
    write_uint(fd, (unsigned long)sig);
    write_s(fd, " code=");
    write_uint(fd, (unsigned long)(info ? info->si_code : 0));
    write_s(fd, " addr=0x");
    write_hex(fd, info ? (unsigned long)(uintptr_t)info->si_addr : 0UL);
    write_s(fd, " pid=");
    write_uint(fd, (unsigned long)getpid());
    write_s(fd, " tid=");
    write_uint(fd, signal_handler_tid());
    write_s(fd, " time=");
    write_uint(fd, (unsigned long)time(NULL));  // platform-ok:async-signal-safe-crash-handler (platform.clock may lock)
    write_s(fd, "\n");
}

#if !defined(__APPLE__)
static void emit_report(int fd, int sig, siginfo_t *info,
                        void *const *frames, int nframes)
{
    emit_marker(fd, sig, info);
    backtrace_symbols_fd(frames, nframes, fd);
    write_s(fd, "[fatal-signal] end\n");
}
#endif

/* The handler itself. SA_SIGINFO style. */
static void fatal_handler(int sig, siginfo_t *info, void *ucontext)
{
#if defined(__APPLE__)
    void *frames[64];
    /* Capture only the interrupted PC first: cap=1 performs no stack walk
     * or thread lookup. Persist primary evidence before any callback/read. */
    size_t primary = signal_handler_capture_frames(ucontext, frames, 1);
    emit_marker(STDERR_FILENO, sig, info);
    signal_handler_write_frames(STDERR_FILENO, frames, primary);
    if (g_crash_fd >= 0) {
        emit_marker(g_crash_fd, sig, info);
        signal_handler_write_frames(g_crash_fd, frames, primary);
        fsync(g_crash_fd);
    }
    if (signal_handler_reset_fatal() != 0)
        _exit(128 + sig);
    signal_handler_run_crash_hook(sig, info, ucontext);
    size_t count = signal_handler_capture_frames(ucontext, frames, 64);
    size_t remaining = count > primary ? count - primary : 0;
    signal_handler_write_frames(STDERR_FILENO, frames + primary, remaining);
    write_s(STDERR_FILENO, "[fatal-signal] end\n");
    if (g_crash_fd >= 0) {
        signal_handler_write_frames(g_crash_fd, frames + primary, remaining);
        write_s(g_crash_fd, "[fatal-signal] end\n");
        fsync(g_crash_fd);
    }
    raise(sig);
    _exit(128 + sig);
#else
    signal_handler_run_crash_hook(sig, info, ucontext);

    /* Backtrace — up to 64 frames. backtrace + backtrace_symbols_fd are
     * documented async-signal-safe (glibc allocates internal buffers
     * lazily but uses mmap, not malloc, on the hot path). Capture once,
     * emit to stderr AND the durable crash log. */
    void *frames[64];
    int n = backtrace(frames, 64);

    emit_report(STDERR_FILENO, sig, info, frames, n);
    if (g_crash_fd >= 0) {
        emit_report(g_crash_fd, sig, info, frames, n);
        fsync(g_crash_fd);  /* survive even if the process dies hard next */
    }

    /* Restore default handler and re-raise so:
     *   - systemd still reports the original status code (e.g. 134),
     *   - the kernel still produces a core file if RLIMIT_CORE permits,
     *   - any parent process / debugger sees the real signal. */
    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigaction(sig, &dfl, NULL);
    raise(sig);
#endif
}

int signal_handler_install(void)
{
    /* SIGPIPE is not a useful process-fatal signal for the node: socket and
     * pipe writers already treat EPIPE/ECONNRESET as ordinary I/O failure, but
     * one missed MSG_NOSIGNAL must not kill the whole process without a
     * postmortem. Ignore it process-wide before worker threads spawn. */
    struct sigaction pipe_ign;
    memset(&pipe_ign, 0, sizeof(pipe_ign));
    pipe_ign.sa_handler = SIG_IGN;
    sigemptyset(&pipe_ign.sa_mask);
    if (sigaction(SIGPIPE, &pipe_ign, NULL) != 0) return -1;

#if defined(__APPLE__)
    if (signal_handler_thread_prepare() != 0)
        return -1;
#else
    /* Alternate signal stack so a stack-overflow SIGSEGV (which exhausts the
     * thread stack) can still run the handler instead of silently dying. */
    static char alt_stack[64 * 1024];
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = alt_stack;
    ss.ss_size = sizeof(alt_stack);
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) return -1;

#endif

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fatal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    const int sigs[] = { SIGABRT, SIGSEGV, SIGBUS, SIGFPE };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        if (sigaction(sigs[i], &sa, NULL) != 0) return -1;
    }
    return 0;
}

int signal_handler_install_termination(void (*handler)(int))
{
    if (!handler)
        return -1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) != 0)
        return -1;
    if (sigaction(SIGTERM, &sa, NULL) != 0)
        return -1;
    return 0;
}
#endif
