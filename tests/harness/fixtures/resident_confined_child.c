/* Copyright 2026 Rhett Creighton - Apache 2.0
 *
 * Tiny native helper for test_resident_confined_run.c (built by the Makefile
 * into build/fixtures/, never linked into a product binary). It speaks no
 * protocol: it does one thing named by argv and exits.
 *
 *   open <path>    open read-only; exit 0, or exit with errno (EACCES = 13)
 *   write <path>   create/truncate and write one byte; exit 0 or errno
 *   exit <n>       exit with n
 *   socket         socket(AF_INET): the seccomp policy kills this (SIGSYS)
 *   spin <iters>   CPU-bound integer loop, no syscalls; exit 0
 *   fdwrite <n>    write one byte to inherited descriptor <n>; exit 0 or errno
 *   fork           fork one child that exits at once; exit 0 or errno
 *   thread         start and join one pthread; exit 0 or non-zero
 *   flood <file>   start small-stack threads until pthread_create fails (cap 3000),
 *                  join them, record the count in <file>; exit 0
 *   vfork          vfork one child that exits at once; exit 0 or errno
 *   setsid         setsid(); exit 0 or errno
 *   setpgid        setpgid(0, 0); exit 0 or errno
 *   daemon <file>  fork a setsid child that records its pid in <file> and
 *                  sleeps 30 s; the parent exits 0 once the pid is recorded
 *                  (a detached descendant)
 */
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static int rcc_open(const char *path, int flags)
{
    int fd = open(path, flags, 0600);
    if (fd < 0) return errno;
    if ((flags & O_WRONLY) && write(fd, "x", 1) != 1) { close(fd); return EIO; }
    close(fd);
    return 0;
}

static int rcc_spin(unsigned long iters)
{
    volatile unsigned long acc = 1;
    for (unsigned long i = 0; i < iters; ++i)
        acc = acc * 6364136223846793005UL + 1442695040888963407UL;
    return acc == 0 ? 1 : 0;
}

static int rcc_fork(void)
{
    pid_t pid = fork();
    if (pid < 0) return errno;
    if (pid == 0) _exit(0);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 0;
}

static void *rcc_thread_main(void *arg)
{
    *(int *)arg = 42;
    return NULL;
}

static int rcc_thread(void)
{
    pthread_t thread;
    pthread_attr_t attr;
    int value = 0;
    /* An explicit stack: with no attribute glibc takes RLIMIT_STACK as the
     * thread stack size, and t-asan/t-tsan run with `ulimit -s 1048576`, so
     * the default thread asks for 1 GiB, which the confined child's address
     * space ceiling refuses (pthread_create returns EAGAIN, code 11). The
     * case proves clone(CLONE_THREAD) is permitted, not the stack default. */
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 65536);
    int rc = pthread_create(&thread, &attr, rcc_thread_main, &value);
    if (rc != 0) return rc;
    pthread_join(thread, NULL);
    return value == 42 ? 0 : 3;
}

static pthread_mutex_t rcc_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rcc_cond = PTHREAD_COND_INITIALIZER;
static int rcc_release;

static void *rcc_idle_main(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&rcc_mutex);
    while (!rcc_release) pthread_cond_wait(&rcc_cond, &rcc_mutex);
    pthread_mutex_unlock(&rcc_mutex);
    return NULL;
}

static int rcc_flood(const char *file)
{
    enum { CAP = 3000 };
    pthread_t threads[CAP];
    pthread_attr_t attr;
    int count = 0;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 32768);
    while (count < CAP && pthread_create(&threads[count], &attr, rcc_idle_main, NULL) == 0)
        ++count;
    pthread_mutex_lock(&rcc_mutex);
    rcc_release = 1;
    pthread_cond_broadcast(&rcc_cond);
    pthread_mutex_unlock(&rcc_mutex);
    for (int i = 0; i < count; ++i) pthread_join(threads[i], NULL);
    FILE *out = fopen(file, "w");
    if (!out) return errno;
    fprintf(out, "%d\n", count);
    fclose(out);
    return 0;
}

static int rcc_vfork(void)
{
    pid_t pid = vfork();
    if (pid < 0) return errno;
    if (pid == 0) _exit(0);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 0;
}

static int rcc_daemon(const char *file)
{
    int sync[2];
    if (pipe(sync) != 0) return errno;
    pid_t pid = fork();
    if (pid < 0) return errno;
    if (pid > 0) {
        char byte;
        close(sync[1]);
        while (read(sync[0], &byte, 1) < 0 && errno == EINTR) {}
        return 0; /* the descendant has recorded its pid (or died trying) */
    }
    close(sync[0]);
    (void)setsid();
    FILE *out = fopen(file, "w");
    if (out) { fprintf(out, "%ld\n", (long)getpid()); fclose(out); }
    close(sync[1]);
    sleep(30);
    _exit(0);
}

/* Inspect post-exec state without sending a signal or opening a proc path. */
static int rcc_signal_state(void)
{
    sigset_t mask;
    struct sigaction caught, ignored;
    if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0 ||
        sigaction(SIGUSR1, NULL, &caught) != 0 ||
        sigaction(SIGUSR2, NULL, &ignored) != 0) return 80;
    if (caught.sa_handler != SIG_DFL || ignored.sa_handler != SIG_IGN) return 81;
    if (sigismember(&mask, SIGUSR1) != 0 || sigismember(&mask, SIGUSR2) != 1) return 82;
    return 0;
}

static int rcc_misc(const char *verb, const char *arg, int *handled)
{
    *handled = 1;
    if (strcmp(verb, "signal-state") == 0) return rcc_signal_state();
    if (strcmp(verb, "fdwrite") == 0)
        return write(atoi(arg), "x", 1) == 1 ? 0 : errno;
    if (strcmp(verb, "fork") == 0) return rcc_fork();
    if (strcmp(verb, "thread") == 0) return rcc_thread();
    if (strcmp(verb, "flood") == 0) return rcc_flood(arg);
    if (strcmp(verb, "vfork") == 0) return rcc_vfork();
    if (strcmp(verb, "setsid") == 0) return setsid() < 0 ? errno : 0;
    if (strcmp(verb, "setpgid") == 0) return setpgid(0, 0) < 0 ? errno : 0;
    if (strcmp(verb, "daemon") == 0) return rcc_daemon(arg);
    *handled = 0;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    const char *verb = argv[1];
    const char *arg = argc > 2 ? argv[2] : "";
    if (strcmp(verb, "open") == 0) return rcc_open(arg, O_RDONLY);
    if (strcmp(verb, "write") == 0)
        return rcc_open(arg, O_WRONLY | O_CREAT | O_TRUNC);
    if (strcmp(verb, "exit") == 0) return atoi(arg);
    if (strcmp(verb, "socket") == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        return fd < 0 ? 3 : 4; /* only reached when no policy killed us */
    }
    if (strcmp(verb, "spin") == 0) return rcc_spin(strtoul(arg, NULL, 10));
    int handled = 0;
    int code = rcc_misc(verb, arg, &handled);
    if (handled) return code;
    return 2;
}
