/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: hostile/behavioral candidate images for the clean-zygote runner.
 *
 * Compiled once per kind (-DZCL_REFLEX_FIXTURE_KIND_<kind>) into a HOT_FORK
 * capsule .so with the ordinary module link flags. Each kind is plain,
 * compile-valid C that a developer could write by accident or on purpose:
 *
 *   canary  — constructor AND story try to read the resident's environment,
 *             a resident-set global, readable files, and a resident-held fd;
 *             every attempt must fail and the story reports what it saw
 *   green   — a well-behaved story (3/3 checks)
 *   regress — a compile-valid behavior regression (4/5 checks)
 *   loop    — never returns; the runner must kill it at the deadline
 *   segv    — crashes with SIGSEGV
 *   socket  — asks for a socket; the seccomp session deny-list kills it
 *   wx      — asks for new executable memory after load; W^X kills it
 *   iouring    — io_uring_setup (a ring would issue socket/connect past the
 *                syscall filter); the runner deny layer kills it
 *   pidfd      — pidfd_open(getppid()) on the runner; killed
 *   killparent — kill(getppid(), SIGKILL); killed, and the runner survives
 *   forkctor / forkstory — fork() from the constructor / the story; killed
 *   execctor / execstory — execve() from the constructor / the story; killed
 *
 * Every escape kind reports "escaped:<what>" and returns GREEN if the call
 * works, and "refused:<errno>" (red) if it merely fails, so a permitted
 * escape can never hide behind the expected-red verdict.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* MAP_ANONYMOUS */
#endif

#include "hotswap/hotfork_capsule.h"
#include "reflex_runner_fixture.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Generic-table numbers (identical on every Linux arch since 5.1/5.3), for
 * libc headers that predate them. */
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

/* Escape probes: `rc` is the syscall's return. Success means the sandbox let
 * the candidate out, which must read as GREEN so the test cannot mistake it
 * for the expected red. */
[[maybe_unused]] static bool escape_detail(long rc, const char *what, char *out,
                                         size_t cap)
{
    if (rc >= 0) {
        (void)snprintf(out, cap, "escaped:%s", what);
        return true;
    }
    (void)snprintf(out, cap, "refused:%s:%d", what, errno);
    return false;
}

[[maybe_unused]] static long try_fork(void)
{
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    return pid;
}

[[maybe_unused]] static long try_exec(void)
{
    char arg0[] = "true";
    char *const argv[] = {arg0, NULL};
    char *const envp[] = {NULL};
    return execve("/bin/true", argv, envp);
}

#if defined(ZCL_REFLEX_FIXTURE_KIND_forkctor) || \
    defined(ZCL_REFLEX_FIXTURE_KIND_execctor)
static long g_ctor_rc = -2;
__attribute__((constructor)) static void fixture_escape_ctor(void)
{
#if defined(ZCL_REFLEX_FIXTURE_KIND_forkctor)
    g_ctor_rc = try_fork();
#else
    g_ctor_rc = try_exec();
#endif
}
#endif

#if defined(ZCL_REFLEX_FIXTURE_KIND_canary)
extern char **environ;
/* Defined (and set nonzero) by the resident; a fresh image holds zero. Weak so
 * the fixture still maps in an image that does not export it — which the
 * probe then reports as "absent", a failed (not meaningful) check. */
extern volatile uint64_t zcl_reflex_resident_canary __attribute__((weak));

struct fixture_probe {
    unsigned run;
    unsigned passed;
    char text[80];
};

static void probe_check(struct fixture_probe *p, bool denied)
{
    p->run++;
    if (denied) p->passed++;
}

static const char *errno_name(int err)
{
    switch (err) {
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case EBADF: return "EBADF";
    case ENOENT: return "ENOENT";
    case 0: return "OPENED";
    default: return "OTHER";
    }
}

static int open_errno(const char *path)
{
    errno = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)close(fd);
        return 0;
    }
    return errno;
}

static int write_errno(int fd)
{
    errno = 0;
    ssize_t n = write(fd, "x", 1);
    return n == 1 ? 0 : errno;
}

static void probe_isolation(struct fixture_probe *p)
{
    size_t env_n = 0;
    for (char **e = environ; e && *e; e++) env_n++;
    const volatile uint64_t *canary = &zcl_reflex_resident_canary;
    int open1 = open_errno(ZCL_REFLEX_FIXTURE_CANARY_FILE);
    int open2 = open_errno(ZCL_REFLEX_FIXTURE_CANARY_FILE2);
    int fd_err = write_errno(ZCL_REFLEX_FIXTURE_PARENT_FD);
    int err_err = write_errno(STDERR_FILENO);
    probe_check(p, getenv(ZCL_REFLEX_FIXTURE_CANARY_ENV) == NULL);
    probe_check(p, env_n == 0);
    probe_check(p, canary != NULL && *canary == 0);
    probe_check(p, open1 != 0);
    probe_check(p, open2 != 0);
    probe_check(p, fd_err != 0);
    probe_check(p, err_err != 0);
    (void)snprintf(p->text, sizeof(p->text),
                   "env=%zu canary=%s open=%s/%s fd%d=%s fd2=%s",
                   env_n, canary ? (*canary ? "SET" : "0") : "absent",
                   errno_name(open1), errno_name(open2),
                   ZCL_REFLEX_FIXTURE_PARENT_FD, errno_name(fd_err),
                   errno_name(err_err));
}

static struct fixture_probe g_ctor;

__attribute__((constructor)) static void fixture_ctor(void)
{
    probe_isolation(&g_ctor);
}
#endif

static bool fixture_finish(struct zcl_hotfork_observation_v1 *out,
                           unsigned run, unsigned passed, const char *detail)
{
    out->magic = ZCL_HOTFORK_OBSERVATION_MAGIC;
    out->checks_run = run;
    out->checks_passed = passed;
    (void)snprintf(out->exercised_surface, sizeof(out->exercised_surface),
                   "%s", ZCL_REFLEX_FIXTURE_SURFACE);
    (void)snprintf(out->detail, sizeof(out->detail), "%s", detail);
    return run > 0 && run == passed;
}

static bool fixture_story(struct zcl_hotfork_observation_v1 *out)
{
#if defined(ZCL_REFLEX_FIXTURE_KIND_canary)
    struct fixture_probe story = {0};
    probe_isolation(&story);
    char detail[192];
    (void)snprintf(detail, sizeof(detail), "ctor=%u/%u story=%u/%u %s",
                   g_ctor.passed, g_ctor.run, story.passed, story.run,
                   story.text);
    return fixture_finish(out, g_ctor.run + story.run,
                          g_ctor.passed + story.passed, detail);
#elif defined(ZCL_REFLEX_FIXTURE_KIND_green)
    return fixture_finish(out, 3, 3, "green checks=3/3");
#elif defined(ZCL_REFLEX_FIXTURE_KIND_regress)
    return fixture_finish(out, 5, 4, "behavior regression: case 5 refused");
#elif defined(ZCL_REFLEX_FIXTURE_KIND_loop)
    for (volatile uint64_t spin = 0;; spin++) {}
    return fixture_finish(out, 1, 1, "unreachable");
#elif defined(ZCL_REFLEX_FIXTURE_KIND_segv)
    volatile int *wild = (volatile int *)(uintptr_t)16;
    *wild = 1;
    return fixture_finish(out, 1, 1, "survived a wild store");
#elif defined(ZCL_REFLEX_FIXTURE_KIND_socket)
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    return fixture_finish(out, 1, s < 0 ? 1u : 0u, "socket returned");
#elif defined(ZCL_REFLEX_FIXTURE_KIND_wx)
    void *page = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return fixture_finish(out, 1, page == MAP_FAILED ? 1u : 0u,
                          "exec mapping returned");
#elif defined(ZCL_REFLEX_FIXTURE_KIND_iouring) || \
    defined(ZCL_REFLEX_FIXTURE_KIND_pidfd) || \
    defined(ZCL_REFLEX_FIXTURE_KIND_killparent) || \
    defined(ZCL_REFLEX_FIXTURE_KIND_forkstory) || \
    defined(ZCL_REFLEX_FIXTURE_KIND_execstory) || \
    defined(ZCL_REFLEX_FIXTURE_KIND_forkctor) || \
    defined(ZCL_REFLEX_FIXTURE_KIND_execctor)
    char detail[96];
    errno = 0;
#if defined(ZCL_REFLEX_FIXTURE_KIND_iouring)
    unsigned char params[120] = {0}; /* struct io_uring_params, zeroed */
    bool escaped = escape_detail(syscall(SYS_io_uring_setup, 8u, params),
                                 "io_uring_setup", detail, sizeof(detail));
#elif defined(ZCL_REFLEX_FIXTURE_KIND_pidfd)
    bool escaped = escape_detail(syscall(SYS_pidfd_open, getppid(), 0u),
                                 "pidfd_open", detail, sizeof(detail));
#elif defined(ZCL_REFLEX_FIXTURE_KIND_killparent)
    bool escaped = escape_detail(kill(getppid(), SIGKILL), "kill_parent",
                                 detail, sizeof(detail));
#elif defined(ZCL_REFLEX_FIXTURE_KIND_forkstory)
    bool escaped = escape_detail(try_fork(), "fork", detail, sizeof(detail));
#elif defined(ZCL_REFLEX_FIXTURE_KIND_execstory)
    bool escaped = escape_detail(try_exec(), "execve", detail, sizeof(detail));
#else
    bool escaped = escape_detail(g_ctor_rc, "constructor", detail,
                                 sizeof(detail));
#endif
    return fixture_finish(out, 1, escaped ? 1u : 0u, detail);
#else
#error "unknown reflex runner fixture kind"
#endif
}

const struct zcl_hotfork_capsule_v1 zcl_hotfork_capsule_v1 = {
    .abi_version = ZCL_HOTFORK_CAPSULE_ABI_V1,
    .descriptor_size = sizeof(struct zcl_hotfork_capsule_v1),
    .owner_id = ZCL_REFLEX_FIXTURE_OWNER,
    .source_tu = ZCL_REFLEX_FIXTURE_SOURCE,
    .candidate_object_root = ZCL_REFLEX_FIXTURE_OBJECT_ROOT,
    .story_id = ZCL_REFLEX_FIXTURE_STORY,
    .story_root = ZCL_REFLEX_FIXTURE_STORY_ROOT,
    .story_fixture_root = ZCL_REFLEX_FIXTURE_FIXTURE_ROOT,
    .run_story = fixture_story,
};
