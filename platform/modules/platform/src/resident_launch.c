/* Copyright 2026 Rhett Creighton - Apache-2.0
 * Purpose: launcher half of the exact resident launch (Linux arm + shared codec) */
/* Purpose: exact resident process launch bound to an accepted artifact.
 *
 * The launcher half of the app-run seam. See resident_launch.h for the
 * contract. This file carries the shared pieces (acceptance re-proof, IPC
 * frame codec, cancellation, stale-result rejection) and the Linux spawn
 * arm (fork + fexecve on the pinned descriptor). The Darwin arm lives in
 * resident_launch_mac.c: it suspends the child before its first instruction
 * and proves the mapped image's CodeDirectory hash equals the hash the
 * kernel returns for the pinned descriptor, so a pathname swap between
 * check and spawn surfaces as a mismatch and the child dies unexecuted.
 * Windows refuses by name, exactly like os_binary_slots: reconstructing a
 * pathname and exec'ing it is a TOCTOU hole, and a guarantee-shaped launch
 * that cannot be proven is worse than a loud refusal.
 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/resident_launch.h"
#include "resident_launch_confined.h"

#include "platform/os_proc.h"
#include "platform/os_sandbox.h"
#include "platform/positioned_file.h"
#include "platform/process_compat.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "platform/rng.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <elf.h>
#include <sys/prctl.h>
#endif

#define RESIDENT_FRAME_MAGIC_RESULT "z23-res-run-v1"
#define RESIDENT_FRAME_MAGIC_STOP "z23-res-stop-v1"

#if defined(_WIN32)
#define RESIDENT_WIN_REFUSAL                                                  \
    "resident exact launch is disabled on Windows pending a descriptor-bound" \
    " execution primitive: a pathname exec here would be a TOCTOU hole, not"  \
    " an exact launch"
#endif

#if defined(__APPLE__)
#include "resident_launch_internal.h"
#endif

static void resident_fail(char *error, size_t error_size, const char *fmt,
                          ...) {
    if (!error || !error_size) return;
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(error, error_size, fmt, args);
    va_end(args);
}

void resident_launch_init(struct resident_launch *launch)
{
    if (!launch) return;
    memset(launch, 0, sizeof(*launch));
    launch->pinned_native = (uintptr_t)-1;
    launch->ipc_native = (uintptr_t)-1;
}

/* Advisory write over the IPC socket, bounded in time. The stop frame is a
 * courtesy to a cooperative app: a child that never reads can fill the
 * parent's send queue, and a blocking send would then wedge the supervisor
 * before it reaches the SIGKILL. Every send is MSG_DONTWAIT; a full queue is
 * waited on for at most `budget_ms` in total, then the frame is abandoned
 * (the caller falls through to the grace wait and the kill). EINTR is
 * retried inside the budget. Returns true only if every byte was queued. */
#if !defined(_WIN32)
#define RESIDENT_STOP_SEND_BUDGET_MS 50u
static bool resident_send_bounded(int fd, const void *data, size_t size,
                                  uint32_t budget_ms)
{
    const unsigned char *p = data;
    size_t done = 0;
    uint32_t waited_ms = 0;
    while (done < size) {
        ssize_t part = send(fd, p + done, size - done,
                            MSG_NOSIGNAL | MSG_DONTWAIT);
        if (part > 0) {
            done += (size_t)part;
            continue;
        }
        if (part < 0 && errno == EINTR) continue;
        if (part < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (waited_ms >= budget_ms) return false;
            struct pollfd pfd = {.fd = fd, .events = POLLOUT};
            (void)poll(&pfd, 1, 5);
            waited_ms += 5;
            continue;
        }
        return false;
    }
    return true;
}

#endif /* !defined(_WIN32) */

#if !defined(_WIN32)
/* Opens the image, proves it is an executable regular file, hashes it
 * through the handle with a stability re-check, and refuses unless the
 * live bytes and positioned-file identity equal the accepted record.
 * Returns the pinned handle the caller owns (resident_launch_close), or
 * NULL with errno and `error` set. */
static struct platform_positioned_file *resident_open_accepted(
    const char *image_path, const struct resident_launch_accepted *accepted,
    struct platform_positioned_file_snapshot *snapshot_out,
    char *error, size_t error_size)
{
    struct platform_positioned_file *file =
        zcl_malloc(sizeof(*file), "resident-launch-image");
    if (!file) {
        resident_fail(error, error_size,
                      "resident launch: image state allocation failed");
        return NULL;
    }
    platform_positioned_file_init(file);
    if (!platform_positioned_file_open(file, image_path)) {
        int saved = errno;
        free(file);
        errno = saved;
        resident_fail(error, error_size,
                      "resident launch: cannot open accepted image at %s: %s",
                      image_path, strerror(saved));
        return NULL;
    }
    struct platform_positioned_file_snapshot before, after;
    if (!platform_positioned_file_is_executable(file) ||
        !platform_positioned_file_snapshot(file, &before)) {
        platform_positioned_file_close(file);
        free(file);
        errno = ENOEXEC;
        resident_fail(error, error_size,
                      "resident launch: %s is not a regular executable image",
                      image_path);
        return NULL;
    }
    /* Hash through the HANDLE, then prove the handle still names the same
     * bytes: a writer that swapped the content mid-read surfaces as a
     * snapshot change and the launch refuses (the dev_activation idiom). */
    unsigned char digest[32];
    if (!resident_sha3_positioned(file, digest) ||
        !platform_positioned_file_snapshot(file, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after)) {
        platform_positioned_file_close(file);
        free(file);
        errno = ESTALE;
        resident_fail(error, error_size,
                      "resident launch: image changed while being proved at %s",
                      image_path);
        return NULL;
    }
    char digest_hex[RESIDENT_LAUNCH_DIGEST_HEX + 1] = {0};
    zcl_hex_encode(digest, sizeof(digest), digest_hex);
    if (before.volume != accepted->image_volume ||
        before.file_low != accepted->image_low ||
        before.file_high != accepted->image_high ||
        before.size != accepted->image_size ||
        strcmp(digest_hex, accepted->image_sha3_hex) != 0) {
        platform_positioned_file_close(file);
        free(file);
        errno = ESTALE;
        resident_fail(error, error_size,
                      "resident launch: live image does not match the accepted"
                      " record (digest or positioned-file identity differs)");
        return NULL;
    }
    *snapshot_out = before;
    return file;
}
#endif

bool resident_launch_prepare(struct resident_launch *launch,
                             const char *image_path,
                             const struct resident_launch_accepted *accepted,
                             char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)launch; (void)image_path; (void)accepted;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!launch || !image_path || !image_path[0] || !accepted ||
        !accepted->image_sha3_hex[0]) {
        errno = EINVAL;
        resident_fail(error, error_size, "resident launch: invalid argument");
        return false;
    }
    struct platform_positioned_file_snapshot snapshot;
    struct platform_positioned_file *file = resident_open_accepted(
        image_path, accepted, &snapshot, error, error_size);
    if (!file) return false;
    unsigned char nonce_bytes[32];
    if (!rng_fill(nonce_bytes, sizeof(nonce_bytes))) {
        platform_positioned_file_close(file);
        free(file);
        errno = EIO;
        resident_fail(error, error_size,
                      "resident launch: launch nonce generation failed");
        return false;
    }
    resident_launch_init(launch);
    launch->pinned_native = (uintptr_t)file;
    launch->pinned_snapshot = snapshot;
    launch->accepted = *accepted;
    zcl_hex_encode(nonce_bytes, sizeof(nonce_bytes), launch->nonce);
    return true;
#endif
}

#if defined(__APPLE__)
/* Bind the pinned descriptor to the accepted bytes again before execution. */
bool resident_launch_revalidate(struct resident_launch *launch,
                                char *error, size_t error_size)
{
    struct platform_positioned_file *file =
        (struct platform_positioned_file *)(void *)launch->pinned_native;
    struct platform_positioned_file_snapshot before, after;
    unsigned char digest[32];
    char hex[65];
    if (!platform_positioned_file_snapshot(file, &before) ||
        !platform_positioned_file_snapshot_equal(&before, &launch->pinned_snapshot) ||
        !resident_sha3_positioned(file, digest) ||
        !platform_positioned_file_snapshot(file, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after)) {
        errno = ESTALE;
        resident_fail(error, error_size, "resident launch: pinned bytes changed after prepare");
        return false;
    }
    zcl_hex_encode(digest, sizeof digest, hex);
    if (strcmp(hex, launch->accepted.image_sha3_hex) != 0) {
        errno = ESTALE;
        resident_fail(error, error_size, "resident launch: pinned bytes changed from accepted hash");
        return false;
    }
    return true;
}
#endif

#if !defined(_WIN32) && !defined(__APPLE__)
/* The launch channel pair: the IPC socket (parent keeps one end, the
 * child inherits the other at the fixed slot) and the exec-status pipe
 * whose write end is CLOEXEC (a successful exec closes it; a failed exec
 * writes its errno first). */
static bool resident_spawn_channels(int ipc[2], int status_pipe[2],
                                    char *error, size_t error_size)
{
    ipc[0] = ipc[1] = -1;
    status_pipe[0] = status_pipe[1] = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc) != 0 ||
        pipe2(status_pipe, O_CLOEXEC) != 0) {
        int saved = errno;
        if (ipc[0] >= 0) close(ipc[0]);
        if (ipc[1] >= 0) close(ipc[1]);
        if (status_pipe[0] >= 0) close(status_pipe[0]);
        if (status_pipe[1] >= 0) close(status_pipe[1]);
        errno = saved;
        resident_fail(error, error_size,
                      "resident launch: IPC channel creation failed: %s",
                      strerror(saved));
        return false;
    }
    return true;
}

/* Move fd out of the child slot range [CHILD_FD, CHILD_FD + n_extra] so the
 * dup2 placement below cannot overwrite it. */
static int resident_child_clear_slot(int fd, size_t n_extra)
{
    int last = RESIDENT_LAUNCH_CHILD_FD + (int)n_extra;
    if (fd < RESIDENT_LAUNCH_CHILD_FD || fd > last) return fd;
    int moved = fcntl(fd, F_DUPFD_CLOEXEC, last + 1);
    if (moved < 0) _exit(126);
    return moved;
}

/* A confined child starts from a clean signal state: nothing the caller
 * blocked or ignored survives the exec, and it dies with the caller. The
 * getppid() re-check closes the window where the caller exits between the
 * fork and PR_SET_PDEATHSIG. */
static void resident_child_clean_signals(pid_t parent)
{
    sigset_t none;
    sigemptyset(&none);
    if (pthread_sigmask(SIG_SETMASK, &none, NULL) != 0) _exit(126);
    for (int sig = 1; sig < NSIG; ++sig) {
        if (sig == SIGKILL || sig == SIGSTOP) continue;
        struct sigaction dfl = {.sa_handler = SIG_DFL};
        sigaction(sig, &dfl, NULL);
    }
#if defined(__linux__)
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) _exit(126);
#endif
    if (getppid() != parent) _exit(126);
}

/* stdin, stdout and stderr become /dev/null; runs after every slot is placed,
 * so the descriptor open() returns is a free one. */
static void resident_child_null_stdio(void)
{
    int null = open("/dev/null", O_RDWR);
    if (null < 0) _exit(126);
    for (int fd = 0; fd <= 2; ++fd)
        if (null != fd && dup2(null, fd) < 0) _exit(126);
    if (null > 2) close(null);
}

static void resident_child_place_fds(struct resident_child_plan *plan)
{
    int source[RESIDENT_LAUNCH_EXTRA_FD_MAX];
    size_t n = plan->n_extra;
    plan->pinned_fd = resident_child_clear_slot(plan->pinned_fd, n);
    plan->status_write = resident_child_clear_slot(plan->status_write, n);
    plan->ipc_child = resident_child_clear_slot(plan->ipc_child, n);
    for (size_t i = 0; i < n; ++i)
        source[i] = resident_child_clear_slot(plan->extra_fds[i], n);
    if (dup2(plan->ipc_child, RESIDENT_LAUNCH_CHILD_FD) < 0) _exit(126);
    for (size_t i = 0; i < n; ++i)
        if (dup2(source[i], RESIDENT_LAUNCH_CHILD_FD + 1 + (int)i) < 0) _exit(126);
    if (plan->null_stdio) resident_child_null_stdio();
}

/* The child's side of a Linux spawn: new session, exactly the named
 * descriptors (stdio, the IPC socket at RESIDENT_LAUNCH_CHILD_FD, the caller's
 * extra descriptors after it, the pinned image, the status pipe), then exec
 * the pinned inode. Only ever returns on exec failure; the errno byte on the status pipe is the parent's
 * synchronous exec outcome. */
static void resident_child_exec(struct resident_child_plan plan,
                                char *const argv[], char *const envp[])
{
    if (setsid() < 0) _exit(126);
    if (plan.profile) resident_child_clean_signals(plan.parent);
    resident_child_place_fds(&plan);
    if (plan.profile) {
        resident_child_close_inherited(&plan);
        resident_child_arm(&plan);
    }
    if (platform_execve_fd(plan.pinned_fd, argv, envp) < 0) {
        int why = errno ? errno : ENOEXEC;
        unsigned char code = (unsigned char)(why & 0xff);
        ssize_t reported = write(plan.status_write, &code, 1); /* pre-exit errno report: the parent's read names the spawn failure */
        (void)reported;
        _exit(127);
    }
    _exit(126); /* unreachable: execve returns only on failure */
}

/* A confined image must be a static ELF (ADR-0004: apps are static PIE). A
 * PT_INTERP image would need a loader and libraries, which means granting
 * whole directories; no manifest field names exact interpreter objects yet,
 * so it is refused by name. */
#if defined(__linux__)
#define RESIDENT_ELF_PHNUM_MAX 128u

static bool resident_pread_exact(const struct platform_positioned_file *file,
                                 void *out, size_t size, uint64_t offset)
{
    int64_t got = platform_positioned_file_read(file, out, size, offset);
    return got == (int64_t)size;
}

static bool resident_image_check_headers(const struct platform_positioned_file *file,
                                         Elf64_Ehdr *eh)
{
    return resident_pread_exact(file, eh, sizeof(*eh), 0) &&
           memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
           eh->e_ident[EI_CLASS] == ELFCLASS64;
}

static unsigned char resident_native_data(void)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ELFDATA2LSB;
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ELFDATA2MSB;
#else
    return ELFDATANONE;
#endif
}

/* Check the native representation before interpreting program headers. */
static int resident_image_native(const Elf64_Ehdr *eh)
{
    unsigned char native_data = resident_native_data();
    if (native_data == ELFDATANONE) return -1;
    if (eh->e_ident[EI_DATA] != native_data ||
        eh->e_ident[EI_VERSION] != EV_CURRENT || eh->e_version != EV_CURRENT)
        return false;
#if defined(__x86_64__)
    return eh->e_machine == EM_X86_64;
#elif defined(__aarch64__)
    return eh->e_machine == EM_AARCH64;
#elif defined(__riscv) && __riscv_xlen == 64
    return eh->e_machine == EM_RISCV;
#else
    return -1;
#endif
}

static bool resident_image_static_only(const struct platform_positioned_file *file,
                                       char *error, size_t error_size)
{
    Elf64_Ehdr eh;
    if (!resident_image_check_headers(file, &eh)) {
        errno = ENOEXEC;
        resident_fail(error, error_size,
                      "resident launch: IMAGE_NOT_STATIC_ELF: a confined image"
                      " must be a 64-bit ELF with program headers");
        return false;
    }
    int native = resident_image_native(&eh);
    if (native < 0) {
        errno = ENOTSUP;
        resident_fail(error, error_size,
                      "resident launch: IMAGE_COMPATIBILITY_UNAVAILABLE:"
                      " native ELF machine or byte order is unsupported");
        return false;
    }
    if (!native) {
        errno = ENOEXEC;
        resident_fail(error, error_size,
                      "resident launch: IMAGE_NOT_NATIVE_ELF: incompatible"
                      " machine, byte order or ELF version");
        return false;
    }
    if (eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
        eh.e_phnum > RESIDENT_ELF_PHNUM_MAX) {
        errno = ENOEXEC;
        resident_fail(error, error_size,
                      "resident launch: IMAGE_NOT_STATIC_ELF: invalid program headers");
        return false;
    }
    for (unsigned i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr ph;
        if (!resident_pread_exact(file, &ph, sizeof(ph),
                                  eh.e_phoff + (uint64_t)i * sizeof(ph))) {
            errno = ENOEXEC;
            resident_fail(error, error_size,
                          "resident launch: IMAGE_NOT_STATIC_ELF: unreadable"
                          " program header");
            return false;
        }
        if (ph.p_type == PT_INTERP) {
            errno = ENOEXEC;
            resident_fail(error, error_size,
                          "resident launch: IMAGE_HAS_INTERPRETER: PT_INTERP"
                          " images are refused; apps must be static PIE (no"
                          " loader directory is ever granted)");
            return false;
        }
    }
    return true;
}

#else
static bool resident_image_static_only(const struct platform_positioned_file *file,
                                       char *error, size_t error_size)
{
    (void)file;
    errno = ENOTSUP;
    resident_fail(error, error_size,
                  "resident launch: CONFINEMENT_UNAVAILABLE: Linux-only");
    return false;
}
#endif

/* Re-prove the pinned BYTES before fork (metadata alone cannot on >=6.6
 * multigrain-timestamp kernels): a swapped image means no process ever exists.
 * Metadata-only changes (rename, unlink, chmod) do not alter the pinned bytes
 * and do not refuse - fexecve still maps exactly the accepted inode. */
static bool resident_preflight_bytes(const struct resident_launch *launch,
                                     const struct platform_positioned_file *file,
                                     char *error, size_t error_size)
{
    unsigned char digest[32];
    char hex[RESIDENT_LAUNCH_DIGEST_HEX + 1] = {0};
    if (!resident_sha3_positioned(file, digest)) {
        errno = EIO;
        resident_fail(error, error_size,
                      "resident launch: pinned image re-read failed");
        return false;
    }
    zcl_hex_encode(digest, sizeof(digest), hex);
    if (strcmp(hex, launch->accepted.image_sha3_hex) != 0) {
        errno = ESTALE;
        resident_fail(error, error_size,
                      "resident launch: image bytes changed after prepare;"
                      " refusing before fork");
        return false;
    }
    return true;
}

/* Report a handshake that did not reach a runnable child: kill and reap it
 * within a bounded grace, release the IPC end, name the state. */
static bool resident_handshake_refused(struct resident_launch *launch, pid_t pid,
                                       int ipc_parent,
                                       const struct resident_handshake_result *hs,
                                       char *error, size_t error_size)
{
    launch->pid = (uint64_t)pid;
    launch->exec_state = hs->state;
    launch->exec_errno = hs->err;
    bool reaped = resident_launch_kill_reap((uint64_t)pid, RESIDENT_REAP_GRACE_MS, NULL);
    close(ipc_parent);
    if (!reaped) {
        errno = EBUSY;
        resident_fail(error, error_size,
                      "resident launch: REAP_FAILED: child pid %lld survived"
                      " SIGKILL within the reap grace (handshake state %d)",
                      (long long)pid, (int)hs->state);
        return false;
    }
    switch (hs->state) {
    case RESIDENT_EXEC_TIMEOUT:
        errno = ETIMEDOUT;
        resident_fail(error, error_size,
                      "resident launch: LAUNCH_TIMEOUT: no exec handshake before"
                      " the deadline; child killed and reaped");
        break;
    case RESIDENT_EXEC_STATUS_ERROR:
        errno = hs->err ? hs->err : EIO;
        resident_fail(error, error_size,
                      "resident launch: STATUS_READ_ERROR: the exec status pipe"
                      " could not be read: %s", strerror(errno));
        break;
    case RESIDENT_EXEC_CHILD_DIED:
        errno = ECHILD;
        resident_fail(error, error_size,
                      "resident launch: child died before exec (crash,"
                      " not a successful launch); not retried");
        break;
    case RESIDENT_EXEC_CONFIRM_UNAVAILABLE:
        errno = EPERM;
        resident_fail(error, error_size,
                      "resident launch: exec-confirm-unavailable (ptrace_scope):"
                      " the child could not request exec tracing, so its exec"
                      " can never be confirmed; refusing to run");
        break;
    case RESIDENT_EXEC_SANDBOX_FAILED:
        errno = EPERM;
        resident_fail(error, error_size,
                      "resident launch: SANDBOX_FAILED: the OS sandbox could not"
                      " be armed in the child; refusing to run unconfined");
        break;
    default:
        errno = hs->err ? hs->err : ENOEXEC;
        resident_fail(error, error_size,
                      "resident launch: exec of the pinned image failed: %s",
                      strerror(errno));
        break;
    }
    return false;
}

static bool resident_spawn_fork(struct resident_child_plan plan,
                                char *const argv[], char *const envp[],
                                int ipc[2], int status_pipe[2], pid_t *pid_out,
                                char *error, size_t error_size)
{
    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        close(ipc[0]); close(ipc[1]);
        close(status_pipe[0]); close(status_pipe[1]);
        errno = saved;
        resident_fail(error, error_size, "resident launch: fork failed: %s",
                      strerror(saved));
        return false;
    }
    if (pid == 0) {
        /* status_pipe's write end is CLOEXEC: a successful exec closes it
         * and the parent reads EOF; a failed exec writes the errno first. */
        plan.ipc_child = ipc[1];
        plan.status_write = status_pipe[1];
        resident_child_exec(plan, argv, envp);
        _exit(126);
    }
    *pid_out = pid;
    return true;
}

static bool resident_confined_deadline(struct resident_launch *launch, uint64_t *deadline_ns,
                                       char *error, size_t error_size)
{
    *deadline_ns = launch->spawn_deadline_ns;
    bool clock_ok = *deadline_ns != 0 || resident_default_deadline(deadline_ns);
#ifdef ZCL_TESTING
    if (launch->debug_fail_clock) clock_ok = false; /* test seam: clock failure */
#endif
    if (clock_ok) return true;
    errno = EIO;
    resident_fail(error, error_size,
                  "resident launch: CLOCK_FAILED: the monotonic clock failed;"
                  " no deadline can be enforced, refusing before fork");
    return false;
}

/* The handshake let the child through: record it, then prove the exec. */
static bool resident_spawn_adopt(struct resident_launch *launch, pid_t pid, int ipc_parent,
                                 enum resident_exec_state state, uint64_t deadline_ns,
                                 bool confined, struct resident_receipt *receipt,
                                 char *error, size_t error_size)
{
    launch->ipc_native = (uintptr_t)ipc_parent;
    launch->spawned = true;
    launch->pid = (uint64_t)pid;
    if (!os_proc_pid_start_token(launch->pid, &launch->start_token)) {
        launch->start_token = 0;
    }
    /* Unconfined: the CLOEXEC pipe's EOF is the (original) exec proof and
     * fexecve maps the exact inode. Confined: EOF after the marker leaves the
     * exec UNPROVEN (the child may have died first), so the receipt says so
     * until the exec stop and /proc/<pid>/exe re-proof upgrade it. */
    launch->exec_state = state;
    (void)snprintf(receipt->mapped_proof, sizeof(receipt->mapped_proof), "%s",
                   confined ? "armed_exec_uncertain" : "fexecve_inode");
    if (confined)
        return resident_confirm_exec(launch, pid, deadline_ns, receipt, error, error_size);
    return resident_reproof_mapped(pid, launch, receipt, error, error_size);
}

/* The extra descriptors must be open, and no profile grant descriptor may sit
 * in a slot the child placement is about to overwrite. */
static bool resident_extra_fds_check(const struct resident_launch *launch,
                                     const struct os_sandbox_profile *profile,
                                     char *error, size_t error_size)
{
    size_t n = launch->n_extra_fds;
    if (n == 0 && !launch->null_stdio) return true;
    bool ok = profile != NULL && n <= RESIDENT_LAUNCH_EXTRA_FD_MAX;
    for (size_t i = 0; ok && i < n; ++i)
        ok = launch->extra_fds[i] >= 0 && fcntl(launch->extra_fds[i], F_GETFD) >= 0;
    int last = RESIDENT_LAUNCH_CHILD_FD + (int)n;
    for (size_t i = 0; ok && n && i < profile->n_fs_rules; ++i) {
        const struct os_sandbox_path_rule *rule = &profile->fs_rules[i];
        ok = !rule->has_fd || rule->fd < RESIDENT_LAUNCH_CHILD_FD || rule->fd > last;
    }
    if (ok) return true;
    errno = EINVAL;
    resident_fail(error, error_size,
                  "resident launch: extra descriptors and null stdio need a"
                  " confined spawn, open descriptors and grants outside the"
                  " child slot range");
    return false;
}

static bool resident_spawn_linux(struct resident_launch *launch,
                                 char *const argv[], char *const envp[],
                                 const struct os_sandbox_profile *profile,
                                 struct resident_receipt *receipt,
                                 char *error, size_t error_size)
{
    struct platform_positioned_file *file =
        (struct platform_positioned_file *)(void *)launch->pinned_native;
    int pinned_fd = (int)platform_positioned_file_native_fd(file);
    if (pinned_fd < 0) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: pinned image descriptor is gone");
        return false;
    }
    if (!resident_preflight_bytes(launch, file, error, error_size)) return false;
    if (profile && !resident_image_static_only(file, error, error_size)) return false;
    if (!resident_extra_fds_check(launch, profile, error, error_size)) return false;
    int ipc[2] = {-1, -1}, status_pipe[2] = {-1, -1};
    if (!resident_spawn_channels(ipc, status_pipe, error, error_size))
        return false;
    uint64_t deadline_ns = 0;
    if (profile && !resident_confined_deadline(launch, &deadline_ns, error, error_size)) {
        close(ipc[0]); close(ipc[1]);              /* every refusal closes both channels */
        close(status_pipe[0]); close(status_pipe[1]);
        return false;
    }
    struct resident_child_plan plan = {.pinned_fd = pinned_fd, .profile = profile,
                                       .extra_fds = launch->extra_fds,
                                       .n_extra = launch->n_extra_fds,
                                       .null_stdio = launch->null_stdio,
                                       .parent = getpid()};
#ifdef ZCL_TESTING
    plan.stall_ms = launch->debug_stall_before_marker_ms;
    plan.die_after_marker = launch->debug_die_after_marker;
    plan.fail_traceme = launch->debug_fail_traceme;
    plan.no_close_range = launch->debug_no_close_range;
#endif
    pid_t pid = 0;
    launch->exec_state = RESIDENT_EXEC_NONE;
    launch->exec_errno = 0;
    if (!resident_spawn_fork(plan, argv, envp, ipc, status_pipe, &pid,
                             error, error_size))
        return false;
    close(ipc[1]);
    close(status_pipe[1]);
    struct resident_handshake_result hs =
        resident_handshake_interpret(profile != NULL, status_pipe[0], deadline_ns);
    close(status_pipe[0]);
    if (!hs.proceed)
        return resident_handshake_refused(launch, pid, ipc[0], &hs, error, error_size);
    return resident_spawn_adopt(launch, pid, ipc[0], hs.state, deadline_ns, profile != NULL,
                                receipt, error, error_size);
}
#endif /* !defined(_WIN32) && !defined(__APPLE__) */

/* Refuse a confined spawn the host cannot enforce. Never degrades: an
 * unavailable Landlock or seccomp is a named refusal, not an unconfined run. */
#if !defined(_WIN32)
static bool resident_confine_supported(const struct os_sandbox_profile *profile,
                                       char *error, size_t error_size)
{
#if defined(__linux__)
    if (!profile->no_new_privs || !profile->landlock || !profile->seccomp) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: a confined spawn needs no_new_privs,"
                      " Landlock and seccomp in the profile");
        return false;
    }
    if (os_sandbox_landlock_abi() < 1) {
        errno = ENOTSUP;
        resident_fail(error, error_size,
                      "resident launch: LANDLOCK_UNAVAILABLE: the kernel"
                      " cannot confine the child; refusing to run unconfined");
        return false;
    }
    if (!os_sandbox_seccomp_supported()) {
        errno = ENOTSUP;
        resident_fail(error, error_size,
                      "resident launch: SECCOMP_UNAVAILABLE: the kernel cannot"
                      " confine the child; refusing to run unconfined");
        return false;
    }
    return true;
#else
    (void)profile;
    errno = ENOTSUP;
    resident_fail(error, error_size,
                  "resident launch: CONFINEMENT_UNAVAILABLE: confined native"
                  " launch is Linux-only; refusing to run unconfined");
    return false;
#endif
}
#endif /* !defined(_WIN32) */

static bool resident_spawn_common(struct resident_launch *launch,
                                  char *const argv[], char *const envp[],
                                  const struct os_sandbox_profile *profile,
                                  struct resident_receipt *receipt,
                                  char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)launch; (void)argv; (void)envp; (void)receipt; (void)profile;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!launch || launch->pinned_native == (uintptr_t)-1 ||
        launch->spawned || !argv || !argv[0] || !receipt) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: spawn needs a prepared, unspawned"
                      " launch with an argv");
        return false;
    }
    if (profile && !resident_confine_supported(profile, error, error_size))
        return false;
    memset(receipt, 0, sizeof(*receipt));
#if defined(__APPLE__)
    if (launch->n_extra_fds || launch->null_stdio) {
        errno = ENOTSUP;
        resident_fail(error, error_size,
                      "resident launch: extra descriptors are Linux-only");
        return false;
    }
    if (!resident_spawn_darwin(launch, argv, envp, receipt,
                               error, error_size))
        return false;
#else
    if (!resident_spawn_linux(launch, argv, envp, profile, receipt,
                              error, error_size))
        return false;
#endif
    (void)snprintf(receipt->nonce, sizeof(receipt->nonce), "%s",
                   launch->nonce);
    (void)snprintf(receipt->image_sha3_hex, sizeof(receipt->image_sha3_hex),
                   "%s", launch->accepted.image_sha3_hex);
    receipt->pid = launch->pid;
    receipt->start_token = launch->start_token;
    receipt->image_volume = launch->accepted.image_volume;
    receipt->image_low = launch->accepted.image_low;
    receipt->image_high = launch->accepted.image_high;
    receipt->image_size = launch->accepted.image_size;
    return true;
#endif
}

bool resident_launch_spawn(struct resident_launch *launch,
                           char *const argv[], char *const envp[],
                           struct resident_receipt *receipt,
                           char *error, size_t error_size)
{
    return resident_spawn_common(launch, argv, envp, NULL, receipt, error,
                                 error_size);
}

bool resident_launch_spawn_confined(struct resident_launch *launch,
                                    char *const argv[], char *const envp[],
                                    const struct os_sandbox_profile *profile,
                                    struct resident_receipt *receipt,
                                    char *error, size_t error_size)
{
    if (!profile) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: a confined spawn needs a profile");
        return false;
    }
    char local[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    char *msg = error && error_size ? error : local;
    size_t msg_size = error && error_size ? error_size : sizeof(local);
    bool ok = resident_spawn_common(launch, argv, envp, profile, receipt, msg,
                                    msg_size);
    if (!ok) LOG_ERROR("resident.launch", "confined spawn refused: %s", msg);
    return ok;
}

bool resident_launch_cancel(struct resident_launch *launch,
                            uint32_t timeout_ms,
                            char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)launch; (void)timeout_ms;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!launch || !launch->spawned) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: cancel needs a spawned launch");
        return false;
    }
    pid_t pid = (pid_t)launch->pid;
    /* Ask first over the IPC channel (a cooperative app stops on the stop
     * frame), then apply the deadline, then kill the process group the
     * child's setsid created. */
    if (launch->ipc_native != (uintptr_t)-1) {
        struct {
            char magic[16];
            char nonce[RESIDENT_LAUNCH_NONCE_HEX + 1u];
        } stop;
        memset(&stop, 0, sizeof(stop));
        (void)snprintf(stop.magic, sizeof(stop.magic), "%s",
                       RESIDENT_FRAME_MAGIC_STOP);
        (void)snprintf(stop.nonce, sizeof(stop.nonce), "%s", launch->nonce);
        (void)resident_send_bounded((int)launch->ipc_native, &stop, sizeof(stop),
                                    RESIDENT_STOP_SEND_BUDGET_MS);
    }
    uint32_t waited_ms = 0;
    int status = 0;
    while (waitpid(pid, &status, WNOHANG) == 0) {
        if (waited_ms >= timeout_ms) break;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&pause, NULL);
        waited_ms += 10;
    }
    if (waitpid(pid, &status, WNOHANG) == 0) {
        (void)kill(-pid, SIGKILL); /* the child is its own group leader */
        (void)kill(pid, SIGKILL);
    }
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    launch->spawned = false;
    return true;
#endif
}

#if !defined(_WIN32)
/* Frame admission policy: right magic, THIS launch's nonce, payload within
 * the caller's buffer. Everything else — including a frame from a
 * superseded launch — is refused by name. */
static bool resident_result_validate(const struct resident_launch *launch,
                                     const struct resident_result_header *wire,
                                     const void *payload, size_t payload_cap,
                                     char *error, size_t error_size)
{
    if (memcmp(wire->magic, RESIDENT_FRAME_MAGIC_RESULT,
               sizeof(RESIDENT_FRAME_MAGIC_RESULT)) != 0) {
        errno = EBADMSG;
        resident_fail(error, error_size,
                      "resident launch: result frame has a bad magic");
        return false;
    }
    if (memcmp(wire->nonce, launch->nonce, sizeof(wire->nonce)) != 0) {
        errno = ESTALE;
        resident_fail(error, error_size,
                      "result_stale_launch: frame carries another launch's"
                      " nonce");
        return false;
    }
    if (wire->payload_len > payload_cap || (!payload && wire->payload_len)) {
        errno = EMSGSIZE;
        resident_fail(error, error_size,
                      "resident launch: result payload %u exceeds the %zu"
                      " byte buffer",
                      (unsigned)wire->payload_len, payload_cap);
        return false;
    }
    return true;
}
#endif

#if !defined(_WIN32)
/* One absolute deadline covers every fragment of one result frame. */
struct resident_result_deadline {
    uint64_t end_ns;
    uint32_t timeout_ms;
};

static bool resident_result_now(uint64_t *now, char *error, size_t error_size)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        resident_fail(error, error_size, "resident launch: result clock failed: %s", strerror(errno));
        return false;
    }
    *now = (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
    return true;
}

static bool resident_result_timeout(const struct resident_result_deadline *deadline,
                                    char *error, size_t error_size)
{
    errno = ETIMEDOUT;
    resident_fail(error, error_size, "resident launch: result timed out after %u ms",
                  (unsigned)deadline->timeout_ms);
    return false;
}

static bool resident_result_wait(int fd, const struct resident_result_deadline *deadline,
                                 char *error, size_t error_size)
{
    for (;;) {
        uint64_t now;
        if (!resident_result_now(&now, error, error_size)) return false;
        if (deadline->timeout_ms && now >= deadline->end_ns)
            return resident_result_timeout(deadline, error, error_size);
        uint64_t remaining = now < deadline->end_ns ? deadline->end_ns - now : 0;
        uint64_t ms = remaining / UINT64_C(1000000) + (remaining % UINT64_C(1000000) != 0);
        int wait_ms = ms > INT_MAX ? INT_MAX : (int)ms;
        struct pollfd waiter = {.fd = fd, .events = POLLIN};
        int ready = poll(&waiter, 1, wait_ms);
        if (ready > 0) return true; /* recv distinguishes data, EOF and socket errors. */
        if (ready == 0) {
            if (!deadline->timeout_ms) return resident_result_timeout(deadline, error, error_size);
            continue; /* A capped poll interval may end before a long deadline. */
        }
        if (errno == EINTR && deadline->timeout_ms) continue;
        if (errno == EINTR) return resident_result_timeout(deadline, error, error_size);
        resident_fail(error, error_size, "resident launch: result poll failed: %s", strerror(errno));
        return false;
    }
}

static bool resident_result_live(const struct resident_result_deadline *deadline,
                                 char *error, size_t error_size)
{
    if (!deadline->timeout_ms) return true; /* Zero retains nonblocking drain semantics. */
    uint64_t now;
    if (!resident_result_now(&now, error, error_size)) return false;
    return now < deadline->end_ns || resident_result_timeout(deadline, error, error_size);
}

static bool resident_result_fragment(int fd, void *data, size_t size,
    const struct resident_result_deadline *deadline, bool header,
    char *error, size_t error_size)
{
    unsigned char *bytes = data;
    size_t done = 0;
    while (done < size) {
        if (!resident_result_live(deadline, error, error_size)) return false;
        /* MSG_DONTWAIT also bounds readers whose caller did not set O_NONBLOCK. */
        ssize_t got = recv(fd, bytes + done, size - done, MSG_DONTWAIT);
        if (got > 0) { done += (size_t)got; continue; }
        if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!deadline->timeout_ms) return resident_result_timeout(deadline, error, error_size);
            if (!resident_result_wait(fd, deadline, error, error_size)) return false;
            continue;
        }
        errno = ECONNRESET;
        resident_fail(error, error_size, "%s",
            header && got == 0 ? "resident launch: resident closed the channel" :
            header ? "resident launch: truncated result header" :
                     "resident launch: truncated result payload");
        return false;
    }
    return true;
}
#endif

bool resident_result_read(struct resident_launch *launch,
                          struct resident_result_header *header,
                          void *payload, size_t payload_cap,
                          uint32_t timeout_ms,
                          char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)launch; (void)header; (void)payload; (void)payload_cap;
    (void)timeout_ms;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!launch || !header || launch->ipc_native == (uintptr_t)-1) {
        errno = EINVAL;
        resident_fail(error, error_size,
                      "resident launch: result read needs a live launch");
        return false;
    }
    uint64_t now;
    if (!resident_result_now(&now, error, error_size)) return false;
    struct resident_result_deadline deadline = {
        .end_ns = now + (uint64_t)timeout_ms * UINT64_C(1000000),
        .timeout_ms = timeout_ms
    };
    int fd = (int)launch->ipc_native;
    struct resident_result_header wire;
    if (!resident_result_fragment(fd, &wire, sizeof(wire), &deadline, true,
                                   error, error_size)) return false;
    if (!resident_result_validate(launch, &wire, payload, payload_cap,
                                  error, error_size)) return false;
    if (wire.payload_len && !resident_result_fragment(fd, payload, wire.payload_len,
            &deadline, false, error, error_size)) return false;
    *header = wire;
    return true;
#endif
}

#if !defined(_WIN32)
static bool resident_startup_expired(const char *phase, char *error, size_t error_size)
{
    errno = ETIMEDOUT;
    resident_fail(error, error_size, "resident launch: %s startup budget expired", phase);
    return false;
}

static bool resident_startup_frame(struct resident_launch *launch,
    const struct resident_result_deadline *deadline, char payload[64],
    uint32_t *length, char *error, size_t error_size)
{
    struct resident_result_header wire;
    int fd = (int)launch->ipc_native;
    if (!resident_result_fragment(fd, &wire, sizeof(wire), deadline, true, error, error_size) ||
        !resident_result_validate(launch, &wire, payload, 63, error, error_size) ||
        !resident_result_fragment(fd, payload, wire.payload_len, deadline, false, error, error_size) ||
        !resident_result_live(deadline, error, error_size)) return false;
    payload[wire.payload_len] = 0;
    *length = wire.payload_len;
    return true;
}

static bool resident_startup_entry(const char *payload, uint32_t length, uint64_t *entry)
{
    if (length < 7 || memcmp(payload, "ENTRY ", 6) != 0) return false;
    uint64_t value = 0;
    for (uint32_t i = 6; i < length; ++i) {
        unsigned char digit = (unsigned char)payload[i];
        if (digit < '0' || digit > '9' || value > ((uint64_t)INT64_MAX - (digit - '0')) / 10u)
            return false;
        value = value * 10u + (digit - '0');
    }
    *entry = value;
    return value != 0;
}

static bool resident_startup_first_byte(struct resident_launch *launch,
    struct resident_startup *startup, char *error, size_t error_size)
{
    struct resident_result_deadline platform = {
        .end_ns = startup->platform_end_ns, .timeout_ms = startup->platform_ms
    };
    int fd = (int)launch->ipc_native;
    for (;;) {
        if (!resident_startup_check(startup, error, error_size)) return false;
        unsigned char byte;
        ssize_t got = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
        if (got > 0) {
            if (!resident_result_now(&startup->entry_observed_ns, error, error_size)) return false;
            return startup->entry_observed_ns < startup->platform_end_ns ||
                resident_startup_expired("platform-entry", error, error_size);
        }
        if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!resident_result_wait(fd, &platform, error, error_size)) return false;
            continue;
        }
        errno = ECONNRESET;
        resident_fail(error, error_size, "resident launch: child closed before startup entry");
        return false;
    }
}
#endif

bool resident_startup_begin(struct resident_startup *startup,
    uint32_t platform_ms, uint32_t protocol_ms, char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)startup; (void)platform_ms; (void)protocol_ms;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!startup || !platform_ms || !protocol_ms) {
        errno = EINVAL;
        resident_fail(error, error_size, "resident launch: nonzero startup phase budgets required");
        return false;
    }
    memset(startup, 0, sizeof(*startup));
    if (!resident_result_now(&startup->began_ns, error, error_size)) return false;
    startup->platform_ms = platform_ms;
    startup->protocol_ms = protocol_ms;
    startup->platform_end_ns = startup->began_ns + (uint64_t)platform_ms * UINT64_C(1000000);
    startup->total_end_ns = startup->platform_end_ns + (uint64_t)protocol_ms * UINT64_C(1000000);
    return true;
#endif
}

bool resident_startup_check(const struct resident_startup *startup,
    char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)startup;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    uint64_t now;
    if (!startup || !startup->platform_ms || !startup->protocol_ms) {
        errno = EINVAL;
        resident_fail(error, error_size, "resident launch: startup budget was not initialized");
        return false;
    }
    if (!resident_result_now(&now, error, error_size)) return false;
    return now < startup->platform_end_ns || resident_startup_expired("platform-entry", error, error_size);
#endif
}

bool resident_startup_read(struct resident_launch *launch,
    struct resident_startup *startup, char *error, size_t error_size)
{
#if defined(_WIN32)
    (void)launch; (void)startup;
    errno = ENOTSUP;
    resident_fail(error, error_size, "%s", RESIDENT_WIN_REFUSAL);
    return false;
#else
    if (!launch || !startup || launch->ipc_native == (uintptr_t)-1 || startup->entry_observed_ns) {
        errno = EINVAL;
        resident_fail(error, error_size, "resident launch: unused startup budget and live channel required");
        return false;
    }
    if (!resident_startup_first_byte(launch, startup, error, error_size)) return false;
    uint64_t end = startup->entry_observed_ns + (uint64_t)startup->protocol_ms * UINT64_C(1000000);
    struct resident_result_deadline protocol = {
        .end_ns = end < startup->total_end_ns ? end : startup->total_end_ns,
        .timeout_ms = startup->protocol_ms
    };
    char payload[64];
    uint32_t length;
    if (!resident_startup_frame(launch, &protocol, payload, &length, error, error_size)) return false;
    if (resident_startup_entry(payload, length, &startup->child_entry_ns)) {
        if (!resident_startup_frame(launch, &protocol, payload, &length, error, error_size)) return false;
    }
    if (length != 5 || memcmp(payload, "READY", 5) != 0) {
        errno = EBADMSG;
        resident_fail(error, error_size, "resident launch: expected one ENTRY then READY, or legacy READY");
        return false;
    }
    if (!resident_result_now(&startup->ready_ns, error, error_size)) return false;
    return startup->ready_ns < protocol.end_ns || resident_startup_expired("READY protocol", error, error_size);
#endif
}

void resident_launch_close(struct resident_launch *launch)
{
    if (!launch) return;
#if !defined(_WIN32)
    if (launch->ipc_native != (uintptr_t)-1 &&
        launch->ipc_native != UINTPTR_MAX) {
        close((int)launch->ipc_native);
    }
#endif
    if (launch->pinned_native != (uintptr_t)-1 &&
        launch->pinned_native != UINTPTR_MAX) {
        struct platform_positioned_file *file =
            (struct platform_positioned_file *)(void *)launch->pinned_native;
        platform_positioned_file_close(file);
        free(file);
    }
    resident_launch_init(launch);
}
