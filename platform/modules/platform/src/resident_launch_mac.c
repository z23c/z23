/* Copyright 2026 Rhett Creighton - Apache-2.0
 * Purpose: Darwin arm of the exact resident launch (suspended spawn + CodeDirectory proof) */
/* Purpose: Darwin arm of the exact resident launch.
 *
 * macOS has no fexecve(2), so a descriptor-bound exec is unavailable — but
 * the kernel can prove the mapped image of a suspended child before its
 * first instruction. F_ADDFILESIGS_INFO returns the CodeDirectory hash for
 * the ALREADY-PINNED descriptor; POSIX_SPAWN_START_SUSPENDED maps the
 * spawned image without running anything; csops(CS_OPS_CDHASH) returns the
 * CodeDirectory hash of that exact mapped process. Equality of the two
 * hashes is the mapped-image receipt. The pathname handed to posix_spawn
 * is a LOCATOR only: replace it between F_GETPATH and spawn and the hashes
 * disagree, so the child is killed before it executes a single instruction.
 *
 * This is the production extraction of an idiom that first shipped in the
 * dev/test process executor; that copy remains until its own lane migrates
 * it onto this module (single source of truth, no forked family).
 */
#if defined(__APPLE__)

#include "resident_launch_internal.h"

#include "platform/os_proc.h"
#include "platform/positioned_file.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* csops is stable Darwin kernel ABI (syscall 169) and exported by libSystem,
 * but the public macOS SDK omits its user declaration. */
extern int csops(pid_t pid, unsigned int ops, void *useraddr,
                 size_t usersize);
enum { ZCL_DARWIN_CS_OPS_CDHASH = 5 };
#define ZCL_DARWIN_CDHASH_LEN 20u

static void rl_mac_fail(char *error, size_t error_size, const char *what)
{
    if (!error || !error_size) return;
    (void)snprintf(error, error_size, "resident launch: %s: %s", what,
                   strerror(errno));
}

static bool rl_mac_pread_exact(int fd, void *body, size_t body_len,
                               off_t offset)
{
    unsigned char *p = body;
    size_t done = 0;
    while (done < body_len) {
        ssize_t got = pread(fd, p + done, body_len - done, offset + (off_t)done);
        if (got > 0) {
            done += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR) continue;
        errno = errno ? errno : EINVAL;
        return false;
    }
    return true;
}

/* Walks the load commands for the single LC_CODE_SIGNATURE row, refusing
 * ambiguous or out-of-bounds commands. Returns false with errno set. */
static bool rl_mac_find_signature_command(int fd, const struct mach_header_64 *header,
                                          uint64_t commands_end,
                                          const struct stat *st,
                                          off_t *blob_offset,
                                          size_t *blob_size)
{
    uint64_t cursor = sizeof(*header);
    bool found = false;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command command;
        if (cursor + sizeof(command) > commands_end ||
            !rl_mac_pread_exact(fd, &command, sizeof(command), (off_t)cursor))
            return false;
        if (command.cmdsize < sizeof(command) ||
            cursor + command.cmdsize > commands_end) {
            errno = ENOEXEC;
            return false;
        }
        if (command.cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command signature_command;
            if (found || command.cmdsize < sizeof(signature_command) ||
                !rl_mac_pread_exact(fd, &signature_command,
                                    sizeof(signature_command), (off_t)cursor)) {
                errno = ENOEXEC;
                return false;
            }
            uint64_t signature_end = (uint64_t)signature_command.dataoff +
                                     (uint64_t)signature_command.datasize;
            if (signature_command.datasize == 0 ||
                signature_end > (uint64_t)st->st_size) {
                errno = ENOEXEC;
                return false;
            }
            *blob_offset = (off_t)signature_command.dataoff;
            *blob_size = (size_t)signature_command.datasize;
            found = true;
        }
        cursor += command.cmdsize;
    }
    if (!found || cursor != commands_end) {
        errno = ENOEXEC;
        return false;
    }
    return true;
}

/* Locates the LC_CODE_SIGNATURE blob of a native thin MH_EXECUTE Mach-O,
 * with every load-command bound checked. Returns false with errno set
 * (ENOEXEC for malformed images, EIO for read failures). */
static bool rl_mac_code_signature_region(int fd, const struct stat *st,
                                         off_t *blob_offset,
                                         size_t *blob_size)
{
    struct mach_header_64 header;
    if (!rl_mac_pread_exact(fd, &header, sizeof(header), 0)) return false;
#if defined(__aarch64__)
    const cpu_type_t native_cpu = CPU_TYPE_ARM64;
#elif defined(__x86_64__)
    const cpu_type_t native_cpu = CPU_TYPE_X86_64;
#else
    errno = ENOTSUP;
    return false;
#endif
    uint64_t commands_end = sizeof(header) + (uint64_t)header.sizeofcmds;
    if (header.magic != MH_MAGIC_64 || header.cputype != native_cpu ||
        header.filetype != MH_EXECUTE ||
        commands_end > (uint64_t)st->st_size ||
        header.ncmds > header.sizeofcmds / sizeof(struct load_command)) {
        errno = ENOEXEC;
        return false;
    }
    return rl_mac_find_signature_command(fd, &header, commands_end, st,
                                         blob_offset, blob_size);
}

static void rl_mac_reap_suspended(pid_t pid)
{
    (void)kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
}

static int rl_mac_spawn_attributes(posix_spawnattr_t *attributes, bool desktop_signals)
{
    int rc = 0;
    short flags = POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSID |
                  POSIX_SPAWN_CLOEXEC_DEFAULT;
    if (desktop_signals) {
        const int signals[] = {SIGPIPE, SIGTERM, SIGINT, SIGHUP, SIGUSR1, SIGCHLD};
        sigset_t defaults, empty;
        sigemptyset(&defaults); sigemptyset(&empty);
        for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i)
            sigaddset(&defaults, signals[i]);
        rc = posix_spawnattr_setsigdefault(attributes, &defaults);
        if (rc == 0) rc = posix_spawnattr_setsigmask(attributes, &empty);
        flags |= POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    }
    if (rc == 0) rc = posix_spawnattr_setflags(attributes, flags);
    return rc;
}

static int rl_mac_spawn_actions(posix_spawn_file_actions_t *actions,
                                int ipc_child, int logfd)
{
    int rc = posix_spawn_file_actions_init(actions);
    if (rc != 0) return rc;
    if (rc == 0 && logfd >= 0)
        rc = posix_spawn_file_actions_addopen(actions, 0, "/dev/null", O_RDONLY, 0);
    if (rc == 0 && logfd >= 0)
        rc = posix_spawn_file_actions_adddup2(actions, logfd, 1);
    if (rc == 0 && logfd >= 0)
        rc = posix_spawn_file_actions_adddup2(actions, logfd, 2);
    if (rc == 0)
        rc = posix_spawn_file_actions_adddup2(actions, ipc_child,
                                              RESIDENT_LAUNCH_CHILD_FD);
    if (rc == 0 && ipc_child != RESIDENT_LAUNCH_CHILD_FD)
        rc = posix_spawn_file_actions_addclose(actions, ipc_child);
    if (rc != 0) posix_spawn_file_actions_destroy(actions);
    return rc;
}

/* Suspended spawn of the locator path with exactly one inherited
 * descriptor: the IPC socket dup'd to the fixed child slot. CLOEXEC_DEFAULT
 * closes every other descriptor in the child. */
static bool rl_mac_suspended_spawn(int ipc_child, int logfd, bool desktop_signals, const char *locator,
                                   char *const argv[], char *const envp[],
                                   pid_t *pid_out,
                                   char *error, size_t error_size)
{
    posix_spawn_file_actions_t actions;
    int rc = rl_mac_spawn_actions(&actions, ipc_child, logfd);
    if (rc != 0) {
        errno = rc;
        rl_mac_fail(error, error_size, "spawn file-actions setup failed");
        return false;
    }
    posix_spawnattr_t attributes;
    rc = posix_spawnattr_init(&attributes);
    if (rc != 0) {
        posix_spawn_file_actions_destroy(&actions);
        errno = rc;
        rl_mac_fail(error, error_size, "suspended spawn setup failed");
        return false;
    }
    rc = rl_mac_spawn_attributes(&attributes, desktop_signals);
    if (rc != 0) {
        posix_spawn_file_actions_destroy(&actions);
        posix_spawnattr_destroy(&attributes);
        errno = rc;
        rl_mac_fail(error, error_size, "suspended spawn setup failed");
        return false;
    }
    rc = posix_spawn(pid_out, locator, &actions, &attributes, argv, envp);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        errno = rc;
        rl_mac_fail(error, error_size, "suspended spawn failed");
        return false;
    }
    return true;
}

/* Proves the suspended child's mapped CodeDirectory equals the pinned
 * descriptor's hash. On any mismatch the child is killed before its first
 * instruction (ESTALE) — the pathname was a locator, the hashes are the
 * proof. */
static bool rl_mac_attest(pid_t pid, const unsigned char expected[20],
                          char *error, size_t error_size)
{
    unsigned char mapped[ZCL_DARWIN_CDHASH_LEN] = {0};
    if (csops(pid, ZCL_DARWIN_CS_OPS_CDHASH, mapped, sizeof(mapped)) != 0) {
        int saved = errno;
        rl_mac_reap_suspended(pid);
        errno = saved;
        rl_mac_fail(error, error_size, "mapped CodeDirectory query failed");
        return false;
    }
    if (memcmp(mapped, expected, sizeof(mapped)) != 0) {
        rl_mac_reap_suspended(pid);
        errno = ESTALE;
        if (error && error_size)
            (void)snprintf(error, error_size,
                           "resident launch: descriptor/mapped CodeDirectory"
                           " mismatch; child refused before execution");
        return false;
    }
    return true;
}

bool resident_spawn_darwin(struct resident_launch *launch,
                           char *const argv[], char *const envp[],
                           struct resident_receipt *receipt,
                           char *error, size_t error_size)
{
    struct platform_positioned_file *file =
        (struct platform_positioned_file *)(void *)launch->pinned_native;
    int exec_fd = (int)platform_positioned_file_native_fd(file);
    if (exec_fd < 0) {
        errno = EINVAL;
        rl_mac_fail(error, error_size, "pinned descriptor is gone");
        return false;
    }
    struct stat executable_stat;
    if (!resident_launch_revalidate(launch, error, error_size)) return false;
    if (fstat(exec_fd, &executable_stat) != 0) {
        rl_mac_fail(error, error_size, "pinned descriptor fstat failed");
        return false;
    }
    off_t signature_offset = 0;
    size_t signature_size = 0;
    if (!rl_mac_code_signature_region(exec_fd, &executable_stat,
                                      &signature_offset, &signature_size)) {
        rl_mac_fail(error, error_size,
                    "pinned image has no exact native code signature");
        return false;
    }
    fsignatures_t signature = {0};
    signature.fs_file_start = 0;
    signature.fs_blob_start = (void *)(uintptr_t)signature_offset;
    signature.fs_blob_size = signature_size;
    signature.fs_fsignatures_size = sizeof(signature);
    if (fcntl(exec_fd, F_ADDFILESIGS_INFO, &signature) != 0) {
        rl_mac_fail(error, error_size,
                    "descriptor CodeDirectory query failed");
        return false;
    }
    char locator[PATH_MAX];
    if (!resident_launch_revalidate(launch, error, error_size)) return false;
    if (fcntl(exec_fd, F_GETPATH, locator) != 0) {
        rl_mac_fail(error, error_size, "locator path query failed");
        return false;
    }

    int ipc[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, ipc) != 0) {
        rl_mac_fail(error, error_size, "IPC channel creation failed");
        return false;
    }
    pid_t pid = -1;
    if (!rl_mac_suspended_spawn(ipc[1], launch->log_stdio ? launch->log_stdio_fd : -1, launch->desktop_signals, locator, argv, envp, &pid,
                                error, error_size)) {
        close(ipc[0]);
        close(ipc[1]);
        return false;
    }
    close(ipc[1]);
    if (!resident_launch_revalidate(launch, error, error_size)) {
        rl_mac_reap_suspended(pid);
        close(ipc[0]);
        return false;
    }
    if (!rl_mac_attest(pid, (const unsigned char *)signature.fs_cdhash,
                       error, error_size)) {
        close(ipc[0]);
        return false;
    }
    /* The mapped image IS the pinned image; let it run. */
    if (kill(pid, SIGCONT) != 0) {
        int saved = errno;
        rl_mac_reap_suspended(pid);
        close(ipc[0]);
        errno = saved;
        rl_mac_fail(error, error_size, "resume of the proven child failed");
        return false;
    }
    launch->ipc_native = (uintptr_t)ipc[0];
    launch->spawned = true;
    launch->pid = (uint64_t)pid;
    if (!os_proc_pid_start_token(launch->pid, &launch->start_token))
        launch->start_token = 0;
    (void)snprintf(receipt->mapped_proof, sizeof(receipt->mapped_proof),
                   "cdhash_suspended");
    return true;
}

#else
/* Keep the translation unit non-empty off Apple hosts: the clang
 * portability gate compiles every C file with -pedantic, and an empty
 * unit is a diagnostic there. */
typedef int zcl_resident_launch_mac_not_built_here;
#endif /* defined(__APPLE__) */
