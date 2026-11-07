/* Copyright 2026 Rhett Creighton - Apache-2.0
 * Purpose: exact resident process launch bound to an accepted artifact */
/* Exact resident process launch bound to an accepted artifact.
 *
 * The launcher half of the app-run seam: given an artifact the caller has
 * ALREADY accepted (content root + positioned-file identity), prepare()
 * re-proves the live bytes and handle identity, spawn() executes exactly
 * that inode via fexecve(2) — never a pathname re-open — hands the child
 * one inherited IPC socket at a fixed descriptor, and returns a receipt
 * binding pid + start token + nonce + image identity. Result frames the
 * child sends back are accepted only while they carry this launch's nonce,
 * so a superseded launch's late results are rejected by name.
 *
 * Platform posture follows os_binary_slots: there is no descriptor-bound
 * execution on macOS or Windows (platform_execve_fd refuses ENOTSUP by
 * design), so spawn() refuses by name there rather than reconstructing a
 * pathname — a TOCTOU hole dressed as a launch. Only Linux proves a mapped
 * image today; the receipt says which proof it carries.
 */
#ifndef ZCL_PLATFORM_RESIDENT_LAUNCH_H
#define ZCL_PLATFORM_RESIDENT_LAUNCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "platform/positioned_file.h"
#include "platform/os_sandbox.h"

#define RESIDENT_LAUNCH_NONCE_HEX 64u
#define RESIDENT_LAUNCH_DIGEST_HEX 64u
#define RESIDENT_LAUNCH_ERROR_MAX 256u
/* The one descriptor the resident child receives: the IPC socket, dup2'd to
 * this fixed number before exec so an app never has to discover it. */
#define RESIDENT_LAUNCH_CHILD_FD 3
/* Most extra descriptors a confined child can be handed; see
 * resident_launch.extra_fds. */
#define RESIDENT_LAUNCH_EXTRA_FD_MAX 8u
#if defined(__APPLE__)
#define RESIDENT_STARTUP_PLATFORM_MS 4000u
#else
#define RESIDENT_STARTUP_PLATFORM_MS 2000u
#endif
#define RESIDENT_STARTUP_PROTOCOL_MS 100u
/* Default deadline for a confined spawn handshake when the caller sets none. */
#define RESIDENT_CONFINED_SPAWN_DEFAULT_MS 10000u
/* Grace the bounded reap waits for a SIGKILLed child before giving up. */
#define RESIDENT_REAP_GRACE_MS 2000u
/* Upper bound on a healthy resident child's answer to one input; a loaded host needs far more than startup. */
#define RESIDENT_RESULT_DEADLINE_MS 30000u

/* What the caller must already hold from acceptance time: the artifact's
 * SHA3-256 content root and the positioned-file identity triple captured
 * over the accepted handle. prepare() refuses any image whose live bytes,
 * size or triple differ — fail-closed BEFORE any process exists. */
struct resident_launch_accepted {
    char image_sha3_hex[RESIDENT_LAUNCH_DIGEST_HEX + 1u];
    uint64_t image_volume, image_low, image_high, image_size;
};

/* Outcome of the launch handshake on the CLOEXEC status pipe. The pipe closes
 * on a successful exec, so EOF after the armed marker proves nothing about the
 * exec itself: the child may have died between the marker and the exec.
 * ARMED_UNCERTAIN says exactly that - the sandbox was armed, the exec is not
 * proven (it becomes CONFIRMED only when /proc/<pid>/exe re-proves the image).
 * NOT FROZEN: N4 (macOS backend) follows this enum. */
enum resident_exec_state {
    RESIDENT_EXEC_NONE = 0,         /* no confined handshake ran (or unconfined) */
    RESIDENT_EXEC_ARMED_UNCERTAIN,  /* marker then EOF: armed, exec unproven */
    RESIDENT_EXEC_CONFIRMED,        /* image identity re-proved after exec */
    RESIDENT_EXEC_FAILED,           /* the child reported an exec errno */
    RESIDENT_EXEC_SANDBOX_FAILED,   /* the child could not arm the sandbox */
    RESIDENT_EXEC_CHILD_DIED,       /* EOF with no marker: died before arming */
    RESIDENT_EXEC_STATUS_ERROR,     /* reading the status pipe failed */
    RESIDENT_EXEC_TIMEOUT,          /* the launch deadline elapsed */
    RESIDENT_EXEC_CONFIRM_UNAVAILABLE /* child could not request exec tracing */
};

/* Binds one resident OS process to the exact accepted image. `start_token`
 * is the kernel's per-process start stamp, so the handle survives pid
 * reuse. `mapped_proof` names what was proven: "fexecve_inode" (the kernel
 * mapped the exact inode this launcher pinned) on every Linux spawn, or
 * "proc_exe_triple" when the child lived long enough for the post-spawn
 * /proc/<pid>/exe re-proof as well. */
struct resident_receipt {
    char nonce[RESIDENT_LAUNCH_NONCE_HEX + 1u];
    char image_sha3_hex[RESIDENT_LAUNCH_DIGEST_HEX + 1u];
    uint64_t pid;
    uint64_t start_token;
    uint64_t image_volume, image_low, image_high, image_size;
    char mapped_proof[24];
};

/* Every frame on the IPC socket starts with this wire header. The child
 * echoes the launch nonce it received; the parent accepts a frame only
 * while that nonce is the current launch's. */
struct resident_result_header {
    char magic[16]; /* "z23-res-run-v1\0" */
    char nonce[RESIDENT_LAUNCH_NONCE_HEX + 1u];
    uint32_t payload_len;
};

struct resident_launch {
    uintptr_t pinned_native;    /* struct platform_positioned_file * */
    uintptr_t ipc_native;       /* parent socket end (or -1) */
    struct platform_positioned_file_snapshot pinned_snapshot;
    struct resident_launch_accepted accepted;
    char nonce[RESIDENT_LAUNCH_NONCE_HEX + 1u];
    uint64_t pid;
    uint64_t start_token;
    bool spawned;
    /* NOT FROZEN (N4 follows). Absolute CLOCK_MONOTONIC-equivalent deadline in
     * ns (platform_time_monotonic_us * 1000) covering a confined spawn's whole
     * handshake; 0 selects RESIDENT_CONFINED_SPAWN_DEFAULT_MS. Set AFTER
     * prepare(), which re-initialises the struct. */
    uint64_t spawn_deadline_ns;
    /* Optional, confined spawns only; set AFTER prepare(). Parent descriptors
     * the child receives at RESIDENT_LAUNCH_CHILD_FD + 1 + i, in order, with
     * close-on-exec cleared on those copies only. The parent keeps its own
     * copies. Every other descriptor is swept in the child before the sandbox
     * arms. A grant descriptor of the profile inside the child's slot range
     * [RESIDENT_LAUNCH_CHILD_FD, RESIDENT_LAUNCH_CHILD_FD + n_extra_fds] is
     * refused. Zero leaves the single-descriptor contract unchanged. */
    int extra_fds[RESIDENT_LAUNCH_EXTRA_FD_MAX];
    size_t n_extra_fds;
    /* Confined spawns only; set AFTER prepare(). The child's stdin, stdout and
     * stderr are /dev/null instead of the caller's. */
    bool null_stdio;
    /* Unconfined desktop spawn only, set after prepare. Borrowed writable
     * regular-file descriptor; child stdin is /dev/null and stdout/stderr
     * are duplicated to it. Caller retains ownership. Incompatible with
     * confined spawn, null_stdio and extra descriptor grants. */
    bool log_stdio;
    int log_stdio_fd;
    /* Opt-in desktop spawn signal mask and dispositions, set after prepare. */
    bool desktop_signals;
    /* Last confined handshake outcome and, for EXEC_FAILED, the child's errno. */
    enum resident_exec_state exec_state;
    int exec_errno;
#ifdef ZCL_TESTING
    /* Test-only fault injection (compiled only into test builds): stall the
     * child this long before the armed marker, or make it die right after it. */
    uint32_t debug_stall_before_marker_ms;
    bool debug_die_after_marker;
    bool debug_fail_traceme; /* force the exec-confirm refusal */
    bool debug_fail_reproof_hash; /* the mapped-image re-hash fails */
    bool debug_fail_clock;        /* the deadline clock fails after channels exist */
    bool debug_no_close_range;    /* close_range(2) unavailable in the child */
    uint32_t debug_reproof_delay_ms; /* sleep inside confirmation, before the reproof */
#endif
};

/* Parent monotonic authority. The first observed IPC byte starts the tight
 * protocol phase, including ENTRY/READY framing; child timestamps never
 * extend a deadline. Legacy children may send READY without ENTRY. */
struct resident_startup {
    uint64_t began_ns, platform_end_ns, total_end_ns;
    uint64_t entry_observed_ns, child_entry_ns, ready_ns;
    uint32_t platform_ms, protocol_ms;
};

bool resident_startup_begin(struct resident_startup *startup,
    uint32_t platform_ms, uint32_t protocol_ms, char *error, size_t error_size);
bool resident_startup_check(const struct resident_startup *startup,
    char *error, size_t error_size);
bool resident_startup_read(struct resident_launch *launch,
    struct resident_startup *startup, char *error, size_t error_size);

void resident_launch_init(struct resident_launch *launch);
/* Opens, hashes and identity-checks the image against `accepted`. No fd is
 * inheritable yet; nothing is spawned. */
bool resident_launch_prepare(struct resident_launch *launch,
                             const char *image_path,
                             const struct resident_launch_accepted *accepted,
                             char *error, size_t error_size);
/* fork + fexecve(pinned fd); the child inherits exactly one descriptor:
 * the IPC socket at RESIDENT_LAUNCH_CHILD_FD (n_extra_fds must be 0). Returns only after the exec
 * outcome is known (exec failure is reported here, not silently lost) and
 * the receipt is complete. */
bool resident_launch_spawn(struct resident_launch *launch,
                           char *const argv[], char *const envp[],
                           struct resident_receipt *receipt,
                           char *error, size_t error_size);
/* Same exact fexecve launch, but the child arms `profile` (built BEFORE the
 * fork by the caller) with os_sandbox_enter just before the exec. The profile
 * must enable no_new_privs, Landlock (with EXECUTE on the image only; no loader
 * directory is granted, so a PT_INTERP image is REFUSED by name) and a seccomp deny-list that leaves execve allowed. Where Landlock
 * or seccomp is unavailable this REFUSES by name (LANDLOCK_UNAVAILABLE /
 * SECCOMP_UNAVAILABLE / CONFINEMENT_UNAVAILABLE) before any process exists;
 * it never runs the image unconfined. A child that cannot arm the sandbox
 * exits without exec and the failure is reported here. */
bool resident_launch_spawn_confined(struct resident_launch *launch,
                                    char *const argv[], char *const envp[],
                                    const struct os_sandbox_profile *profile,
                                    struct resident_receipt *receipt,
                                    char *error, size_t error_size);
/* Result of interpreting the status pipe. `proceed` is true when the spawn
 * may continue (unconfined EOF, or confined marker+EOF = ARMED_UNCERTAIN).
 * Exposed as a seam so the unconfined semantics can be pinned: there, EOF is
 * success and ANY byte or read error is an exec failure (errno `err`, 0 =
 * ENOEXEC), exactly as before confined launch existed. Confined launches poll
 * until `deadline_ns` (platform monotonic ns); unconfined ones block. */
struct resident_handshake_result {
    enum resident_exec_state state;
    int err;
    bool proceed;
};
struct resident_handshake_result resident_handshake_interpret(
    bool confined, int fd, uint64_t deadline_ns);
/* SIGKILLs `pid` and its process group, then waits at most grace_ms for the
 * reap. Returns true when the child was reaped (status in *status if given). */
bool resident_launch_kill_reap(uint64_t pid, uint32_t grace_ms, int *status);
/* Sends the nonce-bound stop frame, waits up to timeout_ms for exit, then
 * escalates to SIGKILL of the child's process group and reaps. Idempotent
 * for an already-exited child. */
bool resident_launch_cancel(struct resident_launch *launch,
                            uint32_t timeout_ms,
                            char *error, size_t error_size);
/* Reads one result frame and accepts it only under the current nonce;
 * stale or malformed frames are refused by name in `error`. A single absolute
 * monotonic timeout covers the complete header and payload, including partial
 * reads, EAGAIN and EINTR; fragments never renew it. timeout_ms == 0 drains
 * only immediately available bytes and refuses an incomplete frame. */
bool resident_result_read(struct resident_launch *launch,
                          struct resident_result_header *header,
                          void *payload, size_t payload_cap,
                          uint32_t timeout_ms,
                          char *error, size_t error_size);
/* Sends one z23-res-run-v1 frame carrying this launch's nonce to the child.
 * Never raises SIGPIPE and never blocks past `budget_ms` on a full queue: a
 * child that stopped reading fails the send (errno EAGAIN), a closed channel
 * fails it with the send errno. */
bool resident_launch_send_frame(struct resident_launch *launch,
                                const void *payload, uint32_t payload_len,
                                uint32_t budget_ms,
                                char *error, size_t error_size);
/* Resource cleanup only — closes descriptors and frees state. It does NOT
 * stop a live child: cancellation is an explicit lifecycle act. */
void resident_launch_close(struct resident_launch *launch);

#endif
