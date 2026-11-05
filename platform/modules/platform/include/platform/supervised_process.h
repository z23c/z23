/* purpose: Define sealed image admission and exclusive bounded descendant supervision. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_PLATFORM_SUPERVISED_PROCESS_H
#define ZCL_PLATFORM_SUPERVISED_PROCESS_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define PLATFORM_SUPERVISED_MAX_MAPS 16u
#define PLATFORM_SUPERVISED_ARGV_DEFAULT_MAX 64u
#define PLATFORM_SUPERVISED_TARGET_ARGV_MAX 512u
#define PLATFORM_SUPERVISED_LAUNCHER_ARGV_MAX 2u
#define PLATFORM_SUPERVISED_ARGV_EXTENDED_MAX \
    (PLATFORM_SUPERVISED_TARGET_ARGV_MAX + PLATFORM_SUPERVISED_LAUNCHER_ARGV_MAX)
#define PLATFORM_SUPERVISED_ENV_MAX 64u
enum platform_supervised_argv_policy {
    PLATFORM_SUPERVISED_ARGV_DEFAULT = 0,
    PLATFORM_SUPERVISED_ARGV_EXTENDED
};
enum platform_supervised_stack_policy {
    PLATFORM_SUPERVISED_STACK_INHERIT = 0,
    PLATFORM_SUPERVISED_STACK_UNLIMITED
};
enum platform_supervised_env_policy {
    PLATFORM_SUPERVISED_ENV_DEFAULT = 0,
    PLATFORM_SUPERVISED_ENV_COMPLETE
};
#define PLATFORM_SUPERVISED_IMAGE_MAX (64u * 1024u * 1024u)
enum platform_supervised_image_result {
    PLATFORM_SUPERVISED_IMAGE_OK,
    PLATFORM_SUPERVISED_IMAGE_UNSUPPORTED,
    PLATFORM_SUPERVISED_IMAGE_REFUSED,
    PLATFORM_SUPERVISED_IMAGE_IO_ERROR
};
/* Linux host_os admission, not a sandbox or complete runtime-closure pin.
 * Input is an immutable caller-owned exact byte copy, disjoint from all outputs.
 * image_fd must initially be -1. Success transfers a sealed top-level image FD.
 * SHA3-256 is checked again from the sealed image. Native ELF64 only; dynamic
 * images permit the platform's fixed system loader and libc.so.6, whose mutable
 * bytes and OS library resolution remain a separately accepted host trust boundary.
 * No package-controlled search paths,
 * RPATH/RUNPATH, audit/filter loaders, initially executable stack or initially
 * writable executable segments. Accepted native code can later change memory
 * protections or load code; this is image admission, not runtime confinement.
 * Privileged source-file mode and package authority are caller checks; byte
 * representation alone does not establish install/owner execution approval. */
enum platform_supervised_image_result platform_supervised_image_capture(
    const void *bytes, size_t length, const uint8_t expected_sha3[32], int *image_fd);
struct platform_supervised_fd_map { int source, target; };
struct platform_supervised_spec {
    int executable_fd; /* Sealed immutable ELF snapshot; caller retains ownership. */
    const char *const *argv; /* Explicit argv[0]; default 64 entries plus NULL. */
    const char *const *env; /* Explicit environment, at most 64 entries plus NULL. */
    const struct platform_supervised_fd_map *maps;
    size_t map_count; /* Unique targets 0..63; all three stdio targets required. */
    int64_t launch_deadline_ns; /* Absolute Linux CLOCK_MONOTONIC deadline. */
    uint32_t cleanup_timeout_ms; /* 1..10000, used on owner EOF/natural exit. */
    bool use_cwd_fd; /* Opt-in trusted directory; default retains existing CWD. */
    int cwd_fd; /* Exclusive stable borrowed FD until start returns; child uses no path. */
    enum platform_supervised_argv_policy argv_policy; /* Extended: 514 non-NULL, 515 slots. */
    /* Unlimited requests BOTH soft/hard RLIMIT_STACK infinity in engine only.
     * Failure uses the exec error pipe; no exec or normal verdict is permitted.
     * Owner/supervisor limits unchanged. No privilege elevation is implied. */
    enum platform_supervised_stack_policy stack_policy;
    /* COMPLETE borrows exactly env_count non-NULL entries followed by NULL.
     * Zero means explicit empty environment, never ambient inheritance.
     * Caller keeps the complete accessible vector stable until start returns.
     * No entry/byte cap is imposed; kernel E2BIG remains a launch failure. */
    enum platform_supervised_env_policy env_policy;
    size_t env_count;
};
enum platform_supervised_state {
    PLATFORM_SUPERVISED_RUNNING,
    PLATFORM_SUPERVISED_CLEAN,
    PLATFORM_SUPERVISED_INCOMPLETE,
    PLATFORM_SUPERVISED_UNSUPPORTED,
    PLATFORM_SUPERVISED_INVALID,
    PLATFORM_SUPERVISED_LAUNCH_FAILED,
    PLATFORM_SUPERVISED_OBSERVATION_FAILED
};
struct platform_supervised_observation {
    enum platform_supervised_state state;
    int error_number;
    bool engine_exit_observed, no_children;
    int engine_wait_status; /* Raw POSIX wait status; meaningful only when observed. */
};
struct platform_supervised_process {
    int64_t supervisor_pid;
    int control_fd;
    struct platform_supervised_observation observation;
};
/* Linux-only trusted-program cancellation, not a sandbox or crash containment.
 * Seals qualify only the top-level executable bytes: loaders, shared libraries,
 * helper execs and the owner environment require separate qualification.
 * Caller must retain exclusive supervisor wait/SIGCHLD-disposition custody.
 * Automatic reaping refuses launch; another waiter or later disposition change
 * loses qualification and returns OBSERVATION_FAILED. CLOEXEC error-pipe EOF
 * establishes the exec handshake only; unexpected pre-exec death can also close
 * it. Observed engine exit/status is separate and must qualify actual execution.
 * Supervisor and engine start with default catchable signal dispositions and
 * an empty signal mask; owner dispositions/mask are preserved. No inherited
 * node handler runs in the supervised child context.
 * Dedicated subreaper owns descendants even when they setsid/double-fork.
 * No ambient descriptors or environment are inherited by the engine. Caller
 * owns a noncopyable handle and closes its lifeline only through this API.
 * Success CLEAN requires genuine ECHILD and reaping the supervisor. INCOMPLETE
 * retains custody: keep the handle, poll/stop again; never discard/reinitialize.
 * Owner EOF triggers bounded cleanup and named INCOMPLETE if stalled; the
 * supervisor remains to retry/reap. Its crash may leave children running.
 * Post-fork branches use fixed storage and syscall operations, no libc locks. */
void platform_supervised_init(struct platform_supervised_process *process);
enum platform_supervised_state platform_supervised_start(
    struct platform_supervised_process *process, const struct platform_supervised_spec *spec);
enum platform_supervised_state platform_supervised_poll(
    struct platform_supervised_process *process);
enum platform_supervised_state platform_supervised_stop(
    struct platform_supervised_process *process, int64_t deadline_ns);
enum platform_supervised_signal {
    PLATFORM_SUPERVISED_HANGUP = 1,
    PLATFORM_SUPERVISED_INTERRUPT = 2,
    PLATFORM_SUPERVISED_TERMINATE = 3
};
/* Queue an allowlisted signal for the exact engine pidfd retained before any
 * wait/reap. True means control-packet acceptance, never delivery or cleanup.
 * Signal applies to the engine only, not its descendants. Caller retains hard
 * execution/cleanup deadlines; repeated HUP cannot authorize deadline renewal. */
bool platform_supervised_signal(struct platform_supervised_process *process,
    enum platform_supervised_signal signal);
#ifdef ZCL_TESTING
/* Test-only emergency custody for a fixture-owned observed descendant. Raw
 * pidfd syscalls stay in this existing platform authority; no product command
 * accepts a numeric PID or exposes these operations. Caller owns returned FD. */
int platform_supervised_fixture_pidfd_open(int64_t owned_pid);
bool platform_supervised_fixture_pidfd_kill(int owned_fd);
void platform_supervised_fixture_observation_error_once(void);
/* Deterministic isolated owner-exit fixture only: gate first supervisor cleanup
 * on one byte/EOF; the engine never inherits this unmapped descriptor. */
void platform_supervised_fixture_cleanup_gate(int fd);
bool platform_supervised_fixture_subreaper(void);
#endif
/* Release only the owner lifeline: used for owner-exit handoff/testing. The
 * handle remains owned and must still be polled until its supervisor is reaped. */
void platform_supervised_owner_eof(struct platform_supervised_process *process);
#endif
