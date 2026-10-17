/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The confined terminal worker — spawn the one granted shell
 * (fbsh) on a PTY inside the terminal-worker sandbox profile, pump both
 * directions under hard byte budgets, and end every session with a named
 * close reason and a process-group kill. Nothing a remote peer sends can
 * hang or exhaust the node: wall-clock lifetime, idle timeout, input and
 * output byte budgets, and a census-backed process-group kill are all
 * enforced HERE, above the seccomp/Landlock cage the child itself runs
 * under, on Linux. Windows spawns the same grant behind ConPTY
 * (CreatePseudoConsole) instead of a PTY, enforces the same byte/lifetime/
 * idle budgets, and holds the shell and every descendant in a kill-on-close
 * Job Object (live-process limit = the POSIX census budget), so a close, a
 * limit or a disconnect ends the whole tree. It has no restricted identity
 * for the shell yet, so mesh_terminal_confinement_refusal keeps the lane
 * refused there unless the owner passes -terminalacceptunconfined. With that
 * flag the remote shell runs as the Windows user that started the node, with
 * all of that user's rights; only peers paired with the terminal capability
 * can open it. A restricted-identity launch is the intended follow-up.
 * Every other platform refuses by name. */

#ifndef ZCL_SESSION_MESH_TERMINAL_WORKER_H
#define ZCL_SESSION_MESH_TERMINAL_WORKER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> /* pid_t */

#include "base/result.h"
#include "session/mesh_terminal_proto.h" /* close-reason enum, geometry bounds */

/* The worker copies its budgets at spawn, so enforcement needs no config
 * pointer, and reads output into the CALLER's buffer — the node never
 * allocates under remote control. */
#define MESH_TERMINAL_WORKER_IO_CHUNK 4096u
#define MESH_TERMINAL_WORKER_ARGV_MAX 16u

/* Failure names for the zcl_result .code field. Every spawn, pump, and
 * resize refusal carries one of these, so a regression can be asserted by
 * name rather than by any-failure. */
enum mesh_terminal_worker_error {
    MESH_TERMINAL_WORKER_ERR_NONE = 0,
    MESH_TERMINAL_WORKER_ERR_NULL = -1,
    MESH_TERMINAL_WORKER_ERR_CONFIG = -2,      /* malformed config/budgets */
    MESH_TERMINAL_WORKER_ERR_PTY = -3,         /* pty master setup failed  */
    MESH_TERMINAL_WORKER_ERR_SPAWN = -4,       /* fork machinery failed    */
    MESH_TERMINAL_WORKER_ERR_CONFINEMENT = -5, /* sandbox enter failed     */
    MESH_TERMINAL_WORKER_ERR_EXEC = -6,        /* execve of the shell failed */
    MESH_TERMINAL_WORKER_ERR_TTY = -7,         /* session/ctty/winsize failed */
    MESH_TERMINAL_WORKER_ERR_NOT_RUNNING = -8, /* session already over     */
    MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT = -9,  /* budget overrun; killed   */
    MESH_TERMINAL_WORKER_ERR_IO = -10,         /* pty i/o failed           */
    MESH_TERMINAL_WORKER_ERR_GEOMETRY = -11,   /* cols/rows out of proto bounds */
    MESH_TERMINAL_WORKER_ERR_UNSUPPORTED = -12, /* non-Linux: honest refusal */
    MESH_TERMINAL_WORKER_ERR_JOB_ASSIGN = -13,  /* Windows: shell could not join its job */
    MESH_TERMINAL_WORKER_ERR_PIDNS_UNAVAILABLE = -14 /* Linux: no user+PID namespace; no unconfined fallback */
};

const char *mesh_terminal_worker_error_string(
    enum mesh_terminal_worker_error error);

/* Platform-neutral byte-budget bookkeeping: true when accepting `n` more
 * bytes on top of `used` bytes already charged against `max` would cross
 * the budget. The Windows ConPTY arm's input path uses this for the same
 * check the POSIX arm inlines (unchanged there); exported so it is
 * provable with a Linux-hosted unit test — no spawned shell, no mingw
 * build — rather than only ever exercised behind a live session. */
bool mesh_terminal_worker_budget_would_overrun(uint64_t used, uint64_t max,
                                               size_t n);

/* Platform-neutral: bounds-check requested terminal geometry against the
 * proto's wire limits (MESH_TERMINAL_MAX_COLS/ROWS). Every spawn and
 * resize call on every arm goes through this one copy; exported for the
 * same reason as the budget helper above — a Linux-hosted unit test can
 * call it directly. */
bool geometry_in_bounds(uint16_t cols, uint16_t rows);

/* Which platform's path grammar a shell path is judged by. The build's own
 * grammar is MESH_TERMINAL_PLATFORM_NATIVE; both are selectable so one
 * Linux-hosted table test covers both. */
enum mesh_terminal_platform {
    MESH_TERMINAL_PLATFORM_POSIX = 0,
    MESH_TERMINAL_PLATFORM_WINDOWS = 1
};
#if defined(_WIN32)
#define MESH_TERMINAL_PLATFORM_NATIVE MESH_TERMINAL_PLATFORM_WINDOWS
#else
#define MESH_TERMINAL_PLATFORM_NATIVE MESH_TERMINAL_PLATFORM_POSIX
#endif

/* Longest accepted shell path, exclusive, per grammar. */
#define MESH_TERMINAL_SHELL_PATH_MAX_POSIX 600u
#define MESH_TERMINAL_SHELL_PATH_MAX_WINDOWS 512u

/* True when `path` is an acceptable -terminalshell value under the given
 * grammar. POSIX: absolute, bounded. Windows: a drive-letter absolute path
 * ("C:\" or "C:/"), no UNC or device prefix, no relative form, no ".."
 * segment, no character Windows forbids in a path, no trailing separator,
 * and a final component ending in ".exe" so that no argument can ride along
 * (the worker quotes the whole value as the image). Pure. */
bool mesh_terminal_shell_path_valid(enum mesh_terminal_platform platform,
                                    const char *path);

/* The environment variables the Windows arm hands the shell, in the order the
 * environment block is written (case-insensitive ascending, as CreateProcess
 * expects). PATH, ComSpec, windir, SystemRoot, TEMP, TMP, APPDATA and
 * LOCALAPPDATA come from the node's own environment when present; HOME,
 * USERPROFILE and TERM are set by the worker. Nothing else crosses. Returns
 * NULL past the last entry. Pure. */
const char *mesh_terminal_win_env_name(size_t index);

/* NULL when the terminal lane may activate on `platform`; otherwise the
 * stable reason it must not. The Windows arm contains the shell's process
 * tree in a Job Object but has no restricted identity for it, so the lane
 * is refused there unless the owner explicitly accepts an unconfined shell
 * (accept_unconfined, flag -terminalacceptunconfined). The flag has no
 * meaning elsewhere and is refused by name. Pure. */
const char *mesh_terminal_confinement_refusal(
    enum mesh_terminal_platform platform, bool accept_unconfined);

/* The state a granted terminal is described by in logs and in the grant
 * capsule: "confined", or MESH_TERMINAL_CONFINEMENT_UNCONFINED. Pure. */
#define MESH_TERMINAL_CONFINEMENT_UNCONFINED "unconfined-owner-accepted"
const char *mesh_terminal_confinement_marker(
    enum mesh_terminal_platform platform, bool accept_unconfined);

struct mesh_terminal_worker_config {
    /* Absolute path of the ONE shell binary the child may exec; it is
     * granted read+execute and nothing else on the host is reachable. */
    const char *shell_path;
    /* Absolute path of the per-terminal working directory; granted
     * read/write/create/execute and made the child's cwd and HOME. */
    const char *workdir;
    uint16_t cols;
    uint16_t rows;
    /* Hard budgets, copied into the worker at spawn. Zero bytes_in,
     * bytes_out, or lifetime is a config refusal — a session with no
     * ceiling is not a session. idle_seconds 0 disables the idle
     * timeout (lifetime still applies). */
    uint64_t max_bytes_in;      /* keyboard bytes from the peer */
    uint64_t max_bytes_out;     /* screen bytes to the peer */
    uint64_t lifetime_seconds;  /* wall clock from spawn */
    uint64_t idle_seconds;      /* no I/O in either direction */
    /* Optional: run this program instead of the shell. NULL-terminated, at
     * most MESH_TERMINAL_WORKER_ARGV_MAX strings; argv[0] is an absolute path
     * and on POSIX becomes the ONE granted binary (read+execute, plus the
     * standard library directories); the POSIX environment stays PATH-less. NULL means the
     * configured shell, exactly as before. Windows requires an absolute .exe
     * image and conventional CRT/CommandLineToArgvW parsing, strict UTF-8,
     * at most 16 arguments, <=32767 input bytes including string terminators,
     * and <=32767 UTF-16 command-line units including NUL. Windows retains
     * its allowlisted environment and owner-accepted unconfined identity.
     * The worker invokes the selected executable directly without adding a shell. */
    const char *const *argv;
    /* Optional (POSIX): where the supervisor of a session process may read the
     * group id. Written the moment the child exists, zeroed after the group is
     * killed and before its leader is reaped, so non-zero always names a group
     * whose leader still holds the id. */
    volatile pid_t *pgid_slot;
};

struct mesh_terminal_worker {
    pid_t pid;
    pid_t pgid;              /* == pid: setsid() makes the child lead its own group */
    /* POSIX: the leader exited but is NOT reaped (waitid WNOWAIT), so it keeps
     * the group id reserved until the group has been killed. */
    bool leader_held;
    volatile pid_t *pgid_slot;  /* from the config; see there */
    int master_fd;           /* PTY master; -1 once closed */
    uint64_t bytes_in;
    uint64_t bytes_out;
    int64_t started_unix;
    int64_t last_activity_unix;
    bool running;
    /* Meaningful once !running: WEXITSTATUS of the reaped shell, or
     * 128 + terminating signal. */
    int exit_code;
    /* The terminating signal number when the shell was killed by a
     * signal (POSIX), else 0. Lets the close evidence name a signal
     * apart from a shell that itself exited with 128 + n. */
    int term_signal;
    /* Why the session ended. MESH_TERMINAL_CLOSE_REQUESTED (0) is the
     * zero value: a session that has not ended reads as "requested" by
     * construction, and every enforcement path names itself. */
    enum mesh_terminal_close_reason close_reason;
    /* Budgets, copied from the config at spawn. */
    uint64_t max_bytes_in;
    uint64_t max_bytes_out;
    uint64_t lifetime_seconds;
    uint64_t idle_seconds;
#if defined(_WIN32)
    /* ConPTY handles. Opaque void* so this header stays free of
     * <windows.h>: HANDLE and HPCON are both pointer-sized opaque handles
     * on every Windows target this project builds for. NULL once closed,
     * mirroring master_fd's -1-when-closed convention. */
    void *win_pc;          /* HPCON: the pseudoconsole */
    void *win_job;         /* HANDLE: kill-on-close Job Object holding the shell tree */
    void *win_process;     /* HANDLE: the spawned shell process */
    void *win_input_write; /* HANDLE: our end of the ConPTY's input pipe */
    void *win_output_read; /* HANDLE: our end of the ConPTY's output pipe */
    void *win_output_state; /* owned bounded OVERLAPPED read state; never shared */
    void *win_close_state;  /* preallocated console closer; never points at caller memory */
    void *win_membership_state; /* owned Job completion wake state */
#endif
};

/* Spawn the confined shell. The child: setsid() (becoming its own
 * process-group leader, so the group is killable as -pid), PTY slave as
 * controlling terminal with the requested winsize, stdio on the slave,
 * cwd/HOME = workdir, then the terminal-worker sandbox profile (Landlock:
 * workdir + shell binary only; seccomp: session deny-set minus the
 * fork/exec family; rlimits; strict W^X for the default shell, file-backed
 * exec (not W^X) for an explicit argv) and execve of shell_path. Every
 * child-side failure is staged back through a close-on-exec pipe and
 * reported BY NAME — spawn never returns ok for a shell that failed to
 * start confined. The parent is never confined. Clock comes in, testable:
 * `now_unix` anchors started/last_activity. */
struct zcl_result mesh_terminal_worker_spawn(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out);

/* Feed peer keyboard bytes. An overrun of max_bytes_in kills the process
 * group, marks close_reason BYTE_LIMIT, and reports BYTE_LIMIT — the
 * bytes are refused, not written. A stalled pty (shell not reading) is a
 * bounded-wait IO refusal that does NOT kill: the lifetime/idle
 * enforcement owns that kill. */
struct zcl_result mesh_terminal_worker_input(struct mesh_terminal_worker *w,
                                             const uint8_t *bytes, size_t n,
                                             int64_t now_unix);

/* Drain pending shell output into `buf` (non-blocking). *out_len may be
 * 0 — the caller polls. Crossing max_bytes_out kills the process group,
 * marks BYTE_LIMIT, and reports it; the chunk already read into buf is
 * valid and *out_len set, so no output is silently dropped. */
struct zcl_result mesh_terminal_worker_output(struct mesh_terminal_worker *w,
                                              uint8_t *buf, size_t cap,
                                              size_t *out_len,
                                              int64_t now_unix);

/* Windows: borrowed manual-reset event for the worker-owned pending output
 * read. Wait together with win_process and the caller's stop/network events;
 * output() alone consumes/charges/rearms it. Settled EOF returns zero; process
 * exit and budgets still end the session. Never close this handle. Zero on
 * unavailable/closed/non-Windows workers. No polling thread is created. */
uintptr_t mesh_terminal_worker_output_wait_handle(struct mesh_terminal_worker *w);

/* Windows: stop the shell subtree and start closing ConPTY while output remains
 * readable. The worker owns the closer and all handles. Repeated calls are safe.
 * The returned event is borrowed; zero means unavailable. kill() cancels output
 * and settles close within a fixed bound. An unsettled OS close retains only
 * its private heap/handles until process exit and refuses future Windows spawns;
 * already-live workers may each retain one such state. Never TerminateThread. */
struct zcl_result mesh_terminal_worker_begin_output_close(struct mesh_terminal_worker *w);
uintptr_t mesh_terminal_worker_close_wait_handle(struct mesh_terminal_worker *w);

/* Windows: borrowed membership-change wake hint, reset by budget_exceeded()
 * before its authoritative all-member census. Notifications are supplemental;
 * callers still check budgets on other events and real deadlines. */
uintptr_t mesh_terminal_worker_budget_wait_handle(struct mesh_terminal_worker *w);

#if defined(_WIN32) && defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
bool mesh_terminal_worker_testing_close_thread_failure(void);
unsigned mesh_terminal_worker_testing_process_limit(void);
bool mesh_terminal_worker_testing_read_cancel_failure(void);
unsigned mesh_terminal_worker_testing_retained_reads(void);
bool mesh_terminal_worker_testing_job_quit_failure(void);
unsigned mesh_terminal_worker_testing_retained_watches(void);
#endif

/* Resize the PTY window (TIOCSWINSZ; the kernel raises SIGWINCH on the
 * shell's foreground group). Geometry bounds are the proto's. */
struct zcl_result mesh_terminal_worker_resize(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows);

/* Enforce every budget at `now_unix` and reap a shell that already
 * exited on its own. Returns true when the session is OVER — close_reason
 * names why (worker-exited / lifetime-limit / idle-timeout) — and the
 * caller may drain remaining output before calling
 * mesh_terminal_worker_kill() to close. */
bool mesh_terminal_worker_budget_exceeded(struct mesh_terminal_worker *w,
                                          int64_t now_unix);

/* True while the shell process is still live (waitpid-verified, so a
 * reaped shell reads false immediately). */
bool mesh_terminal_worker_alive(struct mesh_terminal_worker *w);

/* Kill the whole process group (SIGKILL to -pgid) while the leader still
 * holds the group id (an exited leader stays unreaped until now), reap
 * the shell, and close the PTY. Idempotent; safe on an already-exited
 * shell. close_reason is left as the enforcement path set it. */
void mesh_terminal_worker_kill(struct mesh_terminal_worker *w);

#if defined(ZCL_TESTING)
/* Test seam (POSIX): returns the order of the last group kill and the last
 * leader reap since the previous call (0 = none), then clears both. The
 * custody contract is killpg_seq < reap_seq. */
void mesh_terminal_worker_testing_order(uint32_t *killpg_seq, uint32_t *reap_seq);
#endif

#endif /* ZCL_SESSION_MESH_TERMINAL_WORKER_H */
