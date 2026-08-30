/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The confined terminal worker — spawn the one granted shell
 * (fbsh) on a PTY inside the terminal-worker sandbox profile, pump both
 * directions under hard byte budgets, and end every session with a named
 * close reason and a process-group kill. Nothing a remote peer sends can
 * hang or exhaust the node: wall-clock lifetime, idle timeout, input and
 * output byte budgets, and a census-backed process-group kill are all
 * enforced HERE, above the seccomp/Landlock cage the child itself runs
 * under. Linux only; every other platform refuses by name. */

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
    MESH_TERMINAL_WORKER_ERR_UNSUPPORTED = -12 /* non-Linux: honest refusal */
};

const char *mesh_terminal_worker_error_string(
    enum mesh_terminal_worker_error error);

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
};

struct mesh_terminal_worker {
    pid_t pid;
    pid_t pgid;              /* == pid: setsid() makes the child lead its own group */
    int master_fd;           /* PTY master; -1 once closed */
    uint64_t bytes_in;
    uint64_t bytes_out;
    int64_t started_unix;
    int64_t last_activity_unix;
    bool running;
    /* Meaningful once !running: WEXITSTATUS of the reaped shell, or
     * 128 + terminating signal. */
    int exit_code;
    /* Why the session ended. MESH_TERMINAL_CLOSE_REQUESTED (0) is the
     * zero value: a session that has not ended reads as "requested" by
     * construction, and every enforcement path names itself. */
    enum mesh_terminal_close_reason close_reason;
    /* Budgets, copied from the config at spawn. */
    uint64_t max_bytes_in;
    uint64_t max_bytes_out;
    uint64_t lifetime_seconds;
    uint64_t idle_seconds;
};

/* Spawn the confined shell. The child: setsid() (becoming its own
 * process-group leader, so the group is killable as -pid), PTY slave as
 * controlling terminal with the requested winsize, stdio on the slave,
 * cwd/HOME = workdir, then the terminal-worker sandbox profile (Landlock:
 * workdir + shell binary only; seccomp: session deny-set minus the
 * fork/exec family; rlimits; W^X) and execve of shell_path. Every
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

/* Kill the whole process group (SIGKILL to -pgid, census-verified), reap
 * the shell, and close the PTY. Idempotent; safe on an already-exited
 * shell. close_reason is left as the enforcement path set it. */
void mesh_terminal_worker_kill(struct mesh_terminal_worker *w);

#endif /* ZCL_SESSION_MESH_TERMINAL_WORKER_H */
