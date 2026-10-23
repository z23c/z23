/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Internal helpers of the Linux terminal worker spawn path; see
 * mesh_terminal_worker_spawn.h. */

#define _GNU_SOURCE

#include "mesh_terminal_worker_spawn.h"

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h> /* struct winsize */
#include <unistd.h>

#include "platform/os_sandbox.h"

bool twx_tty_setup(const struct mesh_terminal_worker_config *cfg,
                   const char *slave_path)
{
    if (setsid() < 0) return false;
    int slave = open(slave_path, O_RDWR);
    if (slave < 0) return false;
    /* The shell wants a controlling terminal for job control. */
    if (ioctl(slave, TIOCSCTTY, NULL) < 0) return false;
    struct winsize ws = { .ws_col = cfg->cols, .ws_row = cfg->rows };
    if (ioctl(slave, TIOCSWINSZ, &ws) < 0) return false;
    if (dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDOUT_FILENO) < 0 ||
        dup2(slave, STDERR_FILENO) < 0)
        return false;
    if (slave > STDERR_FILENO) close(slave);
    return true;
}

const char *twx_pidns_refusal(bool userns_probe_ok)
{
    if (userns_probe_ok)
        return "TERMINAL_PIDNS_UNAVAILABLE: user+PID namespace refused; no unconfined fallback";
    return "TERMINAL_PIDNS_UNAVAILABLE: user+PID namespace refused "
           "(kernel.apparmor_restrict_unprivileged_userns=1? install "
           "platform/packaging/linux/apparmor/z23-userns); no unconfined fallback";
}

struct zcl_result twx_stage_error(uint8_t stage)
{
    static const struct {
        uint8_t stage;
        enum mesh_terminal_worker_error code;
        const char *what;
    } k[] = {
        { TW_STAGE_TTY, MESH_TERMINAL_WORKER_ERR_TTY, "pty slave/ctty/winsize setup" },
        { TW_STAGE_CHDIR, MESH_TERMINAL_WORKER_ERR_CONFIG, "workdir chdir" },
        { TW_STAGE_CONFINEMENT, MESH_TERMINAL_WORKER_ERR_CONFINEMENT, "sandbox enter" },
        { TW_STAGE_EXEC, MESH_TERMINAL_WORKER_ERR_EXEC, "execve" },
        { TW_STAGE_PIDNS, MESH_TERMINAL_WORKER_ERR_PIDNS_UNAVAILABLE, NULL },
    };
    enum mesh_terminal_worker_error code = MESH_TERMINAL_WORKER_ERR_SPAWN;
    const char *what = "unknown stage";
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++)
        if (k[i].stage == stage) {
            code = k[i].code;
            what = k[i].what ? k[i].what
                             : twx_pidns_refusal(os_sandbox_userns_available());
        }
    return ZCL_ERR(code, "worker child failed at %s (stage %u)", what, (unsigned)stage);
}

uint8_t twx_read_stage(int fd)
{
    uint8_t stage = 0;
    ssize_t n;
    do {
        n = read(fd, &stage, 1);
    } while (n < 0 && errno == EINTR);
    return n > 0 ? stage : 0;
}

void twx_abandon_child(pid_t pid)
{
    if (pid <= 1) return;
    (void)kill(-pid, SIGKILL);
    (void)kill(pid, SIGKILL);
    pid_t got;
    do {
        got = waitpid(pid, NULL, 0);
    } while (got < 0 && errno == EINTR);
}
#else
typedef int twx_unused_on_this_platform;
#endif
