/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Internal helpers of the Linux terminal worker spawn path (child
 * tty setup, staged-failure naming, abandoned-child custody), split out of
 * mesh_terminal_worker.c to keep it within its size and complexity bands.
 * Not a public interface: only mesh_terminal_worker.c includes it. */
#ifndef ZCL_MESH_TERMINAL_WORKER_SPAWN_H
#define ZCL_MESH_TERMINAL_WORKER_SPAWN_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "base/result.h"
#include "session/mesh_terminal_worker.h"

/* Child-side failure stages, staged back through the close-on-exec pipe
 * so spawn() can refuse BY NAME instead of "the child went away". */
enum {
    TW_STAGE_TTY = 1,        /* slave open / ctty / winsize / dup2 */
    TW_STAGE_CHDIR = 2,      /* workdir chdir */
    TW_STAGE_CONFINEMENT = 3,/* sandbox enter */
    TW_STAGE_EXEC = 4,       /* execve */
    TW_STAGE_PIDNS = 5,      /* PID namespace unshare */
};

/* Forked child only: new session, controlling terminal, window size and the
 * pty slave on 0/1/2. False names the TW_STAGE_TTY failure. */
bool twx_tty_setup(const struct mesh_terminal_worker_config *cfg,
                   const char *slave_path);

/* The one line a refused user+PID namespace reports. `userns_probe_ok` is
 * os_sandbox_userns_available() on the refusing host: false names the likely
 * cause (Ubuntu 23.10+ kernel.apparmor_restrict_unprivileged_userns=1) and the
 * shipped profile; true keeps the neutral text. Never suggests an unconfined
 * shell. */
const char *twx_pidns_refusal(bool userns_probe_ok);

/* The named refusal for a non-zero stage byte read from the staging pipe. */
struct zcl_result twx_stage_error(uint8_t stage);

/* Read the staging pipe to EOF: 0 if the child execed, else the stage byte. */
uint8_t twx_read_stage(int fd);

/* Kill (group and leader) and reap a forked child the parent cannot keep.
 * Only a pid above 1 is ever signalled. */
void twx_abandon_child(pid_t pid);

#endif
