/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Confined child-process runner for the one-file lab (lab.run,
 * lab.test). Linux only: Landlock, seccomp, no_new_privs and rlimits are
 * applied in the forked child before exec; a host that cannot apply them
 * reports LAB_LAUNCH_UNCONFINED and never runs the program. */
#ifndef ZCL_TOOLS_COMMAND_LAB_EXEC_H
#define ZCL_TOOLS_COMMAND_LAB_EXEC_H

#include "platform/os_sandbox.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { LAB_CAPTURE_MAX = 64 * 1024 };

enum lab_profile {
    LAB_PROFILE_COMPILE, /* compiler: may fork and exec; no network */
    LAB_PROFILE_RUN,     /* program: no fork, threads only; no network */
};

enum lab_launch {
    LAB_LAUNCHED,
    LAB_LAUNCH_UNCONFINED, /* confinement could not be applied */
    LAB_LAUNCH_FAILED,     /* pipe, fork or exec failure */
    LAB_LAUNCH_UNSUPPORTED /* not a Linux host */
};

struct lab_spawn {
    enum lab_profile profile;
    bool confine;                 /* apply Landlock and seccomp in the child */
    const char *const *argv;      /* NULL-terminated; argv[0] is absolute */
    const char *const *env;       /* NULL-terminated "NAME=value" pairs */
    const char *cwd;
    const struct os_sandbox_path_rule *rules;
    size_t n_rules;
    const char *stdin_data;
    size_t stdin_len;
    uint32_t timeout_ms;
    uint64_t as_bytes;            /* OS_SANDBOX_RLIMIT_KEEP leaves it */
    uint64_t fsize_bytes;
    uint64_t nofile;
    const char *watch_dir;        /* killed when it holds more than watch_max_bytes */
    uint64_t watch_max_bytes;
};

struct lab_proc {
    enum lab_launch launch;
    char detail[160];             /* setup failure reason, when not launched */
    int exit_code;
    int term_signal;
    bool timed_out;
    bool disk_exceeded;           /* killed for writing over the workdir cap */
    int64_t wall_us;
    int64_t max_rss_kb;
    char *out;                    /* LAB_CAPTURE_MAX bytes, NUL-terminated */
    char *err;
    size_t out_len;
    size_t err_len;
    bool out_cut;
    bool err_cut;
};

/* Allocate and release the capture buffers of a lab_proc. */
bool lab_proc_init(struct lab_proc *p);
void lab_proc_free(struct lab_proc *p);
/* Clear results between runs, keeping the capture buffers. */
void lab_proc_reset(struct lab_proc *p);

/* Run one confined child to completion or deadline. */
void lab_spawn_run(const struct lab_spawn *spawn, struct lab_proc *out);

/* Name of a terminating signal, or "" when the process was not signalled. */
const char *lab_signal_name(int sig);

/* True when this host can apply Landlock and seccomp to a child. */
bool lab_sandbox_available(void);
/* True when the run profile can also enter its own PID namespace, so no
 * process outside the lab is addressable by signal. When it
 * cannot, the self-signal filter alone confines signals. */
bool lab_pidns_available(void);
bool lab_confinement_available(void);
/* Test seam: while set, run children skip the PID namespace and rely on the
 * self-signal filter, as on a host that refuses unprivileged user namespaces. */
void lab_test_disable_pidns(bool on);
/* Test seam: while set, the self-signal filter omits its descriptor-ownership
 * rules, to prove the signal probe really reaches a process without them. */
void lab_test_disable_fd_owner_rules(bool on);
int lab_landlock_abi(void);

/* Test seam: while set, every child fails its Landlock step as a host without
 * Landlock would, so callers can observe the LAB_UNCONFINED refusal. */
void lab_test_force_confinement_failure(bool on);

#endif
