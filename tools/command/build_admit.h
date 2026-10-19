/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: build admission for heavy host commands, as a transport-neutral
 *          engine the ops.host.build and ops.host.jobs leaves project.
 *
 * SHARED STATE. The admission state is plain files in the state directory,
 * locked with flock(2). They use the format of the installed `devbuild`
 * wrapper's z23 project, so both can serve one host during a migration:
 *
 *   z23.lock, z23.lock.1 .. z23.lock.3   one build lane each; exclusive flock
 *   z23.fifo/<ns>-<pid>                  FIFO ticket; shared flock while live
 *   z23.prio/<ns>-<pid>                  landing marker; shared flock while live
 *   heavy.lock                           shared by every admitted job
 *   devbuild.jobs.jsonl                  one accounting line per finished job
 *
 * A ticket or marker is live while some process holds a shared flock on it,
 * so liveness survives PID namespaces. Only the FIFO head, or a landing job,
 * may take a free lane.
 *
 * A job runs in a systemd user scope under development.slice with CPU and
 * memory limits and a disposable scratch directory (released on success,
 * retained on failure). Every external effect has a seam in struct ba_config
 * so tests run without real scopes.
 */

#ifndef ZCL_BUILD_ADMIT_H
#define ZCL_BUILD_ADMIT_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifndef _WIN32
#include <sys/types.h>
#endif

enum { BA_PATH_MAX = 1024, BA_CPU_LIST_MAX = 256, BA_MAX_LANES = 4,
       BA_NAME_MAX = 64 };

/* Free-space reserve in GiB when DEVBUILD_RESERVE_GIB is unset. It is the
 * floor the installed devbuild wrapper admits with, so both admit alike. */
enum { BA_DEFAULT_RESERVE_GIB = 30 };

/* Exit status of a refused or deferred job (EX_TEMPFAIL), a missing command
 * (EX_USAGE) and a scratch directory that cannot be made (EX_CANTCREAT). */
enum { BA_EXIT_DEFERRED = 75, BA_EXIT_USAGE = 64, BA_EXIT_SCRATCH = 73 };

struct ba_config {
    char state_dir[BA_PATH_MAX];     /* locks, tickets, accounting log */
    char scratch_root[BA_PATH_MAX];  /* parent of z23/job.XXXXXXXX */
    char disk_path[BA_PATH_MAX];     /* filesystem the reserve is read from */
    char scope_launcher[BA_PATH_MAX];/* systemd-run, or a test stub */
    char cpu_list[BA_CPU_LIST_MAX];  /* comma list handed to taskset */
    unsigned cpu_workers;
    unsigned lanes;                  /* concurrent jobs, 1..4 */
    unsigned reserve_gib;            /* free-space reserve; 0 disables */
    uint64_t need_mem_kib;           /* MemAvailable floor; 0 disables */
    unsigned poll_ms;                /* wait between admission attempts */
    unsigned zcc_max_mb;
    bool wait;                       /* queue instead of refusing when busy */
    bool priority;                   /* landing job: ahead of ordinary waiters */
    bool keep_scratch;               /* retain scratch even on success */
    bool tmpdir_set;                 /* caller owns TMPDIR: no scratch */
};

/* Parse `lscpu -b -p=CPU,CORE,SOCKET` text: the first two physical cores
 * stay with the host, every later logical CPU is a build worker. False when
 * fewer than four workers remain. */
bool ba_cpu_plan_parse(const char *lscpu_text, char *list, size_t cap,
                       unsigned *workers);

/* The reserve in GiB from DEVBUILD_RESERVE_GIB (0 disables), or
 * BA_DEFAULT_RESERVE_GIB when it is unset, empty, malformed or above 2^20. */
unsigned ba_reserve_gib_from_env(void);

/* Names of the entries of `dir` (dot files and names of BA_NAME_MAX or more
 * bytes skipped) in ascending order, in memory the caller frees. There is no
 * fixed cap: a queue longer than any bound stays in order. True with *count
 * 0 when the directory does not exist; false only on allocation failure. */
bool ba_list_names(const char *dir, char (**names)[BA_NAME_MAX],
                   size_t *count);

/* A held lane: closing the descriptors releases every lock. */
struct ba_slot {
    int lane;                        /* 1-based; 0 for the single-lane path */
    int lane_fd[BA_MAX_LANES];
    int heavy_fd;
};

/* Stop request from a signal handler: admission loops return 128 + signal.
 * Signal 0 clears it. */
void ba_request_stop(int signo);
int ba_stop_signal(void);

/* Wait for or take a lane and the heavy lock. 0 on success with `slot`
 * holding the locks; else the exit status the job must return, with the
 * reason on stderr. */
int ba_admit(const struct ba_config *cfg, struct ba_slot *slot);
void ba_slot_release(struct ba_slot *slot);

/* Run `argv` under admission: reserve and memory checks, a scope with CPU
 * and memory limits, a scratch directory, and one accounting line. Returns
 * the command's exit status (128 + signal when killed), or the deferred
 * status above when the job was not admitted. */
int ba_run(const struct ba_config *cfg, const char *const *argv, int argc);

/* Running and queued jobs as JSON: lane holders and ticket holders read from
 * /proc/locks, with command line and working directory when visible. */
bool ba_status(const char *state_dir, struct json_value *out);

#ifndef _WIN32
/* The same, with owner lookup limited to processes of user `uid`. */
bool ba_status_as(const char *state_dir, uid_t uid, struct json_value *out);
#endif

#endif /* ZCL_BUILD_ADMIT_H */
