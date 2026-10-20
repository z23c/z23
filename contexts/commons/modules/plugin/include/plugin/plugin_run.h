/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: supervise one installed plugin. The plugin's current executable
 * runs as a confined child (Landlock, seccomp, resource limits) that holds
 * only the descriptors its manifest grants. The supervisor pings it with a
 * fresh nonce, restarts it with exponential backoff after an exit or missed
 * pings, and restores the last-good generation once after a crash loop.
 * Linux with Landlock ABI 3 (file truncation handled) and seccomp only;
 * elsewhere plugin_run_open refuses with PLUGIN_RUN_ERR_PLATFORM or
 * PLUGIN_RUN_ERR_SANDBOX.
 * docs/dev/PLUGINS.md describes the descriptors and the ping protocol. */
#ifndef ZCL_PLUGIN_RUN_H
#define ZCL_PLUGIN_RUN_H

#include "plugin/plugin_hostcall.h"
#include "plugin/plugin_store.h"

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

enum plugin_run_status {
    PLUGIN_RUN_OK = 0,
    PLUGIN_RUN_ERR_ARGUMENT,
    PLUGIN_RUN_ERR_PLATFORM,   /* confined spawn is Linux-only */
    PLUGIN_RUN_ERR_STORE,      /* the store refused; see the plugin_status */
    PLUGIN_RUN_ERR_CAPABILITY, /* a granted capability has no descriptor yet */
    PLUGIN_RUN_ERR_SPAWN,      /* the confined spawn was refused */
    PLUGIN_RUN_ERR_FAILED,     /* supervision ended; see plugin_run_info */
    PLUGIN_RUN_ERR_SANDBOX     /* the kernel lacks Landlock ABI 3 or seccomp */
};

/* Stable refusal code, for example "PLUGIN_RUN_CAPABILITY". */
const char *plugin_run_status_code(enum plugin_run_status status);
/* The operator action that resolves the refusal. */
const char *plugin_run_status_next_action(enum plugin_run_status status);

/* A zero field selects its default, shown in parentheses. */
struct plugin_run_options {
    const char *root;            /* plugin store, normally ~/.z23/plugins */
    const char *name;
    uint32_t ping_interval_ms;   /* between pings (1000) */
    uint32_t ping_deadline_ms;   /* a ping unanswered this long is missed (2000) */
    uint32_t ping_miss_limit;    /* consecutive misses that restart it (2) */
    uint32_t backoff_initial_ms; /* first restart delay (250) */
    uint32_t backoff_max_ms;     /* restart delay ceiling (30000) */
    uint32_t stable_ms;          /* healthy time that clears the crash count (10000) */
    uint32_t crash_limit;        /* crashes of one generation before fallback (3) */
    bool log_to_stderr;          /* forward the plugin's log lines to stderr */
    /* Host-call handlers, or NULL to answer every call UNAVAILABLE. The table
     * and its context are owned by the caller and must outlive the run. They
     * are invoked only from the thread that calls plugin_run_poll or
     * plugin_run_loop, one call at a time, so that thread must be the one that
     * owns whatever the handlers touch. node_db is not thread-safe: give the
     * handlers a read-only connection that belongs to the polling thread, or poll
     * from the thread that owns the shared node_db. plugin_run never touches a
     * database itself. */
    const struct plugin_hostcall_handlers *hostcall;
    uint32_t hostcall_per_second; /* host calls served per child per second (200) */
};

enum plugin_run_state {
    PLUGIN_RUN_STATE_BACKOFF,    /* waiting to start the child */
    PLUGIN_RUN_STATE_RUNNING,
    PLUGIN_RUN_STATE_FAILED,     /* supervision ended */
    PLUGIN_RUN_STATE_STOPPED
};

struct plugin_run_info {
    enum plugin_run_state state;
    char generation[PLUGIN_HEX_SHA3_512 + 1]; /* generation of the current or last child */
    uint64_t pid;                /* 0 unless running */
    uint32_t restarts;           /* children started after the first */
    uint32_t crashes;            /* consecutive crashes of this generation */
    uint32_t backoff_ms;         /* delay applied to the next restart */
    uint64_t pings_ok;
    uint64_t log_bytes;
    int last_exit_code;          /* -1 when the child was killed by a signal */
    int last_exit_signal;        /* 0 when it exited */
    bool fell_back;              /* last-good was restored by a crash loop */
    char detail[160];            /* last refusal or exit reason */
    char last_log[128];          /* last complete log line, control bytes shown as '?' */
};

struct plugin_run;

#ifdef ZCL_TESTING
/* Test seam: corrupt the signed SHA3-512 each resolve reads, so the launch-time
 * comparison of the executable's bytes is reached with a mismatch. */
void plugin_run_test_corrupt_signed_hash(bool on);
/* Test seam: how many full signature verifications this process has run. */
unsigned plugin_run_test_verify_count(void);
/* Test seam: call fn at the two points a verification can be raced, between
 * reading the key list and verifying under it (1) and after verifying and
 * before the result is remembered (2). NULL clears it. */
#define PLUGIN_RUN_TEST_AFTER_KEYS 1
#define PLUGIN_RUN_TEST_AFTER_VERIFY 2
void plugin_run_test_set_hook(void (*fn)(int point, void *ctx), void *ctx);
#endif

/* The caller owns process-wide signal state: SIGCHLD must be at SIG_DFL while a
 * run is open, or the kernel discards the child's exit status and it is
 * reported as lost (last_exit_code -1, signal 0). `z23 plugin run` sets it.
 *
 * Verify the plugin's current generation and its capabilities. Starts no
 * process. On PLUGIN_RUN_ERR_STORE the store refusal is written to *store. */
enum plugin_run_status plugin_run_open(const struct plugin_run_options *options,
                                       struct plugin_run **out,
                                       enum plugin_status *store);

/* One non-blocking supervision step: start the child when its delay has
 * passed, reap an exit, drain the log, send or collect one ping. The first
 * start being refused (PLUGIN_RUN_ERR_SPAWN) or a store or capability refusal
 * at a restart ends supervision; later spawn failures count as crashes.
 * Returns PLUGIN_RUN_ERR_FAILED once supervision has ended. */
enum plugin_run_status plugin_run_poll(struct plugin_run *run);

/* Restart only this plugin on its current generation now: the child is
 * stopped, crash count and backoff are cleared, and a new child starts. */
enum plugin_run_status plugin_run_reload(struct plugin_run *run);

void plugin_run_info_get(const struct plugin_run *run, struct plugin_run_info *out);

/* Poll until *stop is set or max_ms has passed (0 means no time limit). A set
 * *reload (may be NULL) means plugin_run_reload and clear. Returns the first
 * error, or PLUGIN_RUN_OK when stopped. */
enum plugin_run_status plugin_run_loop(struct plugin_run *run,
                                       volatile const sig_atomic_t *stop,
                                       volatile sig_atomic_t *reload,
                                       uint32_t max_ms);

/* Stop the child (stop frame, then SIGKILL) and release the supervisor. */
void plugin_run_close(struct plugin_run *run);

#endif
