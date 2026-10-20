/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: supervisor state shared by plugin_run.c (restart policy) and
 * plugin_run_spawn.c (confined child, ping and log plumbing). */
#ifndef ZCL_PLUGIN_RUN_INTERNAL_H
#define ZCL_PLUGIN_RUN_INTERNAL_H

#include "plugin/plugin_run.h"
#include "plugin_internal.h"

#include "platform/resident_launch.h"

enum {
    PRS_TOKEN_HEX = 64,
    PRS_LOG_LINE = 256
};

#define PRS_PING_MAGIC "z23-plg-ping-v1"

/* Supervisor to plugin on the control descriptor; the stop frame of
 * resident_launch_cancel has the same size and shape. */
struct prs_frame {
    char magic[16];
    char value[PRS_TOKEN_HEX + 1]; /* ping: fresh token; stop: launch nonce */
};

/* MISS: the control stream broke the host-call framing and was closed. */
enum prs_ping { PRS_PING_NONE, PRS_PING_OK, PRS_PING_BAD, PRS_PING_MISS };

struct plugin_run {
    struct plugin_run_options opt;
    char plugdir[PLUGIN_PATH_MAX];
    char data_dir[PLUGIN_PATH_MAX];
    char exe[PLUGIN_PATH_MAX];
    unsigned capabilities;
    char exe_sha3[PLUGIN_HEX_SHA3_512 + 1]; /* signed SHA3-512 of the executable */
    enum plugin_status store;
    struct plugin_run_info info;
    struct resident_launch launch;
    int log_fd;
    char log_line[PRS_LOG_LINE];
    size_t log_len;
    bool started_once;
    uint64_t next_ns;       /* when the child may start */
    uint64_t started_ns;
    uint64_t ping_sent_ns;
    uint64_t next_ping_ns;
    bool ping_pending;
    char ping_token[PRS_TOKEN_HEX + 1];
    uint32_t misses;
    uint32_t run_pings;     /* answered pings of the current child */
    /* Control stream of the current child: bytes received and not yet consumed,
     * the reply scratch, the host-call grant mask computed once from the verified
     * manifest, and the rate window. Heap buffers, so the by-value copy in
     * prs_check_target stays small. */
    uint8_t *ctl_rx;
    size_t ctl_rx_len;
    uint8_t *ctl_reply;
    uint32_t grants;
    uint64_t window_start_ns;
    uint32_t window_calls;
    /* Last generation that passed signature verification here, the digest of the
     * publisher_keys bytes it passed under, and its signed manifest. One entry,
     * memory only: a changed key list or generation misses and re-verifies. */
    char verified_generation[PLUGIN_HEX_SHA3_512 + 1];
    unsigned char verified_keys[32];
    struct plugin_manifest verified_manifest;
};

uint64_t prs_now_ns(void);

#if defined(__linux__)
/* Read the current generation, verify it and its capabilities. */
enum plugin_run_status prs_resolve(struct plugin_run *run);
/* Resolve and verify the target as a start would, leaving a running child and
 * the resolved fields untouched when it is refused. */
enum plugin_run_status prs_check_target(struct plugin_run *run);
/* Start the confined child for the resolved generation. */
enum plugin_run_status prs_child_start(struct plugin_run *run);
/* Stop frame, then SIGKILL; releases the launch and the log pipe. */
void prs_child_stop(struct plugin_run *run);
/* True when the child exited on its own; fills last_exit_* and detail. */
bool prs_child_reaped(struct plugin_run *run);
/* Serve the control stream: read what is pending, answer host calls, and report
 * whether a ping reply arrived. Runs every supervise tick. */
enum prs_ping prs_control_pump(struct plugin_run *run, uint64_t now);
/* Allocate or release the per-child control buffers; start also computes the
 * grant mask from run->capabilities. */
bool prs_control_start(struct plugin_run *run);
void prs_control_stop(struct plugin_run *run);
void prs_ping_send(struct plugin_run *run, uint64_t now);
/* Read pending log bytes; final also emits an unterminated last line. */
void prs_log_drain(struct plugin_run *run, bool final);
#else
/* Confined plugin processes are Linux-only; plugin_run_open refuses before any
 * of these run. */
static inline enum plugin_run_status prs_resolve(struct plugin_run *run)
{
    (void)run;
    return PLUGIN_RUN_ERR_PLATFORM;
}

static inline enum plugin_run_status prs_check_target(struct plugin_run *run)
{
    (void)run;
    return PLUGIN_RUN_ERR_PLATFORM;
}

static inline enum plugin_run_status prs_child_start(struct plugin_run *run)
{
    (void)run;
    return PLUGIN_RUN_ERR_PLATFORM;
}

static inline void prs_child_stop(struct plugin_run *run) { (void)run; }
static inline bool prs_child_reaped(struct plugin_run *run) { (void)run; return false; }
static inline void prs_ping_send(struct plugin_run *run, uint64_t now) { (void)run; (void)now; }

static inline enum prs_ping prs_control_pump(struct plugin_run *run, uint64_t now)
{
    (void)run;
    (void)now;
    return PRS_PING_NONE;
}

static inline bool prs_control_start(struct plugin_run *run) { (void)run; return true; }
static inline void prs_control_stop(struct plugin_run *run) { (void)run; }

static inline void prs_log_drain(struct plugin_run *run, bool final)
{
    (void)run;
    (void)final;
}
#endif

#endif
