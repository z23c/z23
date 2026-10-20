/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded jobs that let a RUNNING node fetch one signed plugin
 *          package root from its swarm peers and then install it. begin starts
 *          a bounded provider-directed swarm fetch and returns a job id at
 *          once; advance moves every job on (transfer complete, then the SAME
 *          plugin_dist_receive path `plugin fetch` uses, which verifies and
 *          installs as a NEW generation and never switches or runs anything);
 *          status copies a job out. Every refusal keeps its stable code.
 *          The table is fixed-size: at most PLUGIN_FETCH_ACTIVE_MAX jobs run
 *          at once, a job has a byte cap and a deadline, and a full table
 *          evicts only the oldest finished job. Ids are never reused. */
#ifndef ZCL_PLUGIN_FETCH_JOB_H
#define ZCL_PLUGIN_FETCH_JOB_H

#include "plugin/plugin_dist.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vcs_swarm_engine;
struct vcs_package_store;
struct plugin_fetch_table;

#define PLUGIN_FETCH_TABLE_MAX 16u
#define PLUGIN_FETCH_ACTIVE_MAX 2u
#define PLUGIN_FETCH_PEERS_MAX 16u
#define PLUGIN_FETCH_BYTES_DEFAULT (64ull * 1024ull * 1024ull)
#define PLUGIN_FETCH_BYTES_MAX (256ull * 1024ull * 1024ull)
#define PLUGIN_FETCH_TIMEOUT_DEFAULT_S 600u
#define PLUGIN_FETCH_TIMEOUT_MAX_S 3600u

enum plugin_fetch_state {
    PLUGIN_FETCH_FETCHING = 0, /* swarm transfer in progress */
    PLUGIN_FETCH_INSTALLING,   /* complete; verify-and-install running */
    PLUGIN_FETCH_INSTALLED,    /* terminal: a new generation exists */
    PLUGIN_FETCH_FAILED        /* terminal: see code */
};
const char *plugin_fetch_state_string(enum plugin_fetch_state state);

/* Resident handles, borrowed for the call. scratch_dir is an existing private
 * directory; plugins_dir is the node owner's plugin store. */
struct plugin_fetch_ctx {
    struct vcs_swarm_engine *engine;
    struct vcs_package_store *store;
    const char *plugins_dir;
    const char *scratch_dir;
};

struct plugin_fetch_request {
    uint8_t root[32];
    const char *name;
    bool allow_downgrade;
    const uint64_t *peers;     /* named peer handles, or NULL for all connected */
    size_t peer_count;
    uint64_t max_bytes;        /* 0 = default */
    uint32_t timeout_s;        /* 0 = default */
};

enum plugin_fetch_begin_status {
    PLUGIN_FETCH_BEGIN_OK = 0,
    PLUGIN_FETCH_BEGIN_ARGUMENT,
    PLUGIN_FETCH_BEGIN_BUSY,        /* PLUGIN_FETCH_ACTIVE_MAX jobs running */
    PLUGIN_FETCH_BEGIN_NO_SWARM,
    PLUGIN_FETCH_BEGIN_NO_PEERS,
    PLUGIN_FETCH_BEGIN_UNKNOWN_PEER,
    PLUGIN_FETCH_BEGIN_SWARM_REFUSED
};
const char *plugin_fetch_begin_code(enum plugin_fetch_begin_status status);

struct plugin_fetch_begin_result {
    enum plugin_fetch_begin_status status;
    uint64_t job;              /* nonzero when status is OK */
    bool existing;             /* an active job for this root was returned */
    char detail[192];
};

struct plugin_fetch_view {
    uint64_t job;
    enum plugin_fetch_state state;
    char root_hex[65];
    char name[PLUGIN_NAME_MAX + 1];
    uint64_t started, deadline;
    uint64_t max_bytes;
    uint32_t present_chunks, total_chunks;  /* swarm progress while FETCHING */
    uint64_t present_bytes, total_bytes;
    /* FAILED only. */
    char code[48];
    char next_action[192];
    char detail[256];
    /* INSTALLED only. */
    char version[PLUGIN_VERSION_MAX + 1];
    char generation[PLUGIN_HEX_SHA3_512 + 1];
    bool already_present;
    bool downgrade_allowed;
};

struct plugin_fetch_table *plugin_fetch_table_new(void);
void plugin_fetch_table_free(struct plugin_fetch_table *table);

void plugin_fetch_begin(struct plugin_fetch_table *table, const struct plugin_fetch_ctx *ctx,
                        const struct plugin_fetch_request *request, uint64_t now,
                        struct plugin_fetch_begin_result *out);
/* Moves every job on. Safe from several threads; the install runs outside the
 * table lock and only one thread installs a given job. */
void plugin_fetch_advance(struct plugin_fetch_table *table, const struct plugin_fetch_ctx *ctx,
                          uint64_t now);
bool plugin_fetch_status(struct plugin_fetch_table *table, uint64_t job,
                         struct plugin_fetch_view *out);
/* Rows newest first; returns the count written (<= max). */
size_t plugin_fetch_list(struct plugin_fetch_table *table, struct plugin_fetch_view *out,
                         size_t max);

#endif
