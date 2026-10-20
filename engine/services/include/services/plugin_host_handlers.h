/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: node-backed READ-ONLY handlers for the plugin host-call protocol
 * (plugin/plugin_hostcall.h). Fills the handler vtable for chain.tip,
 * chain.header_by_height and log.write. state.get, state.put, event.append
 * and wallet.request stay NULL, so the dispatcher answers them UNAVAILABLE.
 *
 * Reads reuse existing paths only: the served authority pair
 * (tip_finalize_stage_authority_snapshot) and the block model
 * (db_block_find_by_height, db_block_load_header_by_hash_height). Nothing here
 * writes chain or wallet state, takes cs_main or holds a lock across a reply.
 *
 * Reply layouts (big-endian, as the frame):
 *   chain.tip              height u32, block hash 32, block time u32 (40 bytes)
 *   chain.header_by_height canonical header serialization (140+ bytes), or an
 *                          EMPTY OK reply when no canonical header exists at
 *                          that height or it is past the served tip (a real
 *                          header is never empty, so empty means not found)
 *   log.write              empty
 *
 * Threading (enforced at construction, not just documented): the node is bound
 * to the thread that calls plugin_host_node_init, with a DEDICATED READ-ONLY
 * node_db connection that thread owns. No cached statement of the node's
 * main connection is touched, and every handler refuses when called from any
 * other thread. Header reads use per-call prepared statements on that
 * connection; canonical heights come from the lock-free active chain index and
 * must agree with the authority tip, so a stored fork block is never served.
 * log.write drops C0/DEL/C1 controls and malformed UTF-8; it keeps valid
 * UTF-8 text. */
#ifndef ZCL_SERVICES_PLUGIN_HOST_HANDLERS_H
#define ZCL_SERVICES_PLUGIN_HOST_HANDLERS_H

#include "base/result.h"
#include "plugin/plugin_hostcall.h"

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <stdint.h>

struct node_db;
struct active_chain;

#define PLUGIN_HOST_NAME_MAX 48u      /* plugin name bytes kept in a log prefix */
#define PLUGIN_HOST_LOG_TEXT_MAX 256u /* log text bytes accepted per line */
#define PLUGIN_HOST_LOG_LINE_MAX 384u /* "[plugin NAME] " plus text, with NUL */
#define PLUGIN_HOST_LOG_BURST 20u     /* lines accepted per rate window */
#define PLUGIN_HOST_LOG_WINDOW_MS 1000 /* rate window length */
#define PLUGIN_HOST_TIP_REPLY_BYTES 40u

enum plugin_host_log_level {
    PLUGIN_HOST_LOG_DEBUG = 0,
    PLUGIN_HOST_LOG_INFO = 1,
    PLUGIN_HOST_LOG_WARN = 2,
    PLUGIN_HOST_LOG_ERROR = 3
};

/* Served authority source: fills the tip height and hash, false when none is
 * published. NULL in the node means the reducer's served authority pair. */
typedef bool (*plugin_host_authority_fn)(void *context, int64_t *height,
                                         uint8_t hash[32]);
/* Monotonic milliseconds for the log rate window; NULL means the node clock. */
typedef int64_t (*plugin_host_now_ms_fn)(void *context);
/* Receives one sanitized log line; NULL means the node log. */
typedef void (*plugin_host_log_sink_fn)(void *context, unsigned level,
                                        const char *line);

struct plugin_host_node {
    struct node_db *ndb;               /* read-only, owned by the serving thread */
    const struct active_chain *chain;  /* canonical height -> hash index */
    pthread_t owner;                   /* the thread that called init */
    char plugin[PLUGIN_HOST_NAME_MAX + 1]; /* sanitized by plugin_host_node_init */
    plugin_host_authority_fn authority;
    void *authority_context;
    plugin_host_now_ms_fn now_ms;
    void *now_context;
    plugin_host_log_sink_fn log_sink;
    void *log_context;
    int64_t window_start_ms; /* rate window, owned by log.write */
    unsigned window_lines;
    uint64_t log_dropped;    /* lines refused by the rate limit */
};

/* Prepare a node for one plugin on the CALLING thread, which becomes the only
 * thread allowed to run its handlers (each handler refuses on any other).
 * ro_ndb must be an open, strictly read-only connection that this thread owns
 * (for example from zcl_native_node_db_open_readonly); a writable or closed
 * connection is refused (sqlite3_db_readonly). chain is the node's active
 * chain index (&ms->chain_active), read lock-free. The plugin name has control
 * bytes stripped and is cut at PLUGIN_HOST_NAME_MAX; an empty result is
 * refused. */
struct zcl_result plugin_host_node_init(struct plugin_host_node *node,
                                        struct node_db *ro_ndb,
                                        const struct active_chain *chain,
                                        const char *plugin_name);

/* Fill out with the node-backed handlers (context = node) and leave every
 * other method NULL. Refuses a null argument without writing. */
struct zcl_result plugin_host_node_handlers(struct plugin_hostcall_handlers *out,
                               struct plugin_host_node *node);

#endif
