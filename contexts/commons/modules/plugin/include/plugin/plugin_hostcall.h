/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the plugin host-call protocol. A plugin asks the host for chain
 * reads, state, events and log lines over its control socket as framed
 * requests; the host answers each with one framed reply. This library is
 * only the codec, the method table and the capability-gated dispatcher. It
 * touches no node, socket, file or clock: a caller supplies the handler
 * vtable, so every effect stays in code the caller owns. It is not wired into
 * plugin_run yet; docs/dev/PLUGINS.md describes the control socket today.
 *
 * Wire frame (all integers big-endian):
 *   u32 length   bytes that follow, 8 + payload size
 *   u8  version  PLUGIN_HOSTCALL_VERSION
 *   u8  kind     1 request, 2 reply
 *   u32 id       request id, echoed by the reply
 *   u16 code     request: method id; reply: enum plugin_hostcall_status
 *   ... payload  0 to PLUGIN_HOSTCALL_MAX_PAYLOAD bytes
 *
 * Payload layouts (the codec bounds sizes only; handlers parse the bytes):
 *   chain.tip              empty            -> height u32, block hash 32
 *   chain.header_by_height height u32       -> header bytes
 *   state.get              klen u8, key     -> value bytes
 *   state.put              klen u8, key, value bytes -> empty
 *   event.append           tlen u8, topic, event bytes -> empty
 *   log.write              level u8, text   -> empty
 *   wallet.request         PLANNED, always refused */
#ifndef ZCL_PLUGIN_HOSTCALL_H
#define ZCL_PLUGIN_HOSTCALL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PLUGIN_HOSTCALL_VERSION 1u
#define PLUGIN_HOSTCALL_HEADER_BYTES 12u /* length prefix plus fixed fields */
/* The fixed fields after the length prefix. */
#define PLUGIN_HOSTCALL_BODY_FIXED 8u
/* Hard payload ceiling. 64 KiB holds the largest legitimate request (a state
 * value or an event, both far smaller in practice) with room to spare, while
 * bounding the memory one plugin can make the host buffer to a single small
 * allocation. It also sits below the 2^32 length prefix by sixteen bits, so a
 * length arithmetic overflow is impossible on 32-bit size_t hosts. */
#define PLUGIN_HOSTCALL_MAX_PAYLOAD 65536u
#define PLUGIN_HOSTCALL_MAX_FRAME \
    (PLUGIN_HOSTCALL_HEADER_BYTES + PLUGIN_HOSTCALL_MAX_PAYLOAD)

enum plugin_hostcall_kind {
    PLUGIN_HOSTCALL_KIND_REQUEST = 1,
    PLUGIN_HOSTCALL_KIND_REPLY = 2
};

enum plugin_hostcall_status {
    PLUGIN_HOSTCALL_OK = 0,
    PLUGIN_HOSTCALL_ERR_ARGUMENT,   /* null pointer or zero-size buffer */
    PLUGIN_HOSTCALL_ERR_TRUNCATED,  /* the buffer ends inside the frame */
    PLUGIN_HOSTCALL_ERR_OVERSIZE,   /* declared payload exceeds the maximum */
    PLUGIN_HOSTCALL_ERR_UNDERSIZE,  /* declared length is below the fixed fields */
    PLUGIN_HOSTCALL_ERR_VERSION,    /* unknown protocol version */
    PLUGIN_HOSTCALL_ERR_KIND,       /* neither request nor reply */
    PLUGIN_HOSTCALL_ERR_METHOD,     /* unknown method id */
    PLUGIN_HOSTCALL_ERR_PAYLOAD,    /* payload size outside the method bounds */
    PLUGIN_HOSTCALL_DENIED,         /* the manifest did not grant the capability */
    PLUGIN_HOSTCALL_ERR_PLANNED,    /* the method is listed but not built */
    PLUGIN_HOSTCALL_ERR_UNAVAILABLE,/* the caller supplied no handler */
    PLUGIN_HOSTCALL_ERR_HANDLER,    /* the handler failed or broke its contract */
    PLUGIN_HOSTCALL_ERR_BUFFER      /* the output buffer is too small */
};

/* Stable refusal code, for example "PLUGIN_HOSTCALL_DENIED". */
const char *plugin_hostcall_status_code(enum plugin_hostcall_status status);
/* The action that resolves the refusal. */
const char *plugin_hostcall_status_next_action(enum plugin_hostcall_status status);

/* Capabilities the host-call layer gates on. The manifest names are dotted,
 * like fs.read and clock in plugin_manifest.c, which does not list these yet.
 * Each maps to one ZCL_APP_CAP_* constant in engine/modules/framework/include/
 * zclassic23/app.h:
 *   "chain.read"     ZCL_APP_CAP_CHAIN_READ
 *   "state"          ZCL_APP_CAP_RESIDENT_STATE
 *   "events.append"  ZCL_APP_CAP_SIGNED_EVENTS
 *   "wallet.request" ZCL_APP_CAP_WALLET_REQUESTS
 * The zcl_app_host_v1 calls p2p_publish, lease_acquire, lease_release and
 * state_open have no wire method yet. */
enum plugin_hostcall_cap {
    PLUGIN_HOSTCALL_CAP_NONE = 0,
    PLUGIN_HOSTCALL_CAP_CHAIN_READ = 1u << 0, /* manifest "chain.read" */
    PLUGIN_HOSTCALL_CAP_STATE = 1u << 1,      /* manifest "state" */
    PLUGIN_HOSTCALL_CAP_EVENTS = 1u << 2,     /* manifest "events.append" */
    PLUGIN_HOSTCALL_CAP_WALLET = 1u << 3      /* manifest "wallet.request" */
};

/* Bit for a manifest capability name, or 0 when the name is not a host-call
 * capability. */
uint32_t plugin_hostcall_cap_from_name(const char *name);
/* Granted set from a verified manifest's capability bits (the bit positions
 * of plugin_capability_name in plugin/plugin_store.h). Names outside the
 * host-call vocabulary grant nothing here. */
uint32_t plugin_hostcall_grants_from_manifest(unsigned manifest_capabilities);

enum plugin_hostcall_method {
    PLUGIN_HOSTCALL_M_CHAIN_TIP = 1,
    PLUGIN_HOSTCALL_M_CHAIN_HEADER_BY_HEIGHT = 2,
    PLUGIN_HOSTCALL_M_STATE_GET = 3,
    PLUGIN_HOSTCALL_M_STATE_PUT = 4,
    PLUGIN_HOSTCALL_M_EVENT_APPEND = 5,
    PLUGIN_HOSTCALL_M_LOG_WRITE = 6,
    PLUGIN_HOSTCALL_M_WALLET_REQUEST = 7 /* PLANNED */
};
#define PLUGIN_HOSTCALL_METHOD_COUNT 7u

struct plugin_hostcall_method_info {
    uint16_t id;
    const char *name;
    uint32_t capability; /* enum plugin_hostcall_cap, NONE for no gate */
    uint32_t min_payload;
    uint32_t max_payload;
    bool planned;        /* listed, always refused */
};

/* Method row for an id, or NULL when the id is unknown. */
const struct plugin_hostcall_method_info *plugin_hostcall_method_by_id(uint16_t id);
/* Method row for a dotted name such as "chain.tip", or NULL. */
const struct plugin_hostcall_method_info *plugin_hostcall_method_by_name(const char *name);
/* Rows in id order; index with 0 to PLUGIN_HOSTCALL_METHOD_COUNT - 1. */
const struct plugin_hostcall_method_info *plugin_hostcall_method_at(size_t index);

/* A decoded frame; payload points into the decoded buffer (zero copy). */
struct plugin_hostcall_frame {
    uint8_t kind;        /* enum plugin_hostcall_kind */
    uint32_t id;
    uint16_t code;       /* request: method id; reply: status */
    const uint8_t *payload;
    size_t payload_len;
};

/* Encode one frame into out. Writes the frame size to *written. Refuses a
 * bad kind, an oversized payload, a null payload with a nonzero length, or a
 * buffer too small, and leaves *written 0 on refusal. */
enum plugin_hostcall_status plugin_hostcall_encode(
    const struct plugin_hostcall_frame *frame, uint8_t *out, size_t out_cap,
    size_t *written);

/* Decode the first frame in buf[0..len). Total: any input yields OK or one
 * distinct refusal, and no byte past len is read. *consumed is the frame size
 * on OK and 0 otherwise. ERR_TRUNCATED means more bytes may complete the
 * frame; every other refusal is final. Structure only: method, payload bounds
 * and capability are checked by plugin_hostcall_dispatch. */
enum plugin_hostcall_status plugin_hostcall_decode(
    const uint8_t *buf, size_t len, struct plugin_hostcall_frame *frame,
    size_t *consumed);

/* Handler for one method. Writes at most out_cap reply bytes to out and the
 * count to *out_len; returns 0 on success, nonzero to refuse. */
typedef int (*plugin_hostcall_handler)(void *context, const uint8_t *payload,
                                       size_t payload_len, uint8_t *out,
                                       size_t out_cap, size_t *out_len);

/* Caller-supplied vtable, indexed by method id minus one. A NULL entry makes
 * that method PLUGIN_HOSTCALL_ERR_UNAVAILABLE. */
struct plugin_hostcall_handlers {
    void *context;
    plugin_hostcall_handler method[PLUGIN_HOSTCALL_METHOD_COUNT];
};

/* Check one request and run its handler. Order: request kind, known method,
 * planned, granted capability, payload bounds, handler. Always writes a reply
 * frame (the status in its code, an empty payload unless OK) when reply_cap
 * can hold one, and returns the status that reply carries. A null or
 * non-request frame writes no reply. */
enum plugin_hostcall_status plugin_hostcall_dispatch(
    const struct plugin_hostcall_frame *request, uint32_t granted,
    const struct plugin_hostcall_handlers *handlers, uint8_t *reply,
    size_t reply_cap, size_t *reply_len);

#endif
