/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Service kernel: explicit lifecycle registry for one-binary services.
 *
 * The kernel owns ordering and state accounting only. Domain services keep
 * their implementation details and expose init/start/stop/status callbacks. */

#ifndef ZCL_KERNEL_SERVICE_KERNEL_H
#define ZCL_KERNEL_SERVICE_KERNEL_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_SERVICE_KERNEL_MAX_SERVICES 64

#define ZCL_SERVICE_REQUIRED 0u
#define ZCL_SERVICE_OPTIONAL (1u << 0)
/* INDEPENDENT: this service's start failure is still a failure —
 * start_all() reports it, the entry is marked FAILED with its reason, and
 * the caller decides what to do — but it does NOT cancel the services
 * registered after it, and nothing already started is unwound.
 *
 * The 2026-09-08 node1 outage is what this flag is for. rpc_http was the
 * one REQUIRED service in the frontend kernel. Its bind failed once (the
 * outgoing process still held port 18232), so start_all() rolled back
 * file_service and rom_seed and returned before ever calling
 * https_explorer's start. Nothing about the public site depended on the
 * RPC front door binding, but the site stayed down for 27 minutes because
 * one sibling's transient port conflict cancelled it.
 *
 * OPTIONAL means "its failure is not a failure"; INDEPENDENT means "its
 * failure is a failure, and it is ITS failure". Neither weakens the other:
 * an INDEPENDENT failure still makes start_all() return false. */
#define ZCL_SERVICE_INDEPENDENT (1u << 1)

/* A start that runs longer than this is named in the kernel's in-flight
 * description, so a watchdog can say WHICH service it is waiting on. */
#define ZCL_SERVICE_SLOW_START_US (10LL * 1000000LL)

enum zcl_service_state {
    ZCL_SERVICE_UNREGISTERED = 0,
    ZCL_SERVICE_REGISTERED,
    ZCL_SERVICE_INITIALIZED,
    ZCL_SERVICE_STARTED,
    ZCL_SERVICE_STOPPED,
    ZCL_SERVICE_FAILED
};

struct zcl_service_status {
    enum zcl_service_state state;
    const char *reason;
};

struct zcl_service_kernel;

typedef bool (*zcl_service_init_fn)(struct zcl_service_kernel *kernel,
                                    void *ctx);
typedef bool (*zcl_service_start_fn)(void *ctx);
typedef void (*zcl_service_stop_fn)(void *ctx);
typedef bool (*zcl_service_status_fn)(void *ctx,
                                      struct zcl_service_status *out);

struct zcl_service_spec {
    const char *name;
    zcl_service_init_fn init;
    zcl_service_start_fn start;
    zcl_service_stop_fn stop;
    zcl_service_status_fn status;
    void *ctx;
    unsigned flags;
};

struct zcl_service_entry {
    struct zcl_service_spec spec;
    enum zcl_service_state state;
    const char *failure_reason;
    /* How long this service's start() hook ran, microseconds. Kept per
     * entry because "the frontend took 2.4 seconds" was all the boot log
     * said on 2026-09-08 — it never named which of the eight services
     * spent it, or which one failed. */
    int64_t start_us;
};

struct zcl_service_kernel {
    struct zcl_service_entry services[ZCL_SERVICE_KERNEL_MAX_SERVICES];
    size_t count;
    bool initialized;
    bool started;
    /* The start() hook running right now, for a watchdog on another
     * thread. Atomics only: the reader must never take a lock, and the
     * name is a string literal owned by the spec table, so publishing the
     * pointer cannot dangle. NULL = no start in flight. */
    _Atomic(const char *) starting_name;
    _Atomic int64_t starting_since_us;
};

void zcl_service_kernel_init(struct zcl_service_kernel *kernel);
void zcl_service_kernel_reset(struct zcl_service_kernel *kernel);

bool zcl_service_kernel_register(struct zcl_service_kernel *kernel,
                                 const struct zcl_service_spec *spec);
bool zcl_service_kernel_init_all(struct zcl_service_kernel *kernel);
bool zcl_service_kernel_start_all(struct zcl_service_kernel *kernel);
void zcl_service_kernel_stop_all(struct zcl_service_kernel *kernel);

size_t zcl_service_kernel_count(const struct zcl_service_kernel *kernel);
const struct zcl_service_entry *zcl_service_kernel_find(
    const struct zcl_service_kernel *kernel,
    const char *name);
bool zcl_service_kernel_status(const struct zcl_service_kernel *kernel,
                               const char *name,
                               struct zcl_service_status *out);

/* Describe the start that is in flight RIGHT NOW, if it has been running
 * longer than `slow_us`: writes "<prefix>=<service> <seconds>s" into `out`
 * and returns true. Writes an empty string and returns false otherwise —
 * a fast start is not news.
 *
 * Lock-free atomic loads only, so a watchdog heartbeat can call it while
 * the start it is describing is still blocked. `now_us` is the caller's
 * monotonic clock, which keeps this function itself clock-free and
 * directly testable. */
bool zcl_service_kernel_describe_starting(
    const struct zcl_service_kernel *kernel, const char *prefix,
    int64_t now_us, int64_t slow_us, char *out, size_t cap);

#endif
