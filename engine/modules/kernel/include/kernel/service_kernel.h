/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Service kernel: explicit lifecycle registry for one-binary services.
 *
 * The kernel owns ordering and state accounting only. Domain services keep
 * their implementation details and expose init/start/stop/status callbacks. */

#ifndef ZCL_KERNEL_SERVICE_KERNEL_H
#define ZCL_KERNEL_SERVICE_KERNEL_H

#include <stdbool.h>
#include <stddef.h>

#define ZCL_SERVICE_KERNEL_MAX_SERVICES 64

#define ZCL_SERVICE_REQUIRED 0u
#define ZCL_SERVICE_OPTIONAL (1u << 0)

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
};

struct zcl_service_kernel {
    struct zcl_service_entry services[ZCL_SERVICE_KERNEL_MAX_SERVICES];
    size_t count;
    bool initialized;
    bool started;
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

#endif
