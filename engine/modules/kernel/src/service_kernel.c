/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "kernel/service_kernel.h"
#include <string.h>

static bool service_spec_valid(const struct zcl_service_spec *spec)
{
    return spec && spec->name && spec->name[0] && spec->start && spec->stop;
}

static void service_mark_failed(struct zcl_service_entry *entry,
                                const char *reason)
{
    if (!entry)
        return;
    entry->state = ZCL_SERVICE_FAILED;
    entry->failure_reason = reason ? reason : "failed";
}

static bool service_optional(const struct zcl_service_entry *entry)
{
    return entry && (entry->spec.flags & ZCL_SERVICE_OPTIONAL) != 0;
}

void zcl_service_kernel_init(struct zcl_service_kernel *kernel)
{
    if (!kernel)
        return;
    memset(kernel, 0, sizeof(*kernel));
}

void zcl_service_kernel_reset(struct zcl_service_kernel *kernel)
{
    zcl_service_kernel_init(kernel);
}

bool zcl_service_kernel_register(struct zcl_service_kernel *kernel,
                                 const struct zcl_service_spec *spec)
{
    if (!kernel || !service_spec_valid(spec))
        return false;
    if (kernel->started)
        return false;
    if (kernel->count >= ZCL_SERVICE_KERNEL_MAX_SERVICES)
        return false;
    if (zcl_service_kernel_find(kernel, spec->name))
        return false;

    struct zcl_service_entry *entry = &kernel->services[kernel->count++];
    memset(entry, 0, sizeof(*entry));
    entry->spec = *spec;
    entry->state = ZCL_SERVICE_REGISTERED;
    return true;
}

bool zcl_service_kernel_init_all(struct zcl_service_kernel *kernel)
{
    if (!kernel)
        return false;
    if (kernel->initialized)
        return true;

    for (size_t i = 0; i < kernel->count; i++) {
        struct zcl_service_entry *entry = &kernel->services[i];
        if (entry->spec.init && !entry->spec.init(kernel, entry->spec.ctx)) {
            service_mark_failed(entry, "init failed");
            if (!service_optional(entry))
                return false;
            continue;
        }
        entry->state = ZCL_SERVICE_INITIALIZED;
        entry->failure_reason = NULL;
    }

    kernel->initialized = true;
    return true;
}

bool zcl_service_kernel_start_all(struct zcl_service_kernel *kernel)
{
    if (!kernel)
        return false;
    if (kernel->started)
        return true;
    if (!zcl_service_kernel_init_all(kernel))
        return false;

    for (size_t i = 0; i < kernel->count; i++) {
        struct zcl_service_entry *entry = &kernel->services[i];
        if (entry->state == ZCL_SERVICE_FAILED && service_optional(entry))
            continue;
        if (!entry->spec.start(entry->spec.ctx)) {
            service_mark_failed(entry, "start failed");
            if (service_optional(entry))
                continue;
            for (size_t j = i; j > 0; j--) {
                struct zcl_service_entry *started = &kernel->services[j - 1];
                if (started->state == ZCL_SERVICE_STARTED) {
                    started->spec.stop(started->spec.ctx);
                    started->state = ZCL_SERVICE_STOPPED;
                }
            }
            return false;
        }
        entry->state = ZCL_SERVICE_STARTED;
        entry->failure_reason = NULL;
    }

    kernel->started = true;
    return true;
}

void zcl_service_kernel_stop_all(struct zcl_service_kernel *kernel)
{
    if (!kernel)
        return;

    for (size_t i = kernel->count; i > 0; i--) {
        struct zcl_service_entry *entry = &kernel->services[i - 1];
        if (entry->state == ZCL_SERVICE_STARTED) {
            entry->spec.stop(entry->spec.ctx);
            entry->state = ZCL_SERVICE_STOPPED;
        }
    }

    kernel->started = false;
}

size_t zcl_service_kernel_count(const struct zcl_service_kernel *kernel)
{
    return kernel ? kernel->count : 0;
}

const struct zcl_service_entry *zcl_service_kernel_find(
    const struct zcl_service_kernel *kernel,
    const char *name)
{
    if (!kernel || !name)
        return NULL;
    for (size_t i = 0; i < kernel->count; i++) {
        if (strcmp(kernel->services[i].spec.name, name) == 0)
            return &kernel->services[i];
    }
    return NULL;
}

bool zcl_service_kernel_status(const struct zcl_service_kernel *kernel,
                               const char *name,
                               struct zcl_service_status *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));

    const struct zcl_service_entry *entry =
        zcl_service_kernel_find(kernel, name);
    if (!entry)
        return false;

    out->state = entry->state;
    out->reason = entry->failure_reason;
    if (entry->spec.status)
        return entry->spec.status(entry->spec.ctx, out);
    return true;
}

