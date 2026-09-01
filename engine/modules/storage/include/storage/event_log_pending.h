/* event_log_pending — bounded deferred-record assembly interface. */
#ifndef ZCL_STORAGE_EVENT_LOG_PENDING_H
#define ZCL_STORAGE_EVENT_LOG_PENDING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct platform_private_file;

/* Internal bounded assembly buffer for deferred event-log records. */
struct event_log_pending {
    uint8_t *data;
    size_t len;
    size_t cap;
};

/* Ensure `need` bytes fit. Writes an existing >8 MiB span without syncing;
 * `end_offset` advances only after a complete write. */
bool event_log_pending_prepare(struct event_log_pending *p, size_t need,
                               struct platform_private_file *file,
                               uint64_t *end_offset);
bool event_log_pending_write(struct event_log_pending *p,
                             struct platform_private_file *file,
                             uint64_t *end_offset);
void event_log_pending_destroy(struct event_log_pending *p);

#endif
