/* event_log_pending — bounded deferred-record assembly implementation. */
#include "storage/event_log_pending.h"

#include "platform/private_file.h"
#include "util/safe_alloc.h"

#include <stdlib.h>

#define PENDING_TARGET (8u * 1024u * 1024u)

bool event_log_pending_write(struct event_log_pending *p,
                             struct platform_private_file *file,
                             uint64_t *end_offset)
{
    if (!p || !end_offset || p->len == 0)
        return true;
    if (!file || !platform_private_file_write_at(file, p->data, p->len,
                                                  *end_offset))
        return false;
    *end_offset += (uint64_t)p->len;
    p->len = 0;
    return true;
}

bool event_log_pending_prepare(struct event_log_pending *p, size_t need,
                               struct platform_private_file *file,
                               uint64_t *end_offset)
{
    if (!p || !end_offset || need > SIZE_MAX - p->len)
        return false;
    size_t required = p->len + need;
    if (p->len > 0 && required > PENDING_TARGET) {
        if (!event_log_pending_write(p, file, end_offset))
            return false;
        required = need;
    }
    if (required <= p->cap)
        return true;
    size_t cap = p->cap ? p->cap : 4096u;
    while (cap < required) {
        if (cap > SIZE_MAX / 2) {
            cap = required;
            break;
        }
        cap *= 2;
    }
    uint8_t *grown = zcl_realloc(p->data, cap, "event_log/pending");
    if (!grown)
        return false;
    p->data = grown;
    p->cap = cap;
    return true;
}

void event_log_pending_destroy(struct event_log_pending *p)
{
    if (!p)
        return;
    free(p->data);
    *p = (struct event_log_pending){0};
}
