/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fingerprint the payloads of an event log. */
#include "storage/event_log.h"
#include "crypto/sha3.h"

struct fp_ctx { struct sha3_256_ctx h; };

static bool fp_cb(uint64_t offset, enum event_log_type type,
                  const void *payload, size_t len, void *user)
{
    (void)offset; (void)type;
    struct fp_ctx *c = (struct fp_ctx *)user;
    if (len > 0 && payload)
        sha3_256_write(&c->h, (const unsigned char *)payload, len);
    return true;
}

int event_log_fingerprint(event_log_t *log, uint8_t out[32])
{
    if (!log || !out) return -1;
    struct fp_ctx c;
    sha3_256_init(&c.h);
    if (event_log_stream(log, 0, fp_cb, &c) < 0) return -1;
    sha3_256_finalize(&c.h, out);
    return 0;
}
