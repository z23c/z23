/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_zip243_host.h"
#include "crypto/blake2b.h"

static bool start(void *context, const uint8_t personal[16]) {
    return blake2b_init_salt_personal(context, 32, NULL, 0, NULL,
                                      personal) == 0;
}

static bool update(void *context, const uint8_t *bytes, size_t length) {
    return blake2b_update(context, bytes, length) == 0;
}

static bool finish(void *context, uint8_t digest[32]) {
    return blake2b_final(context, digest, 32) == 0;
}

zcl_zip243_hasher zcl_zip243_host_hasher(struct blake2b_ctx *context) {
    return (zcl_zip243_hasher){.context = context, .init = start,
                                .update = update, .final = finish};
}
