/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private shape shared by transparent intent planning and rendering. */
#ifndef ZCL_VAULT_INTENT_TRANSPARENT_INTERNAL_H
#define ZCL_VAULT_INTENT_TRANSPARENT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#define VI_EFFECTS_MAX 50
#define VI_INPUTS_MAX 128
#define VI_ADDR_MAX 127

struct vi_effect { char to[VI_ADDR_MAX + 1]; int64_t amount; };
struct vi_input { uint8_t txid[32]; uint32_t vout; };
struct vi_payload {
    struct vi_effect effects[VI_EFFECTS_MAX];
    struct vi_input inputs[VI_INPUTS_MAX];
    size_t effects_len, inputs_len;
    int64_t fee;
};

struct json_value;
struct vault_intent_row;
void vault_intent_transparent_render_plan(
    const struct vi_payload *payload, const struct vault_intent_row *row,
    struct json_value *result);

#endif
