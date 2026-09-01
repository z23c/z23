/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Owner-visible rendering for one exact transparent intent plan. */

#include "vault_intent_transparent_internal.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/vault_intent.h"

#include <stdio.h>

static void vit_amount_text(int64_t amount, char out[32])
{
    (void)snprintf(out, 32, "%lld.%08lld",
                   (long long)(amount / 100000000LL),
                   (long long)(amount % 100000000LL));
}

void vault_intent_transparent_render_plan(
    const struct vi_payload *p, const struct vault_intent_row *row,
    struct json_value *result)
{
    char digest[65], fee[32];
    HexStr(row->digest, 32, false, digest, sizeof(digest));
    vit_amount_text(p->fee, fee);
    json_push_kv_str(result, "digest", digest);
    json_push_kv_str(result, "fee", fee);
    json_push_kv_int(result, "confirmation_policy", 6);
    json_push_kv_str(result, "route", "transparent");
    json_push_kv_str(result, "privacy",
        "PUBLIC: recipients, values, inputs, change, and transaction graph are visible");
    struct json_value effects;
    json_init(&effects); json_set_array(&effects);
    for (size_t i = 0; i < p->effects_len; i++) {
        struct json_value effect;
        char amount[32];
        json_init(&effect); json_set_object(&effect);
        vit_amount_text(p->effects[i].amount, amount);
        json_push_kv_str(&effect, "asset", "ZCL");
        json_push_kv_str(&effect, "to", p->effects[i].to);
        json_push_kv_str(&effect, "amount", amount);
        json_push_back(&effects, &effect); json_free(&effect);
    }
    json_push_kv(result, "effects", &effects); json_free(&effects);
}
