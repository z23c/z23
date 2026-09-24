/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter shop-want-command-input-core.v1
 * for contexts/market/controllers/src/shop_native_want.c.
 * Compiled only inside the capsule unity rendered by
 * tools/dev/hotfork_unity.h: phase 1 precedes the owner TU set, phase 2
 * follows it. check-hotfork-stories compiles every unity with the frozen
 * dev flags, so an owner API change cannot silently disable this story.
 */
#if !defined(ZCL_HOTFORK_STORY_PHASE)
#error "HOT_FORK stories are included only by the generated capsule unity"
#elif ZCL_HOTFORK_STORY_PHASE == 1
#define _GNU_SOURCE
#include "hotswap/hotfork_capsule.h"
#include "hotswap/hotswap_service.h"
#define zcl_hotswap_service_acquire(...) NULL
#define zcl_hotswap_service_release(...) ((void)0)
#elif ZCL_HOTFORK_STORY_PHASE == 2
#undef zcl_hotswap_service_release
#undef zcl_hotswap_service_acquire
__attribute__((visibility("hidden"))) bool
zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out)
{
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->magic = ZCL_HOTFORK_OBSERVATION_MAGIC;
    unsigned failed = 0;
#define HF_CHECK(x) \
    do { \
        unsigned n = out->checks_run++; \
        if (x) \
            out->checks_passed++; \
        else \
            failed |= 1u << n; \
    } while (0)
    uint8_t decoded[32];
    const char *secret =
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    HF_CHECK(
        shw_hex32(secret, decoded) && decoded[0] == 0xa1
        && !shw_hex32(
            "A1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            decoded)
        && !shw_hex32("a1", decoded));
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "buyer_secret", secret);
    json_push_kv_int(&input, "amount_zatoshi", 500000);
    json_push_kv_str(&input, "criteria", "sha3-verified result");
    json_push_kv_int(&input, "expires_unix", 1780086400);
    json_push_kv_int(&input, "nonce", 42);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.v1");
    struct shop_want row;
    bool built = shw_build_want(&request, 1780000000, &row, &reply);
    HF_CHECK(built && row.want.amount_zatoshi == 500000
             && row.want.criteria_len == 20 && row.want.nonce == 42
             && row.want.issued_unix == 1780000000
             && row.want.expires_unix == 1780086400
             && shop_want_verify(&row.want) == SHOP_WANT_OK);
    zcl_command_reply_free(&reply);
    json_free(&input);
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "buyer_secret", secret);
    json_push_kv_int(&input, "amount_zatoshi", 1);
    json_push_kv_str(&input, "criteria", "x");
    json_push_kv_int(&input, "expires_unix", 1780000000);
    request.input = &input;
    zcl_command_reply_init(&reply, "zcl.test.v1");
    HF_CHECK(!shw_build_want(&request, 1780000000, &row, &reply)
             && strcmp(reply.error.code, "WANT_ALREADY_EXPIRED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u;failed_mask=0x%x",
             out->checks_passed, out->checks_run, failed);
    return out->checks_run == 3 && out->checks_passed == 3;
}
#else
#error "unknown HOT_FORK story phase"
#endif
