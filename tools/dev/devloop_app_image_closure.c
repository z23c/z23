/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the dev-only closure root of an app copy build record (see
 *          devloop_app_image_closure.h). */

#include "devloop_app_image_closure.h"

#include "base/serialize_le.h"
#include "command/app_image.h"
#include "devloop_action_root.h"
#include "sha3/sha3.h"
#include "vcs/build_action.h"

/* ---- closure and env roots ------------------------------------------- */

static struct zcl_result aib_action_closure(
    const struct zcl_action_root_request *action, size_t index,
    uint8_t out[32])
{
    struct zcl_action_root_result derived = {0};
    if (!zcl_action_root_derive(action, &derived)) {
        struct zcl_result refused = ZCL_ERR(
            -1, "app build record: compile action %zu has no exact input "
                "closure: %s (%s)", index, derived.miss, derived.why);
        zcl_action_root_result_free(&derived);
        return refused;
    }
    struct vcs_build_input_closure_v1 closure;
    char why[256] = "";
    bool ok = vcs_action_preimage_v2_input_closure(
                  derived.preimage, derived.preimage_len, &closure, why,
                  sizeof(why)) &&
              vcs_build_input_closure_v1_root(&closure, out);
    zcl_action_root_result_free(&derived);
    if (!ok)
        return ZCL_ERR(-1, "app build record: compile action %zu input "
                           "closure refused: %s", index,
                       why[0] ? why : "an input class has no root");
    return ZCL_OK;
}

struct zcl_result app_image_closure_root(
    const struct zcl_action_root_request *actions, size_t count,
    uint8_t out[32])
{
    if (!actions || !out || count == 0 || count > APP_IMAGE_BUILD_MAX_ACTIONS)
        return ZCL_ERR(-1, "app build record: closure needs 1..%u compile "
                           "actions, got %zu", APP_IMAGE_BUILD_MAX_ACTIONS,
                       actions ? count : 0u);
    if (count == 1)
        return aib_action_closure(&actions[0], 0, out);
    struct sha3_256_ctx sha;
    uint8_t count_le[4];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)APP_IMAGE_BUILD_CLOSURE_SET_DOMAIN,
                   sizeof(APP_IMAGE_BUILD_CLOSURE_SET_DOMAIN)); /* domain plus its NUL */
    zcl_write_u32_le(count_le, (uint32_t)count);
    sha3_256_write(&sha, count_le, sizeof(count_le));
    for (size_t i = 0; i < count; i++) {
        uint8_t root[32];
        struct zcl_result r = aib_action_closure(&actions[i], i, root);
        if (!r.ok)
            return r;
        sha3_256_write(&sha, root, sizeof(root));
    }
    sha3_256_finalize(&sha, out);
    return ZCL_OK;
}
