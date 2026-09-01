/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Static adapter between signed want rows, the pure view island, and JSON. */

#ifndef ZCL_CONTROLLERS_SHOP_NATIVE_WANT_VIEW_H
#define ZCL_CONTROLLERS_SHOP_NATIVE_WANT_VIEW_H

#include "json/json.h"
#include "models/shop_want.h"
#include "services/shop_want_view_service.h"

#include <stdbool.h>
#include <stdint.h>

bool zcl_shop_want_view_render(const struct shop_want *row, int64_t now_unix,
                               bool full,
                               struct shop_want_view_result_v1 *out);
void zcl_shop_want_view_push_json(
    struct json_value *into, const struct shop_want_view_result_v1 *view);

#endif /* ZCL_CONTROLLERS_SHOP_NATIVE_WANT_VIEW_H */
