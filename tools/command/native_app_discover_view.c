/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Present one verified board advertisement without implying trust. */
#include "command/native_app_discover_view.h"
#include "command/native_app_confirm.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

bool app_discover_present_event(app_library_presenter presenter, void *context,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event)
{
    char why[256] = {0};
    return presenter(context, model, NULL, event, why, sizeof(why)) &&
        event->struct_size == sizeof(*event) && event->abi_version == ZCL_PRESENT_ABI_V1 &&
        (event->outcome == ZCL_PRESENT_WINDOW_DISMISSED ||
         (event->outcome == ZCL_PRESENT_WINDOW_ACTION && event->action_index < model->action_count));
}

static bool adv_row_valid(const struct zcl_app_offer_row *row)
{
    const struct zcl_app_offer *o = &row->offer;
    uint8_t digest[32];
    return memchr(o->name, 0, sizeof(o->name)) && memchr(o->root, 0, sizeof(o->root)) &&
        memchr(o->publisher, 0, sizeof(o->publisher)) && memchr(o->carrier, 0, sizeof(o->carrier)) &&
        memchr(o->sha256, 0, sizeof(o->sha256)) && memchr(o->onion, 0, sizeof(o->onion)) &&
        memchr(row->post_id, 0, sizeof(row->post_id)) && strlen(row->post_id) == 64 &&
        zcl_hex_decode_lower(row->post_id, digest, sizeof(digest)) && zcl_app_offer_valid(o);
}
static bool adv_offer(struct zcl_present_model_v1 *m, const struct zcl_app_offer_row *row,
    size_t index, size_t count)
{
    (void)snprintf(m->summary, sizeof(m->summary), "Available advertisement %zu of %zu. Review before trusting.", index + 1, count);
    app_confirm_action(&m->actions[0], ZCL_PRESENT_ACTION_SELECT, "review", "Review this app");
    app_confirm_action(&m->actions[1], ZCL_PRESENT_ACTION_SELECT, "previous", "Previous");
    app_confirm_action(&m->actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&m->actions[3], ZCL_PRESENT_ACTION_CANCEL, "back", "Back");
    return app_confirm_field(m, "App: ", row->offer.name) &&
        app_confirm_field(m, "Publisher: ", row->offer.publisher) &&
        app_confirm_field(m, "Package: ", row->offer.root) &&
        app_confirm_field(m, "Next: ", "Downloads first. Receive asks before trust or running.");
}
bool app_discover_view(struct zcl_present_model_v1 *model,
    const struct zcl_app_offer_row *row, size_t index, size_t count)
{
    if (!model) return false;
    memset(model, 0, sizeof(*model));
    if (count > ZCL_APP_OFFER_ROWS_MAX ||
        (count ? (!row || index >= count || !adv_row_valid(row)) : (row || index))) return false;
    struct zcl_present_model_v1 m;
    zcl_present_model_init_v1(&m, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(m.request_id, sizeof(m.request_id), "discover-%zu", index);
    (void)snprintf(m.title, sizeof(m.title), "Discover apps");
    m.action_count = count ? 4 : 2;
    if (!count) {
        (void)snprintf(m.summary, sizeof(m.summary), "No offers have reached this node. Refresh or go back.");
        app_confirm_action(&m.actions[0], ZCL_PRESENT_ACTION_SELECT, "refresh", "Refresh");
        app_confirm_action(&m.actions[1], ZCL_PRESENT_ACTION_CANCEL, "back", "Back");
    } else {
        if (!adv_offer(&m, row, index, count)) return false;
    }
    char why[256]; uint32_t pages;
    if (!zcl_present_model_validate_v1(&m, why, sizeof(why)) ||
        !zcl_present_model_page_count_v1(&m, &pages, why, sizeof(why)) || pages != 1) return false;
    *model = m;
    return true;
}

static void adv_empty_page(struct zcl_present_model_v1 *m, bool previous_page, bool has_more)
{
    (void)snprintf(m->summary, sizeof(m->summary), "%s",
        previous_page && has_more ? "No verified apps on this page. Choose More apps, Previous page or Back." :
        has_more ? "No verified apps on this page. Choose More apps, Refresh or Back." :
        previous_page ? "No verified apps on this page. Choose Previous page, Refresh or Back." :
        "No verified apps on this page. Refresh or go back.");
    m->action_count = 0;
    if (has_more)
        app_confirm_action(&m->actions[m->action_count++], ZCL_PRESENT_ACTION_SELECT, "next", "More apps");
    if (previous_page)
        app_confirm_action(&m->actions[m->action_count++], ZCL_PRESENT_ACTION_SELECT, "previous", "Previous page");
    if (!has_more || !previous_page)
        app_confirm_action(&m->actions[m->action_count++], ZCL_PRESENT_ACTION_SELECT, "refresh", "Refresh");
    app_confirm_action(&m->actions[m->action_count++], ZCL_PRESENT_ACTION_CANCEL, "back", "Back");
}
bool app_discover_page_view(struct zcl_present_model_v1 *model,
    const struct zcl_app_offer_row *row, size_t index, size_t count,
    bool previous_page, bool has_more)
{
    if (!app_discover_view(model, row, index, count)) return false;
    if (!count) adv_empty_page(model, previous_page, has_more);
    else {
        (void)snprintf(model->summary, sizeof(model->summary),
            "Advertisement %zu of %zu on this page. Review before trusting.", index + 1, count);
        if (!index && previous_page)
            app_confirm_action(&model->actions[1], ZCL_PRESENT_ACTION_SELECT, "previous", "Previous page");
        if (index + 1 == count) {
            if (has_more)
                app_confirm_action(&model->actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "More apps");
            else
                app_confirm_action(&model->actions[2], ZCL_PRESENT_ACTION_SELECT, "refresh", "Refresh");
        }
    }
    char why[256]; uint32_t pages;
    return zcl_present_model_validate_v1(model, why, sizeof(why)) &&
        zcl_present_model_page_count_v1(model, &pages, why, sizeof(why)) && pages == 1;
}
