/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "home.h"
#include "json/json.h"
#include "layout.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void fill_secrets(struct zapp_view *view)
{
    snprintf(view->fleet_token, sizeof(view->fleet_token), "FLEET-TOKEN-SECRET");
    snprintf(view->fleet_receipt, sizeof(view->fleet_receipt), "RECEIPT-SECRET");
    snprintf(view->ops_plan, sizeof(view->ops_plan), "PLAN-ID-SECRET");
    snprintf(view->ops_text, sizeof(view->ops_text), "OPS-TEXT-SECRET");
    snprintf(view->pair_offer, sizeof(view->pair_offer), "PAIR-OFFER-SECRET");
    snprintf(view->pair_code, sizeof(view->pair_code), "PAIRCD");
    snprintf(view->transcript, sizeof(view->transcript), "TRANSCRIPT-SECRET");
    snprintf(view->connection, sizeof(view->connection), "/data/user/0/org.z23/files/CONNECTION-PATH");
}
static void phone_card_golden(void)
{
    static struct zapp_view view;
    char card[1024];
    snprintf(view.node_line, sizeof(view.node_line), "Node catching up · 1,200 of 2,000");
    snprintf(view.sync_status, sizeof(view.sync_status), "800 blocks to go.");
    snprintf(view.balance, sizeof(view.balance), "Balance 1.25 ZCL");
    view.balance_known = true; view.node_process_running = true;
    fill_secrets(&view);
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(!strcmp(card, "{\"schema\":\"zcl.phone_card.v1\",\"node_line\":\"Node catching up · 1,200 of 2,000\","
        "\"sync\":\"800 blocks to go.\",\"balance\":\"Balance 1.25 ZCL\",\"balance_stale\":false,\"pace\":\"normal\"}"));
    view.pace = ZAPP_PACE_GENTLE; view.balance_stale = true;
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(strstr(card, "\"node_line\":\"Syncing gently · phone is warm\"") && strstr(card, "\"balance_stale\":true"));
    assert(strstr(card, "\"pace\":\"gentle\""));
    view.pace = ZAPP_PACE_PAUSE;
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)) && strstr(card, "\"pace\":\"pause\""));
}
static void phone_card_omits_unknown_balance_and_secrets(void)
{
    static struct zapp_view view;
    char card[1024];
    fill_secrets(&view);
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(!strcmp(card, "{\"schema\":\"zcl.phone_card.v1\",\"node_line\":\"\",\"sync\":\"Sync status unknown\","
        "\"pace\":\"normal\"}"));
    static const char *const secrets[] = {"FLEET-TOKEN", "RECEIPT", "PLAN-ID", "OPS-TEXT", "PAIR-OFFER", "PAIRCD",
        "TRANSCRIPT", "CONNECTION-PATH", "/data/", "fleet_token", "ops_plan", "pair_offer", "key"};
    view.balance_known = true;
    snprintf(view.balance, sizeof(view.balance), "Balance 2 ZCL");
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    for (size_t i = 0; i < sizeof(secrets) / sizeof(secrets[0]); ++i) assert(!strstr(card, secrets[i]));
    assert(zapp_home_phone_card(&view, true, card, sizeof(card)));
    assert(strstr(card, "Preview · separate from your main node") && !strstr(card, "Balance"));
    assert(!zapp_home_phone_card(&view, false, card, 20));
}
static void app_card_golden(void)
{
    struct zapp_app_entry app = {.label = "Maps \"Go\"", .package = "com.example.maps"};
    char card[256];
    assert(zapp_home_app_card(&app, card, sizeof(card)));
    assert(!strcmp(card, "{\"schema\":\"zcl.app_card.v1\",\"label\":\"Maps \\\"Go\\\"\",\"package\":\"com.example.maps\"}"));
    assert(!zapp_home_app_card(&app, card, 30));
}
static void z23_app_cards(void)
{
    static const char *const family[] = {"org.z23.clips", "org.z23.voice", "org.z23.fleet"};
    static const char *const other[] = {"org.z23.nativeapp", "org.z23.voicepreview", "org.z23.voicepreview.x", "org.z23x.clips",
        "com.example.maps", "org.z23"};
    struct json_value card;
    char text[256];
    for (size_t i = 0; i < sizeof(family) / sizeof(family[0]); ++i) {
        struct zapp_app_entry app = {.label = "Clips"};
        snprintf(app.package, sizeof(app.package), "%s", family[i]);
        assert(zapp_home_is_z23_app(family[i]) && zapp_home_app_card(&app, text, sizeof(text)));
        json_init(&card);
        assert(json_read(&card, text, strlen(text)) && zapp_card_is(&card, "z23_app") && !zapp_card_is(&card, "app"));
        json_free(&card);
    }
    for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); ++i) {
        struct zapp_app_entry app = {.label = "X"};
        snprintf(app.package, sizeof(app.package), "%s", other[i]);
#ifdef ZAPP_Z23_TEST_PACKAGE
        assert(zapp_home_is_z23_app("org.z23.voicepreview.clips"));
#else
        assert(!zapp_home_is_z23_app("org.z23.voicepreview.clips"));
#endif
        assert(!zapp_home_is_z23_app(other[i]) && zapp_home_app_card(&app, text, sizeof(text)));
        json_init(&card);
        assert(json_read(&card, text, strlen(text)) && zapp_card_is(&card, "app") && !zapp_card_is(&card, "z23_app"));
        json_free(&card);
    }
    assert(!zapp_home_is_z23_app(NULL));
}
static void built_in_layouts(void)
{
    static const char *const tiles[] = {"assistant", "apps", "settings"};
    assert(zapp_home_layout_count() == 2 && !strcmp(zapp_home_layout_name(0), "default"));
    assert(!strcmp(zapp_home_layout_name(1), "classic") && !zapp_home_layout_name(2) && !zapp_home_layout("other"));
    for (size_t i = 0; i < zapp_home_layout_count(); ++i) {
        const char *document = zapp_home_layout(zapp_home_layout_name(i));
        char reason[160];
        struct zapp_layout *layout = zapp_layout_parse(document, strlen(document), reason, sizeof(reason));
        assert(layout);
        const struct zapp_node *home = zapp_layout_screen(layout, "home");
        assert(home && !strcmp(layout->id, zapp_home_layout_name(i)));
        for (size_t t = 0; t < sizeof(tiles) / sizeof(tiles[0]); ++t) {
            assert(strstr(document, tiles[t]));
            assert(zapp_home_action_label(tiles[t]));
            assert(strstr(document, "\"card\":\"z23_app\""));
            assert(!strstr(document, "\"scan\"") && !strstr(document, "\"record\"") && !strstr(document, "\"watch\""));
        }
        zapp_layout_free(layout);
    }
    assert(strstr(zapp_home_layout("default"), "\"#000000\"") && strstr(zapp_home_layout("classic"), "\"#f7f5ef\""));
    assert(!strcmp(zapp_home_action_label("apps"), "Apps") && !zapp_home_action_label("launch") && !zapp_home_action_label("scan") && !zapp_home_action_label(NULL));
}
int main(void)
{
    phone_card_golden();
    phone_card_omits_unknown_balance_and_secrets();
    app_card_golden();
    z23_app_cards();
    built_in_layouts();
    puts("home tests passed");
    return 0;
}
