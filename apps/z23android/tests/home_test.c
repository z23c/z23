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
static void plant_wallet_marker(struct zapp_view *view)
{
    /* Each text field the Home card does not show holds the marker, so a wallet value that reaches the card is caught. */
    static const char marker[] = "WALLET-MARKER 1.25 ZCL";
    snprintf(view->fleet_status, sizeof(view->fleet_status), "%s", marker);
    snprintf(view->fleet_preview, sizeof(view->fleet_preview), "%s", marker);
    snprintf(view->fleet_receipt, sizeof(view->fleet_receipt), "%s", marker);
    snprintf(view->fleet_token, sizeof(view->fleet_token), "%s", marker);
    snprintf(view->transcript, sizeof(view->transcript), "%s", marker);
    snprintf(view->connection, sizeof(view->connection), "%s", marker);
    snprintf(view->notice, sizeof(view->notice), "%s", marker);
    snprintf(view->result, sizeof(view->result), "%s", marker);
    snprintf(view->voice_status, sizeof(view->voice_status), "%s", marker);
    snprintf(view->scan_text, sizeof(view->scan_text), "%s", marker);
    snprintf(view->ops_text, sizeof(view->ops_text), "%s", marker);
    snprintf(view->pair_offer, sizeof(view->pair_offer), "%s", marker);
}
static void phone_card_golden(void)
{
    static struct zapp_view view;
    char card[1024];
    snprintf(view.node_line, sizeof(view.node_line), "Node catching up · 1,200 of 2,000");
    snprintf(view.sync_status, sizeof(view.sync_status), "800 blocks to go.");
    view.node_process_running = true;
    fill_secrets(&view);
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(!strcmp(card, "{\"schema\":\"zcl.phone_card.v1\",\"node_line\":\"Node catching up · 1,200 of 2,000\","
        "\"sync\":\"800 blocks to go.\",\"pace\":\"normal\"}"));
    view.pace = ZAPP_PACE_GENTLE;
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(strstr(card, "\"node_line\":\"Syncing gently · phone is warm\"") && strstr(card, "\"pace\":\"gentle\""));
    view.pace = ZAPP_PACE_PAUSE;
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)) && strstr(card, "\"pace\":\"pause\""));
}
static void phone_card_omits_secrets(void)
{
    static struct zapp_view view;
    char card[1024];
    fill_secrets(&view);
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(!strcmp(card, "{\"schema\":\"zcl.phone_card.v1\",\"node_line\":\"\",\"sync\":\"Sync status unknown\","
        "\"pace\":\"normal\"}"));
    static const char *const secrets[] = {"FLEET-TOKEN", "RECEIPT", "PLAN-ID", "OPS-TEXT", "PAIR-OFFER", "PAIRCD",
        "TRANSCRIPT", "CONNECTION-PATH", "/data/", "fleet_token", "ops_plan", "pair_offer", "key"};
    for (size_t i = 0; i < sizeof(secrets) / sizeof(secrets[0]); ++i) assert(!strstr(card, secrets[i]));
    assert(zapp_home_phone_card(&view, true, card, sizeof(card)));
    assert(strstr(card, "Preview · separate from your main node") && !strstr(card, "Balance"));
    assert(!zapp_home_phone_card(&view, false, card, 20));
}
static void phone_card_never_shows_wallet(void)
{
    static struct zapp_view view;
    char card[1024];
    snprintf(view.node_line, sizeof(view.node_line), "Node synced");
    snprintf(view.sync_status, sizeof(view.sync_status), "Synced");
    view.node_process_running = true;
    plant_wallet_marker(&view);
    assert(strstr(view.fleet_status, "WALLET-MARKER"));
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(strstr(card, "\"sync\":\"Synced\"") && !strstr(card, "WALLET") && !strstr(card, "ZCL"));
    assert(!strstr(card, "Balance") && !strstr(card, "Wallet") && !strstr(card, "balance"));
    assert(zapp_home_phone_card(&view, true, card, sizeof(card)) && !strstr(card, "WALLET"));
}
static void wallet_tile_has_no_amount(void)
{
    const char *layout = zapp_home_layout("default"), *classic = zapp_home_layout("classic");
    const char *label = zapp_home_action_label("wallet");
    assert(layout && strstr(layout, "\"id\":\"wallet\"") && !strstr(layout, "balance"));
    assert(classic && strstr(classic, "\"id\":\"wallet\"") && !strstr(classic, "balance"));
    assert(label && !strcmp(label, "Wallet"));
}
static void app_card_golden(void)
{
    struct zapp_app_entry app = {.label = "Maps \"Go\"", .package = "com.example.maps", .activity = "com.example.maps.Main"};
    char card[256];
    assert(zapp_home_app_card(&app, card, sizeof(card)));
    assert(!strcmp(card, "{\"schema\":\"zcl.app_card.v1\",\"label\":\"Maps \\\"Go\\\"\",\"package\":\"com.example.maps\",\"activity\":\"com.example.maps.Main\"}"));
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
        struct zapp_app_entry app = {.label = "Clips", .same_signature = true};
        snprintf(app.package, sizeof(app.package), "%s", family[i]);
        assert(zapp_home_is_z23_app(family[i]) && zapp_home_app_card(&app, text, sizeof(text)));
        json_init(&card);
        assert(json_read(&card, text, strlen(text)) && zapp_card_is(&card, "z23_app") && !zapp_card_is(&card, "app"));
        json_free(&card);
    }
    for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); ++i) {
        struct zapp_app_entry app = {.label = "X"};
        snprintf(app.package, sizeof(app.package), "%s", other[i]);
        assert(!zapp_home_is_z23_app(other[i]) && zapp_home_app_card(&app, text, sizeof(text)));
        json_init(&card);
        assert(json_read(&card, text, strlen(text)) && zapp_card_is(&card, "app") && !zapp_card_is(&card, "z23_app"));
        json_free(&card);
    }
    assert(!zapp_home_is_z23_app(NULL));
}
/* A package that is not signed with this app's key gets a plain app tile, whatever its name. */
static void unsigned_z23_package_is_plain(void)
{
    struct zapp_app_entry app = {.label = "Clips", .package = "org.z23.clips", .same_signature = false};
    struct json_value card;
    char text[256];
    assert(zapp_home_app_card(&app, text, sizeof(text)));
    json_init(&card);
    assert(json_read(&card, text, strlen(text)) && zapp_card_is(&card, "app") && !zapp_card_is(&card, "z23_app"));
    json_free(&card);
}
static void label_fits_on_character_boundary(void)
{
    char out[8];
    zapp_home_fit_label(out, sizeof(out), "abc");
    assert(!strcmp(out, "abc"));
    zapp_home_fit_label(out, sizeof(out), "abcdefghij");
    assert(!strcmp(out, "abcdefg"));
    zapp_home_fit_label(out, sizeof(out), "abcdef\xc3\xa9z");
    assert(!strcmp(out, "abcdef"));
    zapp_home_fit_label(out, sizeof(out), "abcde\xc3\xa9z");
    assert(!strcmp(out, "abcde\xc3\xa9"));
    zapp_home_fit_label(out, 1, "abc");
    assert(!out[0]);
}
static void scan_destinations(void)
{
    assert(zapp_home_scan_target(ZAPP_SCAN_FLEET, false) == ZAPP_SCAN_TO_FLEET_REVIEW);
    assert(zapp_home_scan_target(ZAPP_SCAN_PAIR, true) == ZAPP_SCAN_TO_PAIR_REVIEW);
    assert(zapp_home_scan_target(ZAPP_SCAN_PAIR, false) == ZAPP_SCAN_TO_HOME);
    assert(zapp_home_scan_target(ZAPP_SCAN_TEXT, true) == ZAPP_SCAN_TO_HOME);
    assert(zapp_home_scan_target(ZAPP_SCAN_UNREADABLE, true) == ZAPP_SCAN_TO_HOME);
    assert(zapp_home_scan_target(ZAPP_SCAN_PAY, false) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    assert(zapp_home_scan_target(ZAPP_SCAN_PAY, true) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    assert(zapp_home_scan_target(ZAPP_SCAN_PAY_REFUSED, false) == ZAPP_SCAN_TO_HOME);
}
/* The largest label, package and activity, with every label character escaped, still make a card. */
static void worst_case_card_fits(void)
{
    struct zapp_app_entry app = {.same_signature = true};
    static char card[ZAPP_APP_CARD_CAP];
    struct json_value parsed;
    memset(app.label, '\x01', sizeof(app.label) - 1);
    memset(app.package, 'p', sizeof(app.package) - 1);
    memset(app.activity, 'a', sizeof(app.activity) - 1);
    size_t length = zapp_home_app_card(&app, card, sizeof(card));
    assert(length);
    json_init(&parsed);
    assert(json_read(&parsed, card, length));
    json_free(&parsed);
}
static void built_in_layouts(void)
{
    static const char *const tiles[] = {"scan", "assistant"};
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
            assert(!strstr(document, "\"record\"") && !strstr(document, "\"watch\"") && !strstr(document, "\"apps\"") && !strstr(document, "\"settings\""));
        }
        zapp_layout_free(layout);
    }
    assert(strstr(zapp_home_layout("default"), "\"#000000\"") && strstr(zapp_home_layout("classic"), "\"#f7f5ef\""));
    assert(!strcmp(zapp_home_action_label("apps"), "Apps") && !zapp_home_action_label("launch") && !zapp_home_action_label("record") && !zapp_home_action_label(NULL));
    assert(!strcmp(zapp_home_action_label("scan"), "Scan") && !strcmp(zapp_home_action_label("settings"), "Settings"));
}
/* A pairing offer scanned with the camera arrives while the scan screen is still up; the owner must be taken
 * to its review once the scan screen is gone, not lost. */
static void offer_jump(void)
{
    bool seen = false;
    assert(!zapp_home_offer_jump(false, false, &seen) && !seen);
    assert(!zapp_home_offer_jump(true, true, &seen) && !seen);
    assert(zapp_home_offer_jump(true, false, &seen) && seen);
    assert(!zapp_home_offer_jump(true, false, &seen) && seen);
    assert(!zapp_home_offer_jump(true, true, &seen) && seen);
    assert(!zapp_home_offer_jump(false, false, &seen) && !seen);
    assert(zapp_home_offer_jump(true, false, &seen) && seen);
    seen = true;
    assert(!zapp_home_offer_jump(false, true, &seen) && !seen);
}
/* From the camera text to the screen: only a payment code the parser accepts opens the send review. A refused
 * or damaged one is shown on Home as a refusal, and nothing with a payment scheme or an address shape is ever
 * shown as scanned text. */
static void scanned_text_routes(void)
{
    char addr[ZAPP_PAY_ADDRESS_MAX], text[512], value[512];
    memcpy(addr, "zs1", 3); memset(addr + 3, 'q', 75); addr[78] = 0;
    snprintf(text, sizeof(text), "zclassic:%s?amount=1.5", addr);
    enum zapp_scan_kind kind = zapp_scan_classify(text, value, sizeof(value));
    assert(kind == ZAPP_SCAN_PAY && zapp_home_scan_target(kind, false) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    kind = zapp_scan_classify(addr, value, sizeof(value));
    assert(kind == ZAPP_SCAN_PAY && zapp_home_scan_target(kind, true) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    static const char *const tails[] = {"?amount=1\n", "?amount=1&req-x=1", "?amount=1.123456789", "\n", "\t", "?amount=1\r\n"};
    for (size_t i = 0; i < sizeof(tails) / sizeof(tails[0]); ++i) {
        snprintf(text, sizeof(text), "zclassic:%s%s", addr, tails[i]);
        kind = zapp_scan_classify(text, value, sizeof(value));
        assert(kind == ZAPP_SCAN_PAY_REFUSED && value[0] && !strstr(value, "zs1"));
        assert(zapp_home_scan_target(kind, false) == ZAPP_SCAN_TO_HOME);
    }
    snprintf(text, sizeof(text), "%s\n", addr);
    kind = zapp_scan_classify(text, value, sizeof(value));
    assert(kind == ZAPP_SCAN_PAY_REFUSED && !strstr(value, "zs1") && zapp_home_scan_target(kind, true) == ZAPP_SCAN_TO_HOME);
    kind = zapp_scan_classify("hello world", value, sizeof(value));
    assert(kind == ZAPP_SCAN_TEXT && zapp_home_scan_target(kind, true) == ZAPP_SCAN_TO_HOME);
}

int main(void)
{
    phone_card_golden();
    phone_card_omits_secrets();
    phone_card_never_shows_wallet();
    wallet_tile_has_no_amount();
    app_card_golden();
    z23_app_cards();
    unsigned_z23_package_is_plain();
    label_fits_on_character_boundary();
    scan_destinations();
    scanned_text_routes();
    worst_case_card_fits();
    built_in_layouts();
    offer_jump();
    puts("home tests passed");
    return 0;
}
