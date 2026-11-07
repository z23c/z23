/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "home.h"
#include "hosts.h"
#include "residue.h"
#include "json/json.h"
#include "layout.h"
#include "wallet_screens.h"
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
static void node_button_states(void)
{
    static struct zapp_view view;
    char card[1024];
    assert(!strcmp(zapp_home_node_action_for_label("Start node"), "node_start"));
    assert(!strcmp(zapp_home_node_action_for_label("Stop node"), "node_stop"));
    assert(!strcmp(zapp_home_node_action_for_label(""), "") && !strcmp(zapp_home_node_action_for_label("Stopping…"), ""));
    assert(!strcmp(zapp_home_node_label(&view), "Start node"));
    view.node_starting = true;
    assert(!strcmp(zapp_home_node_label(&view), "Stop node"));
    assert(!strcmp(zapp_home_node_action_for_label(zapp_home_node_label(&view)), "node_stop"));
    view.node_starting = false;
    view.node_process_running = true;
    view.node_wanted = true;
    assert(!strcmp(zapp_home_node_label(&view), "Stop node"));
    /* The start marker could not be saved: the node still runs and no stop was sent, so Stop stays. */
    view.node_wanted = false;
    assert(!strcmp(zapp_home_node_label(&view), "Stop node"));
    assert(!strcmp(zapp_home_node_action_for_label(zapp_home_node_label(&view)), "node_stop"));
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)) && strstr(card, "\"node_button\":\"Stop node\"") &&
        !strstr(card, "Stopping"));
    view.node_stopping = true;
    assert(!strcmp(zapp_home_node_label(&view), ""));
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)) && strstr(card, "\"node_button\":\"\"") &&
        strstr(card, "\"node_line\":\"Stopping…\\nYou can use Z23\""));
    assert(zapp_home_phone_card(&view, true, card, sizeof(card)) && strstr(card, "\"node_button\":\"\""));
}
/* Whether the card's node line is exactly text, from the view as it stands. */
static bool node_line_is(const struct zapp_view *view, const char *text)
{
    char card[1024], needle[256];
    snprintf(needle, sizeof(needle), "\"node_line\":\"%s\"", text);
    return zapp_home_phone_card(view, false, card, sizeof(card)) && strstr(card, needle);
}
static void plain_node_line_states(void)
{
    static struct zapp_view view;
    assert(node_line_is(&view, "Node stopped"));
    view.node_process_running = true;
    view.node_wanted = true;
    assert(node_line_is(&view, "Starting node…\\nYou can use Z23"));
    view.node_seen_height = true;
    assert(node_line_is(&view, "Your node is running but has not replied yet"));
    view.node_seen_height = false;
    view.node_running = true;
    view.node_height = 1000;
    view.node_reference = 1800;
    view.chain_state = ZAPP_CHAIN_BEHIND;
    assert(node_line_is(&view, "Catching up: 800 blocks to go"));
}
static void plain_node_line_verdicts(void)
{
    static struct zapp_view view;
    view.node_process_running = true;
    view.node_wanted = true;
    view.node_running = true;
    view.node_height = 1000;
    /* A fleet height ahead of the node's own target: the verdict judges the node behind it, never up to date. */
    view.node_reference = 2000;
    view.chain_state = ZAPP_CHAIN_BEHIND;
    assert(node_line_is(&view, "Catching up: 1,000 blocks to go"));
    view.node_reference = 1000;
    view.chain_state = ZAPP_CHAIN_CURRENT;
    assert(node_line_is(&view, "Up to date"));
    view.chain_state = ZAPP_CHAIN_UNCONFIRMED;
    snprintf(view.chain_doubt, sizeof(view.chain_doubt), "only 1 peer");
    assert(node_line_is(&view, "Can't confirm it's up to date: only 1 peer"));
    snprintf(view.chain_doubt, sizeof(view.chain_doubt), "no new block for 17 min");
    assert(node_line_is(&view, "Can't confirm it's up to date: no new block for 17 min"));
    view.chain_state = ZAPP_CHAIN_WAITING;
    snprintf(view.chain_doubt, sizeof(view.chain_doubt), "No peer has reported a block height yet");
    assert(node_line_is(&view, "No peer has reported a block height yet"));
    view.chain_doubt[0] = 0;
    view.node_height = -1;
    view.node_reference = -1;
    view.chain_state = ZAPP_CHAIN_NONE;
    snprintf(view.node_line, sizeof(view.node_line), "Node running");
    assert(node_line_is(&view, "Checking the chain"));
    view.node_height = 1000;
    assert(node_line_is(&view, "Block 1,000, waiting for other computers"));
    /* A local serving flag does not imply a peer reference. */
    view.node_serving = true;
    assert(node_line_is(&view, "Block 1,000, waiting for other computers"));
    view.node_reference = 1000;
    view.chain_state = ZAPP_CHAIN_CURRENT;
    assert(node_line_is(&view, "Up to date"));
    view.node_reference = -1;
    view.node_height = -1;
    assert(node_line_is(&view, "Checking the chain"));
    view.node_height = 1000;
    view.node_stopping = true;
    assert(node_line_is(&view, "Stopping…\\nYou can use Z23"));
}
/* The lines each node of the phone card takes for one card: the status line wrapped to status_lines, the other texts on one
 * line, and an empty text on none. */
static void card_lines(const struct zapp_node *phone, const char *json, int status_lines, int *lines)
{
    struct json_value card = {0};
    char text[160];
    assert(json_read(&card, json, strlen(json)));
    for (size_t i = 0; i < phone->child_count; ++i) {
        const struct zapp_node *node = &phone->children[i];
        bool shown = zapp_card_field(&card, node->field, text, sizeof(text)) && text[0];
        lines[i] = zapp_layout_text_lines(node, !shown ? 0 : !strcmp(node->field, "node_line") ? status_lines : 1);
    }
    json_free(&card);
}
/* Every node of the phone card takes the same lines for a status of one line or two, and while the node stops, when the
 * button has no label, as while it runs: the tiles under the card never move. */
static void phone_card_keeps_its_height(void)
{
    static struct zapp_view running, stopping;
    char card[1024];
    running.node_process_running = running.node_wanted = running.node_running = true;
    running.node_height = 1000;
    running.node_reference = 1000;
    running.chain_state = ZAPP_CHAIN_CURRENT;
    stopping = running;
    stopping.node_stopping = true;
    for (size_t i = 0; i < zapp_home_layout_count(); ++i) {
        const char *document = zapp_home_layout(zapp_home_layout_name(i));
        char reason[160];
        struct zapp_layout *layout = zapp_layout_parse(document, strlen(document), reason, sizeof(reason));
        assert(layout);
        const struct zapp_node *home = zapp_layout_screen(layout, "home"), *phone = NULL;
        for (size_t c = 0; home && c < home->child_count; ++c)
            if (!strcmp(home->children[c].card, "phone")) phone = &home->children[c];
        assert(phone && phone->child_count == 3);
        int want[3], got[3];
        assert(zapp_home_phone_card(&running, false, card, sizeof(card)));
        card_lines(phone, card, 1, want);
        assert(want[0] == 2 && want[2] == 1);   /* the status line holds two lines and the button one */
        card_lines(phone, card, 2, got);
        assert(!memcmp(want, got, phone->child_count * sizeof(int)));
        assert(zapp_home_phone_card(&stopping, false, card, sizeof(card)) && strstr(card, "\"node_button\":\"\""));
        card_lines(phone, card, 1, got);
        assert(!memcmp(want, got, phone->child_count * sizeof(int)));
        zapp_layout_free(layout);
    }
}
static void phone_card_golden(void)
{
    static struct zapp_view view;
    char card[1024];
    view.node_process_running = true;
    view.node_running = true;
    view.node_wanted = true;
    view.node_height = 1200;
    view.node_reference = 2000;
    view.chain_state = ZAPP_CHAIN_BEHIND;
    fill_secrets(&view);
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(!strcmp(card, "{\"schema\":\"zcl.phone_card.v1\",\"node_line\":\"Catching up: 800 blocks to go\","
        "\"sync\":\"\",\"pace\":\"normal\",\"node_button\":\"Stop node\"}"));
    view.pace = ZAPP_PACE_GENTLE;
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(strstr(card, "\"node_line\":\"800 blocks left\\nKeeping phone cool\"") && strstr(card, "\"pace\":\"gentle\""));
    view.pace = ZAPP_PACE_PAUSE;
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)) && strstr(card, "\"pace\":\"pause\""));
}
static void phone_card_omits_secrets(void)
{
    static struct zapp_view view;
    char card[1024];
    fill_secrets(&view);
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)));
    assert(!strcmp(card, "{\"schema\":\"zcl.phone_card.v1\",\"node_line\":\"Node stopped\",\"sync\":\"\","
        "\"pace\":\"normal\",\"node_button\":\"Start node\"}"));
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
    assert(strstr(card, "\"sync\":\"\"") && !strstr(card, "WALLET") && !strstr(card, "ZCL"));
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
    assert(zapp_home_scan_target(ZAPP_SCAN_PAY_REFUSED, false) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    assert(zapp_home_scan_target(ZAPP_SCAN_PAY_REFUSED, true) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    /* A scan begun at a wallet screen that opens no review returns to the wallet; every review still opens (a payment on Send), and Home scans stay on Home. */
    assert(zapp_home_scan_returns_to_wallet(ZAPP_SCAN_TO_HOME, true) && !zapp_home_scan_returns_to_wallet(ZAPP_SCAN_TO_PAYMENT_REVIEW, true));
    assert(!zapp_home_scan_returns_to_wallet(ZAPP_SCAN_TO_FLEET_REVIEW, true) && !zapp_home_scan_returns_to_wallet(ZAPP_SCAN_TO_PAIR_REVIEW, true));
    assert(!zapp_home_scan_returns_to_wallet(ZAPP_SCAN_TO_HOME, false) && !zapp_home_scan_returns_to_wallet(ZAPP_SCAN_TO_PAYMENT_REVIEW, false));
    /* A scan started on Send that is not a payment stays on Send; a scan started elsewhere never goes there. */
    assert(zapp_home_scan_stays_on_send(true, ZAPP_SCAN_TO_HOME) && !zapp_home_scan_stays_on_send(false, ZAPP_SCAN_TO_HOME));
    assert(!zapp_home_scan_stays_on_send(true, ZAPP_SCAN_TO_FLEET_REVIEW) && !zapp_home_scan_stays_on_send(true, ZAPP_SCAN_TO_PAIR_REVIEW));
    assert(!zapp_home_scan_stays_on_send(true, ZAPP_SCAN_TO_PAYMENT_REVIEW));
    /* The Send screen offers Scan code first and Scan again after a scan ended without a payment. */
    assert(!strcmp(zapp_home_send_scan_label(NULL), "Scan code") && !strcmp(zapp_home_send_scan_label(""), "Scan code"));
    assert(!strcmp(zapp_home_send_scan_label("Camera permission was not given."), "Scan again"));
    /* A refused code shows its reason; a camera refusal shows its own words; anything else says it is not a payment code. */
    assert(!strcmp(zapp_home_send_notice(ZAPP_SCAN_PAY_REFUSED, "reason", "result"), "reason"));
    assert(!strcmp(zapp_home_send_notice(ZAPP_SCAN_TEXT, "", "Camera permission was not given."), "Camera permission was not given."));
    assert(!strcmp(zapp_home_send_notice(ZAPP_SCAN_PAY_REFUSED, "", "result"), "result"));
    assert(!strcmp(zapp_home_send_notice(ZAPP_SCAN_TEXT, "", ""), "That is not a payment code."));
    assert(!strcmp(zapp_home_send_notice(ZAPP_SCAN_TEXT, "plain", NULL), "That is not a payment code."));
    /* A press ends on the control it began on: the same position is not enough on Send, where a redraw can put another button there. */
    assert(zapp_home_same_press(2, false, 0, 2, false, 0) && !zapp_home_same_press(2, false, 0, 3, false, 0));
    assert(zapp_home_same_press(0, true, 7, 0, true, 7) && !zapp_home_same_press(0, true, 7, 0, true, 8));
    assert(!zapp_home_same_press(0, true, 7, 0, false, 7));
    /* Back from Send returns to where Send was opened: the wallet, directly or through a scan begun there, else Home. */
    assert(zapp_home_send_opened_from_wallet(false, true, false) && !zapp_home_send_opened_from_wallet(false, false, true));
    assert(zapp_home_send_opened_from_wallet(true, false, true) && !zapp_home_send_opened_from_wallet(true, false, false));
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
static void scrollable_home_grid(const struct zapp_node *home)
{
    /* Primary and app grids must retain their row heights inside a scrollable Home. */
    assert(home->kind == ZAPP_NODE_LIST && home->child_count >= 3);
    assert(home->children[0].kind == ZAPP_NODE_GRID && home->children[0].child_count == 3);
    assert(!strcmp(home->children[0].children[0].id, "wallet") &&
           !strcmp(home->children[0].children[1].id, "scan") &&
           !strcmp(home->children[0].children[2].id, "assistant"));
    assert(home->children[1].kind == ZAPP_NODE_COLUMN && !strcmp(home->children[1].card, "phone"));
    assert(home->children[1].child_count == 3 && !strcmp(home->children[1].children[2].id, "node_toggle"));
    assert(home->children[2].kind == ZAPP_NODE_GRID && !strcmp(home->children[2].card, "z23_app"));
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
        scrollable_home_grid(home);
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
    snprintf(text, sizeof(text), "\n %s", addr);
    kind = zapp_scan_classify(text, value, sizeof(value));
    assert(kind == ZAPP_SCAN_PAY_REFUSED && !strstr(value, "zs1") && zapp_home_scan_target(kind, true) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    char upper[ZAPP_PAY_ADDRESS_MAX];
    memcpy(upper, "ZS1", 3); memset(upper + 3, 'Q', 75); upper[78] = 0;
    kind = zapp_scan_classify(upper, value, sizeof(value));
    assert(kind == ZAPP_SCAN_PAY_REFUSED && !strstr(value, "ZS1") && zapp_home_scan_target(kind, false) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    static const char *const tails[] = {"?amount=1\n", "?amount=1&req-x=1", "?amount=1.123456789", "\n", "\t", "?amount=1\r\n"};
    for (size_t i = 0; i < sizeof(tails) / sizeof(tails[0]); ++i) {
        snprintf(text, sizeof(text), "zclassic:%s%s", addr, tails[i]);
        kind = zapp_scan_classify(text, value, sizeof(value));
        assert(kind == ZAPP_SCAN_PAY_REFUSED && value[0] && !strstr(value, "zs1"));
        assert(zapp_home_scan_target(kind, false) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    }
    snprintf(text, sizeof(text), "%s\n", addr);
    kind = zapp_scan_classify(text, value, sizeof(value));
    assert(kind == ZAPP_SCAN_PAY_REFUSED && !strstr(value, "zs1") && zapp_home_scan_target(kind, true) == ZAPP_SCAN_TO_PAYMENT_REVIEW);
    kind = zapp_scan_classify("hello world", value, sizeof(value));
    assert(kind == ZAPP_SCAN_TEXT && zapp_home_scan_target(kind, true) == ZAPP_SCAN_TO_HOME);
}

/* Dark is the default: the activity theme and the first built-in Home layout. */
static void dark_by_default(void)
{
    assert(!strcmp(zapp_home_layout_name(0), "default"));
    assert(strstr(zapp_home_layout("default"), "\"background\":\"#000000\""));
    static char manifest[16384];
    FILE *file = fopen("AndroidManifest.xml", "r");
    assert(file);
    size_t size = fread(manifest, 1, sizeof(manifest) - 1, file);
    assert(!ferror(file) && feof(file));
    fclose(file);
    manifest[size] = 0;
    assert(strstr(manifest, "android:theme=\"@android:style/Theme.Material.NoActionBar\""));
    assert(!strstr(manifest, "Light"));
}

/* Wallet data that the wallet screens hold for the owner, planted to see whether it survives them. */
#define MARKER_ADDRESS "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq"
#define MARKER_TXID "9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a"
#define MARKER_SUMMARY \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"wallet_readiness\":\"ready\",\"balance_available\":true,\"spendable_zat\":123456789,\"spendable\":\"1.23456789\"," \
    "\"pending_zat\":50000000,\"pending\":\"0.50000000\",\"pending_notes\":2,\"pending_min_confirmations_needed\":7," \
    "\"sending_zat\":0,\"sending\":\"0.00000000\",\"public_zat\":10000000,\"public\":\"0.10000000\",\"immature_zat\":0," \
    "\"immature\":\"0.00000000\",\"tip_height\":3000000,\"header_height\":3000000,\"scanned_through_height\":3000000," \
    "\"blocks_behind\":0,\"current\":true,\"locked\":false,\"encrypted\":true,\"shielded_keys\":1,\"send_allowed\":true," \
    "\"send_blocked_reason\":\"\"}}"
#define MARKER_HISTORY \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"shielded_state\":\"ok\",\"entries\":[{\"txid\":\"" MARKER_TXID "\",\"status\":\"confirmed\"," \
    "\"height\":1,\"confirmations\":1,\"time\":1700000000,\"direction\":\"received\",\"kind\":\"private\",\"amount_zat\":777," \
    "\"memo_present\":true}],\"count\":1,\"next_cursor\":null}}"
#define MARKER_DETAIL \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entry\":{\"txid\":\"" MARKER_TXID "\",\"memo\":\"padding past the allocator header MEMO-MARKER and then more words, enough to outgrow the first block a JSON string gets\"}}}"
static bool marker_secure(void *ctx, bool on) { (void)ctx; (void)on; return true; }
static uint64_t marker_now(void *ctx) { (void)ctx; return 1; }
static bool marker_run(void *ctx, const char *op, const char *arg, char *out, size_t cap)
{
    (void)ctx; (void)arg;
    snprintf(out, cap, "%s", !strcmp(op, "summary") ? MARKER_SUMMARY : !strcmp(op, "history") ? MARKER_HISTORY :
             !strcmp(op, "detail") ? MARKER_DETAIL : !strcmp(op, "latest") ? "{\"ok\":true,\"data\":{\"address\":\"" MARKER_ADDRESS "\"}}" : "");
    return out[0] != 0;
}
static bool screen_text_has(const struct wallet_screen *screen, const char *needle)
{
    for (size_t i = 0; i < screen->count; ++i) if (strstr(screen->items[i].text, needle)) return true;
    return false;
}
/* The scan finds what the screens hold while they hold it, and finds none of it anywhere in the heap or the
 * program's data once the owner has left, whichever Home builder ran in between. The Home builders take no
 * wallet input, and the Makefile rejects any include of the wallet files by the files that make Home. */
static void wallet_data_does_not_outlive_the_screens(void)
{
    static struct wallet_screen screen;
    static struct zapp_view view;
    struct wallet_env env = {.secure = marker_secure, .run = marker_run, .now_ms = marker_now};
    struct zapp_app_entry app = {.label = "Maps", .package = "com.example.maps", .activity = "com.example.maps.Main"};
    static const char *const markers[] = {"1.23456789", "0.5 ZCL", "MEMO-MARKER", MARKER_TXID, MARKER_ADDRESS, "1700000000", "2023-11-14"};
    char card[2048];
    assert(wallet_screens_init(&env));
    assert(wallet_screens_open(WALLET_PAGE_FUNDS));
    (void)wallet_screens_snapshot(&screen);
    assert(screen_text_has(&screen, "1.23456789 ZCL") && process_holds("1.23456789"));
    assert(wallet_screens_activate(WALLET_ACT_RECEIVE, 0) == WALLET_STAY);
    (void)wallet_screens_snapshot(&screen);
    assert(screen_text_has(&screen, "zs1q") && process_holds("qqqqqqqqqqqqqqqq"));
    assert(wallet_screens_back() && wallet_screens_activate(WALLET_ACT_HISTORY, 0) == WALLET_STAY);
    assert(wallet_screens_activate(WALLET_ACT_DETAIL, 0) == WALLET_STAY);
    (void)wallet_screens_snapshot(&screen);
    assert(screen_text_has(&screen, "MEMO-MARKER") && screen_text_has(&screen, MARKER_TXID) && process_holds("MEMO-MARKER"));
    snprintf(view.node_line, sizeof(view.node_line), "Node synced");
    snprintf(view.sync_status, sizeof(view.sync_status), "Synced");
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)) && zapp_home_app_card(&app, card + strlen(card), sizeof(card) - strlen(card)));
    wallet_screens_close();
    memset(&screen, 0, sizeof(screen));
    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); ++i) {
        assert(!strstr(card, markers[i]));
        assert(!strstr(zapp_home_layout("default"), markers[i]) && !strstr(zapp_home_layout("classic"), markers[i]));
        assert(!wallet_screens_residue(markers[i], strlen(markers[i])));
        assert(!process_holds(markers[i]));
    }
    wallet_screens_shutdown();
}
static void fallback_labels(void)
{
    char label[ZAPP_APP_LABEL_CAP];
    snprintf(label, sizeof(label), "%s", "Maps");
    zapp_home_fallback_label(label, sizeof(label), "Declared", "org.z23.maps");
    assert(!strcmp(label, "Maps"));
    label[0] = 0;
    zapp_home_fallback_label(label, sizeof(label), "Declared", "org.z23.maps");
    assert(!strcmp(label, "Declared"));
    label[0] = 0;
    zapp_home_fallback_label(label, sizeof(label), "", "org.z23.wallet.tools");
    assert(!strcmp(label, "tools"));
    label[0] = 0;
    zapp_home_fallback_label(label, sizeof(label), NULL, NULL);
    assert(!strcmp(label, "App"));
}

static void paced_home_lines(void)
{
    static struct zapp_view view;
    char card[1024];
    view.node_process_running = true;
    view.node_wanted = true;
    view.node_running = true;
    view.node_height = 1000;
    view.node_reference = 2000;
    view.chain_state = ZAPP_CHAIN_BEHIND;
    /* A normal pace shows blocks remaining. */
    view.pace = ZAPP_PACE_NORMAL;
    assert(node_line_is(&view, "Catching up: 1,000 blocks to go"));
    /* Paused while behind: the pause line, never the blocks left and never up to date. */
    view.pace = ZAPP_PACE_PAUSE;
    assert(node_line_is(&view, ZAPP_PAUSED_LINE));
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)) && !strstr(card, "Up to date") && !strstr(card, "Catching up"));
    /* Paused while current: still the pause line, never up to date. */
    view.node_reference = 1000;
    view.chain_state = ZAPP_CHAIN_CURRENT;
    assert(node_line_is(&view, ZAPP_PAUSED_LINE));
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)) && !strstr(card, "Up to date"));
    /* Gentle while behind: the slow catch-up line, with no estimate. */
    view.pace = ZAPP_PACE_GENTLE;
    view.node_reference = 2000;
    view.chain_state = ZAPP_CHAIN_BEHIND;
    assert(node_line_is(&view, "1,000 blocks left\\nKeeping phone cool"));
    view.node_reference = view.node_height + 3276435;
    assert(node_line_is(&view, "3,276,435 blocks left\\nKeeping phone cool"));
    assert(zapp_home_phone_card(&view, false, card, sizeof(card)) && !strstr(card, "min left") && !strstr(card, "Catching up:"));
}

/* Both built-in layouts give the sync caption three lines, so the detail fits beside a long title. */
static void caption_has_three_lines(void)
{
    assert(strstr(zapp_home_layout("default"), "\"style\":\"caption\",\"max_lines\":3}") && strstr(zapp_home_layout("classic"), "\"style\":\"caption\",\"max_lines\":3}"));
}

/* One input of the agreement grid: a node that is stopped, running without a reply, or answering, with its wanted,
 * stopping and onion settings, its pace and the chain readings. */
struct agreement_sample {
    bool responding, process, wanted, stopping, onion;
    enum zapp_pace pace;
    int64_t height, target, peers, fleet, quiet;
};
enum { AGREEMENT_SAMPLES = 3 * 2 * 2 * 2 * 3 * 3 * 3 * 3 * 3 * 3 };

/* Sample i of the grid: every combination of the inputs, in mixed radix. */
static struct agreement_sample agreement_sample_at(unsigned i)
{
    static const int64_t heights[] = {-1, 1000, 1500}, targets[] = {-1, 1000, 2000}, peers[] = {-1, 1, 2},
        fleets[] = {-1, 1000, 2000}, quiets[] = {-1, 60, 1000};
    static const enum zapp_pace paces[] = {ZAPP_PACE_NORMAL, ZAPP_PACE_GENTLE, ZAPP_PACE_PAUSE};
    struct agreement_sample s;
    unsigned k = i;
    const unsigned state = k % 3;
    k /= 3;
    s.process = state >= 1;
    s.responding = state == 2;
    s.wanted = k % 2 == 1;
    k /= 2;
    s.stopping = s.process && k % 2 == 1;
    k /= 2;
    s.onion = k % 2 == 1;
    k /= 2;
    s.pace = paces[k % 3];
    k /= 3;
    s.height = heights[k % 3];
    k /= 3;
    s.target = targets[k % 3];
    k /= 3;
    s.peers = peers[k % 3];
    k /= 3;
    s.fleet = fleets[k % 3];
    k /= 3;
    s.quiet = quiets[k % 3];
    return s;
}

/* Builds the Home node line and the Assistant sentence for one sample, as the controller does, and checks that they
 * agree on paused, up to date and behind. seen records which of the three Home states. */
static void check_agreement(const struct agreement_sample *s, struct zapp_view *view, bool seen[3])
{
    static const char up_to_date[] = "Your node has every block its peers report.";
    /* The controller reports no height for a node that does not answer, and shows the saving line while a stop sent
     * to a running process is in progress. */
    const bool stopping = s->stopping;
    const int64_t height = s->responding ? s->height : -1;
    const enum zapp_pace pace = s->responding ? s->pace : ZAPP_PACE_NORMAL;
    const struct zapp_chain_evidence ev = {.onion_only = s->onion, .fleet_height = s->fleet, .quiet_secs = s->quiet};
    const struct zapp_chain_status chain = zapp_chain_check(height, s->target, s->peers, &ev);
    char node[96], sync[1024], paced[1024], home[160];
    zapp_node_line(s->responding, s->process, stopping, false, height, s->target, s->peers, &ev, node, sizeof(node));
    zapp_sync_line(s->responding, s->process, height, s->target, s->peers, &ev, sync, sizeof(sync));
    if (stopping) snprintf(sync, sizeof(sync), "The node is saving its data before it exits.");
    view->node_process_running = s->process;
    view->node_wanted = s->wanted;
    view->node_stopping = stopping;
    view->node_running = s->responding;
    view->node_seen_height = false;
    view->pace = pace;
    view->node_height = height;
    view->node_reference = chain.reference;
    view->chain_state = chain.state;
    snprintf(view->chain_doubt, sizeof(view->chain_doubt), "%s", chain.reason);
    snprintf(view->node_line, sizeof(view->node_line), "%s", node);
    zapp_home_node_line(view, home, sizeof(home));
    zapp_paced_sync_line(pace, s->process, stopping, sync, paced, sizeof(paced));
    const bool home_paused = !strcmp(home, ZAPP_PAUSED_LINE), home_current = !strcmp(home, "Up to date");
    const bool home_behind = !strncmp(home, "Catching up", 11) ||
        (pace == ZAPP_PACE_GENTLE && strstr(home, " blocks left\nKeeping phone cool") != NULL);
    const bool sync_paused = !strcmp(paced, ZAPP_PAUSED_LINE), sync_current = !strcmp(paced, up_to_date);
    const bool sync_behind = strstr(paced, " to go.") != NULL;
    assert(home_paused == sync_paused);
    assert(home_current == sync_current);
    assert(!home_behind || !sync_current);
    assert(!sync_behind || home_behind);
    assert(!home_behind || sync_behind || strstr(paced, "dials only onion peers") != NULL);
    seen[0] |= home_paused;
    seen[1] |= home_current;
    seen[2] |= home_behind;
}

/* The Assistant sync sentence and the Home node line come from one observation, built as the controller builds them.
 * Over every combination of the inputs they agree on paused and on up to date, and the Assistant never says up to date
 * while Home says behind. The one allowed difference is wording: where Home says "Catching up" with fewer than two onion
 * peers, the Assistant names the onion peers instead. */
static void assistant_and_home_agree(void)
{
    static struct zapp_view view;
    bool seen[3] = {false, false, false};
    for (unsigned i = 0; i < AGREEMENT_SAMPLES; i++) {
        const struct agreement_sample s = agreement_sample_at(i);
        check_agreement(&s, &view, seen);
    }
    assert(seen[0] && seen[1] && seen[2]);
}

int main(void)
{
    fallback_labels();
    dark_by_default();
    phone_card_golden();
    node_button_states();
    plain_node_line_states();
    plain_node_line_verdicts();
    assistant_and_home_agree();
    paced_home_lines();
    phone_card_omits_secrets();
    phone_card_never_shows_wallet();
    wallet_tile_has_no_amount();
    wallet_data_does_not_outlive_the_screens();
    app_card_golden();
    z23_app_cards();
    unsigned_z23_package_is_plain();
    label_fits_on_character_boundary();
    scan_destinations();
    scanned_text_routes();
    worst_case_card_fits();
    built_in_layouts();
    caption_has_three_lines();
    phone_card_keeps_its_height();
    offer_jump();
    puts("home tests passed");
    return 0;
}
