/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "home.h"
#include "hosts.h"
#include "json/json.h"
#include <stdio.h>
#include <string.h>

#define HOME_TILES \
    "{\"type\":\"action\",\"id\":\"wallet\"},{\"type\":\"action\",\"id\":\"scan\"}," \
    "{\"type\":\"action\",\"id\":\"assistant\"}"
#define HOME_PHONE_TEXT \
    "{\"type\":\"text\",\"field\":\"node_line\",\"style\":\"caption\",\"lines\":2}," \
    "{\"type\":\"text\",\"field\":\"sync\",\"style\":\"caption\",\"max_lines\":3}," \
    "{\"type\":\"action\",\"id\":\"node_toggle\",\"field\":\"node_button\",\"lines\":1}"
#define HOME_Z23_APPS(columns) \
    "{\"type\":\"grid\",\"columns\":" columns ",\"card\":\"z23_app\",\"children\":[" \
    "{\"type\":\"action\",\"id\":\"launch\",\"field\":\"label\"}]}"

/* Primary actions and the phone card precede installed apps. Apps and Settings stay in the fixed bar. */
static const char default_layout[] =
    "{\"schema\":\"zcl.layout_recipe.v1\",\"id\":\"default\","
    "\"theme\":{\"background\":\"#000000\",\"text\":\"#ffffff\",\"muted\":\"#9a9a9a\",\"accent\":\"#3ddc97\"},"
    "\"screens\":{\"home\":{\"container\":\"list\",\"children\":["
    "{\"type\":\"grid\",\"columns\":2,\"children\":[" HOME_TILES "]},"
    "{\"type\":\"column\",\"card\":\"phone\",\"children\":[" HOME_PHONE_TEXT "]},"
    HOME_Z23_APPS("2") "]}}}";
/* The light layout keeps the same primary actions, followed by every launchable app. */
static const char classic_layout[] =
    "{\"schema\":\"zcl.layout_recipe.v1\",\"id\":\"classic\","
    "\"theme\":{\"background\":\"#f7f5ef\",\"text\":\"#262b2b\",\"muted\":\"#5f6662\",\"accent\":\"#235e50\"},"
    "\"screens\":{\"home\":{\"container\":\"list\",\"children\":["
    "{\"type\":\"grid\",\"columns\":2,\"children\":[" HOME_TILES "]},"
    "{\"type\":\"column\",\"card\":\"phone\",\"children\":[" HOME_PHONE_TEXT "]},"
    HOME_Z23_APPS("2") ","
    "{\"type\":\"column\",\"card\":\"app\",\"children\":["
    "{\"type\":\"action\",\"id\":\"launch\",\"field\":\"label\"}]}]}}}";
static const struct { const char *name, *document; } layouts[] = {
    {"default", default_layout}, {"classic", classic_layout},
};
static const struct { const char *id, *label; } labels[] = {
    {"scan", "Scan"}, {"assistant", "Assistant"}, {"wallet", "Wallet"}, {"apps", "Apps"}, {"settings", "Settings"},
};

size_t zapp_home_layout_count(void) { return sizeof(layouts) / sizeof(layouts[0]); }
const char *zapp_home_layout_name(size_t index) { return index < zapp_home_layout_count() ? layouts[index].name : NULL; }
const char *zapp_home_layout(const char *name)
{
    for (size_t i = 0; name && i < zapp_home_layout_count(); ++i)
        if (!strcmp(layouts[i].name, name)) return layouts[i].document;
    return NULL;
}
const char *zapp_home_action_label(const char *id)
{
    for (size_t i = 0; id && i < sizeof(labels) / sizeof(labels[0]); ++i)
        if (!strcmp(labels[i].id, id)) return labels[i].label;
    return NULL;
}
const char *zapp_home_node_label(const struct zapp_view *view)
{
    if (view->node_starting) return "Stop node";
    if (!view->node_process_running) return "Start node";
    return view->node_stopping ? "" : "Stop node";
}
const char *zapp_home_node_action_for_label(const char *label)
{
    if (!label) return "";
    if (!strcmp(label, "Start node")) return "node_start";
    return !strcmp(label, "Stop node") ? "node_stop" : "";
}
static size_t finish(struct json_value *card, char *out, size_t cap)
{
    size_t length = json_write(card, out, cap);
    json_free(card);
    return length < cap ? length : 0;
}
static const char *pace_name(enum zapp_pace pace)
{
    return pace == ZAPP_PACE_GENTLE ? "gentle" : pace == ZAPP_PACE_PAUSE ? "pause" : "normal";
}
/* A node behind its reference: gentle pace catches up slowly to keep the phone cool. */
static void behind_line(const struct zapp_view *view, char *out, size_t cap)
{
    char blocks[32];
    const int64_t behind = view->node_reference - view->node_height;
    if (view->pace == ZAPP_PACE_GENTLE) {
        snprintf(out, cap, "%s blocks left\nKeeping phone cool", zapp_grouped(behind, blocks));
        return;
    }
    snprintf(out, cap, "Catching up: %s blocks to go", zapp_grouped(behind, blocks));
}
/* Describe a responding node using the current chain verdict. */
static void responding_node_line(const struct zapp_view *view, char *out, size_t cap)
{
    if (view->node_height < 0) snprintf(out, cap, "Checking the chain");
    else if (view->node_reference < 0) {
        char height[32];
        snprintf(out, cap, "Block %s, waiting for other computers", zapp_grouped(view->node_height, height));
    }
    else if (view->chain_state == ZAPP_CHAIN_BEHIND) behind_line(view, out, cap);
    else if (view->chain_state == ZAPP_CHAIN_UNCONFIRMED) snprintf(out, cap, "Can't confirm it's up to date: %s", view->chain_doubt);
    else if (view->chain_state == ZAPP_CHAIN_WAITING) snprintf(out, cap, "%s", view->chain_doubt);
    else if (view->chain_state == ZAPP_CHAIN_CURRENT) snprintf(out, cap, "Up to date");
    else snprintf(out, cap, "Connected, checking the chain");
}

/* Plain node status; up to date is shown only for the CURRENT verdict. */
static const char *plain_node_line(const struct zapp_view *view, char *out, size_t cap)
{
    if (view->node_stopping && view->node_installing) snprintf(out, cap, "Stopping…\nYou can use Z23");
    else if (view->node_installing) snprintf(out, cap, "Fast sync\n%s",
        view->node_wallet_replaying ? view->node_wallet_replay : "Preparing your wallet");
    else if (!view->node_process_running) snprintf(out, cap, "Node stopped");
    else if (view->node_stopping) snprintf(out, cap, "Stopping…\nYou can use Z23");
    else if (view->node_wallet_replaying && !view->node_running) snprintf(out, cap, "%s", view->node_wallet_replay);
    else if (view->pace == ZAPP_PACE_PAUSE) snprintf(out, cap, "%s", ZAPP_PAUSED_LINE);
    else if (!view->node_running) snprintf(out, cap, "%s", view->node_seen_height ?
        "Your node is running but has not replied yet" : "Starting node…\nYou can use Z23");
    else responding_node_line(view, out, cap);
    return out;
}
/* The plain node line the Home card shows, copied into out; the foreground notification shows the same line. */
const char *zapp_home_node_line(const struct zapp_view *view, char *out, size_t cap)
{
    return plain_node_line(view, out, cap);
}
size_t zapp_home_phone_card(const struct zapp_view *view, bool preview, char *out, size_t cap)
{
    struct json_value card;
    char line[sizeof(view->node_line)];
    json_init(&card); json_set_object(&card);
    json_push_kv_str(&card, "schema", "zcl.phone_card.v1");
    json_push_kv_str(&card, "node_line", preview ? "Preview · separate from your main node" :
        plain_node_line(view, line, sizeof(line)));
    json_push_kv_str(&card, "sync", preview ? "The preview app does not run a node." :
        "");
    json_push_kv_str(&card, "pace", pace_name(view->pace));
    json_push_kv_str(&card, "node_button", preview ? "" : zapp_home_node_label(view));
    return finish(&card, out, cap);
}
bool zapp_home_is_z23_app(const char *package)
{
    static const char family[] = "org.z23.";
    if (!package || strncmp(package, family, sizeof(family) - 1)) return false;
    if (!strcmp(package, "org.z23.nativeapp")) return false;
    return strncmp(package, "org.z23.voicepreview", sizeof("org.z23.voicepreview") - 1) != 0;
}
size_t zapp_home_app_card(const struct zapp_app_entry *app, char *out, size_t cap)
{
    struct json_value card;
    json_init(&card); json_set_object(&card);
    json_push_kv_str(&card, "schema", app->same_signature && zapp_home_is_z23_app(app->package) ? "zcl.z23_app_card.v1" : "zcl.app_card.v1");
    json_push_kv_str(&card, "label", app->label);
    json_push_kv_str(&card, "package", app->package);
    json_push_kv_str(&card, "activity", app->activity);
    if (app->same_signature && zapp_home_is_z23_app(app->package) && app->version_known) {
        json_push_kv_int(&card, "version_code", app->version_code);
        if (app->version_name[0]) json_push_kv_str(&card, "version_name", app->version_name);
    }
    return finish(&card, out, cap);
}
const char *zapp_home_version_line(const struct zapp_app_entry *app, char *out, size_t cap)
{
    if (!out || !cap) return NULL;
    out[0] = 0;
    if (!app || !app->same_signature || !app->version_known || !zapp_home_is_z23_app(app->package)) return out;
    if (app->version_name[0]) snprintf(out, cap, "%s (%lld)", app->version_name, (long long)app->version_code);
    else snprintf(out, cap, "%lld", (long long)app->version_code);
    return out;
}
bool zapp_home_offer_jump(bool offer, bool on_scan_screen, bool *seen)
{
    if (!offer) { *seen = false; return false; }
    if (*seen || on_scan_screen) return false;
    *seen = true;
    return true;
}
/* A readable name for an app whose launcher label came back empty: the declared name when there is one, else the last
 * component of the package (the whole package when it ends in a dot), else "App". Writes only when label is empty. */
void zapp_home_fallback_label(char *label, size_t cap, const char *declared, const char *package)
{
    if (!cap || label[0]) return;
    const char *tail = package && strrchr(package, '.') ? strrchr(package, '.') + 1 : package;
    if (!tail || !tail[0]) tail = package && package[0] ? package : "App";
    snprintf(label, cap, "%s", declared && declared[0] ? declared : tail);
}
void zapp_home_fit_label(char *out, size_t cap, const char *text)
{
    size_t length = strlen(text);
    if (!cap) return;
    if (length >= cap) {
        length = cap - 1;
        while (length && ((unsigned char)text[length] & 0xc0u) == 0x80u) --length;
    }
    memcpy(out, text, length);
    out[length] = '\0';
}
void zapp_home_store_version_name(struct zapp_app_entry *app, const char *text)
{
    if (!app) return;
    app->version_name[0] = 0;
    if (text && text[0]) zapp_home_fit_label(app->version_name, sizeof(app->version_name), text);
}
enum zapp_scan_target zapp_home_scan_target(enum zapp_scan_kind kind, bool pair_offer)
{
    if (kind == ZAPP_SCAN_FLEET) return ZAPP_SCAN_TO_FLEET_REVIEW;
    if (kind == ZAPP_SCAN_PAY || kind == ZAPP_SCAN_PAY_REFUSED) return ZAPP_SCAN_TO_PAYMENT_REVIEW;
    return kind == ZAPP_SCAN_PAIR && pair_offer ? ZAPP_SCAN_TO_PAIR_REVIEW : ZAPP_SCAN_TO_HOME;
}
bool zapp_home_scan_returns_to_wallet(enum zapp_scan_target target, bool began_in_wallet)
{
    return began_in_wallet && target == ZAPP_SCAN_TO_HOME;
}
bool zapp_home_scan_stays_on_send(bool started_on_send, enum zapp_scan_target target)
{
    return started_on_send && target == ZAPP_SCAN_TO_HOME;
}
const char *zapp_home_send_scan_label(const char *notice)
{
    return notice && notice[0] ? "Scan again" : "Scan code";
}
const char *zapp_home_send_notice(enum zapp_scan_kind kind, const char *scan_text, const char *result)
{
    if (kind == ZAPP_SCAN_PAY_REFUSED && scan_text && scan_text[0]) return scan_text;
    return result && result[0] ? result : "That is not a payment code.";
}
bool zapp_home_send_opened_from_wallet(bool origin_is_send, bool origin_is_wallet, bool was_from_wallet)
{
    return origin_is_send ? was_from_wallet : origin_is_wallet;
}
bool zapp_home_same_press(size_t index_a, bool by_button_a, unsigned button_a, size_t index_b, bool by_button_b, unsigned button_b)
{
    if (index_a != index_b || by_button_a != by_button_b) return false;
    return !by_button_a || button_a == button_b;
}
