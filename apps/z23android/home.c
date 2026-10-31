/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "home.h"
#include "hosts.h"
#include "json/json.h"
#include <stdio.h>
#include <string.h>

#define HOME_TILES \
    "{\"type\":\"action\",\"id\":\"scan\"},{\"type\":\"action\",\"id\":\"assistant\"}," \
    "{\"type\":\"action\",\"id\":\"wallet\"}"
#define HOME_PHONE_TEXT \
    "{\"type\":\"text\",\"field\":\"node_line\",\"style\":\"title\",\"max_lines\":2}," \
    "{\"type\":\"text\",\"field\":\"sync\",\"style\":\"caption\",\"max_lines\":2}"
#define HOME_Z23_APPS(columns) \
    "{\"type\":\"grid\",\"columns\":" columns ",\"card\":\"z23_app\",\"children\":[" \
    "{\"type\":\"action\",\"id\":\"launch\",\"field\":\"label\"}]}"

/* Black, immersive: the phone card, the Z23 apps, then big tiles that fill the screen. Apps and Settings stay in the fixed bar of the app, not in a layout. */
static const char default_layout[] =
    "{\"schema\":\"zcl.layout_recipe.v1\",\"id\":\"default\","
    "\"theme\":{\"background\":\"#000000\",\"text\":\"#ffffff\",\"muted\":\"#9a9a9a\",\"accent\":\"#3ddc97\"},"
    "\"screens\":{\"home\":{\"container\":\"column\",\"children\":["
    "{\"type\":\"column\",\"card\":\"phone\",\"children\":[" HOME_PHONE_TEXT "]},"
    HOME_Z23_APPS("2") ","
    "{\"type\":\"grid\",\"columns\":2,\"children\":[" HOME_TILES "]}]}}}";
/* Light: the phone card, the Z23 apps, three tiles (Scan, Assistant, Wallet), then every other launchable app. */
static const char classic_layout[] =
    "{\"schema\":\"zcl.layout_recipe.v1\",\"id\":\"classic\","
    "\"theme\":{\"background\":\"#f7f5ef\",\"text\":\"#262b2b\",\"muted\":\"#5f6662\",\"accent\":\"#235e50\"},"
    "\"screens\":{\"home\":{\"container\":\"list\",\"children\":["
    "{\"type\":\"column\",\"card\":\"phone\",\"children\":[" HOME_PHONE_TEXT "]},"
    HOME_Z23_APPS("2") ","
    "{\"type\":\"grid\",\"columns\":2,\"children\":[" HOME_TILES "]},"
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
size_t zapp_home_phone_card(const struct zapp_view *view, bool preview, char *out, size_t cap)
{
    struct json_value card;
    char line[sizeof(view->node_line)];
    bool running = view->node_running || view->node_process_running;
    json_init(&card); json_set_object(&card);
    json_push_kv_str(&card, "schema", "zcl.phone_card.v1");
    json_push_kv_str(&card, "node_line", preview ? "Preview · separate from your main node" :
        zapp_paced_line(view->pace, running, view->node_line, line, sizeof(line)));
    json_push_kv_str(&card, "sync", preview ? "The preview app does not run a node." :
        view->sync_status[0] ? view->sync_status : "Sync status unknown");
    json_push_kv_str(&card, "pace", pace_name(view->pace));
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
    return finish(&card, out, cap);
}
bool zapp_home_offer_jump(bool offer, bool on_scan_screen, bool *seen)
{
    if (!offer) { *seen = false; return false; }
    if (*seen || on_scan_screen) return false;
    *seen = true;
    return true;
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
enum zapp_scan_target zapp_home_scan_target(enum zapp_scan_kind kind, bool pair_offer)
{
    if (kind == ZAPP_SCAN_FLEET) return ZAPP_SCAN_TO_FLEET_REVIEW;
    if (kind == ZAPP_SCAN_PAY) return ZAPP_SCAN_TO_PAYMENT_REVIEW;
    return kind == ZAPP_SCAN_PAIR && pair_offer ? ZAPP_SCAN_TO_PAIR_REVIEW : ZAPP_SCAN_TO_HOME;
}
